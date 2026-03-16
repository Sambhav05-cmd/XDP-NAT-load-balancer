//go:build lc_est
package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpf lb ../../bpf/lb_lc_est.c

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"log"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
)

var (
	ifname string
)

type BackendEntry struct {
	IP   string `json:"ip"`
	Port uint16 `json:"port"`
}

type ServiceEntry struct {
	VIP  string `json:"vip"`
	Port uint16 `json:"port"`
}

type Config struct {
	Service  ServiceEntry   `json:"service"`
	Backends []BackendEntry `json:"backends"`
}

func parseIPv4(s string) (uint32, error) {
	ip := net.ParseIP(s).To4()
	if ip == nil {
		return 0, fmt.Errorf("invalid IPv4: %s", s)
	}
	return binary.LittleEndian.Uint32(ip), nil
}

func htons(port uint16) uint16 {
	return (port<<8)&0xff00 | port>>8
}

func addService(objs *lbObjects, ip string, port uint16) {

	vip, err := parseIPv4(ip)
	if err != nil {
		log.Println("invalid vip:", err)
		return
	}

	key := lbService{
		Vip:  vip,
		Port: htons(port),
	}

	val := true

	err = objs.lbMaps.Services.Put(&key, &val)
	if err != nil {
		log.Println("failed adding service:", err)
		return
	}

	log.Println("service added:", ip, port)
}

func deleteService(objs *lbObjects, ip string, port uint16) {

	vip, err := parseIPv4(ip)
	if err != nil {
		log.Println("invalid vip:", err)
		return
	}

	key := lbService{
		Vip:  vip,
		Port: htons(port),
	}

	err = objs.lbMaps.Services.Delete(&key)
	if err != nil {
		log.Println("failed deleting service:", err)
		return
	}

	log.Println("service deleted:", ip, port)
}

func listServices(objs *lbObjects) {

	iter := objs.lbMaps.Services.Iterate()

	var k lbService
	var v bool

	for iter.Next(&k, &v) {

		ip := make(net.IP, 4)
		binary.LittleEndian.PutUint32(ip, k.Vip)

		fmt.Println("service:", ip, "port:", htons(k.Port))
	}
}

func addBackend(objs *lbObjects, ip string, port uint16) {

	backIP, err := parseIPv4(ip)
	if err != nil {
		log.Println("invalid ip:", err)
		return
	}

	key := uint32(0)
	var count uint32

	err = objs.lbMaps.BackendCount.Lookup(key, &count)
	if err != nil {
		log.Println("failed reading backend count:", err)
		return
	}

	for i := uint32(0); i < count; i++ {
		var b lbBackend
		err := objs.lbMaps.Backends.Lookup(i, &b)
		if err == nil && b.Ip == backIP && b.Port == htons(port) {
			log.Println("backend already exists:", ip, port)
			return
		}
	}

	backEp := lbBackend{
		Ip:    backIP,
		Port:  htons(port),
		Conns: 0,
	}

	err = objs.lbMaps.Backends.Put(count, &backEp)
	if err != nil {
		log.Println("failed adding backend:", err)
		return
	}

	count++
	objs.lbMaps.BackendCount.Put(key, count)

	log.Println("backend added:", ip, port)
}

func deleteBackend(objs *lbObjects, ip string, port uint16) {

	backIP, err := parseIPv4(ip)
	if err != nil {
		log.Println("invalid ip:", err)
		return
	}

	key := uint32(0)
	var count uint32

	err = objs.lbMaps.BackendCount.Lookup(key, &count)
	if err != nil {
		log.Println("failed reading backend count:", err)
		return
	}

	for i := uint32(0); i < count; i++ {

		var b lbBackend
		err := objs.lbMaps.Backends.Lookup(i, &b)
		if err != nil {
			continue
		}

		if b.Ip == backIP && b.Port == htons(port) {

			if b.Conns != 0 {
				log.Println("cannot delete backend, active connections:", b.Conns)
				return
			}

			last := count - 1

			if i != last {
				var lastBackend lbBackend
				err := objs.lbMaps.Backends.Lookup(last, &lastBackend)
				if err == nil {
					objs.lbMaps.Backends.Put(i, &lastBackend)
				}
			}

			objs.lbMaps.Backends.Delete(last)

			count--
			objs.lbMaps.BackendCount.Put(key, count)

			log.Println("backend deleted:", ip, port)
			return
		}
	}

	log.Println("backend not found:", ip, port)
}

func listBackends(objs *lbObjects) {

	var count uint32
	key := uint32(0)

	err := objs.lbMaps.BackendCount.Lookup(key, &count)
	if err != nil {
		fmt.Println("failed to read backend count")
		return
	}

	for i := uint32(0); i < count; i++ {

		var b lbBackend
		err := objs.lbMaps.Backends.Lookup(i, &b)
		if err != nil {
			continue
		}

		ip := make(net.IP, 4)
		binary.LittleEndian.PutUint32(ip, b.Ip)

		fmt.Println(i, ip, "port:", htons(b.Port), "conns:", b.Conns)
	}
}

func main() {

	flag.StringVar(&ifname, "i", "lo", "iface")
	var configFile string
	flag.StringVar(&configFile, "config", "configs/backends_lc.json", "config")
	flag.Parse()

	data, err := os.ReadFile(configFile)
	if err != nil {
		log.Fatal(err)
	}

	var cfg Config
	json.Unmarshal(data, &cfg)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	rlimit.RemoveMemlock()

	var objs lbObjects
	loadLbObjects(&objs, nil)
	defer objs.Close()

	addService(&objs, cfg.Service.VIP, cfg.Service.Port)

	for i, backend := range cfg.Backends {

		backIP, _ := parseIPv4(backend.IP)

		backEp := lbBackend{
			Ip:    backIP,
			Port:  htons(backend.Port),
			Conns: 0,
		}

		objs.lbMaps.Backends.Put(uint32(i), &backEp)
	}

	count := uint32(len(cfg.Backends))
	key := uint32(0)
	objs.lbMaps.BackendCount.Put(key, count)

	iface, _ := net.InterfaceByName(ifname)

	xdplink, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpLoadBalancer,
		Interface: iface.Index,
		Flags:     link.XDPGenericMode,
	})
	if err != nil {
		log.Fatal(err)
	}
	defer xdplink.Close()

	log.Println("XDP LB running")

	reader := bufio.NewReader(os.Stdin)

	go func() {

		for {

			select {
			case <-ctx.Done():
				return
			default:

				fmt.Print("lb> ")
				line, _ := reader.ReadString('\n')

				parts := strings.Fields(strings.TrimSpace(line))
				if len(parts) == 0 {
					continue
				}

				switch parts[0] {

				case "add":
					p, _ := strconv.Atoi(parts[2])
					addBackend(&objs, parts[1], uint16(p))

				case "del":
					p, _ := strconv.Atoi(parts[2])
					deleteBackend(&objs, parts[1], uint16(p))

				case "list":
					listBackends(&objs)

				case "addsvc":
					p, _ := strconv.Atoi(parts[2])
					addService(&objs, parts[1], uint16(p))

				case "delsvc":
					p, _ := strconv.Atoi(parts[2])
					deleteService(&objs, parts[1], uint16(p))

				case "listsvc":
					listServices(&objs)

				default:
					fmt.Println("add del list addsvc delsvc listsvc")
				}
			}
		}
	}()

	<-ctx.Done()
}