//go:build wlc_syn
package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpf lb4 ../../bpf/lb_wlc_syn.c

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"bufio"
	"strconv"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

var ifname string

type BackendConfig struct {
	IP     string `json:"ip"`
	Port   uint16 `json:"port"`
	Weight uint16 `json:"weight"`
}

type ServiceEntry struct {
	VIP  string `json:"vip"`
	Port uint16 `json:"port"`
}

type Config struct {
	Service  ServiceEntry    `json:"service"`
	Backends []BackendConfig `json:"backends"`
}

func parseIPv4(s string) (uint32, error) {
	ip := net.ParseIP(s).To4()
	if ip == nil {
		return 0, fmt.Errorf("invalid IPv4: %s", s)
	}
	return binary.LittleEndian.Uint32(ip), nil
}

func htons(port uint16) uint16 {
	return (port << 8) | (port >> 8)
}

func addService(objs *lb4Objects, ip string, port uint16) {

	vip, err := parseIPv4(ip)
	if err != nil {
		log.Println("invalid vip:", err)
		return
	}

	key := lb4Service{
		Vip:  vip,
		Port: htons(port),
	}

	val := true

	err = objs.lb4Maps.Services.Put(&key, &val)
	if err != nil {
		log.Println("failed adding service:", err)
		return
	}

	log.Println("service added:", ip, port)
}

func deleteService(objs *lb4Objects, ip string, port uint16) {

	vip, err := parseIPv4(ip)
	if err != nil {
		log.Println("invalid vip:", err)
		return
	}

	key := lb4Service{
		Vip:  vip,
		Port: htons(port),
	}

	err = objs.lb4Maps.Services.Delete(&key)
	if err != nil {
		log.Println("failed deleting service:", err)
		return
	}

	log.Println("service deleted:", ip, port)
}

func listServices(objs *lb4Objects) {

	iter := objs.lb4Maps.Services.Iterate()

	var k lb4Service
	var v bool

	for iter.Next(&k, &v) {

		ip := make(net.IP, 4)
		binary.LittleEndian.PutUint32(ip, k.Vip)

		fmt.Println("service:", ip, "port:", htons(k.Port))
	}
}

func addBackend(objs *lb4Objects, ip string, port uint16, weight uint16) {

	backIP, err := parseIPv4(ip)
	if err != nil {
		log.Println("invalid ip:", err)
		return
	}

	key := uint32(0)
	var count uint32

	objs.lb4Maps.BackendCount.Lookup(key, &count)

	for i := uint32(0); i < count; i++ {

		var b lb4Backend
		err := objs.lb4Maps.Backends.Lookup(i, &b)
		if err == nil && b.Ip == backIP && b.Port == htons(port) {
			log.Println("backend already exists:", ip, port)
			return
		}
	}

	backEp := lb4Backend{
		Ip:     backIP,
		Port:   htons(port),
		Conns:  0,
		Weight: weight,
	}

	objs.lb4Maps.Backends.Put(count, &backEp)

	count++
	objs.lb4Maps.BackendCount.Put(key, count)

	log.Println("backend added:", ip, port)
}

func deleteBackend(objs *lb4Objects, ip string, port uint16) {

	backIP, err := parseIPv4(ip)
	if err != nil {
		log.Println("invalid ip:", err)
		return
	}

	key := uint32(0)
	var count uint32

	objs.lb4Maps.BackendCount.Lookup(key, &count)

	for i := uint32(0); i < count; i++ {

		var b lb4Backend
		err := objs.lb4Maps.Backends.Lookup(i, &b)
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
				var lastBackend lb4Backend
				objs.lb4Maps.Backends.Lookup(last, &lastBackend)
				objs.lb4Maps.Backends.Put(i, &lastBackend)
			}

			objs.lb4Maps.Backends.Delete(last)

			count--
			objs.lb4Maps.BackendCount.Put(key, count)

			log.Println("backend deleted:", ip, port)
			return
		}
	}

	log.Println("backend not found:", ip, port)
}

func updateBackend(objs *lb4Objects, ip string, port uint16, weight uint16) {

	backIP, err := parseIPv4(ip)
	if err != nil {
		log.Println("invalid ip:", err)
		return
	}

	key := uint32(0)
	var count uint32

	objs.lb4Maps.BackendCount.Lookup(key, &count)

	for i := uint32(0); i < count; i++ {

		var b lb4Backend
		err := objs.lb4Maps.Backends.Lookup(i, &b)
		if err != nil {
			continue
		}

		if b.Ip == backIP && b.Port == htons(port) {

			b.Weight = weight
			objs.lb4Maps.Backends.Put(i, &b)

			log.Println("backend weight updated:", ip, port, weight)
			return
		}
	}

	log.Println("backend not found:", ip, port)
}

func listBackends(objs *lb4Objects) {

	var count uint32
	key := uint32(0)

	objs.lb4Maps.BackendCount.Lookup(key, &count)

	for i := uint32(0); i < count; i++ {

		var b lb4Backend
		err := objs.lb4Maps.Backends.Lookup(i, &b)
		if err != nil {
			continue
		}

		ip := make(net.IP, 4)
		binary.LittleEndian.PutUint32(ip, b.Ip)

		fmt.Println(i, ip, "port:", htons(b.Port), "conns:", b.Conns, "weight:", b.Weight)
	}
}

func main() {

	flag.StringVar(&ifname, "i", "lo", "Network interface")

	var configFile string
	flag.StringVar(&configFile, "config", "configs/backends_wlc.json", "Backend configuration")
	flag.Parse()

	data, _ := os.ReadFile(configFile)

	var cfg Config
	json.Unmarshal(data, &cfg)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	rlimit.RemoveMemlock()

	var objs lb4Objects
	loadLb4Objects(&objs, nil)
	defer objs.Close()

	addService(&objs, cfg.Service.VIP, cfg.Service.Port)

	for i, be := range cfg.Backends {

		ip, _ := parseIPv4(be.IP)

		backEp := lb4Backend{
			Ip:     ip,
			Port:   htons(be.Port),
			Conns:  0,
			Weight: be.Weight,
		}

		objs.lb4Maps.Backends.Put(uint32(i), &backEp)
	}

	key := uint32(0)
	objs.lb4Maps.BackendCount.Put(key, uint32(len(cfg.Backends)))

	iface, _ := net.InterfaceByName(ifname)

	xdplink, _ := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpLoadBalancer,
		Interface: iface.Index,
		Flags:     link.XDPGenericMode,
	})
	defer xdplink.Close()

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
					w, _ := strconv.Atoi(parts[3])
					addBackend(&objs, parts[1], uint16(p), uint16(w))

				case "del":
					p, _ := strconv.Atoi(parts[2])
					deleteBackend(&objs, parts[1], uint16(p))

				case "update":
					p, _ := strconv.Atoi(parts[2])
					w, _ := strconv.Atoi(parts[3])
					updateBackend(&objs, parts[1], uint16(p), uint16(w))

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
				}
			}
		}
	}()

	<-ctx.Done()
}