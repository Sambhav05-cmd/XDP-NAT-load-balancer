package main

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"

	pb "lb/proto"

	"github.com/cilium/ebpf"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

const (
	pinDir     = "/sys/fs/bpf/lbxdp"
	daemonSock = "/var/run/lbxdpd.sock"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}
	switch os.Args[1] {
	case "add", "del", "list", "addsvc", "delsvc", "listsvc":
		runMapMode()
	case "weight":
		runGRPCCmd()
	default:
		usage()
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `lbctl — XDP load balancer control

Backend commands (pinned map access, works with lc, wlc, rr, and wrr):
  lbctl add    <ip> <port> [weight]   add backend (weight ignored in lc/rr algo)
  lbctl del    <ip> <port>            remove backend (refused if active conns > 0)
  lbctl list                          list backends with connection counts

Service commands (pinned map access, works with lc, wlc, rr, and wrr):
  lbctl addsvc  <vip> <port>          register a virtual IP
  lbctl delsvc  <vip> <port>          deregister a virtual IP
  lbctl listsvc                       list registered VIPs

Weight command (gRPC, wlc/wrr algo only):
  lbctl weight <ip> <port> <weight>   update a backend's weight live`)
}

// ── gRPC path ─────────────────────────────────────────────────────────────────

func runGRPCCmd() {
	if len(os.Args) < 5 {
		fatalf("usage: lbctl weight <ip> <port> <weight>")
	}
	ip     := os.Args[2]
	port   := mustPort(os.Args[3])
	weight := mustUint16(os.Args[4], "weight")

	conn, err := grpc.NewClient("unix://"+daemonSock,
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		fatalf("connect to daemon: %v", err)
	}
	defer conn.Close()

	c := pb.NewWeightControlClient(conn)
	_, err = c.UpdateWeight(context.Background(), &pb.WeightRequest{
		Ip:     ip,
		Port:   uint32(port),
		Weight: uint32(weight),
	})
	if err != nil {
		fatalf("UpdateWeight: %v", err)
	}
	fmt.Printf("weight updated: %s:%d → %d\n", ip, port, weight)
}

// ── pinned map path ───────────────────────────────────────────────────────────

// lcBackend matches lbBackend/lb2Backend/lb5Backend/lb6Backend.
// C layout: ip(4) port(2) pad(2) conns(4)
// Port stored as htons.
type lcBackend struct {
	Ip    uint32
	Port  uint16
	Pad   uint16
	Conns uint32
}

// wlcBackend matches lb3Backend/lb4Backend.
// C layout: ip(4) port(2) weight(2) conns(4)  — 12 bytes, no padding.
// Port stored as htons.
type wlcBackend struct {
	Ip     uint32
	Port   uint16
	Weight uint16
	Conns  uint32
}

// wrrBackend matches lb7Backend/lb8Backend — same as wlcBackend + UsedCount.
// C layout: ip(4) port(2) pad(2) conns(4) weight(2) pad(2) used_count(4)
// Port stored as htons.
type wrrBackend struct {
	Ip        uint32
	Port      uint16
	Pad0      uint16
	Conns     uint32
	Weight    uint16
	Pad1      uint16
	UsedCount uint32
}

// serviceKey matches all IpPort types.
// C layout: ip(4) port(2) pad(2)
type serviceKey struct {
	Ip   uint32
	Port uint16
	Pad  uint16
}

func runMapMode() {
	mode := readMode()

	backendsMap, err := ebpf.LoadPinnedMap(pinDir+"/backends", nil)
	if err != nil {
		fatalf("open backends map: %v\n(is the daemon running?)", err)
	}
	defer backendsMap.Close()

	countMap, err := ebpf.LoadPinnedMap(pinDir+"/backend_count", nil)
	if err != nil {
		fatalf("open backend_count map: %v", err)
	}
	defer countMap.Close()

	servicesMap, err := ebpf.LoadPinnedMap(pinDir+"/services", nil)
	if err != nil {
		fatalf("open services map: %v", err)
	}
	defer servicesMap.Close()

	var conntrackMap *ebpf.Map
	if (mode == "wlc" || mode == "wrr") && len(os.Args) >= 2 && os.Args[1] == "del" {
		conntrackMap = findConntrackMap()
		if conntrackMap != nil {
			defer conntrackMap.Close()
		} else {
			fmt.Fprintln(os.Stderr, "warning: could not find conntrack map, BackendIdx will not be patched")
		}
	}

	switch os.Args[1] {

	case "add":
		if len(os.Args) < 4 {
			fatalf("usage: lbctl add <ip> <port> [weight]")
		}
		ip     := parseIPv4(os.Args[2])
		port   := mustPort(os.Args[3])
		weight := uint16(1)
		if len(os.Args) >= 5 {
			weight = mustUint16(os.Args[4], "weight")
		}
		addBackend(backendsMap, countMap, ip, port, weight, mode)

	case "del":
		if len(os.Args) < 4 {
			fatalf("usage: lbctl del <ip> <port>")
		}
		ip   := parseIPv4(os.Args[2])
		port := mustPort(os.Args[3])
		delBackend(backendsMap, countMap, conntrackMap, ip, port, mode)

	case "list":
		listBackends(backendsMap, countMap, mode)

	case "addsvc":
		if len(os.Args) < 4 {
			fatalf("usage: lbctl addsvc <vip> <port>")
		}
		ip   := parseIPv4(os.Args[2])
		port := mustPort(os.Args[3])
		key  := serviceKey{Ip: ip, Port: htons(port)}
		val  := true
		if err := servicesMap.Update(&key, &val, ebpf.UpdateAny); err != nil {
			fatalf("addsvc: %v", err)
		}
		fmt.Printf("service added: %s:%d\n", os.Args[2], port)

	case "delsvc":
		if len(os.Args) < 4 {
			fatalf("usage: lbctl delsvc <vip> <port>")
		}
		ip   := parseIPv4(os.Args[2])
		port := mustPort(os.Args[3])
		key  := serviceKey{Ip: ip, Port: htons(port)}
		if err := servicesMap.Delete(&key); err != nil {
			fatalf("delsvc: %v", err)
		}
		fmt.Printf("service deleted: %s:%d\n", os.Args[2], port)

	case "listsvc":
		iter := servicesMap.Iterate()
		var k serviceKey
		var v bool
		found := false
		for iter.Next(&k, &v) {
			fmt.Printf("service: %s  port: %d\n", ipToStr(k.Ip), ntohs(k.Port))
			found = true
		}
		if err := iter.Err(); err != nil {
			fatalf("iterate services: %v", err)
		}
		if !found {
			fmt.Println("no services registered")
		}
	}
}

func readMode() string {
	data, err := os.ReadFile("/run/lbxdp.mode")
	if err != nil {
		return "lc"
	}
	return string(data)
}

// ── backend operations ────────────────────────────────────────────────────────
//
// Port convention (mirrors variants.go exactly):
//   all algos → stored as htons; lbctl writes htons, compares with htons, displays with ntohs

func addBackend(backendsMap, countMap *ebpf.Map, ip uint32, port, weight uint16, mode string) {
	var count uint32
	if err := countMap.Lookup(uint32(0), &count); err != nil {
		fatalf("lookup count: %v", err)
	}

	switch mode {
	case "wlc":
		if wlcFindIdx(backendsMap, count, ip, port) >= 0 {
			fatalf("backend %s:%d already exists", ipToStr(ip), port)
		}
		be := wlcBackend{Ip: ip, Port: htons(port), Conns: 0, Weight: weight}
		if err := backendsMap.Update(count, &be, ebpf.UpdateAny); err != nil {
			fatalf("insert backend: %v", err)
		}
	case "wrr":
		if wrrFindIdx(backendsMap, count, ip, port) >= 0 {
			fatalf("backend %s:%d already exists", ipToStr(ip), port)
		}
		be := wrrBackend{Ip: ip, Port: htons(port), Conns: 0, Weight: weight, UsedCount: 0}
		if err := backendsMap.Update(count, &be, ebpf.UpdateAny); err != nil {
			fatalf("insert backend: %v", err)
		}
	default: // lc and rr
		if lcFindIdx(backendsMap, count, ip, port) >= 0 {
			fatalf("backend %s:%d already exists", ipToStr(ip), ntohs(port))
		}
		be := lcBackend{Ip: ip, Port: htons(port), Conns: 0}
		if err := backendsMap.Update(count, &be, ebpf.UpdateAny); err != nil {
			fatalf("insert backend: %v", err)
		}
	}

	count++
	if err := countMap.Update(uint32(0), &count, ebpf.UpdateExist); err != nil {
		fatalf("update count: %v", err)
	}
	fmt.Printf("backend added: %s:%d\n", ipToStr(ip), ntohs(port))
}

func delBackend(backendsMap, countMap, conntrackMap *ebpf.Map, ip uint32, port uint16, mode string) {
	var count uint32
	if err := countMap.Lookup(uint32(0), &count); err != nil {
		fatalf("lookup count: %v", err)
	}

	switch mode {
	case "wlc":
		idx := wlcFindIdx(backendsMap, count, ip, port)
		if idx < 0 {
			fatalf("backend %s:%d not found", ipToStr(ip), port)
		}
		var cur wlcBackend
		if err := backendsMap.Lookup(uint32(idx), &cur); err != nil {
			fatalf("lookup backend: %v", err)
		}
		if cur.Conns != 0 {
			fatalf("backend has %d active connections — refusing delete", cur.Conns)
		}
		last := count - 1
		if uint32(idx) != last {
			var lb wlcBackend
			if err := backendsMap.Lookup(last, &lb); err != nil {
				fatalf("lookup last: %v", err)
			}
			if err := backendsMap.Update(uint32(idx), &lb, ebpf.UpdateExist); err != nil {
				fatalf("swap: %v", err)
			}
			if conntrackMap != nil {
				if err := patchConntrackRaw(conntrackMap, last, uint32(idx)); err != nil {
					fatalf("patch conntrack: %v", err)
				}
			}
		}
		zero := wlcBackend{}
		if err := backendsMap.Update(last, &zero, ebpf.UpdateExist); err != nil {
			fatalf("zero last slot: %v", err)
		}

	case "wrr":
		idx := wrrFindIdx(backendsMap, count, ip, port)
		if idx < 0 {
			fatalf("backend %s:%d not found", ipToStr(ip), port)
		}
		var cur wrrBackend
		if err := backendsMap.Lookup(uint32(idx), &cur); err != nil {
			fatalf("lookup backend: %v", err)
		}
		if cur.Conns != 0 {
			fatalf("backend has %d active connections — refusing delete", cur.Conns)
		}
		last := count - 1
		if uint32(idx) != last {
			var lb wrrBackend
			if err := backendsMap.Lookup(last, &lb); err != nil {
				fatalf("lookup last: %v", err)
			}
			if err := backendsMap.Update(uint32(idx), &lb, ebpf.UpdateExist); err != nil {
				fatalf("swap: %v", err)
			}
			if conntrackMap != nil {
				if err := patchConntrackRaw(conntrackMap, last, uint32(idx)); err != nil {
					fatalf("patch conntrack: %v", err)
				}
			}
		}
		zero := wrrBackend{}
		if err := backendsMap.Update(last, &zero, ebpf.UpdateExist); err != nil {
			fatalf("zero last slot: %v", err)
		}

	default: // lc and rr
		idx := lcFindIdx(backendsMap, count, ip, port)
		if idx < 0 {
			fatalf("backend %s:%d not found", ipToStr(ip), ntohs(port))
		}
		var cur lcBackend
		if err := backendsMap.Lookup(uint32(idx), &cur); err != nil {
			fatalf("lookup backend: %v", err)
		}
		if cur.Conns != 0 {
			fatalf("backend has %d active connections — refusing delete", cur.Conns)
		}
		last := count - 1
		if uint32(idx) != last {
			var lb lcBackend
			if err := backendsMap.Lookup(last, &lb); err != nil {
				fatalf("lookup last: %v", err)
			}
			if err := backendsMap.Update(uint32(idx), &lb, ebpf.UpdateExist); err != nil {
				fatalf("swap: %v", err)
			}
		}
		zero := lcBackend{}
		if err := backendsMap.Update(last, &zero, ebpf.UpdateExist); err != nil {
			fatalf("zero last slot: %v", err)
		}
	}

	count--
	if err := countMap.Update(uint32(0), &count, ebpf.UpdateExist); err != nil {
		fatalf("update count: %v", err)
	}
	fmt.Printf("backend deleted: %s:%d\n", ipToStr(ip), ntohs(port))
}

func listBackends(backendsMap, countMap *ebpf.Map, mode string) {
	var count uint32
	if err := countMap.Lookup(uint32(0), &count); err != nil {
		fatalf("lookup count: %v", err)
	}
	if count == 0 {
		fmt.Println("no backends registered")
		return
	}
	switch mode {
	case "wlc":
		for i := uint32(0); i < count; i++ {
			var b wlcBackend
			if err := backendsMap.Lookup(i, &b); err != nil {
				continue
			}
			fmt.Printf("%d: %s:%d  weight=%d  conns=%d\n",
				i, ipToStr(b.Ip), ntohs(b.Port), b.Weight, b.Conns)
		}
	case "wrr":
		for i := uint32(0); i < count; i++ {
			var b wrrBackend
			if err := backendsMap.Lookup(i, &b); err != nil {
				continue
			}
			fmt.Printf("%d: %s:%d  weight=%d  used=%d  conns=%d\n",
				i, ipToStr(b.Ip), ntohs(b.Port), b.Weight, b.UsedCount, b.Conns)
		}
	default: // lc and rr — port stored as htons, must ntohs to display
		for i := uint32(0); i < count; i++ {
			var b lcBackend
			if err := backendsMap.Lookup(i, &b); err != nil {
				continue
			}
			fmt.Printf("%d: %s:%d  conns=%d\n",
				i, ipToStr(b.Ip), ntohs(b.Port), b.Conns)
		}
	}
}

// wlcFindIdx: port stored as htons — compare htons vs htons.
func wlcFindIdx(backendsMap *ebpf.Map, count uint32, ip uint32, port uint16) int {
	for i := uint32(0); i < count; i++ {
		var b wlcBackend
		if err := backendsMap.Lookup(i, &b); err != nil {
			continue
		}
		if b.Ip == ip && b.Port == htons(port) {
			return int(i)
		}
	}
	return -1
}

// wrrFindIdx: port stored as htons — compare htons vs htons.
func wrrFindIdx(backendsMap *ebpf.Map, count uint32, ip uint32, port uint16) int {
	for i := uint32(0); i < count; i++ {
		var b wrrBackend
		if err := backendsMap.Lookup(i, &b); err != nil {
			continue
		}
		if b.Ip == ip && b.Port == htons(port) {
			return int(i)
		}
	}
	return -1
}

// lcFindIdx: port stored as htons — compare htons vs htons.
func lcFindIdx(backendsMap *ebpf.Map, count uint32, ip uint32, port uint16) int {
	for i := uint32(0); i < count; i++ {
		var b lcBackend
		if err := backendsMap.Lookup(i, &b); err != nil {
			continue
		}
		if b.Ip == ip && b.Port == htons(port) {
			return int(i)
		}
	}
	return -1
}

// ── conntrack patching ────────────────────────────────────────────────────────

func findConntrackMap() *ebpf.Map {
	progID := ebpf.ProgramID(0)
	for {
		nextID, err := ebpf.ProgramGetNextID(progID)
		if err != nil {
			break
		}
		progID = nextID

		prog, err := ebpf.NewProgramFromID(progID)
		if err != nil {
			continue
		}
		info, err := prog.Info()
		prog.Close()
		if err != nil || !strings.HasPrefix(info.Name, "xdp_load_bal") {
			continue
		}

		mapIDs, _ := info.MapIDs()
		for _, mid := range mapIDs {
			m, err := ebpf.NewMapFromID(mid)
			if err != nil {
				continue
			}
			minfo, err := m.Info()
			if err != nil {
				m.Close()
				continue
			}
			if minfo.Name == "conntrack" {
				return m
			}
			m.Close()
		}
	}
	return nil
}

type ctKey struct {
	Ip   uint32
	Port uint16
	Pad  uint16
}

type ctVal struct {
	Ip          uint32
	Port        uint16
	Pad0        uint16
	BackendIdx  uint32
	State       uint8
	Pad1        uint8
	ServicePort uint16
}

func patchConntrackRaw(conntrackMap *ebpf.Map, oldIdx, newIdx uint32) error {
	type kv struct {
		k ctKey
		v ctVal
	}
	var patches []kv
	iter := conntrackMap.Iterate()
	var k ctKey
	var v ctVal
	for iter.Next(&k, &v) {
		if v.BackendIdx == oldIdx {
			v.BackendIdx = newIdx
			patches = append(patches, kv{k, v})
		}
	}
	if err := iter.Err(); err != nil {
		return fmt.Errorf("iterate: %w", err)
	}
	for _, p := range patches {
		pk, pv := p.k, p.v
		if err := conntrackMap.Update(&pk, &pv, ebpf.UpdateExist); err != nil {
			return fmt.Errorf("update: %w", err)
		}
	}
	fmt.Printf("patched %d conntrack entries: BackendIdx %d → %d\n", len(patches), oldIdx, newIdx)
	return nil
}

// ── net / parse helpers ───────────────────────────────────────────────────────

func parseIPv4(s string) uint32 {
	ip := net.ParseIP(s).To4()
	if ip == nil {
		fatalf("invalid IP address: %q", s)
	}
	return binary.LittleEndian.Uint32(ip)
}

func ipToStr(i uint32) string {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, i)
	return net.IP(b).String()
}

func htons(p uint16) uint16 { return (p<<8)&0xff00 | p>>8 }
func ntohs(p uint16) uint16 { return htons(p) }

func mustPort(s string) uint16 {
	p, err := strconv.Atoi(s)
	if err != nil || p < 1 || p > 65535 {
		fatalf("invalid port: %q", s)
	}
	return uint16(p)
}

func mustUint16(s, name string) uint16 {
	v, err := strconv.Atoi(s)
	if err != nil || v < 0 || v > 65535 {
		fatalf("invalid %s: %q", name, s)
	}
	return uint16(v)
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "lbctl: "+format+"\n", args...)
	os.Exit(1)
}