package main

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"strconv"

	pb "lb/proto"

	"github.com/cilium/ebpf"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

const (
	pinDir   = "/sys/fs/bpf/lbxdp"
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

Backend commands (pinned map access, works with lc and wlc):
  lbctl add    <ip> <port> [weight]   add backend (weight ignored in lc algo)
  lbctl del    <ip> <port>            remove backend (refused if active conns > 0)
  lbctl list                          list backends with connection counts

Service commands (pinned map access, works with lc and wlc):
  lbctl addsvc  <vip> <port>          register a virtual IP
  lbctl delsvc  <vip> <port>          deregister a virtual IP
  lbctl listsvc                       list registered VIPs

Weight command (gRPC, wlc algo only):
  lbctl weight <ip> <port> <weight>   update a backend's weight live`)
}

// ── gRPC path (wlc weight updates) ───────────────────────────────────────────

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
		fatalf("connect to wlc daemon: %v", err)
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

// ── pinned map path (backends + services) ────────────────────────────────────

// lcBackend matches lbBackend/lb2Backend — no Weight field.
type lcBackend struct {
	Ip    uint32
	Port  uint16
	Pad   uint16
	Conns uint32
}

// wlcBackend matches lb3Backend/lb4Backend — has Weight field.
// Layout must match the C struct exactly.
type wlcBackend struct {
	Ip     uint32
	Port   uint16
	Weight uint16
	Conns  uint32
}

// serviceKey matches lbIpPort/lb2IpPort/lb3IpPort/lb4IpPort.
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

	// selection_array and next_id are only present in wlc mode.
	var selectionMap, nextIDMap *ebpf.Map
	if mode == "wlc" {
		selectionMap, err = ebpf.LoadPinnedMap(pinDir+"/selection_array", nil)
		if err != nil {
			fatalf("open selection_array map: %v", err)
		}
		defer selectionMap.Close()

		nextIDMap, err = ebpf.LoadPinnedMap(pinDir+"/next_id", nil)
		if err != nil {
			fatalf("open next_id map: %v", err)
		}
		defer nextIDMap.Close()
	}

	switch os.Args[1] {

	// ── backend commands ──────────────────────────────────────────────────────

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
		addBackend(backendsMap, countMap, selectionMap, nextIDMap, ip, port, weight, mode)

	case "del":
		if len(os.Args) < 4 {
			fatalf("usage: lbctl del <ip> <port>")
		}
		ip   := parseIPv4(os.Args[2])
		port := mustPort(os.Args[3])
		delBackend(backendsMap, countMap, selectionMap, ip, port, mode)

	case "list":
		listBackends(backendsMap, countMap, selectionMap, mode)

	// ── service commands ──────────────────────────────────────────────────────

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

// readMode reads the sentinel written by the daemon at startup.
// Returns "lc" or "wlc". Defaults to "lc" if the file is missing.
func readMode() string {
	data, err := os.ReadFile("/run/lbxdp.mode")
	if err != nil {
		return "lc"
	}
	return string(data)
}

// ── backend operations ────────────────────────────────────────────────────────

func addBackend(backendsMap, countMap, selectionMap, nextIDMap *ebpf.Map,
	ip uint32, port, weight uint16, mode string) {

	var count uint32
	if err := countMap.Lookup(uint32(0), &count); err != nil {
		fatalf("lookup count: %v", err)
	}

	if mode == "wlc" {
		// Duplicate check: walk selection_array, look up each ID in backends hash.
		if wlcFindPos(backendsMap, selectionMap, count, ip, port) >= 0 {
			fatalf("backend %s:%d already exists", ipToStr(ip), ntohs(port))
		}
		// Allocate next stable ID from pinned next_id map.
		var nextID uint32
		if err := nextIDMap.Lookup(uint32(0), &nextID); err != nil {
			fatalf("lookup next_id: %v", err)
		}
		id := nextID
		nextID++
		if err := nextIDMap.Update(uint32(0), &nextID, ebpf.UpdateExist); err != nil {
			fatalf("update next_id: %v", err)
		}
		// Insert into backends hash map keyed by stable ID.
		be := wlcBackend{Ip: ip, Port: htons(port), Weight: weight, Conns: 0}
		if err := backendsMap.Update(&id, &be, ebpf.UpdateAny); err != nil {
			fatalf("insert backend: %v", err)
		}
		// Append new ID into selection_array at position count.
		if err := selectionMap.Update(count, &id, ebpf.UpdateAny); err != nil {
			fatalf("update selection_array: %v", err)
		}
	} else {
		// lc mode: backends is still an array map keyed by position.
		if lcFindPos(backendsMap, count, ip, port) >= 0 {
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

func delBackend(backendsMap, countMap, selectionMap *ebpf.Map,
	ip uint32, port uint16, mode string) {

	var count uint32
	if err := countMap.Lookup(uint32(0), &count); err != nil {
		fatalf("lookup count: %v", err)
	}

	if mode == "wlc" {
		pos := wlcFindPos(backendsMap, selectionMap, count, ip, port)
		if pos < 0 {
			fatalf("backend %s:%d not found", ipToStr(ip), ntohs(port))
		}
		// Read the stable ID sitting at this position.
		var id uint32
		if err := selectionMap.Lookup(uint32(pos), &id); err != nil {
			fatalf("lookup id at pos %d: %v", pos, err)
		}
		// Refuse if active connections remain.
		var b wlcBackend
		if err := backendsMap.Lookup(&id, &b); err != nil {
			fatalf("lookup backend: %v", err)
		}
		if b.Conns != 0 {
			fatalf("backend has %d active connections — refusing delete", b.Conns)
		}
		last := count - 1
		if uint32(pos) != last {
			// Swap the last ID in selection_array into the deleted position.
			var lastID uint32
			if err := selectionMap.Lookup(last, &lastID); err != nil {
				fatalf("lookup last id: %v", err)
			}
			if err := selectionMap.Update(uint32(pos), &lastID, ebpf.UpdateExist); err != nil {
				fatalf("swap selection_array: %v", err)
			}
		}
		// Zero the last slot — selection_array is an array map, no Delete.
		zero := uint32(0)
		if err := selectionMap.Update(last, &zero, ebpf.UpdateExist); err != nil {
			fatalf("zero selection_array last slot: %v", err)
		}
		// Delete from backends hash map by stable ID — real delete.
		if err := backendsMap.Delete(&id); err != nil {
			fatalf("delete backend: %v", err)
		}
	} else {
		// lc mode: plain array swap, same as original.
		idx := lcFindPos(backendsMap, count, ip, port)
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

func listBackends(backendsMap, countMap, selectionMap *ebpf.Map, mode string) {
	var count uint32
	if err := countMap.Lookup(uint32(0), &count); err != nil {
		fatalf("lookup count: %v", err)
	}
	if count == 0 {
		fmt.Println("no backends registered")
		return
	}
	if mode == "wlc" {
		// Walk selection_array[0..count), get stable ID at each position,
		// look up the backend struct from the hash map by that ID.
		for i := uint32(0); i < count; i++ {
			var id uint32
			if err := selectionMap.Lookup(i, &id); err != nil {
				fatalf("selection_array lookup pos %d: %v", i, err)
			}
			var b wlcBackend
			if err := backendsMap.Lookup(&id, &b); err != nil {
				fatalf("backends lookup id %d: %v", id, err)
			}
			fmt.Printf("%d: %s:%d  weight=%d  conns=%d\n",
				id, ipToStr(b.Ip), ntohs(b.Port), b.Weight, b.Conns)
		}
	} else {
		// lc mode: backends is a plain array map, index directly.
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

// wlcFindPos walks selection_array[0..count) and returns the position whose
// stable ID maps to the backend with the given ip:port, or -1 if not found.
func wlcFindPos(backendsMap, selectionMap *ebpf.Map, count uint32,
	ip uint32, port uint16) int {

	for i := uint32(0); i < count; i++ {
		var id uint32
		if err := selectionMap.Lookup(i, &id); err != nil {
			continue
		}
		var b wlcBackend
		if err := backendsMap.Lookup(&id, &b); err != nil {
			continue
		}
		if b.Ip == ip && b.Port == htons(port) {
			return int(i)
		}
	}
	return -1
}

// lcFindPos is the original linear scan for lc mode (array map, keyed by pos).
func lcFindPos(backendsMap *ebpf.Map, count uint32, ip uint32, port uint16) int {
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