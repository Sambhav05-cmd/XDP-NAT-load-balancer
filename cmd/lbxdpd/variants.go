package main

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"os"

	"github.com/cilium/ebpf"
)

// ── config types ──────────────────────────────────────────────────────────────

// backendCfg covers both lc (weight ignored) and wlc (weight honoured).
type backendCfg struct {
	IP     string `json:"ip"`
	Port   uint16 `json:"port"`
	Weight uint16 `json:"weight"` // optional; defaults to 1 in wlc/wrr mode
}

type serviceCfg struct {
	VIP  string `json:"vip"`
	Port uint16 `json:"port"`
}

type config struct {
	Service  serviceCfg   `json:"service"`
	Backends []backendCfg `json:"backends"`
}

// ── shared helpers ────────────────────────────────────────────────────────────

func parseIPv4Cfg(s string) (uint32, error) {
	ip := net.ParseIP(s).To4()
	if ip == nil {
		return 0, fmt.Errorf("invalid IPv4: %q", s)
	}
	return binary.LittleEndian.Uint32(ip), nil
}

func htons(p uint16) uint16 { return (p<<8)&0xff00 | p>>8 }

func defaultWeight(w uint16) uint16 {
	if w == 0 {
		return 1
	}
	return w
}

const (
	pinDir       = "/sys/fs/bpf/lbxdp"
	sentinelPath = "/run/lbxdp.mode"
)

func pinMaps(pins map[string]*ebpf.Map, modeName string) error {
	if err := os.MkdirAll(pinDir, 0755); err != nil {
		return fmt.Errorf("mkdir %s: %w", pinDir, err)
	}
	for path, m := range pins {
		if err := m.Pin(path); err != nil {
			return fmt.Errorf("pin %s: %w", path, err)
		}
	}
	return os.WriteFile(sentinelPath, []byte(modeName), 0644)
}

func loadConfig(cfgPath string) (config, error) {
	var cfg config
	data, err := os.ReadFile(cfgPath)
	if err != nil {
		return cfg, fmt.Errorf("read config %q: %w", cfgPath, err)
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		return cfg, fmt.Errorf("parse config %q: %w", cfgPath, err)
	}
	return cfg, nil
}

// initSchedulerState zeroes the scheduler_state map (index 0 → 0).
// Required by rr and wrr variants so the round-robin counter starts clean.
func initSchedulerState(m *ebpf.Map) error {
	zero := uint32(0)
	if err := m.Update(uint32(0), &zero, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("init scheduler_state: %w", err)
	}
	return nil
}

// patchConntrackLb3 scans the lb3 conntrack map and rewrites every entry
// whose BackendIdx == oldIdx to newIdx.
func patchConntrackLb3(conntrack *ebpf.Map, oldIdx, newIdx uint32) error {
	type kv struct {
		key lb3IpPort
		val lb3ConnMeta
	}
	var patches []kv
	iter := conntrack.Iterate()
	var k lb3IpPort
	var v lb3ConnMeta
	for iter.Next(&k, &v) {
		if v.BackendIdx == oldIdx {
			v.BackendIdx = newIdx
			patches = append(patches, kv{k, v})
		}
	}
	if err := iter.Err(); err != nil {
		return fmt.Errorf("iterate conntrack: %w", err)
	}
	for _, p := range patches {
		pk, pv := p.key, p.val
		if err := conntrack.Update(&pk, &pv, ebpf.UpdateExist); err != nil {
			return fmt.Errorf("patch conntrack entry: %w", err)
		}
	}
	return nil
}

// patchConntrackLb4 is identical to patchConntrackLb3 but uses lb4 types.
func patchConntrackLb4(conntrack *ebpf.Map, oldIdx, newIdx uint32) error {
	type kv struct {
		key lb4IpPort
		val lb4ConnMeta
	}
	var patches []kv
	iter := conntrack.Iterate()
	var k lb4IpPort
	var v lb4ConnMeta
	for iter.Next(&k, &v) {
		if v.BackendIdx == oldIdx {
			v.BackendIdx = newIdx
			patches = append(patches, kv{k, v})
		}
	}
	if err := iter.Err(); err != nil {
		return fmt.Errorf("iterate conntrack: %w", err)
	}
	for _, p := range patches {
		pk, pv := p.key, p.val
		if err := conntrack.Update(&pk, &pv, ebpf.UpdateExist); err != nil {
			return fmt.Errorf("patch conntrack entry: %w", err)
		}
	}
	return nil
}

// patchConntrackLb7 uses lb7 types (wrr-est).
func patchConntrackLb7(conntrack *ebpf.Map, oldIdx, newIdx uint32) error {
	type kv struct {
		key lb7IpPort
		val lb7ConnMeta
	}
	var patches []kv
	iter := conntrack.Iterate()
	var k lb7IpPort
	var v lb7ConnMeta
	for iter.Next(&k, &v) {
		if v.BackendIdx == oldIdx {
			v.BackendIdx = newIdx
			patches = append(patches, kv{k, v})
		}
	}
	if err := iter.Err(); err != nil {
		return fmt.Errorf("iterate conntrack: %w", err)
	}
	for _, p := range patches {
		pk, pv := p.key, p.val
		if err := conntrack.Update(&pk, &pv, ebpf.UpdateExist); err != nil {
			return fmt.Errorf("patch conntrack entry: %w", err)
		}
	}
	return nil
}

// patchConntrackLb8 uses lb8 types (wrr-syn).
func patchConntrackLb8(conntrack *ebpf.Map, oldIdx, newIdx uint32) error {
	type kv struct {
		key lb8IpPort
		val lb8ConnMeta
	}
	var patches []kv
	iter := conntrack.Iterate()
	var k lb8IpPort
	var v lb8ConnMeta
	for iter.Next(&k, &v) {
		if v.BackendIdx == oldIdx {
			v.BackendIdx = newIdx
			patches = append(patches, kv{k, v})
		}
	}
	if err := iter.Err(); err != nil {
		return fmt.Errorf("iterate conntrack: %w", err)
	}
	for _, p := range patches {
		pk, pv := p.key, p.val
		if err := conntrack.Update(&pk, &pv, ebpf.UpdateExist); err != nil {
			return fmt.Errorf("patch conntrack entry: %w", err)
		}
	}
	return nil
}

// ── generic array-backend helpers ────────────────────────────────────────────

type (
	makeEntryFn func(ip uint32, port, weight uint16) interface{}
	getIPPortFn func(m *ebpf.Map, idx uint32) (ip uint32, port uint16, err error)
	getConnsFn  func(m *ebpf.Map, idx uint32) (conns uint32, err error)
	swapEntryFn func(m *ebpf.Map, dst, src uint32) error
	zeroEntryFn func() interface{}
)

func arrayAddBackend(backends, countMap *ebpf.Map,
	ip string, port, weight uint16,
	getIPPort getIPPortFn,
	make makeEntryFn,
	portXform func(uint16) uint16) error {

	pip, err := parseIPv4Cfg(ip)
	if err != nil {
		return err
	}
	var count uint32
	if err := countMap.Lookup(uint32(0), &count); err != nil {
		return fmt.Errorf("lookup count: %w", err)
	}
	storedPort := portXform(port)
	for i := uint32(0); i < count; i++ {
		bip, bport, err := getIPPort(backends, i)
		if err != nil {
			continue
		}
		if bip == pip && bport == storedPort {
			return fmt.Errorf("backend %s:%d already exists", ip, port)
		}
	}
	be := make(pip, storedPort, weight)
	if err := backends.Update(count, be, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("insert backend: %w", err)
	}
	count++
	if err := countMap.Update(uint32(0), &count, ebpf.UpdateExist); err != nil {
		return fmt.Errorf("update count: %w", err)
	}
	return nil
}

func arrayDeleteBackend(backends, countMap *ebpf.Map,
	ip string, port uint16,
	getIPPort getIPPortFn,
	getConns getConnsFn,
	swap swapEntryFn,
	zero zeroEntryFn,
	portXform func(uint16) uint16,
	patchCT func(oldIdx, newIdx uint32) error) error {

	pip, err := parseIPv4Cfg(ip)
	if err != nil {
		return err
	}
	var count uint32
	if err := countMap.Lookup(uint32(0), &count); err != nil {
		return fmt.Errorf("lookup count: %w", err)
	}
	storedPort := portXform(port)

	for i := uint32(0); i < count; i++ {
		bip, bport, err := getIPPort(backends, i)
		if err != nil {
			continue
		}
		if bip != pip || bport != storedPort {
			continue
		}
		conns, err := getConns(backends, i)
		if err != nil {
			return fmt.Errorf("lookup conns: %w", err)
		}
		if conns != 0 {
			return fmt.Errorf("backend %s:%d has %d active connections", ip, port, conns)
		}

		last := count - 1
		if i != last {
			if err := swap(backends, i, last); err != nil {
				return fmt.Errorf("swap: %w", err)
			}
			if patchCT != nil {
				if err := patchCT(last, i); err != nil {
					return fmt.Errorf("patch conntrack: %w", err)
				}
			}
		}

		if err := backends.Update(last, zero(), ebpf.UpdateExist); err != nil {
			return fmt.Errorf("zero last slot: %w", err)
		}
		count--
		if err := countMap.Update(uint32(0), &count, ebpf.UpdateExist); err != nil {
			return fmt.Errorf("update count: %w", err)
		}
		return nil
	}
	return fmt.Errorf("backend %s:%d not found", ip, port)
}

// ── LC-EST variant (lb / lb_lc_est.c) ────────────────────────────────────────

type lcEstVariant struct{ objs lbObjects }

func newLcEstVariant() (*lcEstVariant, error) {
	v := &lcEstVariant{}
	if err := loadLbObjects(&v.objs, nil); err != nil {
		return nil, fmt.Errorf("load BPF objects (lc-est): %w", err)
	}
	if err := pinMaps(map[string]*ebpf.Map{
		pinDir + "/backends":      v.objs.lbMaps.Backends,
		pinDir + "/backend_count": v.objs.lbMaps.BackendCount,
		pinDir + "/services":      v.objs.lbMaps.Services,
	}, "lc"); err != nil {
		v.objs.Close()
		return nil, err
	}
	return v, nil
}

func (v *lcEstVariant) Program() *ebpf.Program                          { return v.objs.XdpLoadBalancer }
func (v *lcEstVariant) Close()                                          { v.objs.Close() }
func (v *lcEstVariant) UpdateWeight(_ string, _ uint16, _ uint16) error { return nil }

func (v *lcEstVariant) Init(cfgPath string) error {
	if err := initPorts(func(p uint16) error {
		return v.objs.lbMaps.FreePorts.Update(nil, &p, ebpf.UpdateAny)
	}); err != nil {
		return fmt.Errorf("init ports: %w", err)
	}
	cfg, err := loadConfig(cfgPath)
	if err != nil {
		return err
	}
	if err := v.AddService(cfg.Service.VIP, cfg.Service.Port); err != nil {
		return fmt.Errorf("add service: %w", err)
	}
	for i, b := range cfg.Backends {
		ip, err := parseIPv4Cfg(b.IP)
		if err != nil {
			return fmt.Errorf("backend[%d] IP: %w", i, err)
		}
		be := lbBackend{Ip: ip, Port: htons(b.Port), Conns: 0}
		if err := v.objs.lbMaps.Backends.Update(uint32(i), &be, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("update backends[%d]: %w", i, err)
		}
	}
	cnt := uint32(len(cfg.Backends))
	return v.objs.lbMaps.BackendCount.Update(uint32(0), &cnt, ebpf.UpdateAny)
}

func (v *lcEstVariant) AddBackend(ip string, port uint16, _ uint16) error {
	return arrayAddBackend(v.objs.lbMaps.Backends, v.objs.lbMaps.BackendCount, ip, port, 0,
		func(m *ebpf.Map, idx uint32) (uint32, uint16, error) {
			var b lbBackend
			if err := m.Lookup(idx, &b); err != nil {
				return 0, 0, err
			}
			return b.Ip, b.Port, nil
		},
		func(ip uint32, port, _ uint16) interface{} {
			return &lbBackend{Ip: ip, Port: port, Conns: 0}
		},
		htons)
}

func (v *lcEstVariant) DeleteBackend(ip string, port uint16) error {
	return arrayDeleteBackend(
		v.objs.lbMaps.Backends, v.objs.lbMaps.BackendCount,
		ip, port,
		func(m *ebpf.Map, idx uint32) (uint32, uint16, error) {
			var b lbBackend
			if err := m.Lookup(idx, &b); err != nil {
				return 0, 0, err
			}
			return b.Ip, b.Port, nil
		},
		func(m *ebpf.Map, idx uint32) (uint32, error) {
			var b lbBackend
			if err := m.Lookup(idx, &b); err != nil {
				return 0, err
			}
			return b.Conns, nil
		},
		func(m *ebpf.Map, dst, src uint32) error {
			var b lbBackend
			if err := m.Lookup(src, &b); err != nil {
				return err
			}
			return m.Update(dst, &b, ebpf.UpdateExist)
		},
		func() interface{} { return &lbBackend{} },
		htons, nil)
}

func (v *lcEstVariant) AddService(ip string, port uint16) error {
	pip, err := parseIPv4Cfg(ip)
	if err != nil {
		return err
	}
	key := lbIpPort{Ip: pip, Port: htons(port)}
	val := true
	return v.objs.lbMaps.Services.Update(&key, &val, ebpf.UpdateAny)
}

func (v *lcEstVariant) DeleteService(ip string, port uint16) error {
	pip, err := parseIPv4Cfg(ip)
	if err != nil {
		return err
	}
	key := lbIpPort{Ip: pip, Port: htons(port)}
	return v.objs.lbMaps.Services.Delete(&key)
}

// ── LC-SYN variant (lb2 / lb_lc_syn.c) ───────────────────────────────────────

type lcSynVariant struct{ objs lb2Objects }

func newLcSynVariant() (*lcSynVariant, error) {
	v := &lcSynVariant{}
	if err := loadLb2Objects(&v.objs, nil); err != nil {
		return nil, fmt.Errorf("load BPF objects (lc-syn): %w", err)
	}
	if err := pinMaps(map[string]*ebpf.Map{
		pinDir + "/backends":      v.objs.lb2Maps.Backends,
		pinDir + "/backend_count": v.objs.lb2Maps.BackendCount,
		pinDir + "/services":      v.objs.lb2Maps.Services,
	}, "lc"); err != nil {
		v.objs.Close()
		return nil, err
	}
	return v, nil
}

func (v *lcSynVariant) Program() *ebpf.Program                          { return v.objs.XdpLoadBalancer }
func (v *lcSynVariant) Close()                                          { v.objs.Close() }
func (v *lcSynVariant) UpdateWeight(_ string, _ uint16, _ uint16) error { return nil }

func (v *lcSynVariant) Init(cfgPath string) error {
	if err := initPorts(func(p uint16) error {
		return v.objs.lb2Maps.FreePorts.Update(nil, &p, ebpf.UpdateAny)
	}); err != nil {
		return fmt.Errorf("init ports: %w", err)
	}
	cfg, err := loadConfig(cfgPath)
	if err != nil {
		return err
	}
	if err := v.AddService(cfg.Service.VIP, cfg.Service.Port); err != nil {
		return fmt.Errorf("add service: %w", err)
	}
	for i, b := range cfg.Backends {
		ip, err := parseIPv4Cfg(b.IP)
		if err != nil {
			return fmt.Errorf("backend[%d] IP: %w", i, err)
		}
		be := lb2Backend{Ip: ip, Port: htons(b.Port), Conns: 0}
		if err := v.objs.lb2Maps.Backends.Update(uint32(i), &be, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("update backends[%d]: %w", i, err)
		}
	}
	cnt := uint32(len(cfg.Backends))
	return v.objs.lb2Maps.BackendCount.Update(uint32(0), &cnt, ebpf.UpdateAny)
}

func (v *lcSynVariant) AddBackend(ip string, port uint16, _ uint16) error {
	return arrayAddBackend(v.objs.lb2Maps.Backends, v.objs.lb2Maps.BackendCount, ip, port, 0,
		func(m *ebpf.Map, idx uint32) (uint32, uint16, error) {
			var b lb2Backend
			if err := m.Lookup(idx, &b); err != nil {
				return 0, 0, err
			}
			return b.Ip, b.Port, nil
		},
		func(ip uint32, port, _ uint16) interface{} {
			return &lb2Backend{Ip: ip, Port: port, Conns: 0}
		},
		htons)
}

func (v *lcSynVariant) DeleteBackend(ip string, port uint16) error {
	return arrayDeleteBackend(
		v.objs.lb2Maps.Backends, v.objs.lb2Maps.BackendCount,
		ip, port,
		func(m *ebpf.Map, idx uint32) (uint32, uint16, error) {
			var b lb2Backend
			if err := m.Lookup(idx, &b); err != nil {
				return 0, 0, err
			}
			return b.Ip, b.Port, nil
		},
		func(m *ebpf.Map, idx uint32) (uint32, error) {
			var b lb2Backend
			if err := m.Lookup(idx, &b); err != nil {
				return 0, err
			}
			return b.Conns, nil
		},
		func(m *ebpf.Map, dst, src uint32) error {
			var b lb2Backend
			if err := m.Lookup(src, &b); err != nil {
				return err
			}
			return m.Update(dst, &b, ebpf.UpdateExist)
		},
		func() interface{} { return &lb2Backend{} },
		htons, nil)
}

func (v *lcSynVariant) AddService(ip string, port uint16) error {
	pip, err := parseIPv4Cfg(ip)
	if err != nil {
		return err
	}
	key := lb2IpPort{Ip: pip, Port: htons(port)}
	val := true
	return v.objs.lb2Maps.Services.Update(&key, &val, ebpf.UpdateAny)
}

func (v *lcSynVariant) DeleteService(ip string, port uint16) error {
	pip, err := parseIPv4Cfg(ip)
	if err != nil {
		return err
	}
	key := lb2IpPort{Ip: pip, Port: htons(port)}
	return v.objs.lb2Maps.Services.Delete(&key)
}

// ── WLC-EST variant (lb3 / lb_wlc_est.c) ─────────────────────────────────────
// struct backend layout: { ip, port, weight, conns }
// Port stored as htons — BPF C reads b->port directly into packet.

type wlcEstVariant struct{ objs lb3Objects }

func newWlcEstVariant() (*wlcEstVariant, error) {
	v := &wlcEstVariant{}
	if err := loadLb3Objects(&v.objs, nil); err != nil {
		return nil, fmt.Errorf("load BPF objects (wlc-est): %w", err)
	}
	if err := pinMaps(map[string]*ebpf.Map{
		pinDir + "/backends":      v.objs.lb3Maps.Backends,
		pinDir + "/backend_count": v.objs.lb3Maps.BackendCount,
		pinDir + "/services":      v.objs.lb3Maps.Services,
		pinDir + "/conntrack":     v.objs.lb3Maps.Conntrack,
	}, "wlc"); err != nil {
		v.objs.Close()
		return nil, err
	}
	return v, nil
}

func (v *wlcEstVariant) Program() *ebpf.Program { return v.objs.XdpLoadBalancer }
func (v *wlcEstVariant) Close()                 { v.objs.Close() }

func (v *wlcEstVariant) Init(cfgPath string) error {
	if err := initPorts(func(p uint16) error {
		return v.objs.lb3Maps.FreePorts.Update(nil, &p, ebpf.UpdateAny)
	}); err != nil {
		return fmt.Errorf("init ports: %w", err)
	}
	cfg, err := loadConfig(cfgPath)
	if err != nil {
		return err
	}
	if err := v.AddService(cfg.Service.VIP, cfg.Service.Port); err != nil {
		return fmt.Errorf("add service: %w", err)
	}
	for i, b := range cfg.Backends {
		ip, err := parseIPv4Cfg(b.IP)
		if err != nil {
			return fmt.Errorf("backend[%d] IP: %w", i, err)
		}
		// wlc stores port as htons (same as lc)
		be := lb3Backend{Ip: ip, Port: htons(b.Port), Conns: 0, Weight: defaultWeight(b.Weight)}
		if err := v.objs.lb3Maps.Backends.Update(uint32(i), &be, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("update backends[%d]: %w", i, err)
		}
	}
	cnt := uint32(len(cfg.Backends))
	return v.objs.lb3Maps.BackendCount.Update(uint32(0), &cnt, ebpf.UpdateAny)
}

func (v *wlcEstVariant) UpdateWeight(ip string, port, weight uint16) error {
	pip, err := parseIPv4Cfg(ip)
	if err != nil {
		return err
	}
	var count uint32
	if err := v.objs.lb3Maps.BackendCount.Lookup(uint32(0), &count); err != nil {
		return fmt.Errorf("lookup count: %w", err)
	}
	for i := uint32(0); i < count; i++ {
		var b lb3Backend
		if err := v.objs.lb3Maps.Backends.Lookup(i, &b); err != nil {
			continue
		}
		if b.Ip == pip && b.Port == htons(port) {
			b.Weight = weight
			return v.objs.lb3Maps.Backends.Update(i, &b, ebpf.UpdateExist)
		}
	}
	return fmt.Errorf("backend %s:%d not found", ip, port)
}

func (v *wlcEstVariant) AddBackend(ip string, port, weight uint16) error {
	return arrayAddBackend(v.objs.lb3Maps.Backends, v.objs.lb3Maps.BackendCount, ip, port, defaultWeight(weight),
		func(m *ebpf.Map, idx uint32) (uint32, uint16, error) {
			var b lb3Backend
			if err := m.Lookup(idx, &b); err != nil {
				return 0, 0, err
			}
			return b.Ip, b.Port, nil
		},
		func(ip uint32, port, w uint16) interface{} {
			return &lb3Backend{Ip: ip, Port: port, Conns: 0, Weight: w}
		},
		htons)
}

func (v *wlcEstVariant) DeleteBackend(ip string, port uint16) error {
	return arrayDeleteBackend(
		v.objs.lb3Maps.Backends, v.objs.lb3Maps.BackendCount,
		ip, port,
		func(m *ebpf.Map, idx uint32) (uint32, uint16, error) {
			var b lb3Backend
			if err := m.Lookup(idx, &b); err != nil {
				return 0, 0, err
			}
			return b.Ip, b.Port, nil
		},
		func(m *ebpf.Map, idx uint32) (uint32, error) {
			var b lb3Backend
			if err := m.Lookup(idx, &b); err != nil {
				return 0, err
			}
			return b.Conns, nil
		},
		func(m *ebpf.Map, dst, src uint32) error {
			var b lb3Backend
			if err := m.Lookup(src, &b); err != nil {
				return err
			}
			return m.Update(dst, &b, ebpf.UpdateExist)
		},
		func() interface{} { return &lb3Backend{} },
		htons,
		func(oldIdx, newIdx uint32) error {
			return patchConntrackLb3(v.objs.lb3Maps.Conntrack, oldIdx, newIdx)
		})
}

func (v *wlcEstVariant) AddService(ip string, port uint16) error {
	pip, err := parseIPv4Cfg(ip)
	if err != nil {
		return err
	}
	key := lb3IpPort{Ip: pip, Port: htons(port)}
	val := true
	return v.objs.lb3Maps.Services.Update(&key, &val, ebpf.UpdateAny)
}

func (v *wlcEstVariant) DeleteService(ip string, port uint16) error {
	pip, err := parseIPv4Cfg(ip)
	if err != nil {
		return err
	}
	key := lb3IpPort{Ip: pip, Port: htons(port)}
	return v.objs.lb3Maps.Services.Delete(&key)
}

// ── WLC-SYN variant (lb4 / lb_wlc_syn.c) ─────────────────────────────────────

type wlcSynVariant struct{ objs lb4Objects }

func newWlcSynVariant() (*wlcSynVariant, error) {
	v := &wlcSynVariant{}
	if err := loadLb4Objects(&v.objs, nil); err != nil {
		return nil, fmt.Errorf("load BPF objects (wlc-syn): %w", err)
	}
	if err := pinMaps(map[string]*ebpf.Map{
		pinDir + "/backends":      v.objs.lb4Maps.Backends,
		pinDir + "/backend_count": v.objs.lb4Maps.BackendCount,
		pinDir + "/services":      v.objs.lb4Maps.Services,
		pinDir + "/conntrack":     v.objs.lb4Maps.Conntrack,
	}, "wlc"); err != nil {
		v.objs.Close()
		return nil, err
	}
	return v, nil
}

func (v *wlcSynVariant) Program() *ebpf.Program { return v.objs.XdpLoadBalancer }
func (v *wlcSynVariant) Close()                 { v.objs.Close() }

func (v *wlcSynVariant) Init(cfgPath string) error {
	if err := initPorts(func(p uint16) error {
		return v.objs.lb4Maps.FreePorts.Update(nil, &p, ebpf.UpdateAny)
	}); err != nil {
		return fmt.Errorf("init ports: %w", err)
	}
	cfg, err := loadConfig(cfgPath)
	if err != nil {
		return err
	}
	if err := v.AddService(cfg.Service.VIP, cfg.Service.Port); err != nil {
		return fmt.Errorf("add service: %w", err)
	}
	for i, b := range cfg.Backends {
		ip, err := parseIPv4Cfg(b.IP)
		if err != nil {
			return fmt.Errorf("backend[%d] IP: %w", i, err)
		}
		// wlc stores port as htons (same as lc)
		be := lb4Backend{Ip: ip, Port: htons(b.Port), Conns: 0, Weight: defaultWeight(b.Weight)}
		if err := v.objs.lb4Maps.Backends.Update(uint32(i), &be, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("update backends[%d]: %w", i, err)
		}
	}
	cnt := uint32(len(cfg.Backends))
	return v.objs.lb4Maps.BackendCount.Update(uint32(0), &cnt, ebpf.UpdateAny)
}

func (v *wlcSynVariant) UpdateWeight(ip string, port, weight uint16) error {
	pip, err := parseIPv4Cfg(ip)
	if err != nil {
		return err
	}
	var count uint32
	if err := v.objs.lb4Maps.BackendCount.Lookup(uint32(0), &count); err != nil {
		return fmt.Errorf("lookup count: %w", err)
	}
	for i := uint32(0); i < count; i++ {
		var b lb4Backend
		if err := v.objs.lb4Maps.Backends.Lookup(i, &b); err != nil {
			continue
		}
		if b.Ip == pip && b.Port == htons(port) {
			b.Weight = weight
			return v.objs.lb4Maps.Backends.Update(i, &b, ebpf.UpdateExist)
		}
	}
	return fmt.Errorf("backend %s:%d not found", ip, port)
}

func (v *wlcSynVariant) AddBackend(ip string, port, weight uint16) error {
	return arrayAddBackend(v.objs.lb4Maps.Backends, v.objs.lb4Maps.BackendCount, ip, port, defaultWeight(weight),
		func(m *ebpf.Map, idx uint32) (uint32, uint16, error) {
			var b lb4Backend
			if err := m.Lookup(idx, &b); err != nil {
				return 0, 0, err
			}
			return b.Ip, b.Port, nil
		},
		func(ip uint32, port, w uint16) interface{} {
			return &lb4Backend{Ip: ip, Port: port, Conns: 0, Weight: w}
		},
		htons)
}

func (v *wlcSynVariant) DeleteBackend(ip string, port uint16) error {
	return arrayDeleteBackend(
		v.objs.lb4Maps.Backends, v.objs.lb4Maps.BackendCount,
		ip, port,
		func(m *ebpf.Map, idx uint32) (uint32, uint16, error) {
			var b lb4Backend
			if err := m.Lookup(idx, &b); err != nil {
				return 0, 0, err
			}
			return b.Ip, b.Port, nil
		},
		func(m *ebpf.Map, idx uint32) (uint32, error) {
			var b lb4Backend
			if err := m.Lookup(idx, &b); err != nil {
				return 0, err
			}
			return b.Conns, nil
		},
		func(m *ebpf.Map, dst, src uint32) error {
			var b lb4Backend
			if err := m.Lookup(src, &b); err != nil {
				return err
			}
			return m.Update(dst, &b, ebpf.UpdateExist)
		},
		func() interface{} { return &lb4Backend{} },
		htons,
		func(oldIdx, newIdx uint32) error {
			return patchConntrackLb4(v.objs.lb4Maps.Conntrack, oldIdx, newIdx)
		})
}

func (v *wlcSynVariant) AddService(ip string, port uint16) error {
	pip, err := parseIPv4Cfg(ip)
	if err != nil {
		return err
	}
	key := lb4IpPort{Ip: pip, Port: htons(port)}
	val := true
	return v.objs.lb4Maps.Services.Update(&key, &val, ebpf.UpdateAny)
}

func (v *wlcSynVariant) DeleteService(ip string, port uint16) error {
	pip, err := parseIPv4Cfg(ip)
	if err != nil {
		return err
	}
	key := lb4IpPort{Ip: pip, Port: htons(port)}
	return v.objs.lb4Maps.Services.Delete(&key)
}

// ── RR-EST variant (lb5 / lb_rr_est.c) ───────────────────────────────────────
// Same backend struct as lc (port stored as htons). Adds scheduler_state init.

type rrEstVariant struct{ objs lb5Objects }

func newRrEstVariant() (*rrEstVariant, error) {
	v := &rrEstVariant{}
	if err := loadLb5Objects(&v.objs, nil); err != nil {
		return nil, fmt.Errorf("load BPF objects (rr-est): %w", err)
	}
	if err := pinMaps(map[string]*ebpf.Map{
		pinDir + "/backends":      v.objs.lb5Maps.Backends,
		pinDir + "/backend_count": v.objs.lb5Maps.BackendCount,
		pinDir + "/services":      v.objs.lb5Maps.Services,
	}, "rr"); err != nil {
		v.objs.Close()
		return nil, err
	}
	return v, nil
}

func (v *rrEstVariant) Program() *ebpf.Program                          { return v.objs.XdpLoadBalancer }
func (v *rrEstVariant) Close()                                          { v.objs.Close() }
func (v *rrEstVariant) UpdateWeight(_ string, _ uint16, _ uint16) error { return nil }

func (v *rrEstVariant) Init(cfgPath string) error {
	if err := initPorts(func(p uint16) error {
		return v.objs.lb5Maps.FreePorts.Update(nil, &p, ebpf.UpdateAny)
	}); err != nil {
		return fmt.Errorf("init ports: %w", err)
	}
	if err := initSchedulerState(v.objs.lb5Maps.SchedulerState); err != nil {
		return err
	}
	cfg, err := loadConfig(cfgPath)
	if err != nil {
		return err
	}
	if err := v.AddService(cfg.Service.VIP, cfg.Service.Port); err != nil {
		return fmt.Errorf("add service: %w", err)
	}
	for i, b := range cfg.Backends {
		ip, err := parseIPv4Cfg(b.IP)
		if err != nil {
			return fmt.Errorf("backend[%d] IP: %w", i, err)
		}
		// rr stores port as htons (same as lc)
		be := lb5Backend{Ip: ip, Port: htons(b.Port), Conns: 0}
		if err := v.objs.lb5Maps.Backends.Update(uint32(i), &be, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("update backends[%d]: %w", i, err)
		}
	}
	cnt := uint32(len(cfg.Backends))
	return v.objs.lb5Maps.BackendCount.Update(uint32(0), &cnt, ebpf.UpdateAny)
}

func (v *rrEstVariant) AddBackend(ip string, port uint16, _ uint16) error {
	return arrayAddBackend(v.objs.lb5Maps.Backends, v.objs.lb5Maps.BackendCount, ip, port, 0,
		func(m *ebpf.Map, idx uint32) (uint32, uint16, error) {
			var b lb5Backend
			if err := m.Lookup(idx, &b); err != nil {
				return 0, 0, err
			}
			return b.Ip, b.Port, nil
		},
		func(ip uint32, port, _ uint16) interface{} {
			return &lb5Backend{Ip: ip, Port: port, Conns: 0}
		},
		htons)
}

func (v *rrEstVariant) DeleteBackend(ip string, port uint16) error {
	return arrayDeleteBackend(
		v.objs.lb5Maps.Backends, v.objs.lb5Maps.BackendCount,
		ip, port,
		func(m *ebpf.Map, idx uint32) (uint32, uint16, error) {
			var b lb5Backend
			if err := m.Lookup(idx, &b); err != nil {
				return 0, 0, err
			}
			return b.Ip, b.Port, nil
		},
		func(m *ebpf.Map, idx uint32) (uint32, error) {
			var b lb5Backend
			if err := m.Lookup(idx, &b); err != nil {
				return 0, err
			}
			return b.Conns, nil
		},
		func(m *ebpf.Map, dst, src uint32) error {
			var b lb5Backend
			if err := m.Lookup(src, &b); err != nil {
				return err
			}
			return m.Update(dst, &b, ebpf.UpdateExist)
		},
		func() interface{} { return &lb5Backend{} },
		htons, nil)
}

func (v *rrEstVariant) AddService(ip string, port uint16) error {
	pip, err := parseIPv4Cfg(ip)
	if err != nil {
		return err
	}
	key := lb5IpPort{Ip: pip, Port: htons(port)}
	val := true
	return v.objs.lb5Maps.Services.Update(&key, &val, ebpf.UpdateAny)
}

func (v *rrEstVariant) DeleteService(ip string, port uint16) error {
	pip, err := parseIPv4Cfg(ip)
	if err != nil {
		return err
	}
	key := lb5IpPort{Ip: pip, Port: htons(port)}
	return v.objs.lb5Maps.Services.Delete(&key)
}

// ── RR-SYN variant (lb6 / lb_rr_syn.c) ───────────────────────────────────────

type rrSynVariant struct{ objs lb6Objects }

func newRrSynVariant() (*rrSynVariant, error) {
	v := &rrSynVariant{}
	if err := loadLb6Objects(&v.objs, nil); err != nil {
		return nil, fmt.Errorf("load BPF objects (rr-syn): %w", err)
	}
	if err := pinMaps(map[string]*ebpf.Map{
		pinDir + "/backends":      v.objs.lb6Maps.Backends,
		pinDir + "/backend_count": v.objs.lb6Maps.BackendCount,
		pinDir + "/services":      v.objs.lb6Maps.Services,
	}, "rr"); err != nil {
		v.objs.Close()
		return nil, err
	}
	return v, nil
}

func (v *rrSynVariant) Program() *ebpf.Program                          { return v.objs.XdpLoadBalancer }
func (v *rrSynVariant) Close()                                          { v.objs.Close() }
func (v *rrSynVariant) UpdateWeight(_ string, _ uint16, _ uint16) error { return nil }

func (v *rrSynVariant) Init(cfgPath string) error {
	if err := initPorts(func(p uint16) error {
		return v.objs.lb6Maps.FreePorts.Update(nil, &p, ebpf.UpdateAny)
	}); err != nil {
		return fmt.Errorf("init ports: %w", err)
	}
	if err := initSchedulerState(v.objs.lb6Maps.SchedulerState); err != nil {
		return err
	}
	cfg, err := loadConfig(cfgPath)
	if err != nil {
		return err
	}
	if err := v.AddService(cfg.Service.VIP, cfg.Service.Port); err != nil {
		return fmt.Errorf("add service: %w", err)
	}
	for i, b := range cfg.Backends {
		ip, err := parseIPv4Cfg(b.IP)
		if err != nil {
			return fmt.Errorf("backend[%d] IP: %w", i, err)
		}
		// rr stores port as htons (same as lc)
		be := lb6Backend{Ip: ip, Port: htons(b.Port), Conns: 0}
		if err := v.objs.lb6Maps.Backends.Update(uint32(i), &be, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("update backends[%d]: %w", i, err)
		}
	}
	cnt := uint32(len(cfg.Backends))
	return v.objs.lb6Maps.BackendCount.Update(uint32(0), &cnt, ebpf.UpdateAny)
}

func (v *rrSynVariant) AddBackend(ip string, port uint16, _ uint16) error {
	return arrayAddBackend(v.objs.lb6Maps.Backends, v.objs.lb6Maps.BackendCount, ip, port, 0,
		func(m *ebpf.Map, idx uint32) (uint32, uint16, error) {
			var b lb6Backend
			if err := m.Lookup(idx, &b); err != nil {
				return 0, 0, err
			}
			return b.Ip, b.Port, nil
		},
		func(ip uint32, port, _ uint16) interface{} {
			return &lb6Backend{Ip: ip, Port: port, Conns: 0}
		},
		htons)
}

func (v *rrSynVariant) DeleteBackend(ip string, port uint16) error {
	return arrayDeleteBackend(
		v.objs.lb6Maps.Backends, v.objs.lb6Maps.BackendCount,
		ip, port,
		func(m *ebpf.Map, idx uint32) (uint32, uint16, error) {
			var b lb6Backend
			if err := m.Lookup(idx, &b); err != nil {
				return 0, 0, err
			}
			return b.Ip, b.Port, nil
		},
		func(m *ebpf.Map, idx uint32) (uint32, error) {
			var b lb6Backend
			if err := m.Lookup(idx, &b); err != nil {
				return 0, err
			}
			return b.Conns, nil
		},
		func(m *ebpf.Map, dst, src uint32) error {
			var b lb6Backend
			if err := m.Lookup(src, &b); err != nil {
				return err
			}
			return m.Update(dst, &b, ebpf.UpdateExist)
		},
		func() interface{} { return &lb6Backend{} },
		htons, nil)
}

func (v *rrSynVariant) AddService(ip string, port uint16) error {
	pip, err := parseIPv4Cfg(ip)
	if err != nil {
		return err
	}
	key := lb6IpPort{Ip: pip, Port: htons(port)}
	val := true
	return v.objs.lb6Maps.Services.Update(&key, &val, ebpf.UpdateAny)
}

func (v *rrSynVariant) DeleteService(ip string, port uint16) error {
	pip, err := parseIPv4Cfg(ip)
	if err != nil {
		return err
	}
	key := lb6IpPort{Ip: pip, Port: htons(port)}
	return v.objs.lb6Maps.Services.Delete(&key)
}

// ── WRR-EST variant (lb7 / lb_wrr_est.c) ─────────────────────────────────────
// Same backend struct as wlc + UsedCount field. Port stored as htons.

type wrrEstVariant struct{ objs lb7Objects }

func newWrrEstVariant() (*wrrEstVariant, error) {
	v := &wrrEstVariant{}
	if err := loadLb7Objects(&v.objs, nil); err != nil {
		return nil, fmt.Errorf("load BPF objects (wrr-est): %w", err)
	}
	if err := pinMaps(map[string]*ebpf.Map{
		pinDir + "/backends":      v.objs.lb7Maps.Backends,
		pinDir + "/backend_count": v.objs.lb7Maps.BackendCount,
		pinDir + "/services":      v.objs.lb7Maps.Services,
		pinDir + "/conntrack":     v.objs.lb7Maps.Conntrack,
	}, "wrr"); err != nil {
		v.objs.Close()
		return nil, err
	}
	return v, nil
}

func (v *wrrEstVariant) Program() *ebpf.Program { return v.objs.XdpLoadBalancer }
func (v *wrrEstVariant) Close()                 { v.objs.Close() }

func (v *wrrEstVariant) Init(cfgPath string) error {
	if err := initPorts(func(p uint16) error {
		return v.objs.lb7Maps.FreePorts.Update(nil, &p, ebpf.UpdateAny)
	}); err != nil {
		return fmt.Errorf("init ports: %w", err)
	}
	if err := initSchedulerState(v.objs.lb7Maps.SchedulerState); err != nil {
		return err
	}
	cfg, err := loadConfig(cfgPath)
	if err != nil {
		return err
	}
	if err := v.AddService(cfg.Service.VIP, cfg.Service.Port); err != nil {
		return fmt.Errorf("add service: %w", err)
	}
	for i, b := range cfg.Backends {
		ip, err := parseIPv4Cfg(b.IP)
		if err != nil {
			return fmt.Errorf("backend[%d] IP: %w", i, err)
		}
		// wrr stores port as htons (same as lc)
		be := lb7Backend{Ip: ip, Port: htons(b.Port), Conns: 0, Weight: defaultWeight(b.Weight), UsedCount: 0}
		if err := v.objs.lb7Maps.Backends.Update(uint32(i), &be, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("update backends[%d]: %w", i, err)
		}
	}
	cnt := uint32(len(cfg.Backends))
	return v.objs.lb7Maps.BackendCount.Update(uint32(0), &cnt, ebpf.UpdateAny)
}

func (v *wrrEstVariant) UpdateWeight(ip string, port, weight uint16) error {
	pip, err := parseIPv4Cfg(ip)
	if err != nil {
		return err
	}
	var count uint32
	if err := v.objs.lb7Maps.BackendCount.Lookup(uint32(0), &count); err != nil {
		return fmt.Errorf("lookup count: %w", err)
	}
	for i := uint32(0); i < count; i++ {
		var b lb7Backend
		if err := v.objs.lb7Maps.Backends.Lookup(i, &b); err != nil {
			continue
		}
		if b.Ip == pip && b.Port == htons(port) {
			b.Weight = weight
			b.UsedCount = 0
			return v.objs.lb7Maps.Backends.Update(i, &b, ebpf.UpdateExist)
		}
	}
	return fmt.Errorf("backend %s:%d not found", ip, port)
}

func (v *wrrEstVariant) AddBackend(ip string, port, weight uint16) error {
	return arrayAddBackend(v.objs.lb7Maps.Backends, v.objs.lb7Maps.BackendCount, ip, port, defaultWeight(weight),
		func(m *ebpf.Map, idx uint32) (uint32, uint16, error) {
			var b lb7Backend
			if err := m.Lookup(idx, &b); err != nil {
				return 0, 0, err
			}
			return b.Ip, b.Port, nil
		},
		func(ip uint32, port, w uint16) interface{} {
			return &lb7Backend{Ip: ip, Port: port, Conns: 0, Weight: w, UsedCount: 0}
		},
		htons)
}

func (v *wrrEstVariant) DeleteBackend(ip string, port uint16) error {
	return arrayDeleteBackend(
		v.objs.lb7Maps.Backends, v.objs.lb7Maps.BackendCount,
		ip, port,
		func(m *ebpf.Map, idx uint32) (uint32, uint16, error) {
			var b lb7Backend
			if err := m.Lookup(idx, &b); err != nil {
				return 0, 0, err
			}
			return b.Ip, b.Port, nil
		},
		func(m *ebpf.Map, idx uint32) (uint32, error) {
			var b lb7Backend
			if err := m.Lookup(idx, &b); err != nil {
				return 0, err
			}
			return b.Conns, nil
		},
		func(m *ebpf.Map, dst, src uint32) error {
			var b lb7Backend
			if err := m.Lookup(src, &b); err != nil {
				return err
			}
			return m.Update(dst, &b, ebpf.UpdateExist)
		},
		func() interface{} { return &lb7Backend{} },
		htons,
		func(oldIdx, newIdx uint32) error {
			return patchConntrackLb7(v.objs.lb7Maps.Conntrack, oldIdx, newIdx)
		})
}

func (v *wrrEstVariant) AddService(ip string, port uint16) error {
	pip, err := parseIPv4Cfg(ip)
	if err != nil {
		return err
	}
	key := lb7IpPort{Ip: pip, Port: htons(port)}
	val := true
	return v.objs.lb7Maps.Services.Update(&key, &val, ebpf.UpdateAny)
}

func (v *wrrEstVariant) DeleteService(ip string, port uint16) error {
	pip, err := parseIPv4Cfg(ip)
	if err != nil {
		return err
	}
	key := lb7IpPort{Ip: pip, Port: htons(port)}
	return v.objs.lb7Maps.Services.Delete(&key)
}

// ── WRR-SYN variant (lb8 / lb_wrr_syn.c) ─────────────────────────────────────

type wrrSynVariant struct{ objs lb8Objects }

func newWrrSynVariant() (*wrrSynVariant, error) {
	v := &wrrSynVariant{}
	if err := loadLb8Objects(&v.objs, nil); err != nil {
		return nil, fmt.Errorf("load BPF objects (wrr-syn): %w", err)
	}
	if err := pinMaps(map[string]*ebpf.Map{
		pinDir + "/backends":      v.objs.lb8Maps.Backends,
		pinDir + "/backend_count": v.objs.lb8Maps.BackendCount,
		pinDir + "/services":      v.objs.lb8Maps.Services,
		pinDir + "/conntrack":     v.objs.lb8Maps.Conntrack,
	}, "wrr"); err != nil {
		v.objs.Close()
		return nil, err
	}
	return v, nil
}

func (v *wrrSynVariant) Program() *ebpf.Program { return v.objs.XdpLoadBalancer }
func (v *wrrSynVariant) Close()                 { v.objs.Close() }

func (v *wrrSynVariant) Init(cfgPath string) error {
	if err := initPorts(func(p uint16) error {
		return v.objs.lb8Maps.FreePorts.Update(nil, &p, ebpf.UpdateAny)
	}); err != nil {
		return fmt.Errorf("init ports: %w", err)
	}
	if err := initSchedulerState(v.objs.lb8Maps.SchedulerState); err != nil {
		return err
	}
	cfg, err := loadConfig(cfgPath)
	if err != nil {
		return err
	}
	if err := v.AddService(cfg.Service.VIP, cfg.Service.Port); err != nil {
		return fmt.Errorf("add service: %w", err)
	}
	for i, b := range cfg.Backends {
		ip, err := parseIPv4Cfg(b.IP)
		if err != nil {
			return fmt.Errorf("backend[%d] IP: %w", i, err)
		}
		// wrr stores port as htons (same as lc)
		be := lb8Backend{Ip: ip, Port: htons(b.Port), Conns: 0, Weight: defaultWeight(b.Weight), UsedCount: 0}
		if err := v.objs.lb8Maps.Backends.Update(uint32(i), &be, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("update backends[%d]: %w", i, err)
		}
	}
	cnt := uint32(len(cfg.Backends))
	return v.objs.lb8Maps.BackendCount.Update(uint32(0), &cnt, ebpf.UpdateAny)
}

func (v *wrrSynVariant) UpdateWeight(ip string, port, weight uint16) error {
	pip, err := parseIPv4Cfg(ip)
	if err != nil {
		return err
	}
	var count uint32
	if err := v.objs.lb8Maps.BackendCount.Lookup(uint32(0), &count); err != nil {
		return fmt.Errorf("lookup count: %w", err)
	}
	for i := uint32(0); i < count; i++ {
		var b lb8Backend
		if err := v.objs.lb8Maps.Backends.Lookup(i, &b); err != nil {
			continue
		}
		if b.Ip == pip && b.Port == htons(port) {
			b.Weight = weight
			b.UsedCount = 0
			return v.objs.lb8Maps.Backends.Update(i, &b, ebpf.UpdateExist)
		}
	}
	return fmt.Errorf("backend %s:%d not found", ip, port)
}

func (v *wrrSynVariant) AddBackend(ip string, port, weight uint16) error {
	return arrayAddBackend(v.objs.lb8Maps.Backends, v.objs.lb8Maps.BackendCount, ip, port, defaultWeight(weight),
		func(m *ebpf.Map, idx uint32) (uint32, uint16, error) {
			var b lb8Backend
			if err := m.Lookup(idx, &b); err != nil {
				return 0, 0, err
			}
			return b.Ip, b.Port, nil
		},
		func(ip uint32, port, w uint16) interface{} {
			return &lb8Backend{Ip: ip, Port: port, Conns: 0, Weight: w, UsedCount: 0}
		},
		htons)
}

func (v *wrrSynVariant) DeleteBackend(ip string, port uint16) error {
	return arrayDeleteBackend(
		v.objs.lb8Maps.Backends, v.objs.lb8Maps.BackendCount,
		ip, port,
		func(m *ebpf.Map, idx uint32) (uint32, uint16, error) {
			var b lb8Backend
			if err := m.Lookup(idx, &b); err != nil {
				return 0, 0, err
			}
			return b.Ip, b.Port, nil
		},
		func(m *ebpf.Map, idx uint32) (uint32, error) {
			var b lb8Backend
			if err := m.Lookup(idx, &b); err != nil {
				return 0, err
			}
			return b.Conns, nil
		},
		func(m *ebpf.Map, dst, src uint32) error {
			var b lb8Backend
			if err := m.Lookup(src, &b); err != nil {
				return err
			}
			return m.Update(dst, &b, ebpf.UpdateExist)
		},
		func() interface{} { return &lb8Backend{} },
		htons,
		func(oldIdx, newIdx uint32) error {
			return patchConntrackLb8(v.objs.lb8Maps.Conntrack, oldIdx, newIdx)
		})
}

func (v *wrrSynVariant) AddService(ip string, port uint16) error {
	pip, err := parseIPv4Cfg(ip)
	if err != nil {
		return err
	}
	key := lb8IpPort{Ip: pip, Port: htons(port)}
	val := true
	return v.objs.lb8Maps.Services.Update(&key, &val, ebpf.UpdateAny)
}

func (v *wrrSynVariant) DeleteService(ip string, port uint16) error {
	pip, err := parseIPv4Cfg(ip)
	if err != nil {
		return err
	}
	key := lb8IpPort{Ip: pip, Port: htons(port)}
	return v.objs.lb8Maps.Services.Delete(&key)
}