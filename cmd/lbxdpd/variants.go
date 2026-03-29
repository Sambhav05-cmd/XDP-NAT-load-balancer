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
	Weight uint16 `json:"weight"` // optional; defaults to 1 in wlc mode
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

// nextBackendID is the process-wide stable ID counter used by wlc variants.
// Starts at 1 — 0 is reserved as an invalid/sentinel value in BPF.
var nextBackendID uint32 = 1

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

// ── LC shared map helpers (backends is BPF_MAP_TYPE_ARRAY) ───────────────────

func lcAddBackend(backends, countMap *ebpf.Map, ip string, port uint16,
	makeEntry func(ip uint32, port uint16) interface{}) error {

	pip, err := parseIPv4Cfg(ip)
	if err != nil {
		return err
	}
	var count uint32
	if err := countMap.Lookup(uint32(0), &count); err != nil {
		return fmt.Errorf("lookup count: %w", err)
	}
	// Duplicate check.
	type raw struct {
		Ip    uint32
		Port  uint16
		_     uint16
		Conns uint32
	}
	for i := uint32(0); i < count; i++ {
		var b raw
		if err := backends.Lookup(i, &b); err != nil {
			continue
		}
		if b.Ip == pip && b.Port == htons(port) {
			return fmt.Errorf("backend %s:%d already exists", ip, port)
		}
	}
	be := makeEntry(pip, htons(port))
	if err := backends.Update(count, be, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("insert backend: %w", err)
	}
	count++
	if err := countMap.Update(uint32(0), &count, ebpf.UpdateExist); err != nil {
		return fmt.Errorf("update count: %w", err)
	}
	return nil
}

func lcDeleteBackend(backends, countMap *ebpf.Map, ip string, port uint16,
	zeroEntry func() interface{},
	swapEntry func(m *ebpf.Map, dst, src uint32) error,
	getConns func(m *ebpf.Map, idx uint32) (uint32, error),
	getIPPort func(m *ebpf.Map, idx uint32) (uint32, uint16, error)) error {

	pip, err := parseIPv4Cfg(ip)
	if err != nil {
		return err
	}
	var count uint32
	if err := countMap.Lookup(uint32(0), &count); err != nil {
		return fmt.Errorf("lookup count: %w", err)
	}
	for i := uint32(0); i < count; i++ {
		bip, bport, err := getIPPort(backends, i)
		if err != nil {
			continue
		}
		if bip != pip || bport != htons(port) {
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
			if err := swapEntry(backends, i, last); err != nil {
				return fmt.Errorf("swap: %w", err)
			}
		}
		if err := backends.Update(last, zeroEntry(), ebpf.UpdateExist); err != nil {
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

// ── WLC shared map helpers (backends is BPF_MAP_TYPE_HASH + selection_array) ─

type (
	lookupIPPortFn func(m *ebpf.Map, id uint32) (ip uint32, port uint16, err error)
	lookupConnsFn  func(m *ebpf.Map, id uint32) (conns uint32, err error)
	makeFn         func(ip uint32, port, weight uint16) interface{}
)

func wlcUpdateWeight(backends, countMap, selectionArray *ebpf.Map,
	ip string, port, weight uint16) error {

	pip, err := parseIPv4Cfg(ip)
	if err != nil {
		return err
	}
	var count uint32
	if err := countMap.Lookup(uint32(0), &count); err != nil {
		return fmt.Errorf("lookup count: %w", err)
	}
	type raw struct {
		Ip     uint32
		Port   uint16
		Weight uint16
		Conns  uint32
	}
	for i := uint32(0); i < count; i++ {
		var id uint32
		if err := selectionArray.Lookup(i, &id); err != nil {
			continue
		}
		var b raw
		if err := backends.Lookup(&id, &b); err != nil {
			continue
		}
		if b.Ip == pip && b.Port == htons(port) {
			b.Weight = weight
			if err := backends.Update(&id, &b, ebpf.UpdateExist); err != nil {
				return fmt.Errorf("update weight: %w", err)
			}
			return nil
		}
	}
	return fmt.Errorf("backend %s:%d not found", ip, port)
}

func wlcAddBackend(backends, countMap, selectionArray *ebpf.Map,
	ip string, port, weight uint16, make makeFn) error {

	pip, err := parseIPv4Cfg(ip)
	if err != nil {
		return err
	}
	if weight == 0 {
		weight = 1
	}
	var count uint32
	if err := countMap.Lookup(uint32(0), &count); err != nil {
		return fmt.Errorf("lookup count: %w", err)
	}
	// Duplicate check via selection_array.
	type raw struct {
		Ip     uint32
		Port   uint16
		Weight uint16
		Conns  uint32
	}
	for i := uint32(0); i < count; i++ {
		var id uint32
		if err := selectionArray.Lookup(i, &id); err != nil {
			continue
		}
		var b raw
		if err := backends.Lookup(&id, &b); err != nil {
			continue
		}
		if b.Ip == pip && b.Port == htons(port) {
			return fmt.Errorf("backend %s:%d already exists", ip, port)
		}
	}
	// Assign a new stable ID.
	id := nextBackendID
	nextBackendID++
	be := make(pip, htons(port), weight)
	if err := backends.Update(&id, be, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("insert backend: %w", err)
	}
	if err := selectionArray.Update(count, &id, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("update selection_array: %w", err)
	}
	count++
	if err := countMap.Update(uint32(0), &count, ebpf.UpdateExist); err != nil {
		return fmt.Errorf("update count: %w", err)
	}
	return nil
}

func wlcDeleteBackend(backends, countMap, selectionArray *ebpf.Map,
	ip string, port uint16,
	lookupIPPort lookupIPPortFn, lookupConns lookupConnsFn) error {

	pip, err := parseIPv4Cfg(ip)
	if err != nil {
		return err
	}
	var count uint32
	if err := countMap.Lookup(uint32(0), &count); err != nil {
		return fmt.Errorf("lookup count: %w", err)
	}
	for i := uint32(0); i < count; i++ {
		var id uint32
		if err := selectionArray.Lookup(i, &id); err != nil {
			continue
		}
		bip, bport, err := lookupIPPort(backends, id)
		if err != nil {
			continue
		}
		if bip != pip || bport != htons(port) {
			continue
		}
		conns, err := lookupConns(backends, id)
		if err != nil {
			return fmt.Errorf("lookup conns: %w", err)
		}
		if conns != 0 {
			return fmt.Errorf("backend %s:%d has %d active connections", ip, port, conns)
		}
		last := count - 1
		if i != last {
			var lastID uint32
			if err := selectionArray.Lookup(last, &lastID); err != nil {
				return fmt.Errorf("lookup last id: %w", err)
			}
			if err := selectionArray.Update(i, &lastID, ebpf.UpdateExist); err != nil {
				return fmt.Errorf("swap selection_array: %w", err)
			}
		}
		zero := uint32(0)
		if err := selectionArray.Update(last, &zero, ebpf.UpdateExist); err != nil {
			return fmt.Errorf("zero selection_array last slot: %w", err)
		}
		if err := backends.Delete(&id); err != nil {
			return fmt.Errorf("delete backend: %w", err)
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

func (v *lcEstVariant) Program() *ebpf.Program { return v.objs.XdpLoadBalancer }
func (v *lcEstVariant) Close()                 { v.objs.Close() }
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
	return lcAddBackend(v.objs.lbMaps.Backends, v.objs.lbMaps.BackendCount, ip, port,
		func(ip uint32, port uint16) interface{} {
			return &lbBackend{Ip: ip, Port: port, Conns: 0}
		})
}

func (v *lcEstVariant) DeleteBackend(ip string, port uint16) error {
	return lcDeleteBackend(v.objs.lbMaps.Backends, v.objs.lbMaps.BackendCount, ip, port,
		func() interface{} { return &lbBackend{} },
		func(m *ebpf.Map, dst, src uint32) error {
			var b lbBackend
			if err := m.Lookup(src, &b); err != nil {
				return err
			}
			return m.Update(dst, &b, ebpf.UpdateExist)
		},
		func(m *ebpf.Map, idx uint32) (uint32, error) {
			var b lbBackend
			if err := m.Lookup(idx, &b); err != nil {
				return 0, err
			}
			return b.Conns, nil
		},
		func(m *ebpf.Map, idx uint32) (uint32, uint16, error) {
			var b lbBackend
			if err := m.Lookup(idx, &b); err != nil {
				return 0, 0, err
			}
			return b.Ip, b.Port, nil
		})
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

func (v *lcSynVariant) Program() *ebpf.Program { return v.objs.XdpLoadBalancer }
func (v *lcSynVariant) Close()                 { v.objs.Close() }
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
	return lcAddBackend(v.objs.lb2Maps.Backends, v.objs.lb2Maps.BackendCount, ip, port,
		func(ip uint32, port uint16) interface{} {
			return &lb2Backend{Ip: ip, Port: port, Conns: 0}
		})
}

func (v *lcSynVariant) DeleteBackend(ip string, port uint16) error {
	return lcDeleteBackend(v.objs.lb2Maps.Backends, v.objs.lb2Maps.BackendCount, ip, port,
		func() interface{} { return &lb2Backend{} },
		func(m *ebpf.Map, dst, src uint32) error {
			var b lb2Backend
			if err := m.Lookup(src, &b); err != nil {
				return err
			}
			return m.Update(dst, &b, ebpf.UpdateExist)
		},
		func(m *ebpf.Map, idx uint32) (uint32, error) {
			var b lb2Backend
			if err := m.Lookup(idx, &b); err != nil {
				return 0, err
			}
			return b.Conns, nil
		},
		func(m *ebpf.Map, idx uint32) (uint32, uint16, error) {
			var b lb2Backend
			if err := m.Lookup(idx, &b); err != nil {
				return 0, 0, err
			}
			return b.Ip, b.Port, nil
		})
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

type wlcEstVariant struct{ objs lb3Objects }

func newWlcEstVariant() (*wlcEstVariant, error) {
	v := &wlcEstVariant{}
	if err := loadLb3Objects(&v.objs, nil); err != nil {
		return nil, fmt.Errorf("load BPF objects (wlc-est): %w", err)
	}
	if err := pinMaps(map[string]*ebpf.Map{
		pinDir + "/backends":        v.objs.lb3Maps.Backends,
		pinDir + "/backend_count":   v.objs.lb3Maps.BackendCount,
		pinDir + "/services":        v.objs.lb3Maps.Services,
		pinDir + "/selection_array": v.objs.lb3Maps.SelectionArray,
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
		id := nextBackendID
		nextBackendID++
		be := lb3Backend{Ip: ip, Port: htons(b.Port), Conns: 0, Weight: defaultWeight(b.Weight)}
		if err := v.objs.lb3Maps.Backends.Update(&id, &be, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("update backends id=%d: %w", id, err)
		}
		pos := uint32(i)
		if err := v.objs.lb3Maps.SelectionArray.Update(pos, &id, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("update selection_array[%d]: %w", i, err)
		}
	}
	cnt := uint32(len(cfg.Backends))
	return v.objs.lb3Maps.BackendCount.Update(uint32(0), &cnt, ebpf.UpdateAny)
}

func (v *wlcEstVariant) UpdateWeight(ip string, port, weight uint16) error {
	return wlcUpdateWeight(v.objs.lb3Maps.Backends, v.objs.lb3Maps.BackendCount,
		v.objs.lb3Maps.SelectionArray, ip, port, weight)
}

func (v *wlcEstVariant) AddBackend(ip string, port, weight uint16) error {
	return wlcAddBackend(v.objs.lb3Maps.Backends, v.objs.lb3Maps.BackendCount,
		v.objs.lb3Maps.SelectionArray, ip, port, weight,
		func(ip uint32, port, weight uint16) interface{} {
			return &lb3Backend{Ip: ip, Port: port, Conns: 0, Weight: weight}
		})
}

func (v *wlcEstVariant) DeleteBackend(ip string, port uint16) error {
	return wlcDeleteBackend(v.objs.lb3Maps.Backends, v.objs.lb3Maps.BackendCount,
		v.objs.lb3Maps.SelectionArray, ip, port,
		func(m *ebpf.Map, id uint32) (uint32, uint16, error) {
			var b lb3Backend
			if err := m.Lookup(&id, &b); err != nil {
				return 0, 0, err
			}
			return b.Ip, b.Port, nil
		},
		func(m *ebpf.Map, id uint32) (uint32, error) {
			var b lb3Backend
			if err := m.Lookup(&id, &b); err != nil {
				return 0, err
			}
			return b.Conns, nil
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
		pinDir + "/backends":        v.objs.lb4Maps.Backends,
		pinDir + "/backend_count":   v.objs.lb4Maps.BackendCount,
		pinDir + "/services":        v.objs.lb4Maps.Services,
		pinDir + "/selection_array": v.objs.lb4Maps.SelectionArray,
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
		id := nextBackendID
		nextBackendID++
		be := lb4Backend{Ip: ip, Port: htons(b.Port), Conns: 0, Weight: defaultWeight(b.Weight)}
		if err := v.objs.lb4Maps.Backends.Update(&id, &be, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("update backends id=%d: %w", id, err)
		}
		pos := uint32(i)
		if err := v.objs.lb4Maps.SelectionArray.Update(pos, &id, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("update selection_array[%d]: %w", i, err)
		}
	}
	cnt := uint32(len(cfg.Backends))
	return v.objs.lb4Maps.BackendCount.Update(uint32(0), &cnt, ebpf.UpdateAny)
}

func (v *wlcSynVariant) UpdateWeight(ip string, port, weight uint16) error {
	return wlcUpdateWeight(v.objs.lb4Maps.Backends, v.objs.lb4Maps.BackendCount,
		v.objs.lb4Maps.SelectionArray, ip, port, weight)
}

func (v *wlcSynVariant) AddBackend(ip string, port, weight uint16) error {
	return wlcAddBackend(v.objs.lb4Maps.Backends, v.objs.lb4Maps.BackendCount,
		v.objs.lb4Maps.SelectionArray, ip, port, weight,
		func(ip uint32, port, weight uint16) interface{} {
			return &lb4Backend{Ip: ip, Port: port, Conns: 0, Weight: weight}
		})
}

func (v *wlcSynVariant) DeleteBackend(ip string, port uint16) error {
	return wlcDeleteBackend(v.objs.lb4Maps.Backends, v.objs.lb4Maps.BackendCount,
		v.objs.lb4Maps.SelectionArray, ip, port,
		func(m *ebpf.Map, id uint32) (uint32, uint16, error) {
			var b lb4Backend
			if err := m.Lookup(&id, &b); err != nil {
				return 0, 0, err
			}
			return b.Ip, b.Port, nil
		},
		func(m *ebpf.Map, id uint32) (uint32, error) {
			var b lb4Backend
			if err := m.Lookup(&id, &b); err != nil {
				return 0, err
			}
			return b.Conns, nil
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
