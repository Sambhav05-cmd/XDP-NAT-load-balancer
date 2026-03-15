# XDP Weighted Least-Connections Load Balancer

A NAT-based TCP load balancer implemented in eBPF at the XDP layer. Supports two scheduling algorithms — **Least Connections (LC)** and **Weighted Least Connections (WLC)** — each available in two connection-tracking modes. Backends are manageable at runtime via an interactive CLI.

> **Why XDP?** Packets are processed before entering the Linux networking stack — minimal CPU overhead, maximum throughput.

---

## Table of Contents

- [Overview](#overview)
- [Scheduling Algorithms](#scheduling-algorithms)
- [Connection Tracking Modes](#connection-tracking-modes)
- [Repository Structure](#repository-structure)
- [Prerequisites](#prerequisites)
- [Configuration](#configuration)
- [Building](#building)
- [Running](#running)
- [Runtime CLI](#runtime-cli)
- [Testing](#testing)
- [Customization](#customization)
- [References](#references)

---

## Overview

Each incoming TCP connection is assigned to a backend according to the active scheduling algorithm. The XDP eBPF program tracks connection state by inspecting TCP flags and maintaining lightweight per-connection structures in eBPF maps. Because everything runs at the XDP layer, packets are intercepted on arrival — before the kernel's normal network stack — keeping overhead very low.

---

## Scheduling Algorithms

| Algorithm | Description |
|-----------|-------------|
| **Least Connections (LC)** | Assigns each new connection to the backend with the fewest active connections. All backends are treated equally. |
| **Weighted Least Connections (WLC)** | Assigns connections based on `active_connections / weight`. Backends with higher weights receive a proportionally larger share of traffic. |

---

## Connection Tracking Modes

Both algorithms are available in two builds, differing only in *when* a connection is counted:

| Mode | Counts on | Pros | Cons |
|------|-----------|------|------|
| **SYN** | SYN packet arrival | Reserves backend immediately; more even distribution during bursts | Incomplete handshakes are briefly counted until cleaned up |
| **Established** | First non-SYN packet (after handshake completes) | Counters reflect only fully established connections | Under burst load, multiple SYNs may see stale counters before they update |

---

## Repository Structure

```
.
├── bpf/                  # eBPF/XDP load balancer program (C)
├── cmd/lb/               # Go user-space loader and CLI
├── configs/
│   ├── backends_lc.json  # Backend config for LC (no weights)
│   └── backends_wlc.json # Backend config for WLC (with weights)
└── scripts/
    └── build.sh          # Builds all four binaries
```

---

## Prerequisites

Install LLVM and required toolchain dependencies:

```bash
sudo ./scripts/llvm.sh
```

> **Requirements:** Root privileges, a modern Linux kernel with eBPF and XDP support.

---

## Configuration

### LC — `configs/backends_lc.json`

```json
{
  "backends": [
    "10.0.0.2",
    "10.0.0.3"
  ]
}
```

### WLC — `configs/backends_wlc.json`

```json
{
  "backends": [
    { "ip": "10.0.0.2", "weight": 1 },
    { "ip": "10.0.0.3", "weight": 3 }
  ]
}
```

Backends can also be added, removed, or reweighted live via the CLI after startup.

---

## Building

Build all four binaries at once:

```bash
./build.sh
```

This produces:

| Binary | Algorithm | Tracking mode |
|--------|-----------|---------------|
| `lb_lc_syn` | Least Connections | SYN |
| `lb_lc_est` | Least Connections | Established |
| `lb_wlc_syn` | Weighted Least Connections | SYN |
| `lb_wlc_est` | Weighted Least Connections | Established |

---

## Running

**LC binaries:**

```bash
sudo ./lb_lc_syn -i <network-interface> -config configs/backends_lc.json
sudo ./lb_lc_est -i <network-interface> -config configs/backends_lc.json
```

**WLC binaries:**

```bash
sudo ./lb_wlc_syn -i <network-interface> -config configs/backends_wlc.json
sudo ./lb_wlc_est -i <network-interface> -config configs/backends_wlc.json
```

Replace `<network-interface>` with the interface to attach the XDP program to (e.g. `eth0`).

---

## Runtime CLI

After starting, an interactive prompt becomes available:

```
lb>
```

### LC commands

| Command | Description |
|---------|-------------|
| `add <ip>` | Add a backend server |
| `del <ip>` | Remove a backend server |
| `list` | List backends and their current connection counts |

### WLC commands

| Command | Description |
|---------|-------------|
| `add <ip> <weight>` | Add a backend server with a given weight |
| `del <ip>` | Remove a backend server |
| `update <ip> <weight>` | Update the weight of an existing backend |
| `list` | List backends with their weights and connection counts |

**Example session (WLC):**

```
lb> add 10.0.0.4 2
lb> update 10.0.0.2 3
lb> del 10.0.0.3
lb> list
```

---

### Verifying the XDP program is attached

```bash
sudo bpftool prog show
```

---

## Testing

### 1. Start backend servers

Run this on each backend machine:

```bash
socat TCP-LISTEN:8000,reuseaddr,fork EXEC:/bin/cat
```

### 2. Send a single request

From a client machine:

```bash
socat - TCP:<load_balancer_IP>:8000
```

### 3. Simulate high concurrency

Launch 100 parallel requests simultaneously:

```bash
for i in $(seq 1 100); do
socat - TCP:<load_balancer_IP:8000 &
done
```

### 4. Check active kernel TCP connections

```bash
ss -tan '( sport = :8000 )' | wc -l
```

### 5. Observe backend distribution

```
lb> list
```

Under burst load, the **SYN** variants distribute more evenly than the **established** variants because counters are incremented immediately on SYN arrival. With WLC, backends with higher weights should absorb a proportionally larger share of connections.

---

## Customization

The load balancer currently filters on **TCP port 8000**. To change this, edit the port filter in the eBPF programs:

```
bpf/lb_lc_syn.c
bpf/lb_lc_est.c
bpf/lb_wlc_syn.c
bpf/lb_wlc_est.c
```

---

## References

- [Teodor Podobnik – XDP Load Balancer Tutorial](https://labs.iximiuz.com/tutorials/xdp-load-balancer-700a1d74)
- [iximiuz Labs – Practical Linux networking and eBPF tutorials](https://labs.iximiuz.com/)
