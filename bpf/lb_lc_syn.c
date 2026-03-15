// go:build ignore
#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include "parse_helpers.h"

#define MAX_BACKENDS 100
#define ETH_ALEN 6
#define AF_INET 2
#define IPROTO_TCP 6
#define MAX_TCP_CHECK_WORDS 750

// every backend's ip and number of active connections

struct backend
{
  __u32 ip;
  __u32 conns;
};

struct five_tuple_t
{
  __u32 src_ip;
  __u32 dst_ip;
  __u16 src_port;
  __u16 dst_port;
  __u8 protocol;
};

// Connection state lives ONLY here (conntrack map).
// State values:
//   0 = SYN seen, not yet established
//   1 = Established
//   2 = Client sent FIN first
//   3 = Backend sent FIN first
//   4 = Both sides have FIN'd → delete on next ACK
struct conn_meta
{
  __u32 ip;          // client IP (used for backend traffic to rewrite back to client IP)
  __u32 backend_idx; // used for client traffic to index into backends map
  __u8 state;
};

// Backend IPs
// We could also include port information but we simplify
// and assume that both LB and Backend listen on the same port for requests
struct
{
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, MAX_BACKENDS);
  __type(key, __u32);
  __type(value, struct backend);
} backends SEC(".maps");

// Get the number of backends from user space
struct
{
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, __u32);
} backend_count SEC(".maps");

// conntrack: keyed by (LB-side five-tuple as seen FROM the backend)
//   src_ip   = LB IP
//   dst_ip   = backend IP
//   src_port = client source port  (LB preserves it when forwarding)
//   dst_port = destination port (e.g. 8000)
//
// This is the store for conn_meta / state.
struct
{
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1000);
  __type(key, struct five_tuple_t);
  __type(value, struct conn_meta);
} conntrack SEC(".maps");

// backendtrack: keyed by the client-facing five-tuple
//   src_ip   = client IP
//   dst_ip   = LB IP
//   src_port = client source port
//   dst_port = destination port
//
// Value is NOT conn_meta any more – it is the conntrack key so we
// can look up the single authoritative conn_meta without duplicating state.
struct
{
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1000);
  __type(key, struct five_tuple_t);
  __type(value, struct five_tuple_t); //  stores the conntrack lookup key
} backendtrack SEC(".maps");

// helpers

static __always_inline void log_fib_error(int rc)
{
  switch (rc)
  {
  case BPF_FIB_LKUP_RET_BLACKHOLE:
    bpf_printk("FIB lookup failed: BLACKHOLE route. Check 'ip route' – the "
               "destination may have a blackhole rule.");
    break;
  case BPF_FIB_LKUP_RET_UNREACHABLE:
    bpf_printk("FIB lookup failed: UNREACHABLE route. Kernel routing table "
               "explicitly marks this destination unreachable.");
    break;
  case BPF_FIB_LKUP_RET_PROHIBIT:
    bpf_printk("FIB lookup failed: PROHIBITED route. Forwarding is "
               "administratively blocked.");
    break;
  case BPF_FIB_LKUP_RET_NOT_FWDED:
    bpf_printk("FIB lookup failed: NOT_FORWARDED. Destination likely on the "
               "same subnet – try BPF_FIB_LOOKUP_DIRECT for on-link lookup.");
    break;
  case BPF_FIB_LKUP_RET_FWD_DISABLED:
    bpf_printk("FIB lookup failed: FORWARDING DISABLED. Enable it via 'sysctl "
               "-w net.ipv4.ip_forward=1' or IPv6 equivalent.");
    break;
  case BPF_FIB_LKUP_RET_UNSUPP_LWT:
    bpf_printk("FIB lookup failed: UNSUPPORTED LWT. The route uses a "
               "lightweight tunnel not supported by bpf_fib_lookup().");
    break;
  case BPF_FIB_LKUP_RET_NO_NEIGH:
    bpf_printk("FIB lookup failed: NO NEIGHBOR ENTRY. ARP/NDP unresolved – "
               "check 'ip neigh show' or ping the target to populate cache.");
    break;
  case BPF_FIB_LKUP_RET_FRAG_NEEDED:
    bpf_printk("FIB lookup failed: FRAGMENTATION NEEDED. Packet exceeds MTU; "
               "adjust packet size or enable PMTU discovery.");
    break;
  case BPF_FIB_LKUP_RET_NO_SRC_ADDR:
    bpf_printk(
        "FIB lookup failed: NO SOURCE ADDRESS. Kernel couldn’t choose a source "
        "IP – ensure the interface has an IP in the correct subnet.");
    break;
  default:
    bpf_printk("FIB lookup failed: rc=%d (unknown). Check routing and ARP/NDP "
               "configuration.",
               rc);
    break;
  }
}

static __always_inline __u16 recalc_ip_checksum(struct iphdr *ip)
{
  // Clear checksum
  ip->check = 0;

  // Compute incremental checksum difference over the header
  __u64 csum = bpf_csum_diff(0, 0, (unsigned int *)ip, sizeof(struct iphdr), 0);

// fold 64-bit csum to 16 bits (the “carry add” loop)
#pragma unroll
  for (int i = 0; i < 4; i++)
  {
    if (csum >> 16)
      csum = (csum & 0xffff) + (csum >> 16);
  }

  return ~csum;
}

static __always_inline __u16 recalc_tcp_checksum(struct tcphdr *tcph, struct iphdr *iph, void *data_end)
{
  tcph->check = 0;
  __u32 sum = 0;

  // Pseudo-header: IP addresses
  sum += (__u16)(iph->saddr >> 16) + (__u16)(iph->saddr & 0xFFFF);
  sum += (__u16)(iph->daddr >> 16) + (__u16)(iph->daddr & 0xFFFF);
  sum += bpf_htons(IPPROTO_TCP);

  // Pseudo-header: TCP Length (Total IP len - IP header len)
  // IMPORTANT: Use the IP header, not data_end
  __u16 tcp_len = bpf_ntohs(iph->tot_len) - (iph->ihl * 4);
  sum += bpf_htons(tcp_len);

  // TCP Header + Payload
  // Use a safe bound check against data_end for the pointer,
  // but the loop limit should be based on the actual packet size
  __u16 *ptr = (__u16 *)tcph;
  for (int i = 0; i < MAX_TCP_CHECK_WORDS; i++)
  {
    if ((void *)(ptr + 1) > data_end || (void *)ptr >= (void *)tcph + tcp_len)
      break;
    sum += *ptr;
    ptr++;
  }

  // Handle odd-length packets (the last byte)
  if (tcp_len & 1)
  {
    if ((void *)ptr + 1 <= data_end)
    {
      sum += bpf_htons(*(__u8 *)ptr << 8);
    }
  }

  while (sum >> 16)
    sum = (sum & 0xFFFF) + (sum >> 16);

  return ~sum;
}

static __always_inline int fib_lookup_v4_full(struct xdp_md *ctx,
                                              struct bpf_fib_lookup *fib,
                                              __u32 src, __u32 dst,
                                              __u16 tot_len)
{
  // Zero and populate only what a full lookup needs
  __builtin_memset(fib, 0, sizeof(*fib));
  // Hardcode address family: AF_INET for IPv4
  fib->family = AF_INET;
  // Source IPv4 address used by the kernel for policy routing and source
  // address–based decisions
  fib->ipv4_src = src;
  // Destination IPv4 address (in network byte order)
  // The address we want to reach; used to find the correct egress route
  fib->ipv4_dst = dst;
  // Hardcoded Layer 4 protocol: TCP, UDP, ICMP
  fib->l4_protocol = IPPROTO_TCP;
  // Total length of the IPv4 packet (header + payload)
  fib->tot_len = tot_len;
  // Interface for the lookup
  fib->ifindex = ctx->ingress_ifindex;

  return bpf_fib_lookup(ctx, fib, sizeof(*fib), 0);
}

// Helper: build the conntrack key for a given (lb_ip, backend_ip,
// client_src_port, dest_port).

static __always_inline struct five_tuple_t
make_ct_key(__u32 lb_ip, __u32 backend_ip,
            __u16 client_src_port, __u16 dest_port)
{
  struct five_tuple_t k = {};
  k.src_ip = lb_ip;
  k.dst_ip = backend_ip;
  k.src_port = client_src_port;
  k.dst_port = dest_port;
  k.protocol = IPPROTO_TCP;
  return k;
}

// Helper: build the backendtrack key for the client-facing direction

static __always_inline struct five_tuple_t
make_bt_key(__u32 client_ip, __u32 lb_ip,
            __u16 client_src_port, __u16 dest_port)
{
  struct five_tuple_t k = {};
  k.src_ip = client_ip;
  k.dst_ip = lb_ip;
  k.src_port = client_src_port;
  k.dst_port = dest_port;
  k.protocol = IPPROTO_TCP;
  return k;
}

// XDP program

SEC("xdp")
int xdp_load_balancer(struct xdp_md *ctx)
{
  void *data_end = (void *)(long)ctx->data_end;
  void *data = (void *)(long)ctx->data;

  struct hdr_cursor nh = {.pos = data};

  // parse Ethernet header
  struct ethhdr *eth;
  int eth_type = parse_ethhdr(&nh, data_end, &eth);
  if (eth_type != bpf_htons(ETH_P_IP))
    return XDP_PASS;

  // parse IP header
  struct iphdr *ip;
  int ip_type = parse_iphdr(&nh, data_end, &ip);
  if ((void *)(ip + 1) > data_end)
    return XDP_PASS;
  if (ip->protocol != IPPROTO_TCP)
    // for simplicity, only load balance TCP traffic
    return XDP_PASS;

  // parse tcp header
  struct tcphdr *tcp;
  int tcp_type = parse_tcphdr(&nh, data_end, &tcp);
  if ((void *)(tcp + 1) > data_end)
    return XDP_PASS;

  // We could technically load-balance all the traffic but
  // we only focus on port 8000 to not impact any other network traffic in the playground
  if (bpf_ntohs(tcp->source) != 8000 && bpf_ntohs(tcp->dest) != 8000)
    return XDP_PASS;

  bpf_printk("IN: SRC IP %pI4 -> DST IP %pI4", &ip->saddr, &ip->daddr);
  /*bpf_printk("IN: SRC MAC %02x:%02x:%02x:%02x:%02x:%02x -> DST MAC "
             "%02x:%02x:%02x:%02x:%02x:%02x",
             eth->h_source[0], eth->h_source[1], eth->h_source[2],
             eth->h_source[3], eth->h_source[4], eth->h_source[5],
             eth->h_dest[0], eth->h_dest[1], eth->h_dest[2], eth->h_dest[3],
             eth->h_dest[4], eth->h_dest[5]);*/

  // store Load Balancer IP for later
  __u32 lb_ip = ip->daddr;

  struct bpf_fib_lookup fib = {};

  // Build the conntrack reverse-lookup key (used when packet came
  // from the backend toward the LB).
  struct five_tuple_t ct_key_from_backend = {};
  ct_key_from_backend.src_ip = ip->daddr;     // LB IP
  ct_key_from_backend.dst_ip = ip->saddr;     // backend IP
  ct_key_from_backend.src_port = tcp->dest;   // client src port
  ct_key_from_backend.dst_port = tcp->source; // dest port on backend side
  ct_key_from_backend.protocol = IPPROTO_TCP;

  struct conn_meta *ct = bpf_map_lookup_elem(&conntrack, &ct_key_from_backend);

  if (ct)
  {
    // packet arrived from backend, conntrack entry exists
    //  check if backend is terminating the connection
    if (tcp->fin)
    {
      struct conn_meta updated = *ct;
      if (ct->state == 2)
      {
        // Client already sent FIN , both sides done
        updated.state = 4;
      }
      else
      {
        // Backend FIN is first
        updated.state = 3;
      }
      bpf_map_update_elem(&conntrack, &ct_key_from_backend, &updated, BPF_ANY);
      ct = bpf_map_lookup_elem(&conntrack, &ct_key_from_backend);
      if (!ct)
        return XDP_ABORTED;
    }

    //  Cleanup: final ACK or RST
    if ((tcp->ack && ct->state == 4 && tcp->fin == 0) || tcp->rst)
    {
      // Decrement backend connection counter
      struct backend *b = bpf_map_lookup_elem(&backends, &ct->backend_idx);
      if (!b)
        return XDP_ABORTED;
      struct backend nb = *b;
      if (nb.conns > 0)
        nb.conns -= 1;
      bpf_map_update_elem(&backends, &ct->backend_idx, &nb, BPF_ANY);

      // Delete conntrack entry
      bpf_map_delete_elem(&conntrack, &ct_key_from_backend);

      // Delete backendtrack entry (key is client-facing direction)
      struct five_tuple_t bt_key = make_bt_key(ct->ip, ip->daddr,
                                               tcp->dest, // client src port
                                               tcp->source);
      bpf_map_delete_elem(&backendtrack, &bt_key);

      bpf_printk("connection deleted. (Backend path) Backend %pI4 conns=%d",
                 &b->ip, nb.conns);
    }

    // FIB lookup: send reply toward the client
    int rc = fib_lookup_v4_full(ctx, &fib, ip->daddr, ct->ip,
                                bpf_ntohs(ip->tot_len));
    if (rc != BPF_FIB_LKUP_RET_SUCCESS)
    {
      log_fib_error(rc);
      return XDP_ABORTED;
    }

    // Rewrite destination to client IP/MAC
    ip->daddr = ct->ip;
    __builtin_memcpy(eth->h_dest, fib.dmac, ETH_ALEN);
  }
  else
  {
    // conntrack entry not found, hence packet is from client
    // Build the client-facing five-tuple for backendtrack
    struct five_tuple_t bt_key = make_bt_key(ip->saddr, ip->daddr,
                                             tcp->source, tcp->dest);

    struct five_tuple_t *ct_key_ptr =
        bpf_map_lookup_elem(&backendtrack, &bt_key);

    struct backend *b;
    struct five_tuple_t ct_key = {};

    if (!ct_key_ptr)
    {
      if (tcp->syn == 0)
        // if not SYN, but no existing connection, drop (not valid)
        return XDP_ABORTED;
      // New connection: pick backend with least connections
      __u32 key = 0;
      __u32 min_conn = (__u32)-1;
      // find current number of backends from user space
      __u32 zero = 0;
      __u32 *num_backends = bpf_map_lookup_elem(&backend_count, &zero);
      if (!num_backends)
        return XDP_ABORTED;
      // iterate over all backends
      for (__u32 i = 0; i < MAX_BACKENDS; i++)
      {
        if (i >= *num_backends)
        {
          break;
        }
        __u32 k = i;
        struct backend *b = bpf_map_lookup_elem(&backends, &k);
        if (b && b->conns < min_conn)
        {
          min_conn = b->conns;
          key = k;
        }
      }

      b = bpf_map_lookup_elem(&backends, &key);
      if (!b)
        return XDP_ABORTED;

      // Increment connection counter for the backend
      struct backend nb = *b;
      nb.conns += 1;
      bpf_map_update_elem(&backends, &key, &nb, BPF_ANY);
      bpf_printk("handshake started : Backend %pI4 conns=%d",
                 &b->ip, nb.conns);

      // Build the conntrack key to store new connection(backend ip and state)
      ct_key = make_ct_key(ip->daddr, b->ip, tcp->source, tcp->dest);

      // store connection (state=0: SYN seen, not yet established)
      struct conn_meta meta = {};
      meta.ip = ip->saddr; // client IP for reply rewriting
      meta.backend_idx = key;
      meta.state = 0;

      // Insert into conntrack (used by backend )
      if (bpf_map_update_elem(&conntrack, &ct_key, &meta, BPF_ANY) != 0)
        return XDP_ABORTED;

      // Insert into backendtrack with the conntrack key as value
      if (bpf_map_update_elem(&backendtrack, &bt_key, &ct_key, BPF_ANY) != 0)
        return XDP_ABORTED;
    }
    else
    {
      // ── Existing connection: look up the live conn_meta ──────
      ct_key = *ct_key_ptr;

      ct = bpf_map_lookup_elem(&conntrack, &ct_key);
      if (!ct)
        return XDP_ABORTED;

      b = bpf_map_lookup_elem(&backends, &ct->backend_idx);
      if (!b)
        return XDP_ABORTED;

      //  If state is 0 and first non-SYN packet , meaning connection established
      if (ct->state == 0 && tcp->syn == 0)
      {
        struct conn_meta updated = *ct;
        updated.state = 1; // connection established, update state to 1
        // Only one write needed , backendtrack points here
        bpf_map_update_elem(&conntrack, &ct_key, &updated, BPF_ANY);

        // bpf_printk("conn established : Backend %pI4 conns=%d",
        //            &b->ip, b->conns);
        ct = bpf_map_lookup_elem(&conntrack, &ct_key);
        if (!ct)
          return XDP_ABORTED;
      }

      // if FIN packet, connection is terminating
      if (tcp->fin)
      {
        struct conn_meta updated = *ct;
        if (ct->state == 3)
        {
          // Backend already sent FIN, both sides done, update state to 4 to wait for final ACK before cleanup
          updated.state = 4;
        }
        else
        {
          // Client FIN is first
          updated.state = 2; // update state to 2 to wait for backend FIN
        }
        // Single write to conntrack , both paths will see it
        bpf_map_update_elem(&conntrack, &ct_key, &updated, BPF_ANY);

        ct = bpf_map_lookup_elem(&conntrack, &ct_key);
        if (!ct)
          return XDP_ABORTED;
      }

      // cleanup: final ACK or RST
      if ((tcp->ack && ct->state == 4 && tcp->fin == 0) || tcp->rst)
      {
        struct backend nb = *b;
        // decrement backend connection counter
        if (nb.conns > 0)
          nb.conns -= 1;
        bpf_map_update_elem(&backends, &ct->backend_idx, &nb, BPF_ANY);
        // delete conntrack and backendtrack entries
        bpf_map_delete_elem(&conntrack, &ct_key);
        bpf_map_delete_elem(&backendtrack, &bt_key);

        bpf_printk("conn deleted (client path). Backend %pI4 conns=%d",
                   &b->ip, nb.conns);
      }
    }

    // FIB lookup: forward packet toward the backend
    int rc = fib_lookup_v4_full(ctx, &fib, ip->daddr, b->ip,
                                bpf_ntohs(ip->tot_len));
    if (rc != BPF_FIB_LKUP_RET_SUCCESS)
    {
      log_fib_error(rc);
      return XDP_ABORTED;
    }

    // Rewrite destination to backend IP/MAC
    ip->daddr = b->ip;
    __builtin_memcpy(eth->h_dest, fib.dmac, ETH_ALEN);

    bpf_printk("Backend %pI4 conns=%d", &b->ip, b->conns);
  }

  // rewrite: source IP/MAC = LB
  ip->saddr = lb_ip;
  __builtin_memcpy(eth->h_source, fib.smac, ETH_ALEN);

  // Recalculate checksums
  ip->check = recalc_ip_checksum(ip);
  tcp->check = recalc_tcp_checksum(tcp, ip, data_end);

  /*bpf_printk("OUT: SRC IP %pI4 -> DST IP %pI4", &ip->saddr, &ip->daddr);
  bpf_printk("OUT SRC MAC %02x:%02x", eth->h_source[0], eth->h_source[1]);
  bpf_printk("OUT SRC MAC %02x:%02x", eth->h_source[2], eth->h_source[3]);
  bpf_printk("OUT SRC MAC %02x:%02x", eth->h_source[4], eth->h_source[5]);

  bpf_printk("OUT DST MAC %02x:%02x", eth->h_dest[0], eth->h_dest[1]);
  bpf_printk("OUT DST MAC %02x:%02x", eth->h_dest[2], eth->h_dest[3]);
  bpf_printk("OUT DST MAC %02x:%02x", eth->h_dest[4], eth->h_dest[5]);*/

  return XDP_TX;
}

char _license[] SEC("license") = "GPL";
