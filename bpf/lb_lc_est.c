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

// every backend's ip, port, and number of active connections
struct backend
{
  __u32 ip;
  __u16 port; // backend listen port (e.g. 8080, 9000, ...)
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
  __u32 ip;           // client IP (used for backend traffic to rewrite back to client IP)
  __u32 backend_idx;  // used for client traffic to index into backends map
  __u16 backend_port; // backend port, needed to restore tcp->source on the reply path
  __u8 state;
};

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
//   dst_port = backend listen port
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
//   dst_port = LB listen port
//
// Value is the conntrack key so we can look up the single authoritative
// conn_meta without duplicating state.
struct
{
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1000);
  __type(key, struct five_tuple_t);
  __type(value, struct five_tuple_t);
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
        "FIB lookup failed: NO SOURCE ADDRESS. Kernel couldn't choose a source "
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
  ip->check = 0;
  __u64 csum = bpf_csum_diff(0, 0, (unsigned int *)ip, sizeof(struct iphdr), 0);
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

  sum += (__u16)(iph->saddr >> 16) + (__u16)(iph->saddr & 0xFFFF);
  sum += (__u16)(iph->daddr >> 16) + (__u16)(iph->daddr & 0xFFFF);
  sum += bpf_htons(IPPROTO_TCP);

  __u16 tcp_len = bpf_ntohs(iph->tot_len) - (iph->ihl * 4);
  sum += bpf_htons(tcp_len);

  __u16 *ptr = (__u16 *)tcph;
#pragma unroll
  for (int i = 0; i < MAX_TCP_CHECK_WORDS; i++)
  {
    if ((void *)(ptr + 1) > data_end || (void *)ptr >= (void *)tcph + tcp_len)
      break;
    sum += *ptr;
    ptr++;
  }

  if (tcp_len & 1)
  {
    if ((void *)ptr + 1 <= data_end)
      sum += bpf_htons(*(__u8 *)ptr << 8);
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
  __builtin_memset(fib, 0, sizeof(*fib));
  fib->family = AF_INET;
  fib->ipv4_src = src;
  fib->ipv4_dst = dst;
  fib->l4_protocol = IPPROTO_TCP;
  fib->tot_len = tot_len;
  fib->ifindex = ctx->ingress_ifindex;
  return bpf_fib_lookup(ctx, fib, sizeof(*fib), 0);
}

// Build the conntrack key (LB-side, as seen FROM the backend):
//   src = LB IP, dst = backend IP, src_port = client src port, dst_port = backend port
static __always_inline struct five_tuple_t
make_ct_key(__u32 lb_ip, __u32 backend_ip,
            __u16 client_src_port, __u16 backend_port)
{
  struct five_tuple_t k = {};
  k.src_ip = lb_ip;
  k.dst_ip = backend_ip;
  k.src_port = client_src_port;
  k.dst_port = backend_port;
  k.protocol = IPPROTO_TCP;
  return k;
}

// Build the backendtrack key (client-facing direction):
//   src = client IP, dst = LB IP, src_port = client src port, dst_port = LB port
static __always_inline struct five_tuple_t
make_bt_key(__u32 client_ip, __u32 lb_ip,
            __u16 client_src_port, __u16 lb_port)
{
  struct five_tuple_t k = {};
  k.src_ip = client_ip;
  k.dst_ip = lb_ip;
  k.src_port = client_src_port;
  k.dst_port = lb_port;
  k.protocol = IPPROTO_TCP;
  return k;
}

// XDP program — Least Connections, established-counting variant
// (connection counter is incremented only once the 3-way handshake completes)

SEC("xdp")
int xdp_load_balancer(struct xdp_md *ctx)
{
  void *data_end = (void *)(long)ctx->data_end;
  void *data = (void *)(long)ctx->data;

  struct hdr_cursor nh = {.pos = data};

  struct ethhdr *eth;
  if (parse_ethhdr(&nh, data_end, &eth) != bpf_htons(ETH_P_IP))
    return XDP_PASS;

  struct iphdr *ip;
  parse_iphdr(&nh, data_end, &ip);
  if ((void *)(ip + 1) > data_end)
    return XDP_PASS;
  if (ip->protocol != IPPROTO_TCP)
    return XDP_PASS;

  struct tcphdr *tcp;
  parse_tcphdr(&nh, data_end, &tcp);
  if ((void *)(tcp + 1) > data_end)
    return XDP_PASS;

  __u32 lb_ip = ip->daddr;

  struct bpf_fib_lookup fib;

  // Build the conntrack reverse-lookup key (packet FROM backend toward LB):
  //   src = LB IP, dst = backend IP, src_port = client src port, dst_port = backend port
  struct five_tuple_t ct_key_from_backend =
      make_ct_key(ip->daddr, ip->saddr, tcp->dest, tcp->source);

  struct conn_meta *ct = bpf_map_lookup_elem(&conntrack, &ct_key_from_backend);

  if (ct)
  {
    // Packet arrived from backend — conntrack entry exists.
    if (tcp->fin)
    {
      struct conn_meta updated = *ct;
      updated.state = (ct->state == 2) ? 4  // client already FIN'd → both done
                                       : 3; // backend FIN first
      bpf_map_update_elem(&conntrack, &ct_key_from_backend, &updated, BPF_ANY);
      ct = bpf_map_lookup_elem(&conntrack, &ct_key_from_backend);
      if (!ct)
        return XDP_ABORTED;
    }

    // Cleanup: final ACK or RST
    if ((tcp->ack && ct->state == 4 && !tcp->fin) || tcp->rst)
    {
      struct backend *b = bpf_map_lookup_elem(&backends, &ct->backend_idx);
      if (!b)
        return XDP_ABORTED;
      struct backend nb = *b;
      if (nb.conns > 0)
        nb.conns--;
      bpf_map_update_elem(&backends, &ct->backend_idx, &nb, BPF_ANY);

      bpf_map_delete_elem(&conntrack, &ct_key_from_backend);

      struct five_tuple_t bt_key = make_bt_key(ct->ip, ip->daddr,
                                               tcp->dest,    // client src port
                                               tcp->source); // LB port
      bpf_map_delete_elem(&backendtrack, &bt_key);

      /*bpf_printk("connection deleted (backend path). Backend %pI4 conns=%d",
                 &b->ip, nb.conns);*/
    }

    // FIB lookup: send reply toward the client
    int rc = fib_lookup_v4_full(ctx, &fib, ip->daddr, ct->ip,
                                bpf_ntohs(ip->tot_len));
    if (rc != BPF_FIB_LKUP_RET_SUCCESS)
    {
      log_fib_error(rc);
      return XDP_ABORTED;
    }

    // Rewrite: destination → client, restore source port to LB port
    ip->daddr = ct->ip;
    tcp->source = bpf_htons(ct->backend_port); // restore to what client originally saw
    __builtin_memcpy(eth->h_dest, fib.dmac, ETH_ALEN);
  }
  else
  {
    // Conntrack miss → packet is from the client side.
    struct five_tuple_t bt_key = make_bt_key(ip->saddr, ip->daddr,
                                             tcp->source, tcp->dest);

    struct five_tuple_t *ct_key_ptr =
        bpf_map_lookup_elem(&backendtrack, &bt_key);

    struct backend *b;
    struct five_tuple_t ct_key = {};

    if (!ct_key_ptr)
    {
      // No existing connection — must be a SYN.
      if (!tcp->syn)
        return XDP_ABORTED;

      // Pick backend with least established connections.
      __u32 zero = 0;
      __u32 *num_backends = bpf_map_lookup_elem(&backend_count, &zero);
      if (!num_backends)
        return XDP_ABORTED;

      __u32 best_key = 0;
      __u32 min_conn = (__u32)-1;

      for (__u32 i = 0; i < MAX_BACKENDS; i++)
      {
        if (i >= *num_backends)
          break;
        __u32 k = i;
        struct backend *cand = bpf_map_lookup_elem(&backends, &k);
        if (cand && cand->conns < min_conn)
        {
          min_conn = cand->conns;
          best_key = k;
        }
      }

      b = bpf_map_lookup_elem(&backends, &best_key);
      if (!b)
        return XDP_ABORTED;

      ct_key = make_ct_key(ip->daddr, b->ip, tcp->source, b->port);

      // State = 0: SYN seen, counter incremented only on first non-SYN (EST-counting).
      struct conn_meta meta = {};
      meta.ip = ip->saddr;
      meta.backend_idx = best_key;
      meta.backend_port = bpf_ntohs(b->port);
      meta.state = 0;

      if (bpf_map_update_elem(&conntrack, &ct_key, &meta, BPF_ANY) != 0)
        return XDP_ABORTED;
      if (bpf_map_update_elem(&backendtrack, &bt_key, &ct_key, BPF_ANY) != 0)
        return XDP_ABORTED;
    }
    else
    {
      // Existing connection — resolve the live conn_meta.
      ct_key = *ct_key_ptr;

      ct = bpf_map_lookup_elem(&conntrack, &ct_key);
      if (!ct)
        return XDP_ABORTED;

      b = bpf_map_lookup_elem(&backends, &ct->backend_idx);
      if (!b)
        return XDP_ABORTED;

      // First non-SYN after SYN-ACK → connection established, increment counter.
      if (ct->state == 0 && !tcp->syn)
      {
        struct conn_meta updated = *ct;
        updated.state = 1;
        bpf_map_update_elem(&conntrack, &ct_key, &updated, BPF_ANY);

        struct backend nb = *b;
        nb.conns++;
        bpf_map_update_elem(&backends, &ct->backend_idx, &nb, BPF_ANY);
        // bpf_printk("conn established: Backend %pI4 conns=%d", &b->ip, nb.conns);

        ct = bpf_map_lookup_elem(&conntrack, &ct_key);
        if (!ct)
          return XDP_ABORTED;
      }

      if (tcp->fin)
      {
        struct conn_meta updated = *ct;
        updated.state = (ct->state == 3) ? 4 : 2;
        bpf_map_update_elem(&conntrack, &ct_key, &updated, BPF_ANY);
        ct = bpf_map_lookup_elem(&conntrack, &ct_key);
        if (!ct)
          return XDP_ABORTED;
      }

      if ((tcp->ack && ct->state == 4 && !tcp->fin) || tcp->rst)
      {
        struct backend nb = *b;
        if (nb.conns > 0)
          nb.conns--;
        bpf_map_update_elem(&backends, &ct->backend_idx, &nb, BPF_ANY);
        bpf_map_delete_elem(&conntrack, &ct_key);
        bpf_map_delete_elem(&backendtrack, &bt_key);
        /* bpf_printk("conn deleted (client path). Backend %pI4 conns=%d",
                   &b->ip, nb.conns); */
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

    // Rewrite: destination → backend IP/port
    ip->daddr = b->ip;
    tcp->dest = b->port; // already in network byte order
    __builtin_memcpy(eth->h_dest, fib.dmac, ETH_ALEN);

    // bpf_printk("Backend %pI4 conns=%d", &b->ip, b->conns);
  }

  // Common rewrite: source IP/MAC = LB
  ip->saddr = lb_ip;
  __builtin_memcpy(eth->h_source, fib.smac, ETH_ALEN);

  ip->check = recalc_ip_checksum(ip);
  tcp->check = recalc_tcp_checksum(tcp, ip, data_end);

  return XDP_TX;
}

char _license[] SEC("license") = "GPL";
