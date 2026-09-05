// albus eBPF sock_ops program — DPI bypass via TCP MSS shrinking and
// userspace fake-ClientHello injection.
//
// Hooks into Linux kernel TCP stack via cgroup sock_ops.

#include "include/bpf_helpers.h"
#include "include/bpf_endian.h"

char _license[] SEC("license") = "GPL";

#define __uint(name, val) int (*name)[val]
#define __type(name, val) typeof(val) *name

// Configuration pushed from Rust userspace
struct albus_config_t {
    __u16 mss;
    __u16 restore_mss;
    __u32 restore_after_bytes;
    __u16 min_mss;
    __u8 enabled;
    __u8 reserved[5];
};

// 128-bit IPv6 address key container
struct ipv6_key_t {
    __u32 addr[4];
};

// Event emitted to userspace on new TCP handshake (IPv4 + IPv6)
struct conn_event_t {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u32 seq;
    __u32 ack;
    __u8 family; // 2 = AF_INET (IPv4), 10 = AF_INET6 (IPv6)
    __u8 reserved[3];
    __u32 src_ip6[4];
    __u32 dst_ip6[4];
};

// State tracked per socket to restore MSS after handshake
struct conn_state_t {
    __u32 bytes_sent;
    __u8 mss_restored;
    __u8 reserved[3];
};

// Map: Global runtime config
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct albus_config_t);
    __uint(max_entries, 1);
} config_map SEC(".maps");

// Map: Target destination ports (e.g. 443)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u16);
    __type(value, __u8);
    __uint(max_entries, 64);
} target_ports SEC(".maps");

// Map: Excluded IPv4 addresses (e.g. DoH upstream servers)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, __u8);
    __uint(max_entries, 64);
} exclude_ips SEC(".maps");

// Map: Excluded IPv6 addresses (e.g. DoH upstream servers)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct ipv6_key_t);
    __type(value, __u8);
    __uint(max_entries, 64);
} exclude_ips_v6 SEC(".maps");

// Map: Perf events sent to userspace
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __type(key, __u32);
    __type(value, __u32);
} conn_events SEC(".maps");

// Map: Socket state by cookie
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, __u64);
    __type(value, struct conn_state_t);
    __uint(max_entries, 65536);
} connections SEC(".maps");

static inline int handle_established(struct bpf_sock_ops *skops, struct albus_config_t *cfg) {
    __u32 family = skops->family;

    if (family == 10) { // AF_INET6
        struct ipv6_key_t key6;
        key6.addr[0] = skops->remote_ip6[0];
        key6.addr[1] = skops->remote_ip6[1];
        key6.addr[2] = skops->remote_ip6[2];
        key6.addr[3] = skops->remote_ip6[3];
        __u8 *excluded = bpf_map_lookup_elem(&exclude_ips_v6, &key6);
        if (excluded) {
            return BPF_OK;
        }
    } else { // AF_INET
        __u32 dst_ip = skops->remote_ip4;
        __u8 *excluded = bpf_map_lookup_elem(&exclude_ips, &dst_ip);
        if (excluded) {
            return BPF_OK;
        }
    }

    __u16 dst_port = (__u16)bpf_ntohl(skops->remote_port);
    __u8 *is_target = bpf_map_lookup_elem(&target_ports, &dst_port);
    if (!is_target) {
        return BPF_OK;
    }

    // Shrink MSS to force ClientHello fragmentation (with optional jitter)
    int mss = (int)cfg->mss;
    if (cfg->min_mss > 0 && cfg->min_mss < cfg->mss) {
        __u32 range = (__u32)(cfg->mss - cfg->min_mss + 1);
        mss = (int)cfg->min_mss + (int)(bpf_get_prandom_u32() % range);
    }
    bpf_setsockopt(skops, SOL_TCP, TCP_MAXSEG, &mss, sizeof(mss));

    // Emit connection event for fake packet injection
    struct conn_event_t evt = {
        .src_ip = skops->local_ip4,
        .dst_ip = skops->remote_ip4,
        .src_port = (__u16)skops->local_port,
        .dst_port = dst_port,
        .seq = skops->snd_nxt,
        .ack = skops->rcv_nxt,
        .family = (__u8)family,
        .reserved = {0, 0, 0},
    };
    if (family == 10) {
        evt.src_ip6[0] = skops->local_ip6[0];
        evt.src_ip6[1] = skops->local_ip6[1];
        evt.src_ip6[2] = skops->local_ip6[2];
        evt.src_ip6[3] = skops->local_ip6[3];
        evt.dst_ip6[0] = skops->remote_ip6[0];
        evt.dst_ip6[1] = skops->remote_ip6[1];
        evt.dst_ip6[2] = skops->remote_ip6[2];
        evt.dst_ip6[3] = skops->remote_ip6[3];
    }
    bpf_perf_event_output(skops, &conn_events, BPF_F_CURRENT_CPU, &evt, sizeof(evt));

    // Track connection state
    __u64 cookie = bpf_get_socket_cookie(skops);
    struct conn_state_t state = {
        .bytes_sent = 0,
        .mss_restored = 0,
    };
    bpf_map_update_elem(&connections, &cookie, &state, BPF_ANY);

    // Request WRITE_HDR_OPT callback for outgoing packets
    int flags = skops->bpf_sock_ops_cb_flags | BPF_SOCK_OPS_WRITE_HDR_OPT_CB_FLAG;
    bpf_sock_ops_cb_flags_set(skops, flags);

    return BPF_OK;
}

static inline int handle_hdr_opt_len(struct bpf_sock_ops *skops) {
    bpf_reserve_hdr_opt(skops, 0, 0);
    return BPF_OK;
}

static inline int handle_write_hdr_opt(struct bpf_sock_ops *skops, struct albus_config_t *cfg) {
    __u64 cookie = bpf_get_socket_cookie(skops);
    struct conn_state_t *state = bpf_map_lookup_elem(&connections, &cookie);
    if (!state) {
        return BPF_OK;
    }
    if (state->mss_restored) {
        return BPF_OK;
    }

    state->bytes_sent += skops->skb_len;

    if (state->bytes_sent > cfg->restore_after_bytes) {
        int normal_mss = 1460;
        if (cfg->restore_mss != 0) {
            normal_mss = (int)cfg->restore_mss;
        }
        bpf_setsockopt(skops, SOL_TCP, TCP_MAXSEG, &normal_mss, sizeof(normal_mss));

        state->mss_restored = 1;

        int flags = skops->bpf_sock_ops_cb_flags & ~BPF_SOCK_OPS_WRITE_HDR_OPT_CB_FLAG;
        bpf_sock_ops_cb_flags_set(skops, flags);

        bpf_map_delete_elem(&connections, &cookie);
    }

    return BPF_OK;
}

SEC("sockops")
int albus_sockops(struct bpf_sock_ops *skops) {
    __u32 key = 0;
    struct albus_config_t *cfg = bpf_map_lookup_elem(&config_map, &key);
    if (!cfg || !cfg->enabled) {
        return BPF_OK;
    }

    __u32 op = skops->op;
    if (op == BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB) {
        return handle_established(skops, cfg);
    }
    if (op == BPF_SOCK_OPS_HDR_OPT_LEN_CB) {
        return handle_hdr_opt_len(skops);
    }
    if (op == BPF_SOCK_OPS_WRITE_HDR_OPT_CB) {
        return handle_write_hdr_opt(skops, cfg);
    }

    return BPF_OK;
}
