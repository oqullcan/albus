#ifndef __BPF_HELPERS_H
#define __BPF_HELPERS_H

#include <linux/types.h>
#include <linux/bpf.h>

#define SEC(NAME) __attribute__((section(NAME), used))

/* Helper function prototypes with official Linux UAPI helper IDs */
#define BPF_HELPER(ret, name, args, id) \
    static ret (*bpf_##name) args __attribute__((unused)) = (ret (*) args) (id)

BPF_HELPER(void *, map_lookup_elem, (void *map, const void *key), 1);
BPF_HELPER(long, map_update_elem, (void *map, const void *key, const void *value, __u64 flags), 2);
BPF_HELPER(long, map_delete_elem, (void *map, const void *key), 3);
BPF_HELPER(__u64, ktime_get_ns, (void), 5);
BPF_HELPER(__u32, get_prandom_u32, (void), 7);
BPF_HELPER(long, perf_event_output, (void *ctx, void *map, __u64 flags, void *data, __u64 size), 25);
BPF_HELPER(__u64, get_socket_cookie, (void *ctx), 46);
BPF_HELPER(long, setsockopt, (struct bpf_sock_ops *skops, int level, int optname, void *optval, int optlen), 49);
BPF_HELPER(long, sock_ops_cb_flags_set, (struct bpf_sock_ops *skops, int flags), 59);
BPF_HELPER(long, reserve_hdr_opt, (struct bpf_sock_ops *skops, __u32 len, __u32 flags), 144);

/* SockOps program success return value */
#define BPF_OK 1
#define SOL_TCP 6
#define TCP_MAXSEG 2

#ifndef BPF_F_CURRENT_CPU
#define BPF_F_CURRENT_CPU 0xFFFFFFFFULL
#endif

#ifndef BPF_ANY
#define BPF_ANY 0
#endif

#endif /* __BPF_HELPERS_H */
