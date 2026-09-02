#ifndef __BPF_HELPERS_H
#define __BPF_HELPERS_H

#include <linux/types.h>
#include <linux/bpf.h>

#define SEC(NAME) __attribute__((section(NAME), used))

/* Helper function prototypes with official Linux UAPI helper IDs */
static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *) 1;
static long (*bpf_map_update_elem)(void *map, const void *key, const void *value, __u64 flags) = (void *) 2;
static long (*bpf_map_delete_elem)(void *map, const void *key) = (void *) 3;
static __u64 (*bpf_ktime_get_ns)(void) = (void *) 5;
static long (*bpf_perf_event_output)(void *ctx, void *map, __u64 flags, void *data, __u64 size) = (void *) 25;
static __u64 (*bpf_get_socket_cookie)(void *ctx) = (void *) 46;
static long (*bpf_setsockopt)(struct bpf_sock_ops *skops, int level, int optname, void *optval, int optlen) = (void *) 49;
static long (*bpf_sock_ops_cb_flags_set)(struct bpf_sock_ops *skops, int flags) = (void *) 59;
static long (*bpf_reserve_hdr_opt)(struct bpf_sock_ops *skops, __u32 len, __u32 flags) = (void *) 144;

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
