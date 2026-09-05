/* 
 * L7 eBPF Program for Network Session Tracking
 * 
 * This program hooks into kernel network events to track socket
 * connections and associate them with the processes that created them.
 * 
 * It attaches to tcp_set_state, tcp_v4_connect, and tcp_v6_connect kprobes
 * to capture TCP connection state changes and associate them with processes.
 * 
 * Supports both IPv4 and IPv6.
 */

/* Include our minimal vmlinux.h first for kernel structure definitions */
#include "vmlinux.h"

/* Include BPF helper headers */
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

/* 
 * Note: We intentionally do NOT include <bpf/bpf_tracing.h> because it 
 * redefines PT_REGS_PARM* macros using short register names (di, si) that
 * conflict with our vmlinux.h struct pt_regs which uses full names (rdi, rsi).
 * Our vmlinux.h already provides the necessary PT_REGS_PARM* definitions.
 */

#define MAX_ENTRIES 65536

/* Network protocol constants */
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17

/* Socket states */
#define TCP_ESTABLISHED 1
#define TCP_SYN_SENT 2
#define TCP_SYN_RECV 3
#define TCP_CLOSE 7

/*
 * sock_common structure offsets (verified with pahole on 6.8.0-88-generic)
 * These are used for direct memory reads without CO-RE.
 * 
 * struct sock_common {
 *     union {
 *         struct { __be32 skc_daddr; __be32 skc_rcv_saddr; };  // 0, 4
 *     };
 *     union { unsigned int skc_hash; };                        // 8
 *     union {
 *         struct { __be16 skc_dport; __u16 skc_num; };         // 12, 14
 *     };
 *     unsigned short skc_family;                               // 16
 *     volatile unsigned char skc_state;                        // 18
 *     ...
 *     struct in6_addr skc_v6_daddr;                            // 56 (16 bytes)
 *     struct in6_addr skc_v6_rcv_saddr;                        // 72 (16 bytes)
 * };
 */
#define SKC_DADDR_OFFSET        0
#define SKC_RCV_SADDR_OFFSET    4
#define SKC_DPORT_OFFSET        12
#define SKC_NUM_OFFSET          14
#define SKC_FAMILY_OFFSET       16
#define SKC_V6_DADDR_OFFSET     56
#define SKC_V6_RCV_SADDR_OFFSET 72

/* Data structures matching the Rust side */
struct session_key {
    __u32 src_ip[4];    /* IPv4/IPv6 address (IPv4 uses first element) */
    __u32 dst_ip[4];    /* IPv4/IPv6 address (IPv4 uses first element) */
    __u16 src_port;
    __u16 dst_port;
    __u8 protocol;      /* TCP=6, UDP=17 */
    __u8 family;        /* AF_INET=2, AF_INET6=10 */
    __u16 padding;      /* Ensure alignment */
};

struct process_info {
    __u32 pid;
    __u32 uid;
    __u64 start_time;
    char process_name[16];
    char process_path[256];
    char username[32];
};

/* eBPF maps */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, struct session_key);
    __type(value, struct process_info);
} l7_connections SEC(".maps");

/* Helper map to track socket to process mappings */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, __u64);  /* socket pointer */
    __type(value, struct process_info);
} socket_to_process SEC(".maps");

/*
 * FLODBADD2 §1b.2 process-event monitoring stream (monitoring role
 * only). A ringbuf of exec/fork/exit events plus a child->parent map so
 * exec/exit events carry ppid without userspace /proc races. Requires
 * kernel 5.8+ for BPF_MAP_TYPE_RINGBUF; on older kernels the loader's
 * tracepoint attach fails and the stream degrades to absent (fail-open).
 */
#ifndef BPF_MAP_TYPE_RINGBUF
#define BPF_MAP_TYPE_RINGBUF 27
#endif

#define PROC_EVENT_EXEC 1
#define PROC_EVENT_FORK 2
#define PROC_EVENT_EXIT 3

struct proc_event {
    __u32 kind;
    __u32 pid;
    __u32 ppid;
    __u32 uid;
    char filename[256]; /* exec: binary path; fork/exit: comm */
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 262144);
} proc_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, __u32);   /* child pid */
    __type(value, __u32); /* parent pid */
} proc_parent SEC(".maps");

/*
 * sched_process_exec context layout (from
 * /sys/kernel/tracing/events/sched/sched_process_exec/format): the 8-byte
 * common header is type(2)+flags(1)+preempt(1)+pid(4), then
 * __data_loc filename @8, pid @12, old_pid @16. Unchanged across every
 * kernel we run on, so it can be a fixed struct.
 */
struct tp_sched_process_exec {
    __u64 _common;
    __u32 __data_loc_filename;
    __u32 pid;
    __u32 old_pid;
};

/*
 * sched_process_fork / sched_process_exit are NOT layout-stable: 6.17
 * stores the comm fields of sched_process_fork as __data_loc (record is
 * 24 bytes) while 5.x/6.8 keep inline char[16] (record is 48 bytes).
 * Direct ctx loads at the wrong offset are rejected at ATTACH time
 * (perf_event_set_bpf_prog: max_ctx_offset > record size -> EACCES),
 * which is exactly the "bpf_link_create failed" seen on the 6.17
 * dogfood host. So the loader reads the live `format` files and hands
 * the offsets in through `proc_tp_cfg`; the programs then read every
 * field with bpf_probe_read_kernel (no direct ctx access, so nothing
 * for max_ctx_offset to trip on) and stay silent (fail-open) until the
 * config is valid.
 */
struct proc_tp_cfg {
    __u32 valid;
    __u32 fork_parent_pid_off;
    __u32 fork_child_pid_off;
    __u32 fork_child_comm_off;
    __u32 fork_child_comm_data_loc; /* 1: __data_loc u32 at off; 0: inline char[16] */
    __u32 exit_pid_off;
    __u32 exit_comm_off;
    __u32 exit_comm_data_loc;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct proc_tp_cfg);
} proc_tp_cfg SEC(".maps");

static __always_inline __u32 tp_read_u32(void *ctx, __u32 off)
{
    __u32 v = 0;
    bpf_probe_read_kernel(&v, sizeof(v), (void *)ctx + off);
    return v;
}

/* Copy a 16-byte comm that is either inline at `off` or behind a
 * __data_loc descriptor stored at `off`. */
static __always_inline void tp_read_comm(void *ctx, __u32 off, __u32 data_loc,
                                         char *dst, __u32 dst_len)
{
    if (data_loc) {
        __u32 loc = tp_read_u32(ctx, off);
        off = loc & 0xFFFF;
    }
    bpf_probe_read_kernel_str(dst, dst_len, (void *)ctx + off);
}

/*
 * Helper to extract IPv4 address from sock_common
 * Uses stable offsets for skc_rcv_saddr (src) and skc_daddr (dst)
 */
static __always_inline __u32 extract_ipv4_addr(struct sock *sk, int is_src) {
    __u32 addr = 0;
    int offset = is_src ? SKC_RCV_SADDR_OFFSET : SKC_DADDR_OFFSET;
    bpf_probe_read_kernel(&addr, sizeof(addr), (void *)sk + offset);
    return addr;
}

/*
 * Helper to extract IPv6 address from sock_common
 * Uses skc_v6_rcv_saddr (src) at offset 72 and skc_v6_daddr (dst) at offset 56
 */
static __always_inline void extract_ipv6_addr(struct sock *sk, int is_src, __u32 *addr) {
    int offset = is_src ? SKC_V6_RCV_SADDR_OFFSET : SKC_V6_DADDR_OFFSET;
    
    /* Read all 16 bytes (4 x __u32) of the IPv6 address */
    bpf_probe_read_kernel(addr, 16, (void *)sk + offset);
}

/*
 * Helper to extract port numbers from sock_common
 * skc_dport is in network byte order, skc_num is in host byte order
 */
static __always_inline __u16 extract_port(struct sock *sk, int is_src) {
    __u16 port = 0;
    if (is_src) {
        bpf_probe_read_kernel(&port, sizeof(port), (void *)sk + SKC_NUM_OFFSET);
    } else {
        bpf_probe_read_kernel(&port, sizeof(port), (void *)sk + SKC_DPORT_OFFSET);
        port = bpf_ntohs(port);
    }
    return port;
}

/*
 * Helper to get username from UID
 * Formats as "root" for UID 0, otherwise "uid-{number}"
 */
static __always_inline void get_username_from_uid(__u32 uid, char *username, int username_size) {
    if (uid == 0) {
        __builtin_memcpy(username, "root", 5);
        return;
    }
    
    /* Format as "uid-{number}" */
    char prefix[] = "uid-";
    int i = 0;
    
    /* Copy prefix */
    #pragma unroll
    for (i = 0; i < 4; i++) {
        username[i] = prefix[i];
    }
    
    /* Convert number to string (simplified, up to 10 digits) */
    char digits[12];
    int digit_count = 0;
    __u32 temp_uid = uid;
    
    while (temp_uid > 0 && digit_count < 10) {
        digits[digit_count++] = '0' + (temp_uid % 10);
        temp_uid /= 10;
    }
    
    /* Reverse and append digits */
    for (int j = digit_count - 1; j >= 0 && i < username_size - 1; j--, i++) {
        username[i] = digits[j];
    }
    
    username[i] = '\0';
}

/* Helper to validate IP addresses */
static __always_inline int is_valid_ip(struct session_key *key) {
    if (key->family == AF_INET) {
        return key->src_ip[0] != 0 || key->dst_ip[0] != 0;
    } else if (key->family == AF_INET6) {
        return key->src_ip[0] != 0 || key->src_ip[1] != 0 || 
               key->src_ip[2] != 0 || key->src_ip[3] != 0 ||
               key->dst_ip[0] != 0 || key->dst_ip[1] != 0 ||
               key->dst_ip[2] != 0 || key->dst_ip[3] != 0;
    }
    return 0;
}

/* Helper to check if we should track this connection */
static __always_inline int should_track_connection(struct session_key *key) {
    /* Don't track if no valid IPs */
    if (!is_valid_ip(key)) {
        return 0;
    }
    
    /* Don't track if both ports are zero */
    if (key->src_port == 0 && key->dst_port == 0) {
        return 0;
    }
    
    /* Track all TCP connections */
    if (key->protocol == IPPROTO_TCP) {
        return 1;
    }
    
    /* For UDP, track DNS (53) and other well-known services */
    if (key->protocol == IPPROTO_UDP) {
        return key->src_port == 53 || key->dst_port == 53 ||
               key->src_port < 1024 || key->dst_port < 1024;
    }
    
    return 0;
}

/* Extract process information for the current task */
static __always_inline void get_process_info(struct process_info *info) {
    /* Get PID and UID */
    info->pid = bpf_get_current_pid_tgid() >> 32;
    info->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    
    /* Get process name */
    bpf_get_current_comm(info->process_name, sizeof(info->process_name));
    
    /* Start time - set to 0, userspace can get from /proc/<pid>/stat */
    info->start_time = 0;
    
    /* Process path - use comm as placeholder, userspace resolves via /proc/<pid>/exe */
    bpf_get_current_comm(info->process_path, 16);
    
    /* Username from UID */
    get_username_from_uid(info->uid, info->username, sizeof(info->username));
}

/*
 * Kprobe handler for tcp_set_state
 * Called when a TCP socket changes state (e.g., becomes ESTABLISHED)
 * Works for both IPv4 and IPv6 connections
 */
SEC("kprobe/tcp_set_state")
int minimal_probe(struct pt_regs *ctx) {
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    int new_state = (int)PT_REGS_PARM2(ctx);
    
    if (!sk) return 0;
    
    /* Only track TCP ESTABLISHED connections */
    if (new_state != TCP_ESTABLISHED) {
        return 0;
    }
    
    /* Read socket family */
    __u16 family = 0;
    bpf_probe_read_kernel(&family, sizeof(family), (void *)sk + SKC_FAMILY_OFFSET);
    
    /* Only track IPv4 and IPv6 */
    if (family != AF_INET && family != AF_INET6) {
        return 0;
    }
    
    /* Build session key */
    struct session_key key = {0};
    key.family = family;
    key.protocol = IPPROTO_TCP;
    
    if (family == AF_INET) {
        key.src_ip[0] = extract_ipv4_addr(sk, 1);
        key.dst_ip[0] = extract_ipv4_addr(sk, 0);
    } else {
        /* IPv6: read full 128-bit addresses */
        extract_ipv6_addr(sk, 1, key.src_ip);
        extract_ipv6_addr(sk, 0, key.dst_ip);
    }
    
    key.src_port = extract_port(sk, 1);
    key.dst_port = extract_port(sk, 0);
    
    /* Validate and check if we should track */
    if (!should_track_connection(&key)) {
        return 0;
    }
    
    /* Try to get process info from socket_to_process map first
     * (captured earlier in tcp_v4_connect/tcp_v6_connect when we were in user context) */
    __u64 sock_ptr = (__u64)sk;
    struct process_info *stored_info = bpf_map_lookup_elem(&socket_to_process, &sock_ptr);
    
    struct process_info info = {0};
    if (stored_info && stored_info->pid > 0) {
        /* Use the previously captured process info */
        __builtin_memcpy(&info, stored_info, sizeof(info));
    } else {
        /* Fall back to current context (may be kernel thread) */
        get_process_info(&info);
    }
    
    /* Store in l7_connections map for userspace queries */
    bpf_map_update_elem(&l7_connections, &key, &info, BPF_ANY);
    
    return 0;
}

/*
 * Kprobe handler for tcp_v4_connect
 * Called from userspace context when connect() syscall is made for IPv4.
 * This gives us accurate process information since we're in user context.
 */
SEC("kprobe/tcp_v4_connect")
int track_connect_v4(struct pt_regs *ctx) {
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    
    if (!sk) return 0;
    
    /* Store process info keyed by socket pointer - we'll merge this
     * with connection info when tcp_set_state is called */
    __u64 sock_ptr = (__u64)sk;
    struct process_info info = {0};
    get_process_info(&info);
    
    /* Only store if we have a valid PID (not kernel context) */
    if (info.pid > 0) {
        bpf_map_update_elem(&socket_to_process, &sock_ptr, &info, BPF_ANY);
    }
    
    return 0;
}

/*
 * Kprobe handler for tcp_v6_connect
 * Called from userspace context when connect() syscall is made for IPv6.
 * This gives us accurate process information since we're in user context.
 */
SEC("kprobe/tcp_v6_connect")
int track_connect_v6(struct pt_regs *ctx) {
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    
    if (!sk) return 0;
    
    /* Store process info keyed by socket pointer - we'll merge this
     * with connection info when tcp_set_state is called */
    __u64 sock_ptr = (__u64)sk;
    struct process_info info = {0};
    get_process_info(&info);
    
    /* Only store if we have a valid PID (not kernel context) */
    if (info.pid > 0) {
        bpf_map_update_elem(&socket_to_process, &sock_ptr, &info, BPF_ANY);
    }
    
    return 0;
}

/*
 * Kprobe handler for __sk_free
 * Called when a socket is being freed - clean up our tracking
 */
SEC("kprobe/__sk_free")
int socket_cleanup(struct pt_regs *ctx) {
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    
    if (!sk) return 0;
    
    __u64 sock_ptr = (__u64)sk;
    bpf_map_delete_elem(&socket_to_process, &sock_ptr);
    
    /* Note: We keep l7_connections entries for userspace to query
     * They will be cleaned up by TTL in userspace */
    
    return 0;
}

SEC("tracepoint/sched/sched_process_fork")
int trace_sched_fork(void *ctx)
{
    __u32 zero = 0;
    struct proc_tp_cfg *cfg = bpf_map_lookup_elem(&proc_tp_cfg, &zero);
    if (!cfg || !cfg->valid)
        return 0;

    __u32 child = tp_read_u32(ctx, cfg->fork_child_pid_off);
    __u32 parent = tp_read_u32(ctx, cfg->fork_parent_pid_off);
    bpf_map_update_elem(&proc_parent, &child, &parent, BPF_ANY);

    struct proc_event *ev = bpf_ringbuf_reserve(&proc_events, sizeof(*ev), 0);
    if (!ev)
        return 0;
    ev->kind = PROC_EVENT_FORK;
    ev->pid = child;
    ev->ppid = parent;
    ev->uid = (__u32)(bpf_get_current_uid_gid() & 0xffffffff);
    __builtin_memset(ev->filename, 0, sizeof(ev->filename));
    tp_read_comm(ctx, cfg->fork_child_comm_off, cfg->fork_child_comm_data_loc,
                 ev->filename, 16);
    bpf_ringbuf_submit(ev, 0);
    return 0;
}

SEC("tracepoint/sched/sched_process_exec")
int trace_sched_exec(struct tp_sched_process_exec *ctx)
{
    struct proc_event *ev = bpf_ringbuf_reserve(&proc_events, sizeof(*ev), 0);
    if (!ev)
        return 0;
    __u32 pid = ctx->pid;
    ev->kind = PROC_EVENT_EXEC;
    ev->pid = pid;
    __u32 *pp = bpf_map_lookup_elem(&proc_parent, &pid);
    ev->ppid = pp ? *pp : 0;
    ev->uid = (__u32)(bpf_get_current_uid_gid() & 0xffffffff);
    __builtin_memset(ev->filename, 0, sizeof(ev->filename));
    /* __data_loc encoding: low 16 bits = offset of the string from the
     * start of the tracepoint record. */
    unsigned int off = ctx->__data_loc_filename & 0xFFFF;
    bpf_probe_read_kernel_str(ev->filename, sizeof(ev->filename),
                              (void *)ctx + off);
    bpf_ringbuf_submit(ev, 0);
    return 0;
}

SEC("tracepoint/sched/sched_process_exit")
int trace_sched_exit(void *ctx)
{
    /* Thread exits share this tracepoint; only report group leaders so
     * the stream mirrors process lifetimes. */
    __u64 id = bpf_get_current_pid_tgid();
    if ((__u32)id != (__u32)(id >> 32))
        return 0;

    __u32 zero = 0;
    struct proc_tp_cfg *cfg = bpf_map_lookup_elem(&proc_tp_cfg, &zero);
    if (!cfg || !cfg->valid)
        return 0;

    __u32 pid = tp_read_u32(ctx, cfg->exit_pid_off);
    /* The parent survives the child; report it so exit events join the
     * same lineage as their exec, then drop the row. */
    __u32 *pp = bpf_map_lookup_elem(&proc_parent, &pid);
    __u32 ppid = pp ? *pp : 0;
    bpf_map_delete_elem(&proc_parent, &pid);

    struct proc_event *ev = bpf_ringbuf_reserve(&proc_events, sizeof(*ev), 0);
    if (!ev)
        return 0;
    ev->kind = PROC_EVENT_EXIT;
    ev->pid = pid;
    ev->ppid = ppid;
    ev->uid = (__u32)(bpf_get_current_uid_gid() & 0xffffffff);
    __builtin_memset(ev->filename, 0, sizeof(ev->filename));
    tp_read_comm(ctx, cfg->exit_comm_off, cfg->exit_comm_data_loc, ev->filename, 16);
    bpf_ringbuf_submit(ev, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
