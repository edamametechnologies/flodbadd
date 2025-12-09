/* 
 * DNS eBPF Program for Process-Aware DNS Resolution Tracking
 * 
 * This program hooks into UDP send operations to track DNS queries
 * and associate them with the processes that made them.
 * 
 * Strategy: Track UDP sockets sending to port 53 and record the process info.
 * Userspace correlates via source port when it sees DNS packets.
 */

/* Include our minimal vmlinux.h first for kernel structure definitions */
#include "vmlinux.h"

/* Include BPF helper headers */
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

#define MAX_ENTRIES 65536
#define DNS_PORT 53

/* Network protocol constants */
#define AF_INET 2
#define AF_INET6 10

/*
 * sock_common structure offsets (verified with pahole on 6.8.0-88-generic)
 */
#define SKC_DADDR_OFFSET      0
#define SKC_RCV_SADDR_OFFSET  4
#define SKC_DPORT_OFFSET      12
#define SKC_NUM_OFFSET        14
#define SKC_FAMILY_OFFSET     16

/* DNS socket info - keyed by source port */
struct dns_socket_info {
    __u32 pid;
    __u32 uid;
    __u64 timestamp;
    __u16 src_port;
    __u16 dst_port;
    __u8 family;
    __u8 padding[3];
    __u32 dst_ip[4];
    char process_name[16];
};

/* Map to store DNS socket info keyed by source port */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, __u16);              /* Source port */
    __type(value, struct dns_socket_info);
} dns_sockets SEC(".maps");

/* Ring buffer for DNS events (optional - for debugging/monitoring) */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);  /* 256KB ring buffer */
} dns_events SEC(".maps");

/*
 * Kprobe handler for udp_sendmsg
 * Captures DNS queries (packets sent to port 53)
 */
SEC("kprobe/udp_sendmsg")
int trace_udp_send(struct pt_regs *ctx) {
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    
    if (!sk) {
        return 0;
    }
    
    /* Read destination port */
    __u16 dst_port = 0;
    if (bpf_probe_read_kernel(&dst_port, sizeof(dst_port), 
                               (void *)sk + SKC_DPORT_OFFSET) < 0) {
        return 0;
    }
    dst_port = __builtin_bswap16(dst_port);  /* Network to host byte order */
    
    /* Only track DNS traffic (port 53) */
    if (dst_port != DNS_PORT) {
        return 0;
    }
    
    /* Get socket family */
    __u16 family = 0;
    if (bpf_probe_read_kernel(&family, sizeof(family), 
                               (void *)sk + SKC_FAMILY_OFFSET) < 0) {
        return 0;
    }
    
    /* Only IPv4/IPv6 */
    if (family != AF_INET && family != AF_INET6) {
        return 0;
    }
    
    /* Read source port */
    __u16 src_port = 0;
    if (bpf_probe_read_kernel(&src_port, sizeof(src_port), 
                               (void *)sk + SKC_NUM_OFFSET) < 0) {
        return 0;
    }
    
    /* Build socket info */
    struct dns_socket_info info = {};
    
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    info.pid = pid_tgid >> 32;
    info.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    info.timestamp = bpf_ktime_get_ns();
    info.src_port = src_port;
    info.dst_port = dst_port;
    info.family = family;
    bpf_get_current_comm(&info.process_name, sizeof(info.process_name));
    
    /* Read destination IP */
    info.dst_ip[0] = 0;
    info.dst_ip[1] = 0;
    info.dst_ip[2] = 0;
    info.dst_ip[3] = 0;
    if (family == AF_INET) {
        bpf_probe_read_kernel(&info.dst_ip[0], sizeof(__u32), 
                              (void *)sk + SKC_DADDR_OFFSET);
    }
    
    /* Store in map keyed by source port */
    bpf_map_update_elem(&dns_sockets, &src_port, &info, BPF_ANY);
    
    /* Optionally send to ring buffer for monitoring */
    struct dns_socket_info *event = bpf_ringbuf_reserve(&dns_events, 
                                                         sizeof(*event), 0);
    if (event) {
        __builtin_memcpy(event, &info, sizeof(*event));
        bpf_ringbuf_submit(event, 0);
    }
    
    return 0;
}

/*
 * Cleanup old entries - called periodically from userspace or via timer
 * For now, rely on userspace cleanup
 */
SEC("kprobe/udp_recvmsg")  
int trace_udp_recv(struct pt_regs *ctx) {
    /* Placeholder for potential response tracking */
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
