/* 
 * DNS eBPF Program for Process-Aware DNS Resolution Tracking
 * 
 * This program hooks into UDP send operations to track DNS queries
 * and associate them with the processes that made them.
 * 
 * Strategy: Track UDP sockets sending to port 53 and record the process info.
 * Userspace correlates via source port when it sees DNS packets.
 * 
 * Supports both IPv4 and IPv6.
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
 * 
 * struct sock_common {
 *     union {
 *         struct { __be32 skc_daddr; __be32 skc_rcv_saddr; };  // 0, 4
 *     };
 *     ...
 *     struct { __be16 skc_dport; __u16 skc_num; };             // 12, 14
 *     unsigned short skc_family;                               // 16
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

/* DNS socket info - keyed by source port */
struct dns_socket_info {
    __u32 pid;
    __u32 uid;
    __u64 timestamp;
    __u16 src_port;
    __u16 dst_port;
    __u8 family;
    __u8 padding[3];
    __u32 src_ip[4];    /* Source IP (IPv4 in first element, or full IPv6) */
    __u32 dst_ip[4];    /* Destination IP (DNS server) */
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
 * Works for both IPv4 and IPv6
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
    
    /* Initialize IP addresses to zero */
    info.src_ip[0] = 0;
    info.src_ip[1] = 0;
    info.src_ip[2] = 0;
    info.src_ip[3] = 0;
    info.dst_ip[0] = 0;
    info.dst_ip[1] = 0;
    info.dst_ip[2] = 0;
    info.dst_ip[3] = 0;
    
    /* Read IP addresses based on family */
    if (family == AF_INET) {
        /* IPv4: read 4-byte addresses */
        bpf_probe_read_kernel(&info.src_ip[0], sizeof(__u32), 
                              (void *)sk + SKC_RCV_SADDR_OFFSET);
        bpf_probe_read_kernel(&info.dst_ip[0], sizeof(__u32), 
                              (void *)sk + SKC_DADDR_OFFSET);
    } else {
        /* IPv6: read full 16-byte addresses */
        bpf_probe_read_kernel(info.src_ip, 16, 
                              (void *)sk + SKC_V6_RCV_SADDR_OFFSET);
        bpf_probe_read_kernel(info.dst_ip, 16, 
                              (void *)sk + SKC_V6_DADDR_OFFSET);
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
 * Kprobe handler for udpv6_sendmsg
 * Captures DNS queries over IPv6 UDP
 */
SEC("kprobe/udpv6_sendmsg")
int trace_udpv6_send(struct pt_regs *ctx) {
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
    dst_port = __builtin_bswap16(dst_port);
    
    /* Only track DNS traffic (port 53) */
    if (dst_port != DNS_PORT) {
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
    info.family = AF_INET6;
    bpf_get_current_comm(&info.process_name, sizeof(info.process_name));
    
    /* Read IPv6 addresses */
    bpf_probe_read_kernel(info.src_ip, 16, 
                          (void *)sk + SKC_V6_RCV_SADDR_OFFSET);
    bpf_probe_read_kernel(info.dst_ip, 16, 
                          (void *)sk + SKC_V6_DADDR_OFFSET);
    
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
 * Placeholder for potential response tracking
 */
SEC("kprobe/udp_recvmsg")  
int trace_udp_recv(struct pt_regs *ctx) {
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
