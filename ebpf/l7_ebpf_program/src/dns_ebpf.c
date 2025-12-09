/* 
 * DNS eBPF Program for Process-Aware DNS Resolution Tracking
 * 
 * This program hooks into UDP send operations to track DNS queries
 * and associate them with the processes that made them.
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
 */
#define SKC_DADDR_OFFSET        0
#define SKC_RCV_SADDR_OFFSET    4
#define SKC_DPORT_OFFSET        12
#define SKC_NUM_OFFSET          14
#define SKC_FAMILY_OFFSET       16
#define SKC_V6_DADDR_OFFSET     56
#define SKC_V6_RCV_SADDR_OFFSET 72

/* 
 * Minimal struct sockaddr_in for reading destination
 * We only need the port which is at offset 2 after the family
 */
struct sockaddr_in_min {
    __u16 sin_family;
    __u16 sin_port;
    __u32 sin_addr;
};

struct sockaddr_in6_min {
    __u16 sin6_family;
    __u16 sin6_port;
    __u32 sin6_flowinfo;
    __u32 sin6_addr[4];
};

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
 * Kprobe handler for __udp4_lib_lookup
 * This is called when looking up a UDP socket, but might not have the dest info.
 */

/*
 * Kprobe handler for ip4_datagram_connect
 * Called when connect() is used on a UDP socket (makes it "connected")
 */
SEC("kprobe/ip4_datagram_connect")
int trace_udp4_connect(struct pt_regs *ctx) {
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    void *uaddr = (void *)PT_REGS_PARM2(ctx);
    
    if (!sk || !uaddr) {
        return 0;
    }
    
    /* Read sockaddr_in from userspace */
    struct sockaddr_in_min sin;
    if (bpf_probe_read_user(&sin, sizeof(sin), uaddr) < 0) {
        return 0;
    }
    
    /* Check if it's DNS (port 53) */
    __u16 dst_port = __builtin_bswap16(sin.sin_port);
    if (dst_port != DNS_PORT) {
        return 0;
    }
    
    /* Read source port from socket */
    __u16 src_port = 0;
    if (bpf_probe_read_kernel(&src_port, sizeof(src_port), 
                               (void *)sk + SKC_NUM_OFFSET) < 0) {
        return 0;
    }
    
    /* Build and store DNS socket info */
    struct dns_socket_info info = {};
    
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    info.pid = pid_tgid >> 32;
    info.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    info.timestamp = bpf_ktime_get_ns();
    info.src_port = src_port;
    info.dst_port = dst_port;
    info.family = AF_INET;
    bpf_get_current_comm(&info.process_name, sizeof(info.process_name));
    
    /* Destination IP from sockaddr */
    info.dst_ip[0] = sin.sin_addr;
    
    /* Source IP from socket (might be 0 if not bound) */
    bpf_probe_read_kernel(&info.src_ip[0], sizeof(__u32), 
                          (void *)sk + SKC_RCV_SADDR_OFFSET);
    
    bpf_map_update_elem(&dns_sockets, &src_port, &info, BPF_ANY);
    
    return 0;
}

/*
 * Kprobe handler for ip6_datagram_connect
 * Called when connect() is used on an IPv6 UDP socket
 */
SEC("kprobe/ip6_datagram_connect")
int trace_udp6_connect(struct pt_regs *ctx) {
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    void *uaddr = (void *)PT_REGS_PARM2(ctx);
    
    if (!sk || !uaddr) {
        return 0;
    }
    
    /* Read sockaddr_in6 from userspace */
    struct sockaddr_in6_min sin6;
    if (bpf_probe_read_user(&sin6, sizeof(sin6), uaddr) < 0) {
        return 0;
    }
    
    /* Check if it's DNS (port 53) */
    __u16 dst_port = __builtin_bswap16(sin6.sin6_port);
    if (dst_port != DNS_PORT) {
        return 0;
    }
    
    /* Read source port from socket */
    __u16 src_port = 0;
    if (bpf_probe_read_kernel(&src_port, sizeof(src_port), 
                               (void *)sk + SKC_NUM_OFFSET) < 0) {
        return 0;
    }
    
    /* Build and store DNS socket info */
    struct dns_socket_info info = {};
    
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    info.pid = pid_tgid >> 32;
    info.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    info.timestamp = bpf_ktime_get_ns();
    info.src_port = src_port;
    info.dst_port = dst_port;
    info.family = AF_INET6;
    bpf_get_current_comm(&info.process_name, sizeof(info.process_name));
    
    /* Destination IP from sockaddr */
    __builtin_memcpy(info.dst_ip, sin6.sin6_addr, sizeof(info.dst_ip));
    
    /* Source IP from socket */
    bpf_probe_read_kernel(info.src_ip, 16, 
                          (void *)sk + SKC_V6_RCV_SADDR_OFFSET);
    
    bpf_map_update_elem(&dns_sockets, &src_port, &info, BPF_ANY);
    
    return 0;
}

/*
 * Tracepoint for udp:udp_fail_queue_rcv_skb (not useful for sends)
 */

/*
 * Kprobe for __sys_sendto - this is called for sendto() syscall
 * which is used by unconnected UDP sockets to send DNS queries.
 * 
 * The sockaddr is passed directly to sendto().
 */
SEC("kprobe/__sys_sendto")
int trace_sendto(struct pt_regs *ctx) {
    int fd = (int)PT_REGS_PARM1(ctx);
    void *addr = (void *)PT_REGS_PARM5(ctx);
    int addr_len = (int)PT_REGS_PARM6(ctx);
    
    if (!addr || addr_len < 4) {
        return 0;
    }
    
    /* Read address family first */
    __u16 family = 0;
    if (bpf_probe_read_user(&family, sizeof(family), addr) < 0) {
        return 0;
    }
    
    __u16 dst_port = 0;
    struct dns_socket_info info = {};
    
    if (family == AF_INET && addr_len >= 8) {
        struct sockaddr_in_min sin;
        if (bpf_probe_read_user(&sin, sizeof(sin), addr) < 0) {
            return 0;
        }
        
        dst_port = __builtin_bswap16(sin.sin_port);
        if (dst_port != DNS_PORT) {
            return 0;
        }
        
        info.family = AF_INET;
        info.dst_ip[0] = sin.sin_addr;
        
    } else if (family == AF_INET6 && addr_len >= 28) {
        struct sockaddr_in6_min sin6;
        if (bpf_probe_read_user(&sin6, sizeof(sin6), addr) < 0) {
            return 0;
        }
        
        dst_port = __builtin_bswap16(sin6.sin6_port);
        if (dst_port != DNS_PORT) {
            return 0;
        }
        
        info.family = AF_INET6;
        __builtin_memcpy(info.dst_ip, sin6.sin6_addr, sizeof(info.dst_ip));
        
    } else {
        return 0;
    }
    
    /* Get PID/UID/process name from current task */
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    info.pid = pid_tgid >> 32;
    info.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    info.timestamp = bpf_ktime_get_ns();
    info.dst_port = dst_port;
    bpf_get_current_comm(&info.process_name, sizeof(info.process_name));
    
    /* We need to get the source port from the socket, but we only have fd.
     * We'll use a per-task map to correlate with the actual socket later.
     * For now, use the PID as key temporarily, and update in udp_sendmsg. */
    
    /* Actually, let's use a different approach: 
     * Store by PID, then in the next probe (udp_sendmsg) we can correlate. */
    __u32 pid = info.pid;
    
    /* Store temporarily by PID - we'll update the key in udp_sendmsg */
    bpf_map_update_elem(&dns_sockets, &pid, &info, BPF_ANY);
    
    return 0;
}

/*
 * Kprobe handler for udp_sendmsg
 * Now we can get the source port and update the map entry.
 */
SEC("kprobe/udp_sendmsg")
int trace_udp_send(struct pt_regs *ctx) {
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    
    if (!sk) {
        return 0;
    }
    
    /* Get current PID */
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    
    /* Look up the entry we stored in sendto probe (if any) */
    struct dns_socket_info *stored = bpf_map_lookup_elem(&dns_sockets, &pid);
    if (!stored) {
        /* No entry from sendto - this might be a connected socket.
         * Check if the socket's destination port is DNS. */
        __u16 dst_port_be = 0;
        bpf_probe_read_kernel(&dst_port_be, sizeof(dst_port_be), 
                              (void *)sk + SKC_DPORT_OFFSET);
        __u16 dst_port = __builtin_bswap16(dst_port_be);
        
        if (dst_port != DNS_PORT) {
            return 0;
        }
        
        /* Read source port */
        __u16 src_port = 0;
        if (bpf_probe_read_kernel(&src_port, sizeof(src_port), 
                                   (void *)sk + SKC_NUM_OFFSET) < 0) {
            return 0;
        }
        
        /* Read family */
        __u16 family = 0;
        bpf_probe_read_kernel(&family, sizeof(family), 
                              (void *)sk + SKC_FAMILY_OFFSET);
        
        /* Build info for connected socket */
        struct dns_socket_info info = {};
        info.pid = pid;
        info.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
        info.timestamp = bpf_ktime_get_ns();
        info.src_port = src_port;
        info.dst_port = dst_port;
        info.family = family;
        bpf_get_current_comm(&info.process_name, sizeof(info.process_name));
        
        if (family == AF_INET) {
            bpf_probe_read_kernel(&info.dst_ip[0], sizeof(__u32), 
                                  (void *)sk + SKC_DADDR_OFFSET);
            bpf_probe_read_kernel(&info.src_ip[0], sizeof(__u32), 
                                  (void *)sk + SKC_RCV_SADDR_OFFSET);
        } else if (family == AF_INET6) {
            bpf_probe_read_kernel(info.dst_ip, 16, 
                                  (void *)sk + SKC_V6_DADDR_OFFSET);
            bpf_probe_read_kernel(info.src_ip, 16, 
                                  (void *)sk + SKC_V6_RCV_SADDR_OFFSET);
        }
        
        bpf_map_update_elem(&dns_sockets, &src_port, &info, BPF_ANY);
        
        return 0;
    }
    
    /* We have an entry from sendto - update with source port and move to correct key */
    __u16 src_port = 0;
    if (bpf_probe_read_kernel(&src_port, sizeof(src_port), 
                               (void *)sk + SKC_NUM_OFFSET) < 0) {
        /* Clean up the PID-keyed entry */
        bpf_map_delete_elem(&dns_sockets, &pid);
        return 0;
    }
    
    /* Update the entry with source port */
    stored->src_port = src_port;
    
    /* Read source IP from socket */
    __u16 family = 0;
    bpf_probe_read_kernel(&family, sizeof(family), 
                          (void *)sk + SKC_FAMILY_OFFSET);
    
    if (family == AF_INET) {
        bpf_probe_read_kernel(&stored->src_ip[0], sizeof(__u32), 
                              (void *)sk + SKC_RCV_SADDR_OFFSET);
    } else if (family == AF_INET6) {
        bpf_probe_read_kernel(stored->src_ip, 16, 
                              (void *)sk + SKC_V6_RCV_SADDR_OFFSET);
    }
    
    /* Copy the entry to the source port key */
    struct dns_socket_info info;
    __builtin_memcpy(&info, stored, sizeof(info));
    
    /* Delete the PID-keyed entry */
    bpf_map_delete_elem(&dns_sockets, &pid);
    
    /* Store with source port as key */
    bpf_map_update_elem(&dns_sockets, &src_port, &info, BPF_ANY);
    
    return 0;
}

/*
 * Kprobe handler for udpv6_sendmsg (similar to udp_sendmsg but for IPv6)
 */
SEC("kprobe/udpv6_sendmsg")
int trace_udpv6_send(struct pt_regs *ctx) {
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    
    if (!sk) {
        return 0;
    }
    
    /* Get current PID */
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    
    /* Look up the entry we stored in sendto probe (if any) */
    struct dns_socket_info *stored = bpf_map_lookup_elem(&dns_sockets, &pid);
    if (!stored) {
        /* Check connected socket */
        __u16 dst_port_be = 0;
        bpf_probe_read_kernel(&dst_port_be, sizeof(dst_port_be), 
                              (void *)sk + SKC_DPORT_OFFSET);
        __u16 dst_port = __builtin_bswap16(dst_port_be);
        
        if (dst_port != DNS_PORT) {
            return 0;
        }
        
        __u16 src_port = 0;
        if (bpf_probe_read_kernel(&src_port, sizeof(src_port), 
                                   (void *)sk + SKC_NUM_OFFSET) < 0) {
            return 0;
        }
        
        struct dns_socket_info info = {};
        info.pid = pid;
        info.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
        info.timestamp = bpf_ktime_get_ns();
        info.src_port = src_port;
        info.dst_port = dst_port;
        info.family = AF_INET6;
        bpf_get_current_comm(&info.process_name, sizeof(info.process_name));
        
        bpf_probe_read_kernel(info.dst_ip, 16, 
                              (void *)sk + SKC_V6_DADDR_OFFSET);
        bpf_probe_read_kernel(info.src_ip, 16, 
                              (void *)sk + SKC_V6_RCV_SADDR_OFFSET);
        
        bpf_map_update_elem(&dns_sockets, &src_port, &info, BPF_ANY);
        
        return 0;
    }
    
    /* Update entry from sendto with source port */
    __u16 src_port = 0;
    if (bpf_probe_read_kernel(&src_port, sizeof(src_port), 
                               (void *)sk + SKC_NUM_OFFSET) < 0) {
        bpf_map_delete_elem(&dns_sockets, &pid);
        return 0;
    }
    
    stored->src_port = src_port;
    bpf_probe_read_kernel(stored->src_ip, 16, 
                          (void *)sk + SKC_V6_RCV_SADDR_OFFSET);
    
    struct dns_socket_info info;
    __builtin_memcpy(&info, stored, sizeof(info));
    
    bpf_map_delete_elem(&dns_sockets, &pid);
    bpf_map_update_elem(&dns_sockets, &src_port, &info, BPF_ANY);
    
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
