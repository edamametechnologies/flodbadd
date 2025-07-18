#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <linux/socket.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/net.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define MAX_ENTRIES 65536

// Network protocol constants
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17

// Socket states
#define TCP_ESTABLISHED 1
#define TCP_SYN_SENT 2
#define TCP_SYN_RECV 3
#define TCP_CLOSE 7

// Data structures matching the Rust side
struct session_key {
    __u32 src_ip[4];    // IPv4/IPv6 address (IPv4 uses first element)
    __u32 dst_ip[4];    // IPv4/IPv6 address (IPv4 uses first element)
    __u16 src_port;
    __u16 dst_port;
    __u8 protocol;      // TCP=6, UDP=17
    __u8 family;        // AF_INET=2, AF_INET6=10
    __u16 padding;      // Ensure alignment
};

struct process_info {
    __u32 pid;
    __u32 uid;
    __u64 start_time;
    char process_name[16];
    char process_path[256];
    char username[32];
};

// eBPF maps
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, struct session_key);
    __type(value, struct process_info);
} l7_connections SEC(".maps");

// Helper map to track socket to process mappings
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, __u64);  // socket pointer
    __type(value, struct process_info);
} socket_to_process SEC(".maps");

// Helper to extract IPv4 address
static __always_inline __u32 extract_ipv4_addr(struct sock *sk, int is_src) {
    struct inet_sock *inet = (struct inet_sock *)sk;
    if (is_src) {
        return BPF_CORE_READ(inet, inet_saddr);
    } else {
        return BPF_CORE_READ(inet, inet_daddr);
    }
}

// Helper to extract IPv6 address
static __always_inline void extract_ipv6_addr(struct sock *sk, int is_src, __u32 *addr) {
    struct ipv6_pinfo *np;
    struct in6_addr *in6_addr;
    
    np = (struct ipv6_pinfo *)BPF_CORE_READ(sk, sk_prot, useroffset);
    if (!np) return;
    
    if (is_src) {
        in6_addr = &BPF_CORE_READ(np, saddr);
    } else {
        in6_addr = &BPF_CORE_READ(np, daddr);
    }
    
    // Copy IPv6 address (16 bytes = 4 x 32-bit words)
    BPF_CORE_READ_INTO(addr, in6_addr, sizeof(struct in6_addr));
}

// Helper to extract port numbers
static __always_inline __u16 extract_port(struct sock *sk, int is_src) {
    struct inet_sock *inet = (struct inet_sock *)sk;
    if (is_src) {
        return bpf_ntohs(BPF_CORE_READ(inet, inet_sport));
    } else {
        return bpf_ntohs(BPF_CORE_READ(inet, inet_dport));
    }
}

// Helper to get process executable path
static __always_inline void get_process_path(struct task_struct *task, char *path, int path_size) {
    struct mm_struct *mm;
    struct file *exe_file;
    struct path *file_path;
    struct dentry *dentry;
    struct qstr dname;
    
    mm = BPF_CORE_READ(task, mm);
    if (!mm) {
        bpf_probe_read_str(path, path_size, "unknown");
        return;
    }
    
    exe_file = BPF_CORE_READ(mm, exe_file);
    if (!exe_file) {
        bpf_probe_read_str(path, path_size, "unknown");
        return;
    }
    
    file_path = &exe_file->f_path;
    dentry = BPF_CORE_READ(file_path, dentry);
    if (!dentry) {
        bpf_probe_read_str(path, path_size, "unknown");
        return;
    }
    
    dname = BPF_CORE_READ(dentry, d_name);
    if (dname.name) {
        bpf_probe_read_str(path, path_size, dname.name);
    } else {
        bpf_probe_read_str(path, path_size, "unknown");
    }
}

// Helper to get username from UID
static __always_inline void get_username_from_uid(__u32 uid, char *username, int username_size) {
    // This is a simplified version - a full implementation would need to
    // look up the username in /etc/passwd or use the user namespace
    // For now, we'll format it as "uid-{number}"
    
    char uid_str[16];
    int i = 0;
    __u32 temp_uid = uid;
    
    // Convert UID to string (simple implementation)
    if (temp_uid == 0) {
        bpf_probe_read_str(username, username_size, "root");
        return;
    }
    
    // Format as "uid-{number}"
    char prefix[] = "uid-";
    int prefix_len = sizeof(prefix) - 1;
    
    // Copy prefix
    for (i = 0; i < prefix_len && i < username_size - 1; i++) {
        username[i] = prefix[i];
    }
    
    // Convert number to string (simplified)
    char digits[16];
    int digit_count = 0;
    
    if (temp_uid == 0) {
        digits[digit_count++] = '0';
    } else {
        while (temp_uid > 0 && digit_count < 15) {
            digits[digit_count++] = '0' + (temp_uid % 10);
            temp_uid /= 10;
        }
    }
    
    // Reverse and append digits
    for (int j = digit_count - 1; j >= 0 && i < username_size - 1; j--, i++) {
        username[i] = digits[j];
    }
    
    username[i] = '\0';
}

// Helper to validate IP addresses
static __always_inline int is_valid_ip(struct session_key *key) {
    // Check if we have at least one non-zero IP address
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

// Helper to check if port is in ephemeral range
static __always_inline int is_ephemeral_port(__u16 port) {
    return port >= 32768;  // Common ephemeral port range start
}

// Helper to check if we should track this connection
static __always_inline int should_track_connection(struct session_key *key) {
    // Don't track if no valid IPs
    if (!is_valid_ip(key)) {
        return 0;
    }
    
    // Don't track if both ports are zero
    if (key->src_port == 0 && key->dst_port == 0) {
        return 0;
    }
    
    // Track all TCP connections and UDP connections with interesting ports
    if (key->protocol == IPPROTO_TCP) {
        return 1;  // Track all TCP
    } else if (key->protocol == IPPROTO_UDP) {
        // For UDP, track DNS (53) and other well-known services
        return key->src_port == 53 || key->dst_port == 53 ||
               key->src_port < 1024 || key->dst_port < 1024;
    }
    
    return 0;
}

// Enhanced process info extraction
static __always_inline void get_enhanced_process_info(struct process_info *info) {
    struct task_struct *task;
    struct cred *cred;
    
    // Get basic info
    info->pid = bpf_get_current_pid_tgid() >> 32;
    info->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    
    task = (struct task_struct *)bpf_get_current_task();
    if (!task) {
        return;
    }
    
    // Get process name
    BPF_CORE_READ_STR_INTO(info->process_name, task, comm);
    
    // Get start time
    info->start_time = BPF_CORE_READ(task, start_time);
    
    // Get process path (enhanced)
    get_process_path(task, info->process_path, sizeof(info->process_path));
    
    // Get username (enhanced)
    get_username_from_uid(info->uid, info->username, sizeof(info->username));
}

// Hook into socket state changes
SEC("kprobe/inet_sock_set_state")
int minimal_probe(struct pt_regs *ctx) {
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    int state = (int)PT_REGS_PARM2(ctx);
    
    if (!sk) return 0;
    
    // Only track established connections and UDP sockets
    __u8 protocol = BPF_CORE_READ(sk, sk_protocol);
    if (protocol != IPPROTO_TCP && protocol != IPPROTO_UDP) {
        return 0;
    }
    
    // For TCP, only track established connections
    if (protocol == IPPROTO_TCP && state != TCP_ESTABLISHED) {
        return 0;
    }
    
    // Extract socket information
    struct session_key key = {0};
    struct process_info info = {0};
    
    __u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
    key.family = family;
    key.protocol = protocol;
    
    if (family == AF_INET) {
        // IPv4
        key.src_ip[0] = extract_ipv4_addr(sk, 1);
        key.dst_ip[0] = extract_ipv4_addr(sk, 0);
        key.src_port = extract_port(sk, 1);
        key.dst_port = extract_port(sk, 0);
    } else if (family == AF_INET6) {
        // IPv6
        extract_ipv6_addr(sk, 1, key.src_ip);
        extract_ipv6_addr(sk, 0, key.dst_ip);
        key.src_port = extract_port(sk, 1);
        key.dst_port = extract_port(sk, 0);
    } else {
        return 0;  // Unsupported family
    }
    
    // Check if we should track this connection
    if (!should_track_connection(&key)) {
        return 0;
    }
    
    // Get process information (enhanced)
    get_enhanced_process_info(&info);
    
    // Store in map
    bpf_map_update_elem(&l7_connections, &key, &info, BPF_ANY);
    
    // Also store socket->process mapping for cleanup
    __u64 sock_ptr = (__u64)sk;
    bpf_map_update_elem(&socket_to_process, &sock_ptr, &info, BPF_ANY);
    
    return 0;
}

// Hook into socket close for cleanup
SEC("kprobe/__sk_free")
int socket_cleanup(struct pt_regs *ctx) {
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    
    if (!sk) return 0;
    
    __u64 sock_ptr = (__u64)sk;
    
    // Remove from socket tracking map
    bpf_map_delete_elem(&socket_to_process, &sock_ptr);
    
    // Note: We intentionally don't remove from l7_connections here
    // because we want to keep the session info for a while even after
    // the socket is closed (for analysis purposes)
    
    return 0;
}

// Hook into process exit for cleanup
SEC("kprobe/do_exit")
int process_cleanup(struct pt_regs *ctx) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    
    // Clean up entries for this PID
    // Note: This is complex in eBPF due to map iteration limitations
    // In practice, we rely on TTL cleanup from userspace
    
    return 0;
}

char LICENSE[] SEC("license") = "GPL"; 