# eBPF Layer 7 Process Resolution

## Overview

Flodbadd includes an optional eBPF (extended Berkeley Packet Filter) subsystem that provides high-performance, kernel-level process attribution for network sessions on Linux. This enables accurate mapping of network connections to the processes that initiated them, enhancing security visibility and threat detection capabilities.

## What is eBPF?

eBPF is a technology that allows programs to run in the Linux kernel without modifying kernel source code or loading kernel modules. For network monitoring, eBPF provides:

- **Near-zero overhead** - Runs directly in kernel space
- **Real-time visibility** - Captures events as they happen
- **Process attribution** - Maps network connections to PIDs, process names, and paths
- **CO-RE (Compile Once, Run Everywhere)** - Works across different kernel versions

## How It Works

### Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        User Space                                │
│  ┌─────────────────┐    ┌─────────────────────────────────────┐ │
│  │   flodbadd      │───>│  l7_ebpf.rs (Aya loader)            │ │
│  │   capture.rs    │    │  - Loads eBPF program               │ │
│  │                 │<───│  - Reads BPF maps                   │ │
│  └─────────────────┘    └─────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
                                    │
                                    │ perf_event_open / BPF syscalls
                                    ▼
┌─────────────────────────────────────────────────────────────────┐
│                       Kernel Space                               │
│  ┌─────────────────────────────────────────────────────────────┐│
│  │                    l7_ebpf.o (eBPF program)                 ││
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐  ││
│  │  │ tcp_v4_     │  │ tcp_set_    │  │ __sk_free           │  ││
│  │  │ connect     │  │ state       │  │ (socket cleanup)    │  ││
│  │  │ (kprobe)    │  │ (kprobe)    │  │ (kprobe)            │  ││
│  │  └─────────────┘  └─────────────┘  └─────────────────────┘  ││
│  │         │                │                    │              ││
│  │         └────────────────┼────────────────────┘              ││
│  │                          ▼                                   ││
│  │  ┌─────────────────────────────────────────────────────────┐││
│  │  │                    BPF Maps                              │││
│  │  │  socket_to_process: HashMap<sock_ptr, process_info>     │││
│  │  │  l7_connections:    HashMap<session_key, process_info>  │││
│  │  └─────────────────────────────────────────────────────────┘││
│  └─────────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────────┘
```

### Kprobe Hooks

The eBPF program attaches to three kernel functions:

| Kprobe | Function | Purpose |
|--------|----------|---------|
| `tcp_v4_connect` | `track_connect` | Captures process info when connection is initiated |
| `tcp_set_state` | `minimal_probe` | Records established connections with session details |
| `__sk_free` | `cleanup_socket` | Cleans up map entries when sockets are closed |

### Data Flow

1. **Connection Initiation**: When a process calls `connect()`, `tcp_v4_connect` fires and captures the PID, process name, and socket pointer
2. **Connection Established**: When the TCP state transitions to ESTABLISHED, `tcp_set_state` captures the full 4-tuple and associates it with the process info
3. **Userspace Query**: The Rust code queries the `l7_connections` map to look up process info for any captured session
4. **Cleanup**: When sockets are freed, `__sk_free` removes stale entries from the maps

## Enabling eBPF

### Cargo Feature

Enable the `ebpf` feature in your `Cargo.toml`:

```toml
[dependencies]
flodbadd = { version = "*", features = ["packetcapture", "ebpf"] }
```

### Build Requirements

The eBPF program is compiled during the Rust build process. Required tools:

```bash
# Ubuntu/Debian
sudo apt install clang llvm libbpf-dev linux-headers-$(uname -r)

# Alpine Linux
sudo apk add clang llvm libbpf-dev linux-headers

# Fedora/RHEL
sudo dnf install clang llvm libbpf-devel kernel-devel
```

### Runtime Requirements

| Requirement | Details |
|-------------|---------|
| **Kernel version** | 4.18+ recommended, 5.x+ for best compatibility |
| **BTF support** | Required for CO-RE; most modern distros include this |
| **Privileges** | `CAP_SYS_ADMIN` + `CAP_BPF` or root |
| **Kernel config** | `CONFIG_BPF=y`, `CONFIG_BPF_SYSCALL=y` |

### Checking eBPF Availability

```bash
# Check kernel version
uname -r

# Check BPF support
cat /proc/sys/kernel/unprivileged_bpf_disabled
# 0 = unprivileged BPF allowed
# 1 = unprivileged BPF disabled (need root)
# 2 = BPF disabled entirely

# Check BTF availability
ls -la /sys/kernel/btf/vmlinux
```

## Platform Support

| Platform | eBPF Support | Notes |
|----------|--------------|-------|
| **Linux (Native)** | ✅ Full | Best performance, all features |
| **Linux (VM)** | ✅ Full | Works in VMs with nested virtualization |
| **Linux (Container)** | ⚠️ Limited | Requires privileged mode or specific capabilities |
| **Docker Desktop** | ❌ No | LinuxKit kernel lacks kprobe support |
| **macOS** | ❌ No | Not available (falls back to netstat) |
| **Windows** | ❌ No | Not available (falls back to netstat) |

### Container Considerations

eBPF kprobes require kernel-level access. For containers:

```yaml
# Docker Compose
services:
  app:
    cap_add:
      - SYS_ADMIN
      - SYS_PTRACE
      - BPF
      - NET_ADMIN
    security_opt:
      - seccomp:unconfined
```

```bash
# Docker run
docker run --privileged ...
# Or with specific capabilities:
docker run --cap-add=SYS_ADMIN --cap-add=BPF --cap-add=NET_ADMIN ...
```

## Graceful Fallback

When eBPF is unavailable, flodbadd automatically falls back to traditional methods:

```rust
// Pseudo-code of fallback logic
fn get_l7_for_session(session: &Session) -> Option<SessionL7> {
    // Try eBPF first (Linux only, when feature enabled)
    #[cfg(all(target_os = "linux", feature = "ebpf"))]
    if let Some(l7) = l7_ebpf::get_l7_for_session(session) {
        return Some(l7);
    }
    
    // Fallback to netstat-based resolution
    l7_fallback::get_l7_for_session(session)
}
```

**Fallback methods:**
- `netstat2` crate for socket-to-process mapping
- `/proc/net/tcp` parsing on Linux
- Platform-specific APIs on macOS/Windows

## Performance Comparison

| Method | Latency | Accuracy | CPU Overhead |
|--------|---------|----------|--------------|
| **eBPF** | < 1ms | Very High | Minimal (kernel-level) |
| **netstat** | 10-50ms | High | Moderate (userspace polling) |
| **/proc parsing** | 5-20ms | High | Low-Moderate |

eBPF provides the best performance because:
- Events are captured at connection time (not polled)
- No userspace context switching for data collection
- BPF maps provide O(1) lookups

## Troubleshooting

### eBPF Not Loading

```
[l7_ebpf] Failed to load eBPF object: no BTF parsed for object
```

**Solution**: Ensure BTF is preserved in the eBPF object. Check that `llvm-strip -g` is not being applied to the `.o` file.

### Kprobe Attachment Failed

```
[l7_ebpf] Failed to attach kprobe: perf_event_open failed
```

**Causes:**
- Running in a container without privileges
- Kernel doesn't support the target function
- SELinux/AppArmor blocking BPF

**Solutions:**
1. Run with `sudo` or as root
2. Add `--privileged` for containers
3. Check SELinux: `ausearch -m avc -ts recent`

### Process Info Shows "swapper/0"

The `swapper/0` process indicates the connection was captured in kernel context (interrupt handler or kernel thread) rather than userspace. This can happen with:
- Server-side connections (accept path)
- Connections established during system initialization

The `tcp_v4_connect` kprobe mitigates this for client connections by capturing process info early.

### Map Lookups Return None

If eBPF is working but not returning L7 data for sessions:

1. **Timing issue**: eBPF captures at connection time; if the connection is very short-lived, it may complete before the map is queried
2. **IP byte order mismatch**: Ensure session IPs are in the correct byte order for map lookups
3. **Protocol mismatch**: eBPF currently captures TCP connections; UDP support may vary

## Testing eBPF

### Integration Tests

```bash
# Run eBPF-specific tests on Linux
cargo test --features packetcapture,ebpf ebpf_integration_tests -- --nocapture
```

### Manual Testing

```bash
# Start capture with eBPF
sudo cargo run --example capture_sessions --features packetcapture,ebpf

# In another terminal, generate traffic
curl https://example.com

# Check if L7 info is populated in session output
```

### Lima VM Testing (macOS)

Since eBPF requires a Linux kernel, use Lima for testing on macOS:

```bash
# Create and start Lima VM
make lima_create
make lima_start

# Run tests inside VM
make lima_test_ebpf
```

See the `Lima.*.yml` configuration files for VM setup.

## Code Structure

```
flodbadd/
├── ebpf/
│   └── l7_ebpf_program/
│       ├── src/
│       │   ├── l7_ebpf.c      # eBPF C program
│       │   ├── vmlinux.h      # Minimal kernel headers
│       │   └── lib.rs         # Build script interface
│       ├── Cargo.toml
│       └── Makefile
├── src/
│   ├── l7.rs                  # L7 resolution interface
│   ├── l7_ebpf.rs             # Aya-based eBPF loader (Linux only)
│   └── capture.rs             # Integrates L7 with packet capture
└── build.rs                   # Triggers eBPF compilation
```

## Security Considerations

### Privilege Requirements

eBPF programs run in kernel space and require elevated privileges:

- **Root or CAP_SYS_ADMIN**: Required to load eBPF programs
- **CAP_BPF**: Specific capability for BPF operations (kernel 5.8+)
- **CAP_PERFMON**: May be required for perf_event-based kprobes

### Kernel Lockdown

On systems with Kernel Lockdown enabled (Secure Boot), eBPF may be restricted:

```bash
# Check lockdown status
cat /sys/kernel/security/lockdown
# none / integrity / confidentiality
```

### Auditing

eBPF program loads are logged in the kernel audit system:

```bash
# View eBPF-related audit logs
ausearch -m BPF
```

## Related Documentation

- [Linux eBPF documentation](https://ebpf.io/what-is-ebpf/)
- [Aya - Rust eBPF library](https://aya-rs.dev/)
- [BPF CO-RE reference](https://nakryiko.com/posts/bpf-core-reference-guide/)



