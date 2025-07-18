# eBPF L7 Network Session Resolution

This directory contains the eBPF program for Layer 7 network session resolution, which tracks network connections and associates them with the local processes that created them.

## Overview

The eBPF program hooks into kernel network events to capture:
- Network session 4-tuples (src/dst IP:port, protocol)
- Process information (PID, name, path, username)
- Connection state and timing information

## Files

- `src/l7_ebpf.c` - Main eBPF program in C
- `src/lib.rs` - Rust library stub (build-time only)
- `build.rs` - Build script to compile the eBPF program
- `Cargo.toml` - Rust build configuration
- `Makefile` - Alternative build system

## Building

### Prerequisites

On Ubuntu/Debian:
```bash
sudo apt-get update
sudo apt-get install -y clang llvm libbpf-dev linux-headers-$(uname -r)
```

### Via Cargo (Recommended)

The eBPF program is automatically built when you build the main flodbadd crate with the `ebpf` feature:

```bash
cd flodbadd
cargo build --features ebpf
```

### Via Makefile

Alternatively, you can build the eBPF program directly:

```bash
cd flodbadd/ebpf/l7_ebpf_program
make
```

## Usage

The eBPF program is automatically loaded and used by the main flodbadd L7 resolver when:

1. Running on Linux
2. The `ebpf` feature is enabled
3. The program has sufficient privileges (root or CAP_BPF)
4. The kernel supports the required eBPF features

## System Requirements

### Kernel Version
- Linux 5.3+ (for tracepoint support with BTF)
- Newer kernels (5.8+) recommended for better stability

### Privileges
- Root access OR
- CAP_BPF + CAP_PERFMON capabilities

### System Configuration

1. **Disable unprivileged eBPF restriction** (if running as root):
   ```bash
   echo 0 | sudo tee /proc/sys/kernel/unprivileged_bpf_disabled
   ```

2. **Set perf_event_paranoid** (for kprobe attachment):
   ```bash
   echo -1 | sudo tee /proc/sys/kernel/perf_event_paranoid
   ```

3. **Mount debugfs** (for kprobe support):
   ```bash
   sudo mount -t debugfs none /sys/kernel/debug
   ```

## Docker Support

When running in Docker, use these additional flags:

```bash
docker run --privileged \
  -v /sys/kernel/debug:/sys/kernel/debug \
  -v /sys/fs/bpf:/sys/fs/bpf \
  your-image
```

**Note**: Docker Desktop on macOS has limited eBPF support. For full functionality, use a native Linux environment.

## How It Works

1. **Hook Points**: The program attaches to kernel functions:
   - `inet_sock_set_state` - Tracks TCP connection state changes
   - `__sk_free` - Cleans up when sockets are freed
   - `do_exit` - Handles process termination

2. **Data Collection**: For each network event, it captures:
   - Session key (IP addresses, ports, protocol)
   - Process information (PID, name, path, username)
   - Timing information (start time, UID)

3. **Storage**: Data is stored in eBPF hash maps:
   - `l7_connections` - Main session→process mapping
   - `socket_to_process` - Helper map for cleanup

4. **Userspace Access**: The Rust code accesses the maps to retrieve process information for network sessions.

## Debugging

### Check if eBPF is loaded:
```bash
sudo bpftool prog list
sudo bpftool map list
```

### View program logs:
```bash
sudo dmesg | grep -i bpf
```

### Check system compatibility:
```bash
# Check kernel version
uname -r

# Check eBPF support
ls /sys/kernel/debug/tracing/events/syscalls/

# Check loaded programs
sudo bpftool prog show
```

## Troubleshooting

### Permission Denied
- Run with root privileges
- Check `unprivileged_bpf_disabled` setting
- Ensure proper capabilities are set

### Program Load Failed
- Check kernel version (need 5.3+)
- Ensure kernel headers are installed
- Check for conflicting security policies

### Map Access Errors
- Verify debugfs is mounted
- Check `perf_event_paranoid` setting
- Ensure sufficient system resources

## Performance

The eBPF program is designed to be lightweight:
- Only tracks relevant connections (TCP + important UDP)
- Uses efficient hash maps for storage
- Minimal per-packet overhead
- Automatic cleanup of stale entries

## Limitations

- Process path extraction is simplified in eBPF context
- Username lookup uses UID formatting (not full /etc/passwd lookup)
- IPv6 support is implemented but may need kernel-specific adjustments
- Some complex network configurations may not be fully supported

## Development

To modify the eBPF program:

1. Edit `src/l7_ebpf.c`
2. Test compilation: `make clean && make`
3. Test loading: Build and run with `--features ebpf`
4. Check logs for any issues

The program uses CO-RE (Compile Once, Run Everywhere) for portability across different kernel versions. 