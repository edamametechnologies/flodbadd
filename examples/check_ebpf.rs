fn main() {
    println!("eBPF support: {}", flodbadd::l7_ebpf::ebpf_support());
    println!("eBPF available: {}", flodbadd::l7_ebpf::is_available());
}
