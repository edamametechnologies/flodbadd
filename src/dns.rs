use crate::dns_ebpf;
use crate::task::TaskHandle;
use dns_parser::Packet as DnsPacket;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::time::interval;
use tracing::{debug, info, trace, warn};
use undeadlock::*;

/// DNS query with optional process attribution
struct PendingQuery {
    domain_name: String,
    timestamp: Instant,
    /// Process ID that made this query (from eBPF, if available)
    pid: Option<u32>,
    /// Process name that made this query (from eBPF, if available)
    process_name: Option<String>,
}

/// DNS resolution with optional process attribution
#[derive(Debug, Clone)]
pub struct DnsResolution {
    pub domain: String,
    /// Process ID that resolved this domain (if known via eBPF)
    pub pid: Option<u32>,
    /// Process name that resolved this domain (if known via eBPF)
    pub process_name: Option<String>,
}

pub struct DnsPacketProcessor {
    pending_dns_queries: Arc<CustomDashMap<u16, PendingQuery>>,
    dns_resolutions: Arc<CustomDashMap<IpAddr, String>>,
    /// Enhanced resolutions with process attribution (from eBPF)
    dns_resolutions_with_process: Arc<CustomDashMap<IpAddr, DnsResolution>>,
    dns_query_cleanup_handle: Option<TaskHandle>,
    /// Whether eBPF DNS tracking is available
    ebpf_available: bool,
}

impl DnsPacketProcessor {
    pub fn new() -> Self {
        let ebpf_available = dns_ebpf::is_available();
        if ebpf_available {
            info!("DNS eBPF tracking enabled - process attribution available");
        } else {
            debug!("DNS eBPF tracking not available - process attribution disabled");
        }

        Self {
            pending_dns_queries: Arc::new(CustomDashMap::new("pending_dns_queries")),
            dns_resolutions: Arc::new(CustomDashMap::new("dns_resolutions")),
            dns_resolutions_with_process: Arc::new(CustomDashMap::new(
                "dns_resolutions_with_process",
            )),
            dns_query_cleanup_handle: None,
            ebpf_available,
        }
    }

    pub fn get_dns_resolutions(&self) -> Arc<CustomDashMap<IpAddr, String>> {
        self.dns_resolutions.clone()
    }

    /// Get DNS resolutions with process attribution (from eBPF if available)
    pub fn get_dns_resolutions_with_process(&self) -> Arc<CustomDashMap<IpAddr, DnsResolution>> {
        self.dns_resolutions_with_process.clone()
    }

    /// Check if eBPF DNS tracking is enabled
    pub fn is_ebpf_enabled(&self) -> bool {
        self.ebpf_available
    }

    /// Process a DNS packet with optional source port for eBPF lookup
    ///
    /// If src_port is provided and eBPF is available, we can look up which
    /// process made the DNS query.
    pub async fn process_dns_packet_with_port(&self, dns_payload: Vec<u8>, src_port: Option<u16>) {
        match DnsPacket::parse(&dns_payload) {
            Ok(dns_packet) => {
                trace!("DNS Packet: {:?}", dns_packet);

                let tx_id = dns_packet.header.id;
                if dns_packet.header.query {
                    // DNS Query
                    if let Some(question) = dns_packet.questions.get(0) {
                        let domain_name = question.qname.to_string();
                        // Exclude reverse lookups
                        if domain_name.ends_with(".in-addr.arpa")
                            || domain_name.ends_with(".ip6.arpa")
                        {
                            return;
                        }

                        // Try to get process info from eBPF using source port
                        let (pid, process_name) = if self.ebpf_available {
                            if let Some(port) = src_port {
                                match dns_ebpf::get_process_by_src_port(port) {
                                    Some(info) => {
                                        debug!(
                                            "DNS Query to {} ({}) from PID {} ({}) [port {}]",
                                            domain_name, tx_id, info.pid, info.process_name, port
                                        );
                                        (Some(info.pid), Some(info.process_name))
                                    }
                                    None => {
                                        debug!(
                                            "DNS Query to {} ({}) - no eBPF info for port {}",
                                            domain_name, tx_id, port
                                        );
                                        (None, None)
                                    }
                                }
                            } else {
                                debug!(
                                    "DNS Query to {} ({}) - no source port provided",
                                    domain_name, tx_id
                                );
                                (None, None)
                            }
                        } else {
                            debug!("DNS Query to {} ({})", domain_name, tx_id);
                            (None, None)
                        };

                        // Store the transaction ID and domain name with process info
                        self.pending_dns_queries.insert(
                            tx_id,
                            PendingQuery {
                                domain_name,
                                timestamp: Instant::now(),
                                pid,
                                process_name,
                            },
                        );
                    }
                } else {
                    // DNS Response
                    // Retrieve the domain name using the transaction ID
                    let pending_query = { self.pending_dns_queries.remove(&tx_id) };
                    if let Some((_, pending_query)) = pending_query {
                        let domain_name = pending_query.domain_name.clone();
                        let pid = pending_query.pid;
                        let process_name = pending_query.process_name.clone();

                        if let Some(ref pname) = process_name {
                            debug!(
                                "DNS Response for {} ({}) from PID {} ({})",
                                domain_name,
                                tx_id,
                                pid.unwrap_or(0),
                                pname
                            );
                        } else {
                            debug!("DNS Response for {} ({})", domain_name, tx_id);
                        }

                        // Collect IP addresses from the answer section
                        for answer in dns_packet.answers {
                            match answer.data {
                                dns_parser::rdata::RData::A(ipv4_addr) => {
                                    let ip_addr = IpAddr::V4(ipv4_addr.0);
                                    self.dns_resolutions.insert(ip_addr, domain_name.clone());

                                    // Store enhanced resolution with process info
                                    self.dns_resolutions_with_process.insert(
                                        ip_addr,
                                        DnsResolution {
                                            domain: domain_name.clone(),
                                            pid,
                                            process_name: process_name.clone(),
                                        },
                                    );
                                }
                                dns_parser::rdata::RData::AAAA(ipv6_addr) => {
                                    let ip_addr = IpAddr::V6(ipv6_addr.0);
                                    self.dns_resolutions.insert(ip_addr, domain_name.clone());

                                    // Store enhanced resolution with process info
                                    self.dns_resolutions_with_process.insert(
                                        ip_addr,
                                        DnsResolution {
                                            domain: domain_name.clone(),
                                            pid,
                                            process_name: process_name.clone(),
                                        },
                                    );
                                }
                                _ => {
                                    // Handle other record types if necessary
                                }
                            }
                        }
                    }
                }
            }
            Err(e) => {
                warn!("Failed to parse DNS packet: {}", e);
            }
        }
    }

    /// Process a DNS packet (backward compatible - no source port)
    pub async fn process_dns_packet(&self, dns_payload: Vec<u8>) {
        self.process_dns_packet_with_port(dns_payload, None).await
    }

    pub async fn start(&mut self) {
        let pending_dns_queries = self.pending_dns_queries.clone();
        let stop_flag = Arc::new(AtomicBool::new(false));
        let stop_flag_clone = stop_flag.clone();

        let handle = tokio::spawn(async move {
            let mut cleanup_interval = interval(Duration::from_secs(10));
            loop {
                cleanup_interval.tick().await;
                if stop_flag_clone.load(Ordering::Relaxed) {
                    break;
                }
                let now = Instant::now();
                // Clean up expired DNS queries
                pending_dns_queries.retain(|_, pending_query| {
                    now.duration_since(pending_query.timestamp) < Duration::from_secs(30)
                });
            }
            info!("DNS query cleanup task terminated");
        });

        self.dns_query_cleanup_handle = Some(TaskHandle { handle, stop_flag });
    }

    pub async fn stop_dns_query_cleanup_task(&mut self) {
        if let Some(task_handle) = self.dns_query_cleanup_handle.take() {
            task_handle.stop_flag.store(true, Ordering::Relaxed);
            let _ = task_handle.handle.await;
        } else {
            warn!("DNS query cleanup task not running");
        }
    }
}
