use crate::device_info::{IpAddressEntry, MacAddressEntry, MdnsServiceEntry};
use chrono::{DateTime, Utc};
use lazy_static::lazy_static;
use macaddr::MacAddr6;
use regex::Regex;
use sorted_vec::SortedVec;
use std::collections::{HashMap, HashSet};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::{net::IpAddr, sync::Arc};
use tokio::task;
use tokio::time::Duration;
use tracing::{debug, info, trace, warn};
use undeadlock::CustomMutex;
use wez_mdns::{Host, QueryParameters};

lazy_static! {
    static ref MDNS_STOP: Arc<AtomicBool> = Arc::new(AtomicBool::new(false));
    static ref MDNS_HANDLE: Arc<CustomMutex<Option<task::JoinHandle<()>>>> =
        Arc::new(CustomMutex::new(None));
    static ref DEVICES: Arc<CustomMutex<HashMap<String, mDNSInfo>>> =
        Arc::new(CustomMutex::new(HashMap::new()));
}

#[derive(Debug, Clone)]
#[allow(non_camel_case_types)]
pub struct mDNSInfo {
    // Timestamped entries for proper granularity
    pub ipv4_addresses: Vec<IpAddressEntry<Ipv4Addr>>,
    pub ipv6_addresses: Vec<IpAddressEntry<Ipv6Addr>>,
    pub mac_addresses: Vec<MacAddressEntry>,
    pub services: Vec<MdnsServiceEntry>,
    // Non-timestamped metadata
    pub hostname: String,
    pub instances: SortedVec<String>,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
}

pub async fn mdns_start() {
    MDNS_STOP.store(false, Ordering::Relaxed);

    if MDNS_HANDLE.lock().await.is_some() {
        trace!("mDNS task already running");
        return;
    }
    info!("Starting mDNS task");
    *MDNS_HANDLE.lock().await = Some(tokio::spawn(fetch_mdns_info_task()));
}

pub fn mdns_stop() {
    info!("Terminating mDNS task");
    MDNS_STOP.store(true, Ordering::Relaxed);
}

// To be called in case of network change
pub async fn mdns_flush() {
    info!("Flushing mDNS database");
    let mut locked_devices = DEVICES.lock().await;
    locked_devices.clear();
}

pub async fn mdns_get_by_ip(ip: &IpAddr) -> Option<mDNSInfo> {
    let locked_devices = DEVICES.lock().await;
    locked_devices.iter().find_map(|(_hostname, mdns_info)| {
        let found = match ip {
            IpAddr::V4(ipv4) => mdns_info.ipv4_addresses.iter().any(|e| e.address == *ipv4),
            IpAddr::V6(ipv6) => mdns_info.ipv6_addresses.iter().any(|e| e.address == *ipv6),
        };

        if found {
            trace!("Found mDNS entry for {}: {:?}", ip, mdns_info);
            Some(mdns_info.clone())
        } else {
            None
        }
    })
}

pub async fn mdns_get_by_ipv6(ipv6: &IpAddr) -> Option<mDNSInfo> {
    let locked_devices = DEVICES.lock().await;
    locked_devices.iter().find_map(|(_hostname, mdns_info)| {
        if let IpAddr::V6(ipv6_addr) = ipv6 {
            if mdns_info
                .ipv6_addresses
                .iter()
                .any(|e| e.address == *ipv6_addr)
            {
                trace!("Found mDNS entry for {}: {:?}", ipv6, mdns_info);
                Some(mdns_info.clone())
            } else {
                None
            }
        } else {
            None
        }
    })
}

pub async fn mdns_get_hostname_by_ip(ip: &IpAddr) -> Option<String> {
    let locked_devices = DEVICES.lock().await;
    locked_devices.iter().find_map(|(_hostname, mdns_info)| {
        let found = match ip {
            IpAddr::V4(ipv4) => mdns_info.ipv4_addresses.iter().any(|e| e.address == *ipv4),
            IpAddr::V6(ipv6) => mdns_info.ipv6_addresses.iter().any(|e| e.address == *ipv6),
        };

        if found {
            trace!("Found mDNS entry for {}: {:?}", ip, mdns_info);
            if !mdns_info.hostname.is_empty() {
                Some(mdns_info.hostname.clone())
            } else {
                None
            }
        } else {
            None
        }
    })
}

fn v6_to_mac(ipv6: &str) -> Option<String> {
    trace!("Attempting to convert IPv6 address {} to MAC address", ipv6);

    let ipv6_addr: Ipv6Addr = ipv6.parse().ok()?;
    let segments = ipv6_addr.segments();

    if segments[0] != 0xfe80 {
        trace!("IPv6 address {} is not a link-local address", ipv6);
        return None;
    }

    trace!("Found link-local IPv6 address {}", ipv6);

    let eui64_bytes = [
        (segments[4] >> 8) as u8,
        (segments[4] & 0xff) as u8,
        (segments[5] >> 8) as u8,
        (segments[5] & 0xff) as u8,
        (segments[6] >> 8) as u8,
        (segments[6] & 0xff) as u8,
        (segments[7] >> 8) as u8,
        (segments[7] & 0xff) as u8,
    ];

    // Convert EUI-64 to EUI-48 (MAC address)
    let eui48_bytes = [
        eui64_bytes[0] ^ 0x02,
        eui64_bytes[1],
        eui64_bytes[2],
        eui64_bytes[5],
        eui64_bytes[6],
        eui64_bytes[7],
    ];

    let mac = eui48_bytes
        .iter()
        .map(|byte| format!("{:02x}", byte))
        .collect::<Vec<String>>()
        .join(":");
    trace!(
        "Converted link-local IPv6 address {} to MAC address {}",
        ipv6,
        mac
    );

    Some(mac)
}

fn extract_mac_address(input: &str) -> Option<String> {
    let re = Regex::new(r"([0-9a-fA-F]{2}[:-]){5}([0-9a-fA-F]{2})").unwrap();
    if let Some(mac) = re.find(input).map(|mat| mat.as_str().to_string()) {
        Some(mac)
    } else {
        None
    }
}

async fn process_host(host: Host, service_name: String) {
    if host.host_name.is_some() {
        let hostname = host.host_name.as_ref().unwrap();
        let instance = host.name.clone();
        if !host.ip_address.is_empty() {
            let ip_addresses = host.ip_address.clone();
            trace!(
                "Found instance {} with host {} and ips {:?}",
                instance,
                hostname,
                ip_addresses
            );
            // Fill in the info for this host
            let mut locked_devices = DEVICES.lock().await;
            let now = Utc::now();
            let mdns_info = locked_devices.entry(hostname.clone()).or_insert(mDNSInfo {
                ipv4_addresses: Vec::new(),
                ipv6_addresses: Vec::new(),
                mac_addresses: Vec::new(),
                services: Vec::new(),
                hostname: hostname.clone(),
                instances: SortedVec::new(),
                first_seen: now,
                last_seen: now,
            });

            // Update the last detected time
            mdns_info.last_seen = now;

            // Process IP addresses with individual timestamps
            for ip in ip_addresses {
                match ip {
                    IpAddr::V4(ipv4) => {
                        // Add or update IPv4 with current timestamp
                        if let Some(entry) = mdns_info
                            .ipv4_addresses
                            .iter_mut()
                            .find(|e| e.address == ipv4)
                        {
                            entry.last_seen = now;
                        } else {
                            mdns_info.ipv4_addresses.push(IpAddressEntry {
                                address: ipv4,
                                last_seen: now,
                            });
                        }
                    }
                    IpAddr::V6(ipv6) => {
                        // Add or update IPv6 with current timestamp
                        if let Some(entry) = mdns_info
                            .ipv6_addresses
                            .iter_mut()
                            .find(|e| e.address == ipv6)
                        {
                            entry.last_seen = now;
                        } else {
                            mdns_info.ipv6_addresses.push(IpAddressEntry {
                                address: ipv6,
                                last_seen: now,
                            });

                            // Try to extract MAC from link-local IPv6
                            if mdns_info.mac_addresses.is_empty() {
                                if let Some(mac_str) = v6_to_mac(&ip.to_string()) {
                                    if let Ok(mac) = mac_str.parse::<MacAddr6>() {
                                        info!("Found MAC {} from IPv6 {}", mac, ip);
                                        mdns_info.mac_addresses.push(MacAddressEntry {
                                            address: mac,
                                            last_seen: now,
                                        });
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // Process services with individual timestamps
            if let Some(entry) = mdns_info
                .services
                .iter_mut()
                .find(|e| e.service == service_name)
            {
                entry.last_seen = now;
            } else {
                debug!("Found service {} for host {}", service_name, hostname);
                mdns_info.services.push(MdnsServiceEntry {
                    service: service_name.clone(),
                    last_seen: now,
                });
            }

            // Filter out the instances limited to the host name
            if !mdns_info.instances.contains(&instance) && &instance != hostname {
                debug!("Found instance {} for host {}", instance, hostname);
                mdns_info.instances.push(host.name.clone());
            }

            // Check if the instance name contains a MAC address
            if let Some(mac_str) = extract_mac_address(&instance) {
                if let Ok(mac) = mac_str.parse::<MacAddr6>() {
                    // Add or update MAC with current timestamp
                    if let Some(entry) = mdns_info
                        .mac_addresses
                        .iter_mut()
                        .find(|e| e.address == mac)
                    {
                        entry.last_seen = now;
                    } else {
                        debug!("Extracted MAC {} from instance {}", mac, instance);
                        mdns_info.mac_addresses.push(MacAddressEntry {
                            address: mac,
                            last_seen: now,
                        });
                    }
                }
            }
        }
    }
}

/// mDNS/DNS names are limited to 63-byte labels and 255 bytes total
/// (RFC 1035 section 3.1). Service and host names learned from the network can
/// violate this, and forwarding such a name to the query builder would build an
/// oversized label. Skip clearly invalid names before resolving them so a
/// malformed or hostile advertisement cannot disrupt discovery.
fn is_resolvable_dns_name(name: &str) -> bool {
    !name.is_empty() && name.len() <= 255 && name.split('.').all(|label| label.len() <= 63)
}

async fn fetch_mdns_info_task() {
    let pause_duration = Duration::from_secs(5);

    loop {
        if MDNS_STOP.load(Ordering::Relaxed) {
            info!("Received mDNS termination signal");
            trace!("mDNS database: {:?}", &*DEVICES.lock().await);
            break;
        }
        trace!("Starting mDNS discovery loop");
        // First discover all the services
        let responses = match wez_mdns::resolve(
            "_services._dns-sd._udp.local",
            QueryParameters::SERVICE_LOOKUP,
        )
        .await
        {
            Ok(responses) => responses,
            Err(e) => {
                warn!("Error querying mDNS services: {:?}", e);
                continue;
            }
        };
        let services = match responses.recv().await {
            Ok(services) => services,
            Err(e) => {
                warn!("Error receiving mDNS services query response: {:?}", e);
                continue;
            }
        };
        let hosts = services.hosts();
        trace!("Response: {:#?}", services);
        trace!("Hosts: {:#?}", hosts);
        // Only process each service once per iteration using a HashSet for O(1) look-ups
        let mut done_service: HashSet<String> = HashSet::new();
        for service in hosts {
            // insert returns false when the key was already present
            if !done_service.insert(service.name.clone()) {
                continue;
            }
            let service_name = service.name.clone();
            let service_name_clone = service_name.clone();
            trace!("Found service: {}", service_name);
            if !is_resolvable_dns_name(&service_name) {
                warn!(
                    "Skipping mDNS service with invalid DNS name (label/length out of range): {:?}",
                    service_name
                );
                continue;
            }
            // Now discover all the instances of this service
            let responses = match wez_mdns::resolve(
                service_name.clone(),
                QueryParameters::SERVICE_LOOKUP,
            )
            .await
            {
                Ok(responses) => responses,
                Err(e) => {
                    // Only warn to prevent multiple sentry errors
                    warn!(
                        "Error querying mDNS service {}: {:?}",
                        service_name.clone(),
                        e
                    );
                    continue;
                }
            };
            // Get the instances
            let instances = match responses.recv().await {
                Ok(instances) => instances,
                Err(e) => {
                    // Only warn to prevent multiple sentry errors
                    warn!(
                        "Error receiving mDNS query response for service {} : {:?}",
                        service_name, e
                    );
                    continue;
                }
            };
            // Scan the hostnames for each instance
            for host in instances.hosts() {
                let host_clone = host.clone();
                // Check if we have a host name
                if let Some(hostname) = host_clone.host_name {
                    process_host(host, service_name_clone.clone()).await;
                    if !is_resolvable_dns_name(&hostname) {
                        warn!(
                            "Skipping mDNS host resolve for invalid DNS name (label/length out of range): {:?}",
                            hostname
                        );
                        continue;
                    }
                    // Now resolve the host to get all the A and AAAA records (IPv6 addresses) to extrapolate the MAC address
                    let responses =
                        match wez_mdns::resolve(hostname.clone(), QueryParameters::HOST_LOOKUP)
                            .await
                        {
                            Ok(responses) => responses,
                            Err(e) => {
                                // Only warn to prevent multiple sentry errors
                                warn!("Error resolving hostname {}: {:?}", hostname.clone(), e);
                                continue;
                            }
                        };
                    let hosts = match responses.recv().await {
                        Ok(hosts) => hosts,
                        Err(e) => {
                            // Only warn to prevent multiple sentry errors
                            warn!(
                                "Error receiving mDNS query response for hostname {}: {:?}",
                                hostname, e
                            );
                            continue;
                        }
                    };
                    // Scan the hosts for each entry
                    for host in hosts.hosts() {
                        process_host(host, service_name_clone.clone()).await;
                    }
                }
            }
        }
        // Wait for 5 seconds before scanning again
        tokio::time::sleep(pause_duration).await;
    }
}

/// Batch-resolve a list of IPs via mDNS, returning (ip, hostname, primary_mac, services).
/// Primary MAC is chosen by most recent `last_seen` among the device's MAC entries.
pub async fn mdns_resolve_batch(
    addresses: &[IpAddr],
) -> Vec<(IpAddr, String, MacAddr6, Vec<String>)> {
    let mut results = Vec::new();
    for address in addresses {
        if let Some(mdns_info) = mdns_get_by_ip(address).await {
            let mut services_instances = mdns_info.instances.to_vec();
            services_instances.extend(mdns_info.services.iter().map(|e| e.service.clone()));
            services_instances.sort();
            services_instances.dedup();

            let primary_mac = mdns_info
                .mac_addresses
                .iter()
                .max_by_key(|e| e.last_seen)
                .map(|e| e.address)
                .unwrap_or(MacAddr6::nil());

            results.push((
                *address,
                mdns_info.hostname,
                primary_mac,
                services_instances,
            ));
        }
    }
    results
}

pub async fn get_mdns_by_hostname(hostname: &str) -> Option<mDNSInfo> {
    let locked_devices = DEVICES.lock().await;
    match locked_devices.get(hostname) {
        Some(mdns_info) => {
            info!("Found mDNS entry for {}: {:?}", hostname, mdns_info);
            Some(mdns_info.clone())
        }
        None => None,
    }
}
