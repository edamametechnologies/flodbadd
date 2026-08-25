use crate::ip::is_identity_bearing_ipv4;
use crate::port_info::*;
use crate::port_vulns::*;
use crate::vendor_vulns::*;
use chrono::{DateTime, Utc};
use edamame_backend::lanscan_device_info_backend::DeviceInfoBackend;
use edamame_backend::lanscan_port_info_backend::PortInfoBackend;
use edamame_backend::lanscan_vulnerability_info_backend::VulnerabilityInfoBackend;
use macaddr::MacAddr6;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use tracing::{debug, warn};

/// Upper bound on open ports for a standard-breadth scan (the ~5099-port DB).
/// Real phones, IoT, and routers sit well below this; a standard scan that
/// falsely marks nearly the entire DB as open lands far above it.
pub const MAX_REASONABLE_OPEN_PORTS: usize = 256;

/// Upper bound on open ports for a deep-breadth scan (0..=65535), and the
/// ceiling applied to community import and share.
///
/// A deep sweep probes ~13x more ports than the standard DB, so it legitimately
/// discovers more listeners: a Docker host publishing many container ports, or a
/// server with a wide service surface, can plausibly exceed
/// [`MAX_REASONABLE_OPEN_PORTS`]. Nothing on a LAN plausibly exceeds this.
/// Import and share use this same value so that a port count we accept from a
/// first-hand local deep scan is also a port count we are willing to store,
/// publish, and accept from a peer -- otherwise local state and the published
/// payload silently disagree.
pub const MAX_REASONABLE_OPEN_PORTS_DEEP: usize = 1024;

/// Probed-port count above which a sweep counts as deep-breadth.
///
/// Sits well above the standard port DB (which may grow over time) and far
/// below a full 0..=65535 sweep, so the classification stays correct without
/// tracking which scan mode produced a given device.
pub const DEEP_PROBE_BREADTH_THRESHOLD: usize = 8192;

/// Pick the open-port ceiling appropriate to how many ports were actually
/// probed for a device. Breadth varies *within* one scan: the host's own IP is
/// always deep-scanned even when neighbors get the standard port list.
pub fn max_reasonable_open_ports_for_probed(probed_ports: usize) -> usize {
    if probed_ports > DEEP_PROBE_BREADTH_THRESHOLD {
        MAX_REASONABLE_OPEN_PORTS_DEEP
    } else {
        MAX_REASONABLE_OPEN_PORTS
    }
}

/// Whether a MAC address is evidence of one specific network interface.
///
/// A multicast address (I/G bit set, which includes broadcast) names a
/// destination group, never an interface's own address, and a nil address names
/// nothing at all. Capture parsing can still surface either as a device's
/// address. Such an address is unusable as identity in *both* directions: it can
/// split one device across records, and -- because any number of unrelated
/// records can hold the same group address -- it can also merge unrelated
/// devices on a shared "identity" that identifies nothing.
pub fn is_identity_bearing_mac(mac: &MacAddr6) -> bool {
    !mac.is_multicast() && !mac.is_nil()
}

#[derive(Debug, Ord, PartialOrd, Eq, PartialEq, Clone, Serialize, Deserialize)]
pub enum DeviceCriticality {
    Unknown,
    Low,
    Medium,
    High,
}

impl std::fmt::Display for DeviceCriticality {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DeviceCriticality::Unknown => write!(f, "Unknown"),
            DeviceCriticality::Low => write!(f, "Low"),
            DeviceCriticality::Medium => write!(f, "Medium"),
            DeviceCriticality::High => write!(f, "High"),
        }
    }
}

// Timestamped entry for IP addresses
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpAddressEntry<T> {
    pub address: T,
    pub last_seen: DateTime<Utc>,
}

impl<T: PartialEq> PartialEq for IpAddressEntry<T> {
    fn eq(&self, other: &Self) -> bool {
        self.address == other.address
    }
}

impl<T: Eq> Eq for IpAddressEntry<T> {}

impl<T: PartialOrd> PartialOrd for IpAddressEntry<T> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        self.address.partial_cmp(&other.address)
    }
}

impl<T: Ord> Ord for IpAddressEntry<T> {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.address.cmp(&other.address)
    }
}

// Timestamped entry for mDNS services
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MdnsServiceEntry {
    pub service: String,
    pub last_seen: DateTime<Utc>,
}

// Timestamped entry for MAC addresses
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MacAddressEntry {
    pub address: MacAddr6,
    pub last_seen: DateTime<Utc>,
}

impl PartialEq for MacAddressEntry {
    fn eq(&self, other: &Self) -> bool {
        self.address == other.address
    }
}

impl Eq for MacAddressEntry {}

impl PartialOrd for MacAddressEntry {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        self.address.partial_cmp(&other.address)
    }
}

impl Ord for MacAddressEntry {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.address.cmp(&other.address)
    }
}

// We should really use HashSets instead of Vec, but we don't in order to make it more usable with FFI
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DeviceInfo {
    // PII
    // Main address is IPv4 or IPv6
    ip_address: IpAddr,
    pub ip_addresses_v4: Vec<IpAddressEntry<Ipv4Addr>>,
    pub ip_addresses_v6: Vec<IpAddressEntry<Ipv6Addr>>,
    mac_address: Option<MacAddr6>,
    pub mac_addresses: Vec<MacAddressEntry>,
    pub hostname: String,
    pub mdns_services: Vec<MdnsServiceEntry>,
    // Non-PII
    pub os_name: String,
    pub os_version: String,
    pub device_vendor: String,
    // Sorted Vec would be better but had trouble with the bridge once...
    pub open_ports: Vec<PortInfo>,
    // Below is the device state
    pub active: bool,
    pub added: bool,
    pub activated: bool,
    pub deactivated: bool,
    pub no_icmp: bool,
    pub non_std_ports: bool,
    pub criticality: DeviceCriticality,
    // We use a string as we rely on a dynamic database of device types
    pub device_type: String,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    // Last time a scan returned a definite port verdict (an open port or a
    // refusal) for this device. `None` means no port evidence has ever been
    // obtained, which is what separates criticality `Unknown` from `Low`: a
    // host that silently drops every probe looks identical to a host with a
    // genuinely minimal attack surface if you only count open ports.
    // `serde(default)` so caches written before this field existed still load.
    #[serde(default)]
    pub last_port_scan: Option<DateTime<Utc>>,
    // Origin tracking for community sharing
    pub origin_ip: String, // IP of the device that first discovered this device
    pub origin_network: String, // Network identifier of where the device was first discovered
    // Below are user properties
    pub custom_name: String,
    pub deleted: bool,
    pub last_modified: DateTime<Utc>,
    // Below are internal properties (not serialized)
    // Flag to track devices seen by direct scanning
    #[serde(skip)]
    pub is_local: bool,
    // Timestamp observed from community peers
    #[serde(skip)]
    pub last_seen_community: Option<DateTime<Utc>>,
    // Active flag observed from community peers
    #[serde(skip)]
    pub community_active: bool,
}

impl DeviceInfo {
    pub fn new(ip_address: Option<IpAddr>) -> DeviceInfo {
        let ip_address = ip_address.unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
        let now = Utc::now();
        let ip_addresses_v4 = match ip_address {
            IpAddr::V4(ip) => vec![IpAddressEntry {
                address: ip,
                last_seen: now,
            }],
            IpAddr::V6(_) => vec![],
        };
        let ip_addresses_v6 = match ip_address {
            IpAddr::V4(_) => vec![],
            IpAddr::V6(ip) => vec![IpAddressEntry {
                address: ip,
                last_seen: now,
            }],
        };
        DeviceInfo {
            ip_address: ip_address,
            ip_addresses_v4: ip_addresses_v4,
            ip_addresses_v6: ip_addresses_v6,
            mac_address: None,
            mac_addresses: Vec::new(),
            hostname: "".to_string(),
            mdns_services: vec![],
            os_name: "".to_string(),
            os_version: "".to_string(),
            device_vendor: "".to_string(),
            open_ports: Vec::new(),
            // Below is the device state
            active: false,
            added: false,
            activated: false,
            deactivated: false,
            no_icmp: false,
            non_std_ports: false,
            criticality: DeviceCriticality::Unknown,
            device_type: "Unknown".to_string(),
            // Initialize the times to UNIX_EPOCH
            first_seen: DateTime::<Utc>::from(std::time::UNIX_EPOCH),
            last_seen: DateTime::<Utc>::from(std::time::UNIX_EPOCH),
            // No port evidence yet -- distinct from "scanned, nothing found".
            last_port_scan: None,
            last_seen_community: None,
            community_active: false,
            // Origin tracking for community sharing
            origin_ip: "".to_string(), // IP of the device that first discovered this device
            origin_network: "".to_string(), // Network identifier of where the device was first discovered
            // Below are user properties
            custom_name: "".to_string(),
            // Not deleted by default
            deleted: false,
            // Initialize the last time to UNIX_EPOCH
            last_modified: DateTime::<Utc>::from(std::time::UNIX_EPOCH),
            // Below are internal properties (not serialized)
            // Not local by default
            is_local: false,
        }
    }

    pub fn get_ip_address(&self) -> IpAddr {
        self.ip_address
    }

    /// Set the primary IP address and add additional addresses.
    /// Uses current time as timestamp. For mDNS or other sources with known timestamps,
    /// use `set_ip_address_with_timestamp` or `populate_from_mdns` instead.
    pub fn set_ip_address(
        &mut self,
        ip_address: IpAddr,
        ip_addresses_v4: Vec<Ipv4Addr>,
        ip_addresses_v6: Vec<Ipv6Addr>,
    ) {
        self.set_ip_address_with_timestamp(
            ip_address,
            ip_addresses_v4,
            ip_addresses_v6,
            Utc::now(),
        );
    }

    /// Set the primary IP address and add additional addresses with explicit timestamp.
    /// Use this when you know when the IP addresses were discovered (e.g., from mDNS, scanning, etc.).
    pub fn set_ip_address_with_timestamp(
        &mut self,
        ip_address: IpAddr,
        ip_addresses_v4: Vec<Ipv4Addr>,
        ip_addresses_v6: Vec<Ipv6Addr>,
        timestamp: DateTime<Utc>,
    ) {
        // Ignore unspecified ip addresses
        if ip_address.is_unspecified() {
            return;
        }

        // First, preserve the current primary IP address by adding it to the appropriate list
        match self.ip_address {
            IpAddr::V4(ip) if !ip.is_unspecified() => {
                self.add_ipv4_entry(ip, timestamp);
            }
            IpAddr::V6(ip) if !ip.is_unspecified() => {
                self.add_ipv6_entry(ip, timestamp);
            }
            _ => {
                // Current IP is unspecified, nothing to preserve
            }
        }

        // Now set the new primary IP address
        self.ip_address = ip_address;

        // Add the new IP address to the appropriate list as well
        match ip_address {
            IpAddr::V4(ip) => {
                self.add_ipv4_entry(ip, timestamp);
            }
            IpAddr::V6(ip) => {
                self.add_ipv6_entry(ip, timestamp);
            }
        }

        // Add any additional IP addresses provided with the same timestamp
        self.add_ip_addresses_with_timestamp(ip_addresses_v4, ip_addresses_v6, timestamp);
    }

    // Helper method to add IPv4 entry with timestamp (updates if exists)
    pub(crate) fn add_ipv4_entry(&mut self, addr: Ipv4Addr, timestamp: DateTime<Utc>) {
        // This list is identity evidence for merge decisions, so keep addresses that
        // name no single host out of it. A record that accumulates several
        // 169.254.0.0/16 addresses (one per DHCP failure) would otherwise start
        // matching every other host that ever fell back to link-local.
        if !is_identity_bearing_ipv4(&addr) {
            return;
        }

        // Check if address already exists, update timestamp if it does
        if let Some(entry) = self.ip_addresses_v4.iter_mut().find(|e| e.address == addr) {
            if timestamp > entry.last_seen {
                entry.last_seen = timestamp;
            }
        } else {
            self.ip_addresses_v4.push(IpAddressEntry {
                address: addr,
                last_seen: timestamp,
            });
        }
    }

    // Helper method to add IPv6 entry with timestamp (updates if exists)
    pub(crate) fn add_ipv6_entry(&mut self, addr: Ipv6Addr, timestamp: DateTime<Utc>) {
        // Check if address already exists, update timestamp if it does
        if let Some(entry) = self.ip_addresses_v6.iter_mut().find(|e| e.address == addr) {
            if timestamp > entry.last_seen {
                entry.last_seen = timestamp;
            }
        } else {
            self.ip_addresses_v6.push(IpAddressEntry {
                address: addr,
                last_seen: timestamp,
            });
        }
    }

    // Helper method to add mDNS service entry with timestamp (updates if exists)
    pub(crate) fn add_mdns_entry(&mut self, service: String, timestamp: DateTime<Utc>) {
        // Check if service already exists, update timestamp if it does
        if let Some(entry) = self.mdns_services.iter_mut().find(|e| e.service == service) {
            if timestamp > entry.last_seen {
                entry.last_seen = timestamp;
            }
        } else {
            self.mdns_services.push(MdnsServiceEntry {
                service,
                last_seen: timestamp,
            });
        }
    }

    // Helper method to add MAC address entry with timestamp (updates if exists)
    pub(crate) fn add_mac_entry(&mut self, addr: MacAddr6, timestamp: DateTime<Utc>) {
        // Reject addresses that name no interface. Capture parsing surfaces group
        // addresses (broadcast included) as device addresses, and once stored they act
        // as identity: the same group address can appear in any number of unrelated
        // records, so a later merge reads it as shared hardware and fuses hosts that
        // have nothing in common. This is the chokepoint every path funnels through,
        // including merge re-importing a peer's entries, so filtering here keeps the
        // garbage out rather than having each caller remember to.
        if !is_identity_bearing_mac(&addr) {
            return;
        }

        // Check if address already exists, update timestamp if it does
        if let Some(entry) = self.mac_addresses.iter_mut().find(|e| e.address == addr) {
            if timestamp > entry.last_seen {
                entry.last_seen = timestamp;
            }
        } else {
            self.mac_addresses.push(MacAddressEntry {
                address: addr,
                last_seen: timestamp,
            });
        }
    }

    /// Add IP addresses using current time as timestamp.
    /// For mDNS or other sources with known timestamps, use `add_ip_addresses_with_timestamp` instead.
    pub fn add_ip_addresses(
        &mut self,
        ip_addresses_v4: Vec<Ipv4Addr>,
        ip_addresses_v6: Vec<Ipv6Addr>,
    ) {
        // Default to current time if not explicitly provided
        self.add_ip_addresses_with_timestamp(ip_addresses_v4, ip_addresses_v6, Utc::now());
    }

    /// Add IP addresses with explicit timestamp.
    /// Use this when you know when the IP addresses were discovered (e.g., from mDNS discovery).
    pub fn add_ip_addresses_with_timestamp(
        &mut self,
        ip_addresses_v4: Vec<Ipv4Addr>,
        ip_addresses_v6: Vec<Ipv6Addr>,
        timestamp: DateTime<Utc>,
    ) {
        // Add IPv4 addresses with timestamps
        for addr in ip_addresses_v4 {
            self.add_ipv4_entry(addr, timestamp);
        }

        // Add IPv6 addresses with timestamps
        for addr in ip_addresses_v6 {
            self.add_ipv6_entry(addr, timestamp);
        }

        // Deduplicate and truncate
        self.deduplicate_and_truncate_ips();
    }

    // Truncate IPv6 addresses to keep only the most recently seen (by timestamp)
    fn truncate_ipv6_addresses(&mut self) {
        const MAX_IPV6_ADDRESSES: usize = 10;
        if self.ip_addresses_v6.len() <= MAX_IPV6_ADDRESSES {
            return;
        }

        // Sort by timestamp (most recent first), then take the first N
        self.ip_addresses_v6
            .sort_by(|a, b| b.last_seen.cmp(&a.last_seen)); // Most recent first
        self.ip_addresses_v6.truncate(MAX_IPV6_ADDRESSES);
    }

    /// Get the most recently seen IPv4 address (by entry timestamp)
    pub fn get_most_recent_ipv4(&self) -> Option<(Ipv4Addr, DateTime<Utc>)> {
        self.ip_addresses_v4
            .iter()
            .max_by_key(|e| e.last_seen)
            .map(|e| (e.address, e.last_seen))
    }

    /// Get the most recently seen IPv6 address (by entry timestamp)
    pub fn get_most_recent_ipv6(&self) -> Option<(Ipv6Addr, DateTime<Utc>)> {
        self.ip_addresses_v6
            .iter()
            .max_by_key(|e| e.last_seen)
            .map(|e| (e.address, e.last_seen))
    }

    /// Validate and sanitize timestamps from external sources (e.g., community sharing).
    /// Returns true if the device was modified.
    /// - Clamps future timestamps to now (clock skew protection)
    /// - Replaces UNIX_EPOCH timestamps with now (placeholder detection)
    /// Note: Old timestamps are valid - a device could have been first seen years ago.
    pub fn validate_timestamps(&mut self) -> bool {
        let now = Utc::now();
        let epoch = DateTime::<Utc>::from(std::time::UNIX_EPOCH);
        // Small buffer to detect epoch-like timestamps (within 1 day of epoch)
        let epoch_threshold = epoch + chrono::Duration::days(1);
        let mut modified = false;

        // Helper to clamp a timestamp - only clamps future or epoch timestamps
        let clamp_timestamp = |ts: DateTime<Utc>| -> (DateTime<Utc>, bool) {
            if ts > now {
                // Future timestamp - clamp to now (clock skew)
                (now, true)
            } else if ts < epoch_threshold {
                // Epoch or near-epoch - this is a placeholder, use now
                (now, true)
            } else {
                // Valid historical timestamp - preserve it
                (ts, false)
            }
        };

        // Validate device-level timestamps
        let (clamped_first, first_modified) = clamp_timestamp(self.first_seen);
        if first_modified {
            self.first_seen = clamped_first;
            modified = true;
        }

        let (clamped_last, last_modified) = clamp_timestamp(self.last_seen);
        if last_modified {
            self.last_seen = clamped_last;
            modified = true;
        }

        // Validate IPv4 entry timestamps
        for entry in self.ip_addresses_v4.iter_mut() {
            let (clamped, was_modified) = clamp_timestamp(entry.last_seen);
            if was_modified {
                entry.last_seen = clamped;
                modified = true;
            }
        }

        // Validate IPv6 entry timestamps
        for entry in self.ip_addresses_v6.iter_mut() {
            let (clamped, was_modified) = clamp_timestamp(entry.last_seen);
            if was_modified {
                entry.last_seen = clamped;
                modified = true;
            }
        }

        // Validate MAC entry timestamps
        for entry in self.mac_addresses.iter_mut() {
            let (clamped, was_modified) = clamp_timestamp(entry.last_seen);
            if was_modified {
                entry.last_seen = clamped;
                modified = true;
            }
        }

        // Validate mDNS service timestamps
        for entry in self.mdns_services.iter_mut() {
            let (clamped, was_modified) = clamp_timestamp(entry.last_seen);
            if was_modified {
                entry.last_seen = clamped;
                modified = true;
            }
        }

        modified
    }

    /// Update primary IP to be the most recently seen address.
    /// IPv4 takes precedence over IPv6 when both have recent entries.
    pub fn update_primary_ip_from_entries(&mut self) {
        let most_recent_v4 = self.get_most_recent_ipv4();
        let most_recent_v6 = self.get_most_recent_ipv6();

        match (most_recent_v4, most_recent_v6) {
            (Some((ipv4, ts_v4)), Some((_, ts_v6))) => {
                // IPv4 takes precedence, but only if it's not significantly older
                // If IPv6 is more than 24 hours newer, use IPv6
                let ipv6_much_newer = (ts_v6 - ts_v4).num_hours() > 24;
                if ipv6_much_newer {
                    if let Some((ipv6, _)) = most_recent_v6 {
                        self.ip_address = IpAddr::V6(ipv6);
                    }
                } else {
                    self.ip_address = IpAddr::V4(ipv4);
                }
            }
            (Some((ipv4, _)), None) => {
                self.ip_address = IpAddr::V4(ipv4);
            }
            (None, Some((ipv6, _))) => {
                self.ip_address = IpAddr::V6(ipv6);
            }
            (None, None) => {
                // Keep current primary if no entries
            }
        }
    }

    // Truncate mDNS services to keep only the most recently seen (by timestamp)
    fn truncate_mdns_services(&mut self) {
        const MAX_MDNS_SERVICES: usize = 20;
        if self.mdns_services.len() <= MAX_MDNS_SERVICES {
            return;
        }

        // Sort by timestamp (most recent first), then take the first N
        self.mdns_services
            .sort_by(|a, b| b.last_seen.cmp(&a.last_seen)); // Most recent first
        self.mdns_services.truncate(MAX_MDNS_SERVICES);
    }

    // Drop mDNS services not re-observed within `max_age`.
    //
    // The cap above bounds how MANY services we keep, not how OLD they may be, and
    // merging only ever adds. A service that stopped answering therefore stayed
    // forever and kept feeding classification, so a device could keep being typed
    // off a service it no longer ran.
    //
    // Expiry is sound here because these are true observation times, not copy
    // times: the discovery loop re-queries continuously rather than waiting on
    // announcements, and `add_mdns_entry` only ever moves `last_seen` forward. A
    // stale entry means the service really did stop answering, not that we stopped
    // asking. Callers pick `max_age`; it must stay well above the discovery period
    // so a live-but-briefly-quiet responder is not dropped.
    //
    // A timestamp in the future (clock skew) gives a negative age and is kept.
    pub fn retain_fresh_mdns_services(&mut self, max_age: chrono::Duration) {
        let now = Utc::now();
        self.mdns_services
            .retain(|entry| now.signed_duration_since(entry.last_seen) <= max_age);
    }

    // Truncate MAC addresses to keep only the most recently seen (by timestamp)
    fn truncate_mac_addresses(&mut self) {
        const MAX_MAC_ADDRESSES: usize = 10;
        if self.mac_addresses.len() <= MAX_MAC_ADDRESSES {
            return;
        }

        // Ensure the primary MAC address is always preserved (if set)
        // This prevents vendor lookup and stable ID generation from failing
        let primary_mac = self.mac_address;

        // Sort by timestamp (most recent first)
        self.mac_addresses
            .sort_by(|a, b| b.last_seen.cmp(&a.last_seen)); // Most recent first

        // If we have a primary MAC, ensure it's in the list before truncation
        if let Some(primary) = primary_mac {
            // Check if primary MAC is already in the top MAX_MAC_ADDRESSES entries
            let primary_in_top = self
                .mac_addresses
                .iter()
                .take(MAX_MAC_ADDRESSES)
                .any(|e| e.address == primary);

            if !primary_in_top {
                // Primary MAC would be truncated - find it and move it to position MAX_MAC_ADDRESSES-1
                if let Some(primary_pos) =
                    self.mac_addresses.iter().position(|e| e.address == primary)
                {
                    let primary_entry = self.mac_addresses.remove(primary_pos);
                    // Insert at position MAX_MAC_ADDRESSES-1 to ensure it's kept
                    // (it will push out the oldest of the top MAX_MAC_ADDRESSES)
                    if self.mac_addresses.len() >= MAX_MAC_ADDRESSES {
                        self.mac_addresses[MAX_MAC_ADDRESSES - 1] = primary_entry;
                    } else {
                        self.mac_addresses.push(primary_entry);
                    }
                }
            }
        }

        // Now truncate to MAX_MAC_ADDRESSES
        self.mac_addresses.truncate(MAX_MAC_ADDRESSES);
    }

    /// Populate DeviceInfo from mDNS data with explicit timestamps.
    ///
    /// This should be called when mDNS data is discovered, using the mDNS discovery timestamp
    /// from `mDNSInfo.last_seen`. This ensures that IP addresses and services are timestamped
    /// with when they were actually seen via mDNS, not when they're added to DeviceInfo.
    ///
    /// Example usage:
    /// ```ignore
    /// if let Some(mdns_info) = mdns_get_by_ip(&ip).await {
    ///     device.populate_from_mdns(
    ///         mdns_info.ip_addr.map(|ip| ip).into_iter().filter_map(|ip| {
    ///             if let IpAddr::V4(v4) = ip { Some(v4) } else { None }
    ///         }).collect(),
    ///         mdns_info.ipv6_addr.into_iter().filter_map(|ip| {
    ///             if let IpAddr::V6(v6) = ip { Some(v6) } else { None }
    ///         }).collect(),
    ///         mdns_info.services.into_iter().collect(),
    ///         mdns_info.last_seen, // Use the mDNS discovery timestamp
    ///     );
    /// }
    /// ```
    pub fn populate_from_mdns(
        &mut self,
        ipv4_addresses: Vec<Ipv4Addr>,
        ipv6_addresses: Vec<Ipv6Addr>,
        mdns_services: Vec<String>,
        discovery_timestamp: DateTime<Utc>,
    ) {
        // Add IPv4 addresses with the mDNS discovery timestamp
        for addr in ipv4_addresses {
            self.add_ipv4_entry(addr, discovery_timestamp);
        }

        // Add IPv6 addresses with the mDNS discovery timestamp
        for addr in ipv6_addresses {
            self.add_ipv6_entry(addr, discovery_timestamp);
        }

        // Add mDNS services with the mDNS discovery timestamp
        for service in mdns_services {
            self.add_mdns_entry(service, discovery_timestamp);
        }

        // Deduplicate and truncate
        self.deduplicate_and_truncate_ips();
        self.truncate_mdns_services();
    }

    // Helper method to deduplicate IP addresses (called after adding new ones)
    pub(crate) fn deduplicate_and_truncate_ips(&mut self) {
        // Deduplicate IPv4: keep entry with most recent timestamp
        let mut ipv4_deduped: Vec<IpAddressEntry<Ipv4Addr>> = Vec::new();
        let mut seen_v4 = HashMap::new();
        for entry in self.ip_addresses_v4.iter() {
            match seen_v4.get(&entry.address) {
                Some(existing_timestamp) if entry.last_seen > *existing_timestamp => {
                    // Update with newer timestamp
                    if let Some(existing_entry) =
                        ipv4_deduped.iter_mut().find(|e| e.address == entry.address)
                    {
                        existing_entry.last_seen = entry.last_seen;
                    }
                    seen_v4.insert(entry.address, entry.last_seen);
                }
                None => {
                    // New address
                    ipv4_deduped.push(entry.clone());
                    seen_v4.insert(entry.address, entry.last_seen);
                }
                _ => {
                    // Older timestamp, skip
                }
            }
        }
        self.ip_addresses_v4 = ipv4_deduped;

        // Deduplicate IPv6: keep entry with most recent timestamp
        let mut ipv6_deduped: Vec<IpAddressEntry<Ipv6Addr>> = Vec::new();
        let mut seen_v6 = HashMap::new();
        for entry in self.ip_addresses_v6.iter() {
            match seen_v6.get(&entry.address) {
                Some(existing_timestamp) if entry.last_seen > *existing_timestamp => {
                    // Update with newer timestamp
                    if let Some(existing_entry) =
                        ipv6_deduped.iter_mut().find(|e| e.address == entry.address)
                    {
                        existing_entry.last_seen = entry.last_seen;
                    }
                    seen_v6.insert(entry.address, entry.last_seen);
                }
                None => {
                    // New address
                    ipv6_deduped.push(entry.clone());
                    seen_v6.insert(entry.address, entry.last_seen);
                }
                _ => {
                    // Older timestamp, skip
                }
            }
        }
        self.ip_addresses_v6 = ipv6_deduped;

        // Truncate to keep only the most recently seen entries
        self.truncate_ipv6_addresses();
    }

    // Effective last seen across local and community sources
    pub fn effective_last_seen(&self) -> DateTime<Utc> {
        match self.last_seen_community {
            Some(ts) => {
                if ts > self.last_seen {
                    ts
                } else {
                    self.last_seen
                }
            }
            None => self.last_seen,
        }
    }

    // Effective active across local and community sources
    pub fn effective_active(&self) -> bool {
        self.active || self.community_active
    }

    pub fn get_mac_address(&self) -> Option<MacAddr6> {
        self.mac_address
    }

    /// Set the primary MAC address and add additional addresses.
    /// Uses current time as timestamp.
    pub fn set_mac_address(&mut self, mac_address: MacAddr6, mac_addresses: Vec<MacAddr6>) {
        self.set_mac_address_with_timestamp(mac_address, mac_addresses, Utc::now());
    }

    /// Set the primary MAC address and add additional addresses with explicit timestamp.
    pub fn set_mac_address_with_timestamp(
        &mut self,
        mac_address: MacAddr6,
        mac_addresses: Vec<MacAddr6>,
        timestamp: DateTime<Utc>,
    ) {
        // A primary that names no interface is worse than no primary: it becomes the
        // record's identity for conflict checks and for the vendor OUI lookup.
        if !is_identity_bearing_mac(&mac_address) {
            return;
        }
        self.mac_address = Some(mac_address);

        // Add the primary MAC address
        self.add_mac_entry(mac_address, timestamp);

        // Add additional MAC addresses. add_mac_entry rejects non-identity addresses.
        for addr in mac_addresses {
            self.add_mac_entry(addr, timestamp);
        }

        // Deduplicate and truncate
        self.deduplicate_and_truncate_macs();
    }

    // Helper method to deduplicate MAC addresses (called after adding new ones)
    pub(crate) fn deduplicate_and_truncate_macs(&mut self) {
        // Deduplicate MACs: keep entry with most recent timestamp
        let mut mac_deduped: Vec<MacAddressEntry> = Vec::new();
        let mut seen = HashMap::new();
        for entry in self.mac_addresses.iter() {
            match seen.get(&entry.address) {
                Some(existing_timestamp) if entry.last_seen > *existing_timestamp => {
                    // Update with newer timestamp
                    if let Some(existing_entry) =
                        mac_deduped.iter_mut().find(|e| e.address == entry.address)
                    {
                        existing_entry.last_seen = entry.last_seen;
                    }
                    seen.insert(entry.address, entry.last_seen);
                }
                None => {
                    // New address
                    mac_deduped.push(entry.clone());
                    seen.insert(entry.address, entry.last_seen);
                }
                _ => {
                    // Older timestamp, skip
                }
            }
        }
        self.mac_addresses = mac_deduped;

        // Truncate to keep only the most recently seen entries
        self.truncate_mac_addresses();
    }

    // Used before any query to AI assistance
    // Sort the fields to make sure they are always in the same order to have prompt consistency
    pub async fn sanitized_device_info_backend(device: &DeviceInfo) -> DeviceInfoBackend {
        // Include the vulnerabilities
        let vulnerabilities: Vec<VulnerabilityInfoBackend> =
            // Sorted
            get_vulns_of_vendor(&device.device_vendor)
                .await
                .iter()
                .map(|vuln| vuln.clone().into())
                .collect();
        let mut open_ports: Vec<PortInfoBackend> = Vec::new();
        for port in device.open_ports.iter() {
            let mut port_info: PortInfoBackend = port.clone().into();
            // Sorted
            port_info.vulnerabilities = get_vulns_of_port(port.port)
                .await
                .iter()
                .map(|vuln| vuln.clone().into())
                .collect();
            open_ports.push(port_info);
        }

        // mDNS instances can be prefixed by the device's serial, mac, ip address.
        // We keep only the part from _xxx._yyy.local onwards
        let re = Regex::new(r".*?(_.*?\.local)").unwrap();

        let mut mdns_services = Vec::new();
        for mdns_entry in device.mdns_services.iter() {
            // Replace the matched pattern with the first captured group, which is _xxx._yyy.local
            let sanitized = re.replace(&mdns_entry.service, "$1").to_string();
            mdns_services.push(sanitized);
        }
        // Sort and deduplicate mDNS services
        mdns_services.sort();
        mdns_services.dedup();
        // Sort open ports
        open_ports.sort_by(|a, b| a.port.cmp(&b.port));
        let device_backend = DeviceInfoBackend {
            mdns_services,
            device_vendor: device.device_vendor.clone(),
            vulnerabilities,
            open_ports,
        };
        device_backend
    }

    // Check if devices in the device list shall be merged based on
    //  (1) same (non empty) hostname
    //  (2) same (non empty) IP v4
    //  (3) same (non empty) IP v6

    fn dedup_vec(devices: &mut Vec<DeviceInfo>) {
        let mut i = 0;
        while i < devices.len() {
            let mut j = i + 1;
            while j < devices.len() {
                // A shared primary address only means "same endpoint" when the address
                // itself names one host. Two hosts that both fell back to link-local,
                // or two records that both ended up holding a broadcast address, are
                // not the same device.
                let primary_ip_match = devices[i].ip_address == devices[j].ip_address
                    && Self::is_identity_bearing_ip(&devices[i].ip_address);

                // Records persisted before add_ipv4_entry started filtering may still
                // hold non-host addresses, so screen them here as well.
                let ipv4_overlap = devices[i]
                    .ip_addresses_v4
                    .iter()
                    .filter(|entry| is_identity_bearing_ipv4(&entry.address))
                    .any(|entry| {
                        devices[j]
                            .ip_addresses_v4
                            .iter()
                            .any(|e| e.address == entry.address)
                    });

                // IPv6 overlap - same IPv6 address means same device
                // (IPv6 address collision is essentially impossible)
                let ipv6_overlap = !devices[i].ip_addresses_v6.is_empty()
                    && !devices[j].ip_addresses_v6.is_empty()
                    && devices[i].ip_addresses_v6.iter().any(|entry_i| {
                        devices[j]
                            .ip_addresses_v6
                            .iter()
                            .any(|entry_j| entry_i.address == entry_j.address)
                    });

                let hostname_match = !devices[i].hostname.is_empty()
                    && !devices[j].hostname.is_empty()
                    && devices[i].hostname == devices[j].hostname;

                // MAC address match - same MAC means same physical device
                // (MAC collision is essentially impossible)
                let mac_match = devices[i].get_mac_address().is_some()
                    && devices[j].get_mac_address().is_some()
                    && devices[i].get_mac_address() == devices[j].get_mac_address();

                // MAC overlap in historical lists - indicates same device over time
                let mac_overlap = devices[i].mac_addresses.iter().any(|e1| {
                    devices[j]
                        .mac_addresses
                        .iter()
                        .any(|e2| e1.address == e2.address)
                });

                let has_conflicts = Self::has_conflicting_characteristics(&devices[i], &devices[j]);

                // IPv4 overlap alone is WEAK evidence - IPs are frequently reused by DHCP
                // Require additional confirmation: MAC or hostname match
                let ipv4_confirmed = ipv4_overlap && (mac_match || mac_overlap || hostname_match);

                // Merge criteria:
                // - Primary IP match: same endpoint in current context
                // - IPv4 list overlap: only if confirmed by MAC or hostname (IPs are reused)
                // - IPv6 overlap: strong evidence (collision essentially impossible)
                // - MAC match: strong evidence (physical device identifier)
                // - Hostname match: weak evidence, requires specific hostname
                let is_duplicate =
                    if primary_ip_match || ipv4_confirmed || ipv6_overlap || mac_match {
                        if has_conflicts {
                            warn!(
                            "Conflicting device characteristics - aborting merge of {:?} and {:?}",
                            devices[i], devices[j]
                        );
                            false
                        } else {
                            true
                        }
                    } else if hostname_match {
                        Self::is_safe_hostname_merge(&devices[i], &devices[j])
                    } else {
                        false
                    };

                if is_duplicate {
                    let duplicate = devices.remove(j);
                    let device = &mut devices[i];
                    DeviceInfo::merge(device, &duplicate);
                } else {
                    j += 1;
                }
            }
            i += 1;
        }
    }

    // Combine the devices based on the same criteria as above
    pub fn merge_vec(devices: &mut Vec<DeviceInfo>, new_devices: &Vec<DeviceInfo>) {
        // Always deduplicate the devices before merging
        DeviceInfo::dedup_vec(devices);
        let mut new_devices = new_devices.clone();
        DeviceInfo::dedup_vec(&mut new_devices);

        debug!(
            "Merging {} devices into {} devices",
            new_devices.len(),
            devices.len()
        );

        for new_device in new_devices {
            let mut found = false;

            for device in devices.iter_mut() {
                // Primary IP address match, only when the address names one host
                // (see the equivalent guard in dedup_vec).
                let primary_ip_match = new_device.ip_address == device.ip_address
                    && Self::is_identity_bearing_ip(&new_device.ip_address);

                // Overlapping IP addresses in the lists
                let ipv4_overlap = new_device
                    .ip_addresses_v4
                    .iter()
                    .filter(|entry| is_identity_bearing_ipv4(&entry.address))
                    .any(|entry| {
                        device
                            .ip_addresses_v4
                            .iter()
                            .any(|e| e.address == entry.address)
                    });

                // IPv6 overlap - same IPv6 address means same device
                // (IPv6 address collision is essentially impossible)
                let ipv6_overlap = !new_device.ip_addresses_v6.is_empty()
                    && !device.ip_addresses_v6.is_empty()
                    && new_device.ip_addresses_v6.iter().any(|new_entry| {
                        device
                            .ip_addresses_v6
                            .iter()
                            .any(|existing_entry| new_entry.address == existing_entry.address)
                    });

                // Hostname matching (for multi-interface devices)
                let hostname_match = !new_device.hostname.is_empty()
                    && !device.hostname.is_empty()
                    && device.hostname == new_device.hostname;

                // MAC address match - same MAC means same physical device
                // (MAC collision is essentially impossible)
                let mac_match = device.get_mac_address().is_some()
                    && new_device.get_mac_address().is_some()
                    && device.get_mac_address() == new_device.get_mac_address();

                // MAC overlap in historical lists - indicates same device over time
                let mac_overlap = device.mac_addresses.iter().any(|e1| {
                    new_device
                        .mac_addresses
                        .iter()
                        .any(|e2| e1.address == e2.address)
                });

                // Check for potential problematic merges
                let has_conflicting_characteristics =
                    Self::has_conflicting_characteristics(device, &new_device);

                // IPv4 overlap alone is WEAK evidence - IPs are frequently reused by DHCP
                // Require additional confirmation: MAC or hostname match
                let ipv4_confirmed = ipv4_overlap && (mac_match || mac_overlap || hostname_match);

                // Decide whether to merge:
                // - Primary IP match: same endpoint in current context
                // - IPv4 list overlap: only if confirmed by MAC or hostname (IPs are reused)
                // - IPv6 overlap: strong evidence (collision essentially impossible)
                // - MAC match: strong evidence (physical device identifier)
                // - Hostname match: weak evidence, requires specific hostname
                let should_merge =
                    if primary_ip_match || ipv4_confirmed || ipv6_overlap || mac_match {
                        // Strong evidence - merge unless there are major conflicts
                        !has_conflicting_characteristics
                    } else if hostname_match {
                        // Hostname match - be more careful
                        Self::is_safe_hostname_merge(device, &new_device)
                    } else {
                        false
                    };

                if should_merge {
                    debug!(
                        "[merge_vec] Merging devices: existing={:?} (MAC: {:?}), new={:?} (MAC: {:?}), reason: IP={}, hostname={}",
                        device.get_ip_address(),
                        device.get_mac_address(),
                        new_device.get_ip_address(),
                        new_device.get_mac_address(),
                        primary_ip_match || ipv4_overlap || ipv6_overlap,
                        hostname_match
                    );

                    // Merge the devices
                    DeviceInfo::merge(device, &new_device);
                    debug!(
                        "[merge_vec] After merge: {:?} last_seen: {:?} is_local: {:?} active: {:?}",
                        device.get_ip_address(),
                        device.last_seen,
                        device.is_local,
                        device.active
                    );
                    found = true;
                    break;
                }
            }

            // If no match was found, add the new device
            if !found {
                devices.push(new_device.clone());
                debug!("[merge_vec] New device added: {:?} last_seen: {:?} is_local: {:?} active: {:?}", new_device.get_ip_address(), new_device.last_seen, new_device.is_local, new_device.active);
            }
        }

        debug!("Total devices after merge: {}", devices.len());
    }

    // Check if two devices have characteristics that suggest they shouldn't be merged
    fn has_conflicting_characteristics(device1: &DeviceInfo, device2: &DeviceInfo) -> bool {
        let hostname_match = !device1.hostname.is_empty()
            && !device2.hostname.is_empty()
            && device1.hostname == device2.hostname;
        let safe_hostname_match = hostname_match && Self::is_specific_hostname(&device1.hostname);
        let vendor_known = |device: &DeviceInfo| {
            !device.device_vendor.is_empty() && device.device_vendor != "Unknown"
        };

        let vendor_conflict = vendor_known(device1)
            && vendor_known(device2)
            && device1.device_vendor != device2.device_vendor;

        let mac_conflict = if safe_hostname_match {
            // Safe hostname match - no MAC conflict even if different
            false
        } else {
            // A differing MAC is evidence of a distinct physical device whether or not
            // we managed to resolve a vendor for either side. Gating this on vendor
            // knowledge let unvendored records absorb unrelated hosts.
            Self::has_mac_conflict(device1, device2)
        };

        vendor_conflict || mac_conflict
    }

    /// Whether an address is evidence of one specific host.
    ///
    /// The IPv4 half is delegated to `ip::is_identity_bearing_ipv4`. For IPv6 only
    /// unspecified, loopback, and multicast are rejected. Link-local IPv6 is
    /// deliberately kept: unlike `169.254.0.0/16`, an `fe80::` address carries a
    /// 64-bit interface identifier that is either MAC-derived or random, so two
    /// records holding the same one really are the same interface.
    fn is_identity_bearing_ip(ip: &IpAddr) -> bool {
        match ip {
            IpAddr::V4(v4) => is_identity_bearing_ipv4(v4),
            IpAddr::V6(v6) => !v6.is_unspecified() && !v6.is_loopback() && !v6.is_multicast(),
        }
    }

    /// Every universally administered address this record has ever carried.
    ///
    /// These are the only addresses that pin a record to physical hardware: they are
    /// burned into the NIC and globally unique, so two records with disjoint
    /// non-empty sets cannot be the same device. Locally administered addresses are
    /// excluded because they are exactly the ones a device rotates, and group
    /// addresses because they identify no interface at all.
    ///
    /// The current primary is unioned in rather than assumed present: the history
    /// list is capped and keeps the most recently seen entries, so a primary that is
    /// stale relative to the rest can fall off it.
    fn universal_mac_identity_set(device: &DeviceInfo) -> HashSet<MacAddr6> {
        device
            .mac_addresses
            .iter()
            .map(|entry| entry.address)
            .chain(device.get_mac_address())
            .filter(|mac| mac.is_universal() && is_identity_bearing_mac(mac))
            .collect()
    }

    // Check if two devices have conflicting MAC addresses using timestamp-aware logic
    // Returns true if MACs suggest these are different devices
    fn has_mac_conflict(device1: &DeviceInfo, device2: &DeviceInfo) -> bool {
        match (device1.get_mac_address(), device2.get_mac_address()) {
            (Some(mac1), Some(mac2)) if mac1 != mac2 => {
                // Different primary MACs - check if they could be the same device.
                //
                // A universally administered MAC is burned into the NIC and is globally
                // unique, so two records holding disjoint sets of them hold distinct
                // NICs. Neither the historical-overlap escape (1) nor the rotation
                // escape (3) may fire in that case: both model MAC *rotation*, which
                // only a locally administered (randomized/virtual) MAC can do.
                //
                // The comparison spans each record's whole MAC history, not just its
                // current primary. Comparing primaries alone leaves a record whose
                // primary happens to be locally administered free to absorb a
                // universally administered one, because a single local address on
                // either side made rotation look possible and waved the guard through
                // -- even when the record already held hardware addresses that
                // contradict the merge. Once that happens the newly absorbed hardware
                // address can become the primary, so the next comparison is against a
                // MAC that arrived by the same bypass, and the record keeps growing.
                let uaa1 = Self::universal_mac_identity_set(device1);
                let uaa2 = Self::universal_mac_identity_set(device2);

                if !uaa1.is_empty() && !uaa2.is_empty() && uaa1.is_disjoint(&uaa2) {
                    debug!(
                        "MAC conflict: universally administered MAC sets are disjoint ({:?} vs {:?}), distinct NICs",
                        uaa1, uaa2
                    );
                    return true;
                }

                // 1. Check for MAC overlap in the historical lists
                // If any MAC appears in both devices, they're likely the same device at
                // different times. Group addresses are excluded: any number of
                // unrelated records can hold the same one, so treating it as shared
                // identity merges devices that have nothing in common.
                let mac_overlap = device1
                    .mac_addresses
                    .iter()
                    .filter(|entry| is_identity_bearing_mac(&entry.address))
                    .any(|entry1| {
                        device2
                            .mac_addresses
                            .iter()
                            .any(|entry2| entry1.address == entry2.address)
                    });

                if mac_overlap {
                    debug!(
                        "No MAC conflict: MACs overlap in historical lists (privacy extension or multi-interface)"
                    );
                    return false; // Not a conflict - same device with multiple MACs over time
                }

                // 2. Check if current MACs were seen very recently in both devices
                // If both MACs are fresh (< 1 hour old), it's a strong signal of different devices
                let now = Utc::now();
                const MAC_CONFLICT_FRESHNESS_THRESHOLD: i64 = 3600; // 1 hour in seconds

                let mac1_fresh = device1
                    .mac_addresses
                    .iter()
                    .find(|e| e.address == mac1)
                    .map(|e| (now - e.last_seen).num_seconds() < MAC_CONFLICT_FRESHNESS_THRESHOLD)
                    .unwrap_or(false);

                let mac2_fresh = device2
                    .mac_addresses
                    .iter()
                    .find(|e| e.address == mac2)
                    .map(|e| (now - e.last_seen).num_seconds() < MAC_CONFLICT_FRESHNESS_THRESHOLD)
                    .unwrap_or(false);

                if mac1_fresh && mac2_fresh {
                    debug!(
                        "MAC conflict: Both MACs ({} and {}) are fresh (< 1h old), likely different devices",
                        mac1, mac2
                    );
                    return true; // Conflict - both fresh MACs, different devices
                }

                // 3. Check if the MACs were seen at very different times (> 24 hours apart)
                // This could indicate privacy MAC rotation or device reuse
                let mac1_timestamp = device1
                    .mac_addresses
                    .iter()
                    .find(|e| e.address == mac1)
                    .map(|e| e.last_seen);

                let mac2_timestamp = device2
                    .mac_addresses
                    .iter()
                    .find(|e| e.address == mac2)
                    .map(|e| e.last_seen);

                if let (Some(t1), Some(t2)) = (mac1_timestamp, mac2_timestamp) {
                    let time_diff_hours = (t1 - t2).num_hours().abs();
                    const MAC_ROTATION_THRESHOLD_HOURS: i64 = 24;

                    if time_diff_hours > MAC_ROTATION_THRESHOLD_HOURS {
                        debug!(
                            "No MAC conflict: MACs seen {} hours apart, likely privacy rotation or device reuse",
                            time_diff_hours
                        );
                        return false; // Not a conflict - likely privacy rotation over time
                    }
                }

                // 4. Default: different MACs without overlap and seen around same time = conflict
                debug!("MAC conflict: Different MACs without overlap or strong temporal signal");
                true
            }
            _ => false, // Same MAC or one/both missing - no conflict
        }
    }

    // Check if a hostname-based merge is safe
    fn is_safe_hostname_merge(device1: &DeviceInfo, device2: &DeviceInfo) -> bool {
        let _ = device2;
        // Allow hostname merge if:
        // 1. the hostname is very specific (not a generic one)

        let specific_hostname = Self::is_specific_hostname(&device1.hostname);
        if specific_hostname {
            debug!(
                "Safe hostname merge: specific hostname ({})",
                device1.hostname
            );
            true
        } else {
            warn!(
                "Unsafe hostname merge: generic hostname ({}) - aborting merge of {:?} and {:?}",
                device1.hostname, device1, device2
            );
            false
        }
    }

    // Check if a hostname is specific enough to be a reliable identifier
    fn is_specific_hostname(hostname: &str) -> bool {
        let hostname_lower = hostname.to_lowercase();

        // Exact generic hostnames that shouldn't be trusted for merging
        let exact_generic_hostnames = [
            "localhost",
            "router",
            "gateway",
            "modem",
            "printer",
            "scanner",
            "camera",
            "device",
            "unknown",
            "android",
            "iphone",
            "ipad",
            "macbook",
            "imac",
            "windows",
            "linux",
            "ubuntu",
            "debian",
        ];

        // If it's exactly a generic hostname, it's not specific
        if exact_generic_hostnames
            .iter()
            .any(|&generic| hostname_lower == generic)
        {
            return false;
        }

        // If it has a domain suffix (.local, .lan, etc.) and is reasonably long, it's likely specific
        if hostname.contains('.') && hostname.len() > 8 {
            return true;
        }

        // If it's a long hostname without being exactly generic, it's probably specific
        hostname.len() > 10
    }

    pub fn merge(device: &mut DeviceInfo, new_device: &DeviceInfo) {
        // Validate key fields of the new device
        // Check if there is a valid IPv4 or IPv6 address
        if new_device.ip_address.is_unspecified() {
            warn!(
                "No valid IPv4 or IPv6 address found - aborting merge of {:?} and {:?}",
                device, new_device
            );
            return;
        }

        // Now we merge based on the hostname or IPv4 or IPv6 address(es)
        // At that stage the new_device.ip_address is guaranteed to be valid

        // Merge IP addresses with timestamps
        // Use each entry's last_seen timestamp directly - this is when that specific IP was seen
        // The entry timestamp is the authoritative source for when that IP address was discovered
        for entry in new_device.ip_addresses_v4.iter() {
            device.add_ipv4_entry(entry.address, entry.last_seen);
        }

        // Merge IPv6 addresses with their individual timestamps
        for entry in new_device.ip_addresses_v6.iter() {
            device.add_ipv6_entry(entry.address, entry.last_seen);
        }

        // Bound the merged lists. `add_ipv*_entry` only dedupes-by-address and
        // appends; the two ingest paths that call it
        // (`add_ip_addresses_with_timestamp`, mDNS discovery) follow up with
        // this call, but the MERGE path did not -- so a device merged on every
        // scan cycle grew without limit. On a macOS host, which rotates RFC 4941
        // privacy addresses, the self-device accumulated 675 IPv6 entries
        // (66 KB, oldest three weeks old) against a MAX_IPV6_ADDRESSES of 10.
        // Truncation keeps the most-recently-seen entries, so it runs BEFORE
        // `update_primary_ip_from_entries` and cannot change which address is
        // selected as primary.
        device.deduplicate_and_truncate_ips();

        // Update primary IP based on the most recently seen entry timestamps
        // IPv4 takes precedence over IPv6 (more stable), but we use entry timestamps
        // to determine which specific address to use
        device.update_primary_ip_from_entries();

        // Use the most recent non empty mac address
        if new_device.mac_address.is_some() {
            if new_device.last_seen > device.last_seen || device.mac_address.is_none() {
                device.mac_address = new_device.mac_address.clone();
            }
        }

        // Merge the MAC addresses with their timestamps
        for entry in new_device.mac_addresses.iter() {
            device.add_mac_entry(entry.address, entry.last_seen);
        }

        // Deduplicate and truncate
        device.deduplicate_and_truncate_macs();

        // Use the most recent non empty hostname
        if !new_device.hostname.is_empty() {
            if new_device.last_seen > device.last_seen || device.hostname.is_empty() {
                device.hostname.clone_from(&new_device.hostname);
            }
        }

        // Use the most recent non empty os name
        if !new_device.os_name.is_empty() {
            if new_device.last_seen > device.last_seen || device.os_name.is_empty() {
                device.os_name.clone_from(&new_device.os_name);
            }
        }

        if !new_device.os_version.is_empty() {
            if new_device.last_seen > device.last_seen || device.os_version.is_empty() {
                device.os_version.clone_from(&new_device.os_version);
            }
        }

        // Merge open ports (union only — local scans must call
        // `reconcile_open_ports_after_scan` first so closed ports can be pruned).
        if !new_device.open_ports.is_empty() {
            // We need to do it manually as the services or banners might be different as it can include timestamps
            for new_port in new_device.open_ports.iter() {
                let mut found = false;
                for existing_port in device.open_ports.iter_mut() {
                    if existing_port.port == new_port.port {
                        // Preserve the dismissed flag from the more recently modified device
                        // This ensures user choices (dismiss/undismiss) are preserved based on
                        // which device was last modified
                        let dismissed = if device.last_modified >= new_device.last_modified {
                            existing_port.dismissed
                        } else {
                            new_port.dismissed
                        };
                        // Use the latest info
                        *existing_port = new_port.clone();
                        // Restore the dismissed flag from the more recent source
                        existing_port.dismissed = dismissed;
                        found = true;
                        break;
                    }
                }
                // If no match was found, add the new port
                if !found {
                    device.open_ports.push(new_port.clone());
                }
            }

            // Sort the ports - Sorted Vec would be better but had trouble with the bridge once...
            device.open_ports.sort_by(|a, b| a.port.cmp(&b.port));
        }

        // Merge mDNS services
        // Use each entry's last_seen timestamp directly - this is when that specific service was seen
        // The entry timestamp is the authoritative source for when that service was discovered
        if !new_device.mdns_services.is_empty() {
            for entry in new_device.mdns_services.iter() {
                device.add_mdns_entry(entry.service.clone(), entry.last_seen);
            }
        }

        // Remove entries that are the suffix of another entry
        // For example, if we have _xxx._apple-mobdev2._tcp.local and _apple-mobdev2._tcp.local, we remove _apple-mobdev2._tcp.local
        let mut mdns_services_cleaned = Vec::new();
        for mdns_entry in device.mdns_services.iter() {
            let mut found = false;
            for mdns_entry2 in device.mdns_services.iter() {
                if mdns_entry.service != mdns_entry2.service
                    && mdns_entry2.service.ends_with(&mdns_entry.service)
                {
                    found = true;
                    break;
                }
            }
            if !found {
                mdns_services_cleaned.push(mdns_entry.clone());
            }
        }

        device.mdns_services = mdns_services_cleaned;
        // Keep only the most recently seen mDNS services (by timestamp)
        device.truncate_mdns_services();

        // Update the flags
        // Only local updates affect local active; community updates affect community_active
        if new_device.is_local {
            device.active = device.active || new_device.active;
        } else {
            device.community_active = device.community_active || new_device.active;
        }
        device.non_std_ports = device.non_std_ports || new_device.non_std_ports;
        device.added = device.added || new_device.added;
        device.activated = device.activated || new_device.activated;
        device.deactivated = device.deactivated || new_device.deactivated;
        device.no_icmp = device.no_icmp || new_device.no_icmp;
        // If either device is local, the result is local
        device.is_local = device.is_local || new_device.is_local;

        // Dynamic fields
        // Use the most recent if valid (not unknown)
        if new_device.device_type != "Unknown" {
            if new_device.last_seen > device.last_seen || device.device_type == "Unknown" {
                device.device_type.clone_from(&new_device.device_type);
            }
        }

        // Use the most recent non empty device vendor
        if !new_device.device_vendor.is_empty() {
            if new_device.last_seen > device.last_seen || device.device_vendor.is_empty() {
                device.device_vendor.clone_from(&new_device.device_vendor);
            }
        }

        // Use the most recent if valid (not unknown)
        if new_device.criticality != DeviceCriticality::Unknown {
            if new_device.last_seen > device.last_seen
                || device.criticality == DeviceCriticality::Unknown
            {
                device.criticality.clone_from(&new_device.criticality);
            }
        }

        // Update first_seen:
        //   * ignore placeholder epoch coming from the new device
        //   * adopt the new value if ours is still the epoch placeholder
        //   * otherwise keep the older (chronologically) timestamp
        let epoch = DateTime::<Utc>::from(std::time::UNIX_EPOCH);
        if new_device.first_seen > epoch {
            if device.first_seen <= epoch || new_device.first_seen < device.first_seen {
                device.first_seen = new_device.first_seen;
            }
        }

        // Update the last seen time only if the new device is local
        if new_device.is_local && new_device.last_seen > device.last_seen {
            debug!(
                "[merge] Updating last_seen for {:?} from {:?} to {:?} (is_local: {:?})",
                device.get_ip_address(),
                device.last_seen,
                new_device.last_seen,
                new_device.is_local
            );
            device.last_seen = new_device.last_seen;
        } else if !new_device.is_local
            && new_device.last_seen
                > device
                    .last_seen_community
                    .unwrap_or(DateTime::<Utc>::from(std::time::UNIX_EPOCH))
        {
            // For community updates, record into last_seen_community only
            debug!(
                "[merge] Updating last_seen_community for {:?} from {:?} to {:?}",
                device.get_ip_address(),
                device.last_seen_community,
                new_device.last_seen
            );
            device.last_seen_community = Some(new_device.last_seen);
        }

        // Handle origin information
        // If the new device is local, use its origin_ip
        if new_device.is_local && !new_device.origin_ip.is_empty() {
            device.origin_ip.clone_from(&new_device.origin_ip);
        } else if device.origin_ip.is_empty() && !new_device.origin_ip.is_empty() {
            // Otherwise preserve origin information - only set it if the target doesn't have it
            device.origin_ip.clone_from(&new_device.origin_ip);
        }

        // Also update origin_network with the same logic
        if new_device.is_local && !new_device.origin_network.is_empty() {
            device.origin_network.clone_from(&new_device.origin_network);
        } else if device.origin_network.is_empty() && !new_device.origin_network.is_empty() {
            // Otherwise preserve origin information - only set it if the target doesn't have it
            device.origin_network.clone_from(&new_device.origin_network);
        }

        // Port-scan evidence is monotonic: keep the newer stamp from either side.
        // A peer's record counts, because a peer that got a definite verdict for
        // this device did observe its ports even if we never could.
        if let Some(new_stamp) = new_device.last_port_scan {
            if device.last_port_scan.is_none_or(|cur| new_stamp > cur) {
                device.last_port_scan = Some(new_stamp);
            }
        }

        // Merge user properties based on the last modified date
        if new_device.last_modified > device.last_modified {
            device.custom_name.clone_from(&new_device.custom_name);
            device.deleted = new_device.deleted;
            device.last_modified = new_device.last_modified;
        }
    }

    /// Reconcile `open_ports` after a local port scan.
    ///
    /// Result:
    /// ```text
    /// open_ports = open_this_scan
    ///            ∪ { existing ports whose port ∉ definitely_closed }
    /// ```
    ///
    /// `definitely_closed` carries only the ports the target *actively refused*
    /// (TCP RST, i.e. `ECONNREFUSED`). A port that timed out, errored, or was
    /// never reached because the scan was cancelled or throttled is absent from
    /// that set and is therefore carried forward: silence is not evidence of
    /// closure, and treating it as such makes ports flap in and out on every
    /// scan of a filtered or rate-limited host.
    ///
    /// Retraction being evidence-driven leaves one gap by design: a host that
    /// silently drops every probe refuses nothing, so a cached list that is
    /// already wrong stays wrong. That case is the anomaly guard's job
    /// ([`Self::strip_anomalous_open_ports_with_limit`] applied to the
    /// reconciled record), not this function's.
    ///
    /// Per-port `dismissed` is preserved for survivors.
    ///
    /// Also stamps [`Self::last_port_scan`] when this scan produced at least one
    /// definite verdict -- an open port or a refusal. A pass where the target was
    /// silent on everything it was asked deliberately does *not* stamp: we learned
    /// nothing, and recording it as scanned would let criticality report `Low`
    /// ("minimal attack surface") for a host that is merely undetectable.
    pub fn reconcile_open_ports_after_scan(
        &mut self,
        open_this_scan: &[PortInfo],
        definitely_closed: &HashSet<u16>,
    ) {
        if !open_this_scan.is_empty() || !definitely_closed.is_empty() {
            self.last_port_scan = Some(Utc::now());
        }

        let previous_dismissed: HashMap<u16, bool> = self
            .open_ports
            .iter()
            .map(|p| (p.port, p.dismissed))
            .collect();

        let mut carried: Vec<PortInfo> = self
            .open_ports
            .iter()
            .filter(|p| !definitely_closed.contains(&p.port))
            .cloned()
            .collect();

        let mut next: Vec<PortInfo> = open_this_scan.to_vec();
        for port in next.iter_mut() {
            if let Some(dismissed) = previous_dismissed.get(&port.port) {
                port.dismissed = *dismissed;
            }
        }

        // A fresh open verdict supersedes the carried-forward entry for the same
        // port, so the service name and banner reflect this scan.
        let open_ports_set: HashSet<u16> = next.iter().map(|p| p.port).collect();
        carried.retain(|p| !open_ports_set.contains(&p.port));
        next.extend(carried);
        next.sort_by(|a, b| a.port.cmp(&b.port));
        self.open_ports = next;
    }

    /// Clear `open_ports` when the count exceeds `limit`.
    /// Returns true when ports were stripped.
    pub fn strip_anomalous_open_ports_with_limit(&mut self, limit: usize) -> bool {
        if self.open_ports.len() > limit {
            warn!(
                "Stripping anomalous open_ports ({} > {}) for {:?}",
                self.open_ports.len(),
                limit,
                self.get_ip_address()
            );
            self.open_ports.clear();
            self.non_std_ports = false;
            true
        } else {
            false
        }
    }

    /// Clear `open_ports` when the count exceeds the deep-scan ceiling
    /// [`MAX_REASONABLE_OPEN_PORTS_DEEP`].
    ///
    /// This is the community-boundary guard, used on import and share. It is
    /// deliberately the loosest ceiling any local scan can produce, so a device
    /// we store from a first-hand deep scan is never silently dropped when it
    /// crosses the boundary.
    pub fn strip_anomalous_open_ports(&mut self) -> bool {
        self.strip_anomalous_open_ports_with_limit(MAX_REASONABLE_OPEN_PORTS_DEEP)
    }

    pub fn clear(&mut self) {
        // Clear the device, only keep the main IP address, the first_seen timestamp and the last_seen timestamp
        let ip_address = self.ip_address.clone();
        let now = Utc::now();
        let ip_addresses_v4 = if let IpAddr::V4(ipv4) = ip_address {
            vec![IpAddressEntry {
                address: ipv4,
                last_seen: now,
            }]
        } else {
            vec![]
        };
        let ip_addresses_v6 = if let IpAddr::V6(ipv6) = ip_address {
            vec![IpAddressEntry {
                address: ipv6,
                last_seen: now,
            }]
        } else {
            vec![]
        };
        let first_seen = self.first_seen;
        let last_seen = self.last_seen;
        *self = DeviceInfo::new(None);
        self.ip_address = ip_address;
        self.ip_addresses_v4 = ip_addresses_v4;
        self.ip_addresses_v6 = ip_addresses_v6;
        self.first_seen = first_seen;
        self.last_seen = last_seen;
    }

    pub fn delete(&mut self) {
        // Clear the device
        self.clear();
        // Flag the device as deleted
        self.deleted = true;
        // Update the last modified to now
        self.last_modified = Utc::now();
    }

    pub fn undelete(&mut self) {
        // Flag the device as not deleted
        self.deleted = false;
        // Update the last modified to now
        self.last_modified = Utc::now();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{TimeZone, Utc};

    // Helper functions for tests
    fn ipv4_entry(addr: Ipv4Addr) -> IpAddressEntry<Ipv4Addr> {
        IpAddressEntry {
            address: addr,
            last_seen: Utc::now(),
        }
    }

    fn mdns_entry(service: &str) -> MdnsServiceEntry {
        MdnsServiceEntry {
            service: service.to_string(),
            last_seen: Utc::now(),
        }
    }

    fn mac_entry(addr: MacAddr6) -> MacAddressEntry {
        MacAddressEntry {
            address: addr,
            last_seen: Utc::now(),
        }
    }

    #[test]
    fn test_merge_deletion() {
        let mut device_original = DeviceInfo::new(Some(IpAddr::V4(Ipv4Addr::new(192, 168, 0, 10))));
        device_original.deleted = false;
        device_original.last_seen = Utc.with_ymd_and_hms(2023, 1, 1, 12, 0, 0).unwrap();
        device_original.last_modified = Utc.with_ymd_and_hms(2023, 1, 1, 12, 0, 0).unwrap();

        let mut device_deleting = device_original.clone();
        // Simulate a manual delete with a later last_modified
        device_deleting.deleted = true;
        device_deleting.last_modified =
            device_original.last_modified + chrono::Duration::seconds(10);

        // Merge: the second device is "fresher" and marks it deleted
        DeviceInfo::merge(&mut device_original, &device_deleting);

        assert_eq!(
            device_original.deleted, true,
            "Device should have been marked as deleted."
        );
        assert_eq!(
            device_original.last_modified, device_deleting.last_modified,
            "last_modified should match the fresher device's timestamp."
        );
    }

    #[test]
    fn test_merge_undelete() {
        let mut device_deleted = DeviceInfo::new(Some(IpAddr::V4(Ipv4Addr::new(192, 168, 0, 20))));
        device_deleted.deleted = true;
        device_deleted.last_seen = Utc.with_ymd_and_hms(2023, 1, 1, 12, 5, 0).unwrap();
        device_deleted.last_modified = Utc.with_ymd_and_hms(2023, 1, 1, 12, 5, 0).unwrap();

        // "Rescan" or updated device info that says it's not deleted
        let mut device_undeleting = device_deleted.clone();
        device_undeleting.deleted = false;
        device_undeleting.last_modified =
            device_deleted.last_modified + chrono::Duration::seconds(10);

        DeviceInfo::merge(&mut device_deleted, &device_undeleting);

        assert_eq!(
            device_deleted.deleted, false,
            "Device should have been 'undeleted' when merging from the fresher source."
        );
        assert_eq!(
            device_deleted.last_modified, device_undeleting.last_modified,
            "last_modified should match the fresher device's timestamp."
        );
    }

    #[test]
    fn test_merge_no_change_if_older() {
        // If the new device data is older, it should be ignored
        let mut device_current = DeviceInfo::new(Some(IpAddr::V4(Ipv4Addr::new(192, 168, 0, 30))));
        device_current.deleted = false;
        device_current.last_seen = Utc.with_ymd_and_hms(2023, 5, 1, 13, 0, 0).unwrap();
        device_current.last_modified = Utc.with_ymd_and_hms(2023, 5, 1, 13, 0, 0).unwrap();

        let mut device_older = device_current.clone();
        device_older.deleted = true;
        // artificially roll back the last_modified to be older
        device_older.last_modified = device_current.last_modified - chrono::Duration::seconds(30);

        // Merge the older device
        DeviceInfo::merge(&mut device_current, &device_older);

        // The older data should NOT override the current device
        assert_eq!(
            device_current.deleted, false,
            "The device should remain not deleted because incoming data was older."
        );
    }

    #[test]
    fn test_merge_vec_multiple() {
        // Test merging multiple new devices, some overlap, some new
        let mut existing_list = vec![
            {
                let mut d = DeviceInfo::new(Some(IpAddr::V4(Ipv4Addr::new(192, 168, 0, 10))));
                d.last_modified = Utc.with_ymd_and_hms(2023, 1, 10, 10, 0, 0).unwrap();
                d.deleted = false;
                d
            },
            {
                let mut d = DeviceInfo::new(Some(IpAddr::V4(Ipv4Addr::new(192, 168, 0, 11))));
                d.last_modified = Utc.with_ymd_and_hms(2023, 1, 10, 10, 5, 0).unwrap();
                d.deleted = true;
                d
            },
        ];

        let new_list = vec![
            // Device has a fresher timestamp and is marked as deleted
            {
                let mut d = DeviceInfo::new(Some(IpAddr::V4(Ipv4Addr::new(192, 168, 0, 10))));
                d.set_ip_address(IpAddr::V4(Ipv4Addr::new(192, 168, 0, 10)), vec![], vec![]);
                d.last_modified = Utc.with_ymd_and_hms(2023, 1, 10, 10, 15, 0).unwrap();
                d.deleted = true;
                d
            },
            // Brand new device
            {
                let mut d = DeviceInfo::new(Some(IpAddr::V4(Ipv4Addr::new(192, 168, 0, 12))));
                d.last_modified = Utc.with_ymd_and_hms(2023, 2, 10, 9, 0, 0).unwrap();
                d.deleted = false;
                d
            },
            // Older info for .11
            {
                let mut d = DeviceInfo::new(Some(IpAddr::V4(Ipv4Addr::new(192, 168, 0, 11))));
                d.set_ip_address(IpAddr::V4(Ipv4Addr::new(192, 168, 0, 11)), vec![], vec![]);
                d.last_modified = Utc.with_ymd_and_hms(2023, 1, 10, 10, 0, 0).unwrap(); // older
                d.deleted = false; // says undeleted, but older
                d
            },
        ];

        DeviceInfo::merge_vec(&mut existing_list, &new_list);

        // After merging, let's check the results
        // 1) 192.168.0.10 should now be deleted
        let device_10 = existing_list
            .iter()
            .find(|d| d.get_ip_address() == IpAddr::V4(Ipv4Addr::new(192, 168, 0, 10)))
            .unwrap();
        assert!(
            device_10.deleted,
            "192.168.0.10 should have been marked deleted from the fresher 'new_list' entry."
        );

        // 2) 192.168.0.12 should have been added
        let device_12 = existing_list
            .iter()
            .find(|d| d.get_ip_address() == IpAddr::V4(Ipv4Addr::new(192, 168, 0, 12)));
        assert!(
            device_12.is_some(),
            "192.168.0.12 should have been newly added."
        );

        // 3) 192.168.0.11 should remain deleted, because the new data was older
        let device_11 = existing_list
            .iter()
            .find(|d| d.get_ip_address() == IpAddr::V4(Ipv4Addr::new(192, 168, 0, 11)))
            .unwrap();
        assert!(
            device_11.deleted,
            "192.168.0.11 should remain deleted because incoming data was older."
        );
    }

    #[test]
    fn test_merge_ipv6() {
        // Check that merges also occur when IPv6 matches
        let mut device1 = DeviceInfo::new(Some(IpAddr::V6(Ipv6Addr::LOCALHOST)));
        device1.hostname = "device1".to_string();
        device1.last_seen = Utc.with_ymd_and_hms(2023, 6, 1, 8, 0, 0).unwrap();
        device1.origin_ip = "127.0.0.1".to_string();
        device1.origin_network = "local-network".to_string();

        let mut device2 = DeviceInfo::new(Some(IpAddr::V6(Ipv6Addr::LOCALHOST)));
        device2.hostname = "device1-new".to_string(); // different hostname
        device2.last_seen = Utc.with_ymd_and_hms(2023, 6, 1, 9, 0, 0).unwrap();
        device2.origin_ip = "127.0.0.1".to_string();
        device2.origin_network = "local-network".to_string();
        device2.is_local = true; // Mark as local for test to pass

        let mut devices = vec![device1.clone()];
        DeviceInfo::merge_vec(&mut devices, &vec![device2.clone()]);
        assert_eq!(
            devices.len(),
            1,
            "They should merge since they share the same IPv6 address."
        );

        // device1 was older, so we expect device2's info to override fields as needed
        let merged = &devices[0];
        assert_eq!(
            merged.hostname, "device1-new",
            "Hostname from device2 should be used since device2 is newer and they have the same origin."
        );
        assert_eq!(
            merged.get_ip_address(),
            IpAddr::V6(Ipv6Addr::LOCALHOST),
            "IPv6 is still localhost."
        );
        assert_eq!(
            merged.last_seen, device2.last_seen,
            "Since device2 was fresher, last_seen should be updated."
        );
    }

    #[test]
    fn test_merge_first_seen_older_valid() {
        let mut device_current = DeviceInfo::new(Some(IpAddr::V4(Ipv4Addr::new(10, 1, 1, 1))));
        // Current device was first seen at 2023-05-01 13:00:00
        device_current.first_seen = Utc.with_ymd_and_hms(2023, 5, 1, 13, 0, 0).unwrap();

        let mut device_new = device_current.clone();
        // The new device has an older (earlier) first_seen of 2023-05-01 12:00:00
        device_new.first_seen = Utc.with_ymd_and_hms(2023, 5, 1, 12, 0, 0).unwrap();

        // Merge them
        DeviceInfo::merge(&mut device_current, &device_new);

        // We expect the device_current.first_seen to be the older date (12:00:00).
        assert_eq!(
            device_current.first_seen,
            Utc.with_ymd_and_hms(2023, 5, 1, 12, 0, 0).unwrap(),
            "The existing device's first_seen should take the older timestamp from new_device if it is valid."
        );
    }

    #[test]
    fn test_merge_first_seen_newer_does_not_override() {
        let mut device_current = DeviceInfo::new(Some(IpAddr::V4(Ipv4Addr::new(10, 1, 1, 2))));
        // Current device was first seen at 2023-05-01 10:00:00
        device_current.first_seen = Utc.with_ymd_and_hms(2023, 5, 1, 10, 0, 0).unwrap();

        let mut device_new = device_current.clone();
        // The new device has a later first_seen (2023-05-01 11:00:00),
        // but we do NOT want to override with a "newer" first_seen.
        // Because the code sets first_seen to the older of the two.
        device_new.first_seen = Utc.with_ymd_and_hms(2023, 5, 1, 11, 0, 0).unwrap();

        // Merge them
        DeviceInfo::merge(&mut device_current, &device_new);

        // Expect that we still have the same older first_seen (10:00:00).
        assert_eq!(
            device_current.first_seen,
            Utc.with_ymd_and_hms(2023, 5, 1, 10, 0, 0).unwrap(),
            "We should keep the older existing first_seen when merging."
        );
    }

    #[test]
    fn test_merge_first_seen_ignore_default_epoch() {
        let mut device_current = DeviceInfo::new(Some(IpAddr::V4(Ipv4Addr::new(10, 1, 1, 3))));
        // Current device was first seen at 2023-05-01 10:30:00
        device_current.first_seen = Utc.with_ymd_and_hms(2023, 5, 1, 10, 30, 0).unwrap();

        let mut device_new = device_current.clone();
        // The new device has the default epoch (1970-01-01) as first_seen
        device_new.first_seen = DateTime::<Utc>::from(std::time::UNIX_EPOCH);

        // Merge them
        DeviceInfo::merge(&mut device_current, &device_new);

        // The existing device's first_seen is valid, so it should NOT be overridden by epoch.
        assert_eq!(
            device_current.first_seen,
            Utc.with_ymd_and_hms(2023, 5, 1, 10, 30, 0).unwrap(),
            "We should ignore default (UNIX epoch) first_seen from the new device."
        );
    }

    #[test]
    fn test_merge_first_seen_replaces_epoch_placeholder() {
        let mut device_current = DeviceInfo::new(Some(IpAddr::V4(Ipv4Addr::new(10, 1, 1, 4))));
        // Simulate placeholder
        device_current.first_seen = DateTime::<Utc>::from(std::time::UNIX_EPOCH);

        let mut community_device = device_current.clone();
        community_device.first_seen = Utc.with_ymd_and_hms(2023, 5, 1, 11, 45, 0).unwrap();

        DeviceInfo::merge(&mut device_current, &community_device);

        assert_eq!(
            device_current.first_seen, community_device.first_seen,
            "When the target still has the epoch placeholder, a valid incoming timestamp should replace it."
        );
    }

    #[test]
    fn test_merge_last_seen_newer_overrides() {
        // If the new device has a more recent last_seen and is local, it should override the existing device
        let mut device_current = DeviceInfo::new(Some(IpAddr::V4(Ipv4Addr::new(192, 168, 10, 1))));
        device_current.last_seen = Utc.with_ymd_and_hms(2023, 5, 1, 13, 0, 0).unwrap();
        device_current.origin_ip = "192.168.1.100".to_string();
        device_current.origin_network = "test-network".to_string();

        let mut device_new = device_current.clone();
        // Give the new device a more recent last_seen
        device_new.last_seen = Utc.with_ymd_and_hms(2023, 5, 1, 14, 0, 0).unwrap();
        // Make the device local to allow updating last_seen
        device_new.is_local = true;
        // Keep the same origin info
        device_new.origin_ip = "192.168.1.100".to_string();
        device_new.origin_network = "test-network".to_string();

        DeviceInfo::merge(&mut device_current, &device_new);

        // The device_current should be updated to the newer last_seen
        assert_eq!(
            device_current.last_seen,
            Utc.with_ymd_and_hms(2023, 5, 1, 14, 0, 0).unwrap(),
            "A more recent last_seen from a local device should override the existing device's last_seen"
        );
    }

    #[test]
    fn test_merge_last_seen_older_no_update() {
        // If the new device has an older last_seen, we do not change the existing device
        let mut device_current = DeviceInfo::new(Some(IpAddr::V4(Ipv4Addr::new(192, 168, 10, 2))));
        device_current.last_seen = Utc.with_ymd_and_hms(2023, 5, 1, 13, 30, 0).unwrap();

        let mut device_older = device_current.clone();
        // Make the new device's last_seen older than the current
        device_older.last_seen = Utc.with_ymd_and_hms(2023, 5, 1, 12, 30, 0).unwrap();

        DeviceInfo::merge(&mut device_current, &device_older);

        // The device_current's last_seen should not be updated
        assert_eq!(
            device_current.last_seen,
            Utc.with_ymd_and_hms(2023, 5, 1, 13, 30, 0).unwrap(),
            "An older last_seen should NOT override the existing device's last_seen"
        );
    }

    // Test that the active state is not overridden by the new device with diferent origin
    #[test]
    fn test_merge_active_state() {
        let mut device_current = DeviceInfo::new(Some(IpAddr::V4(Ipv4Addr::new(192, 168, 10, 3))));
        device_current.active = true;

        let mut device_new = device_current.clone();
        device_new.active = false;
        device_new.origin_ip = "192.168.10.4".to_string();

        DeviceInfo::merge(&mut device_current, &device_new);

        assert_eq!(
            device_current.active, true,
            "Active state should not be overridden by the new device"
        );
    }

    #[test]
    fn test_merge_cross_origin_devices() {
        // Test that devices from different origins can be merged properly
        // after removing the origin IP restriction
        use chrono::{TimeZone, Utc};
        use std::net::{IpAddr, Ipv4Addr};

        // Create a device representing a local detection
        let mut local_device = DeviceInfo::new(Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100))));
        local_device.hostname = "test-device".to_string();
        local_device.origin_ip = "192.168.1.1".to_string();
        local_device.origin_network = "home-network".to_string();
        local_device.last_seen = Utc.with_ymd_and_hms(2023, 1, 1, 12, 0, 0).unwrap();

        // Create a device representing a community detection
        let mut community_device =
            DeviceInfo::new(Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100))));
        community_device.hostname = "test-device".to_string();
        community_device.os_name = "Community OS".to_string(); // Additional info from community
        community_device.device_vendor = "Community Vendor".to_string();
        community_device.origin_ip = "10.0.0.1".to_string();
        community_device.origin_network = "friend-network".to_string();
        community_device.last_seen = Utc.with_ymd_and_hms(2023, 1, 1, 13, 0, 0).unwrap();
        community_device.is_local = false;

        // Merge the community device into the local device
        DeviceInfo::merge(&mut local_device, &community_device);

        // Verify that the community device updated the local device's metadata
        assert_eq!(local_device.os_name, "Community OS");
        assert_eq!(local_device.device_vendor, "Community Vendor");

        // The last_seen time should NOT update since community device isn't local
        assert_eq!(
            local_device.last_seen,
            Utc.with_ymd_and_hms(2023, 1, 1, 12, 0, 0).unwrap()
        );

        // Verify origin info remains unchanged
        assert_eq!(local_device.origin_ip, "192.168.1.1");
        assert_eq!(local_device.origin_network, "home-network");
    }

    #[test]
    fn test_merge_older_community_device() {
        // Test that older community devices don't update newer local devices
        use chrono::{TimeZone, Utc};
        use std::net::{IpAddr, Ipv4Addr};

        // Create a device representing a local detection with newer timestamp
        let mut local_device = DeviceInfo::new(Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100))));
        local_device.hostname = "test-device".to_string();
        local_device.os_name = "Local OS".to_string();
        local_device.origin_ip = "192.168.1.1".to_string();
        local_device.origin_network = "home-network".to_string();
        local_device.last_seen = Utc.with_ymd_and_hms(2023, 1, 1, 14, 0, 0).unwrap();

        // Create a device representing an older community detection
        let mut community_device =
            DeviceInfo::new(Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100))));
        community_device.hostname = "test-device".to_string();
        community_device.os_name = "Community OS".to_string();
        community_device.origin_ip = "10.0.0.1".to_string();
        community_device.origin_network = "friend-network".to_string();
        community_device.last_seen = Utc.with_ymd_and_hms(2023, 1, 1, 12, 0, 0).unwrap();

        // Merge the community device into the local device
        DeviceInfo::merge(&mut local_device, &community_device);

        // Verify that the community device did NOT update the local device
        assert_eq!(local_device.os_name, "Local OS");
        assert_eq!(
            local_device.last_seen,
            Utc.with_ymd_and_hms(2023, 1, 1, 14, 0, 0).unwrap()
        );
    }

    #[test]
    fn test_merge_open_ports_from_community() {
        // Test that open ports are merged correctly from community devices
        use chrono::{TimeZone, Utc};
        use std::net::{IpAddr, Ipv4Addr};

        // Create a device representing a local detection
        let mut local_device = DeviceInfo::new(Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100))));
        local_device.hostname = "test-device".to_string();
        local_device.origin_ip = "192.168.1.1".to_string();
        local_device.origin_network = "home-network".to_string();
        local_device.last_seen = Utc.with_ymd_and_hms(2023, 1, 1, 12, 0, 0).unwrap();

        // Add some open ports to the local device
        local_device.open_ports.push(PortInfo {
            port: 80,
            protocol: "tcp".to_string(),
            service: "http".to_string(),
            banner: "".to_string(),
            dismissed: false,
        });

        // Create a device representing a community detection with additional ports
        let mut community_device =
            DeviceInfo::new(Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100))));
        community_device.hostname = "test-device".to_string();
        community_device.origin_ip = "10.0.0.1".to_string();
        community_device.origin_network = "friend-network".to_string();
        community_device.last_seen = Utc.with_ymd_and_hms(2023, 1, 1, 13, 0, 0).unwrap();
        community_device.is_local = false;

        // Add different open ports to the community device
        community_device.open_ports.push(PortInfo {
            port: 443,
            protocol: "tcp".to_string(),
            service: "https".to_string(),
            banner: "".to_string(),
            dismissed: false,
        });

        // Merge the community device into the local device
        DeviceInfo::merge(&mut local_device, &community_device);

        // Verify that both ports are now in the local device
        assert_eq!(local_device.open_ports.len(), 2);

        // Sort by port number for consistent testing
        local_device.open_ports.sort_by(|a, b| a.port.cmp(&b.port));

        assert_eq!(local_device.open_ports[0].port, 80);
        assert_eq!(local_device.open_ports[0].service, "http");
        assert_eq!(local_device.open_ports[1].port, 443);
        assert_eq!(local_device.open_ports[1].service, "https");

        // Verify timestamp NOT updated since community device isn't local
        assert_eq!(
            local_device.last_seen,
            Utc.with_ymd_and_hms(2023, 1, 1, 12, 0, 0).unwrap()
        );
    }

    #[test]
    fn test_merge_preserves_dismissed_ports() {
        // Test that a user-dismissed port stays dismissed after fresh scan data arrives
        // The existing device has a newer last_modified (user dismissed after scan)
        use chrono::{TimeZone, Utc};
        use std::net::{IpAddr, Ipv4Addr};

        let mut existing_device =
            DeviceInfo::new(Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 200))));
        existing_device.last_seen = Utc.with_ymd_and_hms(2023, 1, 1, 12, 0, 0).unwrap();
        // User dismissed the port at 12:30, so last_modified is newer
        existing_device.last_modified = Utc.with_ymd_and_hms(2023, 1, 1, 12, 30, 0).unwrap();
        existing_device.is_local = true;
        existing_device.open_ports.push(PortInfo {
            port: 8443,
            protocol: "tcp".to_string(),
            service: "custom-admin".to_string(),
            banner: "old-banner".to_string(),
            dismissed: true,
        });

        // Fresh scan result for the same port with new metadata (dismissed flag false by default)
        let mut refreshed_device =
            DeviceInfo::new(Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 200))));
        refreshed_device.last_seen = Utc.with_ymd_and_hms(2023, 1, 1, 12, 15, 0).unwrap();
        // Scan data has older last_modified than user's dismissal
        refreshed_device.last_modified = Utc.with_ymd_and_hms(2023, 1, 1, 12, 15, 0).unwrap();
        refreshed_device.is_local = true;
        refreshed_device.open_ports.push(PortInfo {
            port: 8443,
            protocol: "tcp".to_string(),
            service: "https-alt".to_string(),
            banner: "new-banner".to_string(),
            dismissed: false,
        });

        DeviceInfo::merge(&mut existing_device, &refreshed_device);

        let merged_port = existing_device
            .open_ports
            .iter()
            .find(|p| p.port == 8443)
            .expect("Port 8443 should still exist after merge");

        // Metadata should be refreshed from the latest scan
        assert_eq!(merged_port.service, "https-alt");
        assert_eq!(merged_port.banner, "new-banner");
        // User dismissal must be preserved (existing device was modified more recently)
        assert!(
            merged_port.dismissed,
            "Dismissed flag should not be cleared by older scan data"
        );
    }

    #[test]
    fn test_merge_preserves_undismissed_ports() {
        // Test that a user-undismissed port stays undismissed after merge with old data
        // This tests the scenario where:
        // 1. User dismisses a port
        // 2. Background task clones devices (with dismissed=true)
        // 3. User undismisses the port (updates last_modified)
        // 4. Merge happens with old clone data
        // 5. Port should remain undismissed (user's latest choice based on last_modified)
        use chrono::{TimeZone, Utc};
        use std::net::{IpAddr, Ipv4Addr};

        // Existing device where user has UNDISMISSED the port
        let mut existing_device =
            DeviceInfo::new(Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 200))));
        existing_device.last_seen = Utc.with_ymd_and_hms(2023, 1, 1, 12, 15, 0).unwrap();
        // User undismissed at 12:30, so last_modified is newer than old data
        existing_device.last_modified = Utc.with_ymd_and_hms(2023, 1, 1, 12, 30, 0).unwrap();
        existing_device.is_local = true;
        existing_device.open_ports.push(PortInfo {
            port: 8443,
            protocol: "tcp".to_string(),
            service: "https-alt".to_string(),
            banner: "new-banner".to_string(),
            dismissed: false, // User explicitly undismissed this port
        });

        // Old data (e.g., from a background task clone) where the port was still dismissed
        let mut old_data_device =
            DeviceInfo::new(Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 200))));
        old_data_device.last_seen = Utc.with_ymd_and_hms(2023, 1, 1, 12, 0, 0).unwrap();
        // Old clone has earlier last_modified
        old_data_device.last_modified = Utc.with_ymd_and_hms(2023, 1, 1, 12, 0, 0).unwrap();
        old_data_device.is_local = true;
        old_data_device.open_ports.push(PortInfo {
            port: 8443,
            protocol: "tcp".to_string(),
            service: "custom-admin".to_string(),
            banner: "old-banner".to_string(),
            dismissed: true, // Old state where port was dismissed
        });

        DeviceInfo::merge(&mut existing_device, &old_data_device);

        let merged_port = existing_device
            .open_ports
            .iter()
            .find(|p| p.port == 8443)
            .expect("Port 8443 should still exist after merge");

        // User's undismissed choice must be preserved (existing device has newer last_modified)
        assert!(
            !merged_port.dismissed,
            "Undismissed flag should not be overwritten by older data (based on last_modified)"
        );
    }

    #[test]
    fn test_merge_vec_preserves_user_customizations() {
        // Test that merge_vec preserves user customizations when merging community devices
        use chrono::{TimeZone, Utc};
        use std::net::{IpAddr, Ipv4Addr};

        // Create a local device with user customizations
        let mut local_device = DeviceInfo::new(Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100))));
        local_device.hostname = "test-device".to_string();
        local_device.custom_name = "My Custom Device".to_string();
        local_device.origin_ip = "192.168.1.1".to_string();
        local_device.origin_network = "home-network".to_string();
        local_device.last_seen = Utc.with_ymd_and_hms(2023, 1, 1, 12, 0, 0).unwrap();

        // Create a vector of local devices
        let mut local_devices = vec![local_device];

        // Create a community device with newer information
        let mut community_device =
            DeviceInfo::new(Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100))));
        community_device.hostname = "community-name-for-device".to_string();
        community_device.origin_ip = "10.0.0.1".to_string();
        community_device.origin_network = "friend-network".to_string();
        community_device.last_seen = Utc.with_ymd_and_hms(2023, 1, 1, 13, 0, 0).unwrap();
        community_device.is_local = false;

        // Add some new ports
        community_device.open_ports.push(PortInfo {
            port: 8080,
            protocol: "tcp".to_string(),
            service: "http-alt".to_string(),
            banner: "".to_string(),
            dismissed: false,
        });

        // Create a vector of community devices
        let community_devices = vec![community_device];

        // Merge the community devices into the local devices
        DeviceInfo::merge_vec(&mut local_devices, &community_devices);

        // Verify that user customizations are preserved
        assert_eq!(local_devices[0].custom_name, "My Custom Device");

        // Verify hostname from community device was merged
        assert_eq!(local_devices[0].hostname, "community-name-for-device");

        // Verify timestamp is NOT updated since community device isn't local
        assert_eq!(
            local_devices[0].last_seen,
            Utc.with_ymd_and_hms(2023, 1, 1, 12, 0, 0).unwrap()
        );
    }

    #[test]
    fn test_merge_multiple_community_devices() {
        // Test merging multiple community devices with a local device
        use chrono::{TimeZone, Utc};
        use std::net::{IpAddr, Ipv4Addr};

        // Create a local device
        let mut local_device = DeviceInfo::new(Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100))));
        local_device.hostname = "test-device".to_string();
        local_device.origin_ip = "192.168.1.1".to_string();
        local_device.origin_network = "home-network".to_string();
        local_device.last_seen = Utc.with_ymd_and_hms(2023, 1, 1, 12, 0, 0).unwrap();

        // Add a local device to the vector
        let mut local_devices = vec![local_device];

        // Create a community device #1 with OS info
        let mut community_device1 =
            DeviceInfo::new(Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100))));
        community_device1.hostname = "test-device".to_string();
        community_device1.os_name = "Community OS".to_string();
        community_device1.origin_ip = "10.0.0.1".to_string();
        community_device1.origin_network = "friend-network-1".to_string();
        community_device1.last_seen = Utc.with_ymd_and_hms(2023, 1, 1, 13, 0, 0).unwrap();
        community_device1.is_local = false;

        // Create a community device #2 with vendor info and a later timestamp
        let mut community_device2 =
            DeviceInfo::new(Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100))));
        community_device2.hostname = "test-device".to_string();
        community_device2.device_vendor = "Community Vendor".to_string();
        community_device2.origin_ip = "10.0.0.2".to_string();
        community_device2.origin_network = "friend-network-2".to_string();
        community_device2.last_seen = Utc.with_ymd_and_hms(2023, 1, 1, 14, 0, 0).unwrap();
        community_device2.is_local = false;

        // Create a vector of community devices
        let community_devices = vec![community_device1, community_device2];

        // Merge the community devices into the local devices
        DeviceInfo::merge_vec(&mut local_devices, &community_devices);

        // Verify that information from both community devices was merged
        assert_eq!(local_devices[0].os_name, "Community OS");
        assert_eq!(local_devices[0].device_vendor, "Community Vendor");

        // Verify the timestamp is NOT updated since community devices aren't local
        assert_eq!(
            local_devices[0].last_seen,
            Utc.with_ymd_and_hms(2023, 1, 1, 12, 0, 0).unwrap()
        );

        // Verify origin info remains unchanged
        assert_eq!(local_devices[0].origin_ip, "192.168.1.1");
        assert_eq!(local_devices[0].origin_network, "home-network");
    }

    #[test]
    fn test_last_seen_during_scanning_and_mdns() {
        // Test that last_seen updates correctly during various detection methods
        use chrono::{TimeZone, Utc};
        use std::net::{IpAddr, Ipv4Addr};

        // Step 1: Initial discovery via scanning
        let mut device = DeviceInfo::new(Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100))));
        device.hostname = "test-device".to_string();
        device.origin_ip = "192.168.1.1".to_string();
        device.origin_network = "home-network".to_string();
        // Override the default timestamp for testing
        device.last_seen = Utc.with_ymd_and_hms(2023, 1, 1, 12, 0, 0).unwrap();
        device.first_seen = Utc.with_ymd_and_hms(2023, 1, 1, 12, 0, 0).unwrap();

        // Add a port from scanning
        device.open_ports.push(PortInfo {
            port: 80,
            protocol: "tcp".to_string(),
            service: "http".to_string(),
            banner: "".to_string(),
            dismissed: false,
        });

        // Step 2: Simulate mDNS discovery (happens after initial scan)
        // In FlodbaddFactory::populate_mdns, a new device is created and merged
        let mut mdns_device = DeviceInfo::new(Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100))));
        mdns_device.hostname = "mdns-hostname".to_string();
        mdns_device.origin_ip = "192.168.1.1".to_string();
        mdns_device.origin_network = "home-network".to_string();
        // The mDNS device should be local
        mdns_device.is_local = true;
        // In real code, mDNS sets both timestamps to mdns_info.first_seen
        let mdns_timestamp = Utc.with_ymd_and_hms(2023, 1, 1, 12, 15, 0).unwrap();
        mdns_device.first_seen = mdns_timestamp;
        mdns_device.last_seen = mdns_timestamp;

        // Add mDNS services
        mdns_device.mdns_services.push(MdnsServiceEntry {
            service: "_http._tcp".to_string(),
            last_seen: mdns_timestamp,
        });

        // Merge the mDNS device into our device
        DeviceInfo::merge(&mut device, &mdns_device);

        // Verify mDNS update
        assert_eq!(device.hostname, "mdns-hostname");
        assert!(device
            .mdns_services
            .iter()
            .any(|e| e.service == "_http._tcp"));
        assert_eq!(device.last_seen, mdns_timestamp);

        // Step 3: Simulate a re-scan 30 minutes later (creates a new device instance)
        let mut rescan_device = DeviceInfo::new(Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100))));
        rescan_device.origin_ip = "192.168.1.1".to_string();
        rescan_device.origin_network = "home-network".to_string();
        // The rescan device should be local
        rescan_device.is_local = true;

        // In real code this is Utc::now() at scan time
        let rescan_timestamp = Utc.with_ymd_and_hms(2023, 1, 1, 12, 30, 0).unwrap();
        rescan_device.last_seen = rescan_timestamp;
        rescan_device.first_seen = rescan_timestamp;

        // Found new port during rescan
        rescan_device.open_ports.push(PortInfo {
            port: 443,
            protocol: "tcp".to_string(),
            service: "https".to_string(),
            banner: "".to_string(),
            dismissed: false,
        });

        // Merge the rescan device
        DeviceInfo::merge(&mut device, &rescan_device);

        // Verify rescan updates
        assert_eq!(device.open_ports.len(), 2);
        assert_eq!(device.last_seen, rescan_timestamp);
        assert_eq!(
            device.first_seen,
            Utc.with_ymd_and_hms(2023, 1, 1, 12, 0, 0).unwrap()
        );

        // Step 4: Simulate community device received later
        let mut community_device =
            DeviceInfo::new(Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100))));
        community_device.hostname = "mdns-hostname".to_string();
        community_device.os_name = "Ubuntu 22.04".to_string();
        community_device.origin_ip = "10.0.0.1".to_string();
        community_device.origin_network = "friend-network".to_string();

        // Community detected this 15 minutes after our rescan
        let community_timestamp = Utc.with_ymd_and_hms(2023, 1, 1, 12, 45, 0).unwrap();
        community_device.last_seen = community_timestamp;

        // Merge the community device
        DeviceInfo::merge(&mut device, &community_device);

        // Verify community updates
        assert_eq!(device.os_name, "Ubuntu 22.04");
        // last_seen should NOT be updated since community device is not local
        assert_eq!(device.last_seen, rescan_timestamp);

        // Step 5: Receive older community information (shouldn't update timestamp)
        let mut older_community_device =
            DeviceInfo::new(Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100))));
        older_community_device.hostname = "mdns-hostname".to_string();
        older_community_device.device_vendor = "Old Vendor".to_string();
        older_community_device.origin_ip = "10.0.0.2".to_string();
        older_community_device.origin_network = "another-network".to_string();

        // Older community detection
        let older_timestamp = Utc.with_ymd_and_hms(2023, 1, 1, 12, 10, 0).unwrap();
        older_community_device.last_seen = older_timestamp;

        // Merge the older community device
        DeviceInfo::merge(&mut device, &older_community_device);

        // Verify older info behavior
        assert_eq!(device.device_vendor, "Old Vendor");
        assert_eq!(device.last_seen, rescan_timestamp);
    }

    #[test]
    fn test_last_seen_handling_in_community_lan() {
        // Test simulating the complete flow of device discovery, sharing and merging
        use chrono::{TimeZone, Utc};
        use std::net::{IpAddr, Ipv4Addr};

        // 1. Create a local device as if detected by scanning
        let mut local_device = DeviceInfo::new(Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100))));
        local_device.hostname = "local-discovery".to_string();
        local_device.origin_ip = "192.168.1.1".to_string();
        local_device.origin_network = "home-network".to_string();
        local_device.is_local = true;
        local_device.last_seen = Utc.with_ymd_and_hms(2023, 1, 1, 12, 0, 0).unwrap();
        local_device.open_ports.push(PortInfo {
            port: 80,
            protocol: "tcp".to_string(),
            service: "http".to_string(),
            banner: "".to_string(),
            dismissed: false,
        });

        // 2. Create a device as if detected by another community member
        let mut community_device =
            DeviceInfo::new(Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100))));
        community_device.hostname = "local-discovery".to_string();
        community_device.os_name = "Linux".to_string();
        community_device.origin_ip = "10.0.0.1".to_string();
        community_device.origin_network = "friend-network".to_string();
        community_device.last_seen = Utc.with_ymd_and_hms(2023, 1, 1, 13, 0, 0).unwrap();
        community_device.is_local = false;
        community_device.open_ports.push(PortInfo {
            port: 443,
            protocol: "tcp".to_string(),
            service: "https".to_string(),
            banner: "".to_string(),
            dismissed: false,
        });

        // 3. Simulate the process in community_lan.rs's LanDeviceShared event
        let mut devices_vec = vec![local_device.clone()];
        let community_device_vec = vec![community_device.clone()];

        // 4. Merge the community device (this is what happens after reception)
        DeviceInfo::merge_vec(&mut devices_vec, &community_device_vec);

        // 5. Verify that the merge preserved timestamps correctly
        assert_eq!(devices_vec.len(), 1);

        // The device should have info from both sources
        assert_eq!(devices_vec[0].os_name, "Linux");

        // Ports from both sources should be present
        assert_eq!(devices_vec[0].open_ports.len(), 2);
        devices_vec[0]
            .open_ports
            .sort_by(|a, b| a.port.cmp(&b.port));
        assert_eq!(devices_vec[0].open_ports[0].port, 80);
        assert_eq!(devices_vec[0].open_ports[1].port, 443);

        // The timestamp should NOT be updated from the community device since it's not local
        assert_eq!(
            devices_vec[0].last_seen,
            Utc.with_ymd_and_hms(2023, 1, 1, 12, 0, 0).unwrap()
        );

        // Origin should still be from the local device
        assert_eq!(devices_vec[0].origin_ip, "192.168.1.1");
        assert_eq!(devices_vec[0].origin_network, "home-network");
    }

    #[test]
    fn test_merge_is_local_updates_origin_ip() {
        // Test that when a local device is merged, its origin_ip is used
        let mut device1 = DeviceInfo::new(Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 30))));
        device1.origin_ip = "192.168.1.100".to_string();
        device1.is_local = false;
        device1.last_seen = Utc.with_ymd_and_hms(2023, 1, 1, 12, 0, 0).unwrap();

        let mut device2 = DeviceInfo::new(Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 30))));
        device2.origin_ip = "192.168.1.200".to_string();
        device2.is_local = true;
        device2.last_seen = Utc.with_ymd_and_hms(2023, 1, 1, 13, 0, 0).unwrap();

        // Merge device2 into device1
        DeviceInfo::merge(&mut device1, &device2);

        // Verify the origin_ip was updated because the new device is local
        assert_eq!(
            device1.origin_ip, "192.168.1.200",
            "origin_ip should be updated when merging a local device"
        );
    }

    #[test]
    fn test_merge_not_local_preserves_origin_ip() {
        // Test that when a non-local device is merged, the original origin_ip is preserved
        let mut device1 = DeviceInfo::new(Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 40))));
        device1.origin_ip = "192.168.1.100".to_string();
        device1.is_local = false;
        device1.last_seen = Utc.with_ymd_and_hms(2023, 1, 1, 12, 0, 0).unwrap();

        let mut device2 = DeviceInfo::new(Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 40))));
        device2.origin_ip = "192.168.1.200".to_string();
        device2.is_local = false;
        device2.last_seen = Utc.with_ymd_and_hms(2023, 1, 1, 13, 0, 0).unwrap();

        // Merge device2 into device1
        DeviceInfo::merge(&mut device1, &device2);

        // Verify the origin_ip was NOT updated because the new device is not local
        assert_eq!(
            device1.origin_ip, "192.168.1.100",
            "origin_ip should be preserved when merging a non-local device"
        );
    }

    #[test]
    fn test_merge_is_local_updates_origin_network() {
        // Test that when a local device is merged, its origin_network is used
        let mut device1 = DeviceInfo::new(Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 50))));
        device1.origin_network = "old-network".to_string();
        device1.is_local = false;
        device1.last_seen = Utc.with_ymd_and_hms(2023, 1, 1, 12, 0, 0).unwrap();

        let mut device2 = DeviceInfo::new(Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 50))));
        device2.origin_network = "new-network".to_string();
        device2.is_local = true;
        device2.last_seen = Utc.with_ymd_and_hms(2023, 1, 1, 13, 0, 0).unwrap();

        // Merge device2 into device1
        DeviceInfo::merge(&mut device1, &device2);

        // Verify the origin_network was updated because the new device is local
        assert_eq!(
            device1.origin_network, "new-network",
            "origin_network should be updated when merging a local device"
        );
    }

    #[test]
    fn test_merge_not_local_preserves_origin_network() {
        // Test that when a non-local device is merged, the original origin_network is preserved
        let mut device1 = DeviceInfo::new(Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 60))));
        device1.origin_network = "old-network".to_string();
        device1.is_local = false;
        device1.last_seen = Utc.with_ymd_and_hms(2023, 1, 1, 12, 0, 0).unwrap();

        let mut device2 = DeviceInfo::new(Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 60))));
        device2.origin_network = "new-network".to_string();
        device2.is_local = false;
        device2.last_seen = Utc.with_ymd_and_hms(2023, 1, 1, 13, 0, 0).unwrap();

        // Merge device2 into device1
        DeviceInfo::merge(&mut device1, &device2);

        // Verify the origin_network was NOT updated because the new device is not local
        assert_eq!(
            device1.origin_network, "old-network",
            "origin_network should be preserved when merging a non-local device"
        );
    }

    #[test]
    fn test_merge_is_local_preserved() {
        // Test that is_local flag is preserved when merging
        let mut device1 = DeviceInfo::new(Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10))));
        device1.is_local = true;
        device1.hostname = "local-device".to_string();
        device1.last_seen = Utc.with_ymd_and_hms(2023, 1, 1, 12, 0, 0).unwrap();

        let mut device2 = DeviceInfo::new(Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10))));
        device2.is_local = true; // Local for timestamp to be updated
        device2.os_name = "Some OS".to_string();
        device2.last_seen = Utc.with_ymd_and_hms(2023, 1, 1, 13, 0, 0).unwrap();

        // Merge device2 into device1
        DeviceInfo::merge(&mut device1, &device2);

        // Verify is_local remains true
        assert!(
            device1.is_local,
            "is_local should remain true after merging"
        );
        // Also verify other fields were updated
        assert_eq!(device1.os_name, "Some OS", "OS name should be updated");
        assert_eq!(
            device1.last_seen,
            Utc.with_ymd_and_hms(2023, 1, 1, 13, 0, 0).unwrap(),
            "last_seen should be updated from newer device"
        );
    }

    #[test]
    fn test_merge_is_local_propagates() {
        // Test that is_local=true propagates from source to destination
        let mut device1 = DeviceInfo::new(Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 20))));
        device1.is_local = false;
        device1.hostname = "device".to_string();
        device1.last_seen = Utc.with_ymd_and_hms(2023, 1, 1, 12, 0, 0).unwrap();

        let mut device2 = DeviceInfo::new(Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 20))));
        device2.is_local = true; // Source device is marked as local
        device2.last_seen = Utc.with_ymd_and_hms(2023, 1, 1, 13, 0, 0).unwrap();

        // Merge device2 into device1
        DeviceInfo::merge(&mut device1, &device2);

        // Verify is_local was propagated from device2 to device1
        assert!(
            device1.is_local,
            "is_local should be propagated from source to destination"
        );
    }

    #[test]
    fn test_merge_vec_is_local_behavior() {
        // Test that is_local behavior works correctly when merging vectors
        let mut devices = vec![{
            let mut d = DeviceInfo::new(Some(IpAddr::V4(Ipv4Addr::new(192, 168, 0, 10))));
            d.is_local = false;
            d
        }];

        let new_devices = vec![{
            let mut d = DeviceInfo::new(Some(IpAddr::V4(Ipv4Addr::new(192, 168, 0, 10))));
            d.is_local = true;
            d
        }];

        // Merge the vectors
        DeviceInfo::merge_vec(&mut devices, &new_devices);

        // Verify the result has is_local=true
        assert!(
            devices[0].is_local,
            "is_local should be true after merging vectors"
        );
    }

    #[test]
    fn test_set_ip_address_bug_fix() {
        // Test that set_ip_address actually updates the primary IP address
        let mut device = DeviceInfo::new(Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10))));
        assert_eq!(
            device.get_ip_address(),
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10))
        );

        // Set a new IP address
        let new_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 20));
        device.set_ip_address(new_ip, vec![], vec![]);

        // Verify the primary IP was actually updated
        assert_eq!(
            device.get_ip_address(),
            new_ip,
            "Primary IP address should be updated"
        );

        // Verify both old and new IPs are in the lists
        assert!(
            device
                .ip_addresses_v4
                .iter()
                .any(|e| e.address == Ipv4Addr::new(192, 168, 1, 10)),
            "Old IP should be preserved in list"
        );
        assert!(
            device
                .ip_addresses_v4
                .iter()
                .any(|e| e.address == Ipv4Addr::new(192, 168, 1, 20)),
            "New IP should be added to list"
        );
    }

    #[test]
    fn test_set_ip_address_with_additional_ips() {
        let mut device = DeviceInfo::new(Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));

        let new_primary = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));
        let additional_v4 = vec![Ipv4Addr::new(172, 16, 0, 1), Ipv4Addr::new(172, 16, 0, 2)];
        let additional_v6 = vec![Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)];

        device.set_ip_address(new_primary, additional_v4.clone(), additional_v6.clone());

        // Verify primary IP is updated
        assert_eq!(device.get_ip_address(), new_primary);

        // Verify all IPs are in the appropriate lists
        assert!(device
            .ip_addresses_v4
            .iter()
            .any(|e| e.address == Ipv4Addr::new(10, 0, 0, 1))); // Original
        assert!(device
            .ip_addresses_v4
            .iter()
            .any(|e| e.address == Ipv4Addr::new(192, 168, 1, 100))); // New primary
        assert!(device
            .ip_addresses_v4
            .iter()
            .any(|e| e.address == Ipv4Addr::new(172, 16, 0, 1))); // Additional
        assert!(device
            .ip_addresses_v4
            .iter()
            .any(|e| e.address == Ipv4Addr::new(172, 16, 0, 2))); // Additional
        assert!(device
            .ip_addresses_v6
            .iter()
            .any(|e| e.address == Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)));
        // Additional IPv6
    }

    #[test]
    fn test_merge_vec_conflicting_vendors() {
        // Test that devices with conflicting vendors are not merged
        let mut devices = vec![{
            let mut d = DeviceInfo::new(Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100))));
            d.hostname = "test-device.local".to_string(); // Specific hostname
            d.device_vendor = "Apple Inc.".to_string();
            d.ip_addresses_v4 = vec![
                ipv4_entry(Ipv4Addr::new(192, 168, 1, 100)),
                ipv4_entry(Ipv4Addr::new(10, 0, 0, 2)),
            ]; // Add shared IP
            d.open_ports = vec![
                PortInfo {
                    port: 22,
                    protocol: "tcp".to_string(),
                    service: "ssh".to_string(),
                    banner: "".to_string(),
                    dismissed: false,
                },
                PortInfo {
                    port: 80,
                    protocol: "tcp".to_string(),
                    service: "http".to_string(),
                    banner: "".to_string(),
                    dismissed: false,
                },
            ];
            d
        }];

        let new_devices = vec![{
            let mut d = DeviceInfo::new(Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 101))));
            d.hostname = "test-device.local".to_string(); // Same specific hostname
            d.device_vendor = "Samsung Electronics".to_string(); // Different vendor
            d.ip_addresses_v4 = vec![
                ipv4_entry(Ipv4Addr::new(192, 168, 1, 101)),
                ipv4_entry(Ipv4Addr::new(10, 0, 0, 2)),
            ]; // Same shared IP
            d.open_ports = vec![
                PortInfo {
                    port: 443,
                    protocol: "tcp".to_string(),
                    service: "https".to_string(),
                    banner: "".to_string(),
                    dismissed: false,
                },
                PortInfo {
                    port: 8080,
                    protocol: "tcp".to_string(),
                    service: "http-alt".to_string(),
                    banner: "".to_string(),
                    dismissed: false,
                },
            ];
            d
        }];

        DeviceInfo::merge_vec(&mut devices, &new_devices);

        // Should NOT merge due to conflicting vendors, even with same hostname
        assert_eq!(
            devices.len(),
            2,
            "Devices with conflicting vendors should not merge"
        );
        assert_eq!(devices[0].device_vendor, "Apple Inc.");
        assert_eq!(devices[1].device_vendor, "Samsung Electronics");
    }

    #[test]
    fn test_merge_vec_generic_hostname_blocked() {
        // Test that generic hostnames are blocked from merging
        let mut devices = vec![{
            let mut d = DeviceInfo::new(Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100))));
            d.hostname = "router".to_string(); // Generic hostname
            d.device_vendor = "Netgear".to_string();
            d.open_ports = vec![PortInfo {
                port: 80,
                protocol: "tcp".to_string(),
                service: "http".to_string(),
                banner: "".to_string(),
                dismissed: false,
            }];
            d
        }];

        let new_devices = vec![{
            let mut d = DeviceInfo::new(Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 101))));
            d.hostname = "router".to_string(); // Same generic hostname
            d.device_vendor = "Linksys".to_string(); // Different vendor
            d.open_ports = vec![PortInfo {
                port: 443,
                protocol: "tcp".to_string(),
                service: "https".to_string(),
                banner: "".to_string(),
                dismissed: false,
            }];
            d
        }];

        DeviceInfo::merge_vec(&mut devices, &new_devices);

        // Should NOT merge due to generic hostname
        assert_eq!(
            devices.len(),
            2,
            "Devices with generic hostnames should not merge"
        );
    }

    #[test]
    fn test_merge_vec_specific_hostname_allowed() {
        // Test that specific hostnames allow merging (multi-interface scenario)
        let mut devices = vec![{
            let mut d = DeviceInfo::new(Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100))));
            d.hostname = "john-macbook-pro.local".to_string(); // Very specific hostname
            d.device_vendor = "Apple Inc.".to_string();
            d.ip_addresses_v4 = vec![
                ipv4_entry(Ipv4Addr::new(192, 168, 1, 100)),
                ipv4_entry(Ipv4Addr::new(10, 0, 0, 5)),
            ]; // Add shared IP
            d.open_ports = vec![PortInfo {
                port: 22,
                protocol: "tcp".to_string(),
                service: "ssh".to_string(),
                banner: "".to_string(),
                dismissed: false,
            }];
            d
        }];

        let new_devices = vec![{
            let mut d = DeviceInfo::new(Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 101))));
            d.hostname = "john-macbook-pro.local".to_string(); // Same specific hostname
            d.device_vendor = "Apple Inc.".to_string(); // Same vendor
            d.ip_addresses_v4 = vec![
                ipv4_entry(Ipv4Addr::new(192, 168, 1, 101)),
                ipv4_entry(Ipv4Addr::new(10, 0, 0, 5)),
            ]; // Same shared IP
            d.open_ports = vec![PortInfo {
                port: 80,
                protocol: "tcp".to_string(),
                service: "http".to_string(),
                banner: "".to_string(),
                dismissed: false,
            }];
            d
        }];

        DeviceInfo::merge_vec(&mut devices, &new_devices);

        // Should merge due to IP overlap and compatible characteristics
        assert_eq!(
            devices.len(),
            1,
            "Devices with IP overlap and compatible characteristics should merge"
        );
        assert_eq!(devices[0].open_ports.len(), 2, "Ports should be merged");
    }

    #[test]
    fn test_merge_vec_privacy_extension_scenario() {
        // Test privacy extension scenario: same device, same IP with different MACs, specific hostname
        let mut devices = vec![{
            let mut d = DeviceInfo::new(Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100))));
            d.hostname = "sarah-iphone-13.local".to_string(); // Specific hostname
            d.mac_address = Some(MacAddr6::new(0xB8, 0x27, 0xEB, 0x41, 0x90, 0xA4)); // Real MAC
            d.device_vendor = "Apple Inc.".to_string();
            d.open_ports = vec![PortInfo {
                port: 62078,
                protocol: "tcp".to_string(),
                service: "iphone-sync".to_string(),
                banner: "".to_string(),
                dismissed: false,
            }];
            d
        }];

        let new_devices = vec![{
            let mut d = DeviceInfo::new(Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)))); // Same IP
            d.hostname = "sarah-iphone-13.local".to_string(); // Same specific hostname
            d.mac_address = Some(MacAddr6::new(0x02, 0x12, 0x34, 0x56, 0x78, 0x9A)); // Privacy MAC (locally administered)
            d.device_vendor = "".to_string(); // No vendor from privacy MAC
            d.open_ports = vec![PortInfo {
                port: 5353,
                protocol: "udp".to_string(),
                service: "mdns".to_string(),
                banner: "".to_string(),
                dismissed: false,
            }];
            d
        }];

        DeviceInfo::merge_vec(&mut devices, &new_devices);

        // Should merge due to same IP (privacy extension scenario)
        assert_eq!(
            devices.len(),
            1,
            "Privacy extension scenario should allow merge with same IP"
        );
        assert_eq!(devices[0].open_ports.len(), 2, "Ports should be merged");
        // The real MAC should be preserved (from the fresher device logic)
        assert!(
            devices[0].mac_address.is_some(),
            "MAC address should be preserved"
        );
    }

    #[test]
    fn test_merge_vec_specific_hostname_different_macs_same_vendor() {
        // Devices with the same specific hostname and vendor should merge even if MACs differ
        let mac_primary = MacAddr6::new(0x00, 0x1C, 0x42, 0x7F, 0xAA, 0x01);
        let mac_secondary = MacAddr6::new(0x00, 0x1C, 0x42, 0x7F, 0xAA, 0x02);

        let mut devices = vec![{
            let mut d = DeviceInfo::new(Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 110))));
            d.hostname = "alex-macbook-pro.local".to_string();
            d.device_vendor = "Apple Inc.".to_string();
            d.mac_address = Some(mac_primary);
            d.mac_addresses = vec![mac_entry(mac_primary)];
            d.last_seen = Utc.with_ymd_and_hms(2023, 5, 1, 10, 0, 0).unwrap();
            d
        }];

        let new_devices = vec![{
            let mut d = DeviceInfo::new(Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 111))));
            d.hostname = "alex-macbook-pro.local".to_string();
            d.device_vendor = "Apple Inc.".to_string();
            d.mac_address = Some(mac_secondary);
            d.mac_addresses = vec![mac_entry(mac_secondary)];
            d.last_seen = Utc.with_ymd_and_hms(2023, 5, 1, 11, 0, 0).unwrap();
            d
        }];

        DeviceInfo::merge_vec(&mut devices, &new_devices);

        assert_eq!(
            devices.len(),
            1,
            "Devices with the same specific hostname should merge despite differing MACs"
        );
        assert_eq!(
            devices[0].mac_address,
            Some(mac_secondary),
            "Latest MAC address should be the primary one"
        );
        assert!(
            devices[0]
                .mac_addresses
                .iter()
                .any(|e| e.address == mac_primary)
                && devices[0]
                    .mac_addresses
                    .iter()
                    .any(|e| e.address == mac_secondary),
            "All observed MAC addresses should be retained after merge"
        );
    }

    #[test]
    fn test_merge_vec_ip_overlap_with_conflicts() {
        // Test that IP overlap with conflicting characteristics is blocked
        let mut devices = vec![{
            let mut d = DeviceInfo::new(Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100))));
            d.ip_addresses_v4 = vec![
                ipv4_entry(Ipv4Addr::new(192, 168, 1, 100)),
                ipv4_entry(Ipv4Addr::new(10, 0, 0, 1)),
            ]; // Shared IP
            d.device_vendor = "Raspberry Pi Foundation".to_string();
            d.open_ports = vec![PortInfo {
                port: 22,
                protocol: "tcp".to_string(),
                service: "ssh".to_string(),
                banner: "".to_string(),
                dismissed: false,
            }];
            d
        }];

        let new_devices = vec![{
            let mut d = DeviceInfo::new(Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 101))));
            d.ip_addresses_v4 = vec![
                ipv4_entry(Ipv4Addr::new(192, 168, 1, 101)),
                ipv4_entry(Ipv4Addr::new(10, 0, 0, 1)),
            ]; // Same shared IP
            d.device_vendor = "Freebox SAS".to_string(); // Conflicting vendor
            d.open_ports = vec![PortInfo {
                port: 80,
                protocol: "tcp".to_string(),
                service: "http".to_string(),
                banner: "".to_string(),
                dismissed: false,
            }];
            d
        }];

        DeviceInfo::merge_vec(&mut devices, &new_devices);

        // Should NOT merge due to conflicting vendors, even with IP overlap
        assert_eq!(
            devices.len(),
            2,
            "IP overlap with conflicting vendors should not merge"
        );
    }

    #[test]
    fn test_merge_vec_ip_overlap_without_conflicts() {
        // Test that IP overlap WITH hostname confirmation allows merging
        // (IPv4 overlap alone is not enough - needs MAC or hostname confirmation)
        let mut devices = vec![{
            let mut d = DeviceInfo::new(Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100))));
            d.ip_addresses_v4 = vec![
                ipv4_entry(Ipv4Addr::new(192, 168, 1, 100)),
                ipv4_entry(Ipv4Addr::new(10, 0, 0, 1)),
            ]; // Shared IP
            d.hostname = "multi-interface-device.local".to_string(); // Hostname for confirmation
            d.device_vendor = "Apple Inc.".to_string();
            d.open_ports = vec![
                PortInfo {
                    port: 22,
                    protocol: "tcp".to_string(),
                    service: "ssh".to_string(),
                    banner: "".to_string(),
                    dismissed: false,
                },
                PortInfo {
                    port: 80,
                    protocol: "tcp".to_string(),
                    service: "http".to_string(),
                    banner: "".to_string(),
                    dismissed: false,
                },
            ];
            d
        }];

        let new_devices = vec![{
            let mut d = DeviceInfo::new(Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 101))));
            d.ip_addresses_v4 = vec![
                ipv4_entry(Ipv4Addr::new(192, 168, 1, 101)),
                ipv4_entry(Ipv4Addr::new(10, 0, 0, 1)),
            ]; // Same shared IP
            d.hostname = "multi-interface-device.local".to_string(); // Same hostname
            d.device_vendor = "Apple Inc.".to_string(); // Same vendor
            d.open_ports = vec![
                PortInfo {
                    port: 80,
                    protocol: "tcp".to_string(),
                    service: "http".to_string(),
                    banner: "".to_string(),
                    dismissed: false,
                },
                PortInfo {
                    port: 443,
                    protocol: "tcp".to_string(),
                    service: "https".to_string(),
                    banner: "".to_string(),
                    dismissed: false,
                },
            ];
            d
        }];

        DeviceInfo::merge_vec(&mut devices, &new_devices);

        // Should merge due to IP overlap and compatible characteristics
        assert_eq!(
            devices.len(),
            1,
            "IP overlap without conflicts should allow merge"
        );
        assert_eq!(
            devices[0].open_ports.len(),
            3,
            "Ports should be merged (22, 80, 443)"
        );
    }

    #[test]
    fn test_is_specific_hostname() {
        // Test the hostname specificity detection

        // Generic hostnames should be rejected
        assert!(
            !DeviceInfo::is_specific_hostname("router"),
            "router should be generic"
        );
        assert!(
            !DeviceInfo::is_specific_hostname("gateway"),
            "gateway should be generic"
        );
        assert!(
            !DeviceInfo::is_specific_hostname("device"),
            "device should be generic"
        );
        assert!(
            !DeviceInfo::is_specific_hostname("iphone"),
            "iphone should be generic"
        );
        assert!(
            !DeviceInfo::is_specific_hostname("macbook"),
            "macbook should be generic"
        );
        assert!(
            DeviceInfo::is_specific_hostname("android-phone"),
            "android-phone should be specific (compound name)"
        );

        // Specific hostnames should be accepted
        assert!(
            DeviceInfo::is_specific_hostname("john-macbook-pro.local"),
            "john-macbook-pro.local should be specific"
        );
        assert!(
            DeviceInfo::is_specific_hostname("sarah-iphone-13.local"),
            "sarah-iphone-13.local should be specific"
        );
        assert!(
            DeviceInfo::is_specific_hostname("freebox.local"),
            "freebox.local should be specific"
        );
        assert!(
            DeviceInfo::is_specific_hostname("raspberry-pi-kitchen.lan"),
            "raspberry-pi-kitchen.lan should be specific"
        );
        assert!(
            DeviceInfo::is_specific_hostname("very-long-hostname-that-is-specific"),
            "Long hostnames should be specific"
        );

        // Edge cases
        assert!(
            !DeviceInfo::is_specific_hostname("short"),
            "Short hostnames should be generic"
        );
        assert!(
            !DeviceInfo::is_specific_hostname(""),
            "Empty hostname should be generic"
        );
        assert!(
            DeviceInfo::is_specific_hostname("specific.domain.com"),
            "FQDN should be specific"
        );
    }

    #[test]
    fn test_dedup_vec_with_smart_logic() {
        // Test that dedup_vec uses the same smart logic as merge_vec
        let mut devices = vec![
            {
                let mut d = DeviceInfo::new(Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100))));
                d.hostname = "john-macbook.local".to_string(); // Specific
                d.device_vendor = "Apple Inc.".to_string();
                d.ip_addresses_v4 = vec![
                    ipv4_entry(Ipv4Addr::new(192, 168, 1, 100)),
                    ipv4_entry(Ipv4Addr::new(169, 254, 0, 1)),
                ]; // Add shared IP
                d.open_ports = vec![PortInfo {
                    port: 22,
                    protocol: "tcp".to_string(),
                    service: "ssh".to_string(),
                    banner: "".to_string(),
                    dismissed: false,
                }];
                d
            },
            {
                let mut d = DeviceInfo::new(Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 101))));
                d.hostname = "john-macbook.local".to_string(); // Same specific hostname
                d.device_vendor = "Apple Inc.".to_string(); // Same vendor
                d.ip_addresses_v4 = vec![
                    ipv4_entry(Ipv4Addr::new(192, 168, 1, 101)),
                    ipv4_entry(Ipv4Addr::new(169, 254, 0, 1)),
                ]; // Same shared IP
                d.open_ports = vec![PortInfo {
                    port: 80,
                    protocol: "tcp".to_string(),
                    service: "http".to_string(),
                    banner: "".to_string(),
                    dismissed: false,
                }];
                d
            },
            {
                let mut d = DeviceInfo::new(Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 102))));
                d.hostname = "router".to_string(); // Generic hostname
                d.device_vendor = "Netgear".to_string();
                d
            },
            {
                let mut d = DeviceInfo::new(Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 103))));
                d.hostname = "router".to_string(); // Same generic hostname
                d.device_vendor = "Linksys".to_string(); // Different vendor
                d
            },
        ];

        DeviceInfo::dedup_vec(&mut devices);

        // With smart logic, MacBooks should merge (IP overlap + compatible) but routers should not (generic hostname)
        assert_eq!(
            devices.len(),
            3,
            "Should merge compatible devices with IP overlap but not generic hostnames"
        );

        // Should still have both routers
        let routers: Vec<_> = devices.iter().filter(|d| d.hostname == "router").collect();
        assert_eq!(
            routers.len(),
            2,
            "Generic hostname devices should not merge"
        );

        // Should have one merged MacBook
        let macbooks: Vec<_> = devices
            .iter()
            .filter(|d| d.hostname == "john-macbook.local")
            .collect();
        assert_eq!(
            macbooks.len(),
            1,
            "MacBooks with IP overlap should merge in dedup_vec"
        );
        assert_eq!(
            macbooks[0].open_ports.len(),
            2,
            "MacBook should have merged ports"
        );
    }

    #[test]
    fn test_merge_vec_hostname_only_specific() {
        // Test that specific hostnames allow merging even without IP overlap (multi-interface scenario)
        let mut devices = vec![{
            let mut d = DeviceInfo::new(Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100))));
            d.hostname = "johns-very-specific-macbook-pro.local".to_string(); // Very specific hostname
            d.device_vendor = "Apple Inc.".to_string();
            d.open_ports = vec![PortInfo {
                port: 22,
                protocol: "tcp".to_string(),
                service: "ssh".to_string(),
                banner: "".to_string(),
                dismissed: false,
            }];
            d
        }];

        let new_devices = vec![{
            let mut d = DeviceInfo::new(Some(IpAddr::V4(Ipv4Addr::new(172, 16, 0, 50)))); // Different IP, no overlap
            d.hostname = "johns-very-specific-macbook-pro.local".to_string(); // Same specific hostname
            d.device_vendor = "Apple Inc.".to_string(); // Same vendor (no conflict)
            d.open_ports = vec![PortInfo {
                port: 80,
                protocol: "tcp".to_string(),
                service: "http".to_string(),
                banner: "".to_string(),
                dismissed: false,
            }];
            d
        }];

        DeviceInfo::merge_vec(&mut devices, &new_devices);

        // Should merge due to specific hostname and no conflicts
        assert_eq!(
            devices.len(),
            1,
            "Devices with specific hostnames and no conflicts should merge"
        );
        assert_eq!(devices[0].open_ports.len(), 2, "Ports should be merged");
    }

    #[test]
    fn test_original_bug_scenario() {
        // Test the original bug scenario: Freebox and Raspberry Pi with similar hostnames
        let mut devices = vec![{
            let mut d = DeviceInfo::new(Some(IpAddr::V4(Ipv4Addr::new(82, 64, 124, 164))));
            d.hostname = "freebox.local".to_string(); // Specific hostname
            d.device_vendor = "Freebox SAS".to_string();
            d.mac_address = Some(MacAddr6::new(0x38, 0x07, 0x16, 0x19, 0xD6, 0x2E));
            d.open_ports = vec![
                PortInfo {
                    port: 53,
                    protocol: "tcp".to_string(),
                    service: "dns".to_string(),
                    banner: "".to_string(),
                    dismissed: false,
                },
                PortInfo {
                    port: 80,
                    protocol: "tcp".to_string(),
                    service: "http".to_string(),
                    banner: "nginx".to_string(),
                    dismissed: false,
                },
                PortInfo {
                    port: 443,
                    protocol: "tcp".to_string(),
                    service: "https".to_string(),
                    banner: "nginx".to_string(),
                    dismissed: false,
                },
            ];
            d
        }];

        let new_devices = vec![{
            let mut d = DeviceInfo::new(Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 109))));
            d.hostname = "raspberrypi.local".to_string(); // Different specific hostname
            d.device_vendor = "Raspberry Pi Foundation".to_string(); // Different vendor
            d.mac_address = Some(MacAddr6::new(0xB8, 0x27, 0xEB, 0x41, 0x90, 0xA4)); // Different MAC
            d.open_ports = vec![
                PortInfo {
                    port: 22,
                    protocol: "tcp".to_string(),
                    service: "ssh".to_string(),
                    banner: "OpenSSH".to_string(),
                    dismissed: false,
                },
                PortInfo {
                    port: 80,
                    protocol: "tcp".to_string(),
                    service: "http".to_string(),
                    banner: "lighttpd".to_string(),
                    dismissed: false,
                },
                PortInfo {
                    port: 111,
                    protocol: "tcp".to_string(),
                    service: "sunrpc".to_string(),
                    banner: "".to_string(),
                    dismissed: false,
                },
            ];
            d
        }];

        DeviceInfo::merge_vec(&mut devices, &new_devices);

        // Should NOT merge - different hostnames, different vendors, different MACs, different IPs
        assert_eq!(
            devices.len(),
            2,
            "Freebox and Raspberry Pi should remain separate devices"
        );

        // Verify each device kept its own ports
        let freebox = devices
            .iter()
            .find(|d| d.hostname == "freebox.local")
            .unwrap();
        assert_eq!(
            freebox.open_ports.len(),
            3,
            "Freebox should keep its own ports"
        );
        assert!(
            freebox.open_ports.iter().any(|p| p.port == 53),
            "Freebox should have DNS port"
        );

        let rpi = devices
            .iter()
            .find(|d| d.hostname == "raspberrypi.local")
            .unwrap();
        assert_eq!(
            rpi.open_ports.len(),
            3,
            "Raspberry Pi should keep its own ports"
        );
        assert!(
            rpi.open_ports.iter().any(|p| p.port == 111),
            "Raspberry Pi should have sunrpc port"
        );
    }

    #[test]
    fn test_ipv6_truncation_keeps_most_recent() {
        // Test that IPv6 addresses are truncated to keep only the last 10 most recently added
        let mut device = DeviceInfo::new(Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));
        let base_time = Utc::now();

        // Add 15 IPv6 addresses (should keep only last 10)
        // Use explicit timestamps to ensure deterministic ordering
        // (on fast machines, Utc::now() can return identical timestamps for all entries)
        let mut old_addresses = Vec::new();
        for i in 0..5 {
            old_addresses.push(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, i as u16));
        }

        let mut new_addresses = Vec::new();
        for i in 5..15 {
            new_addresses.push(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, i as u16));
        }

        // Add old addresses first with earlier timestamp
        let old_timestamp = base_time;
        device.add_ip_addresses_with_timestamp(vec![], old_addresses.clone(), old_timestamp);
        // Add new addresses with later timestamp (these should be kept)
        let new_timestamp = base_time + chrono::Duration::seconds(10);
        device.add_ip_addresses_with_timestamp(vec![], new_addresses.clone(), new_timestamp);

        // Should have exactly 10 addresses
        assert_eq!(
            device.ip_addresses_v6.len(),
            10,
            "Should have exactly 10 IPv6 addresses"
        );

        // Should contain the new addresses (5-14) and not the oldest ones (0-4)
        for addr in new_addresses.iter() {
            assert!(
                device.ip_addresses_v6.iter().any(|e| e.address == *addr),
                "Should contain new address {:?}",
                addr
            );
        }

        // Should not contain the oldest addresses
        for addr in old_addresses.iter() {
            assert!(
                !device.ip_addresses_v6.iter().any(|e| e.address == *addr),
                "Should not contain old address {:?}",
                addr
            );
        }
    }

    #[test]
    fn test_mdns_truncation_keeps_most_recent() {
        // Test that mDNS services are truncated to keep only the last 20 most recently added
        let mut device = DeviceInfo::new(Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));
        let base_time = Utc::now();

        // Add 25 mDNS services (should keep only last 20)
        // Use explicit timestamps to ensure deterministic ordering
        // (on fast machines, Utc::now() can return identical timestamps for all entries)
        let mut old_services = Vec::new();
        for i in 0..5 {
            old_services.push(MdnsServiceEntry {
                service: format!("_service{}.local", i),
                last_seen: base_time + chrono::Duration::seconds(i as i64),
            });
        }

        let mut new_services = Vec::new();
        for i in 5..25 {
            new_services.push(MdnsServiceEntry {
                service: format!("_service{}.local", i),
                last_seen: base_time + chrono::Duration::seconds(i as i64),
            });
        }

        // Add old services first
        device.mdns_services.extend(old_services.clone());
        // Add new services (these should be kept)
        device.mdns_services.extend(new_services.clone());
        // Truncate
        device.truncate_mdns_services();

        // Should have exactly 20 services
        assert_eq!(
            device.mdns_services.len(),
            20,
            "Should have exactly 20 mDNS services"
        );

        // Should contain the new services (5-24) and not the oldest ones (0-4)
        for i in 5..25 {
            let service = format!("_service{}.local", i);
            assert!(
                device.mdns_services.iter().any(|e| e.service == service),
                "Should contain new service {}",
                service
            );
        }

        // Should not contain the oldest services
        for i in 0..5 {
            let service = format!("_service{}.local", i);
            assert!(
                !device.mdns_services.iter().any(|e| e.service == service),
                "Should not contain old service {}",
                service
            );
        }
    }

    #[test]
    fn test_retain_fresh_mdns_services_drops_only_stale() {
        let mut device = DeviceInfo::new(Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));
        let now = Utc::now();
        let max_age = chrono::Duration::seconds(1200);

        device.mdns_services = vec![
            MdnsServiceEntry {
                service: "_fresh.local".to_string(),
                last_seen: now - chrono::Duration::seconds(60),
            },
            MdnsServiceEntry {
                // Just inside the window. Not tested at exact equality: the function
                // reads its own Utc::now(), which is microseconds past the one here,
                // so an entry built at exactly `now - max_age` is already outside by
                // the time it is evaluated. Straddling the boundary by a second each
                // way is what is actually observable.
                service: "_boundary.local".to_string(),
                last_seen: now - max_age + chrono::Duration::seconds(1),
            },
            MdnsServiceEntry {
                service: "_stale.local".to_string(),
                last_seen: now - max_age - chrono::Duration::seconds(1),
            },
        ];

        device.retain_fresh_mdns_services(max_age);

        let kept: Vec<&str> = device
            .mdns_services
            .iter()
            .map(|e| e.service.as_str())
            .collect();
        assert!(kept.contains(&"_fresh.local"), "kept: {:?}", kept);
        assert!(kept.contains(&"_boundary.local"), "kept: {:?}", kept);
        assert!(
            !kept.contains(&"_stale.local"),
            "service past the window must be dropped, kept: {:?}",
            kept
        );
    }

    #[test]
    fn test_retain_fresh_mdns_services_keeps_future_timestamps() {
        // Clock skew (NTP step, a responder reporting ahead) yields a negative age.
        // Treat that as fresh rather than expiring a service we just saw -- dropping
        // it would make classification depend on clock drift.
        let mut device = DeviceInfo::new(Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));
        device.mdns_services = vec![MdnsServiceEntry {
            service: "_skewed.local".to_string(),
            last_seen: Utc::now() + chrono::Duration::seconds(300),
        }];

        device.retain_fresh_mdns_services(chrono::Duration::seconds(1200));

        assert_eq!(
            device.mdns_services.len(),
            1,
            "a future timestamp must not be treated as stale"
        );
    }

    #[test]
    fn test_retain_fresh_mdns_services_expires_classification_input() {
        // The case this exists for: a device kept being typed off a service it no
        // longer ran, because merging only ever added and the count cap does not
        // bound age. Once the stale entry is gone the device has no service left to
        // be classified on.
        let mut device = DeviceInfo::new(Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));
        device.mdns_services = vec![MdnsServiceEntry {
            service: "_workstation._tcp.local".to_string(),
            last_seen: Utc::now() - chrono::Duration::seconds(7200),
        }];

        device.retain_fresh_mdns_services(chrono::Duration::seconds(1200));

        assert!(
            device.mdns_services.is_empty(),
            "long-dead service must stop feeding classification"
        );
    }

    #[test]
    fn test_ipv6_deduplication_preserves_most_recent() {
        // Test that deduplication keeps the most recent occurrence
        let mut device = DeviceInfo::new(Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));

        let addr1 = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let addr2 = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2);
        let addr3 = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 3);

        // Add addresses: addr1, addr2, addr1 (duplicate), addr3
        device.add_ip_addresses(vec![], vec![addr1]);
        device.add_ip_addresses(vec![], vec![addr2]);
        device.add_ip_addresses(vec![], vec![addr1]); // Duplicate
        device.add_ip_addresses(vec![], vec![addr3]);

        // Should have 3 addresses (addr1 should appear only once, as the most recent occurrence)
        assert_eq!(
            device.ip_addresses_v6.len(),
            3,
            "Should have 3 unique addresses"
        );

        // Verify all addresses are present and addr1 appears only once
        let addresses: Vec<_> = device.ip_addresses_v6.iter().map(|e| e.address).collect();
        assert_eq!(addresses.len(), 3, "Should have exactly 3 addresses");
        assert!(addresses.contains(&addr1), "Should contain addr1");
        assert!(addresses.contains(&addr2), "Should contain addr2");
        assert!(addresses.contains(&addr3), "Should contain addr3");

        // Verify addr1 appears only once (deduplication worked)
        let addr1_count = addresses.iter().filter(|&&a| a == addr1).count();
        assert_eq!(
            addr1_count, 1,
            "addr1 should appear only once after deduplication"
        );

        // Verify timestamps: addr3 was added last, so it should have the most recent timestamp
        // addr1 was added twice (second time before addr3), so it should have timestamp between addr2 and addr3
        let addr1_entry = device
            .ip_addresses_v6
            .iter()
            .find(|e| e.address == addr1)
            .unwrap();
        let addr2_entry = device
            .ip_addresses_v6
            .iter()
            .find(|e| e.address == addr2)
            .unwrap();
        let addr3_entry = device
            .ip_addresses_v6
            .iter()
            .find(|e| e.address == addr3)
            .unwrap();
        // addr3 was added last, so it should have the most recent timestamp
        assert!(
            addr3_entry.last_seen >= addr1_entry.last_seen,
            "addr3 should have timestamp >= addr1 (was added most recently)"
        );
        assert!(
            addr3_entry.last_seen >= addr2_entry.last_seen,
            "addr3 should have timestamp >= addr2 (was added most recently)"
        );
        // addr1 (second addition) should be more recent than addr2
        assert!(
            addr1_entry.last_seen >= addr2_entry.last_seen,
            "addr1 should have timestamp >= addr2 (was added after addr2)"
        );
    }

    #[test]
    fn test_mdns_deduplication_preserves_most_recent() {
        // Test that mDNS deduplication keeps the most recent occurrence
        let mut device1 = DeviceInfo::new(Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));
        device1.mdns_services.push(mdns_entry("_service1.local"));
        device1.mdns_services.push(mdns_entry("_service2.local"));

        let mut device2 = DeviceInfo::new(Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));
        device2.mdns_services.push(mdns_entry("_service1.local")); // Duplicate
        device2.mdns_services.push(mdns_entry("_service3.local"));

        // Merge device2 into device1
        DeviceInfo::merge(&mut device1, &device2);

        // Should have 3 unique services
        assert_eq!(
            device1.mdns_services.len(),
            3,
            "Should have 3 unique mDNS services"
        );

        // Should contain all services
        assert!(
            device1
                .mdns_services
                .iter()
                .any(|e| e.service == "_service1.local"),
            "Should contain service1"
        );
        assert!(
            device1
                .mdns_services
                .iter()
                .any(|e| e.service == "_service2.local"),
            "Should contain service2"
        );
        assert!(
            device1
                .mdns_services
                .iter()
                .any(|e| e.service == "_service3.local"),
            "Should contain service3"
        );
    }

    #[test]
    fn test_ipv6_truncation_before_add() {
        // Test that truncation happens before adding new items
        let mut device = DeviceInfo::new(Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));
        let base_time = Utc::now();

        // Fill up to 10 addresses with earlier timestamp
        // (on fast machines, Utc::now() can return identical timestamps for all entries)
        let mut addresses = Vec::new();
        for i in 0..10 {
            addresses.push(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, i as u16));
        }
        device.add_ip_addresses_with_timestamp(vec![], addresses, base_time);

        // Now add 5 more addresses with later timestamp
        let new_addresses = vec![
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 10),
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 11),
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 12),
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 13),
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 14),
        ];
        let new_timestamp = base_time + chrono::Duration::seconds(10);
        device.add_ip_addresses_with_timestamp(vec![], new_addresses.clone(), new_timestamp);

        // Should still have exactly 10 addresses
        assert_eq!(
            device.ip_addresses_v6.len(),
            10,
            "Should have exactly 10 addresses after adding more"
        );

        // Should contain the new addresses
        for addr in new_addresses.iter() {
            assert!(
                device.ip_addresses_v6.iter().any(|e| e.address == *addr),
                "Should contain new address {:?}",
                addr
            );
        }
    }

    #[test]
    fn test_mdns_truncation_before_add() {
        // Test that truncation happens before adding new items
        let mut device = DeviceInfo::new(Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));
        let base_time = Utc::now();

        // Fill up to 20 services with explicit timestamps
        // (on fast machines, Utc::now() can return identical timestamps for all entries)
        for i in 0..20 {
            device.mdns_services.push(MdnsServiceEntry {
                service: format!("_service{}.local", i),
                last_seen: base_time + chrono::Duration::seconds(i as i64),
            });
        }

        // Now add 5 more services with later timestamps
        let new_services: Vec<MdnsServiceEntry> = (20..25)
            .map(|i| MdnsServiceEntry {
                service: format!("_service{}.local", i),
                last_seen: base_time + chrono::Duration::seconds(i as i64),
            })
            .collect();

        // Add new services (truncation will happen automatically)
        device.mdns_services.extend(new_services.clone());

        // Deduplicate (simulate merge behavior) - keep most recent timestamp
        let mut seen = HashMap::new();
        for entry in device.mdns_services.iter() {
            match seen.get(&entry.service) {
                Some(existing_timestamp) if entry.last_seen > *existing_timestamp => {
                    seen.insert(entry.service.clone(), entry.last_seen);
                }
                None => {
                    seen.insert(entry.service.clone(), entry.last_seen);
                }
                _ => {}
            }
        }
        let mut deduped = Vec::new();
        for entry in device.mdns_services.iter() {
            if seen.get(&entry.service) == Some(&entry.last_seen) {
                deduped.push(entry.clone());
            }
        }
        device.mdns_services = deduped;
        device.truncate_mdns_services();

        // Should still have exactly 20 services
        assert_eq!(
            device.mdns_services.len(),
            20,
            "Should have exactly 20 services after adding more"
        );

        // Should contain the new services
        for service_entry in new_services.iter() {
            assert!(
                device
                    .mdns_services
                    .iter()
                    .any(|e| e.service == service_entry.service),
                "Should contain new service {}",
                service_entry.service
            );
        }
    }

    #[test]
    fn test_ipv6_insertion_order_preserved() {
        // Test that entries are properly tracked (order doesn't matter since we sort by timestamp)
        let mut device = DeviceInfo::new(Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));

        let addr1 = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let addr2 = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2);
        let addr3 = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 3);

        // Add addresses in order
        device.add_ip_addresses(vec![], vec![addr1]);
        device.add_ip_addresses(vec![], vec![addr2]);
        device.add_ip_addresses(vec![], vec![addr3]);

        // Verify order is preserved
        let addresses: Vec<_> = device.ip_addresses_v6.iter().map(|e| e.address).collect();
        assert_eq!(addresses[0], addr1, "First should be addr1");
        assert_eq!(addresses[1], addr2, "Second should be addr2");
        assert_eq!(addresses[2], addr3, "Third should be addr3");
    }

    #[test]
    fn test_mac_addresses_serialization() {
        // Test that new format serializes and deserializes correctly
        let mac1 = MacAddr6::new(0x00, 0x11, 0x22, 0x33, 0x44, 0x55);
        let timestamp1 = Utc.with_ymd_and_hms(2023, 1, 1, 12, 0, 0).unwrap();

        let entry = MacAddressEntry {
            address: mac1,
            last_seen: timestamp1,
        };

        // Serialize to JSON
        let json = serde_json::to_string(&vec![entry.clone()]).expect("Should serialize");

        // Deserialize back
        let entries: Vec<MacAddressEntry> =
            serde_json::from_str(&json).expect("Should deserialize");

        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].address, mac1);
        assert_eq!(entries[0].last_seen, timestamp1);
    }

    #[test]
    fn test_device_info_mac_addresses_serialization() {
        // Test full DeviceInfo serialization/deserialization
        let mut device = DeviceInfo::new(Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100))));
        device.set_mac_address(MacAddr6::new(0x00, 0x11, 0x22, 0x33, 0x44, 0x55), vec![]);

        // Serialize device
        let json = serde_json::to_string(&device).expect("Should serialize");

        // Deserialize back
        let deserialized: DeviceInfo = serde_json::from_str(&json).expect("Should deserialize");

        assert_eq!(deserialized.mac_addresses.len(), 1);
        assert_eq!(
            deserialized.mac_addresses[0].address,
            MacAddr6::new(0x00, 0x11, 0x22, 0x33, 0x44, 0x55)
        );
    }

    #[test]
    fn test_mac_truncation_keeps_most_recent() {
        // Test that MAC addresses are truncated to keep only the last 10 most recently added
        let mut device = DeviceInfo::new(Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));
        let base_time = Utc::now();

        // Add 15 MAC addresses (should keep only last 10)
        // Use explicit timestamps to ensure deterministic ordering
        // (on fast machines, Utc::now() can return identical timestamps for all entries)
        let mut old_macs = Vec::new();
        for i in 0..5 {
            old_macs.push(MacAddr6::new(0x00, 0x11, 0x22, 0x33, 0x44, i));
        }

        let mut new_macs = Vec::new();
        for i in 5..15 {
            new_macs.push(MacAddr6::new(0x00, 0x11, 0x22, 0x33, 0x44, i));
        }

        // Add old MACs first with earlier timestamp
        let old_timestamp = base_time;
        device.set_mac_address_with_timestamp(old_macs[0], old_macs[1..].to_vec(), old_timestamp);
        // Add new MACs with later timestamp (these should be kept)
        let new_timestamp = base_time + chrono::Duration::seconds(10);
        device.set_mac_address_with_timestamp(new_macs[0], new_macs[1..].to_vec(), new_timestamp);

        // Should have exactly 10 addresses
        assert_eq!(
            device.mac_addresses.len(),
            10,
            "Should have exactly 10 MAC addresses"
        );

        // Should contain the new MACs and not the oldest ones
        for mac in new_macs.iter() {
            assert!(
                device.mac_addresses.iter().any(|e| e.address == *mac),
                "Should contain new MAC {:?}",
                mac
            );
        }

        // Should not contain the oldest MACs
        for mac in old_macs.iter() {
            assert!(
                !device.mac_addresses.iter().any(|e| e.address == *mac),
                "Should not contain old MAC {:?}",
                mac
            );
        }
    }

    #[test]
    fn test_mac_deduplication_preserves_most_recent() {
        // Test that deduplication keeps the most recent occurrence
        let mut device = DeviceInfo::new(Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));

        let mac1 = MacAddr6::new(0x00, 0x11, 0x22, 0x33, 0x44, 0x01);
        let mac2 = MacAddr6::new(0x00, 0x11, 0x22, 0x33, 0x44, 0x02);
        let mac3 = MacAddr6::new(0x00, 0x11, 0x22, 0x33, 0x44, 0x03);

        // Add MACs: mac1, mac2, mac1 (duplicate), mac3
        device.set_mac_address(mac1, vec![]);
        device.set_mac_address(mac2, vec![]);
        device.set_mac_address(mac1, vec![]); // Duplicate
        device.set_mac_address(mac3, vec![]);

        // Should have 3 MACs (mac1 should appear only once)
        assert_eq!(
            device.mac_addresses.len(),
            3,
            "Should have 3 unique MAC addresses"
        );

        // Verify all MACs are present
        let macs: Vec<_> = device.mac_addresses.iter().map(|e| e.address).collect();
        assert!(macs.contains(&mac1), "Should contain mac1");
        assert!(macs.contains(&mac2), "Should contain mac2");
        assert!(macs.contains(&mac3), "Should contain mac3");

        // Verify mac1 appears only once
        let mac1_count = macs.iter().filter(|&&m| m == mac1).count();
        assert_eq!(
            mac1_count, 1,
            "mac1 should appear only once after deduplication"
        );
    }

    #[test]
    fn test_mac_merge_preserves_timestamps() {
        // Test that merging devices preserves MAC address timestamps
        use chrono::{TimeZone, Utc};

        let mut device1 = DeviceInfo::new(Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100))));
        let mac1 = MacAddr6::new(0x00, 0x11, 0x22, 0x33, 0x44, 0x01);
        let timestamp1 = Utc.with_ymd_and_hms(2023, 1, 1, 12, 0, 0).unwrap();
        device1.set_mac_address_with_timestamp(mac1, vec![], timestamp1);

        let mut device2 = DeviceInfo::new(Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100))));
        let mac2 = MacAddr6::new(0x00, 0x11, 0x22, 0x33, 0x44, 0x02);
        let timestamp2 = Utc.with_ymd_and_hms(2023, 1, 1, 13, 0, 0).unwrap();
        device2.set_mac_address_with_timestamp(mac2, vec![], timestamp2);

        // Merge device2 into device1
        DeviceInfo::merge(&mut device1, &device2);

        // Should have both MACs
        assert_eq!(
            device1.mac_addresses.len(),
            2,
            "Should have 2 MAC addresses"
        );

        // Verify both MACs are present with their timestamps
        let mac1_entry = device1
            .mac_addresses
            .iter()
            .find(|e| e.address == mac1)
            .unwrap();
        let mac2_entry = device1
            .mac_addresses
            .iter()
            .find(|e| e.address == mac2)
            .unwrap();

        assert_eq!(
            mac1_entry.last_seen, timestamp1,
            "mac1 timestamp should be preserved"
        );
        assert_eq!(
            mac2_entry.last_seen, timestamp2,
            "mac2 timestamp should be preserved"
        );
    }

    #[test]
    fn test_primary_mac_updated_by_set_mac_address() {
        // Test that set_mac_address updates the primary MAC (by design)
        // This is expected behavior - each call to set_mac_address sets a NEW primary
        let mut device = DeviceInfo::new(Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));

        // Set first primary MAC
        let mac1 = MacAddr6::new(0x10, 0x11, 0x11, 0x11, 0x11, 0x11);
        device.set_mac_address(mac1, vec![]);
        assert_eq!(
            device.get_mac_address(),
            Some(mac1),
            "Primary should be mac1"
        );

        // Set second primary MAC - this UPDATES the primary
        let mac2 = MacAddr6::new(0x22, 0x22, 0x22, 0x22, 0x22, 0x22);
        device.set_mac_address(mac2, vec![]);
        assert_eq!(
            device.get_mac_address(),
            Some(mac2),
            "Primary should now be mac2"
        );

        // Both MACs should be in the list
        assert_eq!(device.mac_addresses.len(), 2);
        assert!(device.mac_addresses.iter().any(|e| e.address == mac1));
        assert!(device.mac_addresses.iter().any(|e| e.address == mac2));
    }

    #[test]
    fn test_primary_mac_protection_in_truncation() {
        // Test that primary MAC is protected from truncation
        // The truncation logic ensures the primary MAC stays in the list
        let mut device = DeviceInfo::new(Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));

        // Set an old primary MAC
        let primary_mac = MacAddr6::new(0xFC, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
        let old_timestamp = Utc.with_ymd_and_hms(2023, 1, 1, 12, 0, 0).unwrap();
        device.set_mac_address_with_timestamp(primary_mac, vec![], old_timestamp);
        assert_eq!(device.get_mac_address(), Some(primary_mac));

        // Add 10 newer MACs WITHOUT calling set_mac_address (to avoid updating primary)
        // Use add_mac_entry directly to simulate discovering new MACs without changing primary
        for i in 0..10 {
            let newer_mac = MacAddr6::new(0x00, 0x11, 0x22, 0x33, 0x44, i);
            let newer_timestamp = Utc.with_ymd_and_hms(2023, 1, 1, 13, i as u32, 0).unwrap();
            device.add_mac_entry(newer_mac, newer_timestamp);
        }

        // Manually trigger dedup and truncate
        device.deduplicate_and_truncate_macs();

        // Should have exactly 10 MACs (truncated from 11)
        assert_eq!(
            device.mac_addresses.len(),
            10,
            "Should have exactly 10 MACs after truncation"
        );

        // Primary MAC should still be the old one
        assert_eq!(
            device.get_mac_address(),
            Some(primary_mac),
            "Primary should not have changed"
        );

        // Primary MAC should be in the list (protection logic)
        let primary_in_list = device
            .mac_addresses
            .iter()
            .any(|e| e.address == primary_mac);
        assert!(
            primary_in_list,
            "Primary MAC should be preserved in the list even if it's the oldest"
        );
    }

    #[test]
    fn test_mac_deduplication_logic_correctness() {
        // Test the deduplication logic with out-of-order timestamps
        let mut device = DeviceInfo::new(Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));

        let mac_a = MacAddr6::new(0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA);
        let t1 = Utc.with_ymd_and_hms(2023, 1, 1, 12, 0, 0).unwrap();
        let t2 = Utc.with_ymd_and_hms(2023, 1, 1, 13, 0, 0).unwrap();
        let t3 = Utc.with_ymd_and_hms(2023, 1, 1, 14, 0, 0).unwrap();

        // Add same MAC with different timestamps in non-chronological order
        device.set_mac_address_with_timestamp(mac_a, vec![], t1);
        device.set_mac_address_with_timestamp(mac_a, vec![], t3); // Newest
        device.set_mac_address_with_timestamp(mac_a, vec![], t2); // Middle

        // Should have only one MAC entry with the newest timestamp
        assert_eq!(
            device.mac_addresses.len(),
            1,
            "Should deduplicate to 1 entry"
        );
        assert_eq!(device.mac_addresses[0].address, mac_a);
        assert_eq!(
            device.mac_addresses[0].last_seen, t3,
            "Should keep the most recent timestamp"
        );
    }

    #[test]
    fn test_group_and_nil_macs_are_never_stored_as_identity() {
        let mut device = DeviceInfo::new(Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100))));
        let now = Utc::now();

        // Broadcast, an arbitrary multicast address, and nil. Capture parsing can
        // surface any of these as a device's address; none names an interface.
        for rejected in [
            MacAddr6::broadcast(),
            MacAddr6::new(0x01, 0x00, 0x5E, 0x00, 0x00, 0xFB), // IPv4 multicast
            MacAddr6::nil(),
        ] {
            device.add_mac_entry(rejected, now);
            device.set_mac_address_with_timestamp(rejected, vec![], now);
        }

        assert!(
            device.mac_addresses.is_empty(),
            "group and nil addresses must not enter the MAC history, got {:?}",
            device.mac_addresses
        );
        assert_eq!(
            device.get_mac_address(),
            None,
            "an address that names no interface must not become the primary"
        );

        // A real unicast address still lands normally.
        let real = MacAddr6::new(0x00, 0x11, 0x22, 0x33, 0x44, 0x55);
        device.set_mac_address_with_timestamp(real, vec![], now);
        assert_eq!(device.get_mac_address(), Some(real));
        assert_eq!(device.mac_addresses.len(), 1);
    }

    #[test]
    fn test_mac_conflict_across_full_history_not_just_primaries() {
        // The loophole this covers: a record whose *primary* is locally administered
        // used to reach the "MAC rotation" escape, letting it absorb a record holding
        // a hardware address that its own history already contradicts. Observed live
        // on 192.168.1.72, which had a randomized primary and had swallowed a
        // universally administered NIC that was simultaneously ARP-reachable at a
        // different address.
        //
        // The timestamps are set far enough apart that the rotation escape would fire
        // and declare "no conflict", so a pass here can only come from comparing the
        // full hardware-address history.
        let now = Utc::now();

        let mut absorber = DeviceInfo::new(Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 72))));
        absorber.device_vendor = "Apple, Inc.".to_string();
        let absorber_hardware = MacAddr6::new(0x00, 0x1B, 0x63, 0x84, 0x45, 0xE6);
        let absorber_randomized = MacAddr6::new(0x9E, 0x2A, 0x77, 0x10, 0x33, 0x0C);
        absorber.add_mac_entry(absorber_hardware, now - chrono::Duration::days(5));
        absorber.add_mac_entry(absorber_randomized, now - chrono::Duration::days(3));
        // The randomized address is the current primary, which is what used to hide
        // the hardware address above from the conflict check.
        absorber.mac_address = Some(absorber_randomized);
        absorber.last_seen = now - chrono::Duration::days(3);

        let mut distinct = DeviceInfo::new(Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 193))));
        distinct.device_vendor = "Apple, Inc.".to_string();
        let distinct_hardware = MacAddr6::new(0xA4, 0xFC, 0x14, 0x2C, 0xA6, 0xCB);
        distinct.add_mac_entry(distinct_hardware, now);
        distinct.mac_address = Some(distinct_hardware);
        distinct.last_seen = now;

        assert!(
            DeviceInfo::has_mac_conflict(&absorber, &distinct),
            "disjoint hardware addresses across the full history are distinct NICs, \
             even when one record's primary is randomized and the two were last seen \
             days apart"
        );
        assert!(
            DeviceInfo::has_conflicting_characteristics(&absorber, &distinct),
            "the conflict must survive to the merge decision"
        );
    }

    #[test]
    fn test_shared_hardware_mac_still_merges_across_history() {
        // The converse of the test above: the widened comparison must not block a
        // genuine merge. One NIC, two records, each having also seen a randomized
        // address, so neither hardware set is disjoint from the other.
        let now = Utc::now();
        let shared_hardware = MacAddr6::new(0x00, 0x1B, 0x63, 0x84, 0x45, 0xE6);

        let mut earlier = DeviceInfo::new(Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100))));
        earlier.device_vendor = "Apple, Inc.".to_string();
        earlier.add_mac_entry(shared_hardware, now - chrono::Duration::days(2));
        earlier.add_mac_entry(
            MacAddr6::new(0x9E, 0x2A, 0x77, 0x10, 0x33, 0x0C),
            now - chrono::Duration::days(2),
        );
        earlier.mac_address = Some(shared_hardware);
        earlier.last_seen = now - chrono::Duration::days(2);

        let mut later = DeviceInfo::new(Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100))));
        later.device_vendor = "Apple, Inc.".to_string();
        let later_randomized = MacAddr6::new(0x6A, 0x55, 0x01, 0xAB, 0xCD, 0xEF);
        later.add_mac_entry(shared_hardware, now);
        later.add_mac_entry(later_randomized, now);
        later.mac_address = Some(later_randomized);
        later.last_seen = now;

        assert!(
            !DeviceInfo::has_mac_conflict(&earlier, &later),
            "records sharing a hardware address are the same NIC and must still merge"
        );
    }

    #[test]
    fn test_randomized_only_records_still_rotate() {
        // Two records that have only ever carried locally administered addresses
        // carry no hardware evidence either way, so the rotation escape must remain
        // reachable -- this is the ordinary iOS/Android privacy case. No hostname is
        // set on either side, because a matching specific hostname would short-circuit
        // the MAC comparison and the test would prove nothing about it.
        let now = Utc::now();

        let mut earlier = DeviceInfo::new(Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100))));
        earlier.device_vendor = "Apple, Inc.".to_string();
        let earlier_mac = MacAddr6::new(0x02, 0x11, 0x22, 0x33, 0x44, 0x55);
        earlier.add_mac_entry(earlier_mac, now - chrono::Duration::days(3));
        earlier.mac_address = Some(earlier_mac);
        earlier.last_seen = now - chrono::Duration::days(3);

        let mut later = DeviceInfo::new(Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100))));
        later.device_vendor = "Apple, Inc.".to_string();
        let later_mac = MacAddr6::new(0x02, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE);
        later.add_mac_entry(later_mac, now);
        later.mac_address = Some(later_mac);
        later.last_seen = now;

        assert!(
            !DeviceInfo::has_mac_conflict(&earlier, &later),
            "randomized-only records carry no hardware evidence and must still rotate"
        );
    }

    #[test]
    fn test_non_host_ipv4_is_not_stored_as_identity() {
        // The history list is merge evidence, so an address that names no single
        // host must never reach it. A record that collected one 169.254 address per
        // DHCP failure would otherwise start matching every other host that ever
        // fell back to link-local.
        let now = Utc::now();
        let mut device = DeviceInfo::new(Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 50))));
        let baseline = device.ip_addresses_v4.len();

        let refused = [
            Ipv4Addr::new(169, 254, 13, 7),    // DHCP-failure fallback
            Ipv4Addr::new(255, 255, 255, 255), // global broadcast
            Ipv4Addr::new(224, 0, 0, 251),     // mDNS multicast
            Ipv4Addr::new(127, 0, 0, 1),       // loopback
            Ipv4Addr::new(0, 0, 0, 0),         // unspecified
        ];
        for addr in refused {
            device.add_ipv4_entry(addr, now);
        }
        assert_eq!(
            device.ip_addresses_v4.len(),
            baseline,
            "non-host addresses must be refused at ingestion, got {:?}",
            device.ip_addresses_v4
        );
        for addr in refused {
            assert!(
                !device.ip_addresses_v4.iter().any(|e| e.address == addr),
                "{addr} names no single host and must not appear in identity history"
            );
        }

        device.add_ipv4_entry(Ipv4Addr::new(192, 168, 9, 50), now);
        assert!(
            device
                .ip_addresses_v4
                .iter()
                .any(|e| e.address == Ipv4Addr::new(192, 168, 9, 50)),
            "a real host address must still be recorded"
        );
    }

    #[test]
    fn test_shared_link_local_ipv4_does_not_merge_distinct_devices() {
        // Two unrelated hosts that both fell back to the same link-local address.
        // Distinct hardware MACs, distinct hostnames -- nothing but the fallback
        // address in common, which is not enough.
        let now = Utc::now();

        let mut a = DeviceInfo::new(Some(IpAddr::V4(Ipv4Addr::new(169, 254, 13, 7))));
        a.hostname = "printer-a.local".to_string();
        let mac_a = MacAddr6::new(0x3C, 0x22, 0xFB, 0x11, 0x11, 0x11);
        a.set_mac_address_with_timestamp(mac_a, vec![], now);
        a.last_seen = now;

        let mut b = DeviceInfo::new(Some(IpAddr::V4(Ipv4Addr::new(169, 254, 13, 7))));
        b.hostname = "laptop-b.local".to_string();
        let mac_b = MacAddr6::new(0xB8, 0x27, 0xEB, 0x22, 0x22, 0x22);
        b.set_mac_address_with_timestamp(mac_b, vec![], now);
        b.last_seen = now;

        let mut devices = vec![a, b];
        DeviceInfo::dedup_vec(&mut devices);
        assert_eq!(
            devices.len(),
            2,
            "a shared DHCP-failure fallback address is not evidence of one device"
        );
    }

    #[test]
    fn test_shared_routable_ipv4_still_merges() {
        // Same shape as the link-local case above but on a routable address, which
        // does name one endpoint. This is the guard against over-tightening: the
        // ordinary "same IP, same host" merge must keep working.
        let now = Utc::now();

        let mut a = DeviceInfo::new(Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 60))));
        a.hostname = "nas.local".to_string();
        a.last_seen = now - chrono::Duration::minutes(5);

        let mut b = DeviceInfo::new(Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 60))));
        b.hostname = "nas.local".to_string();
        b.last_seen = now;

        let mut devices = vec![a, b];
        DeviceInfo::dedup_vec(&mut devices);
        assert_eq!(
            devices.len(),
            1,
            "a shared routable address with a matching hostname is one device"
        );
    }

    #[test]
    fn test_legacy_non_host_ipv4_history_is_screened_at_merge_time() {
        // Records persisted before ingestion filtering existed still hold non-host
        // addresses, so the merge path has to screen them too.
        //
        // The two cases below are the same fixture except for the class of the
        // shared historical address, and the shared hostname is deliberately
        // generic so is_safe_hostname_merge refuses the hostname-only path. That
        // leaves ipv4_confirmed as the only route to a merge, so the differing
        // outcomes isolate exactly the address-class check.
        let build_pair = |shared: Ipv4Addr| {
            let now = Utc::now();

            let mut a = DeviceInfo::new(Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 61))));
            a.hostname = "printer".to_string();
            a.device_vendor = "Acme".to_string();
            a.last_seen = now;
            // Bypass add_ipv4_entry to model a record written by an older build.
            a.ip_addresses_v4.push(IpAddressEntry {
                address: shared,
                last_seen: now,
            });

            let mut b = DeviceInfo::new(Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 62))));
            b.hostname = "printer".to_string();
            b.device_vendor = "Acme".to_string();
            b.last_seen = now;
            b.ip_addresses_v4.push(IpAddressEntry {
                address: shared,
                last_seen: now,
            });

            // Sanity: the records really do overlap on the shared historical address.
            assert!(a
                .ip_addresses_v4
                .iter()
                .any(|e| b.ip_addresses_v4.iter().any(|o| o.address == e.address)));

            vec![a, b]
        };

        let mut stale = build_pair(Ipv4Addr::new(169, 254, 13, 7));
        DeviceInfo::dedup_vec(&mut stale);
        assert_eq!(
            stale.len(),
            2,
            "stale non-host history must not supply the overlap that confirms a merge"
        );

        let mut routable = build_pair(Ipv4Addr::new(192, 168, 77, 7));
        DeviceInfo::dedup_vec(&mut routable);
        assert_eq!(
            routable.len(),
            1,
            "a shared host address in history must still confirm the merge"
        );
    }

    #[test]
    fn test_mac_conflict_detection_privacy_rotation() {
        // Test that devices with privacy MAC rotation are allowed to merge
        // Scenario: iOS device with rotating MACs seen at different times
        let mut device1 = DeviceInfo::new(Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100))));
        device1.hostname = "iphone-specific.local".to_string();
        device1.device_vendor = "Apple Inc.".to_string();
        let mac1 = MacAddr6::new(0x02, 0x11, 0x22, 0x33, 0x44, 0x55); // Privacy MAC
        let yesterday = Utc::now() - chrono::Duration::days(1);
        device1.add_mac_entry(mac1, yesterday);
        device1.mac_address = Some(mac1);
        device1.last_seen = yesterday;

        let mut device2 = DeviceInfo::new(Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100))));
        device2.hostname = "iphone-specific.local".to_string();
        device2.device_vendor = "Apple Inc.".to_string();
        let mac2 = MacAddr6::new(0x02, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE); // Different privacy MAC
        let now = Utc::now();
        device2.add_mac_entry(mac2, now);
        device2.mac_address = Some(mac2);
        device2.last_seen = now;

        // MACs are 24+ hours apart - should NOT be a conflict (privacy rotation)
        let has_conflict = DeviceInfo::has_conflicting_characteristics(&device1, &device2);
        assert!(
            !has_conflict,
            "Should allow merge: different MACs seen 24+ hours apart (privacy rotation)"
        );
    }

    #[test]
    fn test_mac_conflict_detection_simultaneous_fresh_macs() {
        // Test that two devices with fresh different MACs are detected as conflict
        // Scenario: Two different devices on network with different MACs, both recently seen
        let mut device1 = DeviceInfo::new(Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100))));
        device1.device_vendor = "Apple Inc.".to_string();
        let mac1 = MacAddr6::new(0x00, 0x11, 0x22, 0x33, 0x44, 0x55);
        let now = Utc::now();
        device1.add_mac_entry(mac1, now);
        device1.mac_address = Some(mac1);
        device1.last_seen = now;

        let mut device2 = DeviceInfo::new(Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 101))));
        device2.device_vendor = "Apple Inc.".to_string();
        let mac2 = MacAddr6::new(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF);
        device2.add_mac_entry(mac2, now);
        device2.mac_address = Some(mac2);
        device2.last_seen = now;

        // Both MACs fresh (< 1 hour) and different - should be a conflict
        let has_conflict = DeviceInfo::has_conflicting_characteristics(&device1, &device2);
        assert!(
            has_conflict,
            "Should detect conflict: different fresh MACs (< 1h old) suggest different devices"
        );
    }

    #[test]
    fn test_mac_conflict_detection_overlapping_macs() {
        // Test that devices with overlapping MAC lists are allowed to merge
        // Scenario: Same device seen multiple times, accumulated different MACs
        let mut device1 = DeviceInfo::new(Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100))));
        device1.device_vendor = "Apple Inc.".to_string();
        let shared_mac = MacAddr6::new(0x00, 0x11, 0x22, 0x33, 0x44, 0x55);
        let mac1_only = MacAddr6::new(0x02, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE);
        device1.add_mac_entry(shared_mac, Utc::now());
        device1.add_mac_entry(mac1_only, Utc::now());
        device1.mac_address = Some(mac1_only);

        let mut device2 = DeviceInfo::new(Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100))));
        device2.device_vendor = "Apple Inc.".to_string();
        let mac2_only = MacAddr6::new(0x02, 0x11, 0x22, 0x33, 0x44, 0x66);
        device2.add_mac_entry(shared_mac, Utc::now()); // Same MAC!
        device2.add_mac_entry(mac2_only, Utc::now());
        device2.mac_address = Some(mac2_only);

        // MAC overlap detected - should NOT be a conflict
        let has_conflict = DeviceInfo::has_conflicting_characteristics(&device1, &device2);
        assert!(
            !has_conflict,
            "Should allow merge: MAC overlap indicates same device with multiple MACs"
        );
    }

    #[test]
    fn test_mac_conflict_detection_with_safe_hostname() {
        // Test that specific hostname bypasses MAC conflict check
        let mut device1 = DeviceInfo::new(Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100))));
        device1.hostname = "johns-specific-macbook.local".to_string();
        device1.device_vendor = "Apple Inc.".to_string();
        let mac1 = MacAddr6::new(0x11, 0x11, 0x11, 0x11, 0x11, 0x11);
        device1.add_mac_entry(mac1, Utc::now());
        device1.mac_address = Some(mac1);

        let mut device2 = DeviceInfo::new(Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 101))));
        device2.hostname = "johns-specific-macbook.local".to_string();
        device2.device_vendor = "Apple Inc.".to_string();
        let mac2 = MacAddr6::new(0x22, 0x22, 0x22, 0x22, 0x22, 0x22); // Different MAC
        device2.add_mac_entry(mac2, Utc::now());
        device2.mac_address = Some(mac2);

        // Specific hostname - should NOT be a conflict even with fresh different MACs
        let has_conflict = DeviceInfo::has_conflicting_characteristics(&device1, &device2);
        assert!(
            !has_conflict,
            "Should allow merge: specific hostname overrides MAC conflict"
        );
    }

    #[test]
    fn test_update_primary_ip_from_entries() {
        // Test that primary IP is selected based on entry timestamps
        // Start with an empty device and manually set up entries
        let mut device = DeviceInfo::new(None);

        let old_time = Utc.with_ymd_and_hms(2023, 1, 1, 12, 0, 0).unwrap();
        let new_time = Utc.with_ymd_and_hms(2023, 1, 2, 12, 0, 0).unwrap();

        // Clear default entries and add controlled ones
        device.ip_addresses_v4.clear();
        device.add_ipv4_entry(Ipv4Addr::new(192, 168, 1, 10), old_time);
        device.add_ipv4_entry(Ipv4Addr::new(192, 168, 1, 20), new_time);

        // Update primary from entries
        device.update_primary_ip_from_entries();

        // Should select the most recent IPv4
        assert_eq!(
            device.get_ip_address(),
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 20)),
            "Primary IP should be the most recently seen IPv4"
        );
    }

    #[test]
    fn test_update_primary_ip_ipv4_precedence() {
        // Test that IPv4 takes precedence over IPv6
        let mut device = DeviceInfo::new(None);

        let same_time = Utc.with_ymd_and_hms(2023, 1, 1, 12, 0, 0).unwrap();

        // Clear default entries and add controlled ones
        device.ip_addresses_v4.clear();
        device.ip_addresses_v6.clear();
        device.add_ipv4_entry(Ipv4Addr::new(192, 168, 1, 10), same_time);
        device.add_ipv6_entry(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1), same_time);

        // Update primary from entries
        device.update_primary_ip_from_entries();

        // Should select IPv4 (takes precedence)
        assert!(
            matches!(device.get_ip_address(), IpAddr::V4(_)),
            "IPv4 should take precedence over IPv6"
        );
    }

    #[test]
    fn test_update_primary_ip_ipv6_much_newer() {
        // Test that IPv6 wins if it's significantly newer (> 24h)
        let mut device = DeviceInfo::new(None);

        let old_time = Utc.with_ymd_and_hms(2023, 1, 1, 12, 0, 0).unwrap();
        let much_newer_time = Utc.with_ymd_and_hms(2023, 1, 3, 12, 0, 0).unwrap(); // 48 hours later

        // Clear default entries and add controlled ones
        device.ip_addresses_v4.clear();
        device.ip_addresses_v6.clear();
        device.add_ipv4_entry(Ipv4Addr::new(192, 168, 1, 10), old_time);
        device.add_ipv6_entry(
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
            much_newer_time,
        );

        // Update primary from entries
        device.update_primary_ip_from_entries();

        // Should select IPv6 (much newer)
        assert!(
            matches!(device.get_ip_address(), IpAddr::V6(_)),
            "IPv6 should win if significantly newer than IPv4"
        );
    }

    #[test]
    fn test_validate_timestamps_future() {
        // Test that future timestamps are clamped to now
        let mut device = DeviceInfo::new(Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));

        let future_time = Utc::now() + chrono::Duration::hours(24);

        device.first_seen = future_time;
        device.last_seen = future_time;
        device.add_ipv4_entry(Ipv4Addr::new(192, 168, 1, 10), future_time);

        let modified = device.validate_timestamps();

        assert!(modified, "Should have modified timestamps");
        assert!(
            device.first_seen <= Utc::now(),
            "first_seen should be clamped to now"
        );
        assert!(
            device.last_seen <= Utc::now(),
            "last_seen should be clamped to now"
        );
        assert!(
            device.ip_addresses_v4[0].last_seen <= Utc::now(),
            "IPv4 entry timestamp should be clamped"
        );
    }

    #[test]
    fn test_validate_timestamps_epoch() {
        // Test that epoch timestamps are treated as invalid
        let mut device = DeviceInfo::new(Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));

        let epoch = DateTime::<Utc>::from(std::time::UNIX_EPOCH);

        device.first_seen = epoch;
        device.last_seen = epoch;

        let modified = device.validate_timestamps();

        assert!(modified, "Should have modified timestamps");
        assert!(
            device.first_seen > epoch,
            "first_seen should be updated from epoch"
        );
        assert!(
            device.last_seen > epoch,
            "last_seen should be updated from epoch"
        );
    }

    #[test]
    fn test_validate_timestamps_normal() {
        // Test that normal timestamps are not modified (including old historical ones)
        let mut device = DeviceInfo::new(Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));

        // Use an old timestamp from 2 years ago - this should be preserved
        let old_time = Utc.with_ymd_and_hms(2022, 1, 1, 12, 0, 0).unwrap();

        device.first_seen = old_time;
        device.last_seen = old_time;
        device.ip_addresses_v4.clear();
        device.add_ipv4_entry(Ipv4Addr::new(192, 168, 1, 10), old_time);

        let modified = device.validate_timestamps();

        assert!(
            !modified,
            "Should not have modified valid historical timestamps"
        );
        assert_eq!(device.first_seen, old_time);
        assert_eq!(device.last_seen, old_time);
        assert_eq!(device.ip_addresses_v4[0].last_seen, old_time);
    }

    #[test]
    fn test_ipv6_overlap_triggers_merge() {
        // Same IPv6 = same device (IPv6 collision is essentially impossible)
        let old_time = Utc.with_ymd_and_hms(2020, 1, 1, 12, 0, 0).unwrap();

        let mut device1 = DeviceInfo::new(Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100))));
        device1.device_vendor = "Apple Inc.".to_string();
        device1.ip_addresses_v6.push(IpAddressEntry {
            address: Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0xABCD),
            last_seen: old_time,
        });

        let mut device2 = DeviceInfo::new(Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100))));
        device2.device_vendor = "Apple Inc.".to_string(); // Same vendor
        device2.ip_addresses_v6.push(IpAddressEntry {
            address: Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0xABCD),
            last_seen: old_time,
        });

        // Should merge - same IPv6 means same device, regardless of timestamp age
        let mut devices = vec![device1];
        let new_devices = vec![device2];

        DeviceInfo::merge_vec(&mut devices, &new_devices);

        assert_eq!(
            devices.len(),
            1,
            "Same IPv6 = same device, should merge regardless of timestamp age"
        );
    }

    #[test]
    fn test_ipv6_overlap_blocked_by_vendor_conflict() {
        // Same IPv6 but different vendors - vendor conflict blocks merge
        let time = Utc.with_ymd_and_hms(2023, 1, 1, 12, 0, 0).unwrap();

        let mut device1 = DeviceInfo::new(Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100))));
        device1.device_vendor = "Apple Inc.".to_string();
        device1.ip_addresses_v6.push(IpAddressEntry {
            address: Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0xABCD),
            last_seen: time,
        });

        let mut device2 = DeviceInfo::new(Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 101))));
        device2.device_vendor = "Samsung".to_string(); // Different vendor = conflict
        device2.ip_addresses_v6.push(IpAddressEntry {
            address: Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0xABCD),
            last_seen: time,
        });

        // Should NOT merge - vendor conflict blocks the merge
        let mut devices = vec![device1];
        let new_devices = vec![device2];

        DeviceInfo::merge_vec(&mut devices, &new_devices);

        assert_eq!(
            devices.len(),
            2,
            "Vendor conflict should block merge even with IPv6 overlap"
        );
    }

    #[test]
    fn test_merge_updates_primary_from_entries() {
        // Test that merge updates primary IP based on entry timestamps
        let old_time = Utc.with_ymd_and_hms(2023, 1, 1, 12, 0, 0).unwrap();
        let new_time = Utc.with_ymd_and_hms(2023, 1, 2, 12, 0, 0).unwrap();

        // Create device1 with controlled timestamps
        let mut device1 = DeviceInfo::new(None);
        device1.ip_addresses_v4.clear();
        device1.add_ipv4_entry(Ipv4Addr::new(192, 168, 1, 10), old_time);
        device1.ip_address = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10));
        device1.last_seen = old_time;
        device1.is_local = true;

        // Create device2 with matching IP (for merge) but newer additional IP
        let mut device2 = DeviceInfo::new(None);
        device2.ip_addresses_v4.clear();
        device2.add_ipv4_entry(Ipv4Addr::new(192, 168, 1, 10), old_time);
        device2.add_ipv4_entry(Ipv4Addr::new(192, 168, 1, 20), new_time);
        device2.ip_address = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10));
        device2.last_seen = new_time;
        device2.is_local = true;

        DeviceInfo::merge(&mut device1, &device2);

        // Primary should be the most recently seen IPv4
        assert_eq!(
            device1.get_ip_address(),
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 20)),
            "After merge, primary should be the most recent IPv4 entry"
        );
    }

    #[test]
    fn test_network_change_same_mac_different_ipv4() {
        // Scenario: Device moves to a different network (gets new DHCP lease)
        // Same MAC, different IPv4 - should merge because MAC = same physical device
        let t1 = Utc.with_ymd_and_hms(2023, 1, 1, 12, 0, 0).unwrap();
        let t2 = Utc.with_ymd_and_hms(2023, 1, 2, 12, 0, 0).unwrap();

        let mac = MacAddr6::new(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF);

        let mut device1 = DeviceInfo::new(None);
        device1.ip_addresses_v4.clear();
        device1.add_ipv4_entry(Ipv4Addr::new(192, 168, 1, 100), t1);
        device1.ip_address = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));
        device1.add_mac_entry(mac, t1);
        device1.mac_address = Some(mac);
        device1.last_seen = t1;
        device1.is_local = true;

        // Same device on new network (192.168.2.x instead of 192.168.1.x)
        let mut device2 = DeviceInfo::new(None);
        device2.ip_addresses_v4.clear();
        device2.add_ipv4_entry(Ipv4Addr::new(192, 168, 2, 50), t2);
        device2.ip_address = IpAddr::V4(Ipv4Addr::new(192, 168, 2, 50));
        device2.add_mac_entry(mac, t2);
        device2.mac_address = Some(mac);
        device2.last_seen = t2;
        device2.is_local = true;

        // Put both devices in same list and use dedup_vec (which merges by MAC)
        let mut devices = vec![device1, device2];
        DeviceInfo::dedup_vec(&mut devices);

        assert_eq!(
            devices.len(),
            1,
            "Should merge devices with same MAC (MAC = same physical device)"
        );
        assert_eq!(
            devices[0].get_ip_address(),
            IpAddr::V4(Ipv4Addr::new(192, 168, 2, 50)),
            "Primary IP should be the newer one after network change"
        );
        assert_eq!(
            devices[0].ip_addresses_v4.len(),
            2,
            "Both IPv4 addresses should be preserved in history"
        );
    }

    #[test]
    fn test_mac_match_merges_regardless_of_timestamp_age() {
        // Same MAC = same physical device, regardless of how old the timestamps are
        // MAC collision is essentially impossible
        let old_time = Utc.with_ymd_and_hms(2020, 1, 1, 12, 0, 0).unwrap(); // 4+ years ago

        let mac = MacAddr6::new(0xDD, 0xEE, 0xFF, 0x11, 0x22, 0x33);

        let mut device1 = DeviceInfo::new(Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100))));
        device1.device_vendor = "Apple Inc.".to_string();
        device1.add_mac_entry(mac, old_time);
        device1.mac_address = Some(mac);
        device1.last_seen = old_time;

        let mut device2 = DeviceInfo::new(Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100))));
        device2.device_vendor = "Apple Inc.".to_string(); // Same vendor
        device2.add_mac_entry(mac, old_time);
        device2.mac_address = Some(mac);
        device2.last_seen = old_time;

        // Should merge - same MAC means same device, period
        let mut devices = vec![device1, device2];
        DeviceInfo::dedup_vec(&mut devices);

        assert_eq!(
            devices.len(),
            1,
            "Same MAC = same device, should merge regardless of timestamp age"
        );
    }

    #[test]
    fn test_ipv6_only_device_primary_selection() {
        // Test device with only IPv6 addresses (no IPv4)
        let mut device = DeviceInfo::new(None);

        let t1 = Utc.with_ymd_and_hms(2023, 1, 1, 12, 0, 0).unwrap();
        let t2 = Utc.with_ymd_and_hms(2023, 1, 2, 12, 0, 0).unwrap();

        device.ip_addresses_v4.clear();
        device.ip_addresses_v6.clear();

        // Add two IPv6 addresses
        device.add_ipv6_entry(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1), t1);
        device.add_ipv6_entry(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2), t2);

        device.update_primary_ip_from_entries();

        // Should select the most recent IPv6
        assert_eq!(
            device.get_ip_address(),
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2)),
            "Primary should be the most recent IPv6 when no IPv4"
        );
    }

    #[test]
    fn test_update_primary_ip_no_entries() {
        // Test update_primary_ip_from_entries when there are no entries
        let mut device = DeviceInfo::new(Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));

        // Clear all entries
        device.ip_addresses_v4.clear();
        device.ip_addresses_v6.clear();

        let original_ip = device.get_ip_address();
        device.update_primary_ip_from_entries();

        // Should keep the current primary (no change)
        assert_eq!(
            device.get_ip_address(),
            original_ip,
            "Should keep current primary when no entries"
        );
    }

    #[test]
    fn test_same_timestamp_entries() {
        // Test handling of entries with identical timestamps
        let same_time = Utc.with_ymd_and_hms(2023, 1, 1, 12, 0, 0).unwrap();

        let mut device = DeviceInfo::new(None);
        device.ip_addresses_v4.clear();

        // Add multiple entries with same timestamp
        device.add_ipv4_entry(Ipv4Addr::new(192, 168, 1, 10), same_time);
        device.add_ipv4_entry(Ipv4Addr::new(192, 168, 1, 20), same_time);
        device.add_ipv4_entry(Ipv4Addr::new(192, 168, 1, 30), same_time);

        // Should have all entries
        assert_eq!(
            device.ip_addresses_v4.len(),
            3,
            "All entries with same timestamp should be preserved"
        );

        device.update_primary_ip_from_entries();

        // Should select one consistently (max_by_key is deterministic)
        assert!(
            matches!(device.get_ip_address(), IpAddr::V4(_)),
            "Should select one of the IPv4 addresses"
        );
    }

    #[test]
    fn test_local_vs_community_data_priority() {
        // Fresh local data should take priority over stale community data
        let old_time = Utc.with_ymd_and_hms(2023, 1, 1, 12, 0, 0).unwrap();
        let new_time = Utc.with_ymd_and_hms(2023, 1, 2, 12, 0, 0).unwrap();

        // Local device with fresh data
        let mut local_device = DeviceInfo::new(None);
        local_device.ip_addresses_v4.clear();
        local_device.add_ipv4_entry(Ipv4Addr::new(192, 168, 1, 100), new_time);
        local_device.ip_address = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));
        local_device.hostname = "my-device.local".to_string();
        local_device.last_seen = new_time;
        local_device.is_local = true;

        // Community device with older data (same IP)
        let mut community_device = DeviceInfo::new(None);
        community_device.ip_addresses_v4.clear();
        community_device.add_ipv4_entry(Ipv4Addr::new(192, 168, 1, 100), old_time);
        community_device.ip_address = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));
        community_device.hostname = "old-name.local".to_string();
        community_device.last_seen = old_time;
        community_device.is_local = false;

        DeviceInfo::merge(&mut local_device, &community_device);

        // Local device's last_seen should not be downgraded
        assert_eq!(
            local_device.last_seen, new_time,
            "Local last_seen should not be overwritten by older community data"
        );

        // is_local should still be true
        assert!(
            local_device.is_local,
            "is_local should remain true after merge with non-local"
        );
    }

    #[test]
    fn test_merge_ipv4_list_accumulation() {
        // Test that IPv4 list doesn't grow unboundedly through merges
        // Even though IPv4 is stable, we merge data from multiple sources
        let base_time = Utc.with_ymd_and_hms(2023, 1, 1, 12, 0, 0).unwrap();

        let mut device = DeviceInfo::new(None);
        device.ip_addresses_v4.clear();
        device.is_local = true;

        // Simulate multiple merges adding different IPv4 addresses
        for i in 0..15 {
            let mut new_device = DeviceInfo::new(None);
            new_device.ip_addresses_v4.clear();
            let time = base_time + chrono::Duration::hours(i as i64);
            new_device.add_ipv4_entry(Ipv4Addr::new(192, 168, 1, i as u8 + 1), time);
            new_device.ip_address = IpAddr::V4(Ipv4Addr::new(192, 168, 1, i as u8 + 1));
            new_device.last_seen = time;
            new_device.is_local = true;

            DeviceInfo::merge(&mut device, &new_device);
        }

        // IPv4 list should have some entries but potentially bounded
        // (Currently no explicit limit on IPv4, but test documents behavior)
        assert!(
            device.ip_addresses_v4.len() <= 15,
            "IPv4 list should not exceed number of unique IPs added"
        );

        // Primary should be the most recent
        assert_eq!(
            device.get_ip_address(),
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 15)),
            "Primary should be the most recently seen IPv4"
        );
    }

    #[test]
    fn test_ipv4_overlap_alone_does_not_merge() {
        // IPv4 addresses are frequently reused by DHCP
        // IPv4 overlap alone (without MAC or hostname confirmation) should NOT trigger merge
        let time = Utc.with_ymd_and_hms(2023, 1, 1, 12, 0, 0).unwrap();

        // Device 1: had IP 192.168.1.100 in the past
        let mut device1 = DeviceInfo::new(Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 50))));
        device1.hostname = "device-a.local".to_string();
        device1.add_ipv4_entry(Ipv4Addr::new(192, 168, 1, 100), time); // Historical IP
        device1.last_seen = time;

        // Device 2: also had IP 192.168.1.100 (DHCP reused it)
        let mut device2 = DeviceInfo::new(Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 60))));
        device2.hostname = "device-b.local".to_string(); // Different hostname
        device2.add_ipv4_entry(Ipv4Addr::new(192, 168, 1, 100), time); // Same historical IP
        device2.last_seen = time;

        // Should NOT merge - IPv4 overlap but no MAC or hostname confirmation
        let mut devices = vec![device1];
        let new_devices = vec![device2];
        DeviceInfo::merge_vec(&mut devices, &new_devices);

        assert_eq!(
            devices.len(),
            2,
            "IPv4 overlap alone should NOT trigger merge (IPs are reused by DHCP)"
        );
    }

    #[test]
    fn test_ipv4_overlap_with_mac_confirmation_merges() {
        // IPv4 overlap WITH MAC confirmation should merge
        let time = Utc.with_ymd_and_hms(2023, 1, 1, 12, 0, 0).unwrap();
        let mac = MacAddr6::new(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x10);

        // Device 1: had IP 192.168.1.100 in the past
        let mut device1 = DeviceInfo::new(Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 50))));
        device1.hostname = "device.local".to_string();
        device1.add_ipv4_entry(Ipv4Addr::new(192, 168, 1, 100), time);
        device1.add_mac_entry(mac, time);
        device1.mac_address = Some(mac);
        device1.last_seen = time;

        // Device 2: same MAC (confirms same device)
        let mut device2 = DeviceInfo::new(Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 60))));
        device2.hostname = "device.local".to_string();
        device2.add_ipv4_entry(Ipv4Addr::new(192, 168, 1, 100), time);
        device2.add_mac_entry(mac, time);
        device2.mac_address = Some(mac);
        device2.last_seen = time;

        // Should merge - IPv4 overlap confirmed by MAC
        let mut devices = vec![device1];
        let new_devices = vec![device2];
        DeviceInfo::merge_vec(&mut devices, &new_devices);

        assert_eq!(
            devices.len(),
            1,
            "IPv4 overlap with MAC confirmation should merge"
        );
    }

    #[test]
    fn test_ipv4_overlap_with_hostname_confirmation_merges() {
        // IPv4 overlap WITH hostname confirmation should merge
        let time = Utc.with_ymd_and_hms(2023, 1, 1, 12, 0, 0).unwrap();

        // Device 1: had IP 192.168.1.100 in the past
        let mut device1 = DeviceInfo::new(Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 50))));
        device1.hostname = "johns-macbook-pro.local".to_string(); // Specific hostname
        device1.add_ipv4_entry(Ipv4Addr::new(192, 168, 1, 100), time);
        device1.last_seen = time;

        // Device 2: same hostname (confirms same device)
        let mut device2 = DeviceInfo::new(Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 60))));
        device2.hostname = "johns-macbook-pro.local".to_string(); // Same hostname
        device2.add_ipv4_entry(Ipv4Addr::new(192, 168, 1, 100), time);
        device2.last_seen = time;

        // Should merge - IPv4 overlap confirmed by hostname
        let mut devices = vec![device1];
        let new_devices = vec![device2];
        DeviceInfo::merge_vec(&mut devices, &new_devices);

        assert_eq!(
            devices.len(),
            1,
            "IPv4 overlap with hostname confirmation should merge"
        );
    }

    #[test]
    fn test_ipv6_overlap_blocked_by_vendor_conflict_dedup() {
        // Two devices with same IPv6 but different vendors
        // Vendor conflict should block the merge
        let time = Utc.with_ymd_and_hms(2023, 1, 1, 12, 0, 0).unwrap();

        // Device 1: Apple device
        let mut device1 = DeviceInfo::new(Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10))));
        device1.device_vendor = "Apple Inc.".to_string();
        device1.hostname = "johns-macbook.local".to_string();
        let mac1 = MacAddr6::new(0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA);
        device1.add_mac_entry(mac1, time);
        device1.mac_address = Some(mac1);
        device1.last_seen = time;
        device1.ip_addresses_v6.push(IpAddressEntry {
            address: Ipv6Addr::new(0xfe80, 0, 0, 0, 0x1234, 0x5678, 0x9abc, 0xdef0),
            last_seen: time,
        });

        // Device 2: Samsung device - different vendor
        let mut device2 = DeviceInfo::new(Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 20))));
        device2.device_vendor = "Samsung".to_string(); // Different vendor = conflict
        device2.hostname = "galaxy-phone.local".to_string();
        let mac2 = MacAddr6::new(0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB);
        device2.add_mac_entry(mac2, time);
        device2.mac_address = Some(mac2);
        device2.last_seen = time;
        // Same IPv6
        device2.ip_addresses_v6.push(IpAddressEntry {
            address: Ipv6Addr::new(0xfe80, 0, 0, 0, 0x1234, 0x5678, 0x9abc, 0xdef0),
            last_seen: time,
        });

        let mut devices = vec![device1.clone(), device2.clone()];

        // Should NOT merge - vendor conflict blocks the merge
        DeviceInfo::dedup_vec(&mut devices);

        assert_eq!(
            devices.len(),
            2,
            "Vendor conflict should block merge even with IPv6 overlap"
        );
    }

    #[test]
    fn test_merge_preserves_all_entry_timestamps() {
        // Comprehensive test: merge should preserve individual timestamps for all entry types
        let t1 = Utc.with_ymd_and_hms(2023, 1, 1, 10, 0, 0).unwrap();
        let t2 = Utc.with_ymd_and_hms(2023, 1, 1, 11, 0, 0).unwrap();
        let t3 = Utc.with_ymd_and_hms(2023, 1, 1, 12, 0, 0).unwrap();
        let t4 = Utc.with_ymd_and_hms(2023, 1, 1, 13, 0, 0).unwrap();

        let mut device1 = DeviceInfo::new(None);
        device1.ip_addresses_v4.clear();
        device1.ip_addresses_v6.clear();
        device1.mac_addresses.clear();
        device1.mdns_services.clear();
        device1.is_local = true;

        // Device 1: older entries
        device1.add_ipv4_entry(Ipv4Addr::new(192, 168, 1, 10), t1);
        device1.add_ipv6_entry(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1), t1);
        device1.add_mac_entry(MacAddr6::new(0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA), t1);
        device1.add_mdns_entry("_http._tcp.local".to_string(), t1);
        device1.ip_address = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10));
        device1.last_seen = t2;

        let mut device2 = DeviceInfo::new(None);
        device2.ip_addresses_v4.clear();
        device2.ip_addresses_v6.clear();
        device2.mac_addresses.clear();
        device2.mdns_services.clear();
        device2.is_local = true;

        // Device 2: newer entries for some, same for others
        device2.add_ipv4_entry(Ipv4Addr::new(192, 168, 1, 10), t3); // Same IP, newer timestamp
        device2.add_ipv6_entry(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2), t3); // New IPv6
        device2.add_mac_entry(MacAddr6::new(0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA), t3); // Same MAC, newer
        device2.add_mdns_entry("_ssh._tcp.local".to_string(), t4); // New service
        device2.ip_address = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10));
        device2.last_seen = t4;

        DeviceInfo::merge(&mut device1, &device2);

        // Check IPv4: same IP should have updated timestamp
        let ipv4_entry = device1
            .ip_addresses_v4
            .iter()
            .find(|e| e.address == Ipv4Addr::new(192, 168, 1, 10));
        assert!(ipv4_entry.is_some());
        assert_eq!(
            ipv4_entry.unwrap().last_seen,
            t3,
            "IPv4 timestamp should be updated to newer"
        );

        // Check IPv6: should have both entries
        assert_eq!(
            device1.ip_addresses_v6.len(),
            2,
            "Should have both IPv6 entries"
        );

        // Check MAC: should have updated timestamp
        let mac_entry = device1
            .mac_addresses
            .iter()
            .find(|e| e.address == MacAddr6::new(0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA));
        assert!(mac_entry.is_some());
        assert_eq!(
            mac_entry.unwrap().last_seen,
            t3,
            "MAC timestamp should be updated to newer"
        );

        // Check mDNS: should have both services
        assert_eq!(
            device1.mdns_services.len(),
            2,
            "Should have both mDNS services"
        );
    }

    #[test]
    fn test_community_timestamp_validation_on_merge() {
        // Test that validate_timestamps is effective before merge
        let now = Utc::now();
        let future_time = now + chrono::Duration::hours(24);

        let mut local_device = DeviceInfo::new(Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10))));
        local_device.last_seen = now;
        local_device.is_local = true;

        // Malicious/broken community device with future timestamps
        let mut community_device = DeviceInfo::new(None);
        community_device.ip_addresses_v4.clear();
        community_device.add_ipv4_entry(Ipv4Addr::new(192, 168, 1, 10), future_time);
        community_device.ip_address = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10));
        community_device.last_seen = future_time;
        community_device.first_seen = future_time;
        community_device.is_local = false;

        // Validate before merge (this is what community_lan.rs does)
        community_device.validate_timestamps();

        // Now merge
        DeviceInfo::merge(&mut local_device, &community_device);

        // Local device should not have future timestamps
        assert!(
            local_device.last_seen <= now + chrono::Duration::seconds(1),
            "last_seen should not be in the future after merge"
        );
    }

    fn make_port(port: u16, dismissed: bool) -> PortInfo {
        PortInfo {
            port,
            protocol: "tcp".to_string(),
            service: String::new(),
            banner: String::new(),
            dismissed,
        }
    }

    #[test]
    fn test_reconcile_open_ports_prunes_refused_ports() {
        // Cached device poisoned with ~5000 false opens. The host refuses every
        // port it does not actually serve, so a clean rescan collapses it to the
        // real service surface in one pass.
        let mut device = DeviceInfo::new(Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));
        let probed: HashSet<u16> = (1u16..=5000).collect();
        device.open_ports = probed
            .iter()
            .copied()
            .map(|p| make_port(p, false))
            .collect();
        // Port 22 was dismissed by the user before the poison episode.
        if let Some(p) = device.open_ports.iter_mut().find(|p| p.port == 22) {
            p.dismissed = true;
        }

        let open_this_scan = vec![make_port(22, false), make_port(80, false)];
        let refused: HashSet<u16> = probed
            .iter()
            .copied()
            .filter(|p| *p != 22 && *p != 80)
            .collect();
        device.reconcile_open_ports_after_scan(&open_this_scan, &refused);

        let ports: Vec<u16> = device.open_ports.iter().map(|p| p.port).collect();
        assert_eq!(ports, vec![22, 80]);
        let port22 = device.open_ports.iter().find(|p| p.port == 22).unwrap();
        assert!(
            port22.dismissed,
            "dismissed flag must survive reconcile on survivors"
        );
    }

    #[test]
    fn test_reconcile_open_ports_keeps_unrefused_ports() {
        let mut device = DeviceInfo::new(Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 50))));
        device.open_ports = vec![
            make_port(80, false),
            make_port(443, false),
            make_port(65000, true), // never probed (e.g. community-only discovery)
        ];
        // 443 was refused this scan; 65000 was not probed at all.
        let refused: HashSet<u16> = [443u16].into_iter().collect();
        let open_this_scan = vec![make_port(80, false)];

        device.reconcile_open_ports_after_scan(&open_this_scan, &refused);

        let ports: Vec<u16> = device.open_ports.iter().map(|p| p.port).collect();
        assert_eq!(ports, vec![80, 65000]);
        assert!(
            device
                .open_ports
                .iter()
                .find(|p| p.port == 65000)
                .unwrap()
                .dismissed
        );
    }

    #[test]
    fn test_reconcile_open_ports_does_not_prune_on_silence() {
        // A host that drops probes (filtered, rate-limited, or a scan that was
        // cancelled mid-flight) refuses nothing. Without an explicit refusal
        // there is no evidence to retract on, so the cached list must survive
        // intact rather than flap to empty and back.
        let mut device = DeviceInfo::new(Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 148))));
        device.open_ports = vec![make_port(22, false), make_port(80, true)];

        device.reconcile_open_ports_after_scan(&[], &HashSet::new());

        let ports: Vec<u16> = device.open_ports.iter().map(|p| p.port).collect();
        assert_eq!(ports, vec![22, 80]);
        assert!(
            device
                .open_ports
                .iter()
                .find(|p| p.port == 80)
                .unwrap()
                .dismissed,
            "dismissed flag must survive a no-evidence scan"
        );
    }

    #[test]
    fn test_reconcile_stamps_port_scan_evidence() {
        // Either kind of definite verdict counts as evidence the host answered
        // probes. A refusal-only scan is the important case: it produces no open
        // ports, so without the stamp the device would be indistinguishable from
        // one that was never reached and would keep reading as criticality
        // `Unknown` forever.
        let mut opened = DeviceInfo::new(Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10))));
        assert!(opened.last_port_scan.is_none(), "starts with no evidence");
        opened.reconcile_open_ports_after_scan(&[make_port(80, false)], &HashSet::new());
        assert!(opened.last_port_scan.is_some());

        let mut refused = DeviceInfo::new(Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 11))));
        refused.reconcile_open_ports_after_scan(&[], &[443u16].into_iter().collect());
        assert!(
            refused.last_port_scan.is_some(),
            "a host that refuses a port has demonstrably been reached"
        );
        assert!(refused.open_ports.is_empty());
    }

    #[test]
    fn test_reconcile_silence_does_not_stamp_port_scan_evidence() {
        // A dropped-probe scan proves nothing, so it must not claim to have
        // observed the port surface.
        let mut device = DeviceInfo::new(Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 12))));
        device.reconcile_open_ports_after_scan(&[], &HashSet::new());
        assert!(device.last_port_scan.is_none());
    }

    #[test]
    fn test_merge_port_scan_evidence_is_monotonic() {
        // The stamp only moves forward, and it moves forward from either side: a
        // peer that got a verdict for this device did observe its ports even if
        // we never could. This is the one field where accepting a remote record
        // is safe -- it records that a scan happened, not what it found.
        let older = Utc.with_ymd_and_hms(2026, 8, 1, 10, 0, 0).unwrap();
        let newer = Utc.with_ymd_and_hms(2026, 8, 2, 10, 0, 0).unwrap();

        let mut current = DeviceInfo::new(Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 13))));
        current.last_port_scan = Some(older);
        let mut incoming = current.clone();
        incoming.last_port_scan = Some(newer);
        DeviceInfo::merge(&mut current, &incoming);
        assert_eq!(current.last_port_scan, Some(newer));

        // Reverse direction: an older peer stamp must not roll ours back.
        incoming.last_port_scan = Some(older);
        DeviceInfo::merge(&mut current, &incoming);
        assert_eq!(current.last_port_scan, Some(newer));

        // A peer with evidence seeds a device that has none.
        let mut unscanned = DeviceInfo::new(Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 14))));
        let mut peer = unscanned.clone();
        peer.last_port_scan = Some(older);
        DeviceInfo::merge(&mut unscanned, &peer);
        assert_eq!(unscanned.last_port_scan, Some(older));

        // And a peer without evidence never clears ours.
        peer.last_port_scan = None;
        DeviceInfo::merge(&mut unscanned, &peer);
        assert_eq!(unscanned.last_port_scan, Some(older));
    }

    #[test]
    fn test_strip_anomalous_open_ports() {
        // The default entry point is the community-boundary guard, which uses
        // the deep ceiling so a first-hand deep scan we store is also a payload
        // we are willing to publish.
        let mut device = DeviceInfo::new(Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));
        device.open_ports = (1u16..=(MAX_REASONABLE_OPEN_PORTS_DEEP as u16 + 1))
            .map(|p| make_port(p, false))
            .collect();
        device.non_std_ports = true;

        assert!(device.strip_anomalous_open_ports());
        assert!(device.open_ports.is_empty());
        assert!(!device.non_std_ports);

        device.open_ports = vec![make_port(80, false)];
        assert!(!device.strip_anomalous_open_ports());
        assert_eq!(device.open_ports.len(), 1);

        // A count between the two ceilings is anomalous for a standard sweep
        // but plausible for a deep one.
        let between = MAX_REASONABLE_OPEN_PORTS as u16 + 1;
        device.open_ports = (1u16..=between).map(|p| make_port(p, false)).collect();
        assert!(!device.strip_anomalous_open_ports());
        assert_eq!(device.open_ports.len(), between as usize);
        assert!(device.strip_anomalous_open_ports_with_limit(MAX_REASONABLE_OPEN_PORTS));
        assert!(device.open_ports.is_empty());
    }

    #[test]
    fn test_max_reasonable_open_ports_for_probed() {
        // Standard port DB breadth keeps the tight ceiling.
        assert_eq!(
            max_reasonable_open_ports_for_probed(5099),
            MAX_REASONABLE_OPEN_PORTS
        );
        // A full 0..=65535 sweep -- including the always-deep self scan -- gets
        // the loose one.
        assert_eq!(
            max_reasonable_open_ports_for_probed(65536),
            MAX_REASONABLE_OPEN_PORTS_DEEP
        );
        assert_eq!(
            max_reasonable_open_ports_for_probed(DEEP_PROBE_BREADTH_THRESHOLD),
            MAX_REASONABLE_OPEN_PORTS
        );
        assert_eq!(
            max_reasonable_open_ports_for_probed(DEEP_PROBE_BREADTH_THRESHOLD + 1),
            MAX_REASONABLE_OPEN_PORTS_DEEP
        );
    }

    #[test]
    fn test_merge_alone_cannot_shrink_poisoned_ports() {
        // Documents why reconcile must run before merge: union never drops.
        let mut cached = DeviceInfo::new(Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));
        cached.open_ports = (1u16..=500).map(|p| make_port(p, false)).collect();

        let mut fresh = DeviceInfo::new(Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));
        fresh.is_local = true;
        fresh.open_ports = vec![make_port(80, false)];

        DeviceInfo::merge(&mut cached, &fresh);
        assert_eq!(
            cached.open_ports.len(),
            500,
            "merge unions; without reconcile poison persists"
        );
    }

    #[test]
    fn test_dropping_host_poisoned_cache_converges_via_guard() {
        // The measured worst case: a host that silently drops every probe.
        // Nothing is refused, so reconcile has no evidence and carries the whole
        // poisoned list forward. The breadth-scaled guard on the *cached* record
        // is the only thing that clears it, which is why it cannot be applied
        // only to the freshly scanned device (that one holds zero ports here, so
        // it never trips the guard).
        //
        // Sequenced as merge_and_post_process_devices does it: reconcile the
        // cached record, guard it, then merge the fresh device in.
        let mut cached = DeviceInfo::new(Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 148))));
        cached.open_ports = (1u16..=5005).map(|p| make_port(p, false)).collect();
        cached.non_std_ports = true;

        // Fresh scan of a dropping host: no opens, no refusals.
        let fresh = DeviceInfo::new(Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 148))));

        cached.reconcile_open_ports_after_scan(&fresh.open_ports, &HashSet::new());
        assert_eq!(
            cached.open_ports.len(),
            5005,
            "silence retracts nothing -- the guard is the backstop, not reconcile"
        );

        // Standard sweep breadth, so the tight ceiling applies.
        let limit = max_reasonable_open_ports_for_probed(5099);
        assert!(cached.strip_anomalous_open_ports_with_limit(limit));
        assert!(cached.open_ports.is_empty());
        assert!(!cached.non_std_ports);

        // The merge that follows must not undo the guard. It re-unions the fresh
        // device, which passed the scan-site guard, so the record stays bounded.
        DeviceInfo::merge(&mut cached, &fresh);
        assert!(
            cached.open_ports.is_empty(),
            "post-guard merge must not re-poison the record"
        );
    }

    #[test]
    fn test_ourselves_community_ports_survive_scan_reconcile() {
        // Our own record is merged with the community view before reconcile, so
        // reconcile must not treat "the community reported it and our sweep did
        // not confirm it" as a retraction. Only a refusal retracts.
        let mut ourselves = DeviceInfo::new(Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10))));
        ourselves.open_ports = vec![
            make_port(22, false),
            make_port(631, false),
            make_port(49152, false), // community-reported, no longer listening
        ];

        // Our own deep sweep sees 22 only; 631 is genuinely gone (refused).
        let open_this_scan = vec![make_port(22, false)];
        let refused: HashSet<u16> = [631u16].into_iter().collect();
        ourselves.reconcile_open_ports_after_scan(&open_this_scan, &refused);

        let ports: Vec<u16> = ourselves.open_ports.iter().map(|p| p.port).collect();
        assert_eq!(
            ports,
            vec![22, 49152],
            "refused port drops, unconfirmed community port stays"
        );

        // A plausible count stays put under the deep ceiling the self scan earns.
        let limit = max_reasonable_open_ports_for_probed(65536);
        assert!(!ourselves.strip_anomalous_open_ports_with_limit(limit));
        assert_eq!(ourselves.open_ports.len(), 2);
    }
}

#[cfg(test)]
mod ipv6_merge_bounds_tests {
    use super::*;
    use std::net::Ipv6Addr;

    /// A device merged repeatedly (every lanscan cycle) must not accumulate
    /// unbounded IPv6 entries. macOS rotates RFC 4941 privacy addresses, so the
    /// self-device grew to 675 entries before the merge path truncated.
    #[test]
    fn merge_bounds_accumulated_ipv6_addresses() {
        let ip: IpAddr = "192.168.1.10".parse().unwrap();
        let mut device = DeviceInfo::new(Some(ip));

        let base = Utc::now();
        for i in 0..200u16 {
            let mut incoming = DeviceInfo::new(Some(ip));
            incoming.add_ipv6_entry(
                Ipv6Addr::new(0x2a01, 0xe0a, 0x17f, 0xa660, 0, 0, 0, i),
                base + chrono::Duration::seconds(i as i64),
            );
            DeviceInfo::merge(&mut device, &incoming);
        }

        assert!(
            device.ip_addresses_v6.len() <= 10,
            "merge path left {} IPv6 entries (expected <= 10)",
            device.ip_addresses_v6.len()
        );
        // The retained entries must be the most recent ones.
        let newest = device
            .ip_addresses_v6
            .iter()
            .map(|e| e.last_seen)
            .max()
            .expect("entries retained");
        assert_eq!(newest, base + chrono::Duration::seconds(199));
    }
}
