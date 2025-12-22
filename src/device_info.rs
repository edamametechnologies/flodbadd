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
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use tracing::{debug, warn};

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
    fn add_ipv4_entry(&mut self, addr: Ipv4Addr, timestamp: DateTime<Utc>) {
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
    fn add_ipv6_entry(&mut self, addr: Ipv6Addr, timestamp: DateTime<Utc>) {
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
    fn add_mdns_entry(&mut self, service: String, timestamp: DateTime<Utc>) {
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
    fn deduplicate_and_truncate_ips(&mut self) {
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
        // Ignore nil mac addresses
        if mac_address.is_nil() {
            return;
        }
        self.mac_address = Some(mac_address);

        // Add the primary MAC address
        self.add_mac_entry(mac_address, timestamp);

        // Add additional MAC addresses
        for addr in mac_addresses {
            if !addr.is_nil() {
                self.add_mac_entry(addr, timestamp);
            }
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
                let primary_ip_match = devices[i].ip_address == devices[j].ip_address;

                let ipv4_overlap = !devices[i].ip_addresses_v4.is_empty()
                    && !devices[j].ip_addresses_v4.is_empty()
                    && devices[i].ip_addresses_v4.iter().any(|entry| {
                        devices[j]
                            .ip_addresses_v4
                            .iter()
                            .any(|e| e.address == entry.address)
                    });

                let ipv6_overlap = !devices[i].ip_addresses_v6.is_empty()
                    && !devices[j].ip_addresses_v6.is_empty()
                    && devices[i].ip_addresses_v6.iter().any(|entry| {
                        devices[j]
                            .ip_addresses_v6
                            .iter()
                            .any(|e| e.address == entry.address)
                    });

                let hostname_match = !devices[i].hostname.is_empty()
                    && !devices[j].hostname.is_empty()
                    && devices[i].hostname == devices[j].hostname;

                let has_conflicts = Self::has_conflicting_characteristics(&devices[i], &devices[j]);

                let is_duplicate = if primary_ip_match || ipv4_overlap || ipv6_overlap {
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
                // Primary IP address match
                let primary_ip_match = new_device.ip_address == device.ip_address;

                // Overlapping IP addresses in the lists
                let ipv4_overlap = !new_device.ip_addresses_v4.is_empty()
                    && !device.ip_addresses_v4.is_empty()
                    && new_device.ip_addresses_v4.iter().any(|entry| {
                        device
                            .ip_addresses_v4
                            .iter()
                            .any(|e| e.address == entry.address)
                    });

                let ipv6_overlap = !new_device.ip_addresses_v6.is_empty()
                    && !device.ip_addresses_v6.is_empty()
                    && new_device.ip_addresses_v6.iter().any(|entry| {
                        device
                            .ip_addresses_v6
                            .iter()
                            .any(|e| e.address == entry.address)
                    });

                // Hostname matching (for multi-interface devices)
                let hostname_match = !new_device.hostname.is_empty()
                    && !device.hostname.is_empty()
                    && device.hostname == new_device.hostname;

                // Check for potential problematic merges
                let has_conflicting_characteristics =
                    Self::has_conflicting_characteristics(device, &new_device);

                // Decide whether to merge
                let should_merge = if primary_ip_match || ipv4_overlap || ipv6_overlap {
                    // Strong IP evidence - merge unless there are major conflicts
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
        } else if vendor_known(device1) && vendor_known(device2) {
            // Both vendors known - check for MAC conflicts using timestamp-aware logic
            Self::has_mac_conflict(device1, device2)
        } else {
            false
        };

        vendor_conflict || mac_conflict
    }

    // Check if two devices have conflicting MAC addresses using timestamp-aware logic
    // Returns true if MACs suggest these are different devices
    fn has_mac_conflict(device1: &DeviceInfo, device2: &DeviceInfo) -> bool {
        match (device1.get_mac_address(), device2.get_mac_address()) {
            (Some(mac1), Some(mac2)) if mac1 != mac2 => {
                // Different primary MACs - check if they could be the same device

                // 1. Check for MAC overlap in the historical lists
                // If any MAC appears in both devices, they're likely the same device at different times
                let mac_overlap = device1.mac_addresses.iter().any(|entry1| {
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

        // IPv4 takes precedence over IPv6: always use the new_device.ip_address if it's IPv4
        if let IpAddr::V4(_) = new_device.ip_address {
            if new_device.last_seen > device.last_seen {
                device.ip_address = new_device.ip_address;
            }
        // The new device is IPv6 and the device is IPv4, we keep the device's IPv4
        } else if matches!(new_device.ip_address, IpAddr::V6(_))
            && matches!(device.ip_address, IpAddr::V4(_))
        {
            // Keep IPv4, IPv6 addresses already merged above
        } else {
            // The new device is IPv6 and the device is IPv6
            // We set the device's ip_address to the new IPv6 if it's fresher
            if new_device.last_seen > device.last_seen {
                device.ip_address = new_device.ip_address;
            }
        }

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

        // Merge open ports
        if !new_device.open_ports.is_empty() {
            // We need to do it manually as the services or banners might be different as it can include timestamps
            for new_port in new_device.open_ports.iter() {
                let mut found = false;
                for existing_port in device.open_ports.iter_mut() {
                    if existing_port.port == new_port.port {
                        // Preserve the existing dismissed flag
                        let dismissed = existing_port.dismissed;
                        // Use the latest info
                        *existing_port = new_port.clone();
                        if dismissed {
                            existing_port.dismissed = true;
                        }
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

        // Merge user properties based on the last modified date
        if new_device.last_modified > device.last_modified {
            device.custom_name.clone_from(&new_device.custom_name);
            device.deleted = new_device.deleted;
            device.last_modified = new_device.last_modified;
        }
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

    fn ipv6_entry(addr: Ipv6Addr) -> IpAddressEntry<Ipv6Addr> {
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
        use chrono::{TimeZone, Utc};
        use std::net::{IpAddr, Ipv4Addr};

        let mut existing_device =
            DeviceInfo::new(Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 200))));
        existing_device.last_seen = Utc.with_ymd_and_hms(2023, 1, 1, 12, 0, 0).unwrap();
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
        // User dismissal must be preserved
        assert!(
            merged_port.dismissed,
            "Dismissed flag should not be cleared by new scan data"
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
        // Test that IP overlap without conflicts allows merging
        let mut devices = vec![{
            let mut d = DeviceInfo::new(Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100))));
            d.ip_addresses_v4 = vec![
                ipv4_entry(Ipv4Addr::new(192, 168, 1, 100)),
                ipv4_entry(Ipv4Addr::new(10, 0, 0, 1)),
            ]; // Shared IP
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

        // Add 15 IPv6 addresses (should keep only last 10)
        let mut old_addresses = Vec::new();
        for i in 0..5 {
            old_addresses.push(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, i as u16));
        }

        let mut new_addresses = Vec::new();
        for i in 5..15 {
            new_addresses.push(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, i as u16));
        }

        // Add old addresses first
        device.add_ip_addresses(vec![], old_addresses.clone());
        // Add new addresses (these should be kept)
        device.add_ip_addresses(vec![], new_addresses.clone());

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

        // Add 25 mDNS services (should keep only last 20)
        let mut old_services = Vec::new();
        for i in 0..5 {
            old_services.push(mdns_entry(&format!("_service{}.local", i)));
        }

        let mut new_services = Vec::new();
        for i in 5..25 {
            new_services.push(mdns_entry(&format!("_service{}.local", i)));
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

        // Fill up to 10 addresses
        let mut addresses = Vec::new();
        for i in 0..10 {
            addresses.push(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, i as u16));
        }
        device.add_ip_addresses(vec![], addresses);

        // Now add 5 more addresses
        let new_addresses = vec![
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 10),
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 11),
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 12),
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 13),
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 14),
        ];
        device.add_ip_addresses(vec![], new_addresses.clone());

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

        // Fill up to 20 services
        for i in 0..20 {
            device
                .mdns_services
                .push(mdns_entry(&format!("_service{}.local", i)));
        }

        // Now add 5 more services
        let new_services: Vec<MdnsServiceEntry> = (20..25)
            .map(|i| mdns_entry(&format!("_service{}.local", i)))
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

        // Add 15 MAC addresses (should keep only last 10)
        let mut old_macs = Vec::new();
        for i in 0..5 {
            old_macs.push(MacAddr6::new(0x00, 0x11, 0x22, 0x33, 0x44, i));
        }

        let mut new_macs = Vec::new();
        for i in 5..15 {
            new_macs.push(MacAddr6::new(0x00, 0x11, 0x22, 0x33, 0x44, i));
        }

        // Add old MACs first
        device.set_mac_address(old_macs[0], old_macs[1..].to_vec());
        // Add new MACs (these should be kept)
        device.set_mac_address(new_macs[0], new_macs[1..].to_vec());

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
        let mac1 = MacAddr6::new(0x11, 0x11, 0x11, 0x11, 0x11, 0x11);
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
        let primary_mac = MacAddr6::new(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
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
}
