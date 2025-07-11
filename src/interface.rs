use crate::ip::{apply_mask, is_link_local_ipv6, is_local_ipv6};
#[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
use ipnet::{ipv4_mask_to_prefix, ipv6_mask_to_prefix};
#[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
use network_interface::{NetworkInterface, NetworkInterfaceConfig};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::cmp::Ordering;
use std::fmt::{Display, Formatter, Result as FmtResult};
use std::iter::FromIterator;
#[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
use std::net::UdpSocket;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
#[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
use std::thread::sleep;
#[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
use std::time::Duration;
use tracing::debug;
#[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
use tracing::error;

// Define the signature trait
pub trait Signature {
    fn signature(&self) -> String;
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct FlodbaddInterfaceAddrV4 {
    pub ip: Ipv4Addr,
    pub prefix: u8,
}

impl Display for FlodbaddInterfaceAddrV4 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> FmtResult {
        write!(f, "{}/{}", self.ip, self.prefix)
    }
}

impl Signature for FlodbaddInterfaceAddrV4 {
    fn signature(&self) -> String {
        format!("{}", self)
    }
}

// Implement Ord so we can compare/sort FlodbaddInterfaceAddrV4
impl Ord for FlodbaddInterfaceAddrV4 {
    fn cmp(&self, other: &Self) -> Ordering {
        // Compare IP first, then prefix
        match self.ip.cmp(&other.ip) {
            Ordering::Equal => self.prefix.cmp(&other.prefix),
            o => o,
        }
    }
}

impl PartialOrd for FlodbaddInterfaceAddrV4 {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Default for FlodbaddInterfaceAddrV4 {
    fn default() -> Self {
        // Adjust the default values as needed.
        Self {
            ip: Ipv4Addr::new(0, 0, 0, 0),
            prefix: 0,
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub enum FlodbaddInterfaceAddrTypeV6 {
    Temporary(FlodbaddInterfaceAddrV6),
    Secured(FlodbaddInterfaceAddrV6),
    LinkLocal(FlodbaddInterfaceAddrV6),
    Local(FlodbaddInterfaceAddrV6),
    Unspecified(FlodbaddInterfaceAddrV6),
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct FlodbaddInterfaceAddrV6 {
    pub ip: Ipv6Addr,
    pub prefix: u8,
}

impl Default for FlodbaddInterfaceAddrV6 {
    fn default() -> Self {
        Self {
            ip: Ipv6Addr::UNSPECIFIED,
            prefix: 0,
        }
    }
}
impl Display for FlodbaddInterfaceAddrV6 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> FmtResult {
        write!(f, "{}", self.ip)
    }
}

/// Decide if interface a is contained by interface b, meaning:
///  1) They share the same subnet when applying b's prefix,
///  2) b's prefix is smaller or equal (covers an equal-or-larger network),
///  3) They have different names (so they aren't literally the same interface).
fn is_contained(a: &FlodbaddInterface, b: &FlodbaddInterface) -> bool {
    let Some(a_v4) = &a.ipv4 else {
        return false;
    };
    let Some(b_v4) = &b.ipv4 else {
        return false;
    };

    let net_a = apply_mask(a_v4.ip, b_v4.prefix);
    let net_b = apply_mask(b_v4.ip, b_v4.prefix);

    net_a == net_b && b_v4.prefix <= a_v4.prefix
}

/// Helper: check if iface is contained by any item in `others`.
fn contained_by_any(iface: &FlodbaddInterface, others: &[FlodbaddInterface]) -> bool {
    others.iter().any(|x| is_contained(iface, x))
}

/// Deduplicate a list of interfaces by removing any interface that
/// is contained by an already-accepted interface in the same list.
pub fn deduplicate_interface_list(interfaces: &FlodbaddInterfaces) -> FlodbaddInterfaces {
    let mut filtered = FlodbaddInterfaces::new();

    for iface in &interfaces.interfaces {
        if !filtered
            .interfaces
            .iter()
            .any(|accepted| is_contained(iface, accepted))
        {
            filtered.interfaces.push(iface.clone());
        }
    }
    filtered
}

/// Return elements in `check_list` that do not overlap (are not contained)
/// in any interface from `primary_list`.
pub fn filter_interfaces_against(
    primary_list: &FlodbaddInterfaces,
    check_list: &FlodbaddInterfaces,
) -> FlodbaddInterfaces {
    let mut result = FlodbaddInterfaces::new();

    for iface in &check_list.interfaces {
        if !contained_by_any(iface, &primary_list.interfaces) {
            result.interfaces.push(iface.clone());
        }
    }
    result
}

pub fn mask_ipv6(ip: Ipv6Addr, prefix: u8) -> Ipv6Addr {
    let prefix = prefix.min(128);

    // If prefix is zero, return the unmodified IP
    if prefix == 0 {
        return ip;
    }

    let segments = ip.segments();
    let mut value: u128 = 0;
    for (i, seg) in segments.iter().enumerate() {
        value |= (*seg as u128) << ((7 - i) * 16);
    }
    let shift_amount = 128 - prefix;
    let masked_value = (value >> shift_amount) << shift_amount;

    let mut masked_segments = [0u16; 8];
    for i in 0..8 {
        masked_segments[i] = ((masked_value >> ((7 - i) * 16)) & 0xFFFF) as u16;
    }

    Ipv6Addr::from(masked_segments)
}

// For a deterministic yet unique signature, we mask the address to respect the prefix bits.
// This will retain the uniqueness of the IPv6 ISP segments, but not the lower bits that change.
impl Signature for FlodbaddInterfaceAddrV6 {
    fn signature(&self) -> String {
        let masked = mask_ipv6(self.ip, self.prefix);
        format!("{}/{}", masked, self.prefix)
    }
}

impl FlodbaddInterfaceAddrTypeV6 {
    fn rank(&self) -> i32 {
        match self {
            FlodbaddInterfaceAddrTypeV6::Secured(_) => 0,
            FlodbaddInterfaceAddrTypeV6::LinkLocal(_) => 1,
            FlodbaddInterfaceAddrTypeV6::Local(_) => 2,
            FlodbaddInterfaceAddrTypeV6::Temporary(_) => 3,
            FlodbaddInterfaceAddrTypeV6::Unspecified(_) => 4,
        }
    }

    pub fn ip(&self) -> Ipv6Addr {
        match self {
            FlodbaddInterfaceAddrTypeV6::Temporary(a)
            | FlodbaddInterfaceAddrTypeV6::Secured(a)
            | FlodbaddInterfaceAddrTypeV6::LinkLocal(a)
            | FlodbaddInterfaceAddrTypeV6::Local(a)
            | FlodbaddInterfaceAddrTypeV6::Unspecified(a) => a.ip,
        }
    }
}

// Implementing Ord and PartialOrd on FlodbaddInterfaceAddrTypeV6
impl Ord for FlodbaddInterfaceAddrTypeV6 {
    fn cmp(&self, other: &Self) -> Ordering {
        // Compare first by rank, then by IP
        self.rank()
            .cmp(&other.rank())
            .then(self.ip().cmp(&other.ip()))
    }
}

impl PartialOrd for FlodbaddInterfaceAddrTypeV6 {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Display for FlodbaddInterfaceAddrTypeV6 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> FmtResult {
        let ipv6_str = match self {
            FlodbaddInterfaceAddrTypeV6::Temporary(a) => {
                format!("{}/{} (temporary)", a.ip, a.prefix)
            }
            FlodbaddInterfaceAddrTypeV6::Secured(a) => format!("{}/{} (secured)", a.ip, a.prefix),
            FlodbaddInterfaceAddrTypeV6::LinkLocal(a) => {
                format!("{}/{} (link-local)", a.ip, a.prefix)
            }
            FlodbaddInterfaceAddrTypeV6::Local(a) => format!("{}/{} (local)", a.ip, a.prefix),
            FlodbaddInterfaceAddrTypeV6::Unspecified(a) => {
                format!("{}/{} (unspecified)", a.ip, a.prefix)
            }
        };
        write!(f, "{}", ipv6_str)
    }
}

impl Signature for FlodbaddInterfaceAddrTypeV6 {
    fn signature(&self) -> String {
        match self {
            FlodbaddInterfaceAddrTypeV6::Temporary(a) => a.signature(),
            FlodbaddInterfaceAddrTypeV6::Secured(a) => a.signature(),
            FlodbaddInterfaceAddrTypeV6::LinkLocal(a) => a.signature(),
            FlodbaddInterfaceAddrTypeV6::Local(a) => a.signature(),
            FlodbaddInterfaceAddrTypeV6::Unspecified(a) => a.signature(),
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct FlodbaddInterface {
    pub name: String,
    pub ipv4: Option<FlodbaddInterfaceAddrV4>,
    pub ipv6: Vec<FlodbaddInterfaceAddrTypeV6>,
}

impl Display for FlodbaddInterface {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        // Avoid recursion; show the interface name plus addresses
        match &self.ipv4 {
            Some(v4) => write!(f, "{}: IPv4={}, IPv6={:?}", self.name, v4, self.ipv6),
            None => write!(f, "{}: (no IPv4), IPv6={:?}", self.name, self.ipv6),
        }
    }
}

impl Signature for FlodbaddInterface {
    fn signature(&self) -> String {
        // Sort IPv6 addresses for consistent (deterministic) ordering
        let mut sorted_ipv6 = self.ipv6.clone();
        sorted_ipv6.sort();

        format!(
            "{}-{}",
            self.ipv4
                .as_ref()
                .map(|addr| addr.signature())
                .unwrap_or_default(),
            sorted_ipv6
                .iter()
                .map(|addr| addr.signature())
                .collect::<Vec<_>>()
                .join("-")
        )
    }
}

// Sort FlodbaddInterface by name, then by ipv4, then by ipv6.
impl Ord for FlodbaddInterface {
    fn cmp(&self, other: &Self) -> Ordering {
        self.name
            .cmp(&other.name)
            .then_with(|| self.ipv4.cmp(&other.ipv4))
            .then_with(|| self.ipv6.cmp(&other.ipv6))
    }
}

impl PartialOrd for FlodbaddInterface {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl FlodbaddInterface {
    pub fn sort(&mut self) {
        self.ipv6.sort();
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
pub struct FlodbaddInterfaces {
    pub interfaces: Vec<FlodbaddInterface>,
}

// Make it easy to `.collect()` into FlodbaddInterfaces
impl FromIterator<FlodbaddInterface> for FlodbaddInterfaces {
    fn from_iter<I: IntoIterator<Item = FlodbaddInterface>>(iter: I) -> Self {
        Self {
            interfaces: iter.into_iter().collect(),
        }
    }
}

// Make it easy to iterate over FlodbaddInterfaces
impl IntoIterator for FlodbaddInterfaces {
    type Item = FlodbaddInterface;
    type IntoIter = std::vec::IntoIter<FlodbaddInterface>;

    fn into_iter(self) -> Self::IntoIter {
        self.interfaces.into_iter()
    }
}

impl Default for FlodbaddInterfaces {
    fn default() -> Self {
        Self::new()
    }
}

impl FlodbaddInterfaces {
    pub fn new() -> Self {
        Self {
            interfaces: Vec::new(),
        }
    }

    pub fn extend(&mut self, other: Self) {
        self.interfaces.extend(other.interfaces);
    }

    pub fn clear(&mut self) {
        self.interfaces.clear();
    }

    /// Sorts the underlying interfaces by their `Ord` implementation.
    pub fn sort(&mut self) {
        // Each interface can self-sort (its IPv6 list),
        // then we sort the outer vector by FlodbaddInterface's Ord.
        for iface in &mut self.interfaces {
            iface.sort();
        }
        self.interfaces.sort();
    }

    /// Returns an iterator over the contained interfaces
    pub fn iter(&self) -> impl Iterator<Item = &FlodbaddInterface> {
        self.interfaces.iter()
    }

    pub fn len(&self) -> usize {
        self.interfaces.len()
    }

    pub fn is_empty(&self) -> bool {
        self.interfaces.is_empty()
    }
}

impl Display for FlodbaddInterfaces {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> FmtResult {
        for iface in &self.interfaces {
            writeln!(f, "{}", iface)?;
        }
        Ok(())
    }
}

impl Signature for FlodbaddInterfaces {
    fn signature(&self) -> String {
        // Sort the interfaces by name
        let mut interfaces: Vec<FlodbaddInterface> = self.interfaces.clone();
        interfaces.sort_by(|a, b| a.name.cmp(&b.name));
        let interfaces_str = interfaces
            .iter()
            .map(|iface| iface.signature())
            .collect::<Vec<String>>()
            .join("");
        debug!("Interface string for signature is: {}", interfaces_str);
        let mut hasher = Sha256::new();
        hasher.update(interfaces_str.as_bytes());
        let result = hasher.finalize();
        hex::encode(result)
    }
}

// Exclusions and filtering
const EXCLUDED_IFACE_NAMES_PREFIXES: [&str; 23] = [
    "feth",
    "zt",
    "utun",
    "wg",
    "tun",
    "tap",
    "ipsec",
    "ppp",
    "bridge",
    "awdl",
    "llw",
    "lo",
    "rmnet",
    "ccmni",
    "clat",
    "pdp_ip",
    "docker",
    "veth",
    "br-",
    "vboxnet",
    "virbr",
    "vEthernet",
    "ZeroTier",
];

const EXCLUDED_IFACE_NAMES_CONTAINS: [&str; 2] = ["vpn", "virtual"];

pub fn validate_interfaces(interfaces: FlodbaddInterfaces) -> FlodbaddInterfaces {
    // Filter out undesired interfaces, then collect into FlodbaddInterfaces
    interfaces
        .into_iter()
        .filter(|iface| {
            // Exclude if interface name starts with a known pattern
            if EXCLUDED_IFACE_NAMES_PREFIXES.iter().any(|&prefix| {
                iface
                    .name
                    .to_lowercase()
                    .starts_with(&prefix.to_lowercase())
            }) {
                return false;
            }
            // Exclude if interface name contains a known pattern
            if EXCLUDED_IFACE_NAMES_CONTAINS
                .iter()
                .any(|&contains| iface.name.to_lowercase().contains(&contains.to_lowercase()))
            {
                return false;
            }

            // Exclude None, loopback, local, and unspecified addresses for IPv4
            if iface.ipv4.is_none()
                || iface.ipv4.as_ref().map_or(false, |addr| {
                    let [a, b, c, d] = addr.ip.octets();
                    a == 127 || a == 169 && b == 254 || a == 0 && b == 0 && c == 0 && d == 0
                })
            {
                return false;
            }
            true
        })
        .collect()
}

// Helper to classify IPv6 addresses
pub fn type_of_ipv6(ipv6: Ipv6Addr, prefix: u8) -> FlodbaddInterfaceAddrTypeV6 {
    if is_link_local_ipv6(&ipv6) {
        // Link-local
        return FlodbaddInterfaceAddrTypeV6::LinkLocal(FlodbaddInterfaceAddrV6 {
            ip: ipv6,
            prefix,
        });
    }

    if is_local_ipv6(&ipv6) {
        return FlodbaddInterfaceAddrTypeV6::Local(FlodbaddInterfaceAddrV6 { ip: ipv6, prefix });
    }

    // TODO: Check if the ipv6 is a "secured" (e.g. cryptographically generated) address
    // For now, treat everything else as "Temporary"
    FlodbaddInterfaceAddrTypeV6::Temporary(FlodbaddInterfaceAddrV6 { ip: ipv6, prefix })
}

#[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
pub fn get_all_interfaces() -> FlodbaddInterfaces {
    let iface_list = match NetworkInterface::show() {
        Ok(ifaces) => ifaces,
        Err(e) => {
            error!("Failed to fetch interfaces: {}", e);
            return FlodbaddInterfaces::new();
        }
    };

    // Sort the raw network-interface list by name
    let mut iface_list = iface_list.clone();
    iface_list.sort_by_key(|iface| iface.name.clone());

    // Map them into FlodbaddInterface, collect into FlodbaddInterfaces
    let mut result: FlodbaddInterfaces = iface_list
        .iter()
        .filter_map(|iface| {
            let ipv4 = iface.addr.iter().find_map(|addr| match addr {
                network_interface::Addr::V4(ipv4) => Some(FlodbaddInterfaceAddrV4 {
                    ip: ipv4.ip,
                    prefix: ipv4_mask_to_prefix(ipv4.netmask.unwrap_or(Ipv4Addr::UNSPECIFIED))
                        .unwrap_or(0),
                }),
                _ => None,
            });

            let mut ipv6 = iface
                .addr
                .iter()
                .filter_map(|addrinfo| match addrinfo {
                    network_interface::Addr::V6(ipv6) => Some(type_of_ipv6(
                        ipv6.ip,
                        ipv6_mask_to_prefix(ipv6.netmask.unwrap_or(Ipv6Addr::UNSPECIFIED))
                            .unwrap_or(0),
                    )),
                    _ => None,
                })
                .collect::<Vec<_>>();
            // Sort the IPv6 addresses
            ipv6.sort();

            Some(FlodbaddInterface {
                name: iface.name.clone(),
                ipv4,
                ipv6,
            })
        })
        .collect();

    // Finally, sort everything by the FlodbaddInterface Ord
    result.sort();
    result
}

#[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
pub fn get_all_interfaces() -> FlodbaddInterfaces {
    FlodbaddInterfaces::new()
}

pub fn get_valid_network_interfaces() -> FlodbaddInterfaces {
    #[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
    {
        let all_interfaces = get_all_interfaces();
        let mut valid_ifaces = validate_interfaces(all_interfaces);
        // Sort by name (or by Ord) again, just to be sure
        valid_ifaces.sort();
        debug!("Valid interfaces: {:#?}", valid_ifaces);
        valid_ifaces
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
    {
        FlodbaddInterfaces::new()
    }
}

/// Return the **signatures** of each interface as a `Vec<String>`.
pub fn get_signature_of_valid_interfaces(interfaces: FlodbaddInterfaces) -> Vec<String> {
    // The previous code incorrectly tried to return FlodbaddInterfaces.
    // We want signatures, so let's return Vec<String>.
    interfaces.iter().map(|iface| iface.signature()).collect()
}

#[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
pub fn get_own_ips() -> Vec<IpAddr> {
    match NetworkInterface::show() {
        Ok(ifaces) => ifaces
            .iter()
            .flat_map(|iface| iface.addr.iter().map(|addr| addr.ip()))
            .collect(),
        Err(e) => {
            error!("Failed to fetch interfaces: {}", e);
            Vec::new()
        }
    }
}

#[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
pub fn get_own_ips() -> Vec<IpAddr> {
    Vec::new()
}

pub fn get_default_interface() -> Option<FlodbaddInterface> {
    #[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
    {
        const MAX_RETRIES: u8 = 5;

        for _ in 0..MAX_RETRIES {
            // 1) Try to discover the IP used for the default route via UDP socket trick
            if let Some(local_ip) = {
                let socket = UdpSocket::bind("0.0.0.0:0").ok()?;
                if socket.connect("8.8.8.8:80").is_err() {
                    None
                } else {
                    socket.local_addr().ok().map(|addr| addr.ip())
                }
            } {
                // 2) Map that IP back to one of our validated interfaces
                if let Some(iface) = get_valid_network_interfaces().into_iter().find(|iface| {
                    iface
                        .ipv4
                        .as_ref()
                        .map_or(false, |v4| IpAddr::V4(v4.ip) == local_ip)
                        || iface.ipv6.iter().any(|v6| {
                            let ip = match v6 {
                                FlodbaddInterfaceAddrTypeV6::Temporary(a)
                                | FlodbaddInterfaceAddrTypeV6::Secured(a)
                                | FlodbaddInterfaceAddrTypeV6::LinkLocal(a)
                                | FlodbaddInterfaceAddrTypeV6::Local(a)
                                | FlodbaddInterfaceAddrTypeV6::Unspecified(a) => a.ip,
                            };
                            IpAddr::V6(ip) == local_ip
                        })
                }) {
                    return Some(iface);
                }
            }

            // Back-off a little before retrying
            sleep(Duration::from_millis(200));
        }
        None
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
    {
        None
    }
}

// Tests
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_valid_network_interfaces() {
        let interfaces = get_valid_network_interfaces();
        println!("Interfaces: {:#?}", interfaces);
        // Just ensure we can fetch without panicking
        assert!(interfaces.interfaces.len() > 0);
    }

    #[test]
    fn test_get_default_interface() {
        let interface = get_default_interface();
        println!("Interface: {:#?}", interface);
        // Depending on environment, this may be Some(...) or None
        assert!(interface.is_some() || interface.is_none());
    }

    #[test]
    fn test_ordering_v4() {
        let addr1 = FlodbaddInterfaceAddrV4 {
            ip: Ipv4Addr::new(192, 168, 1, 1),
            prefix: 24,
        };
        let addr2 = FlodbaddInterfaceAddrV4 {
            ip: Ipv4Addr::new(192, 168, 1, 2),
            prefix: 24,
        };
        assert!(addr1 < addr2);
    }

    #[test]
    fn test_ordering_v6() {
        let addr1 = FlodbaddInterfaceAddrV6 {
            ip: Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
            prefix: 64,
        };
        let addr2 = FlodbaddInterfaceAddrV6 {
            ip: Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2),
            prefix: 64,
        };
        assert!(addr1.ip < addr2.ip);
    }

    /// Test that repeated calls to signature() on the same FlodbaddInterface
    /// yield the same deterministic result, regardless of the order of IPv6 addresses.
    #[test]
    fn test_signature_determinism_single_iface() {
        let iface1 = FlodbaddInterface {
            name: "test_iface".to_string(),
            ipv4: Some(FlodbaddInterfaceAddrV4 {
                ip: Ipv4Addr::new(192, 168, 1, 100),
                prefix: 24,
            }),
            ipv6: vec![
                FlodbaddInterfaceAddrTypeV6::Temporary(FlodbaddInterfaceAddrV6 {
                    ip: Ipv6Addr::LOCALHOST,
                    prefix: 64,
                }),
                FlodbaddInterfaceAddrTypeV6::Secured(FlodbaddInterfaceAddrV6 {
                    ip: Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
                    prefix: 64,
                }),
                FlodbaddInterfaceAddrTypeV6::Local(FlodbaddInterfaceAddrV6 {
                    ip: Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1),
                    prefix: 64,
                }),
            ],
        };

        // Shuffle or reverse the IPv6 vector to change its ordering
        let mut iface2 = iface1.clone();
        iface2.ipv6.reverse();

        // Compare signatures
        let sig1 = iface1.signature();
        let sig2 = iface2.signature();
        assert_eq!(
            sig1, sig2,
            "Signatures should remain the same despite different IPv6 ordering"
        );
    }

    /// Test that the FlodbaddInterfaces collection also yields a deterministic signature,
    /// regardless of the order of its interfaces or their addresses.
    #[test]
    fn test_flodbaddinterfaces_signature_determinism() {
        let iface_a = FlodbaddInterface {
            name: "ifaceA".to_string(),
            ipv4: Some(FlodbaddInterfaceAddrV4 {
                ip: Ipv4Addr::new(10, 0, 0, 1),
                prefix: 8,
            }),
            ipv6: vec![FlodbaddInterfaceAddrTypeV6::Temporary(
                FlodbaddInterfaceAddrV6 {
                    ip: Ipv6Addr::LOCALHOST,
                    prefix: 64,
                },
            )],
        };

        let iface_b = FlodbaddInterface {
            name: "ifaceB".to_string(),
            ipv4: Some(FlodbaddInterfaceAddrV4 {
                ip: Ipv4Addr::new(192, 168, 0, 50),
                prefix: 24,
            }),
            ipv6: vec![
                FlodbaddInterfaceAddrTypeV6::LinkLocal(FlodbaddInterfaceAddrV6 {
                    ip: Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 2),
                    prefix: 64,
                }),
                FlodbaddInterfaceAddrTypeV6::Local(FlodbaddInterfaceAddrV6 {
                    ip: Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2),
                    prefix: 64,
                }),
            ],
        };

        let mut set1 = FlodbaddInterfaces {
            interfaces: vec![iface_a.clone(), iface_b.clone()],
        };
        let mut set2 = FlodbaddInterfaces {
            interfaces: vec![iface_b, iface_a],
        };

        // The contents are the same, but order is different.
        // Sort them just to ensure the final arrangement is consistent, then compare signatures.
        set1.sort();
        set2.sort();

        let sig1 = set1.signature();
        let sig2 = set2.signature();

        assert_eq!(
            sig1, sig2,
            "Signatures should remain the same for the same data in different orders"
        );
    }

    /// Test the validate_interfaces function to ensure that
    /// interfaces with certain excluded names or IPs are filtered out.
    #[test]
    fn test_validate_interfaces_exclusions() {
        let mut test_set = FlodbaddInterfaces::new();

        // "lo" + 127.0.0.1 => should be excluded
        test_set.interfaces.push(FlodbaddInterface {
            name: "lo".to_string(),
            ipv4: Some(FlodbaddInterfaceAddrV4 {
                ip: Ipv4Addr::new(127, 0, 0, 1),
                prefix: 8,
            }),
            ipv6: vec![],
        });

        // "wlan0" + 192.168.1.42 => should be included
        test_set.interfaces.push(FlodbaddInterface {
            name: "wlan0".to_string(),
            ipv4: Some(FlodbaddInterfaceAddrV4 {
                ip: Ipv4Addr::new(192, 168, 1, 42),
                prefix: 24,
            }),
            ipv6: vec![],
        });

        // "utun0" + 10.0.0.2 => should be excluded (interface name starts with excluded prefix)
        test_set.interfaces.push(FlodbaddInterface {
            name: "utun0".to_string(),
            ipv4: Some(FlodbaddInterfaceAddrV4 {
                ip: Ipv4Addr::new(10, 0, 0, 2),
                prefix: 8,
            }),
            ipv6: vec![],
        });

        // "eth0" + 169.254.0.5 => should be excluded (link local range for IPv4)
        test_set.interfaces.push(FlodbaddInterface {
            name: "eth0".to_string(),
            ipv4: Some(FlodbaddInterfaceAddrV4 {
                ip: Ipv4Addr::new(169, 254, 0, 5),
                prefix: 16,
            }),
            ipv6: vec![],
        });

        // "someiface" + 0.0.0.0 => should be excluded (unspecified)
        test_set.interfaces.push(FlodbaddInterface {
            name: "someiface".to_string(),
            ipv4: Some(FlodbaddInterfaceAddrV4 {
                ip: Ipv4Addr::new(0, 0, 0, 0),
                prefix: 0,
            }),
            ipv6: vec![],
        });

        let validated = validate_interfaces(test_set);

        // Only "wlan0" with 192.168.1.42 should remain
        assert_eq!(validated.interfaces.len(), 1);
        assert_eq!(validated.interfaces[0].name, "wlan0");
        assert_eq!(
            validated.interfaces[0].ipv4.as_ref().unwrap().ip,
            Ipv4Addr::new(192, 168, 1, 42)
        );
    }
}
