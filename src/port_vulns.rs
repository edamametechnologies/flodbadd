use crate::port_info::*;
use crate::port_vulns_db::*;
use crate::vulnerability_info::*;
use anyhow::{Context, Result};
use arc_swap::ArcSwap;
use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::default::Default;
use std::sync::Arc;
use threatmodels_rs::*;
use tracing::{info, warn};
use undeadlock::*;

const PORT_VULNS_NAME: &str = "lanscan-port-vulns-db.json";

#[derive(Debug, Serialize, Deserialize, Clone, Ord, Eq, PartialEq, PartialOrd)]
pub struct VulnerabilityPortInfo {
    pub port: u16,
    pub name: String,
    pub description: String,
    pub vulnerabilities: Vec<VulnerabilityInfo>,
    pub count: u32,
    pub protocol: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct VulnerabilityPortInfoListJSON {
    pub date: String,
    pub signature: String,
    pub vulnerabilities: Vec<VulnerabilityPortInfo>,
}

impl CloudSignature for VulnerabilityPortInfoList {
    fn get_signature(&self) -> String {
        self.signature.clone()
    }
    fn set_signature(&mut self, signature: String) {
        self.signature = signature;
    }
}

#[derive(Clone)]
pub struct VulnerabilityPortInfoList {
    pub date: String,
    pub signature: String,
    pub port_vulns: Arc<HashMap<u16, VulnerabilityPortInfo>>,
    pub http_ports: Arc<HashMap<u16, VulnerabilityPortInfo>>,
    pub https_ports: Arc<HashMap<u16, VulnerabilityPortInfo>>,
}

impl VulnerabilityPortInfoList {
    pub fn new_from_json(vuln_info: VulnerabilityPortInfoListJSON) -> Self {
        info!("Loading port info list from JSON");

        let mut port_vulns: HashMap<u16, VulnerabilityPortInfo> = HashMap::new();
        let mut http_ports: HashMap<u16, VulnerabilityPortInfo> = HashMap::new();
        let mut https_ports: HashMap<u16, VulnerabilityPortInfo> = HashMap::new();

        let mut http_vec: Vec<u16> = Vec::new();
        let mut https_vec: Vec<u16> = Vec::new();

        for port_info in vuln_info.vulnerabilities {
            if port_info.protocol == "http" {
                http_ports.insert(port_info.port, port_info.clone());
                http_vec.push(port_info.port);
            } else if port_info.protocol == "https" {
                https_ports.insert(port_info.port, port_info.clone());
                https_vec.push(port_info.port);
            }
            port_vulns.insert(port_info.port, port_info.clone());

            PORT_VULN_LISTS_CACHE
                .insert(port_info.port, Arc::new(port_info.vulnerabilities.clone()));
            PORT_COUNTS_CACHE.insert(port_info.port, port_info.count);
        }

        http_vec.sort_unstable();
        https_vec.sort_unstable();

        // We don't try to update the cache here because this is called from a non-async context
        // The HTTP/HTTPS port lists will be populated on first access instead

        let port_vulns = Arc::new(port_vulns);
        let http_ports = Arc::new(http_ports);
        let https_ports = Arc::new(https_ports);

        info!(
            "Loaded {} ports, {} HTTP ports, {} HTTPS ports",
            port_vulns.len(),
            http_ports.len(),
            https_ports.len()
        );

        // Atomically publish the new maps so readers bypass the RwLock entirely
        PORT_VULNS_PTR.store(port_vulns.clone());
        HTTP_PORTS_PTR.store(http_ports.clone());
        HTTPS_PORTS_PTR.store(https_ports.clone());

        VulnerabilityPortInfoList {
            date: vuln_info.date,
            signature: vuln_info.signature,
            port_vulns,
            http_ports,
            https_ports,
        }
    }
}

// Define a wrapper for port mappings used in testing
#[derive(Clone, Debug)]
pub struct ServicePortsMap {
    pub port_map: Arc<CustomDashMap<u16, String>>,
    pub signature: String,
}

impl Default for ServicePortsMap {
    fn default() -> Self {
        Self {
            port_map: Arc::new(CustomDashMap::new("port_map")),
            signature: "test_signature".to_string(),
        }
    }
}

impl CloudSignature for ServicePortsMap {
    fn get_signature(&self) -> String {
        self.signature.clone()
    }

    fn set_signature(&mut self, signature: String) {
        self.signature = signature;
    }
}

lazy_static! {
    pub static ref VULNS: CloudModel<VulnerabilityPortInfoList> = {
        let model = CloudModel::initialize(PORT_VULNS_NAME.to_string(), &PORT_VULNS, |data| {
            let vuln_info_json: VulnerabilityPortInfoListJSON =
                serde_json::from_str(data).with_context(|| "Failed to parse JSON data")?;
            Ok(VulnerabilityPortInfoList::new_from_json(vuln_info_json))
        });
        match model {
            Ok(m) => m,
            Err(e) => {
                eprintln!("FATAL: Failed to initialize CloudModel for port vulns: {:?}", e);
                panic!("Failed to initialize CloudModel for port vulns: {:?}", e);
            }
        }
    };

    // For testing purposes - a simple service ports mapping
    pub static ref SERVICE_PORTS: CloudModel<ServicePortsMap> = {
        let model = CloudModel::initialize_empty();
        model
    };

    // Cache for port vulnerability lists by port
    static ref PORT_VULN_LISTS_CACHE: CustomDashMap<u16, Arc<Vec<VulnerabilityInfo>>> = CustomDashMap::new("port_vulnerability_lists_cache");

    // Cache for port counts by port
    static ref PORT_COUNTS_CACHE: CustomDashMap<u16, u32> = CustomDashMap::new("port_counts_cache");

    // Cache for HTTP port lists
    static ref HTTP_PORT_LIST_CACHE: Arc<CustomRwLock<Vec<u16>>> = Arc::new(CustomRwLock::new(Vec::new()));

    // Cache for HTTPS port lists
    static ref HTTPS_PORT_LIST_CACHE: Arc<CustomRwLock<Vec<u16>>> = Arc::new(CustomRwLock::new(Vec::new()));

    // Cache for device criticality computations. The key covers every scoring
    // input, not just the ports -- see `get_device_criticality`.
    // Stored as a lock-free snapshot to avoid DashMap shard contention on hot reads.
    static ref CRITICALITY_CACHE_PTR: ArcSwap<HashMap<String, String>> = ArcSwap::from_pointee(HashMap::new());

    // Lock-free pointers to current maps for hot-path readers
    static ref PORT_VULNS_PTR: ArcSwap<HashMap<u16, VulnerabilityPortInfo>> = ArcSwap::from_pointee(HashMap::new());
    static ref HTTP_PORTS_PTR: ArcSwap<HashMap<u16, VulnerabilityPortInfo>> = ArcSwap::from_pointee(HashMap::new());
    static ref HTTPS_PORTS_PTR: ArcSwap<HashMap<u16, VulnerabilityPortInfo>> = ArcSwap::from_pointee(HashMap::new());
}

#[inline]
fn ensure_port_vulns_initialized() {
    // Ensure the CloudModel is initialized so ArcSwap pointers are populated
    lazy_static::initialize(&VULNS);
}

// Clear all caches
async fn clear_caches() {
    PORT_VULN_LISTS_CACHE.clear();
    PORT_COUNTS_CACHE.clear();

    // No try_write, we just execute the actual clear operation
    // in an async context where we can properly await
    let mut http_list = HTTP_PORT_LIST_CACHE.write().await;
    http_list.clear();
    drop(http_list); // Explicitly release the lock

    let mut https_list = HTTPS_PORT_LIST_CACHE.write().await;
    https_list.clear();
    drop(https_list); // Explicitly release the lock

    // Swap-on-clear to avoid blocking readers on a shared lock.
    CRITICALITY_CACHE_PTR.store(Arc::new(HashMap::new()));
}

pub async fn get_ports() -> Vec<u16> {
    ensure_port_vulns_initialized();
    // Load the current map without touching the model lock
    let ports_map = PORT_VULNS_PTR.load();
    ports_map.keys().copied().collect()
}

pub fn get_deep_ports() -> Vec<u16> {
    (0..65535).collect()
}

pub async fn get_description_from_port(port: u16) -> String {
    ensure_port_vulns_initialized();
    // Read from the lock-free pointer
    let port_vulns = PORT_VULNS_PTR.load();
    if let Some(port_info) = port_vulns.get(&port) {
        return port_info.description.clone();
    }

    "".to_string()
}

pub async fn get_name_from_port(port: u16) -> String {
    ensure_port_vulns_initialized();
    // Read from the lock-free pointer
    let port_vulns = PORT_VULNS_PTR.load();
    if let Some(port_info) = port_vulns.get(&port) {
        return port_info.name.clone();
    }

    "".to_string()
}

pub async fn get_http_ports() -> Vec<u16> {
    ensure_port_vulns_initialized();
    // Try cache first
    {
        let cached = HTTP_PORT_LIST_CACHE.read().await;
        if !cached.is_empty() {
            return cached.clone();
        }
    } // Release the read lock

    // If not in cache, generate and cache it from the lock-free pointer
    let http_ports = HTTP_PORTS_PTR.load();
    let mut http_vec: Vec<u16> = http_ports.keys().copied().collect();
    http_vec.sort_unstable();

    // Update the cache
    {
        let mut http_list = HTTP_PORT_LIST_CACHE.write().await;
        *http_list = http_vec.clone();
    } // Release the write lock

    http_vec
}

pub async fn get_https_ports() -> Vec<u16> {
    ensure_port_vulns_initialized();
    // Try cache first
    {
        let cached = HTTPS_PORT_LIST_CACHE.read().await;
        if !cached.is_empty() {
            return cached.clone();
        }
    } // Release the read lock

    // If not in cache, generate and cache it from the lock-free pointer
    let https_ports = HTTPS_PORTS_PTR.load();
    let mut https_vec: Vec<u16> = https_ports.keys().copied().collect();
    https_vec.sort_unstable();

    // Update the cache
    {
        let mut https_list = HTTPS_PORT_LIST_CACHE.write().await;
        *https_list = https_vec.clone();
    } // Release the write lock

    https_vec
}

pub async fn get_vulns_of_port(port: u16) -> Vec<VulnerabilityInfo> {
    ensure_port_vulns_initialized();
    // Try cache first
    if let Some(cached) = PORT_VULN_LISTS_CACHE.get(&port) {
        let mut vulns = cached.as_ref().clone();
        vulns.sort_by(|a, b| b.name.cmp(&a.name));
        return vulns;
    }

    // If not in cache, read from the lock-free pointer
    let port_vulns = PORT_VULNS_PTR.load();
    if let Some(port_info) = port_vulns.get(&port) {
        let mut vulns = port_info.vulnerabilities.clone();
        vulns.sort_by(|a, b| b.name.cmp(&a.name));

        let arc_vulns = Arc::new(vulns.clone());
        PORT_VULN_LISTS_CACHE.insert(port, arc_vulns);

        return vulns;
    }

    Vec::new()
}

pub async fn get_vulns_names_of_port(port: u16) -> Vec<String> {
    let vulns = get_vulns_of_port(port).await;
    vulns.iter().map(|vuln| vuln.name.clone()).collect()
}

/// A single port whose vulnerability count reaches this on its own makes the
/// device `High`. Only 80 and 443 clear it in the current database, which is the
/// point: a reachable web server is the one service where one open port is
/// enough to call a device high-criticality.
pub const CRITICALITY_HIGH_PORT_VULN_COUNT: u32 = 8;

/// This many *distinct* ports carrying known vulnerabilities makes the device
/// `High` regardless of any individual count. This is what lets a broad host
/// reach `High` without a web server, and it is deliberately a count of
/// vulnerable ports rather than of open ports -- breadth of unremarkable ports
/// (a speaker exposing seven proprietary services with no CVE history) is not
/// the same risk as breadth of known-vulnerable ones.
pub const CRITICALITY_HIGH_VULNERABLE_PORTS: usize = 3;

/// This many open ports makes the device at least `Medium` even when none of
/// them carry a known vulnerability: attack surface we cannot attribute is
/// still attack surface.
pub const CRITICALITY_MEDIUM_OPEN_PORTS: usize = 4;

/// A vendor needs at least this many known vulnerabilities before its history
/// alone lifts a device to `Medium`. The floor exists because the count measures
/// the size of a vendor's CVE catalogue, which tracks how heavily researched the
/// vendor is at least as much as how exposed the device is -- so single-digit
/// catalogues are noise. Vendor history can never reach `High` on its own for
/// the same reason.
pub const CRITICALITY_MEDIUM_VENDOR_VULNS: usize = 10;

/// Everything criticality is derived from. Grouped into a struct because the
/// three inputs must travel together: scoring ports without the vendor and
/// scan-evidence context is what made the previous scale report `Low` for hosts
/// we had simply failed to scan.
#[derive(Debug, Clone, Copy)]
pub struct DeviceCriticalityInputs<'a> {
    /// Open ports the operator has not dismissed.
    pub ports: &'a [PortInfo],
    /// Known vulnerabilities for the device's vendor, already resolved through
    /// the vendor-name fallback walk.
    pub vendor_vuln_count: usize,
    /// Whether any scan has ever returned a definite verdict for this device.
    /// False means `Unknown`: absence of open ports is not evidence of safety.
    pub has_port_scan_evidence: bool,
}

/// Rate a device's criticality as the strongest tier any single signal supports.
///
/// Tiers, in order of precedence:
///
/// | Tier | Claim |
/// |---|---|
/// | `Unknown` | No ports, no port evidence, and no vendor history -- nothing can be claimed |
/// | `High` | One port with [`CRITICALITY_HIGH_PORT_VULN_COUNT`]+ known vulns, or [`CRITICALITY_HIGH_VULNERABLE_PORTS`]+ distinct vulnerable ports |
/// | `Medium` | Any vulnerable port, or [`CRITICALITY_MEDIUM_OPEN_PORTS`]+ open ports, or a vendor with [`CRITICALITY_MEDIUM_VENDOR_VULNS`]+ known vulns |
/// | `Low` | Scanned, and none of the above |
///
/// Taking the maximum over independent signals rather than summing weights is
/// deliberate. A weighted sum needs every signal calibrated against every other
/// one, and the underlying data will not support that: 44 of the port database's
/// weight sits on port 80 alone, and vendor counts span 1 to 211 while measuring
/// something only loosely related to risk. Under a sum, both distortions leak
/// into every verdict and weak signals accumulate into strong ones. Under a max,
/// each rule stands or falls on its own claim and every verdict traces to one
/// rule that fired.
pub async fn get_device_criticality(inputs: DeviceCriticalityInputs<'_>) -> String {
    ensure_port_vulns_initialized();

    let mut ports: Vec<u16> = inputs.ports.iter().map(|p| p.port).collect();
    ports.sort_unstable();
    ports.dedup();

    // The key spans every input, not just the ports. Keying on ports alone let
    // two devices with identical ports but different vendors collide, so
    // whichever was scored first decided for both.
    let key = format!(
        "{}|v{}|e{}",
        ports
            .iter()
            .map(|p| p.to_string())
            .collect::<Vec<String>>()
            .join(","),
        inputs.vendor_vuln_count,
        u8::from(inputs.has_port_scan_evidence),
    );

    let criticality_cache = CRITICALITY_CACHE_PTR.load();
    if let Some(entry) = criticality_cache.get(&key) {
        return entry.clone();
    }

    let criticality = classify_criticality(&ports, inputs);

    // Update the cache snapshot; concurrent writers can overwrite each other, which is fine for a cache.
    let mut updated_cache: HashMap<String, String> = CRITICALITY_CACHE_PTR.load().as_ref().clone();
    updated_cache.insert(key, criticality.clone());
    CRITICALITY_CACHE_PTR.store(Arc::new(updated_cache));
    criticality
}

/// Tier decision for an already-normalised port list. Split out from
/// [`get_device_criticality`] so the rules can be tested without the cache.
fn classify_criticality(ports: &[u16], inputs: DeviceCriticalityInputs<'_>) -> String {
    // `Unknown` requires the absence of *every* signal, not just of ports.
    // `DeviceCriticality::Unknown` sorts below `Low`, so it is the least visible
    // bucket in the UI; anything routed there is in practice deprioritised
    // below a host we scanned and found clean. That is the right home for a
    // sleeping thermostat we know nothing about, and the wrong home for a
    // vendor with a 211-CVE history whose surface we merely failed to measure.
    // So a vendor history that clears the `Medium` bar scores on its own, and
    // only a host with no ports, no scan evidence, and no vendor history is
    // reported as unrated.
    if ports.is_empty()
        && !inputs.has_port_scan_evidence
        && inputs.vendor_vuln_count < CRITICALITY_MEDIUM_VENDOR_VULNS
    {
        return "Unknown".to_string();
    }

    let port_vulns = PORT_VULNS_PTR.load();
    let vuln_count_of = |port: &u16| -> u32 {
        if let Some(count) = PORT_COUNTS_CACHE.get(port) {
            return *count;
        }
        let count = port_vulns.get(port).map_or(0, |info| info.count);
        PORT_COUNTS_CACHE.insert(*port, count);
        count
    };

    let vulnerable: Vec<u32> = ports
        .iter()
        .map(vuln_count_of)
        .filter(|count| *count > 0)
        .collect();
    let worst = vulnerable.iter().copied().max().unwrap_or(0);

    if worst >= CRITICALITY_HIGH_PORT_VULN_COUNT
        || vulnerable.len() >= CRITICALITY_HIGH_VULNERABLE_PORTS
    {
        return "High".to_string();
    }

    if !vulnerable.is_empty()
        || ports.len() >= CRITICALITY_MEDIUM_OPEN_PORTS
        || inputs.vendor_vuln_count >= CRITICALITY_MEDIUM_VENDOR_VULNS
    {
        return "Medium".to_string();
    }

    "Low".to_string()
}

pub async fn update(branch: &str, force: bool) -> Result<UpdateStatus> {
    info!("Starting port vulns update from backend");

    // Clear caches before update to remove stale entries
    clear_caches().await;

    let status = VULNS
        .update(branch, force, |data| {
            let vuln_info_json: VulnerabilityPortInfoListJSON =
                serde_json::from_str(data).with_context(|| "Failed to parse JSON data")?;
            Ok(VulnerabilityPortInfoList::new_from_json(vuln_info_json))
        })
        .await?;

    match status {
        UpdateStatus::Updated => info!("Port vulns were successfully updated."),
        UpdateStatus::NotUpdated => info!("Port vulns are already up to date."),
        UpdateStatus::FormatError => warn!("There was a format error in the port vulns data."),
        UpdateStatus::SkippedCustom => {
            info!("Update skipped because custom port vulns are in use.")
        }
    }

    Ok(status)
}

// Tests
#[cfg(test)]
mod tests {
    use super::*;
    use crate::port_info::PortInfo;
    use serial_test::serial;
    use std::sync::Once;

    /// Regression guard (helper/app/posture startup): the embedded port-vulns
    /// snapshot MUST decode and parse. If a bad regen makes it unparseable, the
    /// `VULNS` CloudModel `lazy_static` panics on its first deref and the daemon
    /// dies at startup. This catches it in CI instead. See also
    /// whitelists/blacklists/sensitive_paths/profiles/vendor_vulns.
    #[test]
    fn test_embedded_port_vulns_snapshot_parses() {
        serde_json::from_str::<VulnerabilityPortInfoListJSON>(&PORT_VULNS)
            .expect("embedded port vulns snapshot must parse as VulnerabilityPortInfoListJSON");
    }

    static INIT: Once = Once::new();

    fn setup() {
        INIT.call_once(|| {
            // Initialize logging or any other setup here
        });
    }

    #[tokio::test]
    #[serial]
    async fn test_get_ports() {
        setup();
        clear_caches().await;
        let ports = get_ports().await;
        assert!(!ports.is_empty(), "Ports list should not be empty");
    }

    #[tokio::test]
    #[serial]
    async fn test_get_http_ports() {
        setup();
        clear_caches().await;
        let http_ports = get_http_ports().await;
        assert!(
            !http_ports.is_empty(),
            "HTTP ports list should not be empty"
        );
    }

    #[tokio::test]
    #[serial]
    async fn test_get_https_ports() {
        setup();
        clear_caches().await;
        let https_ports = get_https_ports().await;
        assert!(
            !https_ports.is_empty(),
            "HTTPS ports list should not be empty"
        );
    }

    #[tokio::test]
    #[serial]
    async fn test_get_description_from_port() {
        setup();
        clear_caches().await;
        let port = 80; // Replace with a port known to exist in your data
        let description = get_description_from_port(port).await;
        assert!(
            !description.is_empty(),
            "Description for port {} should not be empty",
            port
        );
    }

    #[tokio::test]
    #[serial]
    async fn test_get_vulns_of_port() {
        setup();
        clear_caches().await;
        let port = 80; // Replace with a port known to have vulnerabilities
        let vulns = get_vulns_of_port(port).await;
        assert!(
            !vulns.is_empty(),
            "Vulnerabilities for port {} should not be empty",
            port
        );
    }

    fn port(port: u16) -> PortInfo {
        PortInfo {
            port,
            protocol: "tcp".to_string(),
            banner: "".to_string(),
            service: "".to_string(),
            dismissed: false,
        }
    }

    /// Inputs for a device that has been scanned, with no vendor CVE history --
    /// isolates whichever port rule the test is about.
    fn scanned(ports: &[PortInfo]) -> DeviceCriticalityInputs<'_> {
        DeviceCriticalityInputs {
            ports,
            vendor_vuln_count: 0,
            has_port_scan_evidence: true,
        }
    }

    /// The headline product claim: a reachable web server makes a device `High`.
    /// Port 80 carries by far the largest vulnerability catalogue in the DB, so
    /// it clears the single-port threshold on its own.
    #[tokio::test]
    #[serial]
    async fn test_get_device_criticality() {
        setup();
        clear_caches().await;

        let http_count = PORT_VULNS_PTR.load().get(&80).map_or(0, |info| info.count);
        assert!(
            http_count >= CRITICALITY_HIGH_PORT_VULN_COUNT,
            "port 80 has {} known vulns, below the {} needed for a lone port to rate High -- \
             either the DB shrank or the threshold moved",
            http_count,
            CRITICALITY_HIGH_PORT_VULN_COUNT
        );

        let ports = vec![port(80), port(22)];
        assert_eq!(get_device_criticality(scanned(&ports)).await, "High");
    }

    /// A silent host and a genuinely closed-up host both have zero open ports.
    /// Only the scan-evidence flag separates them, and conflating the two is what
    /// made unreachable devices report `Low`.
    #[tokio::test]
    #[serial]
    async fn test_criticality_unknown_without_scan_evidence() {
        setup();
        clear_caches().await;

        assert_eq!(
            get_device_criticality(DeviceCriticalityInputs {
                ports: &[],
                vendor_vuln_count: 0,
                has_port_scan_evidence: false,
            })
            .await,
            "Unknown"
        );
        assert_eq!(get_device_criticality(scanned(&[])).await, "Low");
    }

    /// Vendor history rates an unscanned host, because `Unknown` sorts below
    /// `Low` and would bury it. Failing to measure a heavily-CVE'd vendor's
    /// attack surface is not a reason to file it under the bucket the operator
    /// reads last.
    #[tokio::test]
    #[serial]
    async fn test_criticality_vendor_history_rates_unscanned_host() {
        setup();
        clear_caches().await;
        assert_eq!(
            get_device_criticality(DeviceCriticalityInputs {
                ports: &[],
                vendor_vuln_count: CRITICALITY_MEDIUM_VENDOR_VULNS * 10,
                has_port_scan_evidence: false,
            })
            .await,
            "Medium"
        );
        // Just below the bar is still unrated: a small catalogue is noise, so it
        // is not enough on its own to claim anything about an unscanned host.
        assert_eq!(
            get_device_criticality(DeviceCriticalityInputs {
                ports: &[],
                vendor_vuln_count: CRITICALITY_MEDIUM_VENDOR_VULNS - 1,
                has_port_scan_evidence: false,
            })
            .await,
            "Unknown"
        );
    }

    /// Vendor CVE history is a real signal on a scanned host, but capped at
    /// `Medium`: the count tracks how researched a vendor is as much as how
    /// exposed this device is.
    #[tokio::test]
    #[serial]
    async fn test_criticality_vendor_history_lifts_scanned_host_to_medium() {
        setup();
        clear_caches().await;

        let heavy = DeviceCriticalityInputs {
            ports: &[],
            vendor_vuln_count: CRITICALITY_MEDIUM_VENDOR_VULNS,
            has_port_scan_evidence: true,
        };
        assert_eq!(get_device_criticality(heavy).await, "Medium");

        let light = DeviceCriticalityInputs {
            vendor_vuln_count: CRITICALITY_MEDIUM_VENDOR_VULNS - 1,
            ..heavy
        };
        assert_eq!(get_device_criticality(light).await, "Low");
    }

    /// Open ports carrying no known vulnerability still count as attack surface,
    /// but breadth alone must not reach `High` -- otherwise a speaker exposing
    /// proprietary services outranks a host with a known-vulnerable service.
    #[tokio::test]
    #[serial]
    async fn test_criticality_open_port_breadth_caps_at_medium() {
        setup();
        clear_caches().await;

        // Ports chosen from the high range so they carry no entry in the DB.
        let wide: Vec<PortInfo> = (0..CRITICALITY_MEDIUM_OPEN_PORTS as u16)
            .map(|i| port(61000 + i))
            .collect();
        assert_eq!(get_device_criticality(scanned(&wide)).await, "Medium");
        assert_eq!(
            get_device_criticality(scanned(&wide[..CRITICALITY_MEDIUM_OPEN_PORTS - 1])).await,
            "Low"
        );
    }

    /// Distinct duplicate ports must not inflate the breadth rule.
    #[tokio::test]
    #[serial]
    async fn test_criticality_duplicate_ports_do_not_inflate_breadth() {
        setup();
        clear_caches().await;
        let dupes: Vec<PortInfo> = std::iter::repeat_with(|| port(61000))
            .take(CRITICALITY_MEDIUM_OPEN_PORTS + 2)
            .collect();
        assert_eq!(get_device_criticality(scanned(&dupes)).await, "Low");
    }

    /// The cache key must span every input. Keying on ports alone let two devices
    /// with identical ports but different vendors collide, so whichever was
    /// scored first silently decided for both.
    #[tokio::test]
    #[serial]
    async fn test_criticality_cache_distinguishes_non_port_inputs() {
        setup();
        clear_caches().await;

        let ports = [port(61000)];
        let plain = DeviceCriticalityInputs {
            ports: &ports,
            vendor_vuln_count: 0,
            has_port_scan_evidence: true,
        };
        assert_eq!(get_device_criticality(plain).await, "Low");

        let heavy_vendor = DeviceCriticalityInputs {
            vendor_vuln_count: CRITICALITY_MEDIUM_VENDOR_VULNS,
            ..plain
        };
        assert_eq!(get_device_criticality(heavy_vendor).await, "Medium");
    }

    /// Ports the live DB rates as vulnerable but below the single-port `High`
    /// threshold. Sourced from the DB rather than hardcoded so the breadth tests
    /// assert the rule and not a snapshot of the vulnerability data.
    fn mildly_vulnerable_ports(n: usize) -> Vec<PortInfo> {
        ensure_port_vulns_initialized();
        let vulns = PORT_VULNS_PTR.load();
        let mut candidates: Vec<u16> = vulns
            .iter()
            .filter(|(_, info)| info.count > 0 && info.count < CRITICALITY_HIGH_PORT_VULN_COUNT)
            .map(|(port, _)| *port)
            .collect();
        // Sorted so the selection is deterministic across runs; the DB is a HashMap.
        candidates.sort_unstable();
        assert!(
            candidates.len() >= n,
            "port vulns DB has only {} ports with a count in 1..{}, need {} to exercise \
             the vulnerable-port breadth rule",
            candidates.len(),
            CRITICALITY_HIGH_PORT_VULN_COUNT,
            n
        );
        candidates.into_iter().take(n).map(port).collect()
    }

    /// Breadth of *known-vulnerable* ports reaches `High` on its own, even when no
    /// single port does. This is the path a broad host takes to `High` without a
    /// web server.
    #[tokio::test]
    #[serial]
    async fn test_criticality_vulnerable_port_breadth_reaches_high() {
        setup();
        clear_caches().await;

        let ports = mildly_vulnerable_ports(CRITICALITY_HIGH_VULNERABLE_PORTS);
        assert_eq!(get_device_criticality(scanned(&ports)).await, "High");

        // One short of the threshold stays Medium: still vulnerable, not yet broad.
        assert_eq!(
            get_device_criticality(scanned(&ports[..CRITICALITY_HIGH_VULNERABLE_PORTS - 1])).await,
            "Medium"
        );
    }

    /// A single known-vulnerable port is enough for `Medium` regardless of how
    /// small its count is.
    #[tokio::test]
    #[serial]
    async fn test_criticality_single_vulnerable_port_is_medium() {
        setup();
        clear_caches().await;
        let ports = mildly_vulnerable_ports(1);
        assert_eq!(get_device_criticality(scanned(&ports)).await, "Medium");
    }

    // Modify the signature to zeros, perform an update, and check the signature changes
    #[tokio::test]
    #[serial]
    async fn test_signature_update_after_modification() {
        setup();
        clear_caches().await;
        let branch = "main";
        let signature = "00000000000000000000000000000000".to_string();
        VULNS.set_signature(signature.clone()).await;

        // Clear caches when signature changes
        clear_caches().await;

        // Perform the update
        let status = update(branch, false).await.expect("Update failed");

        // Check that the update was performed
        assert!(
            matches!(status, UpdateStatus::Updated | UpdateStatus::SkippedCustom),
            "Expected the update to be performed or skipped due to custom data"
        );

        // Check that the signature is no longer zeros
        let current_signature = VULNS.get_signature().await;
        assert_ne!(
            current_signature, "00000000000000000000000000000000",
            "Signature should have been updated"
        );
        assert!(
            !current_signature.is_empty(),
            "Signature should not be empty after update"
        );
    }

    // Additional test: Ensure that an invalid update does not change the signature
    #[tokio::test]
    #[serial]
    async fn test_invalid_update_does_not_change_signature() {
        setup();
        clear_caches().await;
        let branch = "nonexistent-branch";

        // Get the current signature
        let original_signature = VULNS.get_signature().await;

        // Attempt to perform an update from a nonexistent branch
        let result = update(branch, false).await;

        // The update should fail
        assert!(result.is_err(), "Update should have failed");

        // Check that the signature has not changed
        let current_signature = VULNS.get_signature().await;
        assert_eq!(
            current_signature, original_signature,
            "Signature should not have changed after failed update"
        );
    }

    #[tokio::test]
    #[serial]
    async fn test_caching_behavior() {
        setup();
        clear_caches().await;

        // First call should populate cache
        let http_ports1 = get_http_ports().await;
        let https_ports1 = get_https_ports().await;

        let port = if !http_ports1.is_empty() {
            http_ports1[0]
        } else {
            80
        };

        let name1 = get_name_from_port(port).await;
        let description1 = get_description_from_port(port).await;
        let vulns1 = get_vulns_of_port(port).await;

        // Second call should use cache
        let http_ports2 = get_http_ports().await;
        let https_ports2 = get_https_ports().await;
        let name2 = get_name_from_port(port).await;
        let description2 = get_description_from_port(port).await;
        let vulns2 = get_vulns_of_port(port).await;

        // Verify results are the same
        assert_eq!(http_ports1, http_ports2, "Cached HTTP ports should match");
        assert_eq!(
            https_ports1, https_ports2,
            "Cached HTTPS ports should match"
        );
        assert_eq!(name1, name2, "Cached port name should match");
        assert_eq!(
            description1, description2,
            "Cached port description should match"
        );
        assert_eq!(vulns1, vulns2, "Cached port vulnerabilities should match");
    }
}
