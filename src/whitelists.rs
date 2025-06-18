use crate::sessions::{Session, SessionInfo, WhitelistState};
use crate::whitelists_db::WHITELISTS;
use anyhow::{anyhow, Context, Result};
use chrono;
use chrono::{DateTime, Utc};
use dashmap::DashSet;
use edamame_models::*;
use ipnet::IpNet;
use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use tracing::{error, info, trace, warn};
use undeadlock::*;

// Constants
const WHITELISTS_FILE_NAME: &str = "whitelists-db.json";

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(deny_unknown_fields)] // Enforce no unknown fields
pub struct WhitelistEndpoint {
    pub domain: Option<String>,
    pub ip: Option<String>,
    pub port: Option<u16>,
    pub protocol: Option<String>,
    pub as_number: Option<u32>,
    pub as_country: Option<String>,
    pub as_owner: Option<String>,
    pub process: Option<String>,
    pub description: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(deny_unknown_fields)] // Enforce no unknown fields
pub struct WhitelistInfo {
    pub name: String,
    pub extends: Option<Vec<String>>,
    pub endpoints: Vec<WhitelistEndpoint>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)] // Enforce no unknown fields
pub struct WhitelistsJSON {
    pub date: String,
    pub signature: Option<String>,
    pub whitelists: Vec<WhitelistInfo>,
}

#[derive(Clone)]
pub struct Whitelists {
    pub date: String,
    pub signature: Option<String>,
    pub whitelists: Arc<CustomDashMap<String, WhitelistInfo>>,
}

impl From<Whitelists> for WhitelistsJSON {
    fn from(whitelists: Whitelists) -> Self {
        WhitelistsJSON {
            date: whitelists.date,
            signature: whitelists.signature,
            whitelists: whitelists
                .whitelists
                .iter()
                .map(|r| r.value().clone())
                .collect(),
        }
    }
}

impl CloudSignature for Whitelists {
    fn get_signature(&self) -> String {
        self.signature.clone().unwrap_or_default()
    }
    fn set_signature(&mut self, signature: String) {
        self.signature = Some(signature);
    }
}

impl Whitelists {
    /// Creates a new Whitelists instance from the provided JSON data.
    pub fn new_from_json(whitelist_info: WhitelistsJSON) -> Self {
        info!("Loading whitelists from JSON");

        let whitelists = Arc::new(CustomDashMap::new("Whitelists"));

        for info in whitelist_info.whitelists {
            whitelists.insert(info.name.clone(), info);
        }

        info!("Loaded {} whitelists", whitelists.len());

        Whitelists {
            date: whitelist_info.date,
            signature: whitelist_info.signature,
            whitelists,
        }
    }

    // Create a whitelist from a list of sessions
    pub fn new_from_sessions(sessions: &Vec<SessionInfo>) -> Self {
        let whitelists = Arc::new(CustomDashMap::new("Whitelists"));

        // Create a whitelist with the current sessions
        let mut endpoints = Vec::new();
        // HashSet to track unique endpoint fingerprints for deduplication
        let mut unique_fingerprints = std::collections::HashSet::new();

        for session in sessions {
            let endpoint = WhitelistEndpoint {
                // Do not include the domain if set to "Unknown" or "Resolving"
                domain: if session.dst_domain == Some("Unknown".to_string())
                    || session.dst_domain == Some("Resolving".to_string())
                {
                    None
                } else {
                    session.dst_domain.clone()
                },
                // Always include the IP address as a fallback to when the domain is set but not resolved
                ip: Some(session.session.dst_ip.to_string()),
                // Always include the port
                port: Some(session.session.dst_port),
                // Always include the protocol
                protocol: Some(session.session.protocol.to_string()),
                // Don't include AS info
                as_number: None, // Session doesn't have AS info
                as_country: None,
                as_owner: None,
                // Include the process info if available
                process: session.l7.as_ref().map(|l7| l7.process_name.clone()),
                description: Some(format!(
                    "Auto-generated from session: {}:{} -> {}:{}",
                    session.session.src_ip,
                    session.session.src_port,
                    session.session.dst_ip,
                    session.session.dst_port
                )),
            };

            // Create a fingerprint tuple that uniquely identifies this endpoint
            // (excluding description which doesn't affect deduplication)
            let fingerprint = (
                endpoint.domain.clone(),
                endpoint.ip.clone(),
                endpoint.port,
                endpoint.protocol.clone(),
                endpoint.as_number,
                endpoint.as_country.clone(),
                endpoint.as_owner.clone(),
                endpoint.process.clone(),
            );

            // Only add the endpoint if we haven't seen this fingerprint before
            if unique_fingerprints.insert(fingerprint) {
                endpoints.push(endpoint);
            }
        }

        let whitelist_info = WhitelistInfo {
            name: "custom_whitelist".to_string(),
            extends: None,
            endpoints,
        };

        whitelists.insert(whitelist_info.name.clone(), whitelist_info);

        // Use "Month DDth YYYY" format as seen in whitelists-db.json
        let today = chrono::Local::now().format("%B %dth %Y").to_string();

        Whitelists {
            date: today,
            signature: None, // No signature for auto-generated whitelists
            whitelists,
        }
    }

    /// Retrieves all endpoints for a given whitelist, including inherited ones.
    fn get_all_endpoints(
        &self,
        whitelist_name: &str,
        visited: &mut HashSet<String>,
    ) -> Result<Vec<WhitelistEndpoint>> {
        // Get the whitelist info and handle the case where it's not found
        let info = self
            .whitelists
            .get(whitelist_name)
            .ok_or_else(|| anyhow!("Whitelist not found: {}", whitelist_name))?;

        // Clone the necessary data
        let endpoints = info.endpoints.clone();
        let extends = info.extends.clone();

        // Drop the Ref to release the lock on the DashMap
        drop(info);

        // Initialize the list of all endpoints with the current ones
        let mut all_endpoints = endpoints;

        if let Some(extends) = extends {
            for parent in extends {
                if !visited.contains(&parent) {
                    visited.insert(parent.clone());
                    // Recursively get endpoints from inherited whitelists
                    all_endpoints.extend(self.get_all_endpoints(&parent, visited)?);
                }
            }
        }
        Ok(all_endpoints)
    }

    //--------------------------------------------------------------------
    /// Merge two JSON whitelist blobs (same `WhitelistsJSON` format) and
    /// return a single JSON string with endpoints deduplicated.
    ///
    /// If the same whitelist `name` exists in both inputs the endpoints are
    /// merged and deduplicated; the `extends` field is kept from the *first*
    /// argument unless it is `None`, in which case the second's value is
    /// used.  Metadata fields (`date`, `signature`) from the first JSON are
    /// preserved.
    //--------------------------------------------------------------------
    pub fn merge_custom_whitelists(json_a: &str, json_b: &str) -> Result<String> {
        use serde_json;

        let a: WhitelistsJSON =
            serde_json::from_str(json_a).context("Failed to parse first whitelist JSON")?;
        let b: WhitelistsJSON =
            serde_json::from_str(json_b).context("Failed to parse second whitelist JSON")?;

        // Helper to fingerprint an endpoint for deduplication
        fn fingerprint(
            ep: &WhitelistEndpoint,
        ) -> (
            Option<String>,
            Option<String>,
            Option<u16>,
            Option<String>,
            Option<u32>,
            Option<String>,
            Option<String>,
            Option<String>,
        ) {
            (
                ep.domain.clone(),
                ep.ip.clone(),
                ep.port,
                ep.protocol.clone(),
                ep.as_number,
                ep.as_country.clone(),
                ep.as_owner.clone(),
                ep.process.clone(),
            )
        }

        // Build a map name -> WhitelistInfo (merged)
        let mut merged: std::collections::HashMap<String, WhitelistInfo> =
            std::collections::HashMap::new();

        // Closure to insert/merge info into map
        let mut add_info = |info: &WhitelistInfo| {
            let entry = merged
                .entry(info.name.clone())
                .or_insert_with(|| WhitelistInfo {
                    name: info.name.clone(),
                    extends: info.extends.clone(),
                    endpoints: Vec::new(),
                });

            // Prefer extends from the first source that specified it
            if entry.extends.is_none() {
                entry.extends = info.extends.clone();
            }

            entry.endpoints.extend(info.endpoints.clone());
        };

        for info in &a.whitelists {
            add_info(info);
        }
        for info in &b.whitelists {
            add_info(info);
        }

        // Deduplicate endpoints per whitelist
        for info in merged.values_mut() {
            let mut seen = std::collections::HashSet::new();
            info.endpoints.retain(|ep| seen.insert(fingerprint(ep)));
        }

        // Assemble output JSON using metadata from first blob
        let output = WhitelistsJSON {
            date: a.date,
            signature: a.signature, // Could compute new; keep original for now
            whitelists: merged.into_values().collect(),
        };

        Ok(serde_json::to_string(&output)?)
    }
}

lazy_static! {
    static ref LISTS: CloudModel<Whitelists> = {
        let model = CloudModel::initialize(WHITELISTS_FILE_NAME.to_string(), WHITELISTS, |data| {
            let whitelist_info_json: WhitelistsJSON =
                serde_json::from_str(data).with_context(|| "Failed to parse JSON data")?;
            Ok(Whitelists::new_from_json(whitelist_info_json))
        })
        .expect("Failed to initialize CloudModel");
        model
    };

    // Cache aggregated endpoints per whitelist per signature
    static ref ENDPOINT_CACHE: CustomDashMap<String, Arc<Vec<WhitelistEndpoint>>> = CustomDashMap::new("Whitelist Endpoint Cache");

    // Tracks whitelists currently being flattened so that concurrent callers
    // can wait instead of spawning duplicate expensive work ("single-flight").
    static ref ENDPOINT_PENDING: DashSet<String> = DashSet::new();

    static ref LAST_WHITELIST_RUN: Mutex<DateTime<Utc>> =
        Mutex::new(DateTime::<Utc>::from(std::time::UNIX_EPOCH));

    // Flag indicating a full whitelist recompute is required.
    static ref NEED_FULL_RECOMPUTE_WHITELIST: AtomicBool = AtomicBool::new(false);
}

/// Checks if a whitelist name exists in the current model (default or custom).
pub async fn is_valid_whitelist(whitelist_name: &str) -> bool {
    LISTS
        .data
        .read()
        .await
        .whitelists
        .contains_key(whitelist_name)
}

/// Checks if a given session is in the specified whitelist.
/// Returns a tuple (bool, Option<String>) where:
/// - The boolean indicates whether the session is in the whitelist
/// - If false, the Option<String> contains a reason why the session didn't match
pub async fn is_session_in_whitelist(
    session_domain: Option<&str>,
    session_ip: Option<&str>,
    port: u16,
    protocol: &str,
    whitelist_name: &str,
    as_number: Option<u32>,
    as_country: Option<&str>,
    as_owner: Option<&str>,
    process: Option<&str>,
) -> (bool, Option<String>) {
    trace!(
        "Checking if domain: {:?}, ip: {:?}, port: {} ({}) is in whitelist {} with ASN {:?}, Country {:?}, Owner {:?}, L7 Process {:?}",
        session_domain,
        session_ip,
        port,
        protocol,
        whitelist_name,
        as_number,
        as_country,
        as_owner,
        process
    );

    let mut visited = HashSet::new();
    visited.insert(whitelist_name.to_string());

    // Pre-snapshot the model once to avoid holding async locks during flatten
    let model_clone = LISTS.data.read().await.clone();
    // Try cache first
    let endpoints_arc = if let Some(entry) = ENDPOINT_CACHE.get(whitelist_name) {
        entry.clone()
    } else {
        // Single-flight guard: if another task is already building this cache, wait.
        let key = whitelist_name.to_string();
        if ENDPOINT_PENDING.insert(key.clone()) {
            // We are the first – do the expensive flatten.
            let spawn_key = key.clone();
            let mut visited_clone = visited.clone();
            let eps_result = tokio::task::spawn_blocking(move || {
                model_clone.get_all_endpoints(&spawn_key, &mut visited_clone)
            })
            .await;

            let eps = eps_result
                .unwrap_or_else(|e| {
                    warn!("Join error flattening whitelist '{}': {}", key, e);
                    Err(anyhow!("flatten join error"))
                })
                .unwrap_or_else(|err| {
                    warn!(
                        "Error retrieving endpoints for whitelist '{}': {}",
                        key, err
                    );
                    Vec::new()
                });

            let arc_eps = Arc::new(eps);
            ENDPOINT_CACHE.insert(key.clone(), arc_eps.clone());
            ENDPOINT_PENDING.remove(&key);
            arc_eps
        } else {
            // Somebody else is working; spin-wait (very short) until cache filled.
            loop {
                if let Some(entry) = ENDPOINT_CACHE.get(whitelist_name) {
                    break entry.clone();
                }
                tokio::task::yield_now().await;
            }
        }
    };

    if endpoints_arc.is_empty() {
        return (
            false,
            Some(format!(
                "Whitelist '{}' contains no endpoints",
                whitelist_name
            )),
        );
    }

    // Match the session against the endpoints
    for endpoint in endpoints_arc.iter() {
        let (matches, _reason) = endpoint_matches_with_reason(
            session_domain,
            session_ip,
            port,
            protocol,
            as_number,
            as_country,
            as_owner,
            process,
            endpoint,
        );

        if matches {
            trace!("Matched whitelist endpoint: {:?}", endpoint);
            return (true, None);
        }
    }

    // If we got here, no endpoint matched
    let reason = format!(
        "No matching endpoint found in whitelist '{}' for domain: {:?}, ip: {:?}, port: {}, protocol: {}, ASN: {:?}, country: {:?}, owner: {:?}, process: {:?}",
        whitelist_name, session_domain, session_ip, port, protocol, as_number, as_country, as_owner, process
    );

    (false, Some(reason))
}

/// Helper function to match the session against a whitelist endpoint with reason.
fn endpoint_matches_with_reason(
    session_domain: Option<&str>,
    session_ip: Option<&str>,
    port: u16,
    protocol: &str,
    as_number: Option<u32>,
    as_country: Option<&str>,
    as_owner: Option<&str>,
    process: Option<&str>,
    endpoint: &WhitelistEndpoint,
) -> (bool, Option<String>) {
    // Process name, protocol and port are fundamental for service identification - they must match
    let protocol_match = protocol_matches(protocol, &endpoint.protocol);
    let port_match = port_matches(port, endpoint.port);
    let process_match = process_matches(process, &endpoint.process);

    if !protocol_match || !port_match || !process_match {
        // If protocol or port don't match, there's no need to proceed further
        let mut reasons = Vec::new();
        if !protocol_match {
            reasons.push(format!(
                "Protocol mismatch: {} not matching {:?}",
                protocol, endpoint.protocol
            ));
        }
        if !port_match {
            reasons.push(format!(
                "Port mismatch: {} not matching {:?}",
                port, endpoint.port
            ));
        }
        if !process_match {
            reasons.push(format!(
                "Process mismatch: {:?} not matching {:?}",
                process, endpoint.process
            ));
        }
        return (false, Some(reasons.join(", ")));
    }

    // Check if we have a domain match
    let domain_match = domain_matches(session_domain, &endpoint.domain);
    let domain_specified = endpoint.domain.is_some();

    // If domain is specified and matches, other checks are irrelevant
    if domain_specified && domain_match {
        return (true, None);
    }

    // Check if we have an IP match
    let ip_match = ip_matches(session_ip, &endpoint.ip);
    let ip_specified = endpoint.ip.is_some();

    // If IP is specified and matches, return true
    if ip_specified && ip_match {
        return (true, None);
    }

    // Track whether we need to check the domain or IP
    let entity_matched = (domain_specified && domain_match) || (ip_specified && ip_match);
    let needs_entity_match = domain_specified || ip_specified;

    // If entity matching is required but failed, we don't match
    if needs_entity_match && !entity_matched {
        let mut reasons = Vec::new();
        if domain_specified {
            reasons.push(format!(
                "Domain mismatch: {:?} not matching {:?}",
                session_domain, endpoint.domain
            ));
        }
        if ip_specified {
            reasons.push(format!(
                "IP mismatch: {:?} not matching {:?}",
                session_ip, endpoint.ip
            ));
        }
        return (false, Some(reasons.join(", ")));
    }

    // AS checks are only relevant if no domain/IP were specified or if they weren't provided in the session
    let should_check_as = (!domain_specified && !ip_specified)
        || (endpoint.as_number.is_some()
            || endpoint.as_owner.is_some()
            || endpoint.as_country.is_some());

    if should_check_as {
        // Check AS number if specified (most specific identifier)
        if let Some(whitelist_asn) = endpoint.as_number {
            match as_number {
                Some(session_asn) if session_asn == whitelist_asn => {
                    // ASN matches, continue to next checks
                }
                _ => {
                    return (
                        false,
                        Some(format!(
                            "AS number mismatch: {:?} not matching {:?}",
                            as_number, endpoint.as_number
                        )),
                    );
                }
            }
        }

        // Check AS owner if specified
        if let Some(ref whitelist_owner) = endpoint.as_owner {
            match as_owner {
                Some(session_owner) if session_owner.eq_ignore_ascii_case(whitelist_owner) => {
                    // Owner matches, continue
                }
                _ => {
                    return (
                        false,
                        Some(format!(
                            "Owner mismatch: {:?} not matching {:?}",
                            as_owner, endpoint.as_owner
                        )),
                    );
                }
            }
        }

        // Check AS country if specified
        if let Some(ref whitelist_country) = endpoint.as_country {
            match as_country {
                Some(session_country)
                    if session_country.eq_ignore_ascii_case(whitelist_country) =>
                {
                    // Country matches, continue
                }
                _ => {
                    return (
                        false,
                        Some(format!(
                            "Country mismatch: {:?} not matching {:?}",
                            as_country, endpoint.as_country
                        )),
                    );
                }
            }
        }
    }

    // All required checks passed
    (true, None)
}

/// Helper function to match domain names with optional wildcards.
fn domain_matches(session_domain: Option<&str>, endpoint_domain: &Option<String>) -> bool {
    match endpoint_domain {
        Some(pattern) => match session_domain {
            Some(domain) => {
                // Convert both to lowercase for case-insensitive matching
                let domain = domain.to_lowercase();
                let pattern = pattern.to_lowercase();

                // Check if pattern contains a wildcard
                if pattern.contains('*') {
                    // Handle prefix wildcard (*.example.com)
                    if pattern.starts_with("*.") {
                        let suffix = &pattern[2..]; // Remove the "*." prefix

                        // If domain exactly matches suffix (e.g., "example.com" vs "*.example.com"),
                        // this should NOT match since *.example.com means there must be a subdomain
                        if domain == suffix {
                            return false;
                        }

                        // For a valid subdomain match:
                        // 1. Domain must end with the suffix
                        // 2. The character before the suffix must be a dot (.)
                        return domain.ends_with(suffix)
                            && domain.len() > suffix.len()
                            && domain.as_bytes()[domain.len() - suffix.len() - 1] == b'.';
                    }

                    // Handle suffix wildcard (example.*)
                    if pattern.ends_with(".*") {
                        let prefix = &pattern[..pattern.len() - 2]; // Remove the ".*" suffix

                        // For wildcard to match:
                        // 1. domain must start with the prefix
                        // 2. if the domain is longer than the prefix, the next character must be a dot
                        //    (ensuring prefix is a complete domain component)
                        if domain.starts_with(prefix) {
                            if domain.len() == prefix.len() {
                                // Domain exactly matches prefix, which is valid
                                return true;
                            } else if domain.len() > prefix.len()
                                && domain.as_bytes()[prefix.len()] == b'.'
                            {
                                // Domain has the prefix followed by a dot and any TLD, which is valid
                                // For suffix wildcards (example.*), we want to match any TLD
                                return true;
                            }
                        }

                        // All other cases are not matches
                        return false;
                    }

                    // Handle middle position wildcard (prefix.*.suffix)
                    let parts: Vec<&str> = pattern.split('*').collect();
                    if parts.len() == 2 {
                        let prefix = parts[0];
                        let suffix = parts[1];

                        // For wildcard to match, domain must start with prefix and end with suffix
                        // and the domain must be longer than just the prefix and suffix combined
                        return domain.starts_with(prefix)
                            && domain.ends_with(suffix)
                            && domain.len() > prefix.len() + suffix.len();
                    }

                    // Unsupported wildcard pattern
                    return false;
                }

                // Exact match for non-wildcard patterns
                domain == pattern
            }
            None => false,
        },
        None => true, // No domain specified in the endpoint, so it's a match
    }
}

/// Helper function to match IP addresses and prefixes.
fn ip_matches(session_ip: Option<&str>, endpoint_ip: &Option<String>) -> bool {
    match endpoint_ip {
        Some(pattern) => match session_ip {
            Some(ip_str) => {
                let ip_addr = match ip_str.parse::<IpAddr>() {
                    Ok(ip) => ip,
                    Err(_) => return false,
                };

                if pattern.contains('/') {
                    // Pattern is an IP network (e.g., "192.168.1.0/24")
                    match pattern.parse::<IpNet>() {
                        Ok(ip_network) => ip_network.contains(&ip_addr),
                        Err(_) => false,
                    }
                } else {
                    // Pattern is a single IP address
                    match pattern.parse::<IpAddr>() {
                        Ok(pattern_ip) => pattern_ip == ip_addr,
                        Err(_) => false,
                    }
                }
            }
            None => false,
        },
        None => true, // No IP specified in the endpoint, so it's a match
    }
}

/// Helper function to match ports.
fn port_matches(port: u16, whitelist_port: Option<u16>) -> bool {
    whitelist_port.map_or(true, |wp| wp == port)
}

fn process_matches(session_l7: Option<&str>, whitelist_l7: &Option<String>) -> bool {
    match whitelist_l7 {
        Some(w_l7) => match session_l7 {
            Some(s_l7) => s_l7.eq_ignore_ascii_case(w_l7),
            None => false,
        },
        None => true,
    }
}

fn protocol_matches(session_protocol: &str, whitelist_protocol: &Option<String>) -> bool {
    match whitelist_protocol {
        // Convert to uppercase both sides
        Some(w_protocol) => session_protocol.eq_ignore_ascii_case(w_protocol),
        None => true,
    }
}

/// Updates the whitelists by fetching the latest data from the specified branch.
/// This function utilizes the `CloudModel` to perform the update.
pub async fn update(branch: &str, force: bool) -> Result<UpdateStatus> {
    info!("Starting whitelists update from backend");

    // Perform the update directly on the model
    let status = LISTS
        .update(branch, force, |data| {
            let whitelist_info_json: WhitelistsJSON =
                serde_json::from_str(data).with_context(|| "Failed to parse JSON data")?;
            Ok(Whitelists::new_from_json(whitelist_info_json))
        })
        .await?;

    // Clear cache whenever we update underlying data
    ENDPOINT_CACHE.clear();
    // Signal downstream that a full whitelist recomputation is needed
    NEED_FULL_RECOMPUTE_WHITELIST.store(true, Ordering::SeqCst);

    match status {
        UpdateStatus::Updated => info!("Whitelists were successfully updated."),
        UpdateStatus::NotUpdated => info!("Whitelists are already up to date."),
        UpdateStatus::FormatError => warn!("There was a format error in the whitelists data."),
        UpdateStatus::SkippedCustom => {
            info!("Update skipped because custom whitelists are in use.")
        }
    }

    Ok(status)
}

/// Sets custom whitelist data, replacing the current data (default or previous custom).
/// Clears the endpoint cache upon successful update or reset.
pub async fn set_custom_whitelists(whitelist_json: &str) -> Result<(), anyhow::Error> {
    info!("Attempting to set custom whitelists.");
    // Clear the custom whitelists if the JSON is empty
    if whitelist_json.is_empty() {
        info!("Received empty JSON, resetting whitelists to default.");
        LISTS.reset_to_default().await;
        ENDPOINT_CACHE.clear(); // Clear cache after reset
        NEED_FULL_RECOMPUTE_WHITELIST.store(true, Ordering::SeqCst);
        return Ok(());
    }

    let whitelist_result = serde_json::from_str::<WhitelistsJSON>(whitelist_json);

    match whitelist_result {
        Ok(whitelist_data) => {
            info!("Successfully parsed custom whitelist JSON.");
            let whitelist = Whitelists::new_from_json(whitelist_data);
            LISTS.set_custom_data(whitelist).await;
            ENDPOINT_CACHE.clear(); // Clear cache after successful set
            NEED_FULL_RECOMPUTE_WHITELIST.store(true, Ordering::SeqCst);
            return Ok(());
        }
        Err(e) => {
            error!(
                "Error parsing custom whitelist JSON: {}. Resetting to default.",
                e
            );
            LISTS.reset_to_default().await;
            ENDPOINT_CACHE.clear(); // Clear cache after reset due to error
            NEED_FULL_RECOMPUTE_WHITELIST.store(true, Ordering::SeqCst);
            return Err(anyhow!("Error parsing custom whitelist JSON: {}", e));
        }
    }
}

/// Incrementally recomputes whitelist conformance for the provided session map.
///
/// The function will:
/// 1. Determine if the underlying whitelist database has changed via the
///    NEED_FULL_RECOMPUTE_WHITELIST flag – this triggers a full recompute.
/// 2. Otherwise evaluate only sessions with `last_modified` newer than the last
///    execution **or** still in `Unknown` state.
/// 3. Refresh `whitelist_exceptions` vector & `whitelist_conformance` flag.
pub async fn recompute_whitelist_for_sessions(
    whitelist_name_arc: &Arc<CustomRwLock<String>>, // currently configured name
    sessions: &Arc<CustomDashMap<Session, SessionInfo>>,
    whitelist_exceptions: &Arc<CustomRwLock<Vec<Session>>>,
    whitelist_conformance: &Arc<AtomicBool>,
    last_exception_time: &Arc<CustomRwLock<DateTime<Utc>>>,
) {
    use tracing::{info, trace};
    trace!("Starting incremental whitelist recomputation");

    // Snapshot of current configuration
    let wl_name_now = whitelist_name_arc.read().await.clone();

    // Determine if a full recompute has been requested via the global flag.
    let flag_full_recompute = NEED_FULL_RECOMPUTE_WHITELIST.swap(false, Ordering::SeqCst);

    // Snapshot last run timestamp (used to decide incremental vs. full recompute)
    let last_run_ts = {
        let guard = LAST_WHITELIST_RUN.lock().unwrap();
        *guard
    };

    // Decide whether to run a full recompute or an incremental pass.  The
    // decision now depends solely on the module-wide flag that is set whenever
    // the underlying whitelist database changes (e.g., update / custom load).
    let full_recompute = flag_full_recompute;

    // Collect sessions needing evaluation and gather snapshots first
    // ----------------------------------------------------------------------------------
    // Skip the whole process if no whitelist is active (empty name) and model not custom
    let should_skip = wl_name_now.is_empty() && !LISTS.is_custom().await;

    if should_skip {
        trace!("Skipping whitelist evaluation because no whitelist is active");
        return;
    }

    // Build working sets for faster processing: Keep exceptions that still exist + find all sessions to evaluate
    let (current_exceptions, sessions_to_evaluate, session_snapshots) = {
        // 1. Get current exceptions (we'll filter only those still in sessions map)
        let exceptions = whitelist_exceptions.read().await.clone();

        // 2. Collect all sessions needing evaluation
        let mut to_evaluate: Vec<Session> = if full_recompute {
            // If full recompute, gather all sessions
            sessions.iter().map(|entry| entry.key().clone()).collect()
        } else {
            // Otherwise just sessions modified since last run or in Unknown state
            sessions
                .iter()
                .filter(|entry| {
                    entry.value().last_modified > last_run_ts
                        || entry.value().is_whitelisted == WhitelistState::Unknown
                })
                .map(|entry| entry.key().clone())
                .collect()
        };

        // Always re-evaluate current exceptions
        for exception in &exceptions {
            if !to_evaluate.contains(exception) && sessions.contains_key(exception) {
                to_evaluate.push(exception.clone());
            }
        }

        // 3. Take a snapshot of all session info we're about to evaluate
        // This avoids holding locks during evaluation
        let mut snapshots = HashMap::with_capacity(to_evaluate.len());
        for session_key in &to_evaluate {
            if let Some(entry) = sessions.get(session_key) {
                snapshots.insert(session_key.clone(), entry.clone());
            }
        }

        // Return all three working sets
        (exceptions, to_evaluate, snapshots)
    };

    // Perform all whitelist checks for all sessions WITHOUT locks
    // ----------------------------------------------------------------------------------

    trace!(
        "Pre-computing whitelist results for {} sessions",
        sessions_to_evaluate.len()
    );

    // Pre-calculate whitelist status for all sessions (this is the expensive part)
    let mut evaluation_results = Vec::with_capacity(sessions_to_evaluate.len());
    let mut new_exceptions = Vec::<Session>::new(); // We'll accumulate non-conforming sessions here

    // Important: First add exceptions that still exist in the sessions map.
    // Use the sessions map directly, not snapshots, to keep current exceptions
    // even if not selected for re-evaluation
    for exception in &current_exceptions {
        if sessions.contains_key(exception) {
            new_exceptions.push(exception.clone());
        }
    }

    info!("Processing {} sessions", sessions_to_evaluate.len());

    for session_key in &sessions_to_evaluate {
        // Skip if we don't have a snapshot (might have been removed)
        if let Some(snapshot) = session_snapshots.get(session_key) {
            // Perform the whitelist check - this is done WITHOUT any locks held
            let (is_ok, reason) = is_session_in_whitelist(
                snapshot.dst_domain.as_deref(),
                Some(&snapshot.session.dst_ip.to_string()),
                snapshot.session.dst_port,
                snapshot.session.protocol.to_string().as_str(),
                &wl_name_now,
                snapshot.dst_asn.as_ref().map(|asn| asn.as_number),
                snapshot.dst_asn.as_ref().map(|asn| asn.country.as_str()),
                snapshot.dst_asn.as_ref().map(|asn| asn.owner.as_str()),
                snapshot.l7.as_ref().map(|l7| l7.process_name.as_str()),
            )
            .await;

            // Store the result directly in the main results collection
            evaluation_results.push((session_key.clone(), is_ok, reason));

            // Track non-conforming sessions for the exceptions list
            if !is_ok && !new_exceptions.contains(session_key) {
                trace!("Adding to new_exceptions: {:?}", session_key);
                new_exceptions.push(session_key.clone());
            } else if is_ok {
                // If it's now conforming, remove from exceptions if present
                new_exceptions.retain(|s| s != session_key);
            }
        }
    }

    // Apply all results with minimal lock time
    // ----------------------------------------------------------------------------------

    trace!(
        "Applying {} whitelist evaluations with minimal lock time",
        evaluation_results.len()
    );

    // Prepare exception list
    new_exceptions.sort();
    new_exceptions.dedup();

    // Fast bulk update of session status - very brief locks per session
    for (session_key, is_conforming, reason) in evaluation_results {
        // Re-acquire a write lock briefly to update just this session
        // This minimizes lock contention by holding the lock for the absolute minimum time
        if let Some(mut entry) = sessions.get_mut(&session_key) {
            let info_mut = entry.value_mut();

            // Get the current values
            let current_state = info_mut.is_whitelisted;
            let current_reason = info_mut.whitelist_reason.clone();

            // Determine new values
            let new_state = if is_conforming {
                WhitelistState::Conforming
            } else {
                WhitelistState::NonConforming
            };

            let new_reason = if is_conforming { None } else { reason };

            // Only update if values changed
            let state_changed = current_state != new_state;
            let reason_changed = current_reason != new_reason;

            if state_changed || reason_changed {
                info_mut.is_whitelisted = new_state;
                info_mut.whitelist_reason = new_reason;
                info_mut.last_modified = Utc::now();
            }
        }
    }

    // Update the whitelist exceptions list atomically
    let exception_list_changed = {
        let guard = whitelist_exceptions.read().await;
        trace!("Current exceptions: {:?}", *guard);
        trace!("New exceptions: {:?}", new_exceptions);
        *guard != new_exceptions
    };

    if exception_list_changed {
        trace!(
            "Updating whitelist exceptions list: {} items",
            new_exceptions.len()
        );
        *whitelist_exceptions.write().await = new_exceptions.clone();
    }

    // Update conformance flag & timestamp
    let nonconforming_exists = !new_exceptions.is_empty();

    if nonconforming_exists {
        whitelist_conformance.store(false, Ordering::Relaxed);
        *last_exception_time.write().await = Utc::now();
    } else {
        whitelist_conformance.store(true, Ordering::Relaxed);
    }

    // Update last run timestamp
    {
        let mut guard = LAST_WHITELIST_RUN.lock().unwrap();
        *guard = Utc::now();
    }

    info!(
        "Whitelist recomputation completed with {} exceptions for {} sessions",
        new_exceptions.len(),
        sessions_to_evaluate.len()
    );
}

// ---- Public wrapper helpers for access while keeping LISTS private ----

/// Reset whitelist model to default bundled lists and clear caches.
pub async fn reset_to_default() {
    LISTS.reset_to_default().await;
    ENDPOINT_CACHE.clear();
    NEED_FULL_RECOMPUTE_WHITELIST.store(true, Ordering::SeqCst);
}

/// `true` when custom whitelist data is loaded.
pub async fn is_custom() -> bool {
    LISTS.is_custom().await
}

/// Snapshot as JSON struct.
pub async fn current_json() -> WhitelistsJSON {
    let data = LISTS.data.read().await.clone();
    WhitelistsJSON::from(data)
}

#[cfg(test)]
pub async fn overwrite_with_test_data(data: Whitelists) {
    LISTS.overwrite_with_test_data(data).await;
    ENDPOINT_CACHE.clear();
    NEED_FULL_RECOMPUTE_WHITELIST.store(true, Ordering::SeqCst);
}

pub async fn get_whitelists() -> String {
    let list_model = &LISTS;
    let data = list_model.data.read().await;
    let json_data = WhitelistsJSON::from(data.clone()); // Clone the data inside the lock
    serde_json::to_string(&json_data).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    /// Test that WhitelistInfo serialization includes name and extends fields
    #[test]
    fn test_whitelist_info_serialization() {
        let whitelist_info = WhitelistInfo {
            name: "test_whitelist".to_string(),
            extends: None,
            endpoints: vec![WhitelistEndpoint {
                domain: Some("example.com".to_string()),
                ip: Some("192.168.1.1".to_string()),
                port: Some(443),
                protocol: Some("TCP".to_string()),
                as_number: None,
                as_country: None,
                as_owner: None,
                process: Some("test_process".to_string()),
                description: Some("Test endpoint".to_string()),
            }],
        };

        let json = serde_json::to_string_pretty(&whitelist_info).unwrap();
        println!("Serialized WhitelistInfo: {}", json);

        // Verify the JSON contains the required fields
        assert!(
            json.contains("\"name\""),
            "JSON should contain 'name' field"
        );
        assert!(
            json.contains("\"extends\""),
            "JSON should contain 'extends' field"
        );
        assert!(
            json.contains("\"endpoints\""),
            "JSON should contain 'endpoints' field"
        );
        assert!(
            json.contains("\"test_whitelist\""),
            "JSON should contain the name value"
        );
    }

    /// Test that WhitelistsJSON serialization works correctly
    #[test]
    fn test_whitelists_json_serialization() {
        let whitelists_json = WhitelistsJSON {
            date: "June 18th 2025".to_string(),
            signature: None,
            whitelists: vec![WhitelistInfo {
                name: "custom_whitelist".to_string(),
                extends: None,
                endpoints: vec![WhitelistEndpoint {
                    domain: None,
                    ip: Some("192.168.1.1".to_string()),
                    port: Some(443),
                    protocol: Some("TCP".to_string()),
                    as_number: None,
                    as_country: None,
                    as_owner: None,
                    process: Some("test_process".to_string()),
                    description: Some("Auto-generated endpoint".to_string()),
                }],
            }],
        };

        let json = serde_json::to_string_pretty(&whitelists_json).unwrap();
        println!("Serialized WhitelistsJSON: {}", json);

        // Verify the JSON structure
        assert!(
            json.contains("\"name\""),
            "JSON should contain 'name' field"
        );
        assert!(
            json.contains("\"extends\""),
            "JSON should contain 'extends' field"
        );
        assert!(
            json.contains("\"custom_whitelist\""),
            "JSON should contain the whitelist name"
        );
        assert!(
            json.contains("\"whitelists\""),
            "JSON should contain 'whitelists' array"
        );
    }

    /// Test direct WhitelistsJSON to verify structure
    #[test]
    fn test_new_from_sessions_structure_mock() {
        // Instead of creating a real SessionInfo (which has complex dependencies),
        // we'll test the structure that new_from_sessions should create
        let whitelists_json = WhitelistsJSON {
            date: "June 18th 2025".to_string(),
            signature: None,
            whitelists: vec![WhitelistInfo {
                name: "custom_whitelist".to_string(),
                extends: None,
                endpoints: vec![WhitelistEndpoint {
                    domain: Some("example.com".to_string()),
                    ip: Some("93.184.216.34".to_string()),
                    port: Some(443),
                    protocol: Some("TCP".to_string()),
                    as_number: None,
                    as_country: None,
                    as_owner: None,
                    process: Some("firefox".to_string()),
                    description: Some(
                        "Auto-generated from session: 192.168.1.100:50000 -> 93.184.216.34:443"
                            .to_string(),
                    ),
                }],
            }],
        };

        // Test serialization
        let json = serde_json::to_string_pretty(&whitelists_json).unwrap();
        println!("Generated JSON: {}", json);

        assert!(
            json.contains("\"name\""),
            "Generated JSON should contain 'name' field"
        );
        assert!(
            json.contains("\"extends\""),
            "Generated JSON should contain 'extends' field"
        );
        assert!(
            json.contains("\"custom_whitelist\""),
            "Generated JSON should contain the whitelist name"
        );

        // Test round-trip
        let parsed: WhitelistsJSON = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.whitelists[0].name, "custom_whitelist");
        assert!(parsed.whitelists[0].extends.is_none());
    }

    /// Test set_custom_whitelists functionality
    #[tokio::test]
    #[serial]
    async fn test_set_custom_whitelists() {
        // Test valid JSON
        let valid_json = r#"{
            "date": "June 18th 2025",
            "signature": null,
            "whitelists": [
                {
                    "name": "test_whitelist",
                    "extends": null,
                    "endpoints": [
                        {
                            "domain": "example.com",
                            "ip": "192.168.1.1",
                            "port": 443,
                            "protocol": "TCP",
                            "as_number": null,
                            "as_country": null,
                            "as_owner": null,
                            "process": "test_process",
                            "description": "Test endpoint"
                        }
                    ]
                }
            ]
        }"#;

        // Test setting valid custom whitelist
        let result = set_custom_whitelists(valid_json).await;
        assert!(result.is_ok(), "Should successfully set valid whitelist");
        assert!(
            is_custom().await,
            "Should indicate custom whitelist is active"
        );

        // Test clearing custom whitelist with empty string
        let result = set_custom_whitelists("").await;
        assert!(result.is_ok(), "Should successfully clear whitelist");
        assert!(
            !is_custom().await,
            "Should indicate custom whitelist is not active"
        );

        // Test invalid JSON
        let invalid_json = r#"{
            "date": "June 18th 2025",
            "whitelists": [
                {
                    "endpoints": []
                }
            ]
        }"#;

        let result = set_custom_whitelists(invalid_json).await;
        assert!(
            result.is_err(),
            "Should fail with invalid JSON missing required fields"
        );
    }

    /// Test augment functionality by testing merge_custom_whitelists
    #[test]
    fn test_merge_custom_whitelists() {
        let whitelist1_json = r#"{
            "date": "June 18th 2025",
            "signature": null,
            "whitelists": [
                {
                    "name": "base_whitelist",
                    "extends": null,
                    "endpoints": [
                        {
                            "domain": "example.com",
                            "ip": null,
                            "port": 443,
                            "protocol": "TCP",
                            "as_number": null,
                            "as_country": null,
                            "as_owner": null,
                            "process": null,
                            "description": "Base endpoint"
                        }
                    ]
                }
            ]
        }"#;

        let whitelist2_json = r#"{
            "date": "June 19th 2025",
            "signature": "different",
            "whitelists": [
                {
                    "name": "base_whitelist",
                    "extends": ["other"],
                    "endpoints": [
                        {
                            "domain": "test.com",
                            "ip": null,
                            "port": 443,
                            "protocol": "TCP",
                            "as_number": null,
                            "as_country": null,
                            "as_owner": null,
                            "process": null,
                            "description": "Additional endpoint"
                        }
                    ]
                }
            ]
        }"#;

        let result = Whitelists::merge_custom_whitelists(whitelist1_json, whitelist2_json);
        assert!(result.is_ok(), "Should successfully merge whitelists");

        let merged_json = result.unwrap();
        assert!(
            merged_json.contains("\"name\""),
            "Merged JSON should contain 'name' field"
        );
        assert!(
            merged_json.contains("\"extends\""),
            "Merged JSON should contain 'extends' field"
        );
        assert!(
            merged_json.contains("\"base_whitelist\""),
            "Merged JSON should contain whitelist name"
        );
        assert!(
            merged_json.contains("example.com"),
            "Should contain endpoints from first whitelist"
        );
        assert!(
            merged_json.contains("test.com"),
            "Should contain endpoints from second whitelist"
        );

        // Verify it's valid JSON
        let parsed: serde_json::Value = serde_json::from_str(&merged_json).unwrap();
        assert!(
            parsed["whitelists"].is_array(),
            "Should have whitelists array"
        );
        assert!(
            parsed["whitelists"][0]["name"].is_string(),
            "Should have name field"
        );
        assert!(
            parsed["whitelists"][0]["extends"].is_array(),
            "Should have extends field"
        );
    }

    /// Test the core serialization bug fix
    #[test]
    fn test_whitelist_json_contains_all_required_fields() {
        // Create a whitelist structure that mimics what create_custom_whitelists generates
        let whitelist_info = WhitelistInfo {
            name: "custom_whitelist".to_string(),
            extends: None,
            endpoints: vec![WhitelistEndpoint {
                domain: Some("example.com".to_string()),
                ip: Some("192.168.1.1".to_string()),
                port: Some(443),
                protocol: Some("TCP".to_string()),
                as_number: None,
                as_country: None,
                as_owner: None,
                process: Some("test_process".to_string()),
                description: Some(
                    "Auto-generated from session: 192.168.1.100:50000 -> 192.168.1.1:443"
                        .to_string(),
                ),
            }],
        };

        let whitelists_json = WhitelistsJSON {
            date: "June 18th 2025".to_string(),
            signature: None,
            whitelists: vec![whitelist_info],
        };

        // Test serialization
        let json_result = serde_json::to_string_pretty(&whitelists_json);
        assert!(
            json_result.is_ok(),
            "Should successfully serialize WhitelistsJSON"
        );

        let json = json_result.unwrap();
        println!("Generated JSON:\n{}", json);

        // Verify all required fields are present
        assert!(
            json.contains("\"date\""),
            "JSON should contain 'date' field"
        );
        assert!(
            json.contains("\"signature\""),
            "JSON should contain 'signature' field"
        );
        assert!(
            json.contains("\"whitelists\""),
            "JSON should contain 'whitelists' field"
        );
        assert!(
            json.contains("\"name\""),
            "JSON should contain 'name' field in whitelist"
        );
        assert!(
            json.contains("\"extends\""),
            "JSON should contain 'extends' field in whitelist"
        );
        assert!(
            json.contains("\"endpoints\""),
            "JSON should contain 'endpoints' field in whitelist"
        );
        assert!(
            json.contains("\"custom_whitelist\""),
            "JSON should contain the actual whitelist name"
        );

        // Verify the structure can be parsed back
        let parsed_result: Result<WhitelistsJSON, _> = serde_json::from_str(&json);
        assert!(
            parsed_result.is_ok(),
            "Generated JSON should be parseable back to WhitelistsJSON"
        );

        let parsed = parsed_result.unwrap();
        assert_eq!(parsed.whitelists.len(), 1, "Should have one whitelist");
        assert_eq!(
            parsed.whitelists[0].name, "custom_whitelist",
            "Should preserve whitelist name"
        );
        assert!(
            parsed.whitelists[0].extends.is_none(),
            "Should preserve extends field"
        );
        assert_eq!(
            parsed.whitelists[0].endpoints.len(),
            1,
            "Should have one endpoint"
        );
    }

    /// Test that the bug from the original toto file is fixed
    #[test]
    fn test_toto_file_bug_fix() {
        // This tests that we can parse a JSON that was previously missing name/extends fields
        // and that our generation now includes them

        // First, test that missing fields cause parsing to fail (as expected)
        let incomplete_json = r#"{
            "date": "June 18th 2025",
            "signature": null,
            "whitelists": [
                {
                    "endpoints": [
                        {
                            "domain": null,
                            "ip": "192.168.1.1",
                            "port": 443,
                            "protocol": "TCP",
                            "as_number": null,
                            "as_country": null,
                            "as_owner": null,
                            "process": "test_process",
                            "description": "Test endpoint"
                        }
                    ]
                }
            ]
        }"#;

        let parse_result: Result<WhitelistsJSON, _> = serde_json::from_str(incomplete_json);
        assert!(
            parse_result.is_err(),
            "Should fail to parse JSON missing required fields"
        );

        // Now test that our generation includes all fields
        let complete_json = r#"{
            "date": "June 18th 2025",
            "signature": null,
            "whitelists": [
                {
                    "name": "custom_whitelist",
                    "extends": null,
                    "endpoints": [
                        {
                            "domain": null,
                            "ip": "192.168.1.1",
                            "port": 443,
                            "protocol": "TCP",
                            "as_number": null,
                            "as_country": null,
                            "as_owner": null,
                            "process": "test_process",
                            "description": "Test endpoint"
                        }
                    ]
                }
            ]
        }"#;

        let parse_result: Result<WhitelistsJSON, _> = serde_json::from_str(complete_json);
        assert!(
            parse_result.is_ok(),
            "Should successfully parse JSON with all required fields"
        );

        let parsed = parse_result.unwrap();
        assert_eq!(parsed.whitelists[0].name, "custom_whitelist");
        assert!(parsed.whitelists[0].extends.is_none());
    }

    /// Test creating custom whitelist with extends field
    #[test]
    fn test_custom_whitelist_with_extends() {
        let whitelist_with_extends = WhitelistsJSON {
            date: "June 18th 2025".to_string(),
            signature: None,
            whitelists: vec![WhitelistInfo {
                name: "extended_custom".to_string(),
                extends: Some(vec!["base".to_string(), "builder".to_string()]),
                endpoints: vec![WhitelistEndpoint {
                    domain: Some("test.example.com".to_string()),
                    ip: None,
                    port: Some(8080),
                    protocol: Some("TCP".to_string()),
                    as_number: None,
                    as_country: None,
                    as_owner: None,
                    process: Some("nodejs".to_string()),
                    description: Some("Custom Node.js service".to_string()),
                }],
            }],
        };

        let json = serde_json::to_string_pretty(&whitelist_with_extends).unwrap();
        println!("Extended whitelist JSON:\n{}", json);

        // Verify extends field is properly serialized
        assert!(json.contains("\"extends\""), "Should contain extends field");
        assert!(
            json.contains("\"base\""),
            "Should contain base in extends array"
        );
        assert!(
            json.contains("\"builder\""),
            "Should contain builder in extends array"
        );

        // Test parsing back
        let parsed: WhitelistsJSON = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.whitelists[0].extends.as_ref().unwrap().len(), 2);
        assert_eq!(parsed.whitelists[0].extends.as_ref().unwrap()[0], "base");
        assert_eq!(parsed.whitelists[0].extends.as_ref().unwrap()[1], "builder");
    }

    /// Test edge case with empty endpoints
    #[test]
    fn test_whitelist_with_empty_endpoints() {
        let empty_endpoints_whitelist = WhitelistsJSON {
            date: "June 18th 2025".to_string(),
            signature: None,
            whitelists: vec![WhitelistInfo {
                name: "empty_endpoints".to_string(),
                extends: None,
                endpoints: vec![],
            }],
        };

        let json = serde_json::to_string_pretty(&empty_endpoints_whitelist).unwrap();
        println!("Empty endpoints whitelist JSON:\n{}", json);

        // Should still contain all required fields
        assert!(json.contains("\"name\""), "Should contain name field");
        assert!(json.contains("\"extends\""), "Should contain extends field");
        assert!(
            json.contains("\"endpoints\""),
            "Should contain endpoints field"
        );
        assert!(
            json.contains("\"empty_endpoints\""),
            "Should contain the whitelist name"
        );

        // Test parsing back
        let parsed: WhitelistsJSON = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.whitelists[0].name, "empty_endpoints");
        assert!(parsed.whitelists[0].extends.is_none());
        assert!(parsed.whitelists[0].endpoints.is_empty());
    }
}

#[cfg(test)]
mod merge_tests {
    use super::*;

    #[test]
    fn test_merge_custom_whitelists_basic() {
        // JSON A – one endpoint
        let json_a = r#"{
            "date":"May 1st 2025",
            "signature":null,
            "whitelists":[
              {"name":"custom_whitelist","extends":null,
               "endpoints":[{"domain":"a.com","port":80}]}
            ]
        }"#;

        // JSON B – another endpoint (plus duplicate of a.com:80 and new extends)
        let json_b = r#"{
            "date":"May 2nd 2025",
            "signature":null,
            "whitelists":[
              {"name":"custom_whitelist","extends":["builder"],
               "endpoints":[{"domain":"a.com","port":80},{"domain":"b.com","port":443}]}
            ]
        }"#;

        let merged = Whitelists::merge_custom_whitelists(json_a, json_b).expect("merge ok");
        let merged_json: WhitelistsJSON = serde_json::from_str(&merged).unwrap();
        assert_eq!(merged_json.whitelists.len(), 1);
        let info = &merged_json.whitelists[0];
        // extends should be from first (null) or second if first none – here first none so second preserved
        assert_eq!(info.extends.as_ref().unwrap(), &vec!["builder".to_string()]);
        // endpoints deduped – should be 2 unique entries
        assert_eq!(info.endpoints.len(), 2);
    }
}
