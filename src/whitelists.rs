use crate::sessions::{DomainResolutionType, Session, SessionInfo, WhitelistState};
#[cfg(feature = "packetcapture")]
use crate::sni::is_reverse_dns_pattern;
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
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use tracing::{error, info, trace, warn};
use undeadlock::*;

// -------------------------------------------------------------------------------------------------
// Model-change tracking for whitelists
// -------------------------------------------------------------------------------------------------

// Incremented on every structural change to the whitelist model (custom list
// loaded, default reset, augmentation, etc.).  Having a monotonic counter lets
// concurrent workers detect mid-flight changes without relying on lossy
// boolean flags.
static WHITELIST_REVISION: AtomicU64 = AtomicU64::new(0);

// Constants
const WHITELISTS_FILE_NAME: &str = "whitelists-db.json";

// CDN/cloud providers that use shared IPs across many domains
// These require domain resolution before whitelisting to prevent false positives
const CDN_PROVIDERS: &[&str] = &[
    "fastly",
    "cloudflare",
    "amazon",
    "aws",
    "google",
    "microsoft",
    "azure",
    "akamai",
    "cloudfront",
    "cdn",
];

// Test data for known CDN providers (AS owner name, test IP address)
#[cfg(test)]
const CDN_PROVIDER_TEST_DATA: &[(&str, &str, &str)] = &[
    ("fastly", "FASTLY", "185.199.110.133"),
    ("cloudflare", "Cloudflare", "104.16.0.1"),
    ("amazon", "Amazon Technologies Inc.", "52.84.0.1"),
    ("aws", "AWS", "3.5.0.1"),
    ("google", "Google LLC", "8.8.8.8"),
    ("microsoft", "Microsoft Corporation", "20.190.0.1"),
    ("azure", "Microsoft Azure", "40.76.0.1"),
    ("akamai", "Akamai Technologies", "23.185.0.1"),
    ("cloudfront", "Amazon CloudFront", "13.32.0.1"),
    ("cdn", "Some CDN Provider", "1.2.3.4"),
];

/// Endpoint rule supporting domain(s), IPs and ports with list/range semantics.
///
/// Notes:
/// - Domains can be expressed as a single `domain` or a list in `domains`.
///   Each entry supports wildcards (e.g. `*.example.com`, `example.*`, or `api.*.example.com`).
/// - IPs can be a single `ip` or a list in `ips`. Each entry can be an IP, CIDR,
///   or explicit inclusive range in the form `start-end` for IPv4/IPv6.
/// - Ports can be a single `port` or a list/ranges via `ports`.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
#[serde(deny_unknown_fields)] // Enforce no unknown fields
pub struct WhitelistEndpoint {
    pub domain: Option<String>,
    pub domains: Option<Vec<String>>,
    pub ip: Option<String>,
    pub ips: Option<Vec<String>>,
    pub port: Option<u16>,
    pub ports: Option<Vec<PortSpec>>,
    pub protocol: Option<String>,
    pub as_number: Option<u32>,
    pub as_country: Option<String>,
    pub as_owner: Option<String>,
    pub process: Option<String>,
    pub description: Option<String>,
}

/// Port specification supporting single values or inclusive ranges.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Hash)]
#[serde(untagged)]
pub enum PortSpec {
    Single(u16),
    Range { start: u16, end: u16 },
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

impl WhitelistsJSON {
    /// Compare two whitelists and return the number of differences
    ///
    /// # Arguments
    /// * `old_whitelist` - The old whitelist to compare against
    /// * `new_whitelist` - The new whitelist to compare
    ///
    /// # Returns
    /// * `f64` - The pourcentage of differences found
    pub fn compare_whitelist(self, old_whitelist_json: WhitelistsJSON) -> f64 {
        let mut different = 0;
        let mut total = 0;
        for new_whitelist in &self.whitelists {
            // Let's find the whitelist entry in the old whitelist
            let old_whitelist = old_whitelist_json
                .whitelists
                .iter()
                .find(|old_whitelist| old_whitelist.name == new_whitelist.name);
            for new_endpoint in &new_whitelist.endpoints {
                // Check if the old whitelist have this whitelist
                if old_whitelist.is_none() {
                    total += 1;
                    different += 1;
                    continue;
                }
                let old_whitelist_endpoints = old_whitelist.unwrap().endpoints.clone();
                // Check if the new endpoint is in the old whitelist endpoints
                if old_whitelist_endpoints.contains(new_endpoint) {
                    total += 1;
                    continue; // No difference, skip to next endpoint
                } else {
                    total += 1;
                    different += 1; // Found a new endpoint
                }
            }
        }
        if total == 0 {
            0.0 // avoid division by zero
        } else {
            (different as f64 / total as f64) * 100.0
        }
    }

    pub fn create_empty_whitelist() -> WhitelistsJSON {
        WhitelistsJSON {
            date: chrono::Local::now().format("%B %dth %Y").to_string(),
            signature: None,
            whitelists: Vec::new(),
        }
    }
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

        let whitelists = Arc::new(CustomDashMap::new("whitelists"));

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
    // If include_process is true, process names will be included in the whitelist entries.
    // This provides stricter matching but may cause whitelist instability across runs.
    pub fn new_from_sessions(sessions: &Vec<SessionInfo>) -> Self {
        Self::new_from_sessions_with_options(sessions, false)
    }

    // Create a whitelist from a list of sessions with process info included
    pub fn new_from_sessions_with_process(sessions: &Vec<SessionInfo>) -> Self {
        Self::new_from_sessions_with_options(sessions, true)
    }

    // Create a whitelist from a list of sessions with configurable options
    pub fn new_from_sessions_with_options(
        sessions: &Vec<SessionInfo>,
        include_process: bool,
    ) -> Self {
        let whitelists = Arc::new(CustomDashMap::new("whitelists"));

        // Helper function to check if an AS owner indicates a CDN/cloud provider
        fn is_cdn_provider(owner: &str, cdn_providers: &[&str]) -> bool {
            let owner_lower = owner.to_lowercase();
            cdn_providers
                .iter()
                .any(|&provider| owner_lower.contains(provider))
        }

        // Create a whitelist with the current sessions
        let mut endpoints = Vec::new();
        // HashSet to track unique endpoint fingerprints for deduplication
        let mut unique_fingerprints = std::collections::HashSet::new();

        for session in sessions {
            // Check if domain is unresolved or unreliable
            let domain_unresolved = session.dst_domain == Some("Unknown".to_string())
                || session.dst_domain == Some("Resolving".to_string())
                || session.dst_domain.is_none();

            // Check if domain came from reverse DNS and looks like a reverse DNS pattern
            // (e.g., "cdn-185-199-111-133.github.com" or "51.241.186.35.bc.googleusercontent.com")
            // These are unreliable for CDN providers as they don't represent the actual requested domain
            #[cfg(feature = "packetcapture")]
            let domain_is_reverse_pattern = session.dst_domain_type
                == DomainResolutionType::Reverse
                && session
                    .dst_domain
                    .as_ref()
                    .map_or(false, |d| is_reverse_dns_pattern(d));
            #[cfg(not(feature = "packetcapture"))]
            let domain_is_reverse_pattern = false;

            // For CDN providers, we need either:
            // - Forward DNS (from captured DNS queries) - reliable
            // - SNI (from TLS ClientHello) - reliable
            // Reverse DNS is unreliable for CDNs as it often shows infrastructure names
            let domain_unreliable_for_cdn = domain_unresolved
                || domain_is_reverse_pattern
                || (session.dst_domain_type == DomainResolutionType::Reverse);

            // If domain is unresolved or unreliable, check if this is a CDN/cloud provider
            // CDN IPs are shared across many domains, so we must require reliable domain resolution
            // to prevent false positives (e.g., whitelisting one Fastly POP allows all Fastly domains)
            if domain_unreliable_for_cdn {
                if let Some(ref asn) = session.dst_asn {
                    if is_cdn_provider(&asn.owner, CDN_PROVIDERS) {
                        // Skip CDN sessions without reliable domain - they need domain-based whitelisting
                        // CDN sessions with Forward DNS or SNI will continue past this point
                        warn!(
                            "Skipping CDN session without reliable domain (resolution: {:?}): {}:{} -> {}:{} (AS owner: {}, domain: {:?})",
                            session.dst_domain_type,
                            session.session.src_ip,
                            session.session.src_port,
                            session.session.dst_ip,
                            session.session.dst_port,
                            asn.owner,
                            session.dst_domain
                        );
                        continue;
                    }
                }
            }

            // When include_process is enabled, we need a valid process name.
            // Skip sessions without resolved process info to avoid creating wildcard entries.
            let process_name: Option<String> = if include_process {
                let name = session.l7.as_ref().and_then(|l7| {
                    let name = &l7.process_name;
                    // Filter out unresolved/unknown process names
                    if name.is_empty() || name == "Unknown" || name == "Resolving" {
                        None
                    } else {
                        Some(name.clone())
                    }
                });
                // If include_process is true but we couldn't get a valid process name,
                // skip this session - we don't want to create wildcard entries
                if name.is_none() {
                    warn!(
                        "Skipping session without resolved process (include_process=true): {}:{} -> {}:{}",
                        session.session.src_ip,
                        session.session.src_port,
                        session.session.dst_ip,
                        session.session.dst_port
                    );
                    continue;
                }
                name
            } else {
                None
            };

            // For whitelisting, only use domains that came from reliable sources (Forward DNS or SNI)
            // Reverse DNS can produce misleading names for CDNs
            let reliable_domain = if domain_unresolved {
                None
            } else if session.dst_domain_type == DomainResolutionType::Forward
                || session.dst_domain_type == DomainResolutionType::SNI
            {
                session.dst_domain.clone()
            } else {
                // Reverse DNS - only use if it doesn't look like a reverse DNS pattern
                #[cfg(feature = "packetcapture")]
                let use_domain = session
                    .dst_domain
                    .as_ref()
                    .map_or(false, |d| !is_reverse_dns_pattern(d));
                #[cfg(not(feature = "packetcapture"))]
                let use_domain = true;

                if use_domain {
                    session.dst_domain.clone()
                } else {
                    None
                }
            };

            let endpoint = WhitelistEndpoint {
                // Only include domain if it's from a reliable source
                domain: reliable_domain,
                domains: None,
                // Always include the IP address as a fallback to when the domain is set but not resolved
                // (but only for non-CDN providers, as CDNs are skipped above)
                ip: Some(session.session.dst_ip.to_string()),
                // Always include the port
                port: Some(session.session.dst_port),
                // Always include the protocol
                protocol: Some(session.session.protocol.to_string()),
                // Don't include AS info
                as_number: None, // Session doesn't have AS info
                as_country: None,
                as_owner: None,
                // Process name is set above (with validation when include_process is true)
                process: process_name,
                description: Some(format!(
                    "Auto-generated from session: {}:{} -> {}:{}",
                    session.session.src_ip,
                    session.session.src_port,
                    session.session.dst_ip,
                    session.session.dst_port
                )),
                ports: None,
                ips: None,
            };

            // Create a fingerprint tuple that uniquely identifies this endpoint
            // (excluding description which doesn't affect deduplication)
            // Include process in fingerprint when include_process is enabled
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
        fn fingerprint(ep: &WhitelistEndpoint) -> String {
            // Normalize ports and ips to stable JSON for hashing/dedup
            let mut obj = serde_json::json!({
                "domain": ep.domain,
                "domains": ep.domains,
                "ip": ep.ip,
                "port": ep.port,
                "protocol": ep.protocol,
                "as_number": ep.as_number,
                "as_country": ep.as_country,
                "as_owner": ep.as_owner,
                "process": ep.process,
            });
            if let Some(domains) = &ep.domains {
                let mut d = domains.clone();
                d.sort();
                obj["domains"] = serde_json::Value::Array(
                    d.into_iter()
                        .map(|s| serde_json::Value::String(s))
                        .collect(),
                );
            }
            if let Some(ports) = &ep.ports {
                let mut ports_norm: Vec<serde_json::Value> = ports
                    .iter()
                    .map(|p| match p {
                        PortSpec::Single(v) => serde_json::json!({"single": v}),
                        PortSpec::Range { start, end } => {
                            serde_json::json!({"start": start, "end": end})
                        }
                    })
                    .collect();
                ports_norm.sort_by(|a, b| a.to_string().cmp(&b.to_string()));
                obj["ports"] = serde_json::Value::Array(ports_norm);
            }
            if let Some(ips) = &ep.ips {
                let mut ips_norm = ips.clone();
                ips_norm.sort();
                obj["ips"] = serde_json::Value::Array(
                    ips_norm
                        .into_iter()
                        .map(|s| serde_json::Value::String(s))
                        .collect(),
                );
            }
            obj.to_string()
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

    /// Produce a factorized version of a single whitelist by merging endpoints that share
    /// the same non-address attributes (protocol, AS, process) and combining their address
    /// specifications:
    /// - Domains are merged into `domains` (keeping `domain` when only one remains).
    /// - Ports are coalesced, merging overlapping/adjacent ranges (e.g., 80, 81-82 → 80-82).
    /// - IP specs are deduplicated (preserving list semantics; no CIDR synthesis is attempted).
    pub fn factorize_whitelist(input: &WhitelistInfo) -> WhitelistInfo {
        // Group key excludes ports. IPs are only used as key for IP-only endpoints.
        // When domains are present, IPs are accumulated into the ips list instead.
        #[derive(Debug, Clone, PartialEq, Eq, Hash)]
        struct Key {
            domains: Vec<String>, // normalized, empty means no domain restriction
            ip: String,           // only populated when domains is empty (IP-only endpoints)
            protocol: Option<String>,
            as_number: Option<u32>,
            as_country: Option<String>,
            as_owner: Option<String>,
            process: Option<String>,
        }

        fn normalize_ports(single: Option<u16>, list: &Option<Vec<PortSpec>>) -> Vec<PortSpec> {
            let mut out: Vec<PortSpec> = Vec::new();
            if let Some(v) = single {
                out.push(PortSpec::Single(v));
            }
            if let Some(vec) = list {
                out.extend(vec.clone());
            }
            // Dedup and merge overlapping/adjacent ranges
            // First expand to ranges
            let mut ranges: Vec<(u16, u16)> = Vec::new();
            for spec in out {
                match spec {
                    PortSpec::Single(v) => ranges.push((v, v)),
                    PortSpec::Range { start, end } => {
                        let (a, b) = if start <= end {
                            (start, end)
                        } else {
                            (end, start)
                        };
                        ranges.push((a, b));
                    }
                }
            }
            if ranges.is_empty() {
                return Vec::new();
            }
            ranges.sort_unstable_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));
            let mut merged: Vec<(u16, u16)> = Vec::new();
            for (s, e) in ranges {
                if let Some(last) = merged.last_mut() {
                    if s <= last.1.saturating_add(1) {
                        if e > last.1 {
                            last.1 = e;
                        }
                        continue;
                    }
                }
                merged.push((s, e));
            }
            // Convert back to PortSpec
            merged
                .into_iter()
                .map(|(s, e)| {
                    if s == e {
                        PortSpec::Single(s)
                    } else {
                        PortSpec::Range { start: s, end: e }
                    }
                })
                .collect()
        }

        fn normalize_ips(single: &Option<String>, list: &Option<Vec<String>>) -> Vec<String> {
            let mut out: Vec<String> = Vec::new();
            if let Some(s) = single {
                out.push(s.clone());
            }
            if let Some(vec) = list {
                out.extend(vec.clone());
            }
            out.sort();
            out.dedup();
            out
        }

        let mut groups: std::collections::HashMap<
            Key,
            (Vec<PortSpec>, Vec<String>, Option<String>),
        > = std::collections::HashMap::new();

        for ep in &input.endpoints {
            // Normalize domain(s)
            let mut domains_vec: Vec<String> = Vec::new();
            if let Some(d) = &ep.domain {
                domains_vec.push(d.clone());
            }
            if let Some(ds) = &ep.domains {
                domains_vec.extend(ds.clone());
            }
            domains_vec.sort();
            domains_vec.dedup();

            let key = Key {
                domains: domains_vec.clone(),
                // Only use IP as grouping key when there's no domain (IP-only endpoints).
                // When a domain is present, the IP should NOT be part of the key so that
                // multiple IPs for the same domain get merged together.
                ip: if domains_vec.is_empty() {
                    ep.ip.clone().unwrap_or_default()
                } else {
                    String::new()
                },
                protocol: ep.protocol.clone(),
                as_number: ep.as_number,
                as_country: ep.as_country.clone(),
                as_owner: ep.as_owner.clone(),
                process: ep.process.clone(),
            };

            let ports = normalize_ports(ep.port, &ep.ports);
            let ips = normalize_ips(&ep.ip, &ep.ips);

            let entry = groups
                .entry(key)
                .or_insert_with(|| (Vec::new(), Vec::new(), None));
            entry.0.extend(ports);
            entry.1.extend(ips);
            // Keep first description if present
            if entry.2.is_none() {
                entry.2 = ep.description.clone();
            }
        }

        // Post-process to dedup and merge port ranges per group
        let mut endpoints: Vec<WhitelistEndpoint> = Vec::with_capacity(groups.len());
        for (key, (ports, mut ips, description)) in groups {
            // Merge port ranges again (in case multiple endpoints added overlapping specs)
            let merged_ports = {
                // Convert to Option<u16> + list and reuse normalize
                fn merge_all(list: Vec<PortSpec>) -> Vec<PortSpec> {
                    let mut ranges: Vec<(u16, u16)> = Vec::new();
                    for spec in list {
                        match spec {
                            PortSpec::Single(v) => ranges.push((v, v)),
                            PortSpec::Range { start, end } => {
                                let (a, b) = if start <= end {
                                    (start, end)
                                } else {
                                    (end, start)
                                };
                                ranges.push((a, b));
                            }
                        }
                    }
                    if ranges.is_empty() {
                        return Vec::new();
                    }
                    ranges.sort_unstable_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));
                    let mut merged: Vec<(u16, u16)> = Vec::new();
                    for (s, e) in ranges {
                        if let Some(last) = merged.last_mut() {
                            if s <= last.1.saturating_add(1) {
                                if e > last.1 {
                                    last.1 = e;
                                }
                                continue;
                            }
                        }
                        merged.push((s, e));
                    }
                    merged
                        .into_iter()
                        .map(|(s, e)| {
                            if s == e {
                                PortSpec::Single(s)
                            } else {
                                PortSpec::Range { start: s, end: e }
                            }
                        })
                        .collect()
                }
                merge_all(ports)
            };

            // Dedup IPs strings
            ips.sort();
            ips.dedup();
            let (ip, ips) = if ips.len() > 1 {
                (None, Some(ips))
            } else if ips.len() == 1 {
                (Some(ips[0].clone()), None)
            } else {
                (None, None)
            };

            // Preserve single domain when exactly one, else store in `domains`
            let (domain_single, domains_list) = if key.domains.len() == 1 {
                (Some(key.domains[0].clone()), None)
            } else if key.domains.is_empty() {
                (None, None)
            } else {
                (None, Some(key.domains.clone()))
            };

            let (port, ports) = if merged_ports.len() == 1 {
                match merged_ports[0] {
                    PortSpec::Single(v) => (Some(v), None),
                    PortSpec::Range { start, end } => {
                        if start == end {
                            (Some(start), None)
                        } else {
                            (None, Some(merged_ports))
                        }
                    }
                }
            } else if merged_ports.is_empty() {
                (None, None)
            } else {
                (None, Some(merged_ports))
            };

            endpoints.push(WhitelistEndpoint {
                domain: domain_single,
                domains: domains_list,
                ip,
                port,
                protocol: key.protocol,
                as_number: key.as_number,
                as_country: key.as_country,
                as_owner: key.as_owner,
                process: key.process,
                description,
                ports,
                ips: ips,
            });
        }

        WhitelistInfo {
            name: input.name.clone(),
            extends: input.extends.clone(),
            endpoints,
        }
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
    static ref ENDPOINT_CACHE: CustomDashMap<String, Arc<Vec<WhitelistEndpoint>>> = CustomDashMap::new("whitelist_endpoint_cache");

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
    let port_match = ports_match(port, endpoint.port, &endpoint.ports);
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

    // Check if we have a domain/domains match
    let domain_match = domains_match(session_domain, &endpoint.domain, &endpoint.domains);
    let domain_specified =
        endpoint.domain.is_some() || endpoint.domains.as_ref().map_or(false, |v| !v.is_empty());

    // If domain is specified and matches, other checks are irrelevant
    if domain_specified && domain_match {
        return (true, None);
    }

    // Check if we have an IP match (single or any from list)
    let ip_match = ip_matches_any(session_ip, &endpoint.ip, &endpoint.ips);
    let ip_specified =
        endpoint.ip.is_some() || endpoint.ips.as_ref().map_or(false, |list| !list.is_empty());

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
        Some(pattern) => session_domain
            .map(|d| single_domain_matches(d, pattern))
            .unwrap_or(false),
        None => true,
    }
}

fn domains_match(
    session_domain: Option<&str>,
    single: &Option<String>,
    many: &Option<Vec<String>>,
) -> bool {
    // If multiple domains are provided, any can match
    if let Some(list) = many {
        if let Some(d) = session_domain {
            for pat in list {
                if single_domain_matches(d, pat) {
                    return true;
                }
            }
            return false;
        }
        return false;
    }
    domain_matches(session_domain, single)
}

fn single_domain_matches(session_domain: &str, pattern: &str) -> bool {
    // Case-insensitive
    let domain = session_domain.to_lowercase();
    let pattern = pattern.to_lowercase();

    if pattern.contains('*') {
        // Prefix wildcard (*.example.com)
        if pattern.starts_with("*.") {
            let suffix = &pattern[2..];
            if domain == suffix {
                return false;
            }
            return domain.ends_with(suffix)
                && domain.len() > suffix.len()
                && domain.as_bytes()[domain.len() - suffix.len() - 1] == b'.';
        }
        // Suffix wildcard (example.*)
        if pattern.ends_with(".*") {
            let prefix = &pattern[..pattern.len() - 2];
            if domain.starts_with(prefix) {
                if domain.len() == prefix.len() {
                    return true;
                }
                if domain.len() > prefix.len() && domain.as_bytes()[prefix.len()] == b'.' {
                    return true;
                }
            }
            return false;
        }
        // Middle wildcard prefix.*.suffix
        if let Some(pos) = pattern.find('*') {
            let (pre, suf_with) = pattern.split_at(pos);
            let suf = &suf_with[1..];
            return domain.starts_with(pre)
                && domain.ends_with(suf)
                && domain.len() > pre.len() + suf.len();
        }
        return false;
    }
    domain == pattern
}

/// Helper function to match IP addresses against single, CIDR, or explicit range patterns.
fn ip_matches_pattern(session_ip: &IpAddr, pattern: &str) -> bool {
    if pattern.contains('/') {
        // CIDR notation
        return pattern
            .parse::<IpNet>()
            .map(|net| net.contains(session_ip))
            .unwrap_or(false);
    }
    if let Some((start, end)) = pattern.split_once('-') {
        // Explicit inclusive range start-end
        if let (Ok(start_ip), Ok(end_ip)) =
            (start.trim().parse::<IpAddr>(), end.trim().parse::<IpAddr>())
        {
            if std::mem::discriminant(&start_ip) != std::mem::discriminant(&end_ip) {
                return false;
            }
            match (start_ip, end_ip, session_ip) {
                (IpAddr::V4(s), IpAddr::V4(e), IpAddr::V4(cur)) => {
                    let s = u32::from(s);
                    let e = u32::from(e);
                    let c = u32::from(*cur);
                    return if s <= e {
                        c >= s && c <= e
                    } else {
                        c >= e && c <= s
                    };
                }
                (IpAddr::V6(s), IpAddr::V6(e), IpAddr::V6(cur)) => {
                    let s = u128::from(s);
                    let e = u128::from(e);
                    let c = u128::from(*cur);
                    return if s <= e {
                        c >= s && c <= e
                    } else {
                        c >= e && c <= s
                    };
                }
                _ => return false,
            }
        }
        return false;
    }
    // Single IP
    pattern
        .parse::<IpAddr>()
        .map(|addr| &addr == session_ip)
        .unwrap_or(false)
}

/// Match against optional single ip or a list of ip specs.
fn ip_matches_any(
    session_ip: Option<&str>,
    endpoint_ip: &Option<String>,
    endpoint_ips: &Option<Vec<String>>,
) -> bool {
    let ip_str = match session_ip {
        Some(s) => s,
        None => return false,
    };
    let addr: IpAddr = match ip_str.parse() {
        Ok(a) => a,
        Err(_) => return false,
    };

    // If a single IP spec is provided, try it first
    if let Some(spec) = endpoint_ip.as_ref() {
        if ip_matches_pattern(&addr, spec) {
            return true;
        }
    }
    // Then try the list of specs
    if let Some(specs) = endpoint_ips.as_ref() {
        for spec in specs {
            if ip_matches_pattern(&addr, spec) {
                return true;
            }
        }
    }
    // If neither is specified, it's a match (no IP restriction)
    endpoint_ip.is_none() && endpoint_ips.is_none()
}

/// Helper function to match ports.
fn ports_match(
    port: u16,
    whitelist_port: Option<u16>,
    whitelist_ports: &Option<Vec<PortSpec>>,
) -> bool {
    // If a list exists, it takes precedence; also accept when neither is provided
    if let Some(list) = whitelist_ports {
        return list.iter().any(|spec| match spec {
            PortSpec::Single(v) => *v == port,
            PortSpec::Range { start, end } => {
                if start <= end {
                    port >= *start && port <= *end
                } else {
                    port >= *end && port <= *start
                }
            }
        });
    }
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
    WHITELIST_REVISION.fetch_add(1, Ordering::SeqCst);

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
        WHITELIST_REVISION.fetch_add(1, Ordering::SeqCst);
        return Ok(());
    }

    let whitelist_result = serde_json::from_str::<WhitelistsJSON>(whitelist_json);

    match whitelist_result {
        Ok(whitelist_data) => {
            info!("Successfully parsed custom whitelist JSON.");
            // Factorize each whitelist before loading
            let mut factored = whitelist_data.clone();
            factored.whitelists = factored
                .whitelists
                .into_iter()
                .map(|info| Whitelists::factorize_whitelist(&info))
                .collect();

            let whitelist = Whitelists::new_from_json(factored);
            LISTS.set_custom_data(whitelist).await;
            ENDPOINT_CACHE.clear(); // Clear cache after successful set
            NEED_FULL_RECOMPUTE_WHITELIST.store(true, Ordering::SeqCst);
            WHITELIST_REVISION.fetch_add(1, Ordering::SeqCst);
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
            WHITELIST_REVISION.fetch_add(1, Ordering::SeqCst);
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
            // Egress-only whitelist policy: only evaluate sessions where traffic originates from us/local
            let is_egress =
                snapshot.is_self_src || (snapshot.is_local_src && !snapshot.is_local_dst);
            if !is_egress {
                // Mark as conforming for whitelist purposes and continue
                evaluation_results.push((session_key.clone(), true, None));
                continue;
            }
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
        evaluation_results.len(),
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
    WHITELIST_REVISION.fetch_add(1, Ordering::SeqCst);
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
    WHITELIST_REVISION.fetch_add(1, Ordering::SeqCst);
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
    use std::net::{IpAddr, Ipv4Addr};

    /// Test that WhitelistInfo serialization includes name and extends fields
    #[test]
    fn test_whitelist_info_serialization() {
        let whitelist_info = WhitelistInfo {
            name: "test_whitelist".to_string(),
            extends: None,
            endpoints: vec![WhitelistEndpoint {
                domain: Some("example.com".to_string()),
                domains: None,
                ip: Some("192.168.1.1".to_string()),
                port: Some(443),
                protocol: Some("TCP".to_string()),
                as_number: None,
                as_country: None,
                as_owner: None,
                process: Some("test_process".to_string()),
                description: Some("Test endpoint".to_string()),
                ports: None,
                ips: None,
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

    #[test]
    fn test_ports_match_list_and_ranges() {
        // Single port
        assert!(ports_match(80, Some(80), &None));
        assert!(!ports_match(81, Some(80), &None));

        // List with singles and ranges
        let list = Some(vec![
            PortSpec::Single(80),
            PortSpec::Range {
                start: 1000,
                end: 1002,
            },
        ]);
        assert!(ports_match(80, None, &list));
        assert!(ports_match(1001, None, &list));
        assert!(!ports_match(1003, None, &list));
    }

    #[test]
    fn test_ip_matches_any_list_and_ranges() {
        // Only single or CIDR
        assert!(ip_matches_any(
            Some("10.0.0.1"),
            &Some("10.0.0.1".into()),
            &None
        ));
        assert!(ip_matches_any(
            Some("10.0.0.2"),
            &Some("10.0.0.0/24".into()),
            &None
        ));
        assert!(!ip_matches_any(
            Some("10.0.1.2"),
            &Some("10.0.0.0/24".into()),
            &None
        ));

        // With list including explicit range and CIDR
        let ips = Some(vec![
            "10.0.0.5-10.0.0.7".into(),
            "192.168.0.0/30".into(),
            "1.2.3.4".into(),
        ]);
        assert!(ip_matches_any(Some("10.0.0.5"), &None, &ips));
        assert!(ip_matches_any(Some("10.0.0.7"), &None, &ips));
        assert!(!ip_matches_any(Some("10.0.0.8"), &None, &ips));
        assert!(ip_matches_any(Some("192.168.0.2"), &None, &ips));
        assert!(!ip_matches_any(Some("192.168.0.4"), &None, &ips));
        assert!(ip_matches_any(Some("1.2.3.4"), &None, &ips));
    }

    #[test]
    fn test_factorize_whitelist_merges_ports_ips_and_preserves_domain() {
        let info = WhitelistInfo {
            name: "custom_whitelist".to_string(),
            extends: None,
            endpoints: vec![
                WhitelistEndpoint {
                    domain: None,
                    domains: None,
                    ip: Some("10.0.0.1".into()),
                    port: Some(120),
                    protocol: Some("TCP".into()),
                    as_number: None,
                    as_country: None,
                    as_owner: None,
                    process: None,
                    description: None,
                    ports: None,
                    ips: None,
                },
                WhitelistEndpoint {
                    domain: Some("a.com".into()),
                    domains: None,
                    ip: None,
                    port: Some(82),
                    protocol: Some("TCP".into()),
                    as_number: None,
                    as_country: None,
                    as_owner: None,
                    process: Some("proc".into()),
                    description: Some("d2".into()),
                    ports: None,
                    ips: Some(vec!["10.0.0.2".into()]),
                },
                WhitelistEndpoint {
                    domain: None,
                    domains: None,
                    ip: Some("10.0.0.1".into()),
                    port: Some(53),
                    protocol: Some("TCP".into()),
                    as_number: None,
                    as_country: None,
                    as_owner: None,
                    process: None,
                    description: None,
                    ports: None,
                    ips: None,
                },
            ],
        };

        let factored = Whitelists::factorize_whitelist(&info);
        // Expect 2 groups (a.com and b.com)
        assert_eq!(factored.endpoints.len(), 2);

        // Find a.com
        let a = factored
            .endpoints
            .iter()
            .find(|e| e.ip.as_deref() == Some("10.0.0.1"))
            .unwrap();
        // Ports should be merged into a single range 80..=82
        let ports = a.ports.as_ref().unwrap();
        assert_eq!(ports.len(), 2);

        // b.com remains separate
        assert!(factored
            .endpoints
            .iter()
            .any(|e| e.domain.as_deref() == Some("a.com")));
    }

    /// Test that endpoints with the same domain but different IPs are merged together.
    /// This is critical for auto-whitelist stability - without this, the same domain
    /// appearing with different CDN/load-balancer IPs would create separate endpoints
    /// and prevent the whitelist from ever stabilizing.
    #[test]
    fn test_factorize_whitelist_merges_same_domain_different_ips() {
        let info = WhitelistInfo {
            name: "custom_whitelist".to_string(),
            extends: None,
            endpoints: vec![
                // Same domain "github.com" with different IPs (like CDN/load balancer)
                WhitelistEndpoint {
                    domain: Some("github.com".into()),
                    domains: None,
                    ip: Some("140.82.114.3".into()),
                    port: Some(443),
                    protocol: Some("TCP".into()),
                    as_number: None,
                    as_country: None,
                    as_owner: None,
                    process: None,
                    description: Some("First GitHub IP".into()),
                    ports: None,
                    ips: None,
                },
                WhitelistEndpoint {
                    domain: Some("github.com".into()),
                    domains: None,
                    ip: Some("140.82.114.4".into()),
                    port: Some(443),
                    protocol: Some("TCP".into()),
                    as_number: None,
                    as_country: None,
                    as_owner: None,
                    process: None,
                    description: Some("Second GitHub IP".into()),
                    ports: None,
                    ips: None,
                },
                WhitelistEndpoint {
                    domain: Some("github.com".into()),
                    domains: None,
                    ip: Some("140.82.112.4".into()),
                    port: Some(443),
                    protocol: Some("TCP".into()),
                    as_number: None,
                    as_country: None,
                    as_owner: None,
                    process: None,
                    description: Some("Third GitHub IP".into()),
                    ports: None,
                    ips: None,
                },
                // IP-only endpoint (no domain) - should remain separate
                WhitelistEndpoint {
                    domain: None,
                    domains: None,
                    ip: Some("10.0.0.1".into()),
                    port: Some(8080),
                    protocol: Some("TCP".into()),
                    as_number: None,
                    as_country: None,
                    as_owner: None,
                    process: None,
                    description: Some("Internal IP only".into()),
                    ports: None,
                    ips: None,
                },
            ],
        };

        let factored = Whitelists::factorize_whitelist(&info);

        // Should have exactly 2 endpoints:
        // 1. github.com with merged IPs
        // 2. 10.0.0.1 (IP-only)
        assert_eq!(
            factored.endpoints.len(),
            2,
            "Expected 2 endpoints after factorization, got {}",
            factored.endpoints.len()
        );

        // Find the github.com endpoint
        let github_ep = factored
            .endpoints
            .iter()
            .find(|e| e.domain.as_deref() == Some("github.com"))
            .expect("Should have github.com endpoint");

        // Should have merged all 3 IPs into the ips list
        let ips = github_ep.ips.as_ref().expect("Should have ips list");
        assert_eq!(ips.len(), 3, "Should have 3 merged IPs, got {}", ips.len());
        assert!(ips.contains(&"140.82.114.3".to_string()));
        assert!(ips.contains(&"140.82.114.4".to_string()));
        assert!(ips.contains(&"140.82.112.4".to_string()));

        // Find the IP-only endpoint - should still exist separately
        let ip_only_ep = factored
            .endpoints
            .iter()
            .find(|e| e.domain.is_none() && e.ip.as_deref() == Some("10.0.0.1"))
            .expect("Should have IP-only endpoint");
        assert_eq!(ip_only_ep.port, Some(8080));
    }

    #[tokio::test]
    #[serial]
    async fn test_set_custom_whitelists_factorizes() {
        let json = r#"{
            "date": "June 18th 2025",
            "signature": null,
            "whitelists": [
                {
                    "name": "custom_whitelist",
                    "extends": null,
                    "endpoints": [
                        {"domain":"a.com","port":80,"protocol":"TCP","process":"p"},
                        {"domain":"a.com","port":81,"protocol":"TCP","process":"p"}
                    ]
                }
            ]
        }"#;

        set_custom_whitelists(json).await.expect("set ok");
        let snap = current_json().await;
        let info = snap
            .whitelists
            .iter()
            .find(|w| w.name == "custom_whitelist")
            .expect("exists");

        // Expect a single endpoint with merged ports list/range
        assert_eq!(info.endpoints.len(), 1);
        let ep = &info.endpoints[0];
        assert!(ep.ports.is_some());
    }

    #[cfg(all(
        any(target_os = "macos", target_os = "linux", target_os = "windows"),
        feature = "packetcapture"
    ))]
    #[tokio::test]
    #[serial]
    async fn test_augment_custom_whitelists_factorizes() {
        // seed custom list with two endpoints that can be merged
        let json = r#"{
            "date": "June 18th 2025",
            "signature": null,
            "whitelists": [
                {
                    "name": "custom_whitelist",
                    "extends": null,
                    "endpoints": [
                        {"domain":"a.com","port":80,"protocol":"TCP","process":"p"},
                        {"domain":"a.com","port":81,"protocol":"TCP","process":"p"}
                    ]
                }
            ]
        }"#;
        set_custom_whitelists(json).await.expect("set ok");

        let cap = crate::capture::FlodbaddCapture::new();
        let out = cap.augment_custom_whitelists().await.expect("augment ok");
        let parsed: WhitelistsJSON = serde_json::from_str(&out.0).unwrap();
        let info = parsed
            .whitelists
            .iter()
            .find(|w| w.name == "custom_whitelist")
            .unwrap();
        assert_eq!(info.endpoints.len(), 1);
        assert!(info.endpoints[0].ports.is_some());
    }

    #[tokio::test]
    #[serial]
    async fn test_egress_only_evaluation() {
        // Prepare a whitelist that matches 8.8.8.8:53/UDP only
        let wl_info = WhitelistInfo {
            name: "egress_test".into(),
            extends: None,
            endpoints: vec![WhitelistEndpoint {
                domain: None,
                domains: None,
                ip: Some("8.8.8.8".into()),
                port: Some(53),
                protocol: Some("UDP".into()),
                as_number: None,
                as_country: None,
                as_owner: None,
                process: None,
                description: None,
                ports: None,
                ips: None,
            }],
        };
        let map = CustomDashMap::new("whitelists");
        map.insert("egress_test".into(), wl_info);
        let model = Whitelists {
            date: "June 18th 2025".into(),
            signature: None,
            whitelists: Arc::new(map),
        };
        overwrite_with_test_data(model).await;

        // Build sessions: one ingress (local dst) and one egress non-matching
        let sessions = Arc::new(CustomDashMap::new("sessions"));
        let ingress_key = Session {
            protocol: crate::sessions::Protocol::UDP,
            src_ip: IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9)),
            src_port: 12345,
            dst_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)),
            dst_port: 9999,
        };
        let egress_key = Session {
            protocol: crate::sessions::Protocol::UDP,
            src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)),
            src_port: 12345,
            dst_ip: IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9)),
            dst_port: 9999,
        };
        let now = Utc::now();
        sessions.insert(
            ingress_key.clone(),
            SessionInfo {
                session: ingress_key.clone(),
                status: crate::sessions::SessionStatus::default(),
                stats: crate::sessions::SessionStats::new(now),
                is_local_src: false,
                is_local_dst: true,
                is_self_src: false,
                is_self_dst: false,
                src_domain: None,
                dst_domain: None,
                dst_service: None,
                l7: None,
                src_asn: None,
                dst_asn: None,
                is_whitelisted: WhitelistState::Unknown,
                criticality: String::new(),
                dismissed: false,
                whitelist_reason: None,
                src_domain_type: DomainResolutionType::None,
                dst_domain_type: DomainResolutionType::None,
                uid: "i".into(),
                last_modified: now,
            },
        );
        sessions.insert(
            egress_key.clone(),
            SessionInfo {
                session: egress_key.clone(),
                status: crate::sessions::SessionStatus::default(),
                stats: crate::sessions::SessionStats::new(now),
                is_local_src: true,
                is_local_dst: false,
                is_self_src: false,
                is_self_dst: false,
                src_domain: None,
                dst_domain: None,
                dst_service: None,
                l7: None,
                src_asn: None,
                dst_asn: None,
                is_whitelisted: WhitelistState::Unknown,
                criticality: String::new(),
                dismissed: false,
                whitelist_reason: None,
                src_domain_type: DomainResolutionType::None,
                dst_domain_type: DomainResolutionType::None,
                uid: "e".into(),
                last_modified: now,
            },
        );

        let whitelist_name = Arc::new(CustomRwLock::new("egress_test".into()));
        let whitelist_exceptions = Arc::new(CustomRwLock::new(Vec::new()));
        let whitelist_conformance = Arc::new(AtomicBool::new(true));
        let last_exception_time = Arc::new(CustomRwLock::new(now));

        // Run recompute
        recompute_whitelist_for_sessions(
            &whitelist_name,
            &sessions,
            &whitelist_exceptions,
            &whitelist_conformance,
            &last_exception_time,
        )
        .await;

        // Ingress should be treated as conforming (egress-only policy)
        let ingress = sessions.get(&ingress_key).unwrap();
        assert_eq!(ingress.is_whitelisted, WhitelistState::Conforming);

        // Egress non-matching should be non-conforming and in exceptions
        let egress = sessions.get(&egress_key).unwrap();
        assert_eq!(egress.is_whitelisted, WhitelistState::NonConforming);
        let ex = whitelist_exceptions.read().await.clone();
        assert!(ex.contains(&egress_key));
        assert!(!ex.contains(&ingress_key));
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
                    domains: None,
                    ip: Some("192.168.1.1".to_string()),
                    port: Some(443),
                    protocol: Some("TCP".to_string()),
                    as_number: None,
                    as_country: None,
                    as_owner: None,
                    process: Some("test_process".to_string()),
                    description: Some("Auto-generated endpoint".to_string()),
                    ports: None,
                    ips: None,
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
                    domains: None,
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
                    ports: None,
                    ips: None,
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
                domains: None,
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
                ports: None,
                ips: None,
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
    fn test_whitelist_file_bug_fix() {
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
                    domains: None,
                    ip: None,
                    port: Some(8080),
                    protocol: Some("TCP".to_string()),
                    as_number: None,
                    as_country: None,
                    as_owner: None,
                    process: Some("nodejs".to_string()),
                    description: Some("Custom Node.js service".to_string()),
                    ports: None,
                    ips: None,
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

    #[test]
    fn test_compare_whitelist_basic() {
        // Create old whitelist with one entry
        let old_whitelist = WhitelistsJSON {
            date: "2024-01-01".to_string(),
            signature: Some("old_sig".to_string()),
            whitelists: vec![WhitelistInfo {
                name: "test_whitelist".to_string(),
                extends: None,
                endpoints: vec![WhitelistEndpoint {
                    domain: Some("example.com".to_string()),
                    domains: None,
                    ip: Some("192.168.1.1".to_string()),
                    ips: None,
                    port: Some(80),
                    ports: None,
                    protocol: Some("HTTP".to_string()),
                    as_number: None,
                    as_country: None,
                    as_owner: None,
                    process: None,
                    description: Some("Old endpoint".to_string()),
                }],
            }],
        };

        // Create new whitelist with same entry plus a new one
        let new_whitelist = WhitelistsJSON {
            date: "2024-01-02".to_string(),
            signature: Some("new_sig".to_string()),
            whitelists: vec![WhitelistInfo {
                name: "test_whitelist".to_string(),
                extends: None,
                endpoints: vec![
                    WhitelistEndpoint {
                        domain: Some("example.com".to_string()),
                        domains: None,
                        ip: Some("192.168.1.1".to_string()),
                        ips: None,
                        port: Some(80),
                        ports: None,
                        protocol: Some("HTTP".to_string()),
                        as_number: None,
                        as_country: None,
                        as_owner: None,
                        process: None,
                        description: Some("Old endpoint".to_string()),
                    },
                    WhitelistEndpoint {
                        domain: Some("new-example.com".to_string()),
                        domains: None,
                        ip: Some("192.168.1.2".to_string()),
                        ips: None,
                        port: Some(443),
                        ports: None,
                        protocol: Some("HTTPS".to_string()),
                        as_number: None,
                        as_country: None,
                        as_owner: None,
                        process: None,
                        description: Some("New endpoint".to_string()),
                    },
                ],
            }],
        };

        let result = new_whitelist.compare_whitelist(old_whitelist);
        // Expected: 1 difference out of 2 total = 0 (due to integer division bug)
        assert_eq!(result, 50.0);
    }

    #[test]
    fn test_compare_whitelist_new_whitelist() {
        // Empty old whitelist
        let old_whitelist = WhitelistsJSON {
            date: "2024-01-01".to_string(),
            signature: Some("old_sig".to_string()),
            whitelists: vec![],
        };

        // New whitelist with one entry
        let new_whitelist = WhitelistsJSON {
            date: "2024-01-02".to_string(),
            signature: Some("new_sig".to_string()),
            whitelists: vec![WhitelistInfo {
                name: "new_whitelist".to_string(),
                extends: None,
                endpoints: vec![WhitelistEndpoint {
                    domain: Some("example.com".to_string()),
                    domains: None,
                    ip: Some("192.168.1.1".to_string()),
                    ips: None,
                    port: Some(80),
                    ports: None,
                    protocol: Some("HTTP".to_string()),
                    as_number: None,
                    as_country: None,
                    as_owner: None,
                    process: None,
                    description: Some("New endpoint".to_string()),
                }],
            }],
        };

        let result = new_whitelist.compare_whitelist(old_whitelist);
        // Expected: 1 difference out of 1 total = 1
        assert_eq!(result, 100.0);
    }

    #[test]
    fn test_compare_whitelist_no_differences() {
        // Same whitelist content
        let whitelist_content = WhitelistsJSON {
            date: "2024-01-01".to_string(),
            signature: Some("sig".to_string()),
            whitelists: vec![WhitelistInfo {
                name: "test_whitelist".to_string(),
                extends: None,
                endpoints: vec![WhitelistEndpoint {
                    domain: Some("example.com".to_string()),
                    domains: None,
                    ip: Some("192.168.1.1".to_string()),
                    ips: None,
                    port: Some(80),
                    ports: None,
                    protocol: Some("HTTP".to_string()),
                    as_number: None,
                    as_country: None,
                    as_owner: None,
                    process: None,
                    description: Some("Test endpoint".to_string()),
                }],
            }],
        };

        let old_whitelist = whitelist_content.clone();
        let new_whitelist = whitelist_content;

        let result = new_whitelist.compare_whitelist(old_whitelist);
        // Expected: 0 differences out of 1 total = 0
        assert_eq!(result, 0.0);
    }

    #[test]
    fn test_compare_whitelist_complex() {
        // Old whitelist with two lists
        let old_whitelist = WhitelistsJSON {
            date: "2024-01-01".to_string(),
            signature: Some("old_sig".to_string()),
            whitelists: vec![
                WhitelistInfo {
                    name: "whitelist_a".to_string(),
                    extends: None,
                    endpoints: vec![
                        WhitelistEndpoint {
                            domain: Some("a.com".to_string()),
                            domains: None,
                            ip: Some("10.0.0.1".to_string()),
                            ips: None,
                            port: Some(80),
                            ports: None,
                            protocol: Some("HTTP".to_string()),
                            as_number: None,
                            as_country: None,
                            as_owner: None,
                            process: None,
                            description: Some("A old endpoint".to_string()),
                        },
                        WhitelistEndpoint {
                            domain: Some("b.com".to_string()),
                            domains: None,
                            ip: Some("10.0.0.2".to_string()),
                            ips: None,
                            port: Some(443),
                            ports: None,
                            protocol: Some("HTTPS".to_string()),
                            as_number: None,
                            as_country: None,
                            as_owner: None,
                            process: None,
                            description: Some("B old endpoint".to_string()),
                        },
                    ],
                },
                WhitelistInfo {
                    name: "whitelist_b".to_string(),
                    extends: None,
                    endpoints: vec![WhitelistEndpoint {
                        domain: Some("x.com".to_string()),
                        domains: None,
                        ip: Some("172.16.0.1".to_string()),
                        ips: None,
                        port: Some(25),
                        ports: None,
                        protocol: Some("SMTP".to_string()),
                        as_number: None,
                        as_country: None,
                        as_owner: None,
                        process: None,
                        description: Some("X endpoint".to_string()),
                    }],
                },
            ],
        };

        // New whitelist:
        // - whitelist_a: 1 existing endpoint, 1 changed (new IP), 1 completely new endpoint
        // - whitelist_b: identical
        // - whitelist_c: completely new whitelist
        let new_whitelist = WhitelistsJSON {
            date: "2024-01-02".to_string(),
            signature: Some("new_sig".to_string()),
            whitelists: vec![
                WhitelistInfo {
                    name: "whitelist_a".to_string(),
                    extends: None,
                    endpoints: vec![
                        // unchanged
                        WhitelistEndpoint {
                            domain: Some("a.com".to_string()),
                            domains: None,
                            ip: Some("10.0.0.1".to_string()),
                            ips: None,
                            port: Some(80),
                            ports: None,
                            protocol: Some("HTTP".to_string()),
                            as_number: None,
                            as_country: None,
                            as_owner: None,
                            process: None,
                            description: Some("A old endpoint".to_string()),
                        },
                        // modified IP (counts as new endpoint in your code)
                        WhitelistEndpoint {
                            domain: Some("b.com".to_string()),
                            domains: None,
                            ip: Some("10.0.0.99".to_string()),
                            ips: None,
                            port: Some(443),
                            ports: None,
                            protocol: Some("HTTPS".to_string()),
                            as_number: None,
                            as_country: None,
                            as_owner: None,
                            process: None,
                            description: Some("B endpoint new IP".to_string()),
                        },
                        // brand new endpoint
                        WhitelistEndpoint {
                            domain: Some("c.com".to_string()),
                            domains: None,
                            ip: Some("10.0.0.3".to_string()),
                            ips: None,
                            port: Some(8080),
                            ports: None,
                            protocol: Some("HTTP".to_string()),
                            as_number: None,
                            as_country: None,
                            as_owner: None,
                            process: None,
                            description: Some("C new endpoint".to_string()),
                        },
                    ],
                },
                // unchanged whitelist_b
                WhitelistInfo {
                    name: "whitelist_b".to_string(),
                    extends: None,
                    endpoints: vec![WhitelistEndpoint {
                        domain: Some("x.com".to_string()),
                        domains: None,
                        ip: Some("172.16.0.1".to_string()),
                        ips: None,
                        port: Some(25),
                        ports: None,
                        protocol: Some("SMTP".to_string()),
                        as_number: None,
                        as_country: None,
                        as_owner: None,
                        process: None,
                        description: Some("X endpoint".to_string()),
                    }],
                },
                // new whitelist_c
                WhitelistInfo {
                    name: "whitelist_c".to_string(),
                    extends: None,
                    endpoints: vec![WhitelistEndpoint {
                        domain: Some("newlist.com".to_string()),
                        domains: None,
                        ip: Some("192.168.100.1".to_string()),
                        ips: None,
                        port: Some(21),
                        ports: None,
                        protocol: Some("FTP".to_string()),
                        as_number: None,
                        as_country: None,
                        as_owner: None,
                        process: None,
                        description: Some("New list endpoint".to_string()),
                    }],
                },
            ],
        };

        let result = new_whitelist.compare_whitelist(old_whitelist);
        // Let's reason: total endpoints in new list = 3 (whitelist_a) + 1 (whitelist_b) + 1 (whitelist_c) = 5
        // Different ones:
        //  - whitelist_a: b.com new IP, c.com new
        //  - whitelist_c: all endpoints new (1)
        //  => different = 3 / total 5 = 60%
        assert_eq!(result, 60.0);
    }

    /// Test that CDN sessions without resolved domains are skipped
    #[test]
    fn test_new_from_sessions_skips_cdn_without_domain() {
        use crate::asn_db::Record;
        use crate::sessions::{
            Protocol, Session, SessionInfo, SessionStats, SessionStatus, WhitelistState,
        };
        use chrono::Utc;
        use uuid::Uuid;

        let now = Utc::now();

        // Test case 1: CDN (Fastly) session with unresolved domain - should be SKIPPED
        let cdn_unresolved = SessionInfo {
            session: Session {
                protocol: Protocol::TCP,
                src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
                src_port: 50000,
                dst_ip: IpAddr::V4(Ipv4Addr::new(185, 199, 110, 133)), // Fastly IP
                dst_port: 443,
            },
            status: SessionStatus::default(),
            stats: SessionStats::new(now),
            is_local_src: true,
            is_local_dst: false,
            is_self_src: false,
            is_self_dst: false,
            src_domain: None,
            dst_domain: Some("Unknown".to_string()), // Unresolved domain
            dst_service: Some("https".to_string()),
            l7: None,
            src_asn: None,
            dst_asn: Some(Record {
                as_number: 54113,
                owner: "FASTLY".to_string(),
                country: "US".to_string(),
            }),
            is_whitelisted: WhitelistState::Unknown,
            criticality: String::new(),
            dismissed: false,
            whitelist_reason: None,
            src_domain_type: DomainResolutionType::None,
            dst_domain_type: DomainResolutionType::None,
            uid: Uuid::new_v4().to_string(),
            last_modified: now,
        };

        // Test case 2: CDN (Fastly) session with resolved domain - should be INCLUDED
        let cdn_resolved = SessionInfo {
            session: Session {
                protocol: Protocol::TCP,
                src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
                src_port: 50001,
                dst_ip: IpAddr::V4(Ipv4Addr::new(185, 199, 108, 133)), // Different Fastly IP
                dst_port: 443,
            },
            status: SessionStatus::default(),
            stats: SessionStats::new(now),
            is_local_src: true,
            is_local_dst: false,
            is_self_src: false,
            is_self_dst: false,
            src_domain: None,
            dst_domain: Some("gist.githubusercontent.com".to_string()), // Resolved domain
            dst_service: Some("https".to_string()),
            l7: None,
            src_asn: None,
            dst_asn: Some(Record {
                as_number: 54113,
                owner: "FASTLY".to_string(),
                country: "US".to_string(),
            }),
            is_whitelisted: WhitelistState::Unknown,
            criticality: String::new(),
            dismissed: false,
            whitelist_reason: None,
            src_domain_type: DomainResolutionType::None,
            dst_domain_type: DomainResolutionType::None,
            uid: Uuid::new_v4().to_string(),
            last_modified: now,
        };

        // Test case 3: Non-CDN session with unresolved domain - should be INCLUDED (IP-only)
        let non_cdn_unresolved = SessionInfo {
            session: Session {
                protocol: Protocol::TCP,
                src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
                src_port: 50002,
                dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), // Internal IP
                dst_port: 8080,
            },
            status: SessionStatus::default(),
            stats: SessionStats::new(now),
            is_local_src: true,
            is_local_dst: false,
            is_self_src: false,
            is_self_dst: false,
            src_domain: None,
            dst_domain: Some("Resolving".to_string()), // Unresolved domain
            dst_service: Some("http".to_string()),
            l7: None,
            src_asn: None,
            dst_asn: Some(Record {
                as_number: 64496, // Private ASN
                owner: "Example ISP".to_string(),
                country: "US".to_string(),
            }),
            is_whitelisted: WhitelistState::Unknown,
            criticality: String::new(),
            dismissed: false,
            whitelist_reason: None,
            src_domain_type: DomainResolutionType::None,
            dst_domain_type: DomainResolutionType::None,
            uid: Uuid::new_v4().to_string(),
            last_modified: now,
        };

        // Test case 4: Non-CDN session with resolved domain - should be INCLUDED
        let non_cdn_resolved = SessionInfo {
            session: Session {
                protocol: Protocol::TCP,
                src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
                src_port: 50003,
                dst_ip: IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)), // example.com
                dst_port: 443,
            },
            status: SessionStatus::default(),
            stats: SessionStats::new(now),
            is_local_src: true,
            is_local_dst: false,
            is_self_src: false,
            is_self_dst: false,
            src_domain: None,
            dst_domain: Some("example.com".to_string()), // Resolved domain
            dst_service: Some("https".to_string()),
            l7: None,
            src_asn: None,
            dst_asn: Some(Record {
                as_number: 15133,
                owner: "Edgecast Networks Inc.".to_string(),
                country: "US".to_string(),
            }),
            is_whitelisted: WhitelistState::Unknown,
            criticality: String::new(),
            dismissed: false,
            whitelist_reason: None,
            src_domain_type: DomainResolutionType::None,
            dst_domain_type: DomainResolutionType::None,
            uid: Uuid::new_v4().to_string(),
            last_modified: now,
        };

        // Test case 5: Session with no ASN info and unresolved domain - should be INCLUDED (backwards compatibility)
        let no_asn_unresolved = SessionInfo {
            session: Session {
                protocol: Protocol::TCP,
                src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
                src_port: 50004,
                dst_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 200)),
                dst_port: 22,
            },
            status: SessionStatus::default(),
            stats: SessionStats::new(now),
            is_local_src: true,
            is_local_dst: false,
            is_self_src: false,
            is_self_dst: false,
            src_domain: None,
            dst_domain: Some("Unknown".to_string()),
            dst_service: Some("ssh".to_string()),
            l7: None,
            src_asn: None,
            dst_asn: None, // No ASN info
            is_whitelisted: WhitelistState::Unknown,
            criticality: String::new(),
            dismissed: false,
            whitelist_reason: None,
            src_domain_type: DomainResolutionType::None,
            dst_domain_type: DomainResolutionType::None,
            uid: Uuid::new_v4().to_string(),
            last_modified: now,
        };

        // Test case 6: Cloudflare CDN with unresolved domain - should be SKIPPED
        let cloudflare_unresolved = SessionInfo {
            session: Session {
                protocol: Protocol::TCP,
                src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
                src_port: 50005,
                dst_ip: IpAddr::V4(Ipv4Addr::new(104, 16, 0, 1)), // Cloudflare IP
                dst_port: 443,
            },
            status: SessionStatus::default(),
            stats: SessionStats::new(now),
            is_local_src: true,
            is_local_dst: false,
            is_self_src: false,
            is_self_dst: false,
            src_domain: None,
            dst_domain: Some("Resolving".to_string()),
            dst_service: Some("https".to_string()),
            l7: None,
            src_asn: None,
            dst_asn: Some(Record {
                as_number: 13335,
                owner: "CLOUDFLARE".to_string(),
                country: "US".to_string(),
            }),
            is_whitelisted: WhitelistState::Unknown,
            criticality: String::new(),
            dismissed: false,
            whitelist_reason: None,
            src_domain_type: DomainResolutionType::None,
            dst_domain_type: DomainResolutionType::None,
            uid: Uuid::new_v4().to_string(),
            last_modified: now,
        };

        let sessions = vec![
            cdn_unresolved,
            cdn_resolved,
            non_cdn_unresolved,
            non_cdn_resolved,
            no_asn_unresolved,
            cloudflare_unresolved,
        ];

        let whitelist = Whitelists::new_from_sessions(&sessions);
        let whitelist_json = WhitelistsJSON::from(whitelist);

        // Should have 4 endpoints (CDN unresolved sessions should be skipped):
        // 1. cdn_resolved (gist.githubusercontent.com)
        // 2. non_cdn_unresolved (10.0.0.1:8080 - IP-only)
        // 3. non_cdn_resolved (example.com)
        // 4. no_asn_unresolved (192.168.1.200:22 - IP-only)
        assert_eq!(
            whitelist_json.whitelists.len(),
            1,
            "Should have one whitelist"
        );
        let endpoints = &whitelist_json.whitelists[0].endpoints;
        assert_eq!(
            endpoints.len(),
            4,
            "Should have 4 endpoints (CDN unresolved sessions skipped)"
        );

        // Verify cdn_resolved is included with domain
        assert!(
            endpoints.iter().any(
                |ep| ep.domain == Some("gist.githubusercontent.com".to_string())
                    && ep.ip == Some("185.199.108.133".to_string())
            ),
            "CDN session with resolved domain should be included"
        );

        // Verify non_cdn_unresolved is included (IP-only)
        assert!(
            endpoints.iter().any(|ep| ep.domain.is_none()
                && ep.ip == Some("10.0.0.1".to_string())
                && ep.port == Some(8080)),
            "Non-CDN session with unresolved domain should be included (IP-only)"
        );

        // Verify non_cdn_resolved is included with domain
        assert!(
            endpoints
                .iter()
                .any(|ep| ep.domain == Some("example.com".to_string())
                    && ep.ip == Some("93.184.216.34".to_string())),
            "Non-CDN session with resolved domain should be included"
        );

        // Verify no_asn_unresolved is included (IP-only, backwards compatibility)
        assert!(
            endpoints.iter().any(|ep| ep.domain.is_none()
                && ep.ip == Some("192.168.1.200".to_string())
                && ep.port == Some(22)),
            "Session with no ASN and unresolved domain should be included (backwards compatibility)"
        );

        // Verify CDN unresolved sessions are NOT included
        assert!(
            !endpoints
                .iter()
                .any(|ep| ep.ip == Some("185.199.110.133".to_string())),
            "CDN session (Fastly) without resolved domain should be skipped"
        );
        assert!(
            !endpoints
                .iter()
                .any(|ep| ep.ip == Some("104.16.0.1".to_string())),
            "CDN session (Cloudflare) without resolved domain should be skipped"
        );
    }

    /// Test that all CDN providers are detected correctly
    #[test]
    fn test_cdn_provider_detection() {
        use crate::asn_db::Record;
        use crate::sessions::{
            Protocol, Session, SessionInfo, SessionStats, SessionStatus, WhitelistState,
        };
        use chrono::Utc;
        use uuid::Uuid;

        let now = Utc::now();
        let mut sessions = Vec::new();

        // Test all CDN providers with unresolved domains - all should be skipped
        // Automatically adapts to changes in CDN_PROVIDERS const
        use std::collections::HashMap;

        // Build HashMap from const test data for efficient lookup
        let known_provider_test_data: HashMap<&str, (&str, &str)> = CDN_PROVIDER_TEST_DATA
            .iter()
            .map(|(provider, owner, ip)| (*provider, (*owner, *ip)))
            .collect();

        // Build test data from CDN_PROVIDERS const - automatically includes all providers
        // Uses known test data if available, otherwise generates default test data
        let cdn_provider_test_data: Vec<(String, String)> = CDN_PROVIDERS
            .iter()
            .map(|provider| {
                if let Some((owner_name, ip)) = known_provider_test_data.get(provider) {
                    (owner_name.to_string(), ip.to_string())
                } else {
                    // Auto-generate test data for new providers not in the known list
                    // Capitalize provider name and use a default IP pattern
                    let owner_name = if provider.len() > 1 {
                        format!("{}{}", provider[..1].to_uppercase(), &provider[1..])
                    } else {
                        provider.to_uppercase()
                    };
                    // Generate a unique test IP based on provider name hash
                    let ip_octet = (provider.len() % 255) as u8;
                    let ip = format!("192.168.1.{}", ip_octet);
                    (owner_name, ip)
                }
            })
            .collect();

        for (owner, ip_str) in &cdn_provider_test_data {
            let ip: IpAddr = ip_str.parse().unwrap();
            sessions.push(SessionInfo {
                session: Session {
                    protocol: Protocol::TCP,
                    src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
                    src_port: 50000,
                    dst_ip: ip,
                    dst_port: 443,
                },
                status: SessionStatus::default(),
                stats: SessionStats::new(now),
                is_local_src: true,
                is_local_dst: false,
                is_self_src: false,
                is_self_dst: false,
                src_domain: None,
                dst_domain: Some("Unknown".to_string()),
                dst_service: Some("https".to_string()),
                l7: None,
                src_asn: None,
                dst_asn: Some(Record {
                    as_number: 12345,
                    owner: owner.clone(),
                    country: "US".to_string(),
                }),
                is_whitelisted: WhitelistState::Unknown,
                criticality: String::new(),
                dismissed: false,
                whitelist_reason: None,
                src_domain_type: DomainResolutionType::None,
                dst_domain_type: DomainResolutionType::None,
                uid: Uuid::new_v4().to_string(),
                last_modified: now,
            });
        }

        // Add one resolved CDN session - should be included
        sessions.push(SessionInfo {
            session: Session {
                protocol: Protocol::TCP,
                src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
                src_port: 50001,
                dst_ip: IpAddr::V4(Ipv4Addr::new(185, 199, 108, 133)),
                dst_port: 443,
            },
            status: SessionStatus::default(),
            stats: SessionStats::new(now),
            is_local_src: true,
            is_local_dst: false,
            is_self_src: false,
            is_self_dst: false,
            src_domain: None,
            dst_domain: Some("example.com".to_string()), // Resolved!
            dst_service: Some("https".to_string()),
            l7: None,
            src_asn: None,
            dst_asn: Some(Record {
                as_number: 54113,
                owner: "FASTLY".to_string(),
                country: "US".to_string(),
            }),
            is_whitelisted: WhitelistState::Unknown,
            criticality: String::new(),
            dismissed: false,
            whitelist_reason: None,
            src_domain_type: DomainResolutionType::None,
            dst_domain_type: DomainResolutionType::None,
            uid: Uuid::new_v4().to_string(),
            last_modified: now,
        });

        let whitelist = Whitelists::new_from_sessions(&sessions);
        let whitelist_json = WhitelistsJSON::from(whitelist);

        // Should only have 1 endpoint (the resolved CDN session)
        assert_eq!(
            whitelist_json.whitelists.len(),
            1,
            "Should have one whitelist"
        );
        let endpoints = &whitelist_json.whitelists[0].endpoints;
        assert_eq!(
            endpoints.len(),
            1,
            "Should have only 1 endpoint (resolved CDN), all unresolved CDNs should be skipped"
        );

        // Verify the resolved CDN session is included
        assert!(
            endpoints
                .iter()
                .any(|ep| ep.domain == Some("example.com".to_string())
                    && ep.ip == Some("185.199.108.133".to_string())),
            "Resolved CDN session should be included"
        );

        // Verify all unresolved CDN sessions are skipped
        for (_, ip_str) in &cdn_provider_test_data {
            assert!(
                !endpoints.iter().any(|ep| ep.ip == Some(ip_str.clone())),
                "CDN session from {} without resolved domain should be skipped",
                ip_str
            );
        }
    }

    /// Test that sessions without ASN info are not skipped (backwards compatibility)
    #[test]
    fn test_no_asn_backwards_compatibility() {
        use crate::sessions::{
            Protocol, Session, SessionInfo, SessionStats, SessionStatus, WhitelistState,
        };
        use chrono::Utc;
        use uuid::Uuid;

        let now = Utc::now();

        // Session with unresolved domain but no ASN info - should be included (backwards compatibility)
        let session_no_asn = SessionInfo {
            session: Session {
                protocol: Protocol::TCP,
                src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
                src_port: 50000,
                dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                dst_port: 8080,
            },
            status: SessionStatus::default(),
            stats: SessionStats::new(now),
            is_local_src: true,
            is_local_dst: false,
            is_self_src: false,
            is_self_dst: false,
            src_domain: None,
            dst_domain: Some("Resolving".to_string()), // Unresolved
            dst_service: Some("http".to_string()),
            l7: None,
            src_asn: None,
            dst_asn: None, // No ASN info - should not be skipped
            is_whitelisted: WhitelistState::Unknown,
            criticality: String::new(),
            dismissed: false,
            whitelist_reason: None,
            src_domain_type: DomainResolutionType::None,
            dst_domain_type: DomainResolutionType::None,
            uid: Uuid::new_v4().to_string(),
            last_modified: now,
        };

        let sessions = vec![session_no_asn];
        let whitelist = Whitelists::new_from_sessions(&sessions);
        let whitelist_json = WhitelistsJSON::from(whitelist);

        // Should have 1 endpoint (IP-only, backwards compatibility)
        assert_eq!(
            whitelist_json.whitelists.len(),
            1,
            "Should have one whitelist"
        );
        let endpoints = &whitelist_json.whitelists[0].endpoints;
        assert_eq!(
            endpoints.len(),
            1,
            "Session without ASN info should be included for backwards compatibility"
        );
        assert!(
            endpoints.iter().any(|ep| ep.domain.is_none()
                && ep.ip == Some("10.0.0.1".to_string())
                && ep.port == Some(8080)),
            "Session without ASN should be included as IP-only endpoint"
        );
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
