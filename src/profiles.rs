use crate::port_info::*;
use crate::profiles_db::*;
use anyhow::{Context, Result};
use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::sync::Arc;
use threatmodels_rs::*;
use tracing::{info, trace, warn};
use undeadlock::*;

// Constants for repository and file names
const PROFILES_NAME: &str = "lanscan-profiles-db.json";

// Cache for device_type computation: key -> device type
lazy_static! {
    static ref DEVICE_TYPE_CACHE: CustomDashMap<String, String> =
        CustomDashMap::new("Profiles Device Type Cache");
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct Attributes {
    pub open_ports: Option<Vec<u16>>,
    pub mdns_services: Option<Vec<String>>,
    pub vendors: Option<Vec<String>>,
    pub hostnames: Option<Vec<String>>,
    pub banners: Option<Vec<String>>,
    pub negate: Option<bool>, // Field to indicate negation
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub enum Condition {
    Leaf(Attributes),
    Node {
        #[serde(rename = "type")]
        condition_type: String,
        sub_conditions: Vec<Condition>,
    },
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct DeviceTypeRule {
    pub device_type: String,
    pub conditions: Vec<Condition>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DeviceTypeListJSON {
    pub date: String,
    pub signature: String,
    pub profiles: Vec<DeviceTypeRule>,
}

impl CloudSignature for DeviceTypeList {
    fn get_signature(&self) -> String {
        self.signature.clone()
    }
    fn set_signature(&mut self, signature: String) {
        self.signature = signature;
    }
}

#[derive(Clone)]
pub struct DeviceTypeList {
    pub date: String,
    pub signature: String,
    // Preserve JSON order: iterate rules in the exact order provided by the file
    pub profiles: Arc<Vec<DeviceTypeRule>>,
}

impl DeviceTypeList {
    pub fn new_from_json(device_info: DeviceTypeListJSON) -> Self {
        info!("Loading device profiles from JSON");

        let profiles_vec = Arc::new(device_info.profiles);

        DeviceTypeList {
            date: device_info.date,
            signature: device_info.signature,
            profiles: profiles_vec,
        }
    }
}

lazy_static! {
    pub static ref PROFILES: CloudModel<DeviceTypeList> = {
        let model = CloudModel::initialize(PROFILES_NAME.to_string(), &DEVICE_PROFILES, |data| {
            let profiles_list: DeviceTypeListJSON =
                serde_json::from_str(data).with_context(|| "Failed to parse JSON data")?;
            Ok(DeviceTypeList::new_from_json(profiles_list))
        });
        match model {
            Ok(m) => m,
            Err(e) => {
                eprintln!(
                    "FATAL: Failed to initialize CloudModel for profiles: {:?}",
                    e
                );
                panic!("Failed to initialize CloudModel for profiles: {:?}", e);
            }
        }
    };
}

pub async fn device_type(
    open_ports: &Vec<PortInfo>,
    mdns_services: &Vec<String>,
    oui_vendor: &str,
    hostname: &str,
) -> String {
    // Build a deterministic cache key
    let mut ports_vec: Vec<u16> = open_ports.iter().map(|p| p.port).collect();
    ports_vec.sort_unstable();
    let ports_key = ports_vec
        .iter()
        .map(|p| p.to_string())
        .collect::<Vec<String>>()
        .join(",");

    let mut mdns_vec: Vec<String> = mdns_services.iter().map(|s| s.to_lowercase()).collect();
    mdns_vec.sort();
    let mdns_key = mdns_vec.join(",");

    let banners: Vec<String> = open_ports.iter().map(|info| info.banner.clone()).collect();
    let mut banners_sorted: Vec<String> = banners.iter().map(|b| b.to_lowercase()).collect();
    banners_sorted.sort();
    let banners_key = banners_sorted.join(",");

    let key = format!(
        "{}|{}|{}|{}|{}",
        ports_key,
        mdns_key,
        oui_vendor.to_lowercase(),
        hostname.to_lowercase(),
        banners_key
    );

    if let Some(entry) = DEVICE_TYPE_CACHE.get(&key) {
        return entry.clone();
    }

    trace!(
        "Computing device type for ports {:?}, mdns {:?}, vendor {}, hostname {}",
        open_ports,
        mdns_services,
        oui_vendor,
        hostname
    );

    // Clone the Arc to avoid holding the lock during iteration
    let profiles_vec = PROFILES.data.read().await.profiles.clone();

    let result = classify_device(
        &profiles_vec,
        &ports_vec,
        mdns_services,
        oui_vendor,
        hostname,
        &banners,
    );

    if result == UNKNOWN_DEVICE_TYPE
        && (!open_ports.is_empty() || !mdns_services.is_empty())
        && !oui_vendor.is_empty()
    {
        warn!(
            "Unknown device type for ports {:?}, mdns {:?}, vendor {}, hostname {}, banners {:?}",
            ports_vec, mdns_services, oui_vendor, hostname, banners_sorted
        );
    }

    DEVICE_TYPE_CACHE.insert(key, result.clone());
    result
}

/// Device type returned when no profile matches.
pub const UNKNOWN_DEVICE_TYPE: &str = "Unknown";

/// Normalised classifier inputs, computed once per device.
struct ProfileInputs {
    open_ports: HashSet<u16>,
    /// mDNS service-type labels without their leading underscore
    /// (`_ipps._tcp` -> `ipps`), never the free-text instance name.
    mdns_types: Vec<String>,
    vendor_words: Vec<String>,
    hostname_words: Vec<String>,
    /// Lowercased banners; banner rules stay substring matches.
    banners: Vec<String>,
}

impl ProfileInputs {
    fn new(
        open_ports: &[u16],
        mdns_services: &[String],
        vendor: &str,
        hostname: &str,
        banners: &[String],
    ) -> Self {
        let mut mdns_types: Vec<String> = mdns_services
            .iter()
            .flat_map(|s| mdns_service_types(s))
            .collect();
        mdns_types.sort();
        mdns_types.dedup();
        Self {
            open_ports: open_ports.iter().copied().collect(),
            mdns_types,
            vendor_words: words(vendor),
            hostname_words: words(hostname),
            banners: banners.iter().map(|b| b.to_lowercase()).collect(),
        }
    }
}

/// Classify a device against an ordered profile list: the first rule with a
/// matching condition wins, `Unknown` when none does. Pure, so any profile
/// list (embedded fallback, a local threatmodels checkout) can be evaluated.
pub fn classify_device(
    profiles: &[DeviceTypeRule],
    open_ports: &[u16],
    mdns_services: &[String],
    vendor: &str,
    hostname: &str,
    banners: &[String],
) -> String {
    let inputs = ProfileInputs::new(open_ports, mdns_services, vendor, hostname, banners);
    for profile in profiles {
        if profile
            .conditions
            .iter()
            .any(|condition| condition_matches(condition, &inputs))
        {
            trace!("Match for device type {:?}", profile.device_type);
            return profile.device_type.clone();
        }
    }
    UNKNOWN_DEVICE_TYPE.to_string()
}

/// Service-type labels of one mDNS entry, lowercased, underscore stripped.
///
/// An entry is normally a full instance name,
/// `[<instance>.][_<subtype>._sub.]_<service>._<proto>.local`. The instance
/// part is free text chosen by the user ("Philippe's iPhone") and is never
/// returned. Bare service types ("ipp", "_ipp._tcp") are accepted too.
fn mdns_service_types(entry: &str) -> Vec<String> {
    let lower = entry.trim().trim_end_matches('.').to_lowercase();
    let labels: Vec<&str> = lower.split('.').collect();
    let mut types = Vec::new();
    for (i, label) in labels.iter().enumerate() {
        if matches!(*label, "_tcp" | "_udp" | "_sub") && i > 0 {
            if let Some(service) = labels[i - 1].strip_prefix('_') {
                if !service.is_empty() {
                    types.push(service.to_string());
                }
            }
        }
    }
    if types.is_empty() {
        // No protocol label: a bare service type such as "ipp" or "_ipp".
        let bare = labels
            .first()
            .copied()
            .unwrap_or("")
            .trim_start_matches('_');
        if labels.len() == 1
            && !bare.is_empty()
            && bare
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        {
            types.push(bare.to_string());
        }
    }
    types
}

/// Lowercase alphanumeric words: "ASUSTek COMPUTER INC." -> [asustek, computer, inc].
fn words(text: &str) -> Vec<String> {
    text.to_lowercase()
        .split(|c: char| !c.is_alphanumeric())
        .filter(|w| !w.is_empty())
        .map(str::to_string)
        .collect()
}

/// True when the rule's words appear as consecutive whole words of `haystack`.
/// With `last_word_prefix`, the rule's last word may be a prefix of the
/// matching word ("xbox" matches "XboxOne-1234").
fn phrase_matches(haystack: &[String], rule: &str, last_word_prefix: bool) -> bool {
    let rule_words = words(rule);
    let n = rule_words.len();
    if n == 0 || haystack.len() < n {
        return false;
    }
    haystack.windows(n).any(|window| {
        window
            .iter()
            .zip(rule_words.iter())
            .enumerate()
            .all(|(i, (word, rule_word))| {
                if last_word_prefix && i == n - 1 {
                    word.starts_with(rule_word.as_str())
                } else {
                    word == rule_word
                }
            })
    })
}

/// A service-type rule matches a label it equals or prefixes ("ipp" matches
/// "ipps", "androidtvremote" matches "androidtvremote2").
fn mdns_rule_matches(mdns_types: &[String], rule: &str) -> bool {
    let rule = rule.trim().trim_start_matches('_').to_lowercase();
    !rule.is_empty() && mdns_types.iter().any(|t| t.starts_with(rule.as_str()))
}

fn condition_matches(condition: &Condition, inputs: &ProfileInputs) -> bool {
    match condition {
        Condition::Leaf(attributes) => {
            let port_match = match &attributes.open_ports {
                Some(ports) => ports.iter().all(|port| inputs.open_ports.contains(port)),
                None => true,
            };

            let mdns_match = match &attributes.mdns_services {
                Some(services) if !services.is_empty() => services
                    .iter()
                    .any(|service| mdns_rule_matches(&inputs.mdns_types, service)),
                _ => true,
            };

            let vendor_match = match &attributes.vendors {
                Some(vendors) if !vendors.is_empty() => vendors
                    .iter()
                    .any(|vendor| phrase_matches(&inputs.vendor_words, vendor, false)),
                _ => true,
            };

            let hostname_match = match &attributes.hostnames {
                Some(hostnames) if !hostnames.is_empty() => hostnames
                    .iter()
                    .any(|host| phrase_matches(&inputs.hostname_words, host, true)),
                _ => true,
            };

            let banner_match = match &attributes.banners {
                Some(banner_rules) if !banner_rules.is_empty() => banner_rules.iter().any(|rule| {
                    let rule = rule.to_lowercase();
                    inputs.banners.iter().any(|banner| banner.contains(&rule))
                }),
                _ => true,
            };

            let result = port_match && mdns_match && vendor_match && hostname_match && banner_match;
            if attributes.negate.unwrap_or(false) {
                !result
            } else {
                result
            }
        }
        Condition::Node {
            condition_type,
            sub_conditions,
        } => match condition_type.as_str() {
            "AND" => sub_conditions
                .iter()
                .all(|sub| condition_matches(sub, inputs)),
            "OR" => sub_conditions
                .iter()
                .any(|sub| condition_matches(sub, inputs)),
            _ => false,
        },
    }
}

/// Evaluate one condition against raw (un-normalised) inputs.
#[cfg(test)]
fn match_condition(
    condition: &Condition,
    open_ports_set: &HashSet<u16>,
    mdns_services: &Vec<String>,
    oui_vendor: &str,
    hostname: &str,
    banners: &Vec<String>,
) -> bool {
    let ports: Vec<u16> = open_ports_set.iter().copied().collect();
    let inputs = ProfileInputs::new(&ports, mdns_services, oui_vendor, hostname, banners);
    condition_matches(condition, &inputs)
}

pub async fn update(branch: &str, force: bool) -> Result<UpdateStatus> {
    info!("Starting profiles update from backend");

    let status = PROFILES
        .update(branch, force, |data| {
            let profiles_list: DeviceTypeListJSON =
                serde_json::from_str(data).with_context(|| "Failed to parse JSON data")?;
            Ok(DeviceTypeList::new_from_json(profiles_list))
        })
        .await?;

    // Clear computed device_type cache whenever we attempt an update (conservative)
    DEVICE_TYPE_CACHE.clear();

    match status {
        UpdateStatus::Updated => info!("Profiles were successfully updated."),
        UpdateStatus::NotUpdated => info!("Profiles are already up to date."),
        UpdateStatus::FormatError => warn!("There was a format error in the profiles data."),
        UpdateStatus::SkippedCustom => info!("Update skipped because custom profiles are in use."),
    }

    Ok(status)
}

// Tests
#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;
    use std::sync::Once;
    use threatmodels_rs::UpdateStatus;

    /// Regression guard (helper/app/posture startup): the embedded device-
    /// profiles snapshot MUST decode and parse. If a bad regen makes it
    /// unparseable, the `PROFILES` CloudModel `lazy_static` panics on its first
    /// deref and the daemon dies at startup. This catches it in CI instead.
    /// See also whitelists/blacklists/sensitive_paths/port_vulns/vendor_vulns.
    #[test]
    fn test_embedded_profiles_snapshot_parses() {
        serde_json::from_str::<DeviceTypeListJSON>(&DEVICE_PROFILES)
            .expect("embedded device profiles snapshot must parse as DeviceTypeListJSON");
    }

    // Initialize logging or other necessary setup here
    static INIT: Once = Once::new();

    fn setup() {
        INIT.call_once(|| {
            // Initialize logging or any other setup here
        });

        // Clear device type cache to ensure test isolation
        DEVICE_TYPE_CACHE.clear();
    }

    #[tokio::test]
    #[serial]
    async fn test_match_condition() {
        setup();
        let condition = Condition::Leaf(Attributes {
            open_ports: Some(vec![80, 443]),
            mdns_services: Some(vec!["http".to_string(), "https".to_string()]),
            vendors: Some(vec!["cisco".to_string(), "arista".to_string()]),
            hostnames: Some(vec!["router".to_string(), "switch".to_string()]),
            banners: Some(vec!["cisco ios".to_string(), "arista eos".to_string()]),
            negate: Some(false),
        });

        let open_ports_set = HashSet::from([80, 443]);
        let mdns_services = vec!["http".to_string(), "https".to_string()];
        let oui_vendor = "cisco";
        let hostname = "router";
        let banners = vec!["cisco ios".to_string(), "arista eos".to_string()];

        assert!(match_condition(
            &condition,
            &open_ports_set,
            &mdns_services,
            &oui_vendor,
            &hostname,
            &banners
        ));
    }

    #[tokio::test]
    #[serial]
    async fn test_match_condition_negate() {
        setup();
        let condition = Condition::Leaf(Attributes {
            open_ports: Some(vec![80, 443]),
            mdns_services: Some(vec!["http".to_string(), "https".to_string()]),
            vendors: Some(vec!["cisco".to_string(), "arista".to_string()]),
            hostnames: Some(vec!["router".to_string(), "switch".to_string()]),
            banners: Some(vec!["cisco ios".to_string(), "arista eos".to_string()]),
            negate: Some(true),
        });

        let open_ports_set = HashSet::from([80, 443]);
        let mdns_services = vec!["http".to_string(), "https".to_string()];
        let oui_vendor = "cisco";
        let hostname = "router";
        let banners = vec!["cisco ios".to_string(), "arista eos".to_string()];

        assert!(!match_condition(
            &condition,
            &open_ports_set,
            &mdns_services,
            &oui_vendor,
            &hostname,
            &banners
        ));
    }

    #[tokio::test]
    #[serial]
    async fn test_match_condition_no_open_ports() {
        setup();
        let condition = Condition::Leaf(Attributes {
            open_ports: None,
            mdns_services: Some(vec!["http".to_string(), "https".to_string()]),
            vendors: Some(vec!["cisco".to_string(), "arista".to_string()]),
            hostnames: Some(vec!["router".to_string(), "switch".to_string()]),
            banners: Some(vec!["cisco ios".to_string(), "arista eos".to_string()]),
            negate: Some(false),
        });

        let open_ports_set = HashSet::new();
        let mdns_services = vec!["http".to_string(), "https".to_string()];
        let oui_vendor = "cisco";
        let hostname = "router";
        let banners = vec!["cisco ios".to_string(), "arista eos".to_string()];

        assert!(match_condition(
            &condition,
            &open_ports_set,
            &mdns_services,
            &oui_vendor,
            &hostname,
            &banners
        ));
    }

    #[tokio::test]
    #[serial]
    async fn test_device_type_unknown() {
        setup();
        let open_ports = vec![];
        let mdns_services = vec![];
        let oui_vendor = "";
        let hostname = "";

        let result = device_type(&open_ports, &mdns_services, oui_vendor, hostname).await;
        assert_eq!(result, "Unknown");
    }

    fn mdns(entries: &[&str]) -> Vec<String> {
        entries.iter().map(|s| s.to_string()).collect()
    }

    fn leaf_mdns(services: &[&str]) -> Condition {
        Condition::Leaf(Attributes {
            open_ports: None,
            mdns_services: Some(mdns(services)),
            vendors: None,
            hostnames: None,
            banners: None,
            negate: None,
        })
    }

    fn leaf_vendor(vendors: &[&str]) -> Condition {
        Condition::Leaf(Attributes {
            open_ports: None,
            mdns_services: None,
            vendors: Some(mdns(vendors)),
            hostnames: None,
            banners: None,
            negate: None,
        })
    }

    fn leaf_hostname(hostnames: &[&str]) -> Condition {
        Condition::Leaf(Attributes {
            open_ports: None,
            mdns_services: None,
            vendors: None,
            hostnames: Some(mdns(hostnames)),
            banners: None,
            negate: None,
        })
    }

    fn matches(
        condition: &Condition,
        mdns_services: &[&str],
        vendor: &str,
        hostname: &str,
    ) -> bool {
        match_condition(
            condition,
            &HashSet::new(),
            &mdns(mdns_services),
            vendor,
            hostname,
            &vec![],
        )
    }

    #[test]
    fn mdns_service_types_ignore_the_instance_name() {
        assert_eq!(
            mdns_service_types("Philippe's iPhone._companion-link._tcp.local"),
            vec!["companion-link"]
        );
        assert_eq!(
            mdns_service_types("HP LaserJet [A1B2C3]._universal._sub._ipp._tcp.local."),
            vec!["universal", "ipp"]
        );
        assert_eq!(mdns_service_types("_ipps._tcp.local"), vec!["ipps"]);
        assert_eq!(mdns_service_types("http"), vec!["http"]);
        assert!(mdns_service_types("Philippe's iPhone").is_empty());
    }

    #[test]
    fn a_printer_rule_does_not_match_an_iphone_instance_name() {
        let printer = leaf_mdns(&["ipp", "printer"]);
        // "Philippe's" contains "ipp", "iPhone" does not make it a printer.
        assert!(!matches(
            &printer,
            &[
                "Philippe's iPhone._companion-link._tcp.local",
                "Philippe's iPhone._rdlink._tcp.local"
            ],
            "",
            "Philippes-iPhone.local"
        ));
        assert!(!matches(
            &printer,
            &["My Printer Room._airplay._tcp.local"],
            "",
            ""
        ));
        // The service type does.
        assert!(matches(
            &printer,
            &["HP OfficeJet 8020._ipps._tcp.local"],
            "",
            ""
        ));
        assert!(matches(
            &printer,
            &["Brother HL-L2350DW._printer._tcp.local"],
            "",
            ""
        ));
    }

    #[test]
    fn an_mdns_rule_matches_a_service_type_prefix() {
        let tv = leaf_mdns(&["androidtvremote"]);
        assert!(matches(
            &tv,
            &["SHIELD._androidtvremote2._tcp.local"],
            "",
            ""
        ));
        assert!(!matches(
            &tv,
            &["androidtvremote fan._http._tcp.local"],
            "",
            ""
        ));
        // A rule is a prefix of the label, not a substring of it.
        assert!(!matches(
            &leaf_mdns(&["link"]),
            &["Mac._companion-link._tcp.local"],
            "",
            ""
        ));
    }

    #[test]
    fn vendors_match_on_word_boundaries() {
        let lg = leaf_vendor(&["lg"]);
        assert!(matches(&lg, &[], "LG Electronics", ""));
        assert!(matches(&lg, &[], "LG Innotek", ""));
        assert!(!matches(&lg, &[], "Belgacom", ""));
        assert!(!matches(&lg, &[], "Algorithmic Research", ""));
        let multi = leaf_vendor(&["sony interactive entertainment", "tp-link"]);
        assert!(matches(
            &multi,
            &[],
            "Sony Interactive Entertainment Inc.",
            ""
        ));
        assert!(!matches(&multi, &[], "Sony Corporation", ""));
        assert!(matches(&multi, &[], "TP-LINK TECHNOLOGIES CO.,LTD.", ""));
        // A vendor rule never matches a word prefix.
        assert!(!matches(
            &leaf_vendor(&["dell"]),
            &[],
            "Dellking Industrial",
            ""
        ));
    }

    #[test]
    fn hostnames_match_whole_words_or_a_word_prefix() {
        let xbox = leaf_hostname(&["xbox"]);
        assert!(matches(&xbox, &[], "", "XboxOne-1234"));
        assert!(matches(&xbox, &[], "", "my-xbox.lan"));
        assert!(!matches(&xbox, &[], "", "boxxbox"));
        let mac = leaf_hostname(&["mac mini"]);
        assert!(matches(&mac, &[], "", "Mac-mini-de-Frank.local"));
        assert!(!matches(&mac, &[], "", "mini-mac.local"));
    }

    #[test]
    fn classify_device_returns_the_first_matching_rule() {
        let profiles = vec![
            DeviceTypeRule {
                device_type: "Printer".to_string(),
                conditions: vec![leaf_mdns(&["ipp"])],
            },
            DeviceTypeRule {
                device_type: "iPhone".to_string(),
                conditions: vec![leaf_hostname(&["iphone"])],
            },
        ];
        let services = mdns(&["Philippe's iPhone._companion-link._tcp.local"]);
        assert_eq!(
            classify_device(&profiles, &[], &services, "", "Philippes-iPhone", &[]),
            "iPhone"
        );
        assert_eq!(
            classify_device(&profiles, &[], &[], "", "", &[]),
            UNKNOWN_DEVICE_TYPE
        );
    }

    /// Validation corpus: known devices with realistic fingerprints, each
    /// classified with the embedded fallback DB and, when a threatmodels
    /// checkout sits next to this repo, with its lanscan-profiles-db.json.
    #[derive(Deserialize)]
    struct CorpusDevice {
        name: String,
        #[allow(dead_code)]
        source: String,
        vendor: String,
        open_ports: Vec<u16>,
        mdns_services: Vec<String>,
        hostname: String,
        banners: Vec<String>,
        expected_type: String,
    }

    #[derive(Deserialize)]
    struct Corpus {
        devices: Vec<CorpusDevice>,
    }

    fn load_corpus() -> Corpus {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/device_type_corpus.json");
        let data = std::fs::read_to_string(&path).expect("read device type corpus");
        serde_json::from_str(&data).expect("parse device type corpus")
    }

    /// Returns the mismatch lines for one profile DB.
    fn classify_corpus(label: &str, profiles: &[DeviceTypeRule], corpus: &Corpus) -> Vec<String> {
        let mut mismatches = Vec::new();
        for device in &corpus.devices {
            let actual = classify_device(
                profiles,
                &device.open_ports,
                &device.mdns_services,
                &device.vendor,
                &device.hostname,
                &device.banners,
            );
            if actual != device.expected_type {
                mismatches.push(format!(
                    "  [{}] {:<48} expected {:<14} got {}",
                    label, device.name, device.expected_type, actual
                ));
            }
        }
        println!(
            "device type corpus [{}]: {}/{} correct",
            label,
            corpus.devices.len() - mismatches.len(),
            corpus.devices.len()
        );
        for line in &mismatches {
            println!("{}", line);
        }
        mismatches
    }

    #[test]
    fn device_type_corpus_classifies_every_known_device() {
        let corpus = load_corpus();
        assert!(corpus.devices.len() >= 50, "corpus unexpectedly small");

        let embedded: DeviceTypeListJSON =
            serde_json::from_str(&DEVICE_PROFILES).expect("embedded profiles parse");
        let mut mismatches = classify_corpus("embedded", &embedded.profiles, &corpus);

        let local = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../threatmodels/lanscan-profiles-db.json");
        if let Ok(data) = std::fs::read_to_string(&local) {
            let list: DeviceTypeListJSON =
                serde_json::from_str(&data).expect("threatmodels lanscan-profiles-db.json parses");
            mismatches.extend(classify_corpus("threatmodels", &list.profiles, &corpus));
        } else {
            println!("device type corpus: ../threatmodels not found, embedded DB only");
        }

        assert!(
            mismatches.is_empty(),
            "{} device type corpus mismatches:\n{}",
            mismatches.len(),
            mismatches.join("\n")
        );
    }

    // Modify the signature to zeros, perform an update, and check the signature changes
    #[tokio::test]
    #[serial]
    async fn test_signature_update_after_modification() {
        setup();
        let branch = "main";

        // Acquire a write lock to modify the signature
        {
            PROFILES
                .set_signature("00000000000000000000000000000000".to_string())
                .await;
        }

        // Perform the update
        let status = update(branch, false).await.expect("Update failed");

        // Check that the update was performed
        assert!(
            matches!(status, UpdateStatus::Updated | UpdateStatus::SkippedCustom),
            "Expected the update to be performed or skipped due to custom data"
        );

        // Check that the signature is no longer zeros
        let current_signature = PROFILES.get_signature().await;
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
        let branch = "nonexistent-branch";

        // Get the current signature
        let original_signature = PROFILES.get_signature().await;

        // Attempt to perform an update from a nonexistent branch
        let result = update(branch, false).await;

        // The update should fail
        assert!(result.is_err(), "Update should have failed");

        // Check that the signature has not changed
        let current_signature = PROFILES.get_signature().await;
        assert_eq!(
            current_signature, original_signature,
            "Signature should not have changed after failed update"
        );
    }
}
