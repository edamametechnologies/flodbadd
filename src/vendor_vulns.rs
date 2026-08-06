use crate::vendor_vulns_db::*;
use crate::vulnerability_info::*;
use anyhow::{Context, Result};
use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use threatmodels_rs::*;
use tracing::{info, warn};
use undeadlock::*;

const VENDOR_VULNS_NAME: &str = "lanscan-vendor-vulns-db.json";

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct VulnerabilityVendorInfo {
    pub vendor: String,
    pub vulnerabilities: Vec<VulnerabilityInfo>,
    pub count: u32,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct VulnerabilityVendorInfoListJSON {
    pub date: String,
    pub signature: String,
    pub vulnerabilities: Vec<VulnerabilityVendorInfo>,
}

#[derive(Clone)]
pub struct VulnerabilityInfoList {
    pub date: String,
    pub signature: String,
    pub vendor_vulns: Arc<HashMap<String, VulnerabilityVendorInfo>>,
}

impl CloudSignature for VulnerabilityInfoList {
    fn get_signature(&self) -> String {
        self.signature.clone()
    }
    fn set_signature(&mut self, signature: String) {
        self.signature = signature;
    }
}

impl VulnerabilityInfoList {
    pub fn new_from_json(vuln_info: &VulnerabilityVendorInfoListJSON) -> Self {
        info!("Loading vendor info list from JSON");

        let mut vendor_vulns: HashMap<String, VulnerabilityVendorInfo> = HashMap::new();
        let mut vendor_vec: Vec<String> = Vec::new();

        for vendor_info in &vuln_info.vulnerabilities {
            vendor_vulns.insert(vendor_info.vendor.clone(), vendor_info.clone());
            vendor_vec.push(vendor_info.vendor.clone());
        }

        vendor_vec.sort();

        // We don't try to update the cache here because this is called from a non-async context
        // The cache will be populated on first access instead

        for vendor_info in &vuln_info.vulnerabilities {
            let mut vulns_sorted = vendor_info.vulnerabilities.clone();
            vulns_sorted.sort_by(|a, b| b.name.cmp(&a.name));

            VULN_LISTS_CACHE.insert(vendor_info.vendor.clone(), Arc::new(vulns_sorted.clone()));

            let vuln_names: Vec<String> = vulns_sorted.iter().map(|v| v.name.clone()).collect();
            VULN_NAME_LISTS_CACHE.insert(vendor_info.vendor.clone(), Arc::new(vuln_names));
        }

        info!("Loaded {} vendors", vendor_vulns.len());

        VulnerabilityInfoList {
            date: vuln_info.date.clone(),
            signature: vuln_info.signature.clone(),
            vendor_vulns: Arc::new(vendor_vulns),
        }
    }
}

lazy_static! {
    pub static ref VULNS: CloudModel<VulnerabilityInfoList> = {
        let model = CloudModel::initialize(VENDOR_VULNS_NAME.to_string(), &VENDOR_VULNS, |data| {
            let vuln_info_json: VulnerabilityVendorInfoListJSON =
                serde_json::from_str(data).with_context(|| "Failed to parse JSON data")?;
            Ok(VulnerabilityInfoList::new_from_json(&vuln_info_json))
        });
        match model {
            Ok(m) => m,
            Err(e) => {
                eprintln!("FATAL: Failed to initialize CloudModel for vendor vulns: {:?}", e);
                panic!("Failed to initialize CloudModel for vendor vulns: {:?}", e);
            }
        }
    };

    // Cache for vendor list (we only need one since it's cleared on update)
    static ref VENDOR_LIST_CACHE: Arc<CustomRwLock<Vec<String>>> = Arc::new(CustomRwLock::new(Vec::new()));

    // Cache for vulnerabilities by vendor
    static ref VULN_LISTS_CACHE: CustomDashMap<String, Arc<Vec<VulnerabilityInfo>>> = CustomDashMap::new("vendor_vulnerability_lists_cache");

    // Cache for vulnerability names by vendor
    static ref VULN_NAME_LISTS_CACHE: CustomDashMap<String, Arc<Vec<String>>> = CustomDashMap::new("vendor_vulnerability_names_cache");
}

// Clear all caches
async fn clear_caches() {
    // No try_write, we just execute the actual clear operation
    // in an async context where we can properly await
    let mut vendor_list = VENDOR_LIST_CACHE.write().await;
    vendor_list.clear();
    drop(vendor_list); // Explicitly release the lock

    VULN_LISTS_CACHE.clear();
    VULN_NAME_LISTS_CACHE.clear();
}

pub async fn get_vendors() -> Vec<String> {
    // Try to get from cache first
    {
        let cached = VENDOR_LIST_CACHE.read().await;
        if !cached.is_empty() {
            return cached.clone();
        }
    } // Release the read lock

    // If not in cache, regenerate and cache it
    let vendors_map = VULNS.data.read().await.vendor_vulns.clone();
    let mut vendor_vec: Vec<String> = vendors_map.keys().cloned().collect();

    vendor_vec.sort();

    // Update the cache
    {
        let mut vendor_list = VENDOR_LIST_CACHE.write().await;
        *vendor_list = vendor_vec.clone();
    } // Release the write lock

    vendor_vec
}

pub async fn get_description_from_vendor(vendor: &str) -> String {
    let vendors_map = VULNS.data.read().await.vendor_vulns.clone();
    vendors_map
        .get(vendor)
        .map_or_else(|| "".to_string(), |v| v.vendor.clone())
}

/// Walk one level up a vendor name for the fallback lookup: drop the last
/// whitespace-separated token, then any punctuation that split left dangling.
///
/// The second step is what makes comma-separated legal suffixes resolve.
/// `"Apple, Inc."` splits to `"Apple,"`, which matches no key in the database
/// even though `"Apple"` is present with 70 vulnerabilities; same for
/// `"Sonos, Inc."` -> `"Sonos"`. Names whose suffix carries no comma
/// (`"HP Inc."` -> `"HP"`) were unaffected, which is why the bug stayed
/// invisible for the vendors that happened to be spelled that way.
///
/// Always returns a strictly shorter string than its input, so callers can
/// loop on it until empty without risking a non-terminating walk.
fn parent_vendor_name(vendor: &str) -> String {
    match vendor.rfind(' ') {
        Some(pos) => vendor[..pos]
            .trim_end_matches(|c: char| matches!(c, ',' | '.' | ';' | ':'))
            .trim_end()
            .to_string(),
        None => String::new(),
    }
}

pub async fn get_vulns_of_vendor(vendor: &str) -> Vec<VulnerabilityInfo> {
    let mut vendor_name = vendor.to_string();
    while !vendor_name.is_empty() {
        // Check cache first
        if let Some(cached_vulns) = VULN_LISTS_CACHE.get(&vendor_name) {
            return cached_vulns.as_ref().clone();
        }

        // If not in cache, check if we have this vendor in our data
        let vendors_map = VULNS.data.read().await.vendor_vulns.clone();
        if let Some(vendor_data) = vendors_map.get(&vendor_name) {
            let mut vulns_sorted = vendor_data.vulnerabilities.clone();
            vulns_sorted.sort_by(|a, b| b.name.cmp(&a.name));

            let arc_vulns = Arc::new(vulns_sorted.clone());
            VULN_LISTS_CACHE.insert(vendor_name, arc_vulns);

            return vulns_sorted;
        }

        vendor_name = parent_vendor_name(&vendor_name);
    }
    Vec::new()
}

pub async fn get_vulns_names_of_vendor(vendor: &str) -> Vec<String> {
    let mut vendor_name = vendor.to_string();
    while !vendor_name.is_empty() {
        // Check cache first
        if let Some(cached_names) = VULN_NAME_LISTS_CACHE.get(&vendor_name) {
            return cached_names.as_ref().clone();
        }

        // If not in cache, check if we have this vendor in our data
        let vendors_map = VULNS.data.read().await.vendor_vulns.clone();
        if let Some(vendor_data) = vendors_map.get(&vendor_name) {
            let mut vulns_sorted = vendor_data.vulnerabilities.clone();
            vulns_sorted.sort_by(|a, b| b.name.cmp(&a.name));

            let vuln_names: Vec<String> = vulns_sorted.iter().map(|v| v.name.clone()).collect();

            let arc_names = Arc::new(vuln_names.clone());
            VULN_NAME_LISTS_CACHE.insert(vendor_name, arc_names);

            return vuln_names;
        }

        vendor_name = parent_vendor_name(&vendor_name);
    }
    Vec::new()
}

pub async fn update(branch: &str, force: bool) -> Result<UpdateStatus> {
    info!("Starting vendor vulns update from backend");

    let status = VULNS
        .update(branch, force, |data| {
            let vuln_info_json: VulnerabilityVendorInfoListJSON = serde_json::from_str(data)?;
            Ok(VulnerabilityInfoList::new_from_json(&vuln_info_json))
        })
        .await?;

    // Clear caches on update
    clear_caches().await;

    match status {
        UpdateStatus::Updated => info!("Vendor vulns were successfully updated."),
        UpdateStatus::NotUpdated => info!("Vendor vulns are already up to date."),
        UpdateStatus::FormatError => warn!("There was a format error in the vendor vulns data."),
        UpdateStatus::SkippedCustom => {
            info!("Update skipped because custom vendor vulns are in use.")
        }
    }

    Ok(status)
}

// Tests
#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    /// Regression guard (helper/app/posture startup): the embedded vendor-vulns
    /// snapshot MUST decode and parse. If a bad regen makes it unparseable, the
    /// `VULNS` CloudModel `lazy_static` panics on its first deref and the daemon
    /// dies at startup. This catches it in CI instead. See also
    /// whitelists/blacklists/sensitive_paths/port_vulns/profiles.
    #[test]
    fn test_embedded_vendor_vulns_snapshot_parses() {
        serde_json::from_str::<VulnerabilityVendorInfoListJSON>(&VENDOR_VULNS)
            .expect("embedded vendor vulns snapshot must parse as VulnerabilityVendorInfoListJSON");
    }

    // Initialize logging or other necessary setup here
    fn setup() {
        // Setup code here if needed
    }

    #[test]
    fn test_parent_vendor_name_drops_dangling_punctuation() {
        // The regression this guards: dropping the last token off a
        // comma-separated legal suffix leaves the comma behind, and
        // "Apple," matches no key even though "Apple" does.
        assert_eq!(parent_vendor_name("Apple, Inc."), "Apple");
        assert_eq!(parent_vendor_name("Sonos, Inc."), "Sonos");
        // Suffixes with no comma were always fine; keep them that way.
        assert_eq!(parent_vendor_name("HP Inc."), "HP");
        assert_eq!(
            parent_vendor_name("Raspberry Pi Foundation"),
            "Raspberry Pi"
        );
        // Repeated separators must not leave trailing whitespace behind.
        assert_eq!(parent_vendor_name("Apple  Inc."), "Apple");
        assert_eq!(
            parent_vendor_name("Philips Lighting BV"),
            "Philips Lighting"
        );
    }

    #[test]
    fn test_parent_vendor_name_always_shortens() {
        // Callers loop until empty, so every step must strictly shorten or the
        // walk never terminates.
        for input in [
            "Apple, Inc.",
            "Samsung Electronics Co.,Ltd",
            "Withings",
            ", Inc.",
            " x",
            "Apple ",
            "",
        ] {
            let parent = parent_vendor_name(input);
            assert!(
                parent.len() < input.len() || input.is_empty(),
                "{input:?} -> {parent:?} did not shorten"
            );
        }
        // And the walk itself terminates from every fleet-observed shape.
        for input in [
            "Apple, Inc.",
            "Guangdong Hongqin Telecom Technology Co.,Ltd.",
        ] {
            let mut name = input.to_string();
            let mut steps = 0;
            while !name.is_empty() {
                name = parent_vendor_name(&name);
                steps += 1;
                assert!(steps < 32, "walk from {input:?} did not terminate");
            }
        }
    }

    #[tokio::test]
    #[serial]
    async fn test_comma_suffixed_vendor_resolves_to_parent() {
        setup();
        clear_caches().await;

        // "Apple, Inc." is what the OUI database actually reports for every
        // Apple device on a LAN, and it used to resolve to zero
        // vulnerabilities while the bare "Apple" key carries 70.
        let bare = get_vulns_of_vendor("Apple").await;
        assert!(
            !bare.is_empty(),
            "the embedded snapshot must carry an 'Apple' key for this test to mean anything"
        );

        clear_caches().await;
        let suffixed = get_vulns_of_vendor("Apple, Inc.").await;
        assert_eq!(
            suffixed.len(),
            bare.len(),
            "'Apple, Inc.' must resolve to the same vulnerabilities as 'Apple'"
        );

        clear_caches().await;
        let names = get_vulns_names_of_vendor("Apple, Inc.").await;
        assert_eq!(
            names.len(),
            bare.len(),
            "the names variant must fall back identically"
        );
    }

    #[tokio::test]
    #[serial]
    async fn test_get_vendors() {
        setup();
        clear_caches().await;
        let vendors = get_vendors().await;
        assert!(!vendors.is_empty(), "Vendors list should not be empty");
    }

    #[tokio::test]
    #[serial]
    async fn test_get_vulns_of_vendor() {
        setup();
        clear_caches().await;
        let vendor = "6Wind";
        let vulns = get_vulns_of_vendor(vendor).await;
        assert!(
            !vulns.is_empty(),
            "Vulnerabilities for the vendor should not be empty"
        );
    }

    #[tokio::test]
    #[serial]
    async fn test_update_vendor_vulns() {
        setup();
        clear_caches().await;
        let branch = "main";
        let status = update(branch, false).await.expect("Update failed");
        assert!(
            matches!(status, UpdateStatus::Updated | UpdateStatus::NotUpdated),
            "Update status should be either Updated or NotUpdated"
        );
    }

    #[tokio::test]
    #[serial]
    async fn test_signature_update_after_modification() {
        setup();
        clear_caches().await;
        let branch = "main";

        // Acquire a write lock to modify the signature
        {
            VULNS
                .set_signature("00000000000000000000000000000000".to_string())
                .await;
            // Clear caches when signature changes
            clear_caches().await;
        }

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
        let vendors1 = get_vendors().await;
        let vendor = if !vendors1.is_empty() {
            vendors1[0].clone()
        } else {
            "6Wind".to_string()
        };

        // Get vulnerabilities and names
        let vulns1 = get_vulns_of_vendor(&vendor).await;
        let names1 = get_vulns_names_of_vendor(&vendor).await;

        // Second call should use cache
        let vendors2 = get_vendors().await;
        let vulns2 = get_vulns_of_vendor(&vendor).await;
        let names2 = get_vulns_names_of_vendor(&vendor).await;

        // Verify results are the same
        assert_eq!(vendors1, vendors2, "Cached vendors should match");
        assert_eq!(vulns1, vulns2, "Cached vulnerabilities should match");
        assert_eq!(names1, names2, "Cached vulnerability names should match");
    }
}
