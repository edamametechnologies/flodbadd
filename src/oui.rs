use crate::oui_db::*;
use lazy_static::lazy_static;
use macaddr::MacAddr6;
use oui::OuiDatabase;
use std::sync::Arc;
use tracing::{error, warn};
use undeadlock::CustomDashMap;
use undeadlock::CustomRwLock;

// TODO load from the cloud regularly and store locally
// const OUI_DB_URL: &str = "https://www.wireshark.org/download/automated/data/manuf";

lazy_static! {
    static ref OUI: Arc<CustomRwLock<OuiDatabase>> = {
        let oui = OuiDatabase::new_from_str(OUI_DB).unwrap();
        Arc::new(CustomRwLock::new(oui))
    };

    static ref VENDOR_CACHE: CustomDashMap<String, String> = CustomDashMap::new("vendor_cache");

    /// OUI prefix cache keyed by the first 3 bytes of the MAC address.
    /// Many devices on a LAN share the same vendor prefix (e.g. Apple, Intel),
    /// so this avoids the OUI crate's linear scan for repeat-vendor lookups.
    static ref PREFIX_CACHE: CustomDashMap<[u8; 3], String> = CustomDashMap::new("oui_prefix_cache");
}

pub async fn get_mac_address_vendor(mac_address: &MacAddr6) -> String {
    let mac_str = mac_address.to_string();

    if let Some(vendor_entry) = VENDOR_CACHE.get(&mac_str) {
        return vendor_entry.value().clone();
    }

    let octets = mac_address.as_bytes();
    let prefix: [u8; 3] = [octets[0], octets[1], octets[2]];

    if let Some(vendor_entry) = PREFIX_CACHE.get(&prefix) {
        let vendor = vendor_entry.value().clone();
        VENDOR_CACHE.insert(mac_str, vendor.clone());
        return vendor;
    }

    let oui = OUI.read().await;

    let vendor = match oui.query_by_str(&mac_str) {
        Ok(Some(res)) => {
            if let Some(name_long) = res.name_long {
                name_long
            } else if !res.name_short.is_empty() {
                res.name_short
            } else {
                warn!("No vendor name found for MAC address: {}", mac_str);
                "".to_string()
            }
        }
        Ok(None) => {
            warn!("No vendor found for MAC address: {}", mac_str);
            "".to_string()
        }
        Err(err) => {
            error!(
                "Failed to query the vendor database for MAC address: {} - {}",
                mac_str, err
            );
            "".to_string()
        }
    };

    PREFIX_CACHE.insert(prefix, vendor.clone());
    VENDOR_CACHE.insert(mac_str, vendor.clone());

    vendor
}
