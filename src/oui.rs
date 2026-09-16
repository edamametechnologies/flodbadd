use crate::oui_db::*;
use lazy_static::lazy_static;
use macaddr::MacAddr6;
use std::collections::HashMap;
use undeadlock::CustomDashMap;

// TODO load from the cloud regularly and store locally

/// The Wireshark `manuf` prefix lengths actually present in the embedded
/// database, longest first. A MAC is probed against each in turn so a
/// 36-bit MA-S assignment wins over the 24-bit OUI that contains it.
const PREFIX_BITS: [u8; 3] = [36, 28, 24];

/// Vendor lookup over the embedded Wireshark `manuf` table.
///
/// Replaces the `oui` crate, which was last published in 2021, pulls
/// `failure` (RUSTSEC type-confusion advisories GHSA-jq66-xh47-j9f3 and
/// GHSA-r98r-j25q-rmpr), and answered each query with a linear scan of all
/// 48k entries. Lookups here are three hash probes and the table borrows its
/// names straight out of `OUI_DB`, so it copies nothing at startup.
struct OuiTable {
    /// `(prefix length in bits, MAC masked to that length)` -> vendor name.
    entries: HashMap<(u8, u64), &'static str>,
}

fn mac_to_u48(octets: &[u8; 6]) -> u64 {
    octets
        .iter()
        .fold(0u64, |acc, b| (acc << 8) | u64::from(*b))
}

fn mask_for(bits: u8) -> u64 {
    // 48-bit address space; `bits` is always one of PREFIX_BITS.
    (!0u64 << (48 - bits)) & 0xFFFF_FFFF_FFFF
}

/// `00:1B:C5` or `00:1B:C5:00:00:00/36` -> (bits, masked value).
fn parse_prefix(spec: &str) -> Option<(u8, u64)> {
    let (addr, bits) = match spec.split_once('/') {
        Some((addr, len)) => (addr, len.trim().parse::<u8>().ok()?),
        None => (spec, 0),
    };
    let mut octets = [0u8; 6];
    let mut seen = 0usize;
    for part in addr.split(':') {
        if seen >= 6 {
            return None;
        }
        octets[seen] = u8::from_str_radix(part.trim(), 16).ok()?;
        seen += 1;
    }
    if seen == 0 {
        return None;
    }
    // An unsuffixed prefix is as long as the octets it spells out.
    let bits = if bits == 0 {
        u8::try_from(seen * 8).ok()?
    } else {
        bits
    };
    if bits == 0 || bits > 48 {
        return None;
    }
    Some((bits, mac_to_u48(&octets) & mask_for(bits)))
}

impl OuiTable {
    fn parse(db: &'static str) -> Self {
        let mut entries = HashMap::new();
        for line in db.lines() {
            let line = line.trim_end();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let mut fields = line.split('\t').filter(|f| !f.is_empty());
            let Some(spec) = fields.next() else {
                continue;
            };
            let Some(key) = parse_prefix(spec.trim()) else {
                continue;
            };
            let name_short = fields.next().unwrap_or("").trim();
            let name_long = fields.next().unwrap_or("").trim();
            // The long name is the descriptive one ("Xerox Corporation");
            // fall back to the short one ("Xerox") when the row has none.
            let name = if !name_long.is_empty() {
                name_long
            } else {
                name_short
            };
            if name.is_empty() {
                continue;
            }
            // First row wins, matching the manuf file's own precedence.
            entries.entry(key).or_insert(name);
        }
        Self { entries }
    }

    fn lookup(&self, octets: &[u8; 6]) -> Option<&'static str> {
        let mac = mac_to_u48(octets);
        PREFIX_BITS
            .iter()
            .find_map(|bits| self.entries.get(&(*bits, mac & mask_for(*bits))).copied())
    }
}

lazy_static! {
    static ref OUI: OuiTable = OuiTable::parse(OUI_DB);

    /// Keyed on the full address. The previous implementation also kept a
    /// cache keyed on the first three octets, which answered every MAC
    /// sharing an OUI with whatever vendor the first one resolved to -- wrong
    /// for the 14.7k MA-M/MA-S assignments that subdivide an OUI at 28 or 36
    /// bits. A three-probe lookup does not need that cache.
    static ref VENDOR_CACHE: CustomDashMap<String, String> = CustomDashMap::new("vendor_cache");
}

pub async fn get_mac_address_vendor(mac_address: &MacAddr6) -> String {
    let mac_str = mac_address.to_string();

    if let Some(vendor_entry) = VENDOR_CACHE.get(&mac_str) {
        return vendor_entry.value().clone();
    }

    let vendor = OUI
        .lookup(&mac_address.into_array())
        .unwrap_or_default()
        .to_string();

    VENDOR_CACHE.insert(mac_str, vendor.clone());
    vendor
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    async fn vendor(mac: &str) -> String {
        get_mac_address_vendor(&MacAddr6::from_str(mac).unwrap()).await
    }

    #[test]
    fn prefix_specs_parse_to_masked_keys() {
        assert_eq!(parse_prefix("00:00:01"), Some((24, 0x00_00_01_00_00_00)));
        // The suffix, not the octet count, sets the length.
        assert_eq!(
            parse_prefix("8C:1F:64:00:00:00/36"),
            Some((36, 0x8C_1F_64_00_00_00))
        );
        // Low bits outside the prefix are masked away.
        assert_eq!(
            parse_prefix("8C:1F:64:FF:FF:FF/28"),
            Some((28, 0x8C_1F_64_F0_00_00))
        );
        assert_eq!(parse_prefix(""), None);
        assert_eq!(parse_prefix("not-a-mac"), None);
        assert_eq!(parse_prefix("00:00:01/99"), None);
    }

    #[test]
    fn the_embedded_table_parses_every_prefix_length() {
        let table = OuiTable::parse(OUI_DB);
        assert!(
            table.entries.len() > 40_000,
            "parsed only {} entries",
            table.entries.len()
        );
        for bits in PREFIX_BITS {
            assert!(
                table.entries.keys().any(|(b, _)| *b == bits),
                "no /{bits} prefixes parsed"
            );
        }
    }

    #[tokio::test]
    async fn known_vendors_resolve() {
        assert_eq!(vendor("00:00:01:02:03:04").await, "Xerox Corporation");
        // Apple, a plain 24-bit OUI.
        assert!(vendor("00:1B:63:00:00:01").await.contains("Apple"));
        // Unassigned space resolves to empty rather than to a wrong vendor.
        assert_eq!(vendor("02:00:00:00:00:01").await, "");
    }

    #[tokio::test]
    async fn a_longer_assignment_beats_the_oui_that_contains_it() {
        let table = OuiTable::parse(OUI_DB);
        // Find a 36-bit assignment whose parent 24-bit OUI resolves
        // differently, and prove the specific one wins.
        let sample = table
            .entries
            .iter()
            .filter(|((bits, _), _)| *bits == 36)
            .find_map(|((_, masked), long_name)| {
                let parent = table.entries.get(&(24, masked & mask_for(24)))?;
                (parent != long_name).then_some((*masked, *long_name))
            })
            .expect("no 36-bit assignment differs from its parent OUI");
        let octets = sample.0.to_be_bytes();
        let mac = [
            octets[2], octets[3], octets[4], octets[5], octets[6], octets[7],
        ];
        assert_eq!(table.lookup(&mac), Some(sample.1));
    }
}
