use crate::asn_db::{Db, Record};
use crate::asn_v4_db::*;
use crate::asn_v6_db::*;
use lazy_static::lazy_static;
use std::io::BufReader;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use tracing::warn;
use undeadlock::*;

// ASN databases are embedded for offline operation
// Future versions may support cloud updates from:
// - IPv4: https://iptoasn.com/data/ip2asn-v4.tsv.gz
// - IPv6: https://iptoasn.com/data/ip2asn-v6.tsv.gz

lazy_static! {
    static ref ASN_V4: Arc<Db> = {
        let asn_v4 = Db::from_tsv(BufReader::new(ASN_V4_DB.as_bytes())).unwrap();
        Arc::new(asn_v4)
    };
    static ref ASN_V6: Arc<Db> = {
        let asn_v6 = Db::from_tsv(BufReader::new(ASN_V6_DB.as_bytes())).unwrap();
        Arc::new(asn_v6)
    };

    // Global cache for IP ASN lookups.
    // The key is the IpAddr and the value is the (possibly missing) Record.
    static ref ASN_CACHE: CustomDashMap<IpAddr, Option<Record>> = CustomDashMap::new("asn_cache");
}

/// Most addresses the lookup cache holds. A miss costs one binary search of
/// the embedded databases, so the cache is emptied when full rather than
/// ordered for eviction; it used to grow with every address ever seen.
const ASN_CACHE_MAX_ENTRIES: usize = 20_000;

/// IANA special-purpose IPv4 blocks no AS announces: (network, prefix
/// length). Protocol constants (the RFC 6890 registry, multicast and the
/// reserved block), not detection data.
const NO_ASN_V4: &[([u8; 4], u8)] = &[
    ([0, 0, 0, 0], 8),      // "this network" (RFC 791)
    ([10, 0, 0, 0], 8),     // private (RFC 1918)
    ([100, 64, 0, 0], 10),  // shared address space, carrier-grade NAT (RFC 6598)
    ([127, 0, 0, 0], 8),    // loopback
    ([169, 254, 0, 0], 16), // link-local (RFC 3927)
    ([172, 16, 0, 0], 12),  // private
    // IETF protocol assignments: the DS-Lite / 464XLAT CLAT block
    // 192.0.0.0/29 (RFC 7335), NAT64 discovery 192.0.0.170-171 (RFC 7050).
    ([192, 0, 0, 0], 24),
    ([192, 0, 2, 0], 24),    // TEST-NET-1 (RFC 5737)
    ([192, 88, 99, 0], 24),  // 6to4 relay anycast, deprecated (RFC 7526)
    ([192, 168, 0, 0], 16),  // private
    ([198, 18, 0, 0], 15),   // benchmarking (RFC 2544)
    ([198, 51, 100, 0], 24), // TEST-NET-2
    ([203, 0, 113, 0], 24),  // TEST-NET-3
    ([224, 0, 0, 0], 4),     // multicast
    ([240, 0, 0, 0], 4),     // reserved, limited broadcast included
];

/// IANA special-purpose IPv6 blocks no AS announces. 2001::/23 is not listed
/// whole: AS112 (2001:4:112::/48) and AMT (2001:3::/32) are announced.
const NO_ASN_V6: &[([u16; 8], u8)] = &[
    ([0, 0, 0, 0, 0, 0, 0, 0], 128), // unspecified
    ([0, 0, 0, 0, 0, 0, 0, 1], 128), // loopback
    // Local-use translation (RFC 8215): where the IPv4 address sits in it is
    // the operator's choice, so it cannot be read back.
    ([0x64, 0xff9b, 1, 0, 0, 0, 0, 0], 48),
    ([0x100, 0, 0, 0, 0, 0, 0, 0], 64),  // discard-only (RFC 6666)
    ([0x2001, 0, 0, 0, 0, 0, 0, 0], 32), // Teredo (RFC 4380)
    ([0x2001, 2, 0, 0, 0, 0, 0, 0], 48), // benchmarking (RFC 5180)
    ([0x2001, 0xdb8, 0, 0, 0, 0, 0, 0], 32), // documentation (RFC 3849)
    ([0x3fff, 0, 0, 0, 0, 0, 0, 0], 20), // documentation (RFC 9637)
    ([0x5f00, 0, 0, 0, 0, 0, 0, 0], 16), // SRv6 SIDs (RFC 9602)
    ([0xfc00, 0, 0, 0, 0, 0, 0, 0], 7),  // unique local (RFC 4193)
    ([0xfe80, 0, 0, 0, 0, 0, 0, 0], 10), // link-local
    ([0xfec0, 0, 0, 0, 0, 0, 0, 0], 10), // site-local, deprecated (RFC 3879)
    ([0xff00, 0, 0, 0, 0, 0, 0, 0], 8),  // multicast
];

/// The NAT64 well-known prefix 64:ff9b::/96 (RFC 6052): the IPv4 address is
/// the last 32 bits.
const NAT64_WELL_KNOWN_PREFIX: [u16; 6] = [0x64, 0xff9b, 0, 0, 0, 0];

/// Where an address's ASN comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AsnSource {
    /// This address, searched in the embedded databases.
    Lookup(IpAddr),
    /// None: a special-purpose address no AS announces.
    SpecialPurpose,
}

fn in_v4_block(ip: Ipv4Addr, (network, prefix_len): ([u8; 4], u8)) -> bool {
    let mask = u32::MAX
        .checked_shl(32 - u32::from(prefix_len))
        .unwrap_or(0);
    u32::from(ip) & mask == u32::from_be_bytes(network) & mask
}

fn in_v6_block(ip: Ipv6Addr, (network, prefix_len): ([u16; 8], u8)) -> bool {
    let mask = u128::MAX
        .checked_shl(128 - u32::from(prefix_len))
        .unwrap_or(0);
    u128::from(ip) & mask == u128::from(Ipv6Addr::from(network)) & mask
}

/// The IPv4 address an IPv6 address stands for: a NAT64 address under the
/// well-known prefix, or an IPv4-mapped address (::ffff:0:0/96).
fn embedded_ipv4(ip: Ipv6Addr) -> Option<Ipv4Addr> {
    if ip.segments()[..6] == NAT64_WELL_KNOWN_PREFIX {
        // The low 32 bits are the IPv4 address.
        return Some(Ipv4Addr::from(u128::from(ip) as u32));
    }
    ip.to_ipv4_mapped()
}

fn asn_source(ip: IpAddr) -> AsnSource {
    match ip {
        IpAddr::V4(ipv4) => {
            if NO_ASN_V4.iter().any(|block| in_v4_block(ipv4, *block)) {
                AsnSource::SpecialPurpose
            } else {
                AsnSource::Lookup(ip)
            }
        }
        IpAddr::V6(ipv6) => {
            if let Some(ipv4) = embedded_ipv4(ipv6) {
                return asn_source(IpAddr::V4(ipv4));
            }
            if NO_ASN_V6.iter().any(|block| in_v6_block(ipv6, *block)) {
                AsnSource::SpecialPurpose
            } else {
                AsnSource::Lookup(ip)
            }
        }
    }
}

// Private helper that performs the direct database lookup (without caching).
async fn lookup_asn_no_cache(ip: IpAddr) -> Option<Record> {
    match ip {
        IpAddr::V4(ipv4) => match ASN_V4.lookup(IpAddr::V4(ipv4)) {
            Some(record) => Some(record),
            None => {
                warn!("Failed to lookup IPv4 address: {}", ipv4);
                None
            }
        },
        IpAddr::V6(ipv6) => match ASN_V6.lookup(IpAddr::V6(ipv6)) {
            Some(record) => Some(record),
            None => {
                warn!("Failed to lookup IPv6 address: {}", ipv6);
                None
            }
        },
    }
}

/// Cached lookup for an IP address ASN record.
///
/// A special-purpose address (private, CGNAT, CLAT, documentation,
/// link-local, multicast, ...) has no ASN: `None` at once, nothing searched,
/// nothing cached, no failure logged. A NAT64 address under 64:ff9b::/96 is
/// looked up by the IPv4 address it embeds. Otherwise this checks the global
/// cache, and if the IP hasn't been seen before, it performs a lookup against
/// the underlying database and stores the result in the cache.
#[inline(always)]
pub async fn get_asn(ip: IpAddr) -> Option<Record> {
    let lookup_ip = match asn_source(ip) {
        AsnSource::SpecialPurpose => return None,
        AsnSource::Lookup(lookup_ip) => lookup_ip,
    };
    if let Some(entry) = ASN_CACHE.get(&ip) {
        return entry.value().clone();
    }
    let result = lookup_asn_no_cache(lookup_ip).await;
    if ASN_CACHE.len() >= ASN_CACHE_MAX_ENTRIES {
        ASN_CACHE.clear();
    }
    ASN_CACHE.insert(ip, result.clone());
    result
}

/// IPv4 lookup using the cached `get_asn` implementation.
pub async fn get_ipv4_asn(ipv4: &Ipv4Addr) -> Option<Record> {
    get_asn(IpAddr::V4(*ipv4)).await
}

/// IPv6 lookup using the cached `get_asn` implementation.
pub async fn get_ipv6_asn(ipv6: &Ipv6Addr) -> Option<Record> {
    get_asn(IpAddr::V6(*ipv6)).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    #[tokio::test]
    #[serial]
    async fn test_get_ipv4_asn() {
        // Use a known good IPv4 address (non local):
        // 217.147.96.0	217.147.111.255	174	US	COGENT-174
        ASN_CACHE.clear();

        let ipv4 = Ipv4Addr::new(217, 147, 96, 0);
        let asn = get_ipv4_asn(&ipv4).await;
        assert!(asn.is_some());
        let asn = asn.unwrap();
        assert_eq!(asn.as_number, 174);
        assert_eq!(asn.country, "US");
        assert_eq!(asn.owner, "COGENT-174");
    }

    #[tokio::test]
    #[serial]
    async fn test_get_ipv6_asn() {
        // Use a known good IPv6 address (non local):
        // 2001:200::
        // 2001:200:5ff:ffff:ffff:ffff:ffff:ffff	2500	JP	WIDE-BB WIDE Project
        ASN_CACHE.clear();

        let ipv6 = Ipv6Addr::new(0x2001, 0x200, 0, 0, 0, 0, 0, 1);
        let asn = get_ipv6_asn(&ipv6).await;
        assert!(asn.is_some());
        let asn = asn.unwrap();
        assert_eq!(asn.as_number, 2500);
        assert_eq!(asn.country, "JP");
        assert_eq!(asn.owner, "WIDE-BB WIDE Project");
    }

    #[tokio::test]
    #[serial]
    async fn test_get_asn_caching_ipv4() {
        // Clear the cache to isolate this test.
        ASN_CACHE.clear();

        let ip = IpAddr::V4(Ipv4Addr::new(217, 147, 96, 0)); // known valid IPv4
                                                             // First lookup should populate the cache.
        let record_first = get_asn(ip).await;
        assert!(record_first.is_some());
        assert!(
            ASN_CACHE.contains_key(&ip),
            "Cache should contain the key after lookup"
        );

        // Second lookup should fetch the value from the cache.
        let record_second = get_asn(ip).await;
        assert_eq!(
            record_first, record_second,
            "Repeated lookup should return the same result"
        );

        // Cache should only have one entry.
        assert_eq!(ASN_CACHE.len(), 1, "Cache should only contain one entry");
    }

    #[tokio::test]
    #[serial]
    async fn test_get_asn_caching_ipv6() {
        // Clear the cache to isolate this test.
        ASN_CACHE.clear();

        let ip = IpAddr::V6(Ipv6Addr::new(0x2001, 0x200, 0, 0, 0, 0, 0, 1)); // known valid IPv6
        let record_first = get_asn(ip).await;
        assert!(record_first.is_some());
        assert!(ASN_CACHE.contains_key(&ip));

        let record_second = get_asn(ip).await;
        assert_eq!(record_first, record_second);
        assert_eq!(ASN_CACHE.len(), 1, "Cache should only contain one entry");
    }

    #[tokio::test]
    #[serial]
    async fn test_get_asn_not_found() {
        // Clear the cache to isolate this test.
        ASN_CACHE.clear();

        // A global address the DB marks "Not routed" (1.0.1.0 - 1.0.3.255).
        // 0.0.0.0, used before, is special-purpose: never searched or cached.
        let ip = IpAddr::V4(Ipv4Addr::new(1, 0, 1, 1));
        let result_first = get_asn(ip).await;
        // Expect None since the lookup should fail.
        assert!(result_first.is_none());
        // The failed lookup should still be cached.
        assert!(ASN_CACHE.contains_key(&ip));

        let result_second = get_asn(ip).await;
        assert!(result_second.is_none());
        // Ensure the cache only contains a single entry for this key.
        assert_eq!(ASN_CACHE.len(), 1, "Cache should only contain one entry");
    }

    #[tokio::test]
    #[serial]
    async fn test_get_ipv4_asn_notion() {
        ASN_CACHE.clear();
        // 208.103.161.1 belongs to AS33191 NOTION
        let ipv4 = Ipv4Addr::new(208, 103, 161, 1);
        let asn = get_ipv4_asn(&ipv4).await;
        assert!(asn.is_some(), "208.103.161.1 should resolve to NOTION");
        let asn = asn.unwrap();
        assert_eq!(asn.as_number, 33191);
        assert_eq!(asn.country, "US");
        assert_eq!(asn.owner, "NOTION");
    }

    /// A NAT64 address (an iPhone hotspot's 64:ff9b::/96) has the ASN of the
    /// IPv4 address it embeds; fmba-3 logged 69 failed lookups of such
    /// addresses in 6 minutes on 2026-10-11. An IPv4-mapped address likewise.
    #[tokio::test]
    #[serial]
    async fn nat64_address_is_looked_up_by_its_embedded_ipv4() {
        ASN_CACHE.clear();
        // 64:ff9b::217.147.96.0 -> COGENT-174
        let nat64: Ipv6Addr = "64:ff9b::d993:6000".parse().unwrap();
        let asn = get_ipv6_asn(&nat64)
            .await
            .expect("the embedded IPv4 address's ASN");
        assert_eq!(asn.as_number, 174);
        assert_eq!(asn.owner, "COGENT-174");
        // 64:ff9b::208.103.161.1 -> NOTION
        let nat64: Ipv6Addr = "64:ff9b::d067:a101".parse().unwrap();
        assert_eq!(get_ipv6_asn(&nat64).await.map(|r| r.as_number), Some(33191));
        let mapped: Ipv6Addr = "::ffff:217.147.96.0".parse().unwrap();
        assert_eq!(get_ipv6_asn(&mapped).await.map(|r| r.as_number), Some(174));
    }

    /// Special-purpose addresses the dogfood hosts failed to look up (CGNAT,
    /// the 464XLAT CLAT address, TEST-NET-1, NAT64 forms of them) and their
    /// siblings: no ASN, nothing searched or cached, no failure logged.
    #[tokio::test]
    #[serial]
    async fn special_purpose_addresses_have_no_asn_and_log_no_failure() {
        ASN_CACHE.clear();
        let (_guard, logged) = crate::test_logs::capture("Failed to lookup");
        for address in [
            "100.121.200.228", // CGNAT (Tailscale)
            "100.64.0.1",
            "100.127.255.255",
            "192.0.0.2",   // 464XLAT CLAT
            "192.0.0.170", // NAT64 prefix discovery (ipv4only.arpa)
            "192.0.2.42",  // TEST-NET-1
            "198.51.100.7",
            "203.0.113.9",
            "198.19.255.255",
            "192.88.99.1",
            "10.1.2.3",
            "172.31.0.1",
            "169.254.1.1",
            "224.0.0.251",
            "240.0.0.1",
            "255.255.255.255",
            "0.0.0.0",
            "64:ff9b::c000:2",  // NAT64 form of the CLAT address
            "64:ff9b::a01:203", // NAT64 form of 10.1.2.3
            "64:ff9b:1::a00:1", // local-use translation prefix
            "::ffff:192.0.2.1",
            "2001:db8::1",
            "3fff::1",
            "2001::1", // Teredo
            "100::1",
            "5f00::1",
            "fe80::1",
            "fd00::1",
            "fec0::1",
            "ff02::fb",
            "::1",
            "::",
        ] {
            let ip: IpAddr = address.parse().unwrap();
            assert_eq!(asn_source(ip), AsnSource::SpecialPurpose, "{address}");
            assert_eq!(get_asn(ip).await, None, "{address}");
            assert!(!ASN_CACHE.contains_key(&ip), "{address} was cached");
        }
        assert_eq!(logged.warn_or_error(), 0, "no lookup failure logged");
    }

    /// The blocks stop where the registry's do: neighbours are looked up, and
    /// so are the announced parts of 2001::/23.
    #[test]
    fn addresses_next_to_the_special_purpose_blocks_are_looked_up() {
        for address in [
            "100.63.255.255",
            "100.128.0.0",
            "192.0.1.1",
            "192.0.3.1",
            "198.17.255.255",
            "198.20.0.0",
            "223.255.255.255",
            "8.8.8.8",
            "2001:4:112::1", // AS112
            "2001:3::1",     // AMT
            "2001:200::1",
            "64:ff9b:2::1",
            "2a01:e0a:127d:7600::1",
        ] {
            let ip: IpAddr = address.parse().unwrap();
            assert_eq!(asn_source(ip), AsnSource::Lookup(ip), "{address}");
        }
        let nat64: IpAddr = "64:ff9b::808:808".parse().unwrap();
        assert_eq!(
            asn_source(nat64),
            AsnSource::Lookup(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)))
        );
    }

    /// The cache never holds more than ASN_CACHE_MAX_ENTRIES addresses (it
    /// used to keep every address it was ever asked about).
    #[tokio::test]
    #[serial]
    async fn asn_cache_is_bounded() {
        ASN_CACHE.clear();
        // 4.0.0.0 - 4.19.11.255 is one LEVEL3 block: every address resolves.
        let base = u32::from(Ipv4Addr::new(4, 0, 0, 0));
        for offset in 0..(ASN_CACHE_MAX_ENTRIES as u32 + 1_000) {
            let ip = IpAddr::V4(Ipv4Addr::from(base + offset));
            assert_eq!(get_asn(ip).await.map(|r| r.as_number), Some(3356));
            assert!(
                ASN_CACHE.len() <= ASN_CACHE_MAX_ENTRIES,
                "cache at {} entries",
                ASN_CACHE.len()
            );
        }
        ASN_CACHE.clear();
    }

    #[tokio::test]
    #[serial]
    async fn test_concurrent_lookups() {
        // Clear the cache to isolate this test.
        ASN_CACHE.clear();

        let ip = IpAddr::V4(Ipv4Addr::new(217, 147, 96, 0));
        // Spawn several concurrent tasks performing the lookup.
        let tasks: Vec<_> = (0..10)
            .map(|_| {
                let ip = ip.clone();
                tokio::spawn(async move { get_asn(ip).await })
            })
            .collect();

        // Await all the tasks.
        let results = futures::future::join_all(tasks).await;
        for task_result in results {
            let lookup_result = task_result.unwrap();
            assert!(lookup_result.is_some());
            let record = lookup_result.unwrap();
            assert_eq!(record.as_number, 174);
        }

        // The cache should contain only one entry for this IP.
        assert_eq!(
            ASN_CACHE.len(),
            1,
            "Cache should only contain one entry for the IP"
        );
    }
}
