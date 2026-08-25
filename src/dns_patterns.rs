//! DNS-name shape helpers.
//!
//! Pure string analysis over hostnames -- no packet capture, no resolver, no
//! platform dependency -- so this module is always compiled.
//!
//! [`is_reverse_dns_pattern`] previously lived in [`crate::sni`], which is gated
//! on `packetcapture` + desktop. `whitelists.rs` is NOT gated, so on every build
//! without `packetcapture` (which includes the default `edamame_core` build used
//! by the EDAMAME app -- core only turns it on via its `standalone` feature)
//! both call sites fell back to their `#[cfg(not(...))]` arms and failed OPEN:
//! the CDN reverse-DNS skip was disabled, and every reverse-DNS name was
//! accepted as a reliable whitelist domain. That let per-edge-IP names such as
//! `cdn-185-199-110-133.github.com` into generated whitelists, which then
//! mismatch the next time the CDN answers from a different edge IP.

/// Check if a domain name looks like reverse DNS (PTR record)
/// Examples of reverse DNS patterns:
/// - "cdn-185-199-111-133.github.com" (IP octets in subdomain)
/// - "51.241.186.35.bc.googleusercontent.com" (reversed IP octets)
/// - "ec2-54-171-230-55.eu-west-1.compute.amazonaws.com" (AWS pattern)
/// - "159.240.178.107.bc.googleusercontent.com" (Google Cloud pattern)
pub fn is_reverse_dns_pattern(domain: &str) -> bool {
    let domain_lower = domain.to_lowercase();

    // Pattern 1: IP octets at the start (e.g., "185.199.111.133.example.com")
    // or reversed (e.g., "133.111.199.185.in-addr.arpa")
    let parts: Vec<&str> = domain_lower.split('.').collect();
    if parts.len() >= 4 {
        // Check if first 4 parts are numbers (potential IP)
        let first_four_numeric = parts[0..4].iter().all(|p| p.parse::<u8>().is_ok());
        if first_four_numeric {
            return true;
        }
    }

    // Pattern 2: Subdomain contains IP pattern like "cdn-1-2-3-4" or "ec2-1-2-3-4"
    if let Some(subdomain) = parts.first() {
        // Check for patterns like "cdn-185-199-111-133" or "ec2-54-171-230-55"
        let subdomain_parts: Vec<&str> = subdomain.split('-').collect();
        if subdomain_parts.len() >= 4 {
            // Check if last 4 parts are numbers
            let last_four = &subdomain_parts[subdomain_parts.len().saturating_sub(4)..];
            let last_four_numeric = last_four.iter().all(|p| p.parse::<u8>().is_ok());
            if last_four_numeric {
                return true;
            }
        }
    }

    // Pattern 3: Known reverse DNS suffixes
    let reverse_dns_suffixes = [
        ".in-addr.arpa",
        ".ip6.arpa",
        ".bc.googleusercontent.com", // Google Cloud reverse DNS
    ];

    for suffix in reverse_dns_suffixes {
        if domain_lower.ends_with(suffix) {
            return true;
        }
    }

    // Pattern 4: AWS/Azure reverse patterns with "compute" or explicit IP format
    // e.g., "ec2-X-X-X-X.*.compute.amazonaws.com"
    if domain_lower.contains(".compute.") && domain_lower.contains("amazonaws.com") {
        return true;
    }

    // Pattern 5: Generic "lb-" or "cdn-" with IP-like patterns
    if let Some(subdomain) = parts.first() {
        if (subdomain.starts_with("lb-") || subdomain.starts_with("cdn-"))
            && subdomain.chars().filter(|&c| c == '-').count() >= 4
        {
            // Likely "lb-140-82-112-24-..." pattern
            return true;
        }
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_reverse_dns_patterns() {
        assert!(is_reverse_dns_pattern("cdn-185-199-111-133.github.com"));
        assert!(is_reverse_dns_pattern(
            "51.241.186.35.bc.googleusercontent.com"
        ));
        assert!(is_reverse_dns_pattern(
            "ec2-54-171-230-55.eu-west-1.compute.amazonaws.com"
        ));
        assert!(is_reverse_dns_pattern("lb-140-82-112-24-iad.github.com"));
        assert!(is_reverse_dns_pattern("1.2.3.4.in-addr.arpa"));
    }

    #[test]
    fn leaves_real_domains_alone() {
        assert!(!is_reverse_dns_pattern("api.github.com"));
        assert!(!is_reverse_dns_pattern("github.com"));
        assert!(!is_reverse_dns_pattern("registry.npmjs.org"));
        assert!(!is_reverse_dns_pattern("backend-score-prod.edamame.tech"));
        assert!(!is_reverse_dns_pattern("s3-eu-west-1-r-w.amazonaws.com"));
        assert!(!is_reverse_dns_pattern("gist.githubusercontent.com"));
    }
}
