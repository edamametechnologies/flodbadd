// SNI (Server Name Indication) Extraction Module
//
// This module extracts the server hostname from TLS ClientHello messages.
// SNI is part of the TLS handshake and provides the actual hostname the client
// is trying to connect to - even when DNS over HTTPS is used.
//
// TLS Record Format:
//   - Content Type: 0x16 (Handshake)
//   - Version: 2 bytes (0x0301 = TLS 1.0, etc.)
//   - Length: 2 bytes
//   - Handshake data
//
// ClientHello (Handshake Type 0x01):
//   - Type: 1 byte (0x01)
//   - Length: 3 bytes
//   - Client Version: 2 bytes
//   - Random: 32 bytes
//   - Session ID: variable
//   - Cipher Suites: variable
//   - Compression Methods: variable
//   - Extensions: variable (SNI is extension type 0x0000)

use tracing::{debug, trace};

/// Result of SNI extraction
#[derive(Debug, Clone)]
pub struct SniInfo {
    /// The server hostname from SNI extension
    pub hostname: String,
}

/// Minimum size for a valid TLS ClientHello with SNI
const MIN_TLS_CLIENT_HELLO_SIZE: usize = 43; // Record header (5) + handshake type (1) + length (3) + version (2) + random (32)

/// TLS record content types
const TLS_CONTENT_TYPE_HANDSHAKE: u8 = 0x16;

/// TLS handshake types
const TLS_HANDSHAKE_CLIENT_HELLO: u8 = 0x01;

/// TLS extension types
const TLS_EXT_SERVER_NAME: u16 = 0x0000;

/// SNI name type for hostname
const SNI_NAME_TYPE_HOSTNAME: u8 = 0x00;

/// Extract SNI hostname from a TCP payload that might be a TLS ClientHello.
///
/// Returns Some(SniInfo) if valid SNI found, None otherwise.
/// This function is designed to be fast and safe - it returns None early
/// for non-TLS traffic rather than doing extensive parsing.
pub fn extract_sni(payload: &[u8]) -> Option<SniInfo> {
    // Quick rejection for non-TLS traffic
    if payload.len() < MIN_TLS_CLIENT_HELLO_SIZE {
        return None;
    }

    // Check TLS record header
    let content_type = payload[0];
    if content_type != TLS_CONTENT_TYPE_HANDSHAKE {
        return None;
    }

    // TLS version (we accept TLS 1.0 - 1.3 in record layer)
    // 0x0301 = TLS 1.0, 0x0302 = TLS 1.1, 0x0303 = TLS 1.2/1.3
    let version_major = payload[1];
    let version_minor = payload[2];
    if version_major != 0x03 || version_minor > 0x04 {
        return None;
    }

    // Record length
    let record_length = u16::from_be_bytes([payload[3], payload[4]]) as usize;
    if payload.len() < 5 + record_length {
        trace!(
            "TLS record truncated: have {}, need {}",
            payload.len(),
            5 + record_length
        );
        return None;
    }

    // Handshake layer starts at offset 5
    let handshake = &payload[5..5 + record_length];
    if handshake.is_empty() {
        return None;
    }

    // Check handshake type
    let handshake_type = handshake[0];
    if handshake_type != TLS_HANDSHAKE_CLIENT_HELLO {
        return None;
    }

    // Handshake length (3 bytes, big-endian)
    if handshake.len() < 4 {
        return None;
    }
    let handshake_length =
        ((handshake[1] as usize) << 16) | ((handshake[2] as usize) << 8) | (handshake[3] as usize);

    if handshake.len() < 4 + handshake_length {
        trace!("ClientHello truncated");
        return None;
    }

    // Parse ClientHello body
    let client_hello = &handshake[4..4 + handshake_length];
    parse_client_hello(client_hello)
}

/// Parse ClientHello body to extract SNI
fn parse_client_hello(data: &[u8]) -> Option<SniInfo> {
    let mut offset = 0;

    // Client version (2 bytes) - skip
    if data.len() < offset + 2 {
        return None;
    }
    offset += 2;

    // Random (32 bytes) - skip
    if data.len() < offset + 32 {
        return None;
    }
    offset += 32;

    // Session ID (1 byte length + variable)
    if data.len() < offset + 1 {
        return None;
    }
    let session_id_len = data[offset] as usize;
    offset += 1;
    if data.len() < offset + session_id_len {
        return None;
    }
    offset += session_id_len;

    // Cipher Suites (2 bytes length + variable)
    if data.len() < offset + 2 {
        return None;
    }
    let cipher_suites_len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
    offset += 2;
    if data.len() < offset + cipher_suites_len {
        return None;
    }
    offset += cipher_suites_len;

    // Compression Methods (1 byte length + variable)
    if data.len() < offset + 1 {
        return None;
    }
    let compression_len = data[offset] as usize;
    offset += 1;
    if data.len() < offset + compression_len {
        return None;
    }
    offset += compression_len;

    // Extensions (2 bytes length + variable)
    if data.len() < offset + 2 {
        // No extensions - no SNI
        return None;
    }
    let extensions_len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
    offset += 2;

    if data.len() < offset + extensions_len {
        trace!("Extensions truncated");
        return None;
    }

    // Parse extensions to find SNI
    let extensions = &data[offset..offset + extensions_len];
    parse_extensions(extensions)
}

/// Parse TLS extensions to find SNI
fn parse_extensions(data: &[u8]) -> Option<SniInfo> {
    let mut offset = 0;

    while offset + 4 <= data.len() {
        // Extension type (2 bytes)
        let ext_type = u16::from_be_bytes([data[offset], data[offset + 1]]);
        offset += 2;

        // Extension length (2 bytes)
        let ext_len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
        offset += 2;

        if data.len() < offset + ext_len {
            trace!("Extension {} truncated", ext_type);
            break;
        }

        // Check for SNI extension
        if ext_type == TLS_EXT_SERVER_NAME {
            let ext_data = &data[offset..offset + ext_len];
            if let Some(hostname) = parse_sni_extension(ext_data) {
                debug!("Extracted SNI: {}", hostname);
                return Some(SniInfo { hostname });
            }
        }

        offset += ext_len;
    }

    None
}

/// Parse SNI extension data to extract hostname
fn parse_sni_extension(data: &[u8]) -> Option<String> {
    if data.len() < 2 {
        return None;
    }

    // Server Name List length (2 bytes)
    let list_len = u16::from_be_bytes([data[0], data[1]]) as usize;
    if data.len() < 2 + list_len {
        return None;
    }

    let mut offset = 2;

    // Parse Server Name entries
    while offset + 3 <= 2 + list_len {
        // Name Type (1 byte)
        let name_type = data[offset];
        offset += 1;

        // Name Length (2 bytes)
        let name_len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
        offset += 2;

        if data.len() < offset + name_len {
            break;
        }

        // Check for hostname type
        if name_type == SNI_NAME_TYPE_HOSTNAME {
            let hostname_bytes = &data[offset..offset + name_len];
            // Convert to string - hostname should be ASCII
            if let Ok(hostname) = std::str::from_utf8(hostname_bytes) {
                // Validate it looks like a hostname
                if is_valid_hostname(hostname) {
                    return Some(hostname.to_lowercase());
                }
            }
        }

        offset += name_len;
    }

    None
}

/// Basic hostname validation
fn is_valid_hostname(hostname: &str) -> bool {
    if hostname.is_empty() || hostname.len() > 253 {
        return false;
    }

    // Must contain at least one dot (not just a TLD)
    if !hostname.contains('.') {
        return false;
    }

    // Basic character validation
    hostname
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_')
}

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
    fn test_is_valid_hostname() {
        assert!(is_valid_hostname("example.com"));
        assert!(is_valid_hostname("sub.example.com"));
        assert!(is_valid_hostname("api.github.com"));
        assert!(is_valid_hostname("my-site.example.org"));

        assert!(!is_valid_hostname(""));
        assert!(!is_valid_hostname("localhost")); // No dot
        assert!(!is_valid_hostname("example")); // No dot
    }

    #[test]
    fn test_is_reverse_dns_pattern() {
        // Should detect as reverse DNS
        assert!(is_reverse_dns_pattern("cdn-185-199-111-133.github.com"));
        assert!(is_reverse_dns_pattern(
            "51.241.186.35.bc.googleusercontent.com"
        ));
        assert!(is_reverse_dns_pattern(
            "ec2-54-171-230-55.eu-west-1.compute.amazonaws.com"
        ));
        assert!(is_reverse_dns_pattern("lb-140-82-112-24-iad.github.com"));
        assert!(is_reverse_dns_pattern("1.2.3.4.in-addr.arpa"));
        assert!(is_reverse_dns_pattern(
            "159.240.178.107.bc.googleusercontent.com"
        ));

        // Should NOT detect as reverse DNS (these are legitimate forward DNS)
        assert!(!is_reverse_dns_pattern("api.github.com"));
        assert!(!is_reverse_dns_pattern("github.com"));
        assert!(!is_reverse_dns_pattern("api.mixpanel.com"));
        assert!(!is_reverse_dns_pattern(
            "edamame.s3.eu-west-1.amazonaws.com"
        ));
        assert!(!is_reverse_dns_pattern("registry.npmjs.org"));
        assert!(!is_reverse_dns_pattern("backend-score-prod.edamame.tech"));
        assert!(!is_reverse_dns_pattern("s3-eu-west-1-r-w.amazonaws.com"));
    }

    #[test]
    fn test_extract_sni_basic() {
        // A minimal TLS ClientHello with SNI for "example.com"
        // This is a real-ish packet structure (simplified)
        let packet = build_test_client_hello("example.com");
        let result = extract_sni(&packet);
        assert!(result.is_some());
        assert_eq!(result.unwrap().hostname, "example.com");
    }

    #[test]
    fn test_extract_sni_non_tls() {
        // HTTP GET request - should return None
        let http_data = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        assert!(extract_sni(http_data).is_none());

        // Random data
        let random_data = [0u8; 100];
        assert!(extract_sni(&random_data).is_none());

        // Too short
        let short_data = [0x16, 0x03, 0x01];
        assert!(extract_sni(&short_data).is_none());
    }

    /// Build a minimal TLS ClientHello with SNI for testing
    fn build_test_client_hello(hostname: &str) -> Vec<u8> {
        let hostname_bytes = hostname.as_bytes();
        let hostname_len = hostname_bytes.len();

        // SNI extension
        let mut sni_ext = Vec::new();
        // Extension type (SNI = 0x0000)
        sni_ext.extend_from_slice(&[0x00, 0x00]);
        // Extension length
        let sni_data_len = 2 + 1 + 2 + hostname_len; // list_len + type + name_len + name
        sni_ext.extend_from_slice(&(sni_data_len as u16).to_be_bytes());
        // Server name list length
        sni_ext.extend_from_slice(&((sni_data_len - 2) as u16).to_be_bytes());
        // Name type (hostname = 0)
        sni_ext.push(0x00);
        // Name length
        sni_ext.extend_from_slice(&(hostname_len as u16).to_be_bytes());
        // Hostname
        sni_ext.extend_from_slice(hostname_bytes);

        // Extensions total
        let extensions_len = sni_ext.len();

        // Build ClientHello body
        let mut client_hello = Vec::new();
        // Client version (TLS 1.2)
        client_hello.extend_from_slice(&[0x03, 0x03]);
        // Random (32 bytes)
        client_hello.extend_from_slice(&[0u8; 32]);
        // Session ID (empty)
        client_hello.push(0x00);
        // Cipher Suites (2 bytes for length + 2 bytes for one suite)
        client_hello.extend_from_slice(&[0x00, 0x02, 0x00, 0x2f]); // TLS_RSA_WITH_AES_128_CBC_SHA
                                                                   // Compression Methods (1 byte for length + 1 byte for null compression)
        client_hello.extend_from_slice(&[0x01, 0x00]);
        // Extensions
        client_hello.extend_from_slice(&(extensions_len as u16).to_be_bytes());
        client_hello.extend_from_slice(&sni_ext);

        // Build Handshake
        let mut handshake = Vec::new();
        // Handshake type (ClientHello)
        handshake.push(0x01);
        // Length (3 bytes)
        let ch_len = client_hello.len();
        handshake.push((ch_len >> 16) as u8);
        handshake.push((ch_len >> 8) as u8);
        handshake.push(ch_len as u8);
        handshake.extend_from_slice(&client_hello);

        // Build TLS Record
        let mut record = Vec::new();
        // Content type (Handshake)
        record.push(0x16);
        // Version (TLS 1.0 for record layer)
        record.extend_from_slice(&[0x03, 0x01]);
        // Length
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);

        record
    }
}
