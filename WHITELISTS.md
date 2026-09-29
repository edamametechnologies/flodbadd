# Flodbadd Whitelist System

## Overview

The Flodbadd whitelist system provides a flexible and powerful way to control network access through a hierarchical structure with clear matching priorities. This document explains how whitelists work, how to create them, and provides examples for common use cases.

## Whitelist Structure

### Basic Components

```rust
// Main whitelist container (from whitelists.rs)
pub struct Whitelists {
    pub date: String,                                    // Creation/update date
    pub signature: Option<String>,                       // Cryptographic signature for integrity
    pub whitelists: Arc<CustomDashMap<String, WhitelistInfo>>, // Named whitelist collection
}

// Individual whitelist definition
pub struct WhitelistInfo {
    pub name: String,                        // Unique identifier
    pub extends: Option<Vec<String>>,        // Parent whitelists to inherit from
    pub endpoints: Vec<WhitelistEndpoint>,   // List of allowed endpoints
}

// Network endpoint specification with comprehensive matching criteria
pub struct WhitelistEndpoint {
    pub domain: Option<String>,       // Single domain (wildcards supported)
    pub domains: Option<Vec<String>>, // List of domains (wildcards supported)
    pub ip: Option<String>,           // Single IP or CIDR
    pub port: Option<u16>,            // Single port
    pub protocol: Option<String>,     // Protocol (TCP, UDP, ICMP, etc.)
    pub as_number: Option<u32>,       // Autonomous System number
    pub as_country: Option<String>,   // Country code for the AS (case-insensitive)
    pub as_owner: Option<String>,     // AS owner/organization name (case-insensitive)
    pub process: Option<String>,      // Process name (case-insensitive)
    pub description: Option<String>,  // Human-readable description for documentation
    pub ports: Option<Vec<PortSpec>>, // List of ports and/or ranges
    pub ips: Option<Vec<String>>,     // List of IP specs (IP, CIDR, or explicit range "start-end")
    pub unresolved_only: Option<bool>, // Match only sessions whose destination has no name
}

// Port specification supports a single port or an inclusive range
#[serde(untagged)]
pub enum PortSpec { Single(u16), Range { start: u16, end: u16 } }
```

### JSON Serialization Format

The system uses a flattened JSON structure for persistence and interchange:

```rust
// JSON representation for serialization
pub struct WhitelistsJSON {
    pub date: String,
    pub signature: Option<String>,
    pub whitelists: Vec<WhitelistInfo>,  // Flattened array format
}
```

## Whitelist Building and Inheritance

### Basic Whitelist Setup

Whitelists are defined in JSON format and can be loaded at runtime or embedded as defaults:

```json
{
  "date": "2024-01-01",
  "signature": "cryptographic-signature-here",
  "whitelists": [
    {
      "name": "basic_services",
      "endpoints": [
        {
          "domain": "api.example.com", 
          "port": 443, 
          "protocol": "TCP",
          "description": "Example API server HTTPS"
        },
        {
          "ip": "192.168.1.0/24",
          "port": 22,
          "protocol": "TCP",
          "description": "Internal SSH access"
        }
      ]
    }
  ]
}
```

### Advanced Inheritance System

The inheritance system supports complex hierarchical structures with circular dependency detection:

```json
{
  "date": "2024-01-01",
  "whitelists": [
    {
      "name": "base_infrastructure",
      "endpoints": [
        { "domain": "dns.google.com", "port": 53, "protocol": "UDP", "description": "Google DNS" },
        { "domain": "time.nist.gov", "port": 123, "protocol": "UDP", "description": "NTP servers" }
      ]
    },
    {
      "name": "corporate_services", 
      "extends": ["base_infrastructure"],
      "endpoints": [
        { "domain": "*.corp.example.com", "port": 443, "protocol": "TCP", "description": "Corporate services" }
      ]
    },
    {
      "name": "development_environment",
      "extends": ["corporate_services"],
      "endpoints": [
        { "ip": "10.0.0.0/8", "description": "Development network access" },
        { "domain": "*.dev.example.com", "protocol": "TCP", "description": "Development services" }
      ]
    }
  ]
}
```

### Inheritance Resolution Algorithm

The system implements depth-first inheritance resolution with cycle detection:

```rust
fn get_all_endpoints(&self, whitelist_name: &str, visited: &mut HashSet<String>) -> Result<Vec<WhitelistEndpoint>> {
    if visited.contains(whitelist_name) {
        return Err(anyhow!("Circular dependency detected in whitelist inheritance"));
    }
    
    visited.insert(whitelist_name.to_string());
    
    let info = self.whitelists.get(whitelist_name)
        .ok_or_else(|| anyhow!("Whitelist not found: {}", whitelist_name))?;
    
    let mut endpoints = info.endpoints.clone();
    
    // Recursively collect from parent whitelists
    if let Some(extends) = &info.extends {
        for parent_name in extends {
            let parent_endpoints = self.get_all_endpoints(parent_name, visited)?;
            endpoints.extend(parent_endpoints);
        }
    }
    
    visited.remove(whitelist_name);
    Ok(endpoints)
}
```

## Matching

`endpoint_matches_with_reason` decides whether one session matches one
endpoint. A session conforms when it matches any endpoint of the whitelist
(with its `extends` chain); an undefined whitelist, or one without endpoints,
conforms nothing.

1. **Gates**: protocol, port (`port`/`ports`) and process must match when the
   endpoint sets them.
2. **Named or not**: a session's destination has an identifying name when it
   has a forward DNS answer or a TLS SNI name. The resolver's placeholders
   (`Unknown`, `Resolving`) and reverse-DNS names built from the address
   (`cdn-185-199-110-133.github.com`, see `dns_patterns::is_reverse_dns_pattern`)
   are not names (`is_identifying_domain`).
3. **Domain first**: an endpoint with `domain`/`domains` matches a named
   session only by name. Its `ip`/`ips` stand in only for sessions without a
   name.
4. **Addresses**: an endpoint with addresses and no domain matches by
   address, except a named destination on shared infrastructure (an AS owner
   that is a CDN or a cloud front end, `is_shared_infrastructure_owner`):
   many sites answer on those addresses, so only a domain entry identifies
   one of them.
5. **Networks**: an endpoint with neither domain nor address matches on its
   AS fields (`as_number`, `as_owner`, `as_country`).
6. **`unresolved_only: true`** restricts an endpoint to sessions without a
   name.

Evaluation covers egress sessions only (`is_egress_session`).

## Session-based Whitelist Generation

### Automatic Whitelist Creation from Traffic

`Whitelists::new_from_sessions` learns one entry per distinct destination,
the way matching reads it:

- a named destination becomes a domain entry; its address is kept as the
  stand-in for unnamed sessions, except on shared infrastructure, where an
  address identifies nothing and is not learned;
- an unnamed destination on shared infrastructure (a connection opened before
  the capture started, for instance) becomes an entry for its AS with
  `unresolved_only: true`;
- any other unnamed destination becomes an address entry.

`Whitelists::augment_with_sessions` learns on top of a given whitelist: the
sessions that do not conform to it become entries, the given entries are kept
as they are, and the result is factorized. It reports the entries that allow
something new.

`WhitelistsJSON::compare_whitelist` compares on what entries allow: domains
(or addresses and network for entries without a domain), ports, protocol and
process. A new address on a known domain, or a new description, is not a
change.

### Loading a custom whitelist

`set_custom_whitelists` checks the JSON first (`parse_custom_whitelists`):
it must parse (unknown fields are refused), define `custom_whitelist`, and
resolve every `extends` within the JSON. A JSON that fails the check is
refused and the whitelists in force stay. `FlodbaddCapture::set_whitelist`
with a name that is not defined still enforces it (every egress session is
non-conforming) and returns an error.

### Whitelist Merging and Composition

Support for merging multiple whitelist sources:

```rust
pub fn merge_custom_whitelists(json_a: &str, json_b: &str) -> Result<String> {
    let whitelist_a: WhitelistsJSON = serde_json::from_str(json_a)?;
    let whitelist_b: WhitelistsJSON = serde_json::from_str(json_b)?;
    
    // Combine whitelists with conflict resolution
    let mut combined_whitelists = whitelist_a.whitelists;
    
    for whitelist_b_info in whitelist_b.whitelists {
        if let Some(existing) = combined_whitelists.iter_mut()
            .find(|w| w.name == whitelist_b_info.name) {
            // Merge endpoints, avoiding duplicates
            merge_whitelist_endpoints(existing, &whitelist_b_info);
        } else {
            combined_whitelists.push(whitelist_b_info);
        }
    }
    
    let merged = WhitelistsJSON {
        date: chrono::Utc::now().format("%B %dth %Y").to_string(),
        signature: None, // Re-signing required after merge
        whitelists: combined_whitelists,
    };
    
    serde_json::to_string(&merged).map_err(Into::into)
}
```

## Pattern Matching Implementation

### Enhanced Domain Matching

The domain matching system supports sophisticated wildcard patterns:

```rust
fn domain_matches(session_domain: Option<&str>, endpoint_domain: &Option<String>) -> bool {
    let (Some(session_domain), Some(endpoint_domain)) = (session_domain, endpoint_domain.as_ref()) else {
        return false;
    };
    
    // Exact match
    if session_domain == endpoint_domain {
        return true;
    }
    
    // Wildcard patterns
    if endpoint_domain.contains('*') {
        return wildcard_match(session_domain, endpoint_domain);
    }
    
    false
}

fn wildcard_match(domain: &str, pattern: &str) -> bool {
    if pattern.starts_with("*.") {
        // Prefix wildcard: *.example.com
        let suffix = &pattern[2..];
        return domain != suffix && 
               domain.ends_with(suffix) && 
               domain.len() > suffix.len() + 1 &&
               domain.chars().nth(domain.len() - suffix.len() - 1) == Some('.');
    }
    
    if pattern.ends_with(".*") {
        // Suffix wildcard: example.*
        let prefix = &pattern[..pattern.len() - 2];
        return domain.starts_with(prefix) && 
               (domain.len() == prefix.len() || 
                domain.chars().nth(prefix.len()) == Some('.'));
    }
    
    if let Some(star_pos) = pattern.find('*') {
        // Middle wildcard: api.*.example.com
        let (prefix, suffix) = pattern.split_at(star_pos);
        let suffix = &suffix[1..]; // Remove the '*'
        return domain.starts_with(prefix) && 
                domain.ends_with(suffix) &&
               domain.len() > prefix.len() + suffix.len();
    }
    
    false
}
```

### CIDR, IP List and IP Range Matching

Comprehensive IP address and CIDR range matching:

```rust
fn ip_matches_any(session_ip: Option<&str>, endpoint_ip: &Option<String>, endpoint_ips: &Option<Vec<String>>) -> bool { /* see code */ }
```

## Integration with Session Analysis

### Real-time Whitelist Evaluation (Egress-only)

The system integrates tightly with the session analysis pipeline:

```rust
pub async fn recompute_whitelist_for_sessions(
    whitelist_name_arc: &Arc<CustomRwLock<String>>,
    sessions: &Arc<CustomDashMap<Session, SessionInfo>>,
    whitelist_exceptions: &Arc<CustomRwLock<Vec<Session>>>,
    whitelist_conformance: &Arc<AtomicBool>,
    last_exception_time: &Arc<CustomRwLock<DateTime<Utc>>>,
) {
    let whitelist_name = whitelist_name_arc.read().await.clone();
    
    if whitelist_name.is_empty() {
        return; // No whitelist configured
    }
    
    let mut new_exceptions = Vec::new();
    let mut conformance = true;
    
    // Evaluate only egress sessions (originating from self/local but not local-local) against the current whitelist
    for session_entry in sessions.iter() {
        let session_info = session_entry.value();
        
        // Skip if already marked as blacklisted (higher priority)
        if session_info.criticality.contains("blacklist:") {
            continue;
        }
        
        let (is_conforming, reason) = is_session_in_whitelist(
            session_info.dst_domain.as_deref(),
            Some(&session_info.session.dst_ip.to_string()),
            session_info.session.dst_port,
            &session_info.session.protocol.to_string(),
            &whitelist_name,
            session_info.dst_asn.as_ref().map(|asn| asn.as_number),
            session_info.dst_asn.as_ref().map(|asn| asn.country.as_str()),
            session_info.dst_asn.as_ref().map(|asn| asn.owner.as_str()),
            session_info.l7.as_ref().map(|l7| l7.process_name.as_str()),
        ).await;
        
        // Update session whitelist state
        let new_state = if is_conforming {
            WhitelistState::Conforming
        } else {
            WhitelistState::NonConforming
        };
        
        if let Some(mut entry) = sessions.get_mut(session_entry.key()) {
            let info = entry.value_mut();
            if info.is_whitelisted != new_state {
                info.is_whitelisted = new_state;
                info.whitelist_reason = reason;
                info.last_modified = Utc::now();
                
                if !is_conforming {
                    new_exceptions.push(session_entry.key().clone());
                    conformance = false;
                }
            }
        }
    }
    
    // Update global state atomically
    *whitelist_exceptions.write().await = new_exceptions;
    whitelist_conformance.store(conformance, Ordering::Relaxed);
    
    if !conformance {
        *last_exception_time.write().await = Utc::now();
    }
}
```

## Cloud Model Integration

### Dynamic Updates and Versioning

The whitelist system supports dynamic updates with cryptographic verification:

```rust
impl CloudSignature for Whitelists {
    fn get_signature(&self) -> String {
        self.signature.clone().unwrap_or_default()
    }
    
    fn set_signature(&mut self, signature: String) {
        self.signature = Some(signature);
    }
}

pub async fn update(branch: &str, force: bool) -> Result<UpdateStatus> {
    LISTS.update(branch, force, |data| {
        let whitelist_info_json: WhitelistsJSON = serde_json::from_str(data)
            .with_context(|| "Failed to parse JSON data")?;
        Ok(Whitelists::new_from_json(whitelist_info_json))
    }).await
}

pub async fn set_custom_whitelists(whitelist_json: &str) -> Result<(), anyhow::Error> {
    if whitelist_json.is_empty() {
        LISTS.reset_to_default().await;
        return Ok(());
    }
    
    let whitelist_result = serde_json::from_str::<WhitelistsJSON>(whitelist_json);
    
    match whitelist_result {
        Ok(whitelist_data) => {
            let whitelist = Whitelists::new_from_json(whitelist_data);
            LISTS.set_custom_data(whitelist).await;
            Ok(())
        }
        Err(e) => {
            LISTS.reset_to_default().await;
            Err(anyhow!("Error parsing custom whitelist JSON: {}", e))
        }
    }
}
```

## Usage Examples

### Capture Integration

```rust
use flodbadd::capture::FlodbaddCapture;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let capture = FlodbaddCapture::new();
    
    // Set a predefined whitelist
    capture.set_whitelist("corporate_standard").await?;
    
    // Or create a custom whitelist from current traffic
    let custom_whitelist = capture.create_custom_whitelists().await?;
    capture.set_custom_whitelists(&custom_whitelist).await;
    
    // Check conformance
    let is_conformant = capture.get_whitelist_conformance().await;
    if !is_conformant {
        let exceptions = capture.get_whitelist_exceptions(false).await;
        println!("Non-conforming sessions: {}", exceptions.len());
    }
    
    Ok(())
}
```

### Testing and Validation

```rust
#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_whitelist_inheritance() {
        let json = r#"{
            "date": "2024-01-01",
            "whitelists": [
                {
                    "name": "base",
                    "endpoints": [{"domain": "api.example.com", "port": 443, "protocol": "TCP"}]
                },
                {
                    "name": "extended",
                    "extends": ["base"],
                    "endpoints": [{"domain": "cdn.example.com", "port": 443, "protocol": "TCP"}]
                }
            ]
        }"#;
        
        let whitelists = Whitelists::new_from_json(serde_json::from_str(json).unwrap());
        let endpoints = whitelists.get_all_endpoints("extended", &mut HashSet::new()).unwrap();
        
        assert_eq!(endpoints.len(), 2);
        assert!(endpoints.iter().any(|e| e.domain == Some("api.example.com".to_string())));
        assert!(endpoints.iter().any(|e| e.domain == Some("cdn.example.com".to_string())));
    }
}
```

## Performance Considerations

### Caching and Optimization

- **Endpoint Resolution Caching**: Inheritance chains are cached to avoid repeated computation
- **Pattern Matching Optimization**: Common patterns are pre-compiled for faster matching
- **Concurrent Access**: CustomDashMap provides lock-free concurrent access for high-throughput scenarios

### Memory Management

- **Lazy Loading**: Only active whitelists are loaded into memory
- **Automatic Cleanup**: Unused whitelist caches are periodically cleaned
- **Incremental Updates**: Only modified sessions are re-evaluated during whitelist changes

## Security Considerations

### Cryptographic Verification

- **Signature Validation**: All distributed whitelists must be cryptographically signed
- **Integrity Checking**: JSON structure is validated against schema before loading
- **Version Control**: Whitelist updates include version tracking and rollback capability

### Privilege Separation

- **Read-only Operation**: Whitelist matching operates in read-only mode during evaluation
- **Atomic Updates**: Whitelist changes are applied atomically to prevent inconsistent states
- **Audit Logging**: All whitelist changes and violations are logged for security auditing

## Best Practices

### Design Guidelines

1. **Principle of Least Privilege**: Start with restrictive rules and add exceptions as needed
2. **Clear Documentation**: Always include meaningful descriptions for endpoints
3. **Hierarchical Structure**: Use inheritance to avoid duplication and maintain consistency
4. **Regular Auditing**: Periodically review and update whitelist rules
5. **Testing**: Validate whitelist changes in development environments before production

### Common Patterns

```json
{
  "name": "secure_corporate_whitelist",
  "extends": ["base_infrastructure"],
  "endpoints": [
    {
      "domain": "*.internal.corp.com",
      "protocol": "TCP",
      "description": "Internal corporate services"
    },
    {
      "as_number": 15169,
      "as_country": "US", 
      "protocol": "TCP",
      "port": 443,
      "description": "Google services (ASN-based)"
    },
    {
      "ip": "10.0.0.0/8",
      "description": "Internal network access"
    }
  ]
}
```

## Troubleshooting

### Common Issues

1. **Inheritance Loops**: Check for circular dependencies in extends chains
2. **Pattern Syntax**: Verify wildcard patterns follow supported formats
3. **Case Sensitivity**: Remember that protocols, countries, and owners are case-insensitive
4. **CIDR Notation**: Ensure IP ranges use valid CIDR format

### Debug Tools

```rust
// Enable detailed logging
RUST_LOG=flodbadd::whitelists=debug cargo run

// Test specific patterns
let result = domain_matches(Some("api.example.com"), &Some("*.example.com".to_string()));
println!("Match result: {}", result);
```

## API Reference

### Core Functions

- `is_session_in_whitelist()` - Main matching function
- `new_from_sessions()` - Generate whitelist from traffic
- `merge_custom_whitelists()` - Combine multiple whitelists
- `get_all_endpoints()` - Resolve inheritance chain

### Configuration

- `set_custom_whitelists()` - Load custom whitelist
- `reset_to_default()` - Revert to embedded defaults
- `update()` - Fetch updates from cloud source

---

*For more information, see the [Flodbadd README](README.md).*