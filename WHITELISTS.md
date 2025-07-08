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
    pub domain: Option<String>,      // Domain name (supports wildcards: *.example.com)
    pub ip: Option<String>,          // IP address or CIDR range
    pub port: Option<u16>,           // Port number (None = any port)
    pub protocol: Option<String>,    // Protocol (TCP, UDP, ICMP, etc.)
    pub as_number: Option<u32>,      // Autonomous System number
    pub as_country: Option<String>,  // Country code for the AS (case-insensitive)
    pub as_owner: Option<String>,    // AS owner/organization name (case-insensitive)
    pub process: Option<String>,     // Process name (case-insensitive)
    pub description: Option<String>, // Human-readable description for documentation
}
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

## Advanced Matching Algorithm

### Multi-Criteria Matching Priority

The whitelist system follows a precise matching order for optimal performance and security:

```rust
pub fn endpoint_matches_with_reason(
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
    // 1. Fundamental criteria must match first
    if !port_matches(port, endpoint.port) {
        return (false, Some(format!("Port mismatch: {} vs {:?}", port, endpoint.port)));
    }
    
    if !protocol_matches(protocol, &endpoint.protocol) {
        return (false, Some(format!("Protocol mismatch: {} vs {:?}", protocol, endpoint.protocol)));
    }
    
    if !process_matches(process, &endpoint.process) {
        return (false, Some(format!("Process mismatch: {:?} vs {:?}", process, endpoint.process)));
    }
    
    // 2. Entity identification (domain has priority over IP)
    let domain_specified = endpoint.domain.is_some();
    let ip_specified = endpoint.ip.is_some();
    
    if domain_specified {
        if domain_matches(session_domain, &endpoint.domain) {
            return check_as_criteria(as_number, as_country, as_owner, endpoint);
        } else if !ip_specified {
            return (false, Some("Domain mismatch and no IP fallback".to_string()));
        }
    }
    
    if ip_specified {
        if ip_matches(session_ip, &endpoint.ip) {
            return check_as_criteria(as_number, as_country, as_owner, endpoint);
        } else if domain_specified {
            return (false, Some("Both domain and IP mismatch".to_string()));
        }
    }
    
    // 3. If neither domain nor IP specified, only AS/process matching
    if !domain_specified && !ip_specified {
        return check_as_criteria(as_number, as_country, as_owner, endpoint);
    }
    
    (false, Some("No matching criteria found".to_string()))
}
```

## Session-based Whitelist Generation

### Automatic Whitelist Creation from Traffic

The system can generate whitelists automatically from observed network sessions:

```rust
impl Whitelists {
    pub fn new_from_sessions(sessions: &Vec<SessionInfo>) -> Self {
        let mut endpoints = Vec::new();
        
        for session in sessions {
            // Extract endpoint information from session
            let endpoint = WhitelistEndpoint {
                domain: session.dst_domain.clone(),
                ip: Some(session.session.dst_ip.to_string()),
                port: Some(session.session.dst_port),
                protocol: Some(session.session.protocol.to_string()),
                as_number: session.dst_asn.as_ref().map(|asn| asn.as_number),
                as_country: session.dst_asn.as_ref().map(|asn| asn.country.clone()),
                as_owner: session.dst_asn.as_ref().map(|asn| asn.owner.clone()),
                process: session.l7.as_ref().map(|l7| l7.process_name.clone()),
                description: Some(format!("Auto-generated from session to {}", session.session.dst_ip)),
            };
            endpoints.push(endpoint);
        }
        
        // Deduplicate endpoints based on fingerprint
        let mut unique_fingerprints = HashSet::new();
        endpoints.retain(|ep| {
            let fingerprint = (
                ep.domain.clone(), ep.ip.clone(), ep.port,
                ep.protocol.clone(), ep.as_number, ep.as_country.clone(),
                ep.as_owner.clone(), ep.process.clone()
            );
            unique_fingerprints.insert(fingerprint)
        });
        
        // Create whitelist structure
        Self::create_custom_whitelist(endpoints)
    }
}
```

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
               domain.endsWith(suffix) &&
               domain.len() > prefix.len() + suffix.len();
    }
    
    false
}
```

### CIDR and IP Range Matching

Comprehensive IP address and CIDR range matching:

```rust
fn ip_matches(session_ip: Option<&str>, endpoint_ip: &Option<String>) -> bool {
    let (Some(session_ip), Some(endpoint_ip)) = (session_ip, endpoint_ip.as_ref()) else {
        return false;
    };
    
    // Parse session IP
    let session_addr: IpAddr = match session_ip.parse() {
        Ok(addr) => addr,
        Err(_) => return false,
    };
    
    if endpoint_ip.contains('/') {
        // CIDR notation
        match endpoint_ip.parse::<IpNet>() {
            Ok(network) => network.contains(&session_addr),
            Err(_) => false,
        }
    } else {
        // Exact IP match
        match endpoint_ip.parse::<IpAddr>() {
            Ok(endpoint_addr) => session_addr == endpoint_addr,
            Err(_) => false,
        }
    }
}
```

## Integration with Session Analysis

### Real-time Whitelist Evaluation

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
    
    // Evaluate all sessions against the current whitelist
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