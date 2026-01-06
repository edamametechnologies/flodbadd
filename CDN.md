# CDN Handling in Whitelist Generation

## Overview

Content Delivery Networks (CDNs) present a unique challenge for network whitelisting. CDN providers like Fastly, Cloudflare, Amazon CloudFront, and Akamai serve thousands of different domains from shared IP address pools. A single IP address may serve `malicious-site.com` one moment and `trusted-bank.com` the next.

This document explains how the whitelist generation system handles CDN traffic to balance security with operational compatibility across different deployment environments.

## The CDN Problem

### Shared IP Infrastructure

When you connect to `github.com`, your traffic may be served by Fastly's CDN infrastructure. The IP address you connect to (e.g., `185.199.111.133`) is shared across potentially thousands of other domains also served by Fastly.

If we whitelist this IP address without associating it with a specific domain, we inadvertently whitelist all traffic to any domain served by that CDN endpoint. This creates a significant security gap.

### Domain Resolution Methods

The system uses several methods to resolve which domain a network session is actually accessing:

| Method | Source | Reliability | Availability |
|--------|--------|-------------|--------------|
| Forward DNS | Captured DNS queries | High | Requires eBPF on Linux |
| SNI | TLS ClientHello | High | Available on all platforms |
| Reverse DNS | PTR record lookup | Variable | Available on all platforms |

**Forward DNS** captures the actual DNS query made by the application (e.g., "What is the IP for github.com?"). This provides the exact domain the user intended to access.

**SNI (Server Name Indication)** extracts the hostname from the TLS handshake. When a client connects to an HTTPS server, it sends the target hostname in the ClientHello message. This is reliable and platform-independent.

**Reverse DNS** performs a PTR lookup on the destination IP address. The response often reflects infrastructure naming rather than the requested domain. For example:
- Requested: `github.com`
- Reverse DNS result: `cdn-185-199-111-133.github.com` or `lb-140-82-112-21-iad.github.com`

## CDN Filtering Strategy

### Identified CDN Providers

The system maintains a list of known CDN/cloud provider keywords:

```
fastly, cloudflare, amazon, aws, google, microsoft, azure, akamai, cloudfront, cdn
```

Sessions are identified as CDN traffic when the destination ASN owner contains any of these keywords.

### Reverse DNS Pattern Detection

Reverse DNS responses from CDN infrastructure often follow predictable patterns that indicate infrastructure names rather than the actual requested domain:

| Pattern | Example | Description |
|---------|---------|-------------|
| IP octets in subdomain | `cdn-185-199-111-133.github.com` | CDN edge node identifier |
| Load balancer naming | `lb-140-82-112-21-iad.github.com` | Load balancer with datacenter code |
| Cloud compute patterns | `ec2-54-171-230-55.eu-west-1.compute.amazonaws.com` | AWS EC2 instance |
| Google Cloud patterns | `51.241.186.35.bc.googleusercontent.com` | GCP reverse DNS |
| Azure patterns | `productionresultssa1.blob.core.windows.net` | Azure storage |

These patterns are detected and flagged as unreliable for whitelisting purposes.

### Decision Matrix

The whitelist generation applies the following logic for each session:

| Domain Resolution | CDN Provider? | Reverse DNS Pattern? | Action |
|-------------------|---------------|---------------------|--------|
| Forward DNS | Yes/No | N/A | Include with domain |
| SNI | Yes/No | N/A | Include with domain |
| Reverse DNS | Yes | Yes | **Skip session** |
| Reverse DNS | Yes | No | Include with domain |
| Reverse DNS | No | Yes/No | Include with domain |
| Unresolved | Yes | N/A | Include IP-only |
| Unresolved | No | N/A | Include IP-only |

The key insight: **only CDN sessions with recognizable reverse DNS patterns are skipped**. All other sessions are included to ensure whitelist generation works across all deployment environments.

## Platform Considerations

### Linux with eBPF

On Linux systems with eBPF support, the system can:
- Capture forward DNS queries directly from the kernel
- Associate DNS responses with the processes that made the queries
- Provide highly accurate domain resolution for whitelist generation

This is the most precise configuration for CDN handling.

### Windows, macOS, and Containers

On platforms without eBPF support:
- Forward DNS capture is not available
- Domain resolution relies on reverse DNS lookups and SNI extraction
- Reverse DNS may fail entirely for some IPs, resulting in "Unknown" domains

To support these environments, sessions with unresolved domains to CDN providers are **included** with IP-only matching. While this is less precise than domain-based whitelisting, it ensures that whitelist generation remains functional.

### Security Trade-offs

| Environment | Precision | Coverage | Risk |
|-------------|-----------|----------|------|
| Linux + eBPF | High | High | Low |
| Any + SNI | High | Medium | Low |
| Non-eBPF, no SNI | Medium | High | Medium |

In non-eBPF environments, the system accepts slightly reduced precision to maintain operational functionality. The reverse DNS pattern filtering still provides protection against the most obvious infrastructure-based false positives.

## Examples

### Session: Forward DNS Resolution (eBPF)

```
Source: 192.168.1.100:54321
Destination: 185.199.111.133:443
Domain: github.com (Forward DNS)
ASN Owner: FASTLY
Resolution Type: Forward

Action: INCLUDE with domain "github.com"
Reason: Forward DNS provides reliable domain association
```

### Session: SNI Resolution

```
Source: 192.168.1.100:54322
Destination: 104.16.0.1:443
Domain: example.com (SNI)
ASN Owner: CLOUDFLARE
Resolution Type: SNI

Action: INCLUDE with domain "example.com"
Reason: SNI provides reliable domain association
```

### Session: Reverse DNS Pattern (Skipped)

```
Source: 192.168.1.100:54323
Destination: 185.199.111.133:443
Domain: cdn-185-199-111-133.github.com (Reverse DNS)
ASN Owner: FASTLY
Resolution Type: Reverse

Action: SKIP
Reason: Reverse DNS pattern detected for CDN provider
```

### Session: Unresolved Domain to CDN

```
Source: 192.168.1.100:54324
Destination: 104.16.0.1:443
Domain: Unknown
ASN Owner: CLOUDFLARE
Resolution Type: None

Action: INCLUDE with IP only
Reason: Supports non-eBPF environments where DNS capture unavailable
```

### Session: Non-CDN with Unresolved Domain

```
Source: 192.168.1.100:54325
Destination: 93.184.216.34:443
Domain: Unknown
ASN Owner: EDGECAST
Resolution Type: None

Action: INCLUDE with IP only
Reason: Not a CDN provider, IP-only whitelisting acceptable
```

## Configuration

The CDN filtering behavior is automatic and does not require configuration. The system:

1. Identifies CDN providers based on ASN owner keywords
2. Detects reverse DNS patterns using heuristic matching
3. Makes inclusion/exclusion decisions based on the matrix above

### Process-Based Whitelisting

When `include_process` is enabled during whitelist creation, an additional constraint applies: sessions must have a resolved process name. This provides defense-in-depth by ensuring whitelist entries are scoped to specific applications.

## Implications for Supply Chain Security

The CDN filtering strategy directly impacts supply chain attack detection:

1. **Legitimate CDN traffic** with proper domain resolution creates precise whitelist entries
2. **Compromised dependencies** contacting CDN infrastructure with unresolved domains may create IP-only entries
3. **New malicious connections** to CDN IPs not in the whitelist will be flagged as exceptions

For maximum security in CI/CD environments:
- Use Linux runners with eBPF support when possible
- Enable `include_process` for process-scoped whitelisting
- Review whitelist exceptions carefully during the learning phase

## References

- [Fastly IP Ranges](https://api.fastly.com/public-ip-list)
- [Cloudflare IP Ranges](https://www.cloudflare.com/ips/)
- [AWS IP Ranges](https://ip-ranges.amazonaws.com/ip-ranges.json)
- [RFC 1035: Domain Names](https://www.rfc-editor.org/rfc/rfc1035)
- [RFC 6066: TLS Extensions (SNI)](https://www.rfc-editor.org/rfc/rfc6066)

