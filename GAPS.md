# Flodbadd Known Gaps and Planned Improvements

This document tracks known limitations, potential memory issues, and planned improvements for the flodbadd crate.

## Memory Management

### Completed Fixes

| Issue | Status | Details |
|-------|--------|---------|
| TCP history string unbounded | **Fixed** | Added `MAX_HISTORY_LENGTH = 1000` in `packets.rs`. Previously, long-lived high-traffic connections could accumulate millions of characters in the history string. |
| DNS resolution caches unbounded | **Fixed** | Added `DNS_CACHE_MAX_ENTRIES = 50,000` with LRU eviction in `dns.rs`. Both `dns_resolutions` and `dns_resolutions_with_process` now track insertion timestamps and evict oldest 10% when over capacity. |
| Reverse DNS cache unbounded | **Fixed** | Added `REVERSE_DNS_CACHE_MAX_ENTRIES = 50,000` with LRU eviction in `resolver.rs`. Cache tracks insertion timestamps and evicts oldest 10% when over capacity during resolver task cycle. |
| Resolver queue unbounded | **Fixed** | Added `RESOLVER_QUEUE_MAX_SIZE = 10,000` in `resolver.rs`. New IPs are dropped (with debug log) when queue is full. |

### Cache Size Limits

| Cache | Location | Max Entries | Eviction Strategy |
|-------|----------|-------------|-------------------|
| `dns_resolutions` | `dns.rs` | 50,000 | LRU (oldest 10% evicted) |
| `dns_resolutions_with_process` | `dns.rs` | 50,000 | LRU (oldest 10% evicted) |
| `reverse_dns` | `resolver.rs` | 50,000 | LRU (oldest 10% evicted) |
| `resolver_queue` | `resolver.rs` | 10,000 | Drop new entries |
| `pending_dns_queries` | `dns.rs` | 65,535 | 30s TTL cleanup |

### Remaining Items

#### 1. Pending DNS Queries Map (Low Priority - Already Mitigated)

**Location:** `dns.rs`

**Issue:** `pending_dns_queries: CustomDashMap<u16, PendingQuery>` could theoretically grow.

**Current mitigation:** 
- Keyed by transaction ID (u16), so max 65,535 entries
- Cleanup task removes entries older than 30 seconds
- Entries removed when matching response arrives

**Status:** Adequately bounded. No action needed.

---

## Performance Optimizations

### Potential Improvements (Low Priority)

#### 1. Whitelist Lookup Performance

**Location:** `whitelists.rs`

**Issue:** Whitelist matching iterates through all endpoints linearly.

**Current behavior:** O(n) where n = number of whitelist endpoints.

**Impact:** Low for typical whitelists (< 1000 rules). Could be noticeable for very large whitelists.

**Potential fix:** Build a hash index for common lookups (by port, by domain suffix).

---

#### 2. DNS Resolution Batch Processing

**Location:** `resolver.rs`

**Issue:** The resolver drains the entire queue at once:
```rust
let to_resolve: Vec<IpAddr> = resolver_queue.write().await.drain(..).collect();
```

**Impact:** Low. Could cause memory spike if queue is very large.

**Potential fix:** Process in batches of 100-500 IPs.

---

## Testing Gaps

### Areas Needing More Test Coverage

1. **Long-running capture tests** - Verify memory doesn't grow unbounded over 24+ hours
2. **High packet rate tests** - Stress test with 100k+ packets/second
3. **Cache eviction tests** - Verify LRU/TTL eviction works correctly when implemented

---

## Version History

| Date | Change |
|------|--------|
| 2026-01-22 | Added `MAX_HISTORY_LENGTH` fix for TCP history string |
| 2026-01-22 | Created GAPS.md to track remaining items |
