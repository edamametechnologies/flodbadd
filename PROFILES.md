## LAN Scan Device Profiles

This document describes the device profiling mechanism used by `flodbadd` for identifying device types on a LAN based on open ports, mDNS services, vendor (OUI), hostnames, and banners. The implementation lives in `flodbadd/src/profiles.rs` and the built‑in default database is in `flodbadd/src/profiles_db.rs`.

### Overview

- **Goal**: Map observed network signals to a high‑level `device_type` (e.g., `Printer`, `SmartTV`).
- **Data**: A JSON document with a set of rules. Each rule declares a `device_type` and one or more boolean conditions.
- **Engine**: Evaluates conditions case‑insensitively and returns the first matching `device_type` in the JSON order. If no rule matches, the result is `"Unknown"`.
- **Updates**: Rules can be remotely updated via a cloud model file named `lanscan-profiles-db.json`.

### JSON Schema

Top‑level structure, as embedded by `profiles_db.rs`:

```json
{
  "date": "<human readable date>",
  "profiles": [ DeviceTypeRule, ... ],
  "signature": "<hex string>"
}
```

Where each `DeviceTypeRule` is:

```json
{
  "device_type": "SmartTV",
  "conditions": [ Condition, ... ]
}
```

A `Condition` is either a `Leaf` or a `Node` (recursive):

```json
{ "Leaf": Attributes }
```

```json
{ "Node": { "type": "AND" | "OR", "sub_conditions": [ Condition, ... ] } }
```

`Attributes` fields (all optional except when noted):

- `open_ports: [u16, ...]` — All listed ports must be present (logical AND within this array).
- `mdns_services: [string, ...]` — Matches if any device mDNS service string contains any listed value (substring match, case‑insensitive).
- `vendors: [string, ...]` — Matches if the OUI vendor string contains any listed value (substring match, case‑insensitive).
- `hostnames: [string, ...]` — Matches if the hostname contains any listed value (substring match, case‑insensitive).
- `banners: [string, ...]` — Matches if any observed banner contains any listed value (substring match, case‑insensitive).
- `negate: bool` — If `true`, the result of the attribute conjunction is negated.

Notes:

- Omitted or empty attribute lists are treated as "no constraint" (i.e., they do not restrict matching).
- Text matching is case‑insensitive and uses substring semantics.
- For `open_ports`, all listed ports must be present for the leaf to match (conjunctive semantics).

### Condition Semantics

- `Leaf(Attributes)` computes the conjunction of the attribute checks, then applies `negate` if present.
- `Node` combines `sub_conditions` either with `AND` (all must match) or `OR` (any may match).
- Within a `DeviceTypeRule`, the rule’s `conditions` are evaluated with an implicit OR: if any top‑level condition matches, the `device_type` is selected.
- The engine iterates rules strictly in the JSON order and returns on the first match (first‑match‑wins). Place more specific rules before generic ones.
- Avoid overlapping rules that would match the same device across multiple `device_type`s. If overlaps are unavoidable, the earlier rule wins due to ordering.
- Keep one `DeviceTypeRule` per `device_type` whenever possible. Duplicate entries for the same `device_type` are processed independently but are discouraged; prefer expressing alternatives inside a single rule using `Node` with `AND`/`OR`.

### Validation and Overlap Checks

- The companion validation scripts (in the `threatmodels` repository) assume no reliance on ordering for correctness and will flag test devices that match multiple `device_type`s as overlapping. Fix overlaps by:
  - Consolidating rules for the same `device_type` using `OR`/`AND` trees, or
  - Refining constraints so only one `device_type` matches for a given device, and
  - Re‑ordering rules so that more specific matches precede broader ones when appropriate.

### Matching Details (from `profiles.rs`)

- Inputs are normalized to lowercase. Ports are collected into a set for O(1) membership checks.
- `mdns_services`: a leaf value matches if any observed service contains the leaf string.
- `vendors`: a leaf value matches if the observed OUI vendor contains the leaf string.
- `hostnames`: a leaf value matches if the observed hostname contains the leaf string.
- `banners`: a leaf value matches if any observed banner contains the leaf string.
- Unknowns: If no rule matches and there was at least one observed signal (ports or mDNS) and a non‑empty vendor, a warning is logged.

### Example Rules

Smart TV (OR over several indicators):

```json
{
  "device_type": "SmartTV",
  "conditions": [
    { "Node": { "type": "OR", "sub_conditions": [
      { "Leaf": { "open_ports": [8008, 8009, 8443, 9000] } },
      { "Leaf": { "open_ports": [3000, 3001, 18181] } },
      { "Leaf": { "mdns_services": ["androidtvremote", "googlecast", "airplay"] } },
      { "Leaf": { "vendors": ["tcl", "hisense", "vizio", "sharp", "toshiba"] } }
    ]}}
  ]
}
```

PC but not a DNS server (negate example):

```json
{
  "device_type": "PC",
  "conditions": [
    { "Node": { "type": "AND", "sub_conditions": [
      { "Leaf": { "vendors": ["dell", "lenovo", "acer", "msi", "asus"] } },
      { "Leaf": { "open_ports": [53], "negate": true } }
    ]}}
  ]
}
```

### Authoring Guidelines

- Keep one `DeviceTypeRule` per `device_type`. Use nested `Node` constructs to express complex logic.
- Order matters: the engine is first‑match‑wins in JSON order. Put the most specific rules earlier, and avoid overlaps between different `device_type`s.
- Validate with the test set; overlaps will be reported by the validator and should be resolved before publishing.
- Prefer lower‑case strings; matching is case‑insensitive, but lower‑case improves readability.
- Use `mdns_services` with substrings that appear in typical service names (e.g., `"ipp"` matches `_ipp._tcp.local.`).
- Be conservative with `banners` as they vary across services and firmware.
- Use `negate` to exclude specific traits (e.g., exclude DNS port 53 when identifying general PCs).
- Validate new rules with representative scan data to avoid false positives.

