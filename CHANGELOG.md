## 15/08/2025 - https://github.com/edamametechnologies/flodbadd/pull/1
    - Add Group by IP instead of port when factorizing the whitelist.
    - Add port handling in WhitelistEndpoint to improve clarity and support for single values and ranges.
    - Add whitelist comparison functionality by adding a method to calculate differences between old and new whitelists.
    - Add Changelog.md
    - Add support for pull request workflows.

## 16/08/2025
    - Capture: enforce single-worker recomputation in `update_sessions_internal` and wait on in-flight updates to complete before returning, ensuring consistent reads for `get_blacklisted_sessions`/`get_sessions` after rule changes.
    - Capture: tighten end-of-iteration handling to avoid briefly clearing the in-progress flag between queued passes (removes visibility gap under load).
    - IP: harden IPv6 LAN cache initialisation by skipping invalid prefix 0 entries (prevents misclassification of all IPv6 as local on some Windows/container setups).
