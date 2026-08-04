#!/usr/bin/env bash
# Temporary no-op: iptoasn.com returns Cloudflare 403 from this host.
# Keep the existing ASN snapshot (2026-07-31) and continue the lockfile cascade.
set -euo pipefail
echo "SKIP: update-asn.sh no-op (iptoasn 403); retaining existing ASN snapshot"
exit 0
