#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SRC_DIR="$SCRIPT_DIR/src"

V4_URL="https://iptoasn.com/data/ip2asn-v4.tsv.gz"
V6_URL="https://iptoasn.com/data/ip2asn-v6.tsv.gz"

TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT

# iptoasn.com sits behind Cloudflare and intermittently returns a 16-byte
# "error code: 1200" body with a 200 status when the origin is slow.
# Retry the download until we get a valid gzip stream (10 attempts,
# exponential backoff up to 30s).
download_asn() {
    local url="$1"
    local out="$2"
    local attempt
    for attempt in 1 2 3 4 5 6 7 8 9 10; do
        if curl -sSL --fail --connect-timeout 15 --max-time 90 \
            "$url" -o "$out.gz" \
            && file "$out.gz" | grep -q "gzip compressed data"; then
            gunzip -f "$out.gz"
            return 0
        fi
        echo "  attempt $attempt failed (Cloudflare 1200 or transient); sleeping $((attempt * 3))s"
        sleep $((attempt * 3))
    done
    echo "ERROR: failed to download $url after 10 attempts" >&2
    return 1
}

echo "Downloading IPv4 ASN database..."
download_asn "$V4_URL" "$TMP_DIR/ip2asn-v4.tsv"
V4_LINES=$(wc -l < "$TMP_DIR/ip2asn-v4.tsv" | tr -d ' ')
echo "  $V4_LINES entries"

echo "Downloading IPv6 ASN database..."
download_asn "$V6_URL" "$TMP_DIR/ip2asn-v6.tsv"
V6_LINES=$(wc -l < "$TMP_DIR/ip2asn-v6.tsv" | tr -d ' ')
echo "  $V6_LINES entries"

# Whitelist endpoints match a session's AS owner exactly (`as_owner`; learned
# custom whitelists carry it), so a refresh that renames owners changes what
# every stored whitelist matches. iptoasn.com did that on 2026-11-02 (AS174's
# "COGENT-174" became "COGENT-174 - Cogent Communications, LLC", and many
# handles changed). When an owner the tests anchor on (src/asn.rs) is not the
# one they expect, keep the current databases: adopting a renamed source is a
# decision that comes with a migration of the stored whitelists, not a refresh.
anchor_matches() {
    awk -F'\t' -v as="$2" -v cc="$3" -v own="$4" \
        '$3 == as && $4 == cc && $5 == own { found = 1; exit } END { exit !found }' "$1"
}
if ! anchor_matches "$TMP_DIR/ip2asn-v4.tsv" 174 US "COGENT-174" \
    || ! anchor_matches "$TMP_DIR/ip2asn-v4.tsv" 33191 US "NOTION" \
    || ! anchor_matches "$TMP_DIR/ip2asn-v6.tsv" 2500 JP "WIDE-BB WIDE Project"; then
    echo "WARNING: the downloaded ASN data renames the owners the tests anchor on" >&2
    echo "  (AS174, AS33191, AS2500): whitelists that match as_owner would change." >&2
    echo "  Keeping the current src/asn_v4_db.rs and src/asn_v6_db.rs." >&2
    exit 0
fi

echo "Writing src/asn_v4_db.rs..."
{
  printf 'pub static ASN_V4_DB: &str = r###"\n'
  cat "$TMP_DIR/ip2asn-v4.tsv"
  printf '"###;\n'
} > "$SRC_DIR/asn_v4_db.rs"

echo "Writing src/asn_v6_db.rs..."
{
  printf 'pub static ASN_V6_DB: &str = r###"\n'
  cat "$TMP_DIR/ip2asn-v6.tsv"
  printf '"###;\n'
} > "$SRC_DIR/asn_v6_db.rs"

echo "Done. Updated ASN databases:"
echo "  asn_v4_db.rs: $V4_LINES IPv4 ranges"
echo "  asn_v6_db.rs: $V6_LINES IPv6 ranges"
