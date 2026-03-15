#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SRC_DIR="$SCRIPT_DIR/src"

V4_URL="https://iptoasn.com/data/ip2asn-v4.tsv.gz"
V6_URL="https://iptoasn.com/data/ip2asn-v6.tsv.gz"

TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT

echo "Downloading IPv4 ASN database..."
curl -sSL "$V4_URL" | gunzip > "$TMP_DIR/ip2asn-v4.tsv"
V4_LINES=$(wc -l < "$TMP_DIR/ip2asn-v4.tsv" | tr -d ' ')
echo "  $V4_LINES entries"

echo "Downloading IPv6 ASN database..."
curl -sSL "$V6_URL" | gunzip > "$TMP_DIR/ip2asn-v6.tsv"
V6_LINES=$(wc -l < "$TMP_DIR/ip2asn-v6.tsv" | tr -d ' ')
echo "  $V6_LINES entries"

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
