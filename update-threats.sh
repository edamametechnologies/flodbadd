#!/bin/bash
#
# Regenerate the embedded CloudModel fallback files for flodbadd.
#
# IMPORTANT: every fallback in this directory is OBFUSCATED via
# tools/encode_cloud_fallback.py (gzip + XOR). The published JSON in
# `../threatmodels/` stays in plain form -- only the fallback we ship in
# the helper binary's rodata gets obfuscated. The reason is Microsoft
# Defender's Stealc/Stealga ML model: sensitive_paths_db.rs in
# particular contains a textbook credential-stealer reconnaissance
# corpus (DPAPI master keys, Windows Credential Manager paths, browser
# User Data dirs, SSH key file names, crypto-wallet locations), which
# embedded as a raw string literal trips
# `Trojan:Win32/Stealga.HAK!MTB`. The other fallbacks (port_vulns,
# vendor_vulns, blacklists, whitelists, profiles) get the same
# treatment for two reasons:
#   1. consistency / one update path
#   2. binary size: vendor_vulns_db.rs is 75 MB plain, ~15 MB obfuscated
#
# The runtime decoder lives in `src/cloud_model_fallback.rs`.

set -e

ENCODER=./tools/encode_cloud_fallback.py

if ! command -v python3 >/dev/null 2>&1; then
    echo "ERROR: python3 is required to run the obfuscation encoder" >&2
    exit 1
fi
if [ ! -x "$ENCODER" ]; then
    chmod +x "$ENCODER" || true
fi

current_branch() {
    local b
    b=$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo dev)
    if [ "$b" != "main" ] && [ "$b" != "dev" ]; then
        b=dev
    fi
    echo "$b"
}

# Fetch a single source JSON (local copy under ../threatmodels/ if --local,
# otherwise raw.githubusercontent.com on the current branch) into a temp
# file. Aborts with a clear message if the result is empty.
fetch_source_json() {
    local source_filename=$1
    local is_local=$2
    local out=$3

    if [ "$is_local" = true ]; then
        echo "  Using local ../threatmodels/${source_filename}"
        cp "../threatmodels/${source_filename}" "$out"
    else
        local branch
        branch=$(current_branch)
        echo "  Fetching ${source_filename} from threatmodels@${branch}"
        wget --no-cache -qO "$out" "https://raw.githubusercontent.com/edamametechnologies/threatmodels/${branch}/${source_filename}"
    fi

    if [ ! -s "$out" ]; then
        echo "ERROR: empty or missing ${source_filename} (target $out) -- aborting" >&2
        return 1
    fi
}

update_obfuscated_fallback() {
    local source_filename=$1
    local target_rs=$2
    local static_name=$3
    local comment=$4
    local is_local=$5

    echo "Updating ${static_name} (obfuscated CloudModel fallback)"

    local tmp_json
    tmp_json=$(mktemp -t flodbadd_threatmodel.XXXXXX.json)
    trap 'rm -f "$tmp_json"' RETURN

    fetch_source_json "$source_filename" "$is_local" "$tmp_json"

    python3 "$ENCODER" \
        "$tmp_json" \
        "$target_rs" \
        "$static_name" \
        "$comment"
}

# Parse command line arguments.
USE_LOCAL=false
while [[ $# -gt 0 ]]; do
    case $1 in
        --local)
            USE_LOCAL=true
            shift
            ;;
        *)
            shift
            ;;
    esac
done

update_obfuscated_fallback \
    "lanscan-profiles-db.json" \
    "./src/profiles_db.rs" \
    "DEVICE_PROFILES" \
    "Built in default device profiles db (obfuscated)" \
    "$USE_LOCAL"

update_obfuscated_fallback \
    "lanscan-port-vulns-db.json" \
    "./src/port_vulns_db.rs" \
    "PORT_VULNS" \
    "Built in default port vulns db (obfuscated)" \
    "$USE_LOCAL"

update_obfuscated_fallback \
    "lanscan-vendor-vulns-db.json" \
    "./src/vendor_vulns_db.rs" \
    "VENDOR_VULNS" \
    "Built in default vendor vulns db (obfuscated)" \
    "$USE_LOCAL"

update_obfuscated_fallback \
    "whitelists-db.json" \
    "./src/whitelists_db.rs" \
    "WHITELISTS" \
    "Built in default whitelists db (obfuscated)" \
    "$USE_LOCAL"

update_obfuscated_fallback \
    "blacklists-db.json" \
    "./src/blacklists_db.rs" \
    "BLACKLISTS" \
    "Built in default blacklists db (obfuscated)" \
    "$USE_LOCAL"

update_obfuscated_fallback \
    "sensitive-paths-db.json" \
    "./src/sensitive_paths_db.rs" \
    "SENSITIVE_PATHS_DB" \
    "Built in default sensitive paths db (obfuscated)" \
    "$USE_LOCAL"
