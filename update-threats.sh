#!/bin/bash

update_flodbadd_port_vulns () {
    local is_local=${1:-false}
    local target=./src/port_vulns_db.rs
    # We need to use 4 # in order to deal with the mess of escape chars found in the CVE descriptions
    local header="// Built in default port vulns db\npub static PORT_VULNS: &str = r####\""
    local trailer="\"####;"

    echo "Updating flodbadd port vulns db"

    # Delete the file if it exists
    if [ -f "$target" ]; then
        rm "$target"
    fi

    if [ "$is_local" = true ]; then
        echo "Using local port vulns db file"
        local body="$(cat ../threatmodels/port-vulns-db.json)"
    else
        echo "Fetching port vulns db from GitHub"
        local branch=$(git rev-parse --abbrev-ref HEAD)
        # Only deal with main and dev branches, default to dev
        if [ $branch != "dev" ] && [ $branch != "main" ]; then
          branch=dev
        fi
        # Prevent bash parsing of escape chars
        local body="$(wget --no-cache -qO- https://raw.githubusercontent.com/edamametechnologies/threatmodels/$branch/lanscan-port-vulns-db.json)"
    fi

    # Interpret escape chars
    echo -n -e "$header" > "$target"
    # Preserve escape chars
    echo -n "$body" >> "$target"
    # Interpret escape chars
    echo -e $trailer >> "$target"
}

update_flodbadd_vendor_vulns () {
    local is_local=${1:-false}
    local target=./src/vendor_vulns_db.rs
    # We need to use 4 # in order to deal with the mess of escape chars found in the CVE descriptions
    local header="// Built in default vendor vulns db\npub static VENDOR_VULNS: &str = r####\""
    local trailer="\"####;"

    echo "Updating flodbadd vendor vulns db"

    # Delete the file if it exists
    if [ -f "$target" ]; then
        rm "$target"
    fi

    if [ "$is_local" = true ]; then
        echo "Using local vendor vulns db file"
        local body="$(cat ../threatmodels/vendor-vulns-db.json)"
    else
        echo "Fetching vendor vulns db from GitHub"
        local branch=$(git rev-parse --abbrev-ref HEAD)
        # Only deal with main and dev branches, default to dev
        if [ $branch != "dev" ] && [ $branch != "main" ]; then
          branch=dev
        fi
        # Prevent bash parsing of escape chars
        local body="$(wget --no-cache -qO- https://raw.githubusercontent.com/edamametechnologies/threatmodels/$branch/lanscan-vendor-vulns-db.json)"
    fi

    # Interpret escape chars
    echo -n -e "$header" > "$target"
    # Preserve escape chars
    echo -n "$body" >> "$target"
    # Interpret escape chars
    echo -e $trailer >> "$target"
}

update_flodbadd_profiles () {
    local is_local=${1:-false}
    local target=./src/profiles_db.rs
    local header="// Built in default profile db\npub static DEVICE_PROFILES: &str = r#\""
    local trailer="\"#;"

    echo "Updating flodbadd profiles db"

    # Delete the file if it exists
    if [ -f "$target" ]; then
        rm "$target"
    fi

    if [ "$is_local" = true ]; then
        echo "Using local profiles db file"
        local body="$(cat ../threatmodels/profiles-db.json)"
    else
        echo "Fetching profiles db from GitHub"
        local branch=$(git rev-parse --abbrev-ref HEAD)
        # Only deal with main and dev branches, default to dev
        if [ $branch != "dev" ] && [ $branch != "main" ]; then
          branch=dev
        fi
        # Prevent bash parsing of escape chars
        local body="$(wget --no-cache -qO- https://raw.githubusercontent.com/edamametechnologies/threatmodels/$branch/lanscan-profiles-db.json)"
    fi

    # Interpret escape chars
    echo -n -e "$header" > "$target"
    # Preserve escape chars
    echo -n "$body" >> "$target"
    # Interpret escape chars
    echo -e $trailer >> "$target"
}

update_whitelists_db() {
    local is_local=${1:-false}
    local target=./src/whitelists_db.rs
    local header="// Built in default whitelists db\npub static WHITELISTS: &str = r#\""
    local trailer="\"#;"

    echo "Updating whitelists db"

    # Delete the file if it exists
    if [ -f "$target" ]; then
        rm "$target"
    fi

    if [ "$is_local" = true ]; then
        echo "Using local whitelists db file"
        local body="$(cat ../threatmodels/whitelists-db.json)"
    else
        echo "Fetching whitelists db from GitHub"
        local branch=$(git rev-parse --abbrev-ref HEAD)
        # Only deal with main and dev branches, default to dev
        if [ $branch != "dev" ] && [ $branch != "main" ]; then
          branch=dev
        fi
        # Prevent bash parsing of escape chars
        local body="$(wget --no-cache -qO- https://raw.githubusercontent.com/edamametechnologies/threatmodels/$branch/whitelists-db.json)"
    fi

    # Interpret escape chars
    echo -n -e "$header" > "$target"
    # Preserve escape chars
    echo -n "$body" >> "$target"
    # Interpret escape chars
    echo -e $trailer >> "$target"
}

update_blacklists_db() {
    local is_local=${1:-false}
    local target=./src/blacklists_db.rs
    local header="// Built in default blacklist db\npub static BLACKLISTS: &str = r#\""
    local trailer="\"#;"

    echo "Updating blacklists db"

    # Delete the file if it exists
    if [ -f "$target" ]; then
        rm "$target"
    fi

    if [ "$is_local" = true ]; then
        echo "Using local blacklist db file"
        local body="$(cat ../threatmodels/blacklists-db.json)"
    else
        echo "Fetching blacklists db from GitHub"
        local branch=$(git rev-parse --abbrev-ref HEAD)
        # Only deal with main and dev branches, default to dev
        if [ $branch != "dev" ] && [ $branch != "main" ]; then
          branch=dev
        fi
        # Prevent bash parsing of escape chars
        local body="$(wget --no-cache -qO- https://raw.githubusercontent.com/edamametechnologies/threatmodels/$branch/blacklists-db.json)"
    fi

    # Interpret escape chars
    echo -n -e "$header" > "$target"
    # Preserve escape chars
    echo -n "$body" >> "$target"
    # Interpret escape chars
    echo -e $trailer >> "$target"
}

update_sensitive_paths_db() {
    local is_local=${1:-false}
    local target=./src/sensitive_paths_db.rs

    # IMPORTANT: this DB is OBFUSCATED in the embedded fallback.
    #
    # Unlike the other *_db.rs files in this directory, sensitive_paths_db.rs
    # is rendered by tools/encode_cloud_fallback.py rather than written as a
    # `pub static FOO: &str = r#"..."#;` raw-string literal. The reason is
    # Microsoft Defender's Stealc/Stealga ML model: this JSON contains the
    # full credential-stealer reconnaissance corpus (Microsoft/Credentials,
    # Microsoft/Protect / DPAPI master keys, browser User Data paths, SSH
    # key file names, crypto-wallet locations, password manager extension
    # IDs, etc.). Embedded as a plain UTF-8 string, the helper binary's
    # rodata section reads as a textbook info-stealer fingerprint and trips
    # `Trojan:Win32/Stealga.HAK!MTB` on signed builds. See
    # `src/cloud_model_fallback.rs` for the runtime decoder.
    #
    # The published JSON in the threatmodels repo stays in plain form;
    # only the *embedded fallback* gets gzip+XOR'd here.

    echo "Updating sensitive paths db (obfuscated CloudModel fallback)"

    # Delete the file if it exists.
    if [ -f "$target" ]; then
        rm "$target"
    fi

    local tmp_json
    tmp_json=$(mktemp -t sensitive_paths_db.XXXXXX.json)
    # Make sure the temp JSON is cleaned up even on early return.
    trap 'rm -f "$tmp_json"' RETURN

    if [ "$is_local" = true ]; then
        echo "Using local sensitive paths db file"
        cp ../threatmodels/sensitive-paths-db.json "$tmp_json"
    else
        echo "Fetching sensitive paths db from GitHub"
        local branch=$(git rev-parse --abbrev-ref HEAD)
        # Only deal with main and dev branches, default to dev
        if [ "$branch" != "dev" ] && [ "$branch" != "main" ]; then
          branch=dev
        fi
        wget --no-cache -qO "$tmp_json" "https://raw.githubusercontent.com/edamametechnologies/threatmodels/$branch/sensitive-paths-db.json"
    fi

    if [ ! -s "$tmp_json" ]; then
        echo "ERROR: empty or missing sensitive paths source JSON ($tmp_json) -- aborting" >&2
        return 1
    fi

    python3 ./tools/encode_cloud_fallback.py \
        "$tmp_json" \
        "$target" \
        SENSITIVE_PATHS_DB \
        "Built in default sensitive paths db (obfuscated)"
}

# Parse command line arguments
USE_LOCAL=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --local)
            USE_LOCAL=true
            shift
            ;;
    esac
done

update_flodbadd_profiles $USE_LOCAL
update_flodbadd_port_vulns $USE_LOCAL
update_flodbadd_vendor_vulns $USE_LOCAL
update_whitelists_db $USE_LOCAL
update_blacklists_db $USE_LOCAL
update_sensitive_paths_db $USE_LOCAL
