#!/usr/bin/env bash
# Fetch the immutable geodata revision declared in .github/build/geodata.lock.
if [[ ${BASH_SOURCE[0]} == "$0" ]]; then set -euo pipefail; fi

geodata_lock_value() {
    local lock=$1 key=$2
    awk -F= -v key="$key" '$1 == key { n++; value=substr($0, length(key)+2) } END { if (n != 1 || value == "") exit 1; print value }' "$lock"
}

verify_geodata_bundle() {
    local dir=$1 lock repository commit geoip_digest geosite_digest file digest
    lock=${2:-$dir/geodata.lock}
    [[ -f $lock && ! -L $lock ]] || { echo 'geodata lock is missing or unsafe' >&2; return 1; }
    repository=$(geodata_lock_value "$lock" repository) || return 1
    commit=$(geodata_lock_value "$lock" commit) || return 1
    geoip_digest=$(geodata_lock_value "$lock" geoip_sha256) || return 1
    geosite_digest=$(geodata_lock_value "$lock" geosite_sha256) || return 1
    [[ $repository =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ && $commit =~ ^[a-f0-9]{40}$ ]] || return 1
    for file in geoip.dat geosite.dat; do
        [[ -f $dir/$file && ! -L $dir/$file && -s $dir/$file ]] || return 1
        if [[ $file == geoip.dat ]]; then digest=$geoip_digest; else digest=$geosite_digest; fi
        [[ $digest =~ ^[a-f0-9]{64}$ ]] || return 1
        printf '%s  %s\n' "$digest" "$file" | (cd "$dir" && sha256sum -c -) || return 1
    done
}

fetch_geodata() {
    local destination=$1 lock=$2 repository commit tmp file
    [[ -f $lock && ! -L $lock ]] || { echo 'checked-in geodata lock is missing or unsafe' >&2; return 1; }
    repository=$(geodata_lock_value "$lock" repository) || return 1
    commit=$(geodata_lock_value "$lock" commit) || return 1
    [[ $repository =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ && $commit =~ ^[a-f0-9]{40}$ ]] || return 1
    mkdir -p "$destination" || return 1
    tmp=$(mktemp -d "$destination/.geodata.XXXXXX") || return 1
    for file in geoip.dat geosite.dat; do
        curl --proto '=https' --tlsv1.2 -fsSL --retry 3 \
            -o "$tmp/$file" "https://raw.githubusercontent.com/$repository/$commit/$file" || { rm -rf "$tmp"; return 1; }
    done
    cp "$lock" "$tmp/geodata.lock" || { rm -rf "$tmp"; return 1; }
    verify_geodata_bundle "$tmp" "$tmp/geodata.lock" || { rm -rf "$tmp"; return 1; }
    for file in geoip.dat geosite.dat geodata.lock; do mv -f "$tmp/$file" "$destination/$file" || { rm -rf "$tmp"; return 1; }; done
    rmdir "$tmp"
}

if [[ ${BASH_SOURCE[0]} != "$0" ]]; then return 0; fi
[[ $# == 1 ]] || { echo 'usage: fetch-geodata.sh DESTINATION' >&2; exit 1; }
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
fetch_geodata "$1" "$root/.github/build/geodata.lock"
