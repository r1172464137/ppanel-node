#!/usr/bin/env bash
# Narrow runtime-payload update: binary plus pinned geodata, with full rollback.
# No install, unit registration or config writes. Default remains deliberately pinned.
if [[ ${BASH_SOURCE[0]} == "$0" ]]; then set -euo pipefail; fi

release_init() {
    RELEASE_REPO=$1; RELEASE_TAG=${2:-}
    [[ $RELEASE_REPO =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] || { echo 'invalid release repository' >&2; return 1; }
    if [[ -z $RELEASE_TAG ]]; then
        local effective
        effective=$(curl --proto '=https' --tlsv1.2 -fsSL --retry 3 -o /dev/null -w '%{url_effective}' "https://github.com/$RELEASE_REPO/releases/latest") || return 1
        [[ $effective == "https://github.com/$RELEASE_REPO/releases/tag/"* ]] || { echo 'latest release not found' >&2; return 1; }
        RELEASE_TAG=${effective##*/}
    fi
    [[ $RELEASE_TAG =~ ^v[0-9]+\.[0-9]+\.[0-9]+([.-][A-Za-z0-9.-]+)?$ ]] || { echo 'invalid release tag (expected vX.Y.Z)' >&2; return 1; }
    RELEASE_BASE="https://github.com/$RELEASE_REPO/releases/download/$RELEASE_TAG"
}

release_fetch() {
    local asset=$1 dir=$2
    [[ $asset =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]] || return 1
    mkdir -p "$dir" || return 1
    curl --proto '=https' --tlsv1.2 -fsSL --retry 3 -o "$dir/SHA256SUMS" "$RELEASE_BASE/SHA256SUMS" || return 1
    awk -v asset="$asset" '$2 == asset { n++; if (length($1) != 64 || $1 !~ /^[a-fA-F0-9]+$/ || NF != 2) bad=1; print $1 "  " asset } END { if (n != 1 || bad) exit 1 }' "$dir/SHA256SUMS" > "$dir/$asset.sha256" || { echo "invalid/missing checksum for $asset" >&2; return 1; }
    curl --proto '=https' --tlsv1.2 -fsSL --retry 3 -o "$dir/$asset" "$RELEASE_BASE/$asset" || return 1
    (cd "$dir" && sha256sum -c "$asset.sha256") || { rm -f "$dir/$asset"; return 1; }
}

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

extract_runtime_payload() {
    local archive=$1 destination=$2 entries file
    mkdir -p "$destination" || return 1
    entries="$destination/.entries"
    unzip -Z1 "$archive" > "$entries" || return 1
    awk '$0 ~ /\// || $0 == ".." { bad=1 } END { exit bad }' "$entries" || return 1
    unzip -q "$archive" -d "$destination" || return 1
    rm -f "$entries"
    for file in ppnode geoip.dat geosite.dat geodata.lock; do [[ -f $destination/$file && ! -L $destination/$file ]] || return 1; done
    verify_geodata_bundle "$destination" "$destination/geodata.lock"
}

node_version_matches() {
    local binary=$1 version=$2 output
    output=$("$binary" version) || return 1
    [[ $output == *"PPanel-node $version ("* ]]
}

verify_running_node() {
    local binary=$1 version=$2 proc_root=${3:-/proc} pid actual
    systemctl is-active --quiet PPanel-node.service || return 1
    pid=$(systemctl show PPanel-node.service --property=MainPID --value) || return 1
    [[ $pid =~ ^[1-9][0-9]*$ ]] || return 1
    actual=$(readlink -f "$proc_root/$pid/exe") || return 1
    [[ $actual == "$binary" ]] || return 1
    cmp -- "$binary" "$proc_root/$pid/exe" || return 1
    node_version_matches "$proc_root/$pid/exe" "$version"
}

restore_node_payload() {
    local install_dir=$1 backup_dir=$2 was_active=$3 file mode
    for file in ppnode geoip.dat geosite.dat geodata.lock; do
        mode=0644; [[ $file != ppnode ]] || mode=0755
        if [[ -f $backup_dir/$file ]]; then
            install -m "$mode" "$backup_dir/$file" "$install_dir/$file.rollback" || return 1
            mv -f "$install_dir/$file.rollback" "$install_dir/$file" || return 1
        else
            rm -f "$install_dir/$file" || return 1
        fi
    done
    if [[ $was_active == true ]]; then
        systemctl restart PPanel-node.service
    else
        systemctl stop PPanel-node.service
    fi
}

if [[ ${BASH_SOURCE[0]} != "$0" ]]; then return 0; fi
[[ ${1:-} != --help ]] || { echo 'sudo bash update.sh [vX.Y.Z] (default v1.1.15, binary+geodata update with rollback)'; exit 0; }
[[ $# -le 1 ]] || { echo 'at most one version argument is allowed' >&2; exit 1; }
[[ $EUID == 0 && $(uname -s) == Linux ]] || { echo 'Linux root update required' >&2; exit 1; }
for cmd in curl sha256sum unzip systemctl readlink cmp install; do command -v "$cmd" >/dev/null; done
install_dir=/usr/local/PPanel-node
binary=$install_dir/ppnode
[[ -f $binary && ! -L $binary && -f /etc/PPanel-node/config.yml ]] || { echo 'expected existing binary and configuration not found; refusing to install/reconfigure' >&2; exit 1; }
unit=$(systemctl show PPanel-node.service --property=FragmentPath --value)
[[ -n $unit && -f $unit ]] || { echo 'existing PPanel-node.service unit not found' >&2; exit 1; }
release_init "${PPNODE_RELEASE_REPO:-r1172464137/ppanel-node}" "${1:-${PPNODE_VERSION:-v1.1.15}}"
version=${RELEASE_TAG#v}
case $(uname -m) in
    x86_64|amd64) arch=64 ;;
    aarch64|arm64) arch=arm64-v8a ;;
    s390x) arch=s390x ;;
    *) echo 'unsupported updater architecture' >&2; exit 1 ;;
esac
tmp=$(mktemp -d); changed=false; was_active=false; backup_dir=''
cleanup() {
    rm -rf "$tmp"
    rm -f "$install_dir"/*.next "$install_dir"/*.rollback
}
rollback() {
    local status=$?
    trap - ERR INT TERM
    if $changed; then
        echo "Update failed; restoring binary and geodata from $backup_dir" >&2
        restore_node_payload "$install_dir" "$backup_dir" "$was_active" || echo 'ROLLBACK FAILED; inspect PPanel-node.service and restore the printed backup immediately' >&2
    fi
    exit "${status:-1}"
}
trap cleanup EXIT
trap rollback ERR
trap 'false' INT TERM
release_fetch "ppanel-node-linux-$arch.zip" "$tmp"
extract_runtime_payload "$tmp/ppanel-node-linux-$arch.zip" "$tmp/extract"
chmod 755 "$tmp/extract/ppnode"
node_version_matches "$tmp/extract/ppnode" "$version"
# Preserve and update the complete runtime payload. Config and unit stay untouched.
backup_dir="$install_dir/before-$RELEASE_TAG-$(date -u +%Y%m%dT%H%M%SZ)-$$"
mkdir -m 0700 "$backup_dir"
for file in ppnode geoip.dat geosite.dat geodata.lock; do [[ ! -f $install_dir/$file ]] || cp -p "$install_dir/$file" "$backup_dir/$file"; done
if systemctl is-active --quiet PPanel-node.service; then was_active=true; fi
for file in geoip.dat geosite.dat geodata.lock; do install -m 0644 "$tmp/extract/$file" "$install_dir/$file.next"; done
install -m 0755 "$tmp/extract/ppnode" "$binary.next"
changed=true
for file in geoip.dat geosite.dat geodata.lock; do mv -f "$install_dir/$file.next" "$install_dir/$file"; done
mv -f "$binary.next" "$binary"
verify_geodata_bundle "$install_dir" "$install_dir/geodata.lock"
systemctl restart PPanel-node.service
# Require a stable MainPID, executable and matching version over two samples.
verified=false
for attempt in {1..10}; do
    sleep 2
    if verify_running_node "$binary" "$version" && verify_geodata_bundle "$install_dir" "$install_dir/geodata.lock"; then
        pid=$(systemctl show PPanel-node.service --property=MainPID --value)
        sleep 2
        if verify_running_node "$binary" "$version" && verify_geodata_bundle "$install_dir" "$install_dir/geodata.lock" && [[ $(systemctl show PPanel-node.service --property=MainPID --value) == "$pid" ]]; then
            verified=true
            break
        fi
    fi
done
$verified
changed=false
trap - ERR INT TERM
printf 'Updated PPanel-node.service to %s; MainPID=%s; exe=%s; payload-backup=%s\n' "$version" "$pid" "$binary" "$backup_dir"
