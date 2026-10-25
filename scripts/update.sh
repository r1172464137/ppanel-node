#!/usr/bin/env bash
# Narrow binary-only update: no install, unit registration, config writes or data removal.
# Default is deliberately pinned to this fork's first REALITY-xver release.
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

restore_node_binary() {
    local binary=$1 backup=$2 was_active=$3
    install -m 0755 "$backup" "$binary.rollback" || return 1
    mv -f "$binary.rollback" "$binary" || return 1
    if [[ $was_active == true ]]; then
        systemctl restart PPanel-node.service
    else
        systemctl stop PPanel-node.service
    fi
}

if [[ ${BASH_SOURCE[0]} != "$0" ]]; then return 0; fi
[[ ${1:-} != --help ]] || { echo 'sudo bash update.sh [vX.Y.Z] (default v1.1.14, binary-only update with rollback)'; exit 0; }
[[ $# -le 1 ]] || { echo 'at most one version argument is allowed' >&2; exit 1; }
[[ $EUID == 0 && $(uname -s) == Linux ]] || { echo 'Linux root update required' >&2; exit 1; }
for cmd in curl sha256sum unzip systemctl readlink cmp install; do command -v "$cmd" >/dev/null; done
binary=/usr/local/PPanel-node/ppnode
[[ -f $binary && ! -L $binary && -f /etc/PPanel-node/config.yml ]] || { echo 'expected existing binary and configuration not found; refusing to install/reconfigure' >&2; exit 1; }
unit=$(systemctl show PPanel-node.service --property=FragmentPath --value)
[[ -n $unit && -f $unit ]] || { echo 'existing PPanel-node.service unit not found' >&2; exit 1; }
release_init "${PPNODE_RELEASE_REPO:-r1172464137/ppanel-node}" "${1:-${PPNODE_VERSION:-v1.1.14}}"
version=${RELEASE_TAG#v}
case $(uname -m) in
    x86_64|amd64) arch=64 ;;
    aarch64|arm64) arch=arm64-v8a ;;
    s390x) arch=s390x ;;
    *) echo 'unsupported updater architecture' >&2; exit 1 ;;
esac
tmp=$(mktemp -d); changed=false; was_active=false; backup=''
cleanup() { rm -rf "$tmp"; }
rollback() {
    local status=$?
    trap - ERR INT TERM
    if $changed; then
        echo "Update failed; restoring binary from $backup" >&2
        restore_node_binary "$binary" "$backup" "$was_active" || echo 'ROLLBACK FAILED; inspect PPanel-node.service and restore the printed backup immediately' >&2
    fi
    exit "${status:-1}"
}
trap cleanup EXIT
trap rollback ERR
trap 'false' INT TERM
release_fetch "ppanel-node-linux-$arch.zip" "$tmp"
unzip -p "$tmp/ppanel-node-linux-$arch.zip" ppnode > "$tmp/ppnode"
chmod 755 "$tmp/ppnode"
node_version_matches "$tmp/ppnode" "$version"
# Preserve the exact existing unit/config and only back up the executable.
backup="$binary.before-$RELEASE_TAG-$(date -u +%Y%m%dT%H%M%SZ)-$$"
cp -p "$binary" "$backup"
if systemctl is-active --quiet PPanel-node.service; then was_active=true; fi
install -m 0755 "$tmp/ppnode" "$binary.next"
changed=true
mv -f "$binary.next" "$binary"
systemctl restart PPanel-node.service
# Require a stable MainPID, executable and matching version over two samples.
verified=false
for attempt in {1..10}; do
    sleep 2
    if verify_running_node "$binary" "$version"; then
        pid=$(systemctl show PPanel-node.service --property=MainPID --value)
        sleep 2
        if verify_running_node "$binary" "$version" && [[ $(systemctl show PPanel-node.service --property=MainPID --value) == "$pid" ]]; then
            verified=true
            break
        fi
    fi
done
$verified
changed=false
trap - ERR INT TERM
printf 'Updated PPanel-node.service to %s; MainPID=%s; exe=%s; backup=%s\n' "$version" "$pid" "$binary" "$backup"
