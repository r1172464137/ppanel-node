#!/usr/bin/env bash
# Release installer/updater; verifies before stopping service or replacing files.
# PPNODE_RELEASE_REPO=owner/repo defaults to r1172464137/ppanel-node.
# --download-only DIR is nonprivileged and never installs/restarts anything.
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

# The installed manager sources these same helpers; sourcing has no host effects.
if [[ ${BASH_SOURCE[0]} != "$0" ]]; then return 0; fi

version=${PPNODE_VERSION:-}; download_dir=''; api_host=''; server_id=''; secret_key=''
while [[ $# -gt 0 ]]; do
    case $1 in
        --download-only) download_dir=${2:?directory required}; shift 2 ;;
        --api-host) api_host=${2:?URL required}; shift 2 ;;
        --server-id) server_id=${2:?ID required}; shift 2 ;;
        --secret-key) secret_key=${2:?key required}; shift 2 ;;
        --help|-h) echo 'Usage: install.sh [vX.Y.Z] [--download-only DIR] [--api-host URL --server-id ID --secret-key KEY]'; exit 0 ;;
        v*) [[ -z $version ]] || { echo 'duplicate version' >&2; exit 1; }; version=$1; shift ;;
        *) echo "unknown argument: $1" >&2; exit 1 ;;
    esac
done
repo=${PPNODE_RELEASE_REPO:-}
if [[ -z $repo && -f /etc/PPanel-node/release-repo ]]; then IFS= read -r repo < /etc/PPanel-node/release-repo; fi
release_init "${repo:-r1172464137/ppanel-node}" "$version"
case $(uname -m) in
    x86_64|amd64) arch=64 ;;
    aarch64|arm64) arch=arm64-v8a ;;
    s390x) arch=s390x ;;
    *) echo 'unsupported installer architecture; use the matching release archive manually' >&2; exit 1 ;;
esac
asset="ppanel-node-linux-$arch.zip"
if [[ -n $download_dir ]]; then release_fetch "$asset" "$download_dir"; exit; fi
[[ $EUID == 0 && $(uname -s) == Linux ]] || { echo 'Linux root installation required; use --download-only for verification' >&2; exit 1; }
for cmd in curl unzip sha256sum install; do command -v "$cmd" >/dev/null; done
if [[ -d /run/systemd/system ]]; then manager=systemd; command -v systemctl >/dev/null
elif command -v rc-service >/dev/null; then manager=openrc
else echo 'systemd or OpenRC is required' >&2; exit 1; fi
# Validate complete generation arguments before touching the installed service.
if [[ -n $api_host || -n $server_id || -n $secret_key ]]; then
    [[ -n $api_host && $server_id =~ ^[1-9][0-9]*$ && -n $secret_key ]] || { echo 'all configuration arguments are required' >&2; exit 1; }
fi
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
release_fetch "$asset" "$tmp"
unzip -Z1 "$tmp/$asset" > "$tmp/entries"
# Release ZIPs are flat files. Reject path traversal, subdirectories and absolute paths.
awk '$0 ~ /\// || $0 == ".." { bad=1 } END { exit bad }' "$tmp/entries"
unzip -q "$tmp/$asset" -d "$tmp/extract"
for file in ppnode config.yml ppnode.sh install.sh geoip.dat geosite.dat; do [[ -f $tmp/extract/$file && ! -L $tmp/extract/$file ]]; done
install_dir=/usr/local/PPanel-node
mkdir -p "$install_dir" /etc/PPanel-node
if [[ -f $install_dir/ppnode ]]; then cp -p "$install_dir/ppnode" "$install_dir/ppnode.previous"; fi
if [[ $manager == systemd ]]; then
    if systemctl is-active --quiet PPanel-node; then systemctl stop PPanel-node; fi
else
    if rc-service PPanel-node status >/dev/null 2>&1; then rc-service PPanel-node stop; fi
fi
install -m 0755 "$tmp/extract/ppnode" "$install_dir/ppnode"
install -m 0644 "$tmp/extract/install.sh" "$install_dir/install.sh"
install -m 0755 "$tmp/extract/ppnode.sh" /usr/bin/ppnode
for file in geoip.dat geosite.dat; do install -m 0644 "$tmp/extract/$file" "/etc/PPanel-node/$file"; done
printf '%s\n' "$RELEASE_REPO" > /etc/PPanel-node/release-repo
# Existing credentials/configuration are never overwritten by an update.
if [[ ! -e /etc/PPanel-node/config.yml ]]; then
    if [[ -n $api_host ]]; then
        host_yaml=${api_host//\'/\'\'}; key_yaml=${secret_key//\'/\'\'}
        umask 077
        printf "Log:\n  Level: warn\n  Output: ''\n  Access: none\nApi:\n  ApiHost: '%s'\n  ServerID: %s\n  SecretKey: '%s'\n  Timeout: 30\n" "$host_yaml" "$server_id" "$key_yaml" > /etc/PPanel-node/config.yml
    else
        install -m 0600 "$tmp/extract/config.yml" /etc/PPanel-node/config.yml
    fi
fi
if [[ $manager == systemd ]]; then
    cat > /etc/systemd/system/PPanel-node.service <<EOF
[Unit]
Description=PPanel-node Service
After=network-online.target nss-lookup.target
Wants=network-online.target
[Service]
WorkingDirectory=$install_dir
ExecStart=$install_dir/ppnode server --config /etc/PPanel-node/config.yml
Restart=on-failure
RestartSec=10
LimitNOFILE=999999
[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable PPanel-node
    systemctl start PPanel-node
else
    cat > /etc/init.d/PPanel-node <<EOF
#!/sbin/openrc-run
name="PPanel-node"
command="$install_dir/ppnode"
command_args="server --config /etc/PPanel-node/config.yml"
pidfile="/run/ppnode.pid"
command_background="yes"
depend() { need net; }
EOF
    chmod 755 /etc/init.d/PPanel-node
    rc-update add PPanel-node default
    rc-service PPanel-node start
fi
printf 'Installed %s from %s. Configuration preserved in /etc/PPanel-node/config.yml\n' "$RELEASE_TAG" "$RELEASE_REPO"
