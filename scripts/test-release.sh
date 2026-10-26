#!/usr/bin/env bash
# Nonprivileged tests of the production download helpers. No HTTP or service calls.
set -euo pipefail
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
source "$here/install.sh"
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/source" "$tmp/download"
printf 'verified release payload\n' > "$tmp/source/test.zip"
(cd "$tmp/source" && sha256sum test.zip > SHA256SUMS)
cp "$tmp/source/SHA256SUMS" "$tmp/good-sums"

# Geodata bundle verification and installation are independent of release ZIP checksums.
mkdir -p "$tmp/geodata-source" "$tmp/geodata-installed"
printf 'test geoip payload\n' > "$tmp/geodata-source/geoip.dat"
printf 'test geosite payload\n' > "$tmp/geodata-source/geosite.dat"
geoip_digest=$(sha256sum "$tmp/geodata-source/geoip.dat" | awk '{print $1}')
geosite_digest=$(sha256sum "$tmp/geodata-source/geosite.dat" | awk '{print $1}')
cat > "$tmp/geodata-source/geodata.lock" <<EOF
repository=test/fork
commit=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
geoip_sha256=$geoip_digest
geosite_sha256=$geosite_digest
EOF
verify_geodata_bundle "$tmp/geodata-source"
install_geodata_payload "$tmp/geodata-source" "$tmp/geodata-installed"
for file in geoip.dat geosite.dat geodata.lock; do cmp "$tmp/geodata-source/$file" "$tmp/geodata-installed/$file"; done
printf '#!/bin/sh\nexit 0\n' > "$tmp/geodata-source/ppnode"
chmod 755 "$tmp/geodata-source/ppnode"
(cd "$tmp/geodata-source" && zip -q "$tmp/runtime-payload.zip" ppnode geoip.dat geosite.dat geodata.lock)
extract_runtime_payload "$tmp/runtime-payload.zip" "$tmp/runtime-extracted"
for file in ppnode geoip.dat geosite.dat geodata.lock; do cmp "$tmp/geodata-source/$file" "$tmp/runtime-extracted/$file"; done
printf 'corrupt\n' >> "$tmp/geodata-installed/geoip.dat"
if verify_geodata_bundle "$tmp/geodata-installed"; then echo 'accepted corrupt installed geodata' >&2; exit 1; fi
install_geodata_payload "$tmp/geodata-source" "$tmp/geodata-installed"

curl() {
    local output='' effective=false arg url=''
    while [[ $# -gt 0 ]]; do
        arg=$1; shift
        case $arg in
            -o) output=$1; shift ;;
            -w) effective=true; shift ;;
            --proto|--tlsv1.2|--retry) [[ $arg == --tlsv1.2 ]] || shift ;;
            https:*) url=$arg ;;
        esac
    done
    [[ ${CURL_FAIL:-false} == false ]] || return 22
    [[ $url == https://github.com/test/fork/releases/* ]] || return 23
    if $effective; then printf '%s' 'https://github.com/test/fork/releases/tag/v1.2.3'; return; fi
    cp "$tmp/source/${url##*/}" "$output"
}

release_init test/fork ''
[[ $RELEASE_TAG == v1.2.3 ]]
release_fetch test.zip "$tmp/download"
cmp "$tmp/source/test.zip" "$tmp/download/test.zip"
if release_init '../bad/repo' v1.2.3; then exit 1; fi
if release_init test/fork '../../bad'; then exit 1; fi
release_init test/fork v1.2.3
if release_fetch '../escape' "$tmp/download"; then exit 1; fi
# Corrupt payload.
printf 'corrupt\n' > "$tmp/source/test.zip"
if release_fetch test.zip "$tmp/download"; then exit 1; fi
[[ ! -e $tmp/download/test.zip ]]
# Missing, duplicate, malformed and traversal-only entries must fail closed.
for mode in missing duplicate malformed traversal; do
    case $mode in
        missing) printf '' > "$tmp/source/SHA256SUMS" ;;
        duplicate) cp "$tmp/good-sums" "$tmp/source/SHA256SUMS"; printf '\n' >> "$tmp/source/SHA256SUMS"; while IFS= read -r line; do printf '%s\n' "$line" >> "$tmp/source/SHA256SUMS"; done < "$tmp/good-sums" ;;
        malformed) printf 'bad  test.zip\n' > "$tmp/source/SHA256SUMS" ;;
        traversal) printf '%064d  ../test.zip\n' 0 > "$tmp/source/SHA256SUMS" ;;
    esac
    if release_fetch test.zip "$tmp/download"; then echo "accepted $mode manifest" >&2; exit 1; fi
done
CURL_FAIL=true
if release_fetch test.zip "$tmp/download"; then exit 1; fi
if release_init test/fork ''; then exit 1; fi
unset CURL_FAIL

if [[ -f $here/verify-release-rootfs.sh ]]; then
    mkdir -p "$tmp/bin"
    for arch in amd64 arm64; do
        root="$tmp/rootfs/linux_$arch"
        mkdir -p "$root/app/etc" "$root/etc/ssl/certs" "$root/usr/share/zoneinfo/Asia"
        printf 'binary-%s\n' "$arch" > "$tmp/bin/ppanel-server-linux-$arch"
        cp "$tmp/bin/ppanel-server-linux-$arch" "$root/app/ppanel"
        chmod 755 "$root/app/ppanel"
        printf '%s\n' '-----BEGIN CERTIFICATE-----' > "$root/etc/ssl/certs/ca-certificates.crt"
        printf 'timezone\n' > "$root/usr/share/zoneinfo/Asia/Shanghai"
        touch "$root/app/etc/ppanel.yaml"
    done
    bash "$here/verify-release-rootfs.sh" "$tmp/rootfs" "$tmp/bin"
    : > "$tmp/rootfs/linux_arm64/etc/ssl/certs/ca-certificates.crt"
    if bash "$here/verify-release-rootfs.sh" "$tmp/rootfs" "$tmp/bin"; then exit 1; fi
fi
# The standalone updater shares the installer's exact release/geodata checks.
for function in release_init release_fetch geodata_lock_value verify_geodata_bundle extract_runtime_payload; do
    declare -f "$function" > "$tmp/$function.installer"
    bash -c 'source "$1/update.sh"; declare -f "$2"' _ "$here" "$function" > "$tmp/$function.updater"
    cmp "$tmp/$function.installer" "$tmp/$function.updater"
done
for function in geodata_lock_value verify_geodata_bundle; do
    declare -f "$function" > "$tmp/$function.installer"
    bash -c 'source "$1/fetch-geodata.sh"; declare -f "$2"' _ "$here" "$function" > "$tmp/$function.fetcher"
    cmp "$tmp/$function.installer" "$tmp/$function.fetcher"
done
# The fetcher must use the lock's immutable commit and independently verify bytes.
(
    test_root=$tmp
    source "$here/fetch-geodata.sh"
    mkdir -p "$test_root/fetch-source" "$test_root/fetched"
    cp "$test_root/geodata-source/geoip.dat" "$test_root/geodata-source/geosite.dat" "$test_root/fetch-source/"
    curl() {
        local output='' url='' arg
        while [[ $# -gt 0 ]]; do
            arg=$1; shift
            case $arg in
                -o) output=$1; shift ;;
                --proto|--retry) shift ;;
                --tlsv1.2|-fsSL) ;;
                https:*) url=$arg ;;
            esac
        done
        [[ $url == https://raw.githubusercontent.com/test/fork/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/* ]]
        cp "$test_root/fetch-source/${url##*/}" "$output"
    }
    fetch_geodata "$test_root/fetched" "$test_root/geodata-source/geodata.lock"
    for file in geoip.dat geosite.dat geodata.lock; do cmp "$test_root/geodata-source/$file" "$test_root/fetched/$file"; done
)
source "$here/update.sh"
mkdir -p "$tmp/proc/123"
printf '#!/usr/bin/env bash\nprintf "PPanel-node 1.1.14 (test)\\n"\n' > "$tmp/node"
chmod 755 "$tmp/node"
ln -s "$tmp/node" "$tmp/proc/123/exe"
systemctl() {
    case $1 in is-active) return "${SERVICE_STATUS:-0}" ;; show) printf '%s\n' "${SERVICE_PID:-123}" ;; *) return 1 ;; esac
}
node_version_matches "$tmp/node" 1.1.14
if node_version_matches "$tmp/node" 1.1.13; then exit 1; fi
verify_running_node "$tmp/node" 1.1.14 "$tmp/proc"
SERVICE_STATUS=1
if verify_running_node "$tmp/node" 1.1.14 "$tmp/proc"; then exit 1; fi
unset SERVICE_STATUS
SERVICE_PID=0
if verify_running_node "$tmp/node" 1.1.14 "$tmp/proc"; then exit 1; fi
unset SERVICE_PID
if verify_running_node "$tmp/other" 1.1.14 "$tmp/proc"; then exit 1; fi
# Exercise complete binary+geodata rollback with a mocked service manager.
systemctl() { printf '%s\n' "$*" >> "$tmp/service-calls"; return "${RESTART_STATUS:-0}"; }
mkdir -p "$tmp/runtime" "$tmp/payload-backup"
for file in ppnode geoip.dat geosite.dat geodata.lock; do printf 'old-%s\n' "$file" > "$tmp/payload-backup/$file"; printf 'new-%s\n' "$file" > "$tmp/runtime/$file"; done
restore_node_payload "$tmp/runtime" "$tmp/payload-backup" true
for file in ppnode geoip.dat geosite.dat geodata.lock; do cmp "$tmp/runtime/$file" "$tmp/payload-backup/$file"; done
grep -Fx 'restart PPanel-node.service' "$tmp/service-calls"
rm -f "$tmp/payload-backup/geoip.dat"
printf 'new geoip\n' > "$tmp/runtime/geoip.dat"
restore_node_payload "$tmp/runtime" "$tmp/payload-backup" false
[[ ! -e $tmp/runtime/geoip.dat ]]
grep -Fx 'stop PPanel-node.service' "$tmp/service-calls"
RESTART_STATUS=1
if restore_node_payload "$tmp/runtime" "$tmp/payload-backup" true; then exit 1; fi
unset RESTART_STATUS
python3 - "$here/../.github/build" <<'PY'
import json, pathlib, sys
root = pathlib.Path(sys.argv[1])
names = json.loads((root/'friendly-filenames.json').read_text())
rows = json.loads((root/'release-targets.json').read_text())['include']
assert len(rows) == 25
ids = set()
for row in rows:
    key = row['goos'] + '-' + row['goarch'] + row.get('goarm', '') + row.get('gomips', '')
    assert key == row['id'] and key not in ids and names[key]['friendlyName']
    ids.add(key)
PY
for script in "$here"/*.sh; do bash -n "$script"; done
ruby -e 'require "yaml"; ARGV.each { |path| YAML.parse_file(path) }' "$here"/../.github/workflows/*.yml
grep -F 'bash scripts/fetch-geodata.sh' "$here/../.github/workflows/ci.yml" "$here/../.github/workflows/release.yml" >/dev/null
grep -F 'RUN bash scripts/fetch-geodata.sh ./output/geodata' "$here/../Dockerfile" >/dev/null
grep -F '/usr/local/PPanel-node/' "$here/../Dockerfile" >/dev/null
grep -F 'geoip.dat geosite.dat geodata.lock' "$here/release-build.sh" "$here/install.sh" "$here/update.sh" >/dev/null
if grep -R 'raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/release/' "$here/../.github/workflows"; then
    echo 'workflow still uses mutable geodata release branch' >&2
    exit 1
fi
printf 'PASS: production release/geodata helpers, rollback, workflow YAML and shell syntax\n'
