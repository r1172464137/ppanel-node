#!/usr/bin/env bash
# Build one existing friendly-name release target. Geodata is fetched once by CI.
set -euo pipefail
: "${VERSION:?set VERSION without leading v}"
: "${GEODATA_DIR:?directory with geoip.dat, geosite.dat and geodata.lock}"
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
source "$here/fetch-geodata.sh"
verify_geodata_bundle "$GEODATA_DIR" "$GEODATA_DIR/geodata.lock"
os=${1:?goos}; arch=${2:?goarch}; arm=${3:-}; float=${4:-}
out=${RELEASE_OUT:-output/release}
key="$os-$arch$arm$float"
name=$(jq -er --arg key "$key" '.[$key].friendlyName // error("unsupported release target")' .github/build/friendly-filenames.json)
asset="ppanel-node-$name"
[[ ! -d $out/package/$asset ]] || rm -rf "$out/package/$asset"
mkdir -p "$out/package/$asset"
flags="-s -w -buildid= -X github.com/perfect-panel/ppanel-node/cmd.version=$VERSION"
if [[ $os == android ]]; then flags+=' -checklinkname=0'; fi
ext=''; [[ $os != windows ]] || ext='.exe'
CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" GOARM="$arm" GOMIPS="${float:-hardfloat}" go build -trimpath -ldflags "$flags" -o "$out/package/$asset/ppnode$ext" .
cp README.md LICENSE "$out/package/$asset/"
cp conf/config.yml.example "$out/package/$asset/config.yml"
cp scripts/install.sh scripts/ppnode.sh scripts/update.sh "$out/package/$asset/"
for file in geoip.dat geosite.dat geodata.lock; do
    test -s "$GEODATA_DIR/$file"
    cp "$GEODATA_DIR/$file" "$out/package/$asset/$file"
done
(cd "$out/package/$asset" && zip -q -9 "../../$asset.zip" ./*)
