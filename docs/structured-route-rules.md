# Structured route rules

PPNODE accepts the additive JSON/protobuf route-rule fields while retaining the
legacy domain fields (`block` and `outbound.rules`). Missing additive fields are
empty, so responses from an older panel remain compatible.

## Accepted grammar

Rule prefixes are case-insensitive and normalized to Xray's canonical values:

- `example.com.`, `full:example.com` and `FULL:example.com.` -> `full:example.com`
- `keyword:tracker` -> `keyword:tracker`
- `suffix:example.com` and backend-canonical `domain:example.com` -> `domain:example.com`
- `regex:...` and `regexp:...` -> `regexp:...`
- `geosite:category-pt` remains unchanged

Exact/full/suffix/domain values trim one terminal DNS root dot and otherwise
must be valid ASCII host names. Repeated/internal dots, malformed labels,
whitespace, IP addresses, CIDRs and case-insensitive `bittorrent` are rejected
with category guidance. `keyword:` is non-empty and rejects whitespace/control
characters, while `keyword:bittorrent` remains a legitimate explicit domain
matcher. Regular expressions are accepted only when Go's RE2 `regexp.Compile`
accepts them; textual inspection is intentionally not used because it rejects
valid quoted literals, character classes and octal escapes. GeoSite and GeoIP
labels use the shared restricted patterns. CIDRs are masked to their canonical
network prefix. Protocol values are case-insensitive and canonicalize to
`bittorrent`; no other protocol is accepted.

## Bounds and compatibility

The shared canonical contract permits at most 1024 unique canonical values per
category, 4096 bytes per canonical rule, 128 structured outbounds, and 4096
canonical structured block+outbound rules totaling at most 48 KiB. DNS resolver
domain lists use the same grammar/per-category limit but are intentionally not
part of the structured route aggregate.

Separately, PPNODE applies node-only pre-normalization DoS bounds of 4096 raw
entries per category and 8192 raw structured block+outbound entries. Duplicates
within those raw bounds are deduplicated before canonical limits are applied.

Rule parsing happens before outbound protocol support is checked. Therefore an
invalid rule on an obsolete or unsupported outbound fails configuration
building instead of being silently ignored. This fail-closed behavior is
intentional; valid unsupported outbounds continue to be skipped as before.

## Protocol evidence limits

The core data-plane test sends a valid TCP BitTorrent handshake through a
sniffing inbound and proves selection of a controlled SOCKS outbound. It also
sends the exact µTP v1 ST_SYN shape recognized by the bundled Xray sniffer.
This is evidence for those recognizable protocol headers only; arbitrary UDP,
DHT traffic, encrypted BitTorrent, and obfuscated transports are not claimed to
match.
