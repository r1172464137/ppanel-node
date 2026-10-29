# Ordered node routing v1 — cutover-only

This node requires a complete ordered routing v1 policy in every JSON or
protobuf configuration response. Missing/null routing, unknown versions or
kinds, unknown/duplicate/case-variant JSON fields, missing `enabled`, invalid
references and mixed legacy fields fail closed. Reserved legacy `block`,
`block_ips`, `block_protocols`, `outbound` and embedded matching fields are
never compiled. New nodes do **not** support old panels: upgrade backend, node
and frontend together in a coordinated stop-the-world cutover.

Every configuration request carries `X-PPanel-Routing-Version: 1`. The
`protocols` JSON field must be present: `null` and `[]` both mean zero
protocols; missing or another type is invalid. Protobuf repeated protocols are
empty when absent. In both wires `total` must equal the number of protocols,
including disabled entries. Pull, push and user-monitor intervals accept `0`
for the existing 60-second default or `1..86400` seconds; all other values
are rejected before conversion. Required monitor/report tasks must start before
applied can advance. An enabled protocol unsupported by this node rejects the
candidate, rather than being reported as applied. Disabled unsupported
protocols are not started.

## Routing

Built-in `direct`/`block` map to the Xray `Default`/`block` tags. Custom
`ob_<UUIDv4>` IDs use a distinct stable tag namespace. The explicit
`default_outbound_id` determines Xray's first outbound. The UDP/53 system
rule stays first; each enabled business row becomes one single-kind rule in
array order. Disabled rows still undergo full format, budget and reference
validation. Xray's existing private-destination freedom security boundary is
not weakened by the builder.

Domain strategy remains `AsIs`: domain rules use the original or sniffed
domain, while IP rules use the target IP already in the routing context.
Values normalize to exact `full:`, `keyword:`, suffix `domain:`, RE2 `regexp:`,
`geosite:`, IP/CIDR, `geoip:` or the recognized `bittorrent` protocol. Raw and
canonical limits are 128 custom outbounds, 512 rules, 1024 input values per
row, 8192 total values, 4096 bytes per value, 256 KiB canonical match text,
and an inclusive 1 MiB serialized policy; response input is bounded to 2 MiB.

JSON and protobuf preserve existing connection fields, including inbound
`plugin`/`plugin_opts` and outbound ALPN, XHTTP, encryption, multiplex and
raw `settings`/`stream_settings`. Preservation does not imply support. An
**enabled Shadowsocks inbound** with plugin semantics is rejected: the node
does not run SIP003 plugins. Disabled protocols remain inactive.

The pinned Xray implementation's ordered-outbound capability matrix is:

| Protocol | Node behavior |
|---|---|
| direct/freedom, block/blackhole | Supported, including explicit safe custom settings |
| SOCKS | TCP and UDP, subject to the upstream SOCKS server |
| HTTP | TCP CONNECT only; UDP is not supported by Xray's HTTP outbound |
| Shadowsocks | TCP and native UDP; UoT and plugins are rejected |
| VLESS, VMess, Trojan, AnyTLS, Hysteria2 | Forwarding implemented; the configured transport, security and upstream must be compatible |
| TUIC | **Rejected before build/application**: both the outbound Process and TUIC transport dialer are unimplemented. TUIC inbound remains supported |
| WireGuard, custom DNS/loopback and unknown protocols | Rejected: not supported business outbounds in this node |

Raw settings cannot bypass the protocol/transport allowlist. Hysteria outbound
requires Hysteria transport, and the Hysteria transport is not accepted for
other outbound protocols. Non-default UoT/UoTVersion and nested raw UoT aliases
are rejected for every ordered inbound and outbound, including disabled inbound
entries and AnyTLS. AnyTLS's own native implementation may internally use UoT;
this is not a claim that the panel's UoT fields are consumed. Multiplex and unsupported encryption/plugins are
rejected rather than silently ignored. TLS ALPN and XHTTP mode/extra are
consumed; raw settings retain their explicit precedence. Raw settings and
nested XHTTP reject case-folding key collisions before Go/Xray struct decoding.
REALITY `spider_x`, transport paths and nested raw/XHTTP download settings are
parsed and checked before Xray's builder, which otherwise can panic on malformed
URI escapes. REALITY spider queries allow at most 32 unique parameters and a
4096-byte URI. The consumed p/c/t/i/r values must be nonnegative, ordered
integer or min-max pairs: p≤4096 bytes, c≤8 workers, t≤16 requests per worker,
c×t≤64, i≤30000 ms and r≤5000 ms. Duplicate, case-variant, malformed or
out-of-range parameters fail closed; the bounds reflect the pinned Xray
fallback's padding allocation, goroutine creation, request loops and sleeps.
These controls bound configuration-driven amplification, not arbitrary remote
response size: the pinned dependency still uses an unbounded `io.ReadAll`, has
no explicit fallback HTTP timeout and retains discovered fallback paths. A
hostile REALITY fallback server remains a separate upstream memory/availability
risk; use trusted targets until that implementation is bounded.

## Node DNS

Node DNS supports **classic UDP only**. `proto` is normalized by trimming and
lowercasing: empty and `udp` mean canonical `udp`; `tcp`, `tls`, `https`,
`quic` and all other values are rejected. `server_name` must be exactly empty;
there is no DNS-over-TLS SNI support. `address` is an ASCII hostname (IDNA
A-labels are valid), IPv4 or IPv6 literal, optionally followed by a numeric
port in `1..65535`; omission means port 53. Use `[IPv6]:port` for an IPv6
address with a port. Schemes, userinfo, paths, whitespace, scoped IPv6 and
malformed addresses/ports are rejected. Four-component numeric strings that
look like malformed IPv4 are not treated as hostnames. Bare `localhost` and
`fakedns` are represented as absolute hostnames with a trailing dot so Xray
does not interpret them as its special local/fake DNS modes and ignore the
configured UDP port. DNS `domains` retain the same domain-rule normalization.

The existing resolver ordering is unchanged: the system `localhost` resolver
is first, while matching `domains` can prioritize a configured resolver.
Without matching domains a custom resolver is a fallback, not a guaranteed
replacement for system DNS. DNS dispatch still follows Xray routing and its
UDP/53 system behavior; the chosen business default/outbounds must permit the
resolver to be reached. Invalid DNS candidates are rejected before core and
listener cutover, without advancing ETag or applied status.

## Candidate ownership and status

Observations, pending candidates and applied configurations are separate. The
latest observation survives an A→B→A race while B is starting. Only a new core
and all required listeners successfully starting commit ETag/hash/applied;
304 and identical bodies never discard an outstanding candidate. Bad
candidates retry with bounded backoff, newer candidates replace them, and a
failed rollback clears the applied receipt. The new core's monitor starts with
an immediate recheck so a fenced, retired in-flight fetch cannot delay observing
new panel content until the next pull interval. Startup retries re-read the local
configuration and recreate the panel client so a corrected host/secret takes
effect without restarting the process. An API timeout change rebuilds its HTTP
transport while sharing candidate/ETag state for the same server identity.
API timeout is `0` for 30 seconds or `1..86400` seconds. Logging and pprof
initialize only from the first successfully applied local configuration;
logging changes apply on successful reload, while pprof port changes require a
process restart and never open a second listener.

One server-level reporter operates before core startup, with zero protocols,
and during rollback failure. Each process generates a random UUID instance ID
once and retains it across client recreation and reload. Status sends only
validated identities for this server and bounded, redacted errors. Periodic
fetch failures, including 426, invalid protobuf/JSON and oversized responses,
wake the reporter; a successful fetch clears the fetch error.

`QueryServerProtocolConfigData.routing` is protobuf tag 12 and `Outbound.id`
is tag 44. `RouteRule.enabled` is optional tag 2. Server status JSON uses
`routing_version`, `routing_applied`, `routing_pending`, `routing_error`,
`instance_id` and `routing_sequence`; protobuf `PushServerStatusRequest` uses
tags 5–10 respectively (`routing_sequence` is `uint64`, positive and monotonic
within the process). A per-server process-wide publication fence atomically
captures the state, allocates its sequence and checks the client generation;
retired clients and their certificate heartbeats cannot publish over a newer
applied generation, even when the API host or secret changed. An older request
already in flight retains its lower sequence. `RoutingIdentity` uses tags 1–5
for mode/source/source_server_id/source_revision/local_transition_revision;
`RoutingError` uses identity/stage/message at 1–3. The status stage vocabulary
is `fetch`, `validate`, `build`, `core_start`, `prepare`, `stop`, `bind`,
`restore`; local config and monitor failures map to `validate` and `prepare`
respectively, matching the backend's currently accepted values. Server status
requests have no protocol query parameter. The backend must order by instance
ID and sequence; its receive time is for TTL only, not ordering. Cross-instance
conflicts and freshness require backend support before deployment.

## Local test evidence

The real Router tests require the production geodata pinned in
`.github/build/geodata.lock`, available at `output/release-geodata/` or via
`PPNODE_TEST_GEODATA`; missing/mismatched fixtures fail rather than skip. They
prove both `google-cn` and `cn` membership of `www.gstatic.com` and opposite
route decisions under reversed order. The local data-plane tests use a real
HTTP client, actual VLESS node listener, certificate-verified local HTTPS
server, controlled direct/SOCKS paths and an authenticated local panel fixture.
One isolated-process test exercises the unchanged built-in direct outbound: a
controlled dialer maps a public test destination to the local HTTPS server only
after Freedom's private-IP check; the test also proves private IPs remain
blocked. Another test uses an explicit custom freedom exception scoped to the
test HTTPS IP and port. Neither change is part of production configuration.
The reverse-order test uses an observable custom outbound as default, verifies
post-reload health through the same listener/outbound, then observes the actual
dispatch's stable rule ID and block tag rather than a synthetic router query.
A trusted local TLS/H2 server also exercises the real Xray REALITY fallback:
unsafe spider candidates never connect, while a bounded positive control emits
the expected padding receipt. Separate tests cover native Shadowsocks UDP,
AsIs/sniffing, rollback, race-free limiter updates, zero protocols and the
A→B→A race.
