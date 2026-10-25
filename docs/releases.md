# Fork releases and safe updates

Distribution source: **r1172464137/ppanel-node**, never an implicit fallback to upstream.
The module stays on Go 1.27.1; release builds use Go **1.27.3** with `CGO_ENABLED=0`
and `-X github.com/perfect-panel/ppanel-node/cmd.version=1.1.14` for tag `v1.1.14`.

## Update an existing production node to v1.1.14

Run this command **on the node host**, using your own authorized access. No panel
change can upgrade the executable on that host. It requires root, Linux, curl,
GNU sha256sum, unzip and systemd. It supports amd64, arm64 and s390x installers.

```bash
sudo bash -c 'set -euo pipefail; d=$(mktemp -d); trap "rm -rf \"$d\"" EXIT; cd "$d"; b=https://github.com/r1172464137/ppanel-node/releases/download/v1.1.14; curl --proto "=https" --tlsv1.2 -fsSL --retry 3 "$b/update.sh" -o update.sh; curl --proto "=https" --tlsv1.2 -fsSL --retry 3 "$b/SHA256SUMS" -o SHA256SUMS; sha256sum --check --ignore-missing SHA256SUMS; bash update.sh v1.1.14'
```

The command verifies the updater before executing it. The updater then verifies
`ppanel-node-linux-64.zip` (amd64), `ppanel-node-linux-arm64-v8a.zip` (arm64), or
`ppanel-node-linux-s390x.zip` against the same release's SHA256SUMS. Missing,
duplicate, malformed or mismatched archive checksums fail closed.

The updater:

1. Requires existing `/usr/local/PPanel-node/ppnode`, `/etc/PPanel-node/config.yml`
   and `PPanel-node.service`; it is not an installer.
2. Downloads and verifies before any service changes, then checks the new binary's version.
3. Backs up **only the current binary** beside it as `ppnode.before-v1.1.14-<UTC>-<pid>`.
4. Atomically replaces the binary and restarts **only `PPanel-node.service`**.
5. Requires a stable, active MainPID whose `/proc/<pid>/exe` resolves to the exact
   installed binary, has the same bytes, and reports `PPanel-node 1.1.14`.
6. On failure, restores the binary atomically and restarts the prior service (or
   returns it to stopped if previously inactive). Failures remain nonzero; if the
   rollback restart fails it prints an explicit warning and the backup path.

It does **not** write config, certificate/geodata files or the unit file, invoke
`daemon-reload`, re-register the service, wipe state, or kill unrelated processes.
This is binary-only: it also deliberately leaves an old management script alone.
**Do not use an old `ppnode update`/`update_shell` command that still downloads
perfect-panel upstream.** Reuse the verified command above, or separately adopt
this release's verified `ppnode.sh` manager and bundled `install.sh` helper.
The new manager defaults to the fork, verifies release checksums, and its `update`
command invokes the narrow updater. `PPNODE_RELEASE_REPO=owner/repo` is an explicit
operator override; no fallback repository is tried.

## New installations

Use the same verified command, replacing both `update.sh` occurrences and the final
invocation with `install.sh`. The installer supports systemd or OpenRC. Optional
arguments: `--api-host URL --server-id ID --secret-key KEY` (all three together).
It never overwrites an existing `/etc/PPanel-node/config.yml`. Unlike the updater,
it intentionally creates/refreshes the service and management files. Repository
overrides are persisted as plain data in `/etc/PPanel-node/release-repo` for the
manager; they are never evaluated as shell code.

Nonprivileged download/verification only:

```bash
PPNODE_RELEASE_REPO=r1172464137/ppanel-node bash scripts/install.sh v1.1.14 --download-only ./verified-download
```

## CI and asset contract

`.github/workflows/release.yml` publishes on pushed `v[0-9]*` tags, validated as
`vX.Y.Z` (optionally a prerelease suffix). `workflow_dispatch` accepts an existing
`release_tag` for recovery. Build failures prevent publication; a rerun rebuilds
all assets and replaces the release manifest consistently. `GITHUB_TOKEN` with
`contents: write` is sufficient. No PAT or Docker Hub credentials are used.

The existing platform matrix is kept in `.github/build/release-targets.json`;
friendly ZIP names are from `.github/build/friendly-filenames.json`. It includes
Linux, Windows, macOS, FreeBSD and Android targets plus MIPS soft-float variants.
Android keeps its required `-checklinkname=0`. Every ZIP contains its binary,
LICENSE, README, `config.yml`, verified-release management/installer/update scripts,
and geodata. Geodata is fetched and checked once per release before fan-out.
Release-level assets also include `install.sh`, `ppnode.sh`, `update.sh`, `config.yml`
and a single SHA256SUMS over every archive and script/template.

The optional Docker workflow is separate (manual or a user-published Release,
read-only builds on PRs). A Release created with GITHUB_TOKEN does not recursively
trigger other workflows; manually dispatch the optional image workflow if wanted.
It uses Go 1.27.3 and only GITHUB_TOKEN for GHCR publication.

Local checks (no live installation or real node fixtures):

```bash
bash scripts/test-release.sh
# Production checksum/version/MainPID/rollback helpers are tested with local mocks.
go test -race ./api/panel ./core/inbound ./core -run 'TestRealityXver|TestValidateServerConfig' -count=1
```
