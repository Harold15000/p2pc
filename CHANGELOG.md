# Changelog

All notable changes to P2PC are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Before 1.0, a minor release (0.x) can include breaking
changes; they are listed under **Changed** or **Removed**.

## [Unreleased]

### Added

- H2 workspace scaffold: empty crates `p2pc-device` and `p2pc-wsl`, and placeholder directories `apps/desktop`,
  `apps/web`, `templates/`, `deploy/relay` and `deploy/web`. No behaviour change.
- Proto: the H2 JobSpec extension (`kind`, `service`, `volumes`, blob `inputs`, read-only `template`) with
  kind-dependent defaults and context-aware validation, the service view, principals, devices, pairing tickets, join
  requests, blobs, volumes, templates, the H2 scopes, audit kinds and error codes; the Python SDK models gain the
  matching response fields. H1 wire formats are unchanged.
- Proto: the H2 protocol types: the `p2pc/pair/1`, `p2pc/device/1` and `p2pc/invite/1` ALPNs, pairing tickets and
  invites, the hub, approval and node check phrases (BLAKE3, BIP-39 English list), the `p2pc/device/1` limits, and the
  agent capabilities, stream headers, messages and additive `Welcome`/`Heartbeat` fields (H2 §6.1).
- Server: paired devices as principals next to API keys (pairing tickets, device listing and revocation, `init
  --owner-device`, `devices add`, `devices revoke`), join requests with approval phrases, `pre_approved` join tokens,
  node approval, the H2 database tables and config keys. The database is migrated forward on first start. `GET
  /v1/whoami` gains `principal`, and join tokens list `created_by`, `pre_approved` and `bound_iroh_node_id`; `key_id`
  and `created_by_key_id` are `null` for a device.
- Server: the hub's iroh endpoint serves `p2pc/pair/1` (only while a pairing ticket is open) and `p2pc/device/1` (the
  REST API for paired devices, in-process, with its own stream budget), each under pre-auth limits (H2 §5.3, §6.3,
  §10.5).
- Server: service jobs (restart on node loss with a cap of 5 restarts in 24 h, health from agents, idle cancel, stop
  reasons, the wait for the node that holds a volume), agent capabilities in placement, the `kind` filter and the
  `service` view of `GET /v1/jobs/{id}`, the template view of the job routes for `templates:launch`, and `nodes:join`
  join tokens whose node gets no lease until an `admin` approves it.
- Server: `POST /v1/jobs/{id}/ports/{port}/connect` opens a connection into a port of a running service over an HTTP/1.1
  upgrade. Template services are reachable by non-admin principals only through their `allowed_routes`, one filtered
  HTTP request per connection. `GET /v1/jobs/{id}` shows today's `service.traffic`.
- Server: blobs (H2 §7.5): `POST`/`HEAD`/`DELETE /v1/blobs/{sha256}` and `GET /v1/blobs`, per-account storage with
  account and device quotas, a tombstone GC and a staging sweep; blob `inputs` on jobs; `BlobFetch` delivers them to
  agents.
- Agent: service jobs run in the same sandbox under H1's wall-clock limit, up to 30 days, with health checks
  (`starting`/`healthy`/`unhealthy`, stopped as `health_check_failed`), `ServiceHealth` reports, a 64 MiB log ring, and
  `used_cpu_ms`/`max_rss_mb` in heartbeats.
- Shim and agent: service ports through an ingress bridge. The agent listens on its own socket in the job's read-only
  `/.p2pc` mount and the shim dials it from inside the container, so the container keeps `--network=none` and the port
  never exists on a host interface. The agent serves the hub's `PortOpen` streams and its own health checks through it,
  and declares the `service_jobs` capability.
- Agent: persistent volumes for services and template jobs (H2 §11.3). New config keys `share.volumes_mb` (default 0:
  off) and `volume_retention_days` (default 30). Volumes are per-account, hash-named directories of the agent, mounted
  with `:U` after a no-follow check, held by one lease at a time, and reported with `VolumeReport`; `VolumeDelete`
  deletes one that no lease uses. New job errors `volume_unsafe` and `volume_limit`.
- Agent: `p2pc-agent status --json` (iroh NodeId before enrollment, node phrase, approval, hub version, pause), `share
  set` (live share changes and the owner's pause: refused leases answered `draining`, a resume reconnects), `leave`
  (bounded and confirmed), `Welcome.pending_approval` and `NodeApproved` handling, and the `BlobFetch` client (H2 §5.5,
  §6.1, §8.4, §8.7).
- `p2pc-wsl`: WSL checks, pinned image download with resume and SHA-256 verification, distro import and the "P2PC node"
  scheduled task, ported from `install.ps1` with a parity test.
- Desktop app shell (Tauri 2): tray with the H2 §8.4 states, single instance, start at sign-in (opt-out),
  DPAPI-protected device key, strict CSP and a capability limited to the app's own commands.
- Desktop app: first run (welcome with the opt-in update choice, checks with the elevated WSL install and its reboot,
  image download and import, the share with the disk arithmetic, "Create my cloud" with the hub's blob quota and a
  pre-approved token for the hub PC's own node, "Add my phone"), resumable from `setup.json`, with the H2 §8.8 errors
  and the mirrored-networking warning.
- Templates: the Private AI chat and Transcribe audio templates, and `templates-bundle`, the tool that checks, compiles
  and signs the template bundle (H2 §7.6).
- CLI and client: `p2pc service`, `blobs`, `volumes`, `templates`, `devices` and `nodes approve`, `run --input`, and the
  client calls behind them (H2 §7.8).
- MCP: new tool `p2pc_blob_put` (Unix only for now; reads only the `--upload-dir`, default `~/p2pc-uploads`, never
  through a symbolic link) and `inputs` by blob digest in `p2pc_run`/`p2pc_estimate`. Python SDK: `blobs.put`, job
  `inputs`, `services.run`/`connect`, `templates.list`/`launch`.

### Changed

- Hard rules 3 and 4 (CONTRIBUTING, H1 §9 and §10) each gain the one bounded H2 exception: agent-created per-account
  persistent volumes (ADR-015) and inbound iroh on the hub PC and a joining PC's relay-only invite listener (ADR-016),
  both now Accepted (O-16).
- Server: services are metered one UTC day at a time. Their usage is cut at every 00:00 UTC (with a catch-up at start),
  a capped principal's service reserves one day of its cap and is stopped with `cap_reached`, `spent(P, D)` counts each
  unit once, and `GET /v1/usage` counts finished attempts over slices, adds `estimated_slices`, and groups by `device`,
  `principal`, `kind` and `template` (H2 §12).
- WSL node image 0.3.0: the distro can host the hub.
  - `p2pc-run` replaces `p2pc-node-run` (kept as a symlink). It runs `p2pc-server` while
    `/var/lib/p2pc-server/hub.enabled` exists, with the REST listener on loopback only, enforced from the config and
    from `/proc`.
  - `install.ps1 -Upgrade` carries `/var/lib/p2pc-server`, after checking that the drives have room.
  - `p2pc-test-distro` checks that nothing of the distro listens on a non-loopback TCP address.
  - Each binary ships its `LICENSE` and `THIRD-PARTY-LICENSES`.

### Security

- RUSTSEC-2026-0462: upgraded `rmcp` to 3.9.0 (unbounded response buffering in its Streamable HTTP clients).
- RUSTSEC-2026-0459 (bundled SQLite in `libsqlite3-sys` 0.37): not yet fixed upstream for `sqlx`. The server opens only
  its own database, so the exposure is limited to restoring a database backup from an untrusted source: don't. The
  advisory is ignored in `deny.toml` until a `sqlx` release allows `libsqlite3-sys` 0.39.

## [0.1.0] - preview

First public release (milestone "Personal Cloud"): jobs run on machines you own. **Preview:** functional end to end,
not production-ready. The Python SDK in `sdk/python` has its own version and changelog.

### Added

- **Server.** `install-server.sh` installs the control plane (`p2pc-server`) as a hardened systemd service in one
  command, and prints the admin key once. The server keeps its state in SQLite and opens no port to the internet: its
  REST API listens on loopback, and clients elsewhere reach it through its server address (`p2pc_srv_…`) over an
  encrypted iroh tunnel.
- **Node enrollment** with a single-use token: `install-node.sh` on Linux (rootless Podman), and `install.ps1 -Join` on
  Windows 11 (a dedicated `p2pc-node` WSL2 distro). Tokens are never read from a command line. Machines connect outbound
  over QUIC (iroh), so they work behind NAT.
- **Jobs:** an OCI image, a command, and the CPU, memory, GPU, disk and time they need. Live logs, the job's exit
  code, and output files from `/outputs`, each checked against its SHA-256. Small input files (up to 512 KiB in all).
- **NVIDIA GPUs** on Linux and WSL2 nodes, through CDI (`--gpu 1`).
- **Best-fit scheduler:** each job goes to the machine it fits most tightly, so the big machines stay free for big
  jobs, and what does not fit anywhere waits in the queue. A job whose machine is lost is retried on another one, and a
  machine that comes back never runs a stale attempt.
- **Clients:** the `p2pc` CLI, the REST API (`docs/api/openapi.json`), the Python SDK, and an MCP
  server (`p2pc mcp`) for AI agents such as Claude Code.
- **Node controls:** each machine sets the share of its CPU, memory and GPUs it offers. `p2pc machines drain`, `resume`
  and `rm` from the CLI.
- **API keys:** scopes, an expiry, a daily cap in compute units and an image allowlist. The MCP server accepts
  only a capped, non-admin key by default (`--allow-admin` and `--allow-uncapped` override it, with a warning).
- **Usage:** `p2pc usage` shows what was reserved and used, per job, per machine or per key.
- **Sandbox:** all capabilities dropped, `no-new-privileges`, the default seccomp profile, no host paths except
  the job's own scratch directories, and limits on CPU, memory, PIDs, disk and time.
- **Egress:** no network by default. `--egress` names the domains a job may reach, through the agent's egress proxy,
  which always refuses loopback, private ranges, CGNAT (Tailscale included), link-local addresses and the host itself.
- **Reproducible release:** static (musl) Linux binaries, `SHA256SUMS`, SBOMs and the third-party license texts.
- **Windows downloads** are listed with their SHA-256 in `SHA256SUMS-windows`, published with the release.
- **No telemetry.**

### Known limitations

- **No macOS nodes.** A Mac can only be a client, with `p2pc` built from source.
- **A single server.** There is no high availability: if the server is down, no new jobs are placed.
- **Linux nodes run jobs in rootless containers, not VMs.** That is fine for your own jobs, and it is the reason
  running other people's code, and sharing your machines with others, is out of scope.
- **The egress proxy has residual risks,** for example a node that can never open its egress gate on some networks.
  They are listed in [`docs/security/residual-risks.md`](docs/security/residual-risks.md).
- **Binaries for x86_64 Linux only** in the release. The CLI builds from source on other systems.
- **By default the machines meet through n0's public iroh relays,** which are meant for development. They see only node
  IDs, timing and sizes, never a request, a key or a job. Set `relays` to use your own.
- **Inputs are small** (512 KiB in all, inline in the job): a job fetches bigger data itself, through its egress
  allowlist.
- **No checkpointing.** A job that loses its machine starts again from the beginning on the next one.

[Unreleased]: https://github.com/Harold15000/p2pc/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/Harold15000/p2pc/releases/tag/v0.1.0
