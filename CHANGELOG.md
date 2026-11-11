# Changelog

All notable changes to P2PC are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Before 1.0, a minor release (0.x) can include breaking
changes; they are listed under **Changed** or **Removed**.

## [Unreleased]

### Added

- H2 workspace scaffold: empty crates `p2pc-device` and `p2pc-wsl`, and placeholder directories `apps/desktop`,
  `apps/web`, `templates/`, `deploy/relay` and `deploy/web`. No behaviour change.

### Changed

- Hard rules 3 and 4 (CONTRIBUTING, H1 §9 and §10) each gain the one bounded H2 exception: agent-created per-account
  persistent volumes (ADR-015) and inbound iroh on the hub PC and a joining PC's relay-only invite listener (ADR-016),
  both now Accepted (O-16).

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
