# Developing P2PC

The toolchain is pinned in `rust-toolchain.toml`: `rustup` installs it (with `rustfmt` and `clippy`) on first use.
Rules and workflow are in [`CONTRIBUTING.md`](../../CONTRIBUTING.md).

## Build

```sh
cargo build --workspace
# The static helper injected into job sandboxes (needs: rustup target add x86_64-unknown-linux-musl)
cargo build -p p2pc-shim --target x86_64-unknown-linux-musl
```

## Test

```sh
cargo test --workspace
```

Tests are hermetic: no real network, no public relays, no container runtime. Anything that needs Podman is
`#[ignore]` and says how to run it on a test node.

### OpenAPI document

`docs/api/openapi.json` is generated from the server code (utoipa) and never edited by hand. The
`crates/p2pc-server/tests/openapi.rs` test fails when the committed file differs from what the code generates. After
changing an endpoint or an API type, regenerate it and commit the result:

```sh
P2PC_UPDATE_OPENAPI=1 cargo test -p p2pc-server --test openapi
```

### The template bundle in the hub

`p2pc-server` embeds the template bundle of its own build: `crates/p2pc-server/build.rs` compiles `templates/` with
`scripts/templates-bundle`, so a template that breaks a bundle rule stops the build. Two build-time variables,
both optional:

| Variable | Meaning |
|---|---|
| `P2PC_TEMPLATES_RELEASE` | Set (to anything but `0`) by a release build: a placeholder image digest stops the build. |
| `P2PC_RELEASE_PUBLIC_KEY` | The release key's public half, the base64 line of a minisign public key file. The hub verifies a newer bundle file in `<data>/templates/` against it. Without it the hub loads no bundle file and serves its embedded bundle only. |

No key is in the repository. Tests sign their bundles with a throwaway key made at test time.

## The agent's environment

`p2pc-agent` reads these environment variables (the flags and `agent.toml` win where they overlap):

| Variable | Meaning |
|---|---|
| `P2PC_AGENT_CONFIG` | The config file, when `--config` is not given. Default: `/etc/p2pc/agent.toml` as root, otherwise `~/.config/p2pc-agent/agent.toml`. |
| `P2PC_AGENT_SUPERVISED` | `1` when an installer (`install.ps1`'s Scheduled Task, `install-node.sh`'s systemd unit) starts the agent. `p2pc-agent join` then ends with "The installer starts the agent." instead of telling you to run `p2pc-agent run`. Any other value, or unset, keeps the default hint. The installers set it. |

## Run the server locally

```sh
# Creates the data dir (0700), server.toml and the database, and prints the admin key once.
cargo run -p p2pc-server -- init --data-dir /tmp/p2pc-dev
cargo run -p p2pc-server -- serve --config /tmp/p2pc-dev/server.toml
curl -H "Authorization: Bearer $P2PC_KEY" http://127.0.0.1:7477/v1/whoami
```

`init` also creates the server's iroh key (`server.key`, mode 0600; `serve` refuses a key that group or others can
read) and prints the server address `p2pc_srv_…` next to the admin key. `p2pc-server info --config <file>` prints the
NodeId and the address again. The node gateway is configured in `server.toml`:

```toml
[iroh]
relays = []                       # [] = n0's public relays (development); set your own iroh-relay URLs for production
direct_addresses = "default-route" # or "none" (relay only), or ["192.0.2.0/24", …]
tunnel_max_streams = 128          # p2pc/http/1 streams in total; must stay below [http] max_connections

[nodes]
lease_ttl_s = 60
heartbeat_interval_s = 5
min_agent_version = "0.1.0"
```

The endpoint never maps ports (iroh is built without `portmapper`), publishes to no discovery service, and binds
only the addresses `p2pc_proto::net::select_addresses` picks: never CGNAT/Tailscale, link-local or a container or VM
bridge.

The data dir is `$P2PC_DATA_DIR`, then `--data-dir`, then `$XDG_DATA_HOME/p2pc-server` or
`~/.local/share/p2pc-server`. `server.toml` rejects unknown keys. Database migrations live in
`crates/p2pc-server/migrations/` and are named `<UTC timestamp>_<description>.sql`, so that parallel branches never
clash on numbering.

## Lint

Run all of these before opening a PR (CI runs the same):

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo deny check          # licenses and advisories; needed when dependencies change
scripts/check-spdx.sh     # every .rs and .sh file starts with an SPDX header
```

## Layout

| Path | What |
|---|---|
| `crates/p2pc-proto` | API and protocol types (Apache-2.0) |
| `crates/p2pc-server` | Control plane, binary `p2pc-server` (AGPL-3.0-only) |
| `crates/p2pc-agent` | Node daemon, binary `p2pc-agent` |
| `crates/p2pc-cli` | CLI, binary `p2pc` |
| `crates/p2pc-shim` | Static helper for sandboxes, binary `p2pc-shim` |
| `scripts/` | Repo tooling |
