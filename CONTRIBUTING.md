# Contributing to P2PC

P2PC turns the machines you own into a private compute cloud with a single Jobs API. You submit a job (OCI image,
command and resources) from the REST API, the CLI, the Python SDK or MCP, and it runs in a sandbox on one of your
machines. Nodes open no ports: agents connect outbound to the control plane.

This repository is public, so everything in it must be publishable. The scope and architecture of v0.1 are defined in
`docs/specs/H1-personal-cloud.md`. The spec is authoritative. Decisions are recorded in `docs/adr/README.md`.

These rules apply to every contributor, human or AI coding agent.

## Stack

- Rust, pinned in `rust-toolchain.toml` (edition 2024). Workspace crates:
  - `p2pc-proto`: shared types and the agent protocol.
  - `p2pc-server`: the control plane, built on axum, sqlx (SQLite) and utoipa (OpenAPI).
  - `p2pc-agent`: the node daemon.
  - `p2pc-cli`: the `p2pc` binary, which includes the MCP server over stdio.
  - `p2pc-shim`: a small static helper that runs inside job sandboxes.
- Agent ↔ control plane networking: iroh 1.x (QUIC, NAT traversal, relays).
- Python SDK in `sdk/python` (Python >= 3.11, managed with `uv`).

## Commands

- Format: `cargo fmt --all --check`
- Lint: `cargo clippy --workspace --all-targets --all-features -- -D warnings`
- Tests: `cargo test --workspace`
- Licenses and advisories: `cargo deny check`
- Python SDK: `uv run --project sdk/python pytest`

If your environment runs `cargo` through a wrapper that serializes builds, a build may wait for a lock. That is
expected: do not work around it.

## Layout (target for v0.1)

- `crates/<name>/`: Rust crates.
- `sdk/python/`: Python SDK.
- `docs/specs/`: specs (maintainers only).
- `docs/adr/`: decision records (maintainers only).
- `docs/api/openapi.json`: generated from the server. Never edit it by hand.
- `deploy/`: systemd units, install scripts and the WSL image builder.
- `tests/acceptance/`: end-to-end acceptance tests.

## Licensing

- `crates/p2pc-server` is **AGPL-3.0-only**. Everything else is **Apache-2.0**. Each crate declares its `license`
  in `Cargo.toml`.
- Every source file starts with an SPDX header, for example `// SPDX-License-Identifier: Apache-2.0`.
- Dependencies must be permissive. The allowlist is in `deny.toml`, and `cargo deny check licenses` must pass.
- Never copy code from GPL, AGPL or LGPL projects. Never paste code from any project without a compatible license
  and attribution.
- This includes our own server: never copy code from `crates/p2pc-server` into an Apache-2.0 crate. If the agent,
  the client or the CLI needs the same logic, move it to a shared Apache-2.0 crate (`p2pc-proto`, `p2pc-net`), and
  have the server use it from there.

## Hard rules (non-negotiable; breaking one is a P1 in review)

1. **Untrusted code runs only in a VM-class sandbox.** v0.1 runs only the node owner's own jobs, in an OCI sandbox
   (rootless Podman). The agent must reject a job whose owner is not the node's owner, and must reject a job that asks
   for a sandbox class the node cannot provide. Do not add a path that relaxes this.
2. **Sandboxes have no network by default.** Egress is allowed only through the agent's egress proxy, with an
   allowlist. The proxy resolves DNS itself and **always** refuses:
   - loopback;
   - RFC 1918 ranges;
   - CGNAT `100.64.0.0/10` (this includes Tailscale);
   - link-local (`169.254.0.0/16`, `fe80::/10`);
   - IPv6 ULA `fc00::/7`;
   - multicast;
   - the host's own addresses.

   A job must never reach the owner's LAN, the host's services or a tailnet.
3. **Sandbox hardening is not optional:**
   - rootless on Linux, or root inside the dedicated WSL2 distro with `--userns=auto` on Windows (spec §9.0);
   - all capabilities dropped, `no-new-privileges` and default seccomp;
   - no `--privileged`;
   - no container-runtime socket and no host paths mounted, except the per-job scratch directories the agent creates;
   - limits on CPU, memory, PIDs, disk and wall-clock time.
4. **Nodes never listen on the network** by default. Agents only connect outbound.
5. **Secrets:**
   - API keys and enrollment codes are stored only as hashes and shown once.
   - Never put secrets in logs, errors, panics, test fixtures or the repo. Use `secrecy` or redaction.
   - Job environment values are never logged.
6. **No telemetry and no phoning home** unless the user explicitly enables it.
7. **Public-repo hygiene:** no personal data, real hostnames, IPs, tailnet names or internal business documents. In
   examples and tests, use `example.com` or `example.invalid` for names, and `192.0.2.0/24`, `198.51.100.0/24` or
   `2001:db8::/32` for addresses.
8. **Windows (WSL):** the agent's distro never uses `/mnt/c` or Windows interop. Never add code that reads or writes
   the Windows filesystem.

## How we work

1. Each task gets its own branch (`feat/…`, `fix/…`, `chore/…`), created from `origin/main` in its own worktree.
   - **Never `git stash`**: the stash is shared between worktrees.
   - **Never push to `main`**.
   - AI coding agents do not push: a maintainer publishes their branch.
2. **Tests first** when there is logic: write the test, watch it fail, implement, watch it pass.
3. Before reporting done, the format check, clippy and the tests above must pass. Summarize their output in the PR,
   including the number of tests.
4. Commits:
   - small, in English, in Conventional Commits style (`feat:`, `fix:`, `test:`, `docs:`, `chore:`);
   - signed off with `git commit -s` (DCO, see below);
   - files added **by name**: never `git add -A`, `git add .` or `git commit -a`.
5. **Independent review is mandatory.** It is done by someone other than the author, using the `p2pc-review` guide in
   `.claude/skills/p2pc-review/SKILL.md`. Nothing is merged while P1 or P2 findings are open.
6. Maintainers merge with merge commits, never squash.
7. **Shared types grow; other crates must not break.** Several tasks change `p2pc-proto` in parallel, and fields are
   added to its types.
   - Outside `p2pc-proto`, build its structs through a constructor or with `..Default::default()`, in tests and
     helpers too. Do not use full struct literals that break when a field is added.
   - Derive `Default` on a `p2pc-proto` type when there is a sensible empty value.
8. **Fake secrets in tests and docs.** Make them obviously fake, for example by using `example.invalid` hosts, and
   put a `gitleaks:allow` comment on the same line. The secret scan (AC-12) runs over the whole history.
   `.gitleaksignore` holds only findings the maintainers have reviewed; never add to it yourself.
9. If something is missing (access, a secret, a decision) or the spec is ambiguous, say so and stop:
   - never fake data;
   - never weaken a test to make it pass;
   - never edit a spec to match your code.

## Automatic guards for AI agents

`.claude/settings.json` and `.claude/hooks/guardia.mjs` (messages in Spanish) block the following:
- `git stash`;
- any push to `main`, and forced, bulk or delete pushes;
- merging PRs, and `cargo publish`;
- reading or writing real `.env` files and the machine's secret paths, and dumping the environment;
- editing the protected files listed in `.claude/guardia.json` (this guide, the licenses, `deny.toml`, `SECURITY.md`,
  the review guide, the specs and the ADR index);
- editing the guard itself.

After each shell command, the guard uses git to check that nothing protected changed. When a guard fires, follow its
instruction literally, and if it says stop, stop and explain. Never work around a guard.

Tests for the guard itself: `node .claude/hooks/probar-guardia.mjs`.

## Developer Certificate of Origin

Every commit must be signed off (`git commit -s`). By signing off you certify the
[Developer Certificate of Origin 1.1](https://developercertificate.org/): you wrote the change, or you have the right
to submit it under the license of the files it touches.
