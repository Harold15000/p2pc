# deploy/relay

The container image and configuration for running [`iroh-relay`](https://docs.rs/iroh-relay) 1.4.1 on a platform that
only offers HTTP(S) and WebSockets (H2 spec §10.2), and the relay-map rules every P2PC endpoint follows with it (§10.3).
The relay holds no user data: it forwards end-to-end encrypted traffic between iroh endpoints and cannot read it. Anyone
can run their own.

| File | What it is |
|---|---|
| `Dockerfile` | Builds `iroh-relay` 1.4.1 (`cargo install iroh-relay --version 1.4.1 --features server --locked`) on a pinned Rust image and runs it on a pinned Debian slim image, as `nobody`. |
| `relay.toml` | The relay's config, as measured in experiment E12 (below). `$PORT` is its one placeholder. |
| `entrypoint.sh` | Replaces `$PORT` with the platform's port (1-65535, refused otherwise), then runs `iroh-relay --config-path` on the result. |
| `railway.toml` | Railway's config as code: build from the `Dockerfile`, health check on `/ping`. |

`deploy/tests/test-relay.sh` checks all four (run by `deploy/check.sh`).

## What this relay does, and does not

- **Plain HTTP behind the platform's TLS edge.** Without a `tls` section, `iroh-relay` serves every relay service (the
  relay itself and its `/ping` probe route) over plain HTTP on `http_bind_addr`. The platform terminates TLS, forwards
  WebSockets over HTTP/1.1, and does not close idle WebSocket connections. Clients use `https://relay.<domain>/`, which
  browsers reach as `wss://`.
- **It relays only.** QUIC address discovery needs TLS and UDP on the relay, and an HTTP-only platform has no UDP, so
  `enable_quic_addr_discovery = false`: this relay never tells an endpoint its public address. A P2PC node needs that
  address to open its egress gate (H1 §9), so **a node's relay map must also hold a relay that offers address
  discovery** (see [Relay maps](#relay-maps)).
- **Open, with limits.** `access = "everyone"`: pairing makes phones unknowable in advance, so any NodeId may relay.
  The cost is bounded by the limits below, the platform's spending cap and an alert on egress volume.
- **No metrics, no telemetry.** `enable_metrics = false`: nothing listens beyond the relay's port, and nothing is sent
  anywhere.

### The config (E12)

| Setting | Value | Why |
|---|---|---|
| `enable_relay` | `true` | |
| `http_bind_addr` | `"[::]:$PORT"` | The platform's port, on every address of the container. |
| `enable_quic_addr_discovery` | `false` | No UDP on the platform. |
| `enable_metrics` | `false` | Metrics only on a private port or off (§10.2): off. |
| `access` | `"everyone"` | Any NodeId (§10.2). |
| `limits.accept_conn_limit` / `accept_conn_burst` | `10.0` / `40` | New connections per second, and the burst. |
| `limits.client.rx.bytes_per_second` / `max_burst_bytes` | `4194304` / `16777216` | Per client: 4 MiB/s steady, bursts of 16 MiB. |

With this config, E12 connected native and WebAssembly clients through the relay, relay-only: p50 81 ms, and 50 MB in
9 s.

## Build and try it locally

```sh
podman build -t p2pc-relay deploy/relay           # or: docker build
podman run --rm -e PORT=3340 -p 127.0.0.1:3340:3340 p2pc-relay
curl -i http://127.0.0.1:3340/ping                 # HTTP/1.1 200 OK
```

A relay on loopback over plain `http` is a development relay: `p2pc-net` accepts `http://localhost:3340/` in a node's
relay list (and nothing else over plain `http`), never in the hub's.

## Deploy on a PaaS with HTTP only (Railway)

These steps use Railway, the first target; any platform that runs a Dockerfile, sets `PORT`, terminates TLS and
forwards WebSockets works the same way.

1. **Create a service from this repository** (or your fork). In the service's settings, set the **root directory** to
   `deploy/relay`: the platform then builds `deploy/relay/Dockerfile` and reads `deploy/relay/railway.toml`.
2. **Port.** The platform sets `PORT`; the entrypoint binds the relay to it. Do not set `PORT` yourself, and do not
   publish any other port. The image refuses a `PORT` that is not a port number rather than fall back to port 80.
3. **Health check.** `railway.toml` sets it to `/ping`, the relay's plain HTTP probe route, which answers `200`.
4. **Domain.** Attach your own domain, `relay.<domain>` (owner decision O-2), and let the platform issue its
   certificate. Avoid publishing the platform-generated domain: relay URLs end up in pairing tickets, configs and the
   web app's CSP, and changing one later means a release (below).
5. **Cost and abuse** (owner decision O-3). Set the platform's **spending cap** and an **alert on egress volume**. The
   relay's own limits are in `relay.toml`; the traffic is end-to-end encrypted, so nobody can inspect it.
6. **Check it** from any machine:

   ```sh
   curl -sI https://relay.example.com/ping          # 200
   ```

   and, on a node that uses it, `p2pc-agent doctor`: every relay is listed with its reachability, its latency and
   whether it offers address discovery.

No account name, project, token or private URL belongs in this directory: a self-hoster follows the same steps with
their own.

## Alternative: a host with UDP

On a host with a public address (a VPS, for example) that can accept TCP 80 and 443 and UDP 7842, run the same
`iroh-relay` **with TLS**, and the relay also offers QUIC address discovery. Such a relay can stand in for n0's relays
in a node's map. Build it the same way (`cargo install iroh-relay --version 1.4.1 --features server --locked`) and run
`iroh-relay --config-path relay.toml` under a service manager, with a config such as this one (with TLS, the relay
services move to `https_bind_addr`, and `http_bind_addr` keeps only the captive-portal check):

```toml
enable_relay = true
http_bind_addr = "[::]:80"
enable_quic_addr_discovery = true
enable_metrics = false
access = "everyone"

[tls]
# A certificate from Let's Encrypt for `hostname`, which must resolve to this host; or `cert_mode = "Manual"` with
# `manual_cert_path` and `manual_key_path`.
cert_mode = "LetsEncrypt"
hostname = "relay.example.com"
contact = "relay-admin@example.com"
https_bind_addr = "[::]:443"
quic_bind_addr = "[::]:7842"

[limits]
accept_conn_limit = 10.0
accept_conn_burst = 40

[limits.client.rx]
bytes_per_second = 4194304
max_burst_bytes = 16777216
```

Open TCP 80 and 443 and UDP 7842 in the host's firewall.

`p2pc-net` cannot tell from a URL whether a self-hosted relay offers address discovery, so with only your own relay in
a node's map, `p2pc-agent doctor` still warns that no relay offers it; `p2pc-agent status` shows whether the egress
gate actually opened.

## Relay maps

Every P2PC endpoint has a relay map: the relays its iroh endpoint uses. `p2pc-net` validates them
(`p2pc_net::relays::check_relay_map`); the agent logs what it finds at start, and `p2pc-agent doctor` shows it.

- **Every entry** is `https://<host>/`: no credentials, path, query or fragment (iroh always dials `/relay` on the
  host). Plain `http` is only for a development relay on loopback. An IP address must be a public one.
- **Nodes (agents, and the desktop app's endpoint)** need at least one relay that offers QUIC address discovery, or
  every job with internet access fails with `egress_unavailable`; doctor then says "jobs with internet access will not
  start: no relay offers address discovery". The official map is **n0's public relays plus this HTTP relay**. n0's
  relays (iroh 1.4.1's default map, all under `relay.n0.iroh.link`) are, in an agent's `agent.toml`:

  ```toml
  [iroh]
  # `[iroh] relays` replaces the join token's relays: list the hub's relay too.
  relays = [
    "https://relay.example.com/",
    "https://use1-1.relay.n0.iroh.link./",
    "https://usw1-1.relay.n0.iroh.link./",
    "https://euc1-1.relay.n0.iroh.link./",
    "https://aps1-1.relay.n0.iroh.link./",
  ]
  ```

- **The hub** is reached by phones through its home relay, and iroh picks the home relay from the whole map by
  latency, so **every** relay of the hub's map must be an `https` DNS name that browsers reach and that the web app's
  CSP allows (`connect-src`, H2 §9.5; `P2PC_WEB_RELAYS` for a self-built web app). In the official deployment the
  hub's map is this relay only; agents dial the hub through it whatever their own home relay is.
- **Beta:** every endpoint uses n0's relays, and the official web app's CSP allows them.

## Changing the relay or updating the image

- **A new relay URL** reaches paired phones the next time they connect through a relay that still works (§10.2): keep
  the old relay running for one release after a change.
- **A newer `iroh-relay`**: change the version in the `Dockerfile` and in `deploy/tests/test-relay.sh`, and run E12's
  checks again.
- **Newer base images**: take the digest of the tag's multi-platform index, for example with
  `skopeo inspect --raw docker://docker.io/library/debian:trixie-slim | sha256sum` or from the
  [docker-library/repo-info](https://github.com/docker-library/repo-info) repository, and replace it in the `FROM`
  line. Keep the Rust image's version equal to `rust-toolchain.toml`'s.
