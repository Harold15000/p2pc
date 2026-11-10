# Milestone 2 · P2PC Desktop App and Phone Access (v0.2): specification

- **Status:** draft for review (spec v9, 2026-11-10: v8 plus the fixes of its ninth review). Implementation starts
  when the architect marks it accepted. The two hard-rule exceptions it proposes (persistent volumes, ADR-015; inbound
  iroh connections on the hub PC, ADR-016; both in §4.3) take effect only through one separate change after that
  (O-16); until then the tasks that need them are blocked (§17).
- **Owner:** the P2PC architect. Only the architect changes this file. Implementers who find a problem report it in
  their PR instead of editing the spec.
- **Normative words:** MUST, SHOULD and MAY are used as in RFC 2119.
- **Builds on:** `docs/specs/H1-personal-cloud.md` (v0.1, released). Section references written as "H1 §N" point there.
  Everything in H1 stays in force unless this document changes it explicitly; §4.3 lists every change.
- **Facts and guesses.** External facts carry a source tag (`[S1]`, …) that resolves in §19. Numbers marked **(H)**
  are estimates or hypotheses, to be confirmed by the experiment named next to them (§18).

## 1. Goal

**A non-technical person turns their own Windows PCs into a private cloud, and uses it from their phone.**

- They install a desktop app on a Windows 11 PC in **at most 5 minutes, with at most 1 reboot**. The app sets up the
  H1 pieces (the `p2pc-node` WSL2 distro, the agent and, on the first PC, the hub) without a terminal.
- They choose how much of each PC to share (CPU, RAM, GPU), and can pause, resume or stop sharing at any time.
- They open the P2PC web app on their phone, pair it with a QR code, and use their own PCs from anywhere. The first use
  case is a **private AI chat running on their own GPU**; the second is **transcribing an audio file** recorded on the
  phone.
- Nothing is exposed on the internet or the LAN. The phone reaches the hub through a relay, end-to-end encrypted, and
  the services that jobs run are reachable only through that authenticated tunnel.

Developers keep everything from H1: the REST API, the CLI, the Python SDK, the MCP server, Linux nodes and a
self-hosted server. H1 users who never install the app see only additive changes.

**Target:** a beta for trusted testers about 4-6 weeks after this spec is accepted, with AI-assisted development
**(H)**. The beta is not a public release: §14.5 lists what stands between the two.

## 2. User stories (what "done" means)

Personas: **Ana** is not technical; she has a gaming PC with an NVIDIA GPU, a laptop and an iPhone. **Dev** is an H1
user.

- **U1 · Install.** Ana downloads `P2PC-setup.exe` and runs it. No administrator rights are needed for the app itself.
  If WSL is missing, the app asks once for permission (one UAC prompt) and for one reboot, then continues where it
  stopped. From launching the installer to "Your cloud is ready" takes at most 5 minutes on the reference PC (§16),
  not counting the reboot itself.
- **U2 · Share.** On the "Share" step Ana moves three controls: CPU (cores), RAM (GiB) and GPU (on or off). The
  defaults are the H1 defaults (75 % of CPU and RAM, every offerable GPU), capped by what WSL gives the distro. She can
  change them later; the change applies within 10 s, without a restart.
- **U3 · Create my cloud.** On the first PC Ana chooses "Create my cloud". The app starts the hub on that PC, enrolls
  the PC as the first node and makes the app itself the owner's first device. She never sees an API key.
- **U4 · Join my cloud.** On the laptop Ana installs the app and chooses "Join my cloud". The laptop shows a QR code;
  she scans it with her already-paired phone, approves the new PC in the app on her hub PC after checking that the hub
  PC and the laptop show the same 6 words, checks that the phone and the laptop then show the same 6 other words, and
  taps "Join" on the laptop. No token is typed. (Without a phone, she can paste an invite text instead, §5.4.)
- **U5 · Add my phone.** The app shows a QR code. Ana scans it with the phone camera; the web app opens, pairs, and
  offers "Add to Home Screen". From then on the phone works on Wi-Fi and on 4G/5G.
- **U6 · Private AI chat.** In the phone web app Ana taps "Private AI chat". The service starts on the PC with the GPU,
  downloads a small default model the first time (with a progress bar), and she chats with streamed answers. Chat
  history stays on the phone.
- **U7 · Transcribe.** Ana records a voice memo, picks it in the web app, chooses "Transcribe", and gets the text back
  as a file, even if she closes the tab while the job runs.
- **U8 · Devices.** The desktop app lists the paired devices (name, platform, last seen) and revokes any of them. A
  revoked phone loses access within 5 s, even mid-chat.
- **U9 · Control.** From the tray icon or the app window Ana pauses sharing (nothing new starts; what runs keeps
  running), resumes it, or stops sharing (everything on this PC stops now). On the hub PC, "Turn off my cloud" stops the
  hub too, and the app says what that means.
- **U10 · Uninstall.** Uninstalling from Windows Settings removes everything P2PC put on the PC: the distro, its
  container images and model files, the scheduled task, the app's files and registry entries. The one exception is the
  backup of an upgrade that failed, which can be the only copy of the PC's identity (and, on the hub PC, of the cloud):
  it is kept unless Ana ticks "Also delete these backups" (§8.7), as `install.ps1 -Uninstall` keeps it. Uninstalling a
  joined PC also removes it from the cloud. Uninstalling the hub PC warns that this deletes the cloud, and first removes
  the other PCs from it so they stop looking for it.
- **U11 · Updates.** The app updates itself from signed releases, and updates the distro (agent, hub, image) after it.
  It looks for updates on its own only if Ana said yes at first run (§8.2); otherwise when she clicks "Check for
  updates". Ana is told before a running chat or job is interrupted.
- **U12 · Developers.** Dev runs `p2pc service run`, `p2pc service connect`, `p2pc blobs put`, `p2pc run --input
  <file>:<path>` and `p2pc templates launch`, and uses the same services from his laptop. Everything H1 did still works
  unchanged.

## 3. Non-goals for H2

- **Other desktop platforms.** No macOS or Linux desktop app. Linux nodes keep the H1 installers; a Mac stays a client
  (the web app works in Safari on macOS).
- **Accounts.** No sign-up, no login, no cloud user database. Devices are paired with the hub directly (§5). Accounts,
  passkeys and recovery through an account are candidates for H3.
- **Teams and multi-user.** One owner per cloud, as in H1.
- **Remote desktop, file sync, file browsing,** a terminal in the browser, Jupyter or code-server templates.
- **Sharing with strangers, a marketplace, payments,** or exposing a service to anyone who is not a paired device or an
  API-key holder of this cloud. No public URLs.
- **Hub failover or migration.** The hub is a single point of failure: when the hub PC is off, asleep or offline, the
  phone cannot reach the cloud, even if other PCs are on. The app says so in plain words (§8.6). Moving the hub to
  another PC is H3.
- **Summing machines.** No RAM or GPU pooling across PCs; a job or service runs on one node, as in H1.
- **A generic "open the service's own web UI" in the phone browser.** Templates get a UI written in the web app (§9.4).
  Proxying an arbitrary HTTP web UI into the phone browser needs a service-worker proxy over iroh, which is an H3
  candidate (§18, open item O-7).
- **Resumable uploads, multi-GPU jobs, GPU sharing between jobs, Windows or macOS guests, VMs.**
- **Code signing of the beta installer.** The beta is unsigned (§14.4). A public H2 release requires signing.
- **Telemetry and phoning home.** No usage, crash or diagnostic data goes to the P2PC project; crash and diagnostic data
  stay on the PC unless the user exports them. The hub makes no request to the project, and the web app none beyond
  loading its own files from the origin the user opened. Apart from the node image download of the install the user
  started (§8.3), the app makes exactly two kinds of request to project-run servers on its own, the update check (§14.1,
  template bundles included) and the web app verification fetch (§9.6), and only if the user turned them on (first run,
  §8.2, or Settings), as hard rule 6 requires; they carry no identifier of the user or the cloud. Relays carry the
  user's own end-to-end encrypted traffic (§10) and are not reports to the project.

## 4. Architecture

```
 Phone browser (PWA)                    Owner's PCs (Windows 11)                        Dev clients
 ┌──────────────────────┐               ┌───────────────────────────────────────────┐   CLI · SDK · MCP
 │ web app (static, TS) │               │ P2PC desktop app (Tauri 2, per-user)       │   (H1, unchanged)
 │ p2pc-device (WASM)   │               │  UI · p2pc-device (native) · p2pc-wsl      │        │
 │ device key in IDB    │               └──────────────┬────────────────────────────┘        │ p2pc/http/1
 └──────────┬───────────┘                              │ wsl.exe (manage)  + iroh (use)       │ (API key)
            │ wss (TLS by the PaaS)                    ▼                                     │
            ▼                           ┌─ WSL2 distro `p2pc-node` (first PC only: hub) ─────┼──────────┐
 ┌──────────────────────┐   QUIC/relay  │ p2pc-server (hub) · SQLite · blobs · templates  ◄──┘          │
 │ iroh-relay (HTTP     │◄─────────────►│   ALPNs: agent/1 · http/1 · pair/1 · device/1                 │
 │ behind PaaS TLS)     │               │ p2pc-agent ── rootless-style Podman (--userns=auto) ── jobs    │
 │ + n0 relays (QAD)    │               │ supervised by p2pc-run (no systemd in the distro)              │
 └──────────────────────┘               └────────────────────────────────────────────────────────────────┘
            ▲                                          ▲ p2pc/agent/1 (iroh, dialled by the agent)
            │                           ┌─ other PCs: WSL2 distro `p2pc-node` (agent only) ─┐
            └──────────────────────────►│ p2pc-agent · Podman · services (ingress bridge)   │
                                        └───────────────────────────────────────────────────┘
 Static host (Cloudflare Pages / Vercel / self-hosted): serves the web app files only. No API, no database.
```

Flow of a chat message: phone web app → `p2pc/device/1` stream (relay, end-to-end encrypted) → hub REST in-process →
`POST /v1/jobs/{id}/connect` upgrade (§7.4) → a stream that the hub opens on the GPU node's agent connection →
the agent's ingress socket → the shim inside the container → `127.0.0.1:11434` (the LLM server). The container keeps
`--network=none` (H1 §9) the whole time.

### 4.1 Components

| Component | Where | License | Role in H2 |
|---|---|---|---|
| `p2pc-proto` | crate | Apache-2.0 | Adds the types of §6 and §7: service jobs, volumes, blob inputs, devices, pairing, templates, new protocol messages. |
| `p2pc-server` | crate, binary | AGPL-3.0-only | Adds devices and pairing (`p2pc/pair/1`, `p2pc/device/1`), service jobs, port forwarding, blobs, templates, daily metering split. Runs as the **hub** inside the first PC's distro. |
| `p2pc-agent` | crate, binary | Apache-2.0 | Adds service lifecycle, health checks, the ingress bridge, volumes, blob fetch, live share changes and `Leave`. |
| `p2pc-shim` | crate, binary | Apache-2.0 | Adds the ingress side of the bridge (§11.2). |
| `p2pc-net` | crate | Apache-2.0 | Adds relay-map validation (§10.3). Address hygiene unchanged. |
| `p2pc-device` | **new** crate | Apache-2.0 | The client side of pairing and of `p2pc/device/1`: one code base compiled natively (desktop app) and to WebAssembly (web app). Depends on `iroh` with `default-features = false` [S1] and on `p2pc-proto`. No tokio networking, no filesystem. |
| `p2pc-wsl` | **new** crate | Apache-2.0 | Windows-only library: WSL checks and installation, distro import, upgrade with state backup, uninstall, the scheduled task. A Rust port of the parts of `deploy/wsl/install.ps1` the app needs (§8.3). |
| `apps/desktop` | **new** Tauri 2 app (`src-tauri` crate `p2pc-desktop`) | Apache-2.0 | The desktop app (§8). |
| `apps/web` | **new** TypeScript app | Apache-2.0 | The web app (§9). The desktop app embeds the same UI build. |
| `deploy/relay` | **new** | Apache-2.0 | Container image and config for `iroh-relay` on an HTTP-only PaaS (§10.2). |
| `templates/` | **new** data | Apache-2.0 | Template definitions (§7.6), signed at release. |
| `p2pc-cli`, `p2pc-client`, `sdk/python` | existing | Apache-2.0 | Additive commands and methods (§7.8). |

### 4.2 Topology decisions

- **D1 · The hub runs inside the first PC's `p2pc-node` distro.**
  - *Decision.* The first PC's distro runs both `p2pc-agent` and `p2pc-server`, each supervised by `p2pc-run`
    (§8.5). The hub's state lives in `/var/lib/p2pc-server` inside the distro. P2PC installs no Windows service and
    no firewall rule on the Windows host, and adds no listening TCP port reachable from the LAN: the hub's REST binds
    the distro's loopback, which WSL's `localhostForwarding` also exposes on the Windows host's own loopback (§8.5).
    The app's device endpoint and the hub's endpoint bind UDP sockets (§10.4); the hub's accepts incoming connections
    as H1's server does (§10.5), and the app's relay-only invite listener binds none (§5.4).
  - *Alternatives.* (a) `p2pc-server` as a native Windows service: needs administrator rights, a Windows build of the
    server and a second set of hardening; rejected for the "Windows host stays untouched" rule. (b) A second,
    hub-only distro: doubles the image and the upgrade path, and the WSL VM is shared anyway (H1 §9.0); rejected.
    (c) A hosted hub run by the project: needs accounts and a cloud database, and breaks "nothing in our cloud";
    rejected for H2.
  - *Consequence.* Jobs and the hub share one distro. Since H1 runs only the owner's own jobs (H1 SI-1) this does not
    change the trust model, but a container escape now reaches the hub's database too. §11.5 records this.
- **D2 · Devices talk to the hub only, never to nodes.** Service traffic from a device goes phone → hub → node. In the
  common case the GPU PC is the hub PC, so the second hop is local. Direct device → node connections are H3 (O-6).
- **D3 · One web app code base.** The phone web app and the desktop app UI are one TypeScript build. The desktop app
  adds its Tauri commands (install, share, devices); the web app adds pairing and key storage.
- **D4 · No project-run database.** The project's cloud footprint in H2 is a static site and a relay (§10). Both hold no
  user data and can be self-hosted.

### 4.3 What changes in H1, and what stays

**Stays exactly as in H1:** the agent control-stream framing and limits (except the `Join` failure rule, fixed
below), leases, epochs and fencing, the two-sided liveness rule (SI-13), the scheduler's fit and offer-cap rules, the
sandbox's fixed arguments (extended only; the one proposed change to its mount rule is the "Sandbox and hard rules" row
below), the egress proxy and its deny ranges,
API keys, join token semantics (their table changes only in who may create a token, below), the audit table's
append-only rules, the REST error format, the CLI exit codes, the MCP server's existing tools, and every existing
endpoint's request and response shape (responses may grow, H1 §7; what `GET /v1/usage` counts once a ledger row is a
slice is defined in §12). The Linux installers are unchanged.

**Changes (all additive unless marked):**

| Area | Change | Section |
|---|---|---|
| JobSpec | `kind` (`batch` default, `service`), `service` block, `volumes`, blob `inputs`, `template` (read-only). Old clients send none of them and get H1 behaviour. | §7.1 |
| JobSpec rules for services | **Changed, for `kind = "service"` only** (batch jobs keep H1's rules exactly): `timeout_s` has the range 60-2,592,000 and defaults to the maximum (H1: 1-86,400, default 3,600); out of range is `422 out_of_range`, as in H1, never clamped. `retry.max_attempts` defaults to 3 (H1: 2) and counts consecutive attempts that never became healthy, under a cap of 5 node-loss restarts in 24 h (H1: every attempt consumed by node loss). | §7.1, §7.2 |
| Job states | Unchanged words. A service's `running` adds `health` (`starting`, `healthy`, `unhealthy`). Stopping a service ends it `cancelled` with a `reason`. | §7.2 |
| Principals | **Changed.** A request is authenticated by an API key **or** by a paired device. Every place that reads `key_id` reads a `principal` that is one of the two. Storage: `jobs`, `usage_records` and `join_tokens` get a nullable `key_id` (H1: `NOT NULL`) plus a nullable `device_id`, with a `CHECK` that exactly one is set; job idempotency becomes unique per principal through two partial unique indexes; `audit_events` gains `actor_device_id`. SQLite cannot relax `NOT NULL` or add a `CHECK` in place, so this is a forward-only table rebuild (§5.6), not an additive column. | §5.5, §5.6 |
| Scopes | New: `services:connect`, `templates:launch`, `blobs:write`, `nodes:join`, `nodes:invite`. `admin` covers them. A principal with `templates:launch` also gets the narrow **template view** of jobs (state, logs, outputs, ports and cancel of its own template jobs and of `singleton` template instances); `jobs:read`, `jobs:write` and `services:connect` keep H1's project-wide meaning. | §5.5 |
| Node enrollment | **Changed.** A node enrolled with a join token minted by a non-`admin` principal starts `pending_approval` and gets no lease until an `admin` principal approves it. Tokens minted by `admin` API keys enroll as in H1. A token minted by an `admin` **device** (the hub PC's "Copy invite") also starts its node `pending_approval`, unless it was minted with the `pre_approved` option, which only the hub PC's app uses: for its own node at first run (§8.2 step 4) and as the explicit option of "Copy invite" (15 minutes, single use; `join_tokens.pre_approved`). A join token minted for an approved join request is bound to the joining agent's NodeId and enrolls no other (`join_tokens.bound_iroh_node_id`, §5.4). The stored rule: a node is created `approved` iff its token has `pre_approved = 1`, or a `bound_iroh_node_id`, or was created by an `admin` API key; otherwise `pending_approval` (§5.5). | §5.4, §5.5 |
| Sandbox and hard rules | **Proposed change, not in force with this spec.** Hard rule 3 (CONTRIBUTING) and H1 §9 ("never … host paths beyond the three per-job directories") would gain exactly one exception, recorded in ADR-015 (**Proposed**): **persistent volumes**. A volume is a directory the agent creates itself, per account, named by a hash of the volume name (never a path taken from the JobSpec); it is mounted only into service jobs and template jobs of that account, is size-limited (`max_mb`, H1's fail-closed measurement), is checked without following links before every mount, and is deleted without following links. **The exception takes effect only when the architect accepts this spec after E11, through a separate change that amends CONTRIBUTING hard rule 3 and H1 §9's "Never" line together and marks ADR-015 Accepted** (the same change puts the listening exception below in force, O-16). Until then hard rule 3 and H1 §9 stand unchanged, no code may mount a volume, and T2-22 (agent volumes) is blocked (§17, O-16). Nothing else in hard rule 3 changes and services need no exception from it: every job, services included, has a finite wall-clock limit (`timeout_s`, at most 30 days). | §7.1, §11.1, §11.3 |
| Phoning home (hard rule 6) | The app's daily update check and its web app verification fetch are **opt-in**: an explicit yes/no at first run with nothing preselected, and a Settings toggle. Without it the app checks for updates and verifies the web app only when the user clicks "Check for updates" or "Verify web app". | §3, §8.2, §9.6, §14.1 |
| Listening (hard rule 4, H1 §10) | **Proposed change, not in force with this spec.** Hard rule 4 (CONTRIBUTING: "nodes never listen on the network") and H1 §10 ("nodes never listen on a TCP or UDP port that is reachable from outside, beyond what iroh needs for outbound QUIC") would gain exactly one bounded exception, recorded in ADR-016 (**Proposed**): **the hub PC accepts inbound iroh connections**. The hub PC is also a node, and H2 does not read the rules as covering agents only. On that PC, only while the hub is enabled, the hub's own iroh endpoint accepts incoming QUIC on the UDP sockets `p2pc-net` binds for that endpoint under H1's address hygiene, with every ALPN behind a ticket, a token, a key or a paired NodeId and under pre-auth limits; on a PC that is joining, the app's relay-only invite listener (no IP transport) accepts the two `p2pc/invite/1` exchanges of one join (open, then hand-over, both from one phone) while the invite is valid. Nothing else listens beyond the loopback REST listener, and every agent still only dials out (§10.5). **The exception takes effect only through the same separate change as the volume exception (O-16), which amends CONTRIBUTING hard rules 3 and 4, H1 §9 and H1 §10 together and marks ADR-015 and ADR-016 Accepted.** Until then hard rule 4 and H1 §10 stand unchanged, no code may make a P2PC process on a node PC accept an inbound connection, and the tasks that do (T2-11, T2-41, T2-43, T2-44) are blocked (§17, O-16). | §5.4, §10.5, O-16 |
| `Join` failure limits (H1 §6 "Before `Join`") | **Changed: a fix of pre-existing H1 behaviour.** H1's 60 failed `Join`s a minute in total no longer refuses a `Join` without looking at its token: a `Join` with a valid token that gets a slot enrolls whatever the failure counters say, as for pairing and invites. The connection, pending and per-NodeId limits are unchanged. | §6.1, T2-17 |
| Agent protocol | New messages and server-opened streams behind the agent capabilities `service_jobs`, `volumes`, `blob_inputs`, `leave`, `share_update`, `approval` in `Hello.features`. No new ALPN. | §6.1 |
| New ALPNs | `p2pc/pair/1` and `p2pc/device/1` on the hub; `p2pc/invite/1` on a joining PC's app. | §6 |
| `init` | `p2pc-server init --owner-device <NodeId>` registers a device instead of printing an API key (the H1 form still works). New offline commands `p2pc-server devices add` and `p2pc-server devices revoke`. | §5.3 |
| Usage ledger | **Changed.** H1 keeps one row per finished attempt, keyed `UNIQUE (job_id, attempt)` and `lease_id UNIQUE`. H2 keeps one row per finished **slice**, keyed `UNIQUE (job_id, attempt, slice_start)`: a service attempt is split at every 00:00 UTC, and a batch attempt stays one slice. Rows gain the principal columns (§5.6), `kind`, `template_id`, `slice_start`, `slice_end`, `last_slice` and `charge_day`. The table is rebuilt (forward-only) with its append-only triggers. H1 property test 6 ("exactly one row per finished attempt") becomes "exactly one row per finished slice". `GET /v1/usage` keeps its shape; its `attempts` counts last slices, and grouping by key leaves device rows out (§12). | §5.6, §12 |
| Daily caps | **Changed.** The cap query counts ledger rows by their `charge_day` (the UTC day each slice is charged to) instead of by `jobs.created_at`, plus open reservations, never counting a reservation and the rows written against it twice. A batch slice is charged to its job's creation day, so batch jobs keep H1's numbers exactly. A capped principal's service is charged one UTC day at a time (a daily reservation) instead of by its whole `timeout_s` at creation, and is stopped when the day's cap is reached. | §12 |
| WSL image | Ships `p2pc-server`; `p2pc-node-run` becomes `p2pc-run` (agent, and hub when enabled); the upgrade carries `/var/lib/p2pc-server` too. | §8.5 |
| Agent config | Share limits can change at run time (`p2pc-agent share set`), sent as `InventoryUpdate`. | §8.2 |
| MCP server | One new tool, `p2pc_blob_put`, which reads a local file only from one upload directory, never through a symbolic link (SI-H2-21). `p2pc_run` takes blob digests, never local paths. The H1 tools are unchanged. | §7.8 |
| `install.ps1` | Kept for developers. The app does not call it; `p2pc-wsl` reimplements its install, upgrade and uninstall rules with the same checks and the same state layout, and a parity test pins them (§8.3). | §8.3 |

## 5. Identities, pairing and devices

### 5.1 Identities in H2

| Identity | Key | Where it lives | Proves |
|---|---|---|---|
| Hub | iroh secret key (H1 §5 "Server identity") | `/var/lib/p2pc-server` inside the hub PC's distro, 0600 | The hub is the hub. Every device and node pins its NodeId. |
| Node | iroh secret key (H1 §5 "Node identity") | `/var/lib/p2pc` inside each distro, 0600 | The agent is an enrolled node. |
| Device | iroh secret key, generated on the device | Phone: browser storage (§9.3). Desktop app: `%LOCALAPPDATA%\P2PC\device.key`, protected with DPAPI (user scope) | The device is paired. iroh's TLS authenticates the NodeId, so no bearer secret travels. |
| API key | H1 §5 | Unchanged | Developer clients, as in H1. |
| Release key | minisign key pair (Tauri updater format [S5]) | Private half offline with the release manager; public half compiled into the app and the hub | Updates (§14) and template bundles (§7.6) come from the project. |

A device key is never derived from, or sent to, anything else. Losing it means pairing again.

### 5.2 Pairing tickets

- **Created by** `POST /v1/devices/pairing-tickets` (`admin` scope). Body:
  `{label?, scopes?, daily_unit_cap?, allowed_images?, expires_in_s?, device_expires_in_s?, blobs_quota_mb?}`. The
  default scopes are the **phone profile**
  (§5.5). `expires_in_s` defaults to 600 and is at most 3,600. `daily_unit_cap` and `allowed_images` have H1's meaning
  and no-escalation rule as for API keys (H1 §5): if the creator has a cap, the ticket must carry one at or below it,
  and if the creator has an image list, the ticket's list must be made only of its patterns, else
  `403 escalation_denied`. `device_expires_in_s` (optional; absent: the device never expires) sets the device's
  `expires_at`, counted from the ticket's creation with `checked_add`; it must be a positive integer greater than
  `expires_in_s`, so a device is never born expired (else, or on overflow, `422 out_of_range`); if the creator has an
  `expires_at`, the ticket must set one at or before it (H1 §5: a longer life is more power), else
  `403 escalation_denied`. `blobs_quota_mb` (optional) caps the bytes of the blobs the device holds a claim on (§7.5);
  if the creator has one, the ticket must carry one at or below it, else `403 escalation_denied`. The device row
  stores all of these, and they bind the device as its own principal (§5.5, §12). The desktop app's pairing screen
  offers an optional daily limit. A paired device takes its ticket creator's project:
  `pairing_tickets` and `devices` store `(project_id, account_id)` with the same composite foreign key as `api_keys`.
- **Format.** `p2pc_pair_<base32 payload>`, in the H1 join-token style. The payload holds the hub NodeId, the hub's
  relay URLs, a 16-byte random code and the expiry. The hub stores only SHA-256 of the code.
- **The payload is not authenticated** (as H1 §5 join tokens). The hub uses the expiry, the scopes and the single-use
  flag from its own row, looked up by the code's hash with a constant-time comparison.
- **The QR code** encodes `https://<web app origin>/pair#p2pc_pair_…`. The ticket is in the **fragment**, which browsers
  never send to the static host, so the host's logs never see it. The web app removes the fragment from the address
  bar and from history (`history.replaceState`) before doing anything else.
- **Single-use, atomic.** One
  `UPDATE pairing_tickets SET consumed_at = ?, device_id = ? WHERE code_hash = ? AND consumed_at IS NULL AND expires_at > ? AND revoked_at IS NULL`
  runs in the transaction that inserts the device. With two concurrent `Pair`s for one ticket, exactly one device is
  created (SI-H2-2).
- **Retry is idempotent.** If the phone lost the `Paired` answer, the same ticket from the **same** device NodeId gets
  the same answer again, as long as that device is still live. Any other NodeId gets `invalid_ticket`, and so does a
  retry from the same NodeId once the device it created has been revoked (by an `admin` or by itself): a consumed
  ticket never revives a revoked device, and the answer is the same `invalid_ticket` as for an unknown ticket
  (SI-H2-2).
- **Listing and revoking.** `GET /v1/devices/pairing-tickets` and `DELETE /v1/devices/pairing-tickets/{id}` (`admin`),
  like join tokens. The desktop app revokes the ticket it showed when its QR screen closes.
- **Audit.** `pairing_ticket_created`, `device_paired`, `pairing_ticket_revoked`, `device_revoked`, failed pairings
  aggregated per minute (H1 §5 "Audit" rules; `auth_failed`, §5.6).

### 5.3 Pairing exchange (ALPN `p2pc/pair/1`)

1. The device generates its own iroh secret key (from the platform CSPRNG: `crypto.getRandomValues` in the browser) and
   stores it (§9.3) **before** dialling, so a crash after the hub registers it never leaves a registered key that the
   device forgot.
2. It dials the hub's NodeId on `p2pc/pair/1` using the ticket's relay URLs, opens one bidirectional stream and sends
   `Pair{ticket, label, platform}` (`platform` is a short free-text hint such as `"iOS Safari"`, at most 64 bytes).
3. The hub answers `Paired{device_id, hub_name, account_id, scopes, server_version, api_version}` or
   `PairError{code}` with `code` one of `invalid_ticket` (unknown, expired, revoked or used: one code for all, as
   H1 §5), `rate_limited`, `hub_too_old`. Then it closes the connection.
4. The device stores `device_id`, the hub NodeId and relays, and from then on uses `p2pc/device/1` (§6.3).
5. The desktop app that showed the QR polls `GET /v1/devices` and shows "Paired: iPhone (Safari) — not you? Revoke".

**Before pairing** the hub accepts `p2pc/pair/1` from any NodeId, so it is unauthenticated surface; it serves that ALPN
only while a pairing ticket is open (§10.5). It gets the H1 §6 "Before `Join`" limits, counted **separately** from the
agent ALPN: at most 32 connections at once and 8 pending `Pair`s; one `Pair` per connection, within 10 s; a frame limit
of 4 KiB. Beyond the connection limits a new connection closes with no detail.

**The limits shed load; they never lock the owner out.** A flood can fill the connection slots and delay a valid
`Pair` (the device retries with backoff while its ticket is valid), but the hub never refuses a request with a valid
ticket because other requests failed:
- every `Pair` that gets a slot is checked against the hub's rows (one hash and one indexed lookup), and a valid ticket
  pairs whatever the failure counters say;
- failed pairings are counted per NodeId (10 a minute) and per **ticket-hash prefix** (the first 16 bits of the
  SHA-256 of the presented code, 10 a minute each), with no global failure bucket. A NodeId over its limit is refused
  when it connects (only its own failures count, and nobody else holds its key). Failing attempts in a prefix over
  its limit are closed with no detail and aggregated into one audit event a minute. These counters slow down one
  NodeId or one prefix only: NodeIds cost nothing to make (H1's per-NodeId limiter already forgets keys beyond 4,096)
  and the attacker picks the code it presents, so failures spread over many NodeIds and all 65,536 prefixes trip
  neither;
- **what bounds an attacker's cost is the connection caps:** at most 32 connections and 8 pending `Pair`s at once, so
  the hub's pre-auth work is at most that of 8 concurrent exchanges, each one handshake, one hash and one indexed
  lookup;
- **aggregate failure cap (every pre-auth ALPN).** Beyond 60 failures a minute in total on one ALPN, further failures
  get no detailed answer (the connection closes with no detail) and are not logged or audited one by one, only counted
  into the one aggregated audit event a minute. The cap limits answers and logging, never the lookup: a request with a
  valid credential that gets a slot still succeeds. `p2pc/agent/1` (§6.1), `p2pc/invite/1` (§6.2) and the device check
  of `p2pc/device/1` (§6.3) apply the same rule.

**Who creates the owner's first device.** `p2pc-server init --owner-device <NodeId> [--label <text>]` creates the
account, the default project and an **owner device** with the `admin` scope, and prints no API key. The desktop app
generates its own device key first and passes its public NodeId. `p2pc-server devices add --data-dir <dir> --node-id
<NodeId> --scopes <list> --label <text> [--project <project_id>]` (default: the default project) does the same offline
later (local data-dir access, audited as `device_added_offline`, the H1 `keys recover` pattern). Its twin `p2pc-server
devices revoke --data-dir <dir> --id <device_id>` revokes a device offline, under the same last-admin rule as `DELETE
/v1/devices/{id}` (§5.5), audited as `device_revoked_offline`. Like `keys recover`, both work while the hub runs. The
hub PC's app uses `devices revoke` through `wsl.exe` when its own device connection cannot get a slot within 10 s, so
the owner's revocation never depends on the pre-auth slots that unknown NodeIds share (§6.3). Plain `p2pc-server init`
keeps its H1 behaviour.

### 5.4 Joining another PC (invites)

The H1 join token is about 90 base32 characters: too long to type, and a desktop PC often has no camera. A short code
would need a rendezvous service to resolve it, which H2 does not have (D4). So:

- **Primary path: phone-assisted invite, approved on the hub PC.**
  1. The new PC's app starts an **invite listener**: a temporary iroh endpoint in the app with a fresh key, serving
     only ALPN `p2pc/invite/1` (under the proposed listening exception of §4.3, ADR-016, so not before O-16). The
     phone is relay-only, so this connection always goes through a relay; the listener is therefore relay-only too:
     it MUST be built through `p2pc-net` with `direct_addresses = "none"`, so it has no IP transport, binds no UDP
     socket and publishes and serves no direct address. E10 confirms that iroh serves a relay-only endpoint this way;
     if E10 shows this is impossible, this spec and ADR-016 are amended before O-16.
  2. It reads the local agent's NodeId (`iroh_node_id` in `p2pc-agent status --json`; the agent creates its key at
     first start, H1 §5 "Node identity"), draws a 32-byte **listener nonce** from the platform CSPRNG, which it keeps
     in memory only, and shows a QR code: `https://<web app origin>/invite#p2pc_inv_<base32: listener NodeId, agent
     NodeId, relays, 16-byte code, listener commitment, expiry (15 min)>`. The **listener commitment** is
     `BLAKE3("p2pc-join-commit-v1" || listener nonce)`: the QR carries the commitment, never the nonce.
  3. The owner scans it with the paired phone. The phone relays the invite to the hub as a **join request**:
     `POST /v1/nodes/join-requests {listener_node_id, iroh_node_id, invite_expires_at, listener_commitment}` (all four
     copied from the QR) with the narrow scope **`nodes:invite`**, which the default phone profile has (§5.5). The hub
     refuses with `422 invalid_join_request` a request whose `invite_expires_at` is not within
     `(now, now + 15 min + 120 s]` on the hub's clock (120 s of clock skew between the two PCs), whose
     `listener_node_id` or `iroh_node_id` is not a valid Ed25519 public key (32 bytes that decode to a curve point), or
     whose commitment is not 32 bytes. Otherwise it draws a 32-byte **hub nonce** from its CSPRNG, stores it in the
     row and answers `201 {id, expires_at, hub_nonce}`; the request starts `awaiting_reveal`. The request carries no
     secret, expires 15 minutes after it was created, and gives the phone nothing yet. Limits (`429` beyond): at most 4
     open per account, at most 2 open per requesting device, and at most 6 created per device per hour, so one stolen
     phone cannot keep every slot filled.
  4. **Reveal.** The phone dials the listener on `p2pc/invite/1` with its device endpoint and sends
     `InviteOpen{code, hub_node_id, hub_nonce}`. The app checks the code (constant time), keeps the hub NodeId, the hub
     nonce and the phone's NodeId, and answers `InviteReveal{listener_nonce}`. It answers one `InviteOpen` only: from
     then on it accepts `p2pc/invite/1` only from that NodeId, and a repeated `InviteOpen` from it with the same hub
     NodeId and hub nonce gets the same answer (§6.2). The app now shows the **approval phrase**: 6 words from the fixed 2,048-word
     list of step 7, derived from `BLAKE3("p2pc-join-request-v2" || hub NodeId || agent NodeId || listener nonce || hub
     nonce)`, with "Your hub PC will show these words". The phone sends
     `POST /v1/nodes/join-requests/{id}/reveal {listener_nonce}` (the requesting device only, once); the hub checks
     `BLAKE3("p2pc-join-commit-v1" || listener_nonce)` against the stored commitment (constant time) and the request
     becomes `pending`. A nonce that does not match ends the request `rejected` with `409 join_request_closed` (audited
     `join_request_reveal_failed`). The phone shows "Approve the new PC in the P2PC app on your hub PC".
  5. **Approval on the hub PC.** The desktop app on the hub PC (an `admin` principal) shows a `pending` request as "A
     new PC wants to join your cloud" with what the owner can check: the request's source device (its label and platform
     as recorded at pairing, not as the request claims), the time the request was created ("3 minutes ago"), and the
     **approval phrase**, which the hub computes from its own NodeId, the request's agent NodeId, the revealed listener
     nonce and its own hub nonce. A request still `awaiting_reveal` shows no phrase and cannot be approved. The screen
     says "Approve only if your new PC shows the same words". "Approve" calls
     `POST /v1/nodes/join-requests/{id}/approve` (`admin`), which records the approving principal and mints nothing yet.
     The hub refuses to approve a request that is not `pending` or was created more than 15 minutes ago
     (`409 join_request_closed`), checked against the row's `created_at` on the hub's clock, whatever state the expiry
     sweep has left it in. "Reject" (`DELETE /v1/nodes/join-requests/{id}`) or the expiry ends the request with nothing
     minted. Every step is audited (`join_request_created`, `join_request_revealed`, `join_request_approved`,
     `join_request_rejected`, `join_request_delivered`).
     - *What the phrase defeats, and at what cost.* The attacker is a thief with the owner's phone, or code running in
       the web app's origin on it (an XSS or a compromised static host, §9.6): it sees the QR and controls everything
       the phone sends. The token is bound to the request's agent NodeId (step 6) and enrolls only that NodeId, so
       copying the owner's NodeIds gains nothing; the attacker must send the agent NodeId of a machine it controls and
       still make the hub PC show the words that the owner's new PC shows. The same phrase also covers the other
       direction: the new PC hashes the hub NodeId it was told in `InviteOpen` and later refuses a join token for any
       other hub (step 6), so a compromised phone cannot make the owner's new PC join the attacker's own cloud either,
       as long as the owner taps "Join" only after approving matching words on the hub PC; the new PC's "Join" screen
       says so (step 7).
     - The phrase hashes only the two NodeIds whose secret keys an attacker must hold to use the result (the hub that
       the new PC dials and the agent that the token is bound to) and the two nonces. The listener NodeId and the
       expiry, which an attacker could set freely, are checked (step 3) but not hashed.
     - The commitment rules out any offline search. The hub PC's phrase is fixed by what the attacker sends before the
       hub draws its nonce (the agent NodeId and the commitment, which binds the listener nonce it can later reveal).
       The new PC's phrase is fixed by the one hub NodeId and hub nonce it accepts before it reveals its listener nonce.
       Each phrase is thus fixed before the attacker learns the one value that makes it random, in either order of the
       steps, so the two match only by chance: 1 in 2^66 (6 words of 11 bits, about 7 × 10^19) per join request,
       whatever computing power the attacker has. A device creates at most 6 requests an hour, and each one appears on
       the hub PC.
     - Without the nonces, a phrase over values the attacker can vary would be a search problem: 4 words over the
       agent NodeId, the listener NodeId and the expiry fall to about 2^44 hashes, minutes on a few rented GPUs.
  6. The phone polls `GET /v1/nodes/join-requests/{id}` until the request is `approved`, then calls
     `POST /v1/nodes/join-requests/{id}/token` (the requesting device only). That call mints the join token (15
     minutes, single use, on behalf of the approving principal, **bound to the request's agent NodeId**), stores only
     its hash (hard rule 5) and returns it **once**; the request becomes `delivered`. The hub reloads the approving
     principal in the minting transaction and refuses with `409 join_request_closed` if it is no longer live (revoked
     or expired; H1 §5 re-checks power at the point of use). Like `approve`, the call is
     refused for a request created more than 15 minutes ago (`409 join_request_closed`), checked against the row's
     `created_at` on the hub's clock, whatever state the expiry sweep has left it in, so how long a token can be
     minted never depends on when the sweep runs. The hub refuses a `Join` with a bound token from any other NodeId
     with H1's invalid-token answer, and does not consume the token. A phone that loses that answer opens a new
     request. The phone dials the listener on `p2pc/invite/1` again and sends `Invite{code, join_token, hub_name}`.
     The app checks the code (constant time, single use), that the dialler is the NodeId of the `InviteOpen` and that
     the join token names the hub NodeId of the `InviteOpen` (else `InviteError{code:"hub_mismatch"}`, and the app
     shows "This invite is for another cloud: do not join"), and answers `InviteAck{}`.
  7. The phone and the new PC then show a second check phrase, the **hub phrase**: 6 words from a fixed 2,048-word list,
     derived from `BLAKE3("p2pc-invite-v1" || hub NodeId || listener NodeId || code)`. The owner taps "Join" on the PC
     only if they match; the screen also says "Join only if you approved this PC on your hub PC". This defeats someone
     who photographed the QR and pushes their own hub's token: the PC would otherwise join a stranger's cloud and run
     the stranger's jobs (H1 SI-1 protects the owner of the cloud, not a node joined to the wrong cloud). Such a
     photographer cannot hand over a token after the owner's phone has sent `InviteOpen` (step 4); if it sends
     `InviteOpen` first, the owner's phone is refused and says "This PC is already talking to another phone: cancel on
     the PC and start again". The hub NodeId is the one input it can choose, so a matching phrase costs about 2^66 key
     generations inside the invite's 15 minutes, out of reach **(H)**.
  8. The app feeds the join token to `p2pc-agent join -` through stdin (H1 §7 CLI conventions) and closes the
     listener. The token carries an `admin`'s approval of this join request, so the node is approved when it
     enrolls (§5.5).
- **Direct tokens from `nodes:join`.** A principal with `nodes:join` (the opt-in developer device profile, or an API
  key) may call `POST /v1/nodes/join-tokens` itself (at most 900 s) and hand the token over as an invite text (below).
  The QR path always goes through a join request: the listener requires `hub_node_id` and `hub_nonce` in `InviteOpen`,
  so a PC never joins through its listener without the approval phrase. The node a direct token enrolls starts
  **`pending_approval`** (§5.5), so the approval on the hub PC comes after enrollment instead of before. Either way, no
  PC gets work from the cloud before an `admin` principal has approved it.
- **Fallback: invite text.** The hub PC's app shows "Copy invite": a join token as text (15 min, single use), for the
  owner to carry by any private channel; the new PC's app has a "Paste invite" field. The text never goes on a command
  line (H1 §7). The app shows the hub name from the join result and asks for confirmation before the node takes leases.
  - **Bound to approval.** The token is not bound to any NodeId, so whoever holds the text can enroll a machine. A
    node enrolled with it therefore starts **`pending_approval`** (§5.5), like one from a `nodes:join` token, and the
    hub PC's app approves it on the node phrase screen of §5.5, which the joining PC also shows (`join_pending`, §8.8).
    A leaked text thus enrolls at most one pending node that never gets work, and the owner sees it waiting.
  - **Pre-approved invites.** The "Copy invite" screen has an explicit, unchecked option "Pre-approve: this PC gets
    work as soon as it joins". It mints the token with `pre_approved: true` (§7.3): still 15 minutes and single use,
    and its node is created `approved`. Only the hub PC's app offers it; the web app never does, and the hub accepts
    `pre_approved: true` only from an `admin` principal.
  - **The hub PC's own node.** First-run step 4 (§8.2) joins the hub PC's agent with a token that the app mints over its
    own device connection with `pre_approved: true` and `expires_in_s` 300, without asking: the token goes from the app
    to the local agent through stdin and never leaves the PC, so that node gets work as soon as the cloud is ready.
- **Re-joining** a PC that is already a live node (reinstall without uninstall) follows H1 §5 "Re-enrolling the same
  machine": same node id.

### 5.5 Principals and scopes

- **Principal.** Every authenticated request carries a principal: `Key{key_id}` (H1) or `Device{device_id}`. Ownership
  (`account_id`, `project_id`), scopes, caps and image allowlists come from the principal's row (a device's project
  from its pairing ticket, §5.2). Audit events, the usage
  ledger and `GET /v1/whoami` name the principal (`whoami` gains `principal: {kind, id}`; `key_id` stays, `null` for
  a device). §5.6 says how the database stores it.
- **A device principal exists only on `p2pc/device/1`.** Requests on the TCP REST listener and on `p2pc/http/1` are
  authenticated by API key only. No header can turn a request into a device request (SI-H2-3): device requests are
  served in-process with the principal attached as a request extension, never relayed to the TCP listener.
- **New scopes:** `services:connect` (open a service port, §7.4), `templates:launch` (§7.6), `blobs:write` (§7.5),
  `nodes:invite` (open a join request that an `admin` must approve, §5.4), `nodes:join` (create a join token valid at
  most 15 minutes, whose node starts `pending_approval`, §5.4). `admin` covers all of them. `jobs:write` already
  allows services and blob inputs.
- **Template view.** `jobs:read` (H1) reads every job of the project, with its logs and outputs, and
  `services:connect` opens a port of any service of the project, including a developer's own `p2pc service run`
  service. Neither is in the default phone profile. A principal with `templates:launch` instead gets a narrow view,
  checked in the job routes themselves (one function, used by every route below):
  - **Visible jobs:** the template jobs (`template` set) that this principal launched, and every instance of a
    `singleton` template in its account and project, whoever launched it (a singleton is shared, §7.6). No other job
    is visible: `GET /v1/jobs` leaves it out, and every route on it answers `404` as for an unknown id (H1 SI-7 style).
  - **State:** `GET /v1/jobs` and `GET /v1/jobs/{id}` on visible jobs (H1 redaction of `env` and `files` applies).
  - **Logs and outputs:** `GET /v1/jobs/{id}/logs` and `GET /v1/jobs/{id}/outputs[/{path}]` only on the template jobs
    this principal launched; on a singleton instance launched by someone else, `404`.
  - **Ports:** `POST /v1/jobs/{id}/ports/{port}/connect` on a visible template service, filtered by the template's
    `allowed_routes` (§7.4).
  - **Cancel:** `POST /v1/jobs/{id}/cancel` on a visible job (§7.2).

  A principal that also holds `jobs:read`, `jobs:write` or `services:connect` keeps H1's project-wide rule for that
  route; the template view only adds to a principal without them. `GET /v1/usage`, `POST /v1/estimate` and
  `GET /v1/blobs` keep `jobs:read`.
- **Profiles** (presets for the UI; the API takes scope lists):

  | Profile | Scopes | Used by |
  |---|---|---|
  | Owner | `admin` | The desktop app on the hub PC (created by `init --owner-device`). |
  | Phone (default) | `nodes:read`, `templates:launch`, `blobs:write`, `nodes:invite` | Phones and browsers paired from the app. |
  | Developer device | Phone + `jobs:read`, `jobs:write`, `services:connect`, `nodes:join` | Opt-in in the app's pairing screen ("allow running any container, reading every job's logs and outputs, opening any service and adding PCs"). |

  The default phone profile cannot submit arbitrary JobSpecs, read the jobs, logs or outputs of developer jobs or of
  other devices' template jobs, open a non-template service, or mint join tokens. A stolen, unlocked phone or an XSS
  in the web app can, until the device is revoked:
  - launch vetted templates (§7.6) and read the state, logs and outputs of the template jobs it launched;
  - see the state of the shared `singleton` instances, send them the HTTP requests their template allows, and stop
    them. A template-view principal never gets a raw port connection: the hub forwards only the template's
    `allowed_routes` (§7.4, §7.6). For the beta that is the private chat: the attacker can chat with the owner's models
    and list them (`POST /api/chat`, `GET /api/tags`), and cannot pull, create, copy, push or delete a model; the only
    model downloads are the hub's own, of the template's declared model at launch (§7.6). Chat history is not on the
    hub (§9.4), so other devices' conversations are not exposed;
  - see the PCs and volumes (`nodes:read`);
  - upload blobs, check whether the account holds a blob of a given digest (`HEAD`), and withdraw its own claim on a
    blob it uploaded, which deletes the blob only when no other principal has a claim on it (`blobs:write`, §7.5);
  - ask for a PC to join, which the hub PC must approve (§5.4).

  That is everything it can reach; SI-H2-18 pins it with a negative test per route. It bounds what an attacker with a
  device key can run on, or read from, the owner's PCs.
- **No escalation** (H1 §5 `check_no_escalation`) applies to devices: a pairing ticket's scopes, cap, image list,
  device expiry and blob quota are within its creator's (§5.2). Only `admin` principals create pairing tickets in H2.
- **Revocation.** `DELETE /v1/devices/{id}` (`admin`) sets `revoked_at`, closes every live `p2pc/device/1` connection of
  that NodeId and every service stream it opened, within 5 s (SI-H2-4). As for keys (H1 §5), an `admin` principal may
  revoke only a device it could have created (`check_no_escalation` applied to the device's scopes, cap, image list,
  expiry and blob quota), else `403 escalation_denied`. A device can revoke itself ("Forget this cloud" in the web
  app). The hub refuses to revoke the last live unrestricted `admin` principal, device or key (H1 "Last admin key",
  extended to devices; an unrestricted device has no `expires_at`, no `daily_unit_cap`, no `allowed_images` and no
  `blobs_quota_mb`, and a key keeps H1's definition, since keys have no blob quota):
  revoking such a key keeps H1's `409 last_admin_key`, unchanged, and revoking such a device gets the new `409
  last_admin_device`. The offline `devices add` and `keys recover` remain the way back. The offline `p2pc-server devices
  revoke` (§5.3) revokes the same way when the app cannot get a device connection; a running hub notices a revocation
  written by another process because of its **liveness sweep**: every 2 s it re-reads the `revoked_at` and
  `expires_at` of the devices that hold live connections, and closes every connection and service stream of a device
  that is revoked or has `expires_at <= now`, by the same path as `DELETE`. So the 5 s of SI-H2-4 hold for an offline
  revocation and for an expiry too, including upgraded port connections and log follows that carry traffic.
- **Unknown or revoked device.** A device is live while it is neither revoked nor past its `expires_at`. A
  `p2pc/device/1` connection from a NodeId that is not a live device gets the same close code (`not_paired`) whether
  it was never paired, revoked, expired or belongs to nothing. Revoked and expired rows are kept.
- **`last_seen_at`** is written at most once a minute, as H1 `last_used_at`.
- **Node approval.** A node row records `enrolled_by` (the principal that minted its join token) and `approval`
  (`approved` or `pending_approval`).
  - A node enrolled with a token minted by a non-`admin` principal (a `nodes:join` device or API key) is created
    `pending_approval`. The scheduler never offers it a lease and treats it as ineligible with a `reason` ("waiting for
    approval on the hub PC"); everything else (connection, inventory, heartbeats) works as for any node. Nodes are
    created `approved`, as in H1, only from tokens that already carry an `admin`'s approval: tokens minted by `admin`
    API keys (H1 behaviour, unchanged), tokens of approved join requests (§5.4) and tokens minted with `pre_approved`
    (the hub PC's own node at first run and pre-approved invite texts, §5.4). A token minted by an `admin` device
    without `pre_approved` (the default "Copy invite") gives a `pending_approval` node too. The stored rule is: a
    node is created `approved` iff its token has `pre_approved = 1`, or has a `bound_iroh_node_id` (only tokens of
    approved join requests do, §5.6), or was created by an `admin` API key; otherwise `pending_approval`.
  - Only an `admin` principal approves: `POST /v1/nodes/{id}/approve` (idempotent), audited as `node_approved`. The
    desktop app on the hub PC shows "New PC waiting: Approve / Remove" with what the owner can check, since the name
    is whatever the node reported: the principal that minted its token (as recorded by the hub), the enrollment time,
    and the **node phrase**, 6 words (66 bits) from the same list derived from `BLAKE3("p2pc-node-v1" || node NodeId)`.
    It is a fingerprint of a long-lived key, so an attacker who knows a target NodeId can search offline for its own
    key with the same phrase; at 66 bits that is about 2^66 key generations, hundreds of GPU-years **(H)**.
    "Remove" is H1's `DELETE /v1/nodes/{id}`. The joined PC's app shows "Waiting for approval on your hub PC" with the
    same node phrase (§8.8), and `p2pc-agent status` prints it on a Linux node, so the owner approves only the
    machine whose screen shows the same words.
  - Revoking a device offers "also remove the PCs this device added".
  - A stolen phone with the default profile can therefore only open join requests, and a stolen developer device only
    enroll pending nodes: in neither case does a machine the thief controls get any work without the owner's approval
    on the hub PC (SI-H2-19). This closes O-4.
  - `GET /v1/nodes` and `GET /v1/nodes/{id}` gain `approval`, `enrolled_by` and `node_phrase` (additive).

### 5.6 How principals are stored

H1 stores the principal of jobs, ledger rows and join tokens as a `NOT NULL` API key: `jobs.key_id`
(`crates/p2pc-server/migrations/20261105130000_jobs.sql`), `usage_records.key_id` (`20261105150000_scheduler.sql`) and
`join_tokens.created_by_key_id` (`20261105140000_join_tokens_nodes.sql`). A device principal has no API key, so H2
stores a principal in two columns:

- **Columns.** `key_id TEXT REFERENCES api_keys (key_id)` and `device_id TEXT REFERENCES devices (device_id)`, both
  nullable, with `CHECK ((key_id IS NULL) <> (device_id IS NULL))`: exactly one is set, in `jobs` and in
  `usage_records`. `join_tokens` has `created_by_key_id` and `created_by_device_id` under the same `CHECK`, plus
  `bound_iroh_node_id` (nullable; set only for tokens of join requests, §5.4) and `pre_approved` (`NOT NULL DEFAULT 0`;
  set only by an `admin` principal's explicit option, §5.4). `audit_events` gains `actor_device_id`
  with `CHECK (actor_key_id IS NULL OR actor_device_id IS NULL)` (aggregated failures have no actor), and its update
  trigger compares the new column too. `nodes` gains `approval` (`NOT NULL DEFAULT 'approved'`) and `enrolled_by`, the
  principal of the token that enrolled it (`NULL` for H1 nodes); both are plain added columns. The new `blobs` table
  (§7.5) has no principal column: its uploaders are rows of the new `blob_uploaders (account_id, sha256,
  uploaded_by_key_id, uploaded_by_device_id)`, with the same exactly-one `CHECK` and two partial unique indexes, one
  per principal column, as for idempotency below. Each row is one principal's **claim** on the blob.
- **Audit kinds.** The rebuilt `audit_events` keeps H1's closed `kind` list and adds every H2 kind:
  `pairing_ticket_created`, `pairing_ticket_revoked`, `device_paired`, `device_revoked`, `device_added_offline`,
  `device_revoked_offline`, `join_request_created`, `join_request_revealed`, `join_request_reveal_failed`,
  `join_request_approved`, `join_request_rejected`, `join_request_delivered`, `node_approved`, `node_left` and
  `template_bundle_loaded`. Aggregated failures add no kind: they reuse H1's `auth_failed` in the owner's account, as
  H1 already does for failed `Join`s (`subject_id` `join`), with `subject_id` `pair` for failed pairings and `device`
  for `not_paired` closes; failures beyond the aggregate failure cap of §5.3 are counted into the same row of their
  ALPN. So the `auth_failed` bucket index and the update trigger's `WHEN`, which allow aggregation only for
  `auth_failed`, stay as in H1.
- **Idempotency per principal.** SQLite treats NULLs as distinct in a unique index, so H1's
  `jobs_idempotency ON jobs (key_id, idempotency_key)` would silently stop deduplicating every device submission once
  `key_id` may be NULL. It is replaced by two partial unique indexes, in which the principal column is never NULL:

  ```sql
  CREATE UNIQUE INDEX jobs_idempotency_key ON jobs (key_id, idempotency_key)
      WHERE idempotency_key IS NOT NULL AND key_id IS NOT NULL;
  CREATE UNIQUE INDEX jobs_idempotency_device ON jobs (device_id, idempotency_key)
      WHERE idempotency_key IS NOT NULL AND device_id IS NOT NULL;
  ```

  The scope stays H1's: one principal. Another principal reusing the same idempotency key gets its own job and learns
  nothing about the first. Template launches (§7.6) use the same indexes.
- **Cap lookups.** H1's `jobs_key_created` stays and gains `jobs_device_created ON jobs (device_id, created_at)`; the
  ledger is indexed by principal and `charge_day` (§12).
- **Migration.** One forward-only migration (T2-10), after the one that creates `devices`, rebuilds `jobs`,
  `usage_records`, `join_tokens` and `audit_events`:
  - SQLite cannot relax `NOT NULL`, add a `CHECK` or change a `UNIQUE` constraint in place, so each table is rebuilt
    with the procedure of `20261108120000_finished_lease_holds.sql`: `PRAGMA defer_foreign_keys = ON`, rows saved in a
    temporary table, the table dropped and created again under its own name, rows copied back. The tables that
    reference `jobs` keep pointing at it, and foreign keys are checked at `COMMIT`. The migration runs in one
    transaction, so a failure leaves the H1 tables;
  - every index and trigger of the old tables is created again, as `20261106130000_audit_node_reenrolled.sql` does for
    `audit_events`: `jobs_terminal_is_final`, `usage_records_no_update`, `usage_records_no_delete`,
    `audit_events_no_delete`, `audit_events_no_update`, and every H1 index and constraint except those replaced here
    (`jobs_idempotency` above; the `kind` list, which gains the H2 kinds above; the ledger's `UNIQUE (job_id, attempt)`
    and `lease_id UNIQUE`, §12). Dropping a table runs no row-level trigger, so the append-only triggers never fire
    during the rebuild, and they are in force again before `COMMIT`;
  - H1 rows are copied with `device_id` NULL and their key unchanged, and each ledger row becomes one slice (§12:
    `slice_start = started_at`, `slice_end = ended_at`, `last_slice = 1`, `kind = 'batch'`, `charge_day` = the UTC
    day of its job's `created_at`), so every H1 number (caps, `GET /v1/usage`) is the same after the migration;
  - a migration test runs it on a database filled through the H1 migrations and checks: every row and value copied;
    `PRAGMA foreign_key_check` empty; the append-only triggers still refuse `UPDATE` and `DELETE`; H1's cap and usage
    values unchanged (SI-H2-20).

## 6. Protocol additions

All new protocols follow H1 §6 framing (u32 big-endian length, then a JSON message tagged by `"type"`) and its
compatibility rules: unknown fields ignored, unknown `type` decodes to `Unknown` and gets
`Error{code:"unsupported_message"}`, closed nested enums, server upgraded before its agents.

| ALPN | Who dials whom | Authentication | Purpose |
|---|---|---|---|
| `p2pc/agent/1` | agent → hub | enrolled node NodeId | H1, plus §6.1. |
| `p2pc/http/1` | client → hub | API key in each request | H1, unchanged. Service ports also work through it (§7.4). |
| `p2pc/pair/1` | device → hub | one-time ticket in the message | Pairing (§5.3). |
| `p2pc/device/1` | device → hub | paired device NodeId (iroh TLS) | REST and service ports for devices (§6.3). |
| `p2pc/invite/1` | phone → new PC's app | one-time code in the message | Hands a join token to a PC that is joining (§5.4). |

### 6.1 Agent protocol additions (within `p2pc/agent/1`)

New agent capabilities in `Hello.features`. The hub sends a lease that needs one only to agents that declared it (H1
§6 "Compatibility"), and the scheduler treats a node without it as ineligible for such jobs, with a `reason`:

| Capability | Needed by |
|---|---|
| `service_jobs` | any job with `kind: "service"` |
| `volumes` | any job with `volumes` |
| `blob_inputs` | any job whose `inputs` reference a blob |
| `leave` | the agent may send `Leave` |
| `share_update` | the agent applies share changes live (informative; no lease needs it) |
| `approval` | the agent understands `Welcome.pending_approval` and `NodeApproved` (informative: approval is enforced by the scheduler, never by the agent) |

**New agent → hub messages:**
- `ServiceHealth{lease_id, epoch, state:"starting"|"healthy"|"unhealthy", since, detail?}`: sent on every change of
  the health state of a service lease, and repeated in each `Heartbeat` as `running[].health`.
- `VolumeReport{volumes:[{name, size_mb, last_used_at, in_use_by?}]}`: after `Hello` and every 10 minutes, and when a
  lease that mounted a volume ends.
- `Leave{reason}`: "remove me". The hub deletes the node as `DELETE /v1/nodes/{id}` would, audits `node_left`, closes
  the connection and answers nothing. The agent then exits with code 7 (H1 "removed from the server"), so H1's terminal
  stop rules switch off its supervisor. Sent by `p2pc-agent leave`, which the app runs on uninstall (§8.7).

**Changed agent → hub messages (additive):** `Heartbeat.running[]` gains `health` for service leases and, at most once a
minute, `used_cpu_ms` (cumulative, from the lease cgroup) and `max_rss_mb` (the attempt's peak so far, from the lease
cgroup) for service leases, used by the daily split (§12).
`Inventory` gains `volumes_mb` (the disk share for volumes, apart from `offered.disk_mb`, §11.3) and `owner_paused`
(bool, §8.4): while it is true the scheduler treats the node as draining, and the agent rejects new leases with
`draining`. Both come with `share_update`; an agent without it sends neither.

**New hub → agent messages:**
- `Lease` is unchanged in shape. Its `job` now may carry `kind`, `service`, `volumes` and blob `inputs` (§7.1). An
  agent that does not declare the capability never receives such a lease; if one arrives anyway it answers
  `LeaseRejected{reason:"invalid_job"}` (H1 "must understand").
- `Cancel{lease_id, epoch, reason}` gains reasons `stopped`, `idle_timeout`, `health_check_failed` and `cap_reached`
  (informative; the agent's behaviour is the H1 cancel sequence).
- `VolumeDelete{name}`: delete a node-local volume that no lease uses. The agent answers with a fresh `VolumeReport`.
- `Welcome` gains `pending_approval` (bool, additive) and, to agents that declared `approval`, the hub sends
  `NodeApproved{}` when an `admin` approves the node (§5.5). The agent shows both in `p2pc-agent status --json`, which
  the joined PC's app reads. An agent without `approval` simply gets no lease until it is approved.

**`Join` failure limits (a fix of pre-existing H1 behaviour).** H2 applies the rule of §5.3 to `p2pc/agent/1` too:
the pre-auth limits shed load, but they never refuse a `Join` carrying a valid token because other `Join`s failed. H1
§6 counts failed `Join`s per NodeId (10 a minute) and in total (60 a minute), and H1's server refuses any `Join`
without looking at its token once the total is reached (`MinuteLimiter::allows` in
`crates/p2pc-server/src/gateway/limits.rs`, called first by `join()` in `gateway/agent.rs`), so a few throwaway
NodeIds that know the hub's NodeId stop every new PC from joining. On the hub PC, reachable through a relay by
default (§10.5), that matters more. The fix (T2-17) MUST do one of:
- look the token up (one hash and one indexed lookup) when only the total is exhausted, so that a valid token enrolls
  and the total limits only answers and logging; or
- drop the total as a reason to refuse and count failures per NodeId and per **token-hash prefix** (the first 16 bits
  of the SHA-256 of the presented token, 10 a minute each), as §5.3 does for pairing tickets.

In both, a NodeId over its own limit is still refused without the lookup (only its own failures count), and the 64
connections, 16 pending `Join`s and 10 s deadline stay as in H1. As §5.3 says for pairing, the per-NodeId and
per-prefix counters do not bound an attacker who spreads failures over fresh NodeIds and prefixes: the connection and
pending caps do. So both options keep H1's 60-a-minute total as the aggregate failure cap of §5.3, which limits failure
answers and logging, never the token lookup. SI-H2-17 tests it.

**New streams on an agent connection.** H1 lets the **agent** open one bidirectional stream per output file after the
control stream. H2 adds streams in both directions. Every non-control stream starts with one JSON header frame whose
`type` says what it is; an unknown `type` resets the stream with the error code `unsupported_stream`, never the
connection.

| Opened by | Header | Then | Answer |
|---|---|---|---|
| agent | `UploadHeader{…}` | file bytes | `UploadAck` (H1, unchanged; old agents send no `type` and are read as uploads) |
| hub | `PortOpen{lease_id, epoch, port, conn_id}` | raw bytes both ways | the agent's first frame `PortOpenAck{ok, reason?}` (`reason`: `stale_lease`, `port_not_exposed`, `not_ready`, `too_many_connections`, `connect_failed`) |
| agent | `BlobFetch{lease_id, epoch, sha256}` | — | `BlobFetchAck{ok, size?, reason?}` then `size` raw bytes (`reason`: `stale_lease`, `not_referenced`, `gone`) |

- **Who opens what.** The hub opens streams only toward agents that declared `service_jobs`; an H1 agent never sees an
  incoming stream. On agent-opened streams the hub reads a header with a `type` as one of the new kinds and a header
  without one as an H1 `UploadHeader`.
- **Fencing.** `PortOpen` and `BlobFetch` name `(lease_id, epoch)` and are refused for anything but the job's current
  lease, on both ends (SI-H2-6).
- **Limits.** Per agent connection: at most 256 concurrent port streams and 8 concurrent blob fetches. Per service
  lease: at most 64 concurrent port streams (`too_many_connections` beyond that). QUIC stream limits are set so that
  the control stream and uploads can always open (the port budget is below the connection's stream limit).
- **Port stream end.** A clean end of either side is propagated as a QUIC stream finish; a reset as a reset. Idle port
  streams are **not** timed out on the agent connection (a chat may idle for minutes); the service's `idle_timeout_s`
  (§7.1) ends the whole service instead. The client side of every port connection has its own idle limit
  (`port_idle_s`, §7.4).
- **Blob integrity.** The agent hashes what it receives and refuses a mismatch (`error="input_integrity"`, a
  `start_failed`-class error, H1 §9 "Podman failures are not job exits").

### 6.2 Pairing and invite messages

`p2pc/pair/1`: `Pair{ticket, label, platform}`, `Paired{…}`, `PairError{code}` (§5.3). `p2pc/invite/1`:
`InviteOpen{code, hub_node_id, hub_nonce}` answered by `InviteReveal{listener_nonce}` (§5.4 step 4), then, on a new
connection, `Invite{code, join_token, hub_name}` answered by `InviteAck{}` (step 6); either can get `InviteError{code}`
(`invalid_code`, `expired`, `already_open`, `hub_mismatch`). `hub_nonce` and `listener_nonce` are 32 bytes. One exchange
per connection, frame limit 4 KiB, 10 s deadline.

**Pre-auth limits of `p2pc/invite/1`** (the invite listener, §5.4; the `p2pc/pair/1` numbers are in §5.3). The listener
accepts any NodeId that knows its NodeId from the QR, so it is unauthenticated surface, with limits of its own: at most
8 connections at once and 2 pending exchanges; one `InviteOpen` or `Invite` per connection, within 10 s; a frame limit
of 4 KiB; beyond the connection limits a new connection closes with no detail. Failed exchanges (`invalid_code`) are
counted per NodeId, 5 a minute, and a NodeId over its limit is refused when it connects; there is no global failure
bucket for refusals, so a valid code that gets a slot is always accepted, and the aggregate failure cap of §5.3 limits
only answers and logging. The listener lives at most until the invite's expiry (15 minutes) and binds itself to the
first phone that opens it:
- before an `InviteOpen` is accepted, an `Invite` gets `invalid_code`;
- the first `InviteOpen` with the valid code binds the listener to its NodeId. A repeated `InviteOpen` from that NodeId
  with the same hub NodeId and hub nonce gets the same `InviteReveal`; one with other values gets `already_open`;
- from any other NodeId, every message then gets `already_open` and the connection closes;
- after its first accepted `Invite` (from the bound NodeId only) it accepts no new connection.

### 6.3 Device protocol (ALPN `p2pc/device/1`)

- **Each bidirectional stream carries one HTTP/1.1 connection** to the hub's REST API, served **in-process** by the same
  axum router as the TCP listener, with `Principal::Device` attached. Keep-alive is allowed; HTTP/2 is not used.
- A request on a device stream that carries an `Authorization` header gets `400 unexpected_authorization`: mixing two
  principals on one request is refused, so a confused client cannot run as an API key over a device connection.
- **Same limits as the REST listener** (H1 §10 "Slow clients": 10 s headers, 30 s body and request, 60 s keep-alive
  idle; streaming routes and port connections excluded from the request limit), plus the device budget below. The
  hub refuses to start with a config that breaks any of its relations.
  - **Per device:** at most 2 connections per device NodeId and at most 16 concurrent streams per device across them
    (`device_streams_per_device`). A stream is one HTTP/1.1 connection, so an upgraded port connection or a log follow
    holds one for its life.
  - **Total:** device streams count against their own budget (`device_stream_budget`, default 96), **separate from H1's
    REST connection cap**: H1's cap (256) and its tunnel budget (128, below the cap) apply unchanged to TCP connections
    and `p2pc/http/1` streams, device streams never count against that cap, and TCP connections or `p2pc/http/1` streams
    never take a device slot. The hub's open HTTP connections are thus bounded by the REST cap plus the device budget
    (352 by default). This matters on the hub PC: the TCP listener is reachable from every process on the Windows host's
    loopback and in the user's other WSL2 distros (§8.5), and unauthenticated TCP connections cost nothing, so local
    processes may fill the TCP cap, but they cannot take the device slots that the owner's app needs to revoke a phone,
    and paired phones cannot take the slots of local API-key clients. Every TCP request still needs an API key (H1 §10).
  - **Reserved for `admin`:** 32 of the 96 (`device_stream_admin_reserve`) are usable only by devices with the `admin`
    scope, so paired phones, together, hold at most 64 and can never take the slots of the hub PC's app, which is how
    a device gets revoked. The reserve must be at least `device_streams_per_device`, and below the budget.
  - **Idle limits:** a streaming route keeps H1's 60 s idle limit; an upgraded port connection on `p2pc/device/1`
    closes after `port_idle_s` (default 600 s, §7.4) with no byte in either direction (the web app opens a new one
    per chat request). A misbehaving phone that leaves streams open therefore gives them back within 10 minutes, and
    within 5 s of its revocation or of its `expires_at` (§5.5).
- **The hub checks the device at connection time and on every request.** A revocation or an expiry is seen at the next
  request, and the hub also closes the device's connections and service streams actively: its 2 s liveness sweep
  closes those of every device that is revoked or has `expires_at <= now` (§5.5).
- **Before the device check** (unauthenticated surface: any NodeId can complete the handshake). The hub looks the NodeId
  up (one indexed lookup) right after the handshake, before it accepts any stream, and closes a NodeId that is not a
  live device with `not_paired` (§5.5). Limits, counted separately from the other ALPNs: at most 32 connections at once
  that have not passed the check, each checked within 5 s; beyond that a new connection closes with no detail.
  `not_paired` closes are counted per NodeId, 10 a minute, and a NodeId over its limit is closed at connect without the
  lookup; there is no global failure bucket, so a live device that gets a slot always passes. The closes are aggregated
  into one audit event a minute (H1 §5 "Audit"; `auth_failed`, §5.6), under the aggregate failure cap of §5.3. A
  connection that passes counts against its device's 2 connections from then on. Unknown NodeIds share these 32 slots
  with every device, the hub PC's app included, so a flood of fresh NodeIds can delay the app's connection; the owner's
  revocation then goes through the offline `p2pc-server devices revoke` (§5.3), which needs no slot.
- **Why HTTP and not new messages:** one API for every client, one OpenAPI document, and the device gets every
  endpoint its scopes allow without protocol work. The cost is an HTTP/1.1 implementation in `p2pc-device` (hyper's
  client connection over the iroh stream, natively and in WASM; E9 confirms the WASM build, §18).

## 7. API additions (REST)

H1 §7 rules hold: OpenAPI 3.1 generated from the code with the drift test, RFC 9457 errors with a stable `code`,
cursor pagination, request bodies reject unknown fields, responses may grow.

### 7.1 JobSpec extension

A service job, as the "Private AI chat" template produces it (digests and hosts are placeholders until E11):

```json
{
  "kind": "service",
  "name": "Private AI chat",
  "image": "docker.io/ollama/ollama@sha256:<pinned in E11>",
  "command": ["/bin/ollama", "serve"],
  "env": {"OLLAMA_HOST": "127.0.0.1:11434", "OLLAMA_MODELS": "/volumes/models"},
  "resources": {"cpu": 4, "memory_mb": 8192, "gpu": 1, "disk_mb": 2048},
  "timeout_s": 2592000,
  "egress": {"allow": ["registry.ollama.ai", "<model CDN host, from E11>"]},
  "service": {
    "ports": [{"port": 11434, "name": "api"}],
    "health": {"http_get": "/api/version", "port": 11434, "interval_s": 10, "timeout_s": 3,
               "start_period_s": 600, "failure_threshold": 3},
    "idle_timeout_s": 3600,
    "restart": "on_node_loss"
  },
  "volumes": [{"name": "tpl:private-chat/models", "mount": "/volumes/models", "max_mb": 20480}],
  "placement": {"pools": ["mine"], "node_id": null, "labels": {}},
  "retry": {"max_attempts": 3},
  "idempotency_key": "optional"
}
```

A batch job with a blob input (the "Transcribe audio" template, abridged):

```json
{
  "kind": "batch",
  "image": "<whisper image>@sha256:<pinned in E11>",
  "command": ["/bin/sh", "/inputs/.template/transcribe.sh"],
  "env": {"LANGUAGE": "auto", "MODEL": "small"},
  "inputs": [{"path": "/inputs/audio", "blob": "sha256:<64 hex>"}],
  "volumes": [{"name": "tpl:transcribe/models", "mount": "/volumes/models", "max_mb": 5120}],
  "resources": {"cpu": 4, "memory_mb": 4096, "gpu": 1, "disk_mb": 4096},
  "timeout_s": 3600
}
```

**Validation** (in `p2pc-proto`, unit-tested). Every existing field keeps its H1 rule, with two exceptions, both for
`kind = "service"` only and both listed in §4.3: `timeout_s` (range and default) and `retry.max_attempts` (default and
meaning). For batch jobs every H1 rule holds exactly.

| Field | Rule |
|---|---|
| `kind` | `"batch"` (default) or `"service"`. |
| `timeout_s` | Every job has a finite wall-clock limit (hard rule 3): no kind has a "no limit" value, and an absent `timeout_s` takes the default below. `batch`: H1, unchanged (1-86,400, default 3,600). **Changed for `service`:** 60-2,592,000 (30 days, the maximum), default the maximum. A value out of range gets `422 out_of_range` as in H1, never clamped. When a service reaches it, it ends `timed_out` and the user restarts it (§7.2). Daily caps charge services per day (§12). |
| `service` | Required when `kind = "service"`, forbidden otherwise. |
| `service.ports` | 1-8 entries. `port` 1-65,535, unique; `name` `[a-z][a-z0-9-]{0,31}`, unique. The shim refuses to forward any port not listed (§11.2). |
| `service.health` | Optional. Exactly one of `http_get` (an absolute path, at most 256 bytes, no `..`, no CR/LF/NUL) or `tcp: true`; `port` must be in `ports`. `interval_s` 2-300 (default 10), `timeout_s` 1-60 (default 3), `start_period_s` 0-3,600 (default 300), `failure_threshold` 1-20 (default 3). Without `health`, the service is `healthy` as soon as a connection to its first port succeeds through the bridge. |
| `service.idle_timeout_s` | `null` (never) or 300-604,800. Default 3,600. Idle = no open port connection and no byte forwarded for that long, measured by the hub (§7.4). `null` is allowed only because the wall-clock limit (`timeout_s`) always applies. |
| `service.restart` | `"never"` or `"on_node_loss"` (default). See §7.2. |
| `volumes` | Allowed only when `kind = "service"` or the job comes from a template launch (§4.3, "Sandbox and hard rules"); otherwise `422 volumes_not_allowed`. 0-4 entries. `name`: `[a-z0-9][a-z0-9._-]{0,62}`, or `tpl:<template id>/<name>`, which only a template launch may use (SI-H2-9). `name` is a label, never a path: the agent derives the directory (§11.3). `mount`: absolute, under `/volumes/`, no `..`, not a prefix of another mount. `max_mb`: 64-262,144. Two entries may not share a name. |
| `inputs` | 0-32 entries `{path, blob}`. `path` follows the `files` path rules (under `/inputs`, no `..`, no path a directory of another, no clash with `files`). `blob` is `sha256:<64 lowercase hex>` and must exist in the caller's account when the job is created (`422 unknown_blob`). The sum of blob sizes and inline `files` must fit in `resources.disk_mb` minus 64 MiB (`422 inputs_exceed_disk`). |
| `template` | Read-only. Set by `POST /v1/templates/{id}/launch` (`{id, version}`); a client that sends it gets `422 read_only_field`. |
| `resources.gpu` | 0 or 1, as H1. |
| `retry.max_attempts` | 1-5, as H1. `batch`: H1, unchanged (default 2; attempts are consumed only by node loss). **Changed for `service`:** default 3, and it counts **consecutive attempts that never became healthy**, with at most 5 node-loss restarts in any 24 h whatever the count (§7.2). `jobs.max_attempts` stores the value for both kinds. |
| `idempotency_key` | H1 rules, scoped to the principal (an API key or a device, §5.6). |

The Lease frame limit (1 MiB, H1 §6) still applies to the whole job; blob inputs do not count, inline `files` do.

### 7.2 Service lifecycle and states

- **States.** The H1 words are kept: `queued → assigned → running → {succeeded | failed | timed_out | cancelled | lost}`.
  A running service adds `service.health`: `starting` (from `JobStarted` until the first passing check, at most
  `start_period_s`), `healthy`, or `unhealthy` (the last `failure_threshold` checks failed).
- **Ends of a service:**
  - stopped by a principal → `cancelled`, `reason: "stopped"`;
  - idle for `idle_timeout_s` → `cancelled`, `reason: "idle_timeout"`;
  - the daily cap of its principal reached (§12) → `cancelled`, `reason: "cap_reached"`;
  - `timeout_s` reached (at most 30 days) → `timed_out`. Nothing restarts it automatically: the user restarts it from
    the app, the web app or the CLI. A template's UI offers "Restart", which launches the template again (for a
    `singleton`, the previous instance is terminal, so the launch creates a new one, §7.6);
  - still `starting` after `start_period_s`, or `unhealthy` for `failure_threshold` consecutive checks after it was
    healthy → the agent stops it (H1 cancel sequence) → `failed`, `error: "health_check_failed"`;
  - the process exits by itself → `succeeded` (code 0) or `failed`. H2 never restarts a service in place; that is
    O-8;
  - node loss → see restart.
- **Restart on node loss.** With `restart: "on_node_loss"`, a service whose node is lost is requeued like an H1 batch
  job, with two differences:
  - `retry.max_attempts` (1-5, default 3 for services; both changed from H1, §4.3 and §7.1) counts **consecutive
    attempts that never became healthy**. An attempt that was `healthy` for at least 10 minutes resets the count. A
    gaming PC that sleeps every night therefore brings its chat back every morning, while a service that crashes the
    node at start stops after 3 tries;
  - whatever the count, node-loss restarts are capped at **5 in any 24 hours** per service. The node loss that would be
    the sixth within 24 hours ends the job `lost` with `error: "restart_limit"`, and the UI says the service kept
    losing its node. A nightly sleep stays well under the cap; a node that flaps cannot restart a service forever.

  With `"never"`, the first node loss ends the job `lost`.
- **Waiting for the same node.** A requeued service with a volume prefers the node that holds the volume (§11.3): when
  that node is eligible but offline or busy, the scheduler waits up to `volume_affinity_wait_s` (default 900 s) before
  placing it elsewhere with an empty volume. `reason` says so while it waits.
- **Who can stop a service.** `POST /v1/jobs/{id}/cancel` keeps H1's rule for `jobs:write`, unchanged: any job of the
  caller's account and project. H2 adds one path for a principal without `jobs:write`: with `templates:launch` it may
  cancel the jobs of its template view (§5.5), that is, a template job it launched itself or an instance of a
  `singleton` template in its account and project. The restriction to its own launches applies only to this
  `templates:launch` path, never to `jobs:write`. A singleton instance is shared by every launcher (a launch returns
  the running instance, §7.6), so any principal that may launch it may also stop it.
- **`GET /v1/jobs/{id}`** adds, for services, `service: {health, health_since, ports:[{port, name}], open_connections,
  last_activity_at, idle_deadline, deadline, cap_deadline, restarts_24h, setup}`; `setup` is the hub's model pull of
  §7.6 (`{state: "pulling"|"done"|"failed", completed_mb, total_mb}`, `null` for a job without one); `idle_deadline` is
  `null` while a
  connection is open or when `idle_timeout_s` is `null`; `deadline` is when `timeout_s` ends the current attempt;
  `cap_deadline` is when today's cap reservation runs out (§12), `null` for an uncapped principal. `GET /v1/jobs` gains
  the filter `kind`.

### 7.3 Endpoints added

| Method and path | Scope | Notes |
|---|---|---|
| `POST /v1/jobs/{id}/ports/{port}/connect` | services:connect, or templates:launch for a template service of its template view (§5.5) | HTTP/1.1 upgrade to a raw byte stream into the service; on the template-view path, one request filtered by the template's `allowed_routes` (§7.4). |
| `POST /v1/blobs` | blobs:write | Upload one blob (§7.5). |
| `HEAD /v1/blobs/{sha256}` | blobs:write or jobs:read | `200` with `Content-Length` if the caller's account has it, else `404`. |
| `GET /v1/blobs` | jobs:read | `{sha256, size, created_at, referenced_by, expires_at}`, cursor pagination. |
| `DELETE /v1/blobs/{sha256}` | blobs:write | Removes the caller's claim (an `admin`: every claim); a caller without a claim gets `403`, unless it is `admin` (§7.5). `409 blob_in_use` while a non-terminal job references it. |
| `GET /v1/volumes` | nodes:read | `{name, node_id, size_mb, max_mb, last_used_at, in_use_by}` from the latest `VolumeReport`s. |
| `DELETE /v1/volumes/{node_id}/{name}` | admin | Sends `VolumeDelete`. `{name}` is one percent-encoded path segment: a `tpl:` name is sent as `tpl%3Aprivate-chat%2Fmodels`, and the hub decodes the segment once and validates the result with §7.1's name rule (`404` for an unknown volume). `409 volume_in_use`; `503 node_offline` (the deletion is not queued). A route test and a CLI test (`p2pc volumes rm`) cover a `tpl:` name. |
| `GET /v1/templates` | jobs:read or templates:launch | The loaded template bundle (§7.6), with `bundle_version`; an empty list and `bundle_error` when no bundle can be loaded. |
| `POST /v1/templates/{id}/launch` | templates:launch | `{params, idempotency_key?}` → `201` with `Job`, or `200` with the running instance of a `singleton` template. |
| `POST /v1/devices/pairing-tickets`, `GET …`, `DELETE …/{id}` | admin | §5.2 (body `{label?, scopes?, daily_unit_cap?, allowed_images?, expires_in_s?, device_expires_in_s?, blobs_quota_mb?}`). `POST` returns `{ticket, url, expires_at}` once. |
| `GET /v1/devices`, `GET /v1/devices/{id}` | admin, or the device itself | `{id, label, platform, scopes, daily_unit_cap, allowed_images, blobs_quota_mb, expires_at, created_at, last_seen_at, revoked_at, paired_by}`. For a non-`admin` device, `GET /v1/devices` is filtered to that device alone (a one-item list), and `GET /v1/devices/{id}` of any other device gets `404`, as an unknown id. |
| `DELETE /v1/devices/{id}` | admin, or the device itself | Revoke (§5.5); an `admin` principal that could not have created the device gets `403 escalation_denied`. |
| `POST /v1/nodes/join-tokens` | admin, or nodes:join | H1, plus `nodes:join` with `expires_in_s <= 900`, and an optional `pre_approved` (bool, `admin` only, else `403`; with it `expires_in_s <= 900`, else `422 out_of_range`). The node starts `pending_approval` (§5.5) when the token's minter is a non-`admin` principal, or an `admin` device without `pre_approved`; tokens of `admin` API keys enroll as in H1. |
| `POST /v1/nodes/join-requests` | nodes:invite | `{listener_node_id, iroh_node_id, invite_expires_at, listener_commitment}` → `201 {id, expires_at, hub_nonce}` (15 min), state `awaiting_reveal`. `422 invalid_join_request` when `invite_expires_at` is not within `(now, now + 15 min + 120 s]`, a NodeId is not a valid Ed25519 public key or the commitment is not 32 bytes. `429` beyond 4 open per account, 2 open per device or 6 created per device per hour. §5.4. |
| `POST /v1/nodes/join-requests/{id}/reveal` | the requesting device | `{listener_nonce}`, only while `awaiting_reveal` and created at most 15 minutes ago: a nonce that matches the commitment sets `pending` (`200`); one that does not sets `rejected` and gets `409 join_request_closed`, as does a call in any other state (a second reveal included) or after 15 minutes. §5.4 step 4. |
| `GET /v1/nodes/join-requests`, `GET /v1/nodes/join-requests/{id}` | admin, or the requesting device (its own requests only; the list is filtered to them) | `{id, requested_by, listener_node_id, iroh_node_id, approval_phrase, state, created_at, expires_at}`, `state` one of `awaiting_reveal`, `pending`, `approved`, `rejected`, `expired`, `delivered`; `approval_phrase` is `null` while `awaiting_reveal`. |
| `POST /v1/nodes/join-requests/{id}/approve` | admin | Records the approval; mints nothing. `409 join_request_closed` unless `pending` and created at most 15 minutes ago. |
| `POST /v1/nodes/join-requests/{id}/token` | the requesting device | Only when `approved` and created at most 15 minutes ago (on the hub's clock, whatever state the expiry sweep has left it in): mints the join token (15 min, single use, bound to the request's `iroh_node_id`) on behalf of the approving principal, reloaded in the minting transaction (`409 join_request_closed` if it is revoked or expired), stores only its hash, returns `{join_token, expires_at}` once and sets `delivered`. Otherwise `409 join_request_closed`. |
| `DELETE /v1/nodes/join-requests/{id}` | admin, or the requesting device | Reject or withdraw an `awaiting_reveal` or `pending` request. |
| `POST /v1/nodes/{id}/approve` | admin | Approves a `pending_approval` node (idempotent); audited `node_approved` (§5.5). |
| `GET /v1/server` | any principal | H1 fields plus `api_version` (integer, 2 for H2), `min_web_version`, `hub_name`, `max_blob_mb` (§7.5). |
| `PATCH /v1/server` | admin | `{hub_name}` (1-64 printable characters). |

No endpoint returns blob contents: the hub is not a file store.

### 7.4 Service ports

- **Request.** `POST /v1/jobs/{id}/ports/{port}/connect` with `Connection: Upgrade` and `Upgrade: p2pc-port/1`, no body.
  On success the hub answers `101 Switching Protocols` and the connection becomes a raw, bidirectional byte stream to
  `127.0.0.1:<port>` inside the service's container; on the template-view path, a filtered HTTP request instead
  (below).
- **Errors before the upgrade:** `404` (unknown job, or not visible to the principal), `409 service_not_running`,
  `409 service_not_ready` (health is `starting`; `?wait_ready=true` waits up to 30 s instead),
  `422 port_not_exposed`, `429 too_many_connections`, `502 node_unreachable` (the hub could not open the stream or the
  agent answered `PortOpenAck{ok:false}`; the agent's `reason` is in `detail`).
- **The same endpoint serves every client:** devices over `p2pc/device/1`, API keys over TCP REST or `p2pc/http/1`
  (H1 tunnel) and behind a TLS reverse proxy that passes upgrades. One code path, one authorization check
  (SI-H2-5): `services:connect` for any service of the caller's project, or `templates:launch` for a template service
  of the caller's template view (§5.5); any other job answers `404`.
- **Template-view connections carry filtered HTTP, never raw bytes.** When the connect is authorized through the
  template view (the principal has `templates:launch` but not `services:connect`), the hub does not splice the
  upgraded connection into the port. It reads **one** HTTP/1.1 request from it and forwards that request only if its
  method and path match an entry `{port, method, path}` of the template's `allowed_routes` (§7.6), taken from the
  bundle the hub serves by the job's `template.id` (no bundle served: nothing matches):
  - the request target is origin-form and equals the entry's path byte for byte, with no query, no fragment and no
    decoding or normalization; the only wildcard is a final path segment `*` (one non-empty segment of
    `[A-Za-z0-9._-]`), and the bundle test allows it only where a template needs it (the beta templates do not);
  - request line and headers at most 8 KiB and 64 headers (`431 headers_too_large`), within H1's 10 s; a body only
    with `Content-Length`, at most 1 MiB (`413 too_large`), within 30 s; `Transfer-Encoding`, `Upgrade`, `Expect` and
    the `CONNECT` method get `400`;
  - anything else gets `403 route_not_allowed` from the hub itself, and nothing reaches the service;
  - an allowed request is forwarded with `Connection: close` set, no byte after its body is forwarded, and the
    response is relayed as it comes (a streamed chat answer included) until the service closes; then the hub closes
    the connection. The next request needs a new connection, as the web app already opens one per chat request.

  Raw port connections stay available to principals with `services:connect` (developer devices, `admin` keys and
  devices). SI-H2-18 tests the filter.
- **Limits.** The upgraded connection leaves the H1 whole-request limit. On every transport it closes after
  `port_idle_s` (default 600 s) with no byte in either direction. On the TCP listener and `p2pc/http/1`, upgraded port
  connections together hold at most `port_conn_budget` (default 64, below H1's REST cap of 256) of that cap, so the rest
  stays for other requests; beyond it, `429 too_many_connections`. On `p2pc/device/1` they count against the device
  budget (§6.3). At most 64 open connections per service and 16 per principal per service. Bytes are counted per service
  per UTC day (§12), never logged.
- **Idle accounting.** The hub, which relays every byte, updates `last_activity_at` at most once every 10 s per
  service, and sends `Cancel{reason:"idle_timeout"}` when `idle_timeout_s` has passed with no open connection and no
  traffic. A clock-injected test covers it.
- **Client helpers.** `p2pc service connect <job> --port <p> [--listen 127.0.0.1:<local>]` listens locally and opens
  one upgraded connection per accepted TCP connection; the Python SDK has `client.services.connect(job, port)` (a
  context manager returning a local port); the web app and the desktop app use `p2pc-device`'s
  `open_port(job, port) → duplex stream`.
- **What the hub sees.** The hub relays service bytes in clear text between two encrypted transports. It is the owner's
  own hub, inside the owner's own PC; §15.2 lists it anyway.

### 7.5 Blobs

- **Upload.** `POST /v1/blobs` with `Content-Length` (required; chunked uploads get `411`), `X-P2PC-SHA256: <64 hex>`
  (required) and the raw bytes as the body. Answers `201 {sha256, size, created_at, expires_at}`, or `200` with the
  same body when the account already has it (the body is still read and discarded, or the client may `HEAD` first).
- **Checks before reading the body:** `Content-Length <= max_blob_mb` (default 2,048 MiB, `413 too_large`); then, with
  `checked_add`, the account's stored bytes plus in-flight reservations plus this size `<= blobs_quota_mb` (default
  20,480 MiB; on the hub PC the app sets it at "Create my cloud" from the disk arithmetic of §8.2;
  `507 quota_exceeded`); for a device with `blobs_quota_mb` (§5.2), the same sum over the blobs it holds a claim on
  and its own reservations must also fit that quota (`507 quota_exceeded`); and at most 2 uploads per principal are in
  progress at once (`429 too_many_uploads`). The reservation is taken in the same short transaction and released on
  every exit path. Every principal whose upload creates the blob or is deduplicated against it gets its own claim, a
  `blob_uploaders` row (§5.6), so a later uploader is recorded as well as the first.
- **Writing.** The body streams to `<data>/blobs/staging/<random>` while hashing. A short body, a hash mismatch
  (`422 digest_mismatch`) or a broken connection deletes the staging file. On success: `fsync`, rename to
  `<data>/blobs/<account_id>/sha256/<aa>/<bb>/<hex>`, then insert the row (two short transactions with no I/O under
  the write lock; the H1 rule). `<account_id>` is the hub's own account ID (a fixed ID format, never a string from the
  request), so the file of a digest exists once per account and only rows of that account refer to it.
- **Timeouts.** The upload route leaves the 30 s body limit; it has a 60 s idle limit instead, and a floor of 16 KiB/s
  averaged over any 60 s window. An upload of 2 GiB at 9 Mbit/s (E4's relay figure) takes about 30 minutes **(H)**:
  allowed, but the web app warns above 200 MiB.
- **Namespacing.** Blobs are content-addressed **per account**, in the database and on disk: deduplication never
  crosses accounts, `HEAD` in one account says nothing about another, and GC or `DELETE /v1/blobs/{sha256}` in one
  account never removes a file that another account's row refers to (SI-H2-8). H2 has one account per hub (H1 §5);
  the per-account path keeps this true when Milestone 3 adds more.
- **Lifetime.** A blob expires 24 h after it was uploaded or after the last job that references it became terminal,
  whichever is later, plus the artifact retention when a job references it (H1 §12, 7 days). A non-terminal job keeps
  it alive. GC follows H1's retry-queue rule (`ORDER BY last_attempt_at`) and deletes in three steps, never the file
  before its row is dead:
  1. **Tombstone**, in one short `BEGIN IMMEDIATE` transaction that re-checks the blob is expired and unreferenced:
     set `deleting_at`. From then on `HEAD`, `GET /v1/blobs`, upload deduplication and job creation treat the blob as
     absent. Job creation checks the blob and inserts its reference in one transaction too, so either the reference
     comes first and the re-check keeps the blob, or the tombstone comes first and the job gets `422 unknown_blob`.
  2. **File**: delete it, outside any database transaction.
  3. **Row**: delete it.

  `DELETE /v1/blobs/{sha256}` on a blob of the caller's account that no non-terminal job references removes only the
  caller's claim (an `admin` removes every claim; a caller without a claim gets `403`), and runs the same three steps
  at once when no claim remains.
  An upload of a digest with a tombstone waits until step 3 has run for it, then stores the blob as new. A lock in the
  hub keyed by **`(account_id, digest)`** makes this safe: the GC (or the `DELETE`) holds it from before step 1 until
  step 3, and an upload holds it from its check of the row (deduplication or tombstone) until its rename and row
  insert. The same digest in two accounts takes two different locks and two different files. A GC that stops between
  steps resumes from the tombstone.
- **Delivery to a node** is the `BlobFetch` stream (§6.1), into the job's `inputs/` directory, read-only in the
  container like inline files.

### 7.6 Templates

- **A template** is a vetted JobSpec plus a UI entry. It is data: `templates/<id>.toml` in the repository, reviewed like
  code. Fields: `id`, `version`, `title`, `description`, `kind`, `ui` (`chat`, `transcribe` or `none`), `singleton`
  (bool), `requirements` (`gpu = "required" | "preferred" | "none"`, `min_vram_mb`), `params` (typed: `enum` with
  values, `int` with bounds, `bool`, `blob`; each with one `target`, below), the `spec` (a JobSpec), `licenses` (the
  image and model licenses, shown in the UI), `download_mb` (an estimate of the first-run download, shown before
  launch) and, for a service, `allowed_routes`: the `{port, method, path}` entries that template-view principals may
  send to it (§7.4; exact method and path). A service template without them is closed to template-view principals.
- **Resources are fixed by the template.** The `spec` sets the job's `resources`; a template has no separate
  `resources` field and no minimum or maximum, because no parameter target reaches them. The only resource the hub
  changes at launch is `resources.gpu` (below).
- **Parameter targets.** A parameter reaches the job in exactly one of these ways, named by its `target`:
  - `env:<NAME>` or `argv:<index>`: a **whole** env value or a **whole** argv element of the template's `spec`;
  - `field:<JobSpec field>`, only for an `int` parameter and only for a field of this closed list:
    `service.idle_timeout_s` and `timeout_s`. The template's bounds for the parameter must lie inside the field's
    JobSpec range (§7.1) for the template's `kind`, and the launch checks the value's type and the template's bounds
    (`422 invalid_params` outside them) before the normal JobSpec validation runs on the result;
  - `input:<path>`, only for a `blob` parameter: one `inputs` entry `{path, blob}` at the path fixed by the template;
    the digest must exist in the caller's account (`422 unknown_blob`, §7.1);
  - `pull`, only for an `enum` parameter of a `ui = "chat"` template: the model the hub downloads at launch (below).

  The only other field the hub sets at launch is `resources.gpu`, from `requirements.gpu` (placement hints, below).
- **Rules every template MUST meet** (checked by a test over the whole bundle):
  - the image is pinned by `@sha256:` digest;
  - parameters reach the job only through the targets above: whole env values, whole argv elements, a listed JobSpec
    field within the template's bounds, or an `inputs` entry at a fixed path; never interpolated into a shell string
    or a path; enum values come from the template;
  - egress is a fixed list in the template; volumes use the `tpl:<id>/` namespace;
  - `allowed_routes` name ports in `service.ports`, one method and an exact absolute path each (a final `*` segment
    only where the template needs it), and never a route that pulls, creates, copies, pushes or deletes models;
  - the spec sets a finite `timeout_s` (for a batch template, one that fits the daily caps the template is meant for);
  - every field passes the normal JobSpec validation.
- **Bundle.** CI compiles `templates/*.toml` into `templates.json` and signs it with the release key (minisign,
  §5.1). The hub embeds the bundle of its own release. It may load a newer bundle from `<data>/templates/` (put there
  by the desktop app's updater, §14.1). This lets a security fix move an image digest without a hub release, so the
  hub also refuses to go back (anti-rollback):
  - **High-water mark.** The hub stores, in its database, the `bundle_version` and SHA-256 of the highest bundle it
    has ever loaded (`template_bundle_state`, §13), written in the same step that makes the bundle current. A hub
    upgrade whose embedded bundle is above the mark raises it at start.
  - **Loading a bundle file** requires all of: the signature verifies against the embedded public key; its
    `bundle_version` is higher than the embedded one (the embedded floor); it is not lower than the mark, and a bundle
    equal to the mark has the recorded SHA-256 (the same bundle loaded again at start); its `min_hub_version` is at
    most the hub's version. Otherwise the hub logs why and ignores the file.
  - **What it serves.** The highest of the valid bundle file and the embedded bundle, as long as it is not below the
    mark. If neither reaches the mark (the file at the mark was deleted or damaged), the hub serves no template:
    `GET /v1/templates` returns an empty list with `bundle_error`, a launch gets `503 templates_unavailable`, and the
    desktop app's next update check fetches the current bundle again (§14.1). An older bundle is never served.
  - The hub reads `<data>/templates/` at start and every 60 s; a bundle that becomes current is audited as
    `template_bundle_loaded` with its version.
- **Launch.** `POST /v1/templates/{id}/launch` validates `params` against the template (unknown parameter, wrong type or
  out of bounds → `422 invalid_params`), builds the JobSpec through the parameter targets, sets
  `template: {id, version}` and creates the job with the caller as principal. Caps, image allowlists and placement
  apply as for any job. For a `singleton` template, a launch while an instance is `queued`, `assigned` or `running`
  returns that instance (`200`); any principal with `templates:launch` in that account and project may also stop it
  (§7.2).
- **Model download.** Models reach a template's volume only from the hub, never from a principal: when an attempt of a
  job whose template has a `pull` parameter first becomes healthy, the hub itself sends one
  `POST /api/pull {"model": <the parameter's value>, "stream": true}` to the service through the bridge and reports
  its progress as `service.setup` (§7.2). It reads the answer as untrusted: lines of at most 4 KiB, only `status`,
  `completed` and `total`; a longer or malformed line ends the pull with `setup.state = "failed"`.
- **Launch by a capped principal** (one with a `daily_unit_cap`). The launch is checked against the cap before the job
  exists, and refused with H1's `402 cap_exceeded` and a `detail` that names the template, the units it needs and
  the units left today, so the UI can say "Your daily limit does not allow <template>". A batch template passes when
  its estimate (resources × its finite `timeout_s`) fits what is left today; a service template passes when the
  first day's reservation of §12 gives it at least 15 minutes of runtime, and is then stopped with a notice when the
  day's cap is reached (§12).
- **Placement hints.** `requirements.gpu = "preferred"` launches with `gpu: 1` when the account has an eligible GPU
  node and with `gpu: 0` otherwise; the UI says "running on CPU: slow".

**Templates shipped with the beta:**

| Template | Kind | What | Status |
|---|---|---|---|
| `private-chat` | service, singleton, `ui = "chat"` | Ollama (MIT [S12]) with its API on port 11434, models in `tpl:private-chat/models` (20 GiB cap), `idle_timeout_s` an `int` parameter with target `field:service.idle_timeout_s` (900-86,400 s, default 3,600, inside the field's 300-604,800 range), `timeout_s` 30 days (the maximum; after it the chat UI offers "Restart"). `allowed_routes`: `POST /api/chat` and `GET /api/tags` on port 11434, nothing else. Parameter `model` (target `pull`): an enum of small models whose licenses allow this use; default **a model of at most ~4 B parameters with an Apache-2.0 or MIT license (H)**, chosen in E11 by quality, size (about 2.5 GiB **(H)**) and VRAM (fits 6 GiB **(H)**). Ollama follows `HTTPS_PROXY` for downloads [S12], which the shim sets (H1 §9). | E11 pins the image digest, the model list and the egress hosts. |
| `transcribe` | batch, `ui = "transcribe"` | whisper.cpp (MIT; upstream publishes `ghcr.io/ggml-org/whisper.cpp:main-cuda` with ffmpeg included [S13]) with a fixed script (`/inputs/.template/transcribe.sh`, shipped as an inline `files` entry of the template, so it is read-only in the container): convert the input with ffmpeg, run the model, write `transcript.txt`, `.srt` and `.vtt` to `/outputs`. Parameters: `audio` (`blob`, target `input:/inputs/audio`), `language` (enum, default `auto`, target `env:LANGUAGE`), `model` (`base`, `small` default, `medium`; target `env:MODEL`). Models in `tpl:transcribe/models` (5 GiB cap). | E11 chooses the image (an upstream image with ffmpeg and CUDA, or our own build published by digest) and the model download hosts. |

The chat UI is part of the web app (§9.4): it uses exactly the template's `allowed_routes` of Ollama's HTTP API
(`GET /api/tags`, `POST /api/chat` with `stream: true`) through §7.4, and shows the hub's model download from
`service.setup`. Nothing of a third-party web UI is loaded into the phone.

### 7.7 Errors added

`invalid_ticket`, `not_paired`, `unexpected_authorization`, `last_admin_device`, `route_not_allowed`,
`headers_too_large`, `service_not_running`,
`service_not_ready`, `port_not_exposed`, `too_many_connections`, `node_unreachable`, `unknown_blob`,
`inputs_exceed_disk`, `digest_mismatch`, `quota_exceeded`, `blob_in_use`, `volume_in_use`, `volumes_not_allowed`,
`node_offline`, `read_only_field`, `unknown_template`, `invalid_params`, `templates_unavailable`, `join_request_closed`,
`invalid_join_request`. Every one is in the OpenAPI document with its HTTP status. H1's `last_admin_key` stays,
unchanged, for keys (§5.5), and H1's `cap_exceeded` serves template launches too (§7.6). The MCP tool error
`path_not_allowed` (§7.8) is not an API error.

### 7.8 Clients (CLI, SDK, MCP)

Additive. H1 client rules (credentials, retries of idempotent calls only, outage tracking, exit codes, escaping job
output) apply to every new command.

- **CLI.**
  - `p2pc service run [--port <p>[:<name>]]… [--health-http <path> | --health-tcp] [--idle <dur>|--no-idle]
    [--restart never|on-node-loss] [--volume <name>:<mount>[:<size>]]… <run options> -- <command>`: prints the job
    ID; `--wait-ready` waits for `healthy`. For services the H1 `--timeout` option defaults to 30 days, the maximum.
  - `p2pc service connect <job> --port <p> [--listen <addr>]`: a long-running local forwarder. It exits when the
    service becomes terminal: 0 for `cancelled` or `succeeded`, otherwise the H1 code of that outcome (75 lost, 124
    timed out, the exit code or 125 for `failed`). SIGTERM → 0 and Ctrl-C → 130, as `p2pc proxy`.
  - `p2pc service stop <job>` (alias of `cancel`), `p2pc service list`.
  - `p2pc blobs put <file>` (HEAD first; prints the digest), `p2pc blobs ls`, `p2pc blobs rm <digest>`.
  - `p2pc run --input <local file>:<container path>`: uploads the file as a blob (HEAD first) and adds the `inputs`
    entry. Inline `--file` keeps the H1 512 KiB limit.
  - `p2pc templates ls`, `p2pc templates launch <id> [--param k=v]…`.
  - `p2pc devices ls`, `p2pc devices revoke <id>`, `p2pc devices pair [--scopes …] [--cap <units>]
    [--image <pattern>]…` (the cap and image flags of `p2pc keys create`): prints the pairing URL once, as a secret,
    and a QR code in the terminal when stdout is a TTY.
  - `p2pc volumes ls`, `p2pc volumes rm <node> <name>` (the name percent-encoded into one path segment, §7.3).
  - `p2pc nodes approve <node>` (§5.5) prints the node phrase and asks for confirmation (`--yes` skips it);
    `p2pc nodes ls` shows `approval`.
- **Python SDK.** `client.blobs.put(path)`, `client.jobs.run(..., inputs={"/inputs/x": blob})`,
  `client.services.run(...)`, `client.services.connect(job, port)`, `client.templates.list()/launch(...)`.
- **MCP.** `p2pc_run` accepts `inputs` with blob digests only, never a local path. A new tool `p2pc_blob_put` uploads
  a local file. No service tools in H2. H1 treats the agent behind MCP as steerable by untrusted job output (H1 §7
  "Job output is data"), so a prompt-injected agent must not be able to upload `~/.ssh/*` or the CLI's credentials as
  a blob and then send them out through a job with egress. `p2pc_blob_put` therefore reads only from one directory
  (SI-H2-21):
  - **The upload directory.** `p2pc mcp --upload-dir <dir>`, default `~/p2pc-uploads`. At start `p2pc mcp` creates it
    with mode 0700 if it is missing. It refuses to start when the directory is a symbolic link, is not a directory
    owned by the user, or grants group or other access; and when it is the user's home directory itself, or is,
    contains or lies inside the p2pc config and credentials directory.
  - **Paths.** The tool takes a path relative to the upload directory; an absolute path is accepted only when it lies
    lexically under the upload directory, and is then handled as the relative rest. Empty, `.` and `..` components,
    and any component that starts with `.` (hidden files and directories), are refused before anything is opened.
  - **No symbolic link anywhere.** The tool opens the upload directory with `O_NOFOLLOW | O_DIRECTORY` and each
    component below it with `openat(O_NOFOLLOW)` (`O_DIRECTORY` for the intermediate ones), so no link is followed in
    any component. Where the platform has no `openat` (Windows), it canonicalizes the path, re-checks that the result
    is under the canonical upload directory, and refuses the path if any component is a symbolic link or another
    reparse point.
  - **Regular files only.** Before opening the last component, an `fstatat(AT_SYMLINK_NOFOLLOW)` must show a regular
    file; it is then opened with `O_NOFOLLOW | O_NONBLOCK` (so a FIFO swapped in cannot block), and `fstat` on the
    descriptor must show a regular file with the same device and inode. FIFOs, sockets, devices and directories are
    refused.
  - **Size.** The size from `fstat` must be at most the hub's `max_blob_mb` (from `GET /v1/server`, §7.3). The hash
    and the upload read the same descriptor, never the path again, and the upload stops with an error if the file
    yields more bytes than that size.
  - **Errors** are the tool error `path_not_allowed` with the rule that failed. The tool never returns file contents.

  The same rule, through the same function, applies wherever the CLI reads a local file on an agent's behalf; in H2
  `p2pc_blob_put` is the only such place. The interactive `p2pc blobs put` and `p2pc run --input` read the path the
  user typed, as any CLI command does.

## 8. Desktop app

### 8.1 Shape

- **Decision: Tauri 2** (Rust core, system WebView2, web UI), Windows 11 first.
  - *Alternatives.* Electron: ships its own Chromium (≈100 MB more), and the core logic would be Node rather than our
    Rust crates. A native WinUI app: no reuse of the web UI, and a Windows-only skill set. Flutter: no reuse of the
    TypeScript UI or of `p2pc-device`'s WASM sibling. Tauri reuses the Rust crates (`p2pc-wsl`, `p2pc-device`) and the
    web app's UI (D3).
- **Installer:** NSIS, **per-user** (`installMode: "currentUser"`), which needs no administrator rights and installs
  under `%LOCALAPPDATA%` [S4]. WebView2 through the default `downloadBootstrapper` [S4]; Windows 11 already ships the
  runtime.
- **Process model.** One app process per signed-in user, single instance, started at sign-in from `HKCU\…\Run` (opt-out
  in Settings), living in the tray. Closing the window keeps the tray icon. The app is **not** what keeps the node
  running: the H1 scheduled task does (§8.5), so quitting the app does not stop sharing.
- **The app never needs administrator rights**, except once to install WSL (§8.2 step 2). Every other operation
  (`wsl --import`, the scheduled task with a per-user logon trigger, `HKCU` keys) works with a standard user token,
  as H1 measured for the task (H1 §9.0).

### 8.2 First run

| Step | Screen | What happens | Time budget (H) |
|---|---|---|---|
| 1 | **Welcome** | What P2PC does and does not do, in five lines: it runs only what you start, nothing is visible on your network, you can stop or uninstall at any time, no account, no telemetry. Then one explicit choice with **nothing preselected**: "Check for updates and verify the web app automatically: Yes / No" (§14.1, §9.6; hard rule 6). "Start" stays disabled until the user picks one; Settings has the same toggle. The beta testers' guide asks testers to choose "Yes". | — |
| 2 | **Checks** | Windows build ≥ 22000 (Windows 10 21H2+ works for H1 but is not supported by the beta app); virtualization on in the firmware; WSL present and ≥ 2.0; WSL default version 2; ≥ 20 GiB free on the profile's drive; NVIDIA driver present (warning only). These are `install.ps1`'s checks (H1 deploy README), same thresholds (its `-MinFreeGB 20` counts in units of 2^30 bytes, so GiB). In the background the node image download starts (§8.3). | 15 s |
| 2a | **Install WSL** (only if missing or too old) | Explains why, then runs `wsl.exe --install --no-distribution` **elevated** (one UAC prompt) [S6]. If the Virtual Machine Platform had to be enabled, asks for the **one reboot** and registers a `HKCU\…\RunOnce` entry so the app reopens at step 2 after it. | 1-2 min + reboot |
| 3 | **Share** | Three controls: CPU cores (1 … the WSL VM's processors), RAM (1 GiB … the WSL VM's memory, which WSL caps at 50 % of the host's RAM by default [S7]; the app never edits `.wslconfig`, H1 §9.0), GPU on/off (only if the node reports an offerable GPU), and one "Disk space for P2PC" control, the share `D` for jobs and volumes (disk arithmetic below). A "Keep this PC awake while sharing" switch (§8.6). Meanwhile the image is verified and imported (`wsl --import … --version 2`). | 30-90 s (import < 1 min, H1 deploy README) |
| 4 | **Create or join** | "Create my cloud" (first PC) or "Join my cloud" (§5.4). Create: writes `hub.enabled`, runs `p2pc-server init --owner-device <the app's device NodeId> --hub-name "My cloud"`, starts the hub, makes a join token with `pre_approved: true` over the app's own device connection (so the hub PC's own node is `approved` at once, §5.4) and joins the local agent through stdin. | 15-30 s |
| 5 | **Add my phone** | A QR code with a pairing ticket (phone profile, 10 min), the web app URL as text, and "Skip for now". Shows "Paired: <platform>" when it happens. | 30-60 s |
| — | **Ready** | "Your cloud is ready", the PC list, the phone list, and (hub PC) the sentence of §8.6. | — |

- **Disk arithmetic.** P2PC's disk use on a PC has four parts, all on the profile's drive (the distro's virtual disk):
  - `D`, the share of step 3, split with one formula: jobs `offered.disk_mb = min(50 GiB, D / 2)` and volumes
    `volumes_mb = D − that`;
  - `I`, the node's container image store: an allowance of 16 GiB **(H)** for the template images (CUDA builds of
    Ollama and whisper.cpp) plus a few job images; E11 measures the template images and fixes `I`. H1's per-image size
    cap still applies, and H1's disk floor protects the owner's disk if images grow past `I`;
  - `B`, on the hub PC only, the hub's blob quota (`blobs_quota_mb`, §7.5);
  - the 20 GiB floor of step 2, which stays free.

  So `D ≤ free − 20 GiB − I − B`, and the control's default is `min(90 GiB, that)`. Step 3 does not yet know whether
  the PC will host the hub, so it computes with `B = 0`; "Create my cloud" (step 4) then sets `blobs_quota_mb` to
  `min(20 GiB, free − 20 GiB − I − D)`, and when that is under 4 GiB (twice the largest blob) it goes back to step 3
  and asks for a smaller share.
  - **Minimum for the templates.** Both templates need `D ≥ 50 GiB`: that gives 25 GiB for volumes (20 GiB for
    `private-chat`'s models plus 5 GiB for `transcribe`'s, §7.6) and 25 GiB for jobs. The Share control marks 50 GiB;
    below it, the app says "The AI chat and transcription may not run on this PC" (the scheduler finds the node
    ineligible for a volume that does not fit, §11.3). Step 2 keeps `install.ps1`'s 20 GiB check for the distro and adds
    a warning when free space is under `20 GiB + I + 50 GiB` (86 GiB with the default `I`; 106 GiB on a PC meant to be
    the hub, with the default `B`).
  - With the defaults, a PC needs `90 + 16 + 20 = 126` GiB free for the default share, and the hub PC 146 GiB.
- **Budget.** On the reference PC (§16) with WSL already installed, steps 1-5 fit in about 3-4 minutes **(H)**: image
  download ≈ 430 MB (H1 deploy README) ≈ 35 s at 100 Mbit/s, import < 1 min, distro start ≈ 1 s (E1: 0.78 s), hub init
  and join a few seconds. E10 measures it, including the WSL-install path.
- **Resumable.** Each step writes its result to `%LOCALAPPDATA%\P2PC\setup.json`. A crash, a closed window or the
  reboot resumes at the first unfinished step; a finished step is never redone (import is not repeated if the distro
  exists and passes its checks).
- **Virtualization off in the firmware** cannot be fixed by the app. It shows a short guide and a link to the
  manufacturer-neutral Microsoft page, and stays at step 2. E10 records how often testers hit this.
- **Errors** have codes and fixed messages (§8.8). The app never shows a raw stack trace or a PowerShell error.

### 8.3 `p2pc-wsl`: installing and upgrading the distro from Rust

- **Decision: port the needed logic of `install.ps1` to Rust,** in the `p2pc-wsl` crate, instead of calling the script.
  - *Why not call `install.ps1`.* Execution policy and "downloaded file" marks block it (H1 deploy README tells users to
    unblock it by hand); PowerShell 5.1 re-encodes binary data on pipes, which the script works around with `cmd.exe`
    redirections; its errors are exit codes plus console text that the app would have to parse. Rust drives
    `wsl.exe` with byte-exact pipes and returns typed errors.
  - *Cost.* Two implementations of the same rules. Mitigation: `install.ps1` stays the developer path, and a **parity
    test** runs both against the same scenarios on the Windows CI runner (checks, install, upgrade carrying state,
    uninstall) and compares the resulting state (distro listing, `/var/lib/p2pc` and `/var/lib/p2pc-server` listings,
    task XML).
- **What it does** (each one H1 behaviour unless marked):
  - the checks of §8.2 step 2, with H1's thresholds;
  - **image download** from the release (URL and SHA-256 compiled into the app build for its matching image version;
    HTTP range resume; verified before import) — new;
  - `wsl --import p2pc-node <%LOCALAPPDATA%\P2PC\wsl\p2pc-node> <tar> --version 2`;
  - the boot-status freshness rule (`init_starttime`) before declaring the distro ready;
  - **upgrade** with H1's state-preserving procedure (stop, archive inside the distro, copy out byte-exact with hash
    check, unregister, import, restore, verify listings), extended to archive **both** `/var/lib/p2pc` and
    `/var/lib/p2pc-server` — changed;
  - the scheduled task "P2PC node" with H1's triggers (logon of this user, plus the 5-minute watchdog), its wrapper
    and its exit-64 terminal stop; registered from a task XML through `schtasks /Create /XML` under the user's token,
    with the DACL that lets the user's own wrapper disable it;
  - stop, start, uninstall (§8.7).
- **Never:** touch other distros, `.wslconfig`, Windows features (except the explicit elevated `wsl --install` of step
  2a), the firewall, or anything outside `%LOCALAPPDATA%\P2PC` and the app's own folders.

### 8.4 States and controls

| State | Meaning | Tray icon | Entered by |
|---|---|---|---|
| `setup` | First run not finished | grey | install |
| `sharing` | Node online, taking work | green | resume, setup done |
| `paused` | Node online, takes no new work; running jobs and services continue | yellow | "Pause" |
| `stopped` | Distro terminated, task disabled; nothing runs. On the hub PC the whole cloud is offline | grey | "Stop sharing" / "Turn off my cloud" |
| `updating` | §14 | blue | update |
| `attention` | An error needs the user (§8.8) | red | any error |

- **Pause / resume** set `owner_paused` through `p2pc-agent share set --paused true|false` run with `wsl.exe` (§6.1).
  They work on every PC, with or without the hub. The node's existing H1 drain by the API stays separate.
- **Share changes** run `p2pc-agent share set --cpu … --memory-mb … --gpu … --disk-mb … --volumes-mb …`. The agent
  validates (never above hardware, H1 §6), writes `agent.toml` atomically and sends `InventoryUpdate` within 10 s.
  Leases already running keep their reservation; lowering the share below what runs only stops new placements.
- **Stop sharing** (joined PC) is H1 `-Stop`: disable the task, `wsl --terminate p2pc-node`. Running work is lost and
  retried elsewhere (H1 §9 "no checkpointing"); the app asks for confirmation when something runs.
- **On the hub PC** the choices are "Pause", "Stop sharing this PC" (pause, then cancel this node's running jobs; the
  hub stays up) and "Turn off my cloud" (H1 `-Stop`; the app explains that the phone and the other PCs lose the cloud
  until it is turned on).
- **Status** comes from `p2pc-agent status --json` (local; H1) and, on the hub PC, from the app's own device connection
  (`GET /v1/nodes`, `/v1/devices`, `/v1/jobs?kind=service`). On a joined PC the app shows the local node only, plus a
  link to the web app.

### 8.5 Inside the distro: one supervisor for agent and hub

- **The distro has no systemd** (`systemd=false`, H1 §9.0 and E1: all WSL2 distros share one cgroup v2 root, and a
  second systemd would fight over it). So the hub is **not** a systemd service.
- **`p2pc-run`** replaces `p2pc-node-run` (same path kept as a symlink for one release). It supervises up to two
  children, each with its own backoff (1 s doubling to 30 s), its own lock and its own size-rotated log in
  `/var/log/p2pc/`:
  - the agent, always (H1 behaviour, terminal codes 6/7/8 included);
  - the hub (`p2pc-server serve`, `P2PC_DATA_DIR=/var/lib/p2pc-server`), when `/var/lib/p2pc-server/hub.enabled`
    exists.
- **Terminal stops.** An agent terminal code stops only the agent child. `p2pc-run` exits 64 (so the H1 wrapper disables
  the task) only when no child is left to supervise: the agent is terminal **and** the hub is disabled. On the hub PC,
  the hub keeps running after its own node is removed.
- **Hub listener.** REST binds `127.0.0.1:7477` inside the distro (H1 default). With WSL's default NAT networking,
  `localhostForwarding` (on by default) makes ports bound to localhost in the WSL VM reachable from Windows as
  `localhost:<port>` [S7], on the Windows host's own loopback only, where every local process (other Windows users'
  sessions included) can reach it. Every other WSL2 distro of the user, Docker Desktop's included, shares the VM's
  network namespace (H1 §9.0, E1) and reaches `127.0.0.1:7477` directly. That is acceptable because every REST request
  needs an API key (H1 §10), devices never use TCP, and device streams have a budget of their own that TCP connections
  cannot take (§6.3); but it MUST NOT be reachable from the LAN (SI-H2-11 tests it from a second machine). E10 records
  what Windows' loopback exposes.
- **Sleep.** When Windows sleeps the WSL VM is suspended: nodes go offline and, on the hub PC, the whole cloud
  disappears for the phone. H1 leases recover as lost and requeued (U6). Clocks may jump after resume (H1 note on WSL
  clocks); every timer uses monotonic clocks, as H1 requires.
- **Signed-in user only.** The task runs at the user's logon (H1); while nobody is signed in on that PC, nothing of
  P2PC runs there. Locking the screen is fine. Running without a signed-in user needs a stored password or S4U, which
  the beta does not do (O-10).

### 8.6 What the hub PC means for the user

- The Ready screen and the tray menu on the hub PC say: "This PC is your cloud's hub. Your phone can reach your cloud
  only while this PC is on, awake and signed in."
- "Keep this PC awake while sharing" (off by default; suggested on the hub PC) holds
  `SetThreadExecutionState(ES_CONTINUOUS | ES_SYSTEM_REQUIRED)` while the app runs, the state is `sharing` or
  `paused`, and, on a laptop, only on AC power. It never changes the Windows power plan.
- Choose the hub well: the first-run step 4 says "Create your cloud on the PC that is on most often".

### 8.7 Uninstall

The NSIS uninstaller runs `P2PC.exe --uninstall-cleanup` before it removes the app's files. Cleanup, in order, each
step logged to `%TEMP%\p2pc-uninstall-<time>.log` (the only file left afterwards, and deleted by Windows' own temp
cleanup):

1. **Hub PC:** a confirmation that names the consequence ("This PC hosts your cloud. Uninstalling deletes your cloud:
   your phone and your other PCs will lose it.") with an explicit checkbox. Cancelling stops the uninstall. After
   confirmation, and before anything is stopped, the app **deletes every other node** through its own device
   connection (H1 `DELETE /v1/nodes/{id}`, best effort, 30 s in total). A connected agent loses its session at once,
   gets `not_enrolled` when it reconnects and exits 7, so its PC's app shows `node_removed` ("This PC was removed from
   your cloud") instead of retrying forever. A joined PC that is off at that moment never hears it; the 14-day rule of
   §8.8 (`hub_gone`) covers it.
2. **Joined PC:** `p2pc-agent leave` (best effort, 10 s), so the hub drops the node (§6.1).
3. Stop and delete the scheduled task "P2PC node" and its wrapper (H1 `-Uninstall`, exit 37 rule: if the task cannot
   be removed, stop here and tell the user).
4. `wsl --unregister p2pc-node`: deletes the distro, its container images, volumes (model files) and, on the hub, the
   cloud's database and blobs.
5. Delete `%LOCALAPPDATA%\P2PC\`: `wsl\`, `logs\`, `setup.json`, `device.key` and `backups\` with `install.ps1
   -Uninstall`'s default rule (H1 deploy README): verified upgrade backups (`p2pc-state-<time>.ok.tar`) are deleted,
   and the backup of an upgrade that failed (`p2pc-state-<time>.tar`) is **kept**, because it can be the only copy of
   the node identity and, on the hub PC, of the cloud's database. The confirmation lists each kept backup by its full
   path with an unchecked checkbox "Also delete these backups" (`-DeleteFailedBackups`); without it, the backups and
   the folders that hold them stay, and the final page names them. With no such backup, the folder goes entirely.
6. Delete the app's data folders (`%APPDATA%\<app identifier>`, `%LOCALAPPDATA%\<app identifier>` including WebView2's
   `EBWebView`), the `Run` and `RunOnce` values. NSIS removes the install folder and its uninstall registry key.
7. **WSL itself stays installed**: it is part of Windows and may serve other things. The final page says how to remove
   it.

AC-H2-9 checks the result with a before/after inventory of the user profile, `HKCU`, scheduled tasks and `wsl -l -v`,
and the handling of a failed-upgrade backup.

### 8.8 Errors

| Code | Cause | The app shows | Then |
|---|---|---|---|
| `virtualization_off` | Firmware virtualization disabled | "Turn on virtualization in your PC's firmware settings" and a guide | Stays at step 2 |
| `wsl_install_failed` | `wsl --install` failed or was declined at UAC | The step, the exit code, "Try again" | Stays at 2a |
| `wsl_too_old` | WSL < 2.0 and no update possible | How to update from the Microsoft Store | Stays at 2 |
| `disk_low` | < 20 GiB free | How much is needed | Stays at 2 |
| `image_download_failed` / `image_hash_mismatch` | Network, or a corrupt or tampered file | "Try again"; a mismatch is never retried silently | Stays at 3 |
| `import_failed` | `wsl --import` error | WSL's message (sanitized), "Try again" | Stays at 3 |
| `distro_unhealthy` | Boot status or isolation checks fail (H1 `p2pc-test-distro` subset) | Which check | `attention` |
| `hub_unreachable` | Joined PC cannot reach the hub | "Your hub PC is off or offline" | `attention`, retries |
| `hub_gone` | `hub_unreachable` without a break for 14 days | "Your cloud is gone: remove P2PC from this PC, or join another cloud" | The app stops the watchdog (H1 `-Stop`: task disabled, distro terminated) and offers "Remove" (the uninstaller) or "Join another cloud" (§5.4). It never retries on its own again. |
| `join_pending` | The node enrolled but is `pending_approval` (§5.5) | "Approve this PC in the P2PC app on your hub PC", with the node phrase the hub PC shows | Waits; leaves the state on `NodeApproved` or the next `Welcome` |
| `join_rejected` | Invite expired, used, revoked | "Ask for a new invite" | Stays at 4 |
| `node_removed` | Agent exit 7 | "This PC was removed from your cloud" with "Join again" | `attention` |
| `agent_too_old` | Agent exit 6 | "Update needed" | runs the updater |
| `gpu_unavailable` | `gpu_status` not `ok` | The H1 reason in words (driver, CDI) | warning only |

### 8.9 App security

- The webview loads only bundled assets. No remote page, no remote script, no `eval`; a strict CSP in
  `tauri.conf.json` [S8]. Links open in the system browser.
- **Capabilities** [S8]: the main window gets only the app's own commands (status, share, pause, pairing, devices,
  setup steps). No shell, filesystem or generic HTTP plugin is enabled. Every command validates its arguments in Rust.
- The device key is stored with DPAPI (current user) in `%LOCALAPPDATA%\P2PC\device.key`. No API key is ever stored by
  the app.
- **The app's iroh endpoints.** The device endpoint only dials: it serves no ALPN, so it accepts no incoming
  connection. The invite listener (§5.4) exists only while a join is in progress, serves only `p2pc/invite/1` and is
  relay-only; it rests on the proposed listening exception of §4.3 (ADR-016) and is not built before O-16. The device
  endpoint binds UDP sockets (§10.4); the invite listener has no IP transport and binds none (§5.4); the app opens no
  TCP listener.
- Output from jobs and services shown in the app (logs, chat answers) is untrusted data and is rendered as text
  (§9.5).
- Logs (`%LOCALAPPDATA%\P2PC\logs`, size-rotated) contain no secret, ticket, invite code or join token (SI-H2-1).

## 9. Web app (phone and any browser)

### 9.1 Shape

- **Decision: a static, installable web app (PWA)** that runs an iroh client compiled to WebAssembly (`p2pc-device`).
  iroh compiles to WASM with `default-features = false`; in a browser every connection goes through a relay, because
  the browser cannot send UDP, and stays end-to-end encrypted [S1].
  - *Alternatives.* (a) A gateway that terminates HTTPS and forwards to hubs: a trusted party in the middle that sees
    every request, and a cloud service to run and secure; rejected, because it breaks end-to-end encryption and ADR-009
    keeps the personal cloud closed by default. (b) Native
    iOS and Android apps: app-store review, two code bases, and months; an H3+ candidate. (c) Tailscale-style VPN
    apps: the user would install and sign in to a third-party service; rejected for the "no account" goal.
- **Hosting.** The official build is deployed to a static host (Cloudflare Pages or Vercel) with the headers of §9.5.
  The same build runs from any static web server (a sample nginx config ships in `deploy/web/`). The host serves files
  only: no functions, no API, no database, no analytics.
- **Stack.** TypeScript, a small UI framework chosen in T2-20 (Svelte or Preact), bundled. No CDN, no remote fonts, no
  third-party script. `npm ci --ignore-scripts` with a lockfile; dependency licenses checked like `deny.toml`.
- **Shared with the desktop app** (D3): the same components and pages; the desktop build swaps the WASM transport for
  Tauri commands into the native `p2pc-device`.
- **Browsers (H, E9 decides):** iOS/iPadOS Safari 17+ (home-screen web app), Chrome on Android 120+, current desktop
  Chrome, Edge, Firefox and Safari. Required: WebAssembly, WebSocket, IndexedDB, WebCrypto AES-GCM,
  `crypto.getRandomValues`.

### 9.2 Pages

| Page | What |
|---|---|
| `/pair` | Reads the ticket from the fragment, clears it, pairs (§5.3), or explains the iOS steps (§9.3). Also "Scan pairing code" (camera, bundled QR decoder). |
| `/invite` | Phone-assisted join of a PC (§5.4): sends the join request, exchanges the hub and listener nonces with the PC (§5.4 step 4), waits for the approval on the hub PC, shows the hub phrase, then hands over the join token. |
| `/` (home) | Hub name and online state; PCs (name, online, sharing or paused, GPU); running template services of its template view (§5.5); shortcuts to the templates. |
| `/chat` | The private chat (§9.4). |
| `/transcribe` | Upload, launch, follow, read the transcript (§9.4). |
| `/jobs` | Read-only list of the recent jobs it can see and their state: with the default profile, the template jobs this device launched and the shared `singleton` instances (template view, §5.5). |
| `/settings` | This device (label, scopes, "Forget this cloud" = self-revoke and wipe), versions (web app, hub, API), relay in use, "How to verify this app" (§9.6). |

### 9.3 Device key storage in the browser

- **iroh needs the raw 32-byte secret key** for its handshake inside the WASM module, so the key cannot be a
  non-extractable WebCrypto Ed25519 key, even though every major browser now supports Ed25519 in WebCrypto [S10]
  **(H: E9 checks whether iroh can use an external signer; if it can, the key becomes non-extractable)**.
- **Storage.** The web app creates a **non-extractable AES-GCM-256 `CryptoKey`** and keeps it in IndexedDB (a stored
  `CryptoKey` stays non-extractable), and stores the device key encrypted with it, next to the hub NodeId, relays,
  `device_id` and scopes.
  - It protects against copying the storage files or reading IndexedDB values from another context: they hold
    ciphertext and a key object that cannot be exported.
  - It does **not** protect against code running in the web app's origin (an XSS, a malicious host or service-worker
    update), which can call `decrypt`. §9.5 and §9.6 address those.
- **Persistence.** The web app calls `navigator.storage.persist()`. On iOS, Safari deletes all script-writable storage
  of a site after 7 days without user interaction, but home-screen web apps are exempt, and their storage is kept
  apart from Safari's [S9]. Therefore:
  - **iOS:** scanning the QR opens Safari; the web app sees it is not running standalone and does **not** consume the
    ticket. It shows three steps: "Add to Home Screen", "Open P2PC from your Home Screen", "Tap Scan and scan the same
    QR code again" (the ticket is still valid for its 10 minutes). "Use in Safari anyway" pairs in the tab, with a
    warning that Safari may forget the pairing after 7 days without use.
  - **Android (Chrome):** an installed web app shares the origin's storage, so it pairs in the tab and then offers
    "Install".
  - E9 confirms both behaviours on real devices.
- **Losing the key** (storage cleared, phone reset) means pairing again; the old device stays listed until revoked, and
  the desktop app shows its `last_seen_at`.
- **A stolen phone** is handled by revocation from the desktop app (U8, SI-H2-4). The device scopes (§5.5) bound what
  the thief can do until then. A
  screen lock is the user's first defence; an app-level PIN or passkey unlock is H3 (O-9).

### 9.4 Template UIs

- **Private chat** (`ui = "chat"`).
  - Start: launches `private-chat` (singleton; launching again returns the running instance), shows `queued` reasons in
    words ("Your GPU PC is off", "The GPU is busy"), then the health state.
  - First run: while the hub downloads the launch's model (§7.6), shows `service.setup`'s progress, with the size
    from the template (`download_mb`); then lists models with `/api/tags`.
  - Chat: `/api/chat` with `stream: true`; tokens appear as they arrive.
  - **History stays on the device** (IndexedDB, encrypted with the same `CryptoKey`), with "Clear history". Nothing of
    the conversation is stored on the hub; the service's own volume holds only model files.
  - Interruptions: if the stream breaks (tab in the background, network change), the partial answer is kept and
    marked "interrupted" with "Retry". Streams are not resumable in H2.
  - "Stop the chat service" cancels the job (allowed by §7.2 to any principal that may launch it); otherwise
    `idle_timeout_s` stops it.
  - When the service has ended by itself, the page says why in words and offers "Restart" (a new launch): after
    `timed_out` ("The chat service ran for its 30-day limit"), `cap_reached` ("Your daily limit was reached") or
    `lost` with `restart_limit` ("Your GPU PC kept going offline").
- **Transcribe** (`ui = "transcribe"`).
  - Pick an audio file (the file picker also offers recording on phones). The web app hashes it (WebCrypto SHA-256),
    `HEAD`s the blob, uploads it if missing (progress bar, warning above 200 MiB, §7.5), launches `transcribe` and
    follows the job.
  - The job survives the tab: on return the page shows its state from `GET /v1/jobs`. The transcript comes from the H1
    outputs endpoint; the page shows the text and offers download and the system share sheet.
  - A broken upload restarts from zero (O-11).

### 9.5 Web app security (XSS and supply chain)

- **Headers** (set by the static host; `deploy/web/_headers` for Cloudflare Pages, `vercel.json` for Vercel, and the
  nginx sample; checked by AC-H2-11):

  ```
  Content-Security-Policy: default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self';
    img-src 'self' data: blob:; media-src 'self' blob:; font-src 'self'; manifest-src 'self'; worker-src 'self';
    connect-src 'self' <relay origins of this build>; frame-ancestors 'none'; base-uri 'none'; form-action 'none';
    require-trusted-types-for 'script'; trusted-types 'none'
  X-Content-Type-Options: nosniff
  Referrer-Policy: no-referrer
  Permissions-Policy: camera=(self), microphone=(self), geolocation=(), payment=(), usb=()
  Cross-Origin-Opener-Policy: same-origin
  Strict-Transport-Security: max-age=31536000
  ```

  `index.html` repeats the CSP in a `<meta>` tag (without `frame-ancestors`, which only works as a header) so that a
  host that drops headers still gets most of it. Trusted Types is enforced where the browser supports it; if the chosen
  UI framework needs a Trusted Types policy, it gets exactly one named policy, reviewed, and the CSP names it instead
  of `'none'`.
- **Subresource Integrity** on every script and stylesheet `index.html` loads. It guards against a cache or edge that
  alters a bundle, not against a host that also alters `index.html` (§9.6).
- **`connect-src` names the relays.** The official build lists the official relay origins and, during the beta, n0's
  public relays. A pairing ticket whose relays are not allowed by this build's CSP is refused with a clear message:
  "This cloud uses a relay that this copy of the web app does not allow. Use your own copy (§9.6)". Self-hosters
  build with their own relay list (`P2PC_WEB_RELAYS` at build time).
- **Untrusted content.** Model answers, job logs, file names, hub and device names are data. They are inserted with
  `textContent` or through a Markdown-subset renderer that builds DOM nodes (paragraphs, emphasis, lists, code blocks)
  and never produces HTML strings; links are shown as text with an explicit "Open" that asks first; no remote image
  is ever loaded. No `innerHTML`, `eval`, `new Function` or `document.write` in the code base (a lint rule enforces
  it; SI-H2-12).
- **No third-party code at run time**: no analytics, no error reporting service, no remote fonts.

### 9.6 A malicious or compromised static host

The host serves the code that holds the device key, so a host that serves modified code can steal keys of devices
that load it. Mitigations, none of them complete:

1. **Reproducible, signed builds.** CI builds `apps/web` with pinned toolchains. Every web build, including one
   deployed between app releases, ships `web-manifest.json` with `web_version` (the build's version, monotonic),
   `min_hub_version` (the oldest hub the build works with, §14.3) and every file's path and SHA-256, plus its
   signature `web-manifest.json.minisig` made with the release key (§5.1). Both are served at the web app's origin
   (`/web-manifest.json`) and published with the build on GitHub Releases. Anyone can rebuild and compare. The
   release pipeline deploys a release's web build before it publishes the app update of that release (T2-34).
2. **The desktop app verifies the deployed web app** against the manifest the origin serves, not only against its
   own release's build: at start and daily when the user turned automatic checks on (§8.2 step 1, hard rule 6), and
   otherwise only when the user clicks "Verify web app" in Settings. It fetches the manifest and its signature from
   the configured origin, verifies the signature against the release key compiled into the app, and then fetches every
   listed file and compares hashes. It keeps a **high-water mark**, the highest `web_version` it has verified, in its
   local state; the mark starts at, and on every app update rises to at least, the version of the web build of the
   app's own release. Outcomes:
   - *Valid signature, `web_version` at or above the mark, every file matches:* verified; the mark rises to that
     version. A build newer than the app's own release is a notice, not a warning: "The web app is newer than this
     app" (with "Check for updates" when automatic checks are off). If the build's `min_hub_version` is above the
     local hub's version (on the hub PC), the app says "Your phone's web app needs a newer hub: update P2PC on this
     PC" (§14.3).
   - *Signature missing or invalid:* a warning, "The web app at <origin> is not a signed P2PC build", which offers a
     self-hosted copy (item 3) and to revoke the phone devices. A copy that the user built with their own relay list
     (§9.5) cannot carry the release signature: when `web_app_origin` is not the official origin, Settings shows
     "Not verified: self-built copy" instead, without the warning.
   - *Valid signature, `web_version` below the mark:* a rollback warning, "The web app at <origin> is older than one
     this app has already verified", which offers a self-hosted copy. An old signed build may carry a fixed bug, so it
     is never accepted silently.
   - *Valid signature, a file that does not match:* the red tampering warning, which offers to revoke the phone
     devices and a self-hosted copy.

   This detects untargeted tampering only: a host can serve different bytes to different clients. SI-H2-22 tests
   every outcome.
3. **A self-hosted copy.** The desktop app's `web_app_origin` setting changes the origin that pairing QR codes point
   to. Keys are bound to the origin (browser storage is per origin), so moving means pairing again.
4. **Bounded device power** (§5.5): a stolen device key with the default phone profile can launch vetted templates,
   read the state, logs and outputs of the template jobs it launched, use and stop the shared chat service (only its
   `allowed_routes`: chat and the model list, §7.4), upload and check blobs and withdraw its own claims, and open join
   requests, which do nothing until an `admin` approves them on the hub PC. It cannot run arbitrary containers, read
   developer jobs or other devices' template jobs, open a non-template service, mint join tokens or create pairing
   tickets, and no PC it helps enroll gets work without that approval (SI-H2-18, SI-H2-19).
5. **The service worker** caches the app shell only; it never intercepts or caches API traffic (there is no HTTP API
   traffic in the browser: it all goes through iroh). Its updates are subject to the same host risk; the app shows the
   version it runs in Settings.

§15.2 lists the residual risk.

## 10. Networking and relays

### 10.1 Paths

| Path | Transport | Notes |
|---|---|---|
| Phone ↔ hub | Always through a relay, over WebSocket (wss) | Browsers cannot send UDP, so there is no direct path; the relay cannot decrypt [S1]. |
| Desktop app (hub PC) ↔ hub | iroh, local | Same machine. |
| Agent ↔ hub | iroh, direct when possible, else relay | E4 measured a WSL2-NAT node with no direct path to a LAN peer: relay, about 97 ms and 9 Mbit/s on n0's relay (H1 §10). |
| Hub ↔ node for service ports and blobs | the agent's existing connection | Local when the service runs on the hub PC (the common case). |
| Node → internet (model downloads) | the job's egress proxy (H1 §9) | Never through our relay. |

A chat needs well under 100 kbit/s; a blob upload is bounded by the relay (§7.5). E9 measures both on our relay.

### 10.2 Our relay on an HTTP-only platform

- **Decision.** The beta uses n0's public relays, which are free and rate-limited, meant for testing. The official
  deployment adds our own `iroh-relay` on a PaaS that only offers HTTP(S) and WebSockets (Railway is the first
  target). Self-hosters run their own; `deploy/relay/` has the container image and the config.
- **Mode.** `iroh-relay` without a `tls` section serves every relay service over plain HTTP on `http_bind_addr` [S2].
  The platform's edge terminates TLS and forwards WebSockets over HTTP/1.1; idle HTTP/1.1 connections are closed after
  60 s, but WebSocket connections are not [S3]. Clients use `https://relay.<domain>` as the relay URL.
- **What we lose.** QUIC address discovery needs TLS and UDP on the relay [S2], and Railway's public networking is
  HTTP(S) plus a TCP proxy, with no UDP [S3]. So our relay only relays; it does not tell endpoints their public
  address. §10.3 says why that matters and how the relay map covers it.
- **Config** (in `deploy/relay/relay.toml`): `enable_relay = true`, `enable_quic_addr_discovery = false`,
  `http_bind_addr = "[::]:$PORT"`, metrics only on a private port or off, the platform's health check on the relay's
  plain HTTP probe route, iroh-relay's per-client rate limits set (values from E9/E12), access open to any NodeId
  (pairing makes devices unknowable in advance).
- **Cost and abuse.** Anyone can relay through an open relay. The traffic is end-to-end encrypted, so we cannot and do
  not inspect it. Limits: per-client rate limits, a connection cap, the PaaS spending cap, and an alert on egress
  volume. Budget and plan are owner decisions (O-3).
- **Relay list updates.** The hub's relay list comes from its config (the app writes the official list of its
  release). Devices store the list from their ticket and refresh it from `GET /v1/server` on every connection, so a
  relay change reaches paired phones the next time they connect through a relay that still works. Keeping the old
  relay alive for one release after a change is part of the release checklist.

### 10.3 Relay map rules

- **Native endpoints need QUIC address discovery.** H1's egress gate opens only after the node has observed its public
  IPv4 through its endpoint (H1 §9, "hairpin NAT"; residual risk R-2). An agent whose relays offer no QUIC address
  discovery never opens the gate, and every job with egress, including both templates' model downloads, fails with
  `egress_unavailable`.
- **So:** agents and the desktop app use a relay map with at least one relay that offers QUIC address discovery (n0's
  public relays, or a self-hosted relay with TLS and UDP), plus our HTTP relay. `p2pc-net` validates the map: with no
  address-discovery relay, the agent logs a warning at start and `p2pc-agent doctor` says "jobs with internet access
  will not start: no relay offers address discovery".
- **The hub's home relay must be one that browsers can reach and that the web app's CSP allows** (§9.5), because a
  phone reaches the hub through the hub's relay. In the official deployment the hub's relay map is our HTTP relay
  only; agents dial the hub through it whatever their own home relay is. **(H)** iroh 1.x picks a home relay from its
  map by latency and connects a dialler through the target's home relay; E12 verifies both with a mixed map.
- **Beta:** every endpoint uses n0's relays; the official web app's CSP allows them. This satisfies both rules.

### 10.4 Exposure

- **Address hygiene is unchanged** (H1 §10, E4) for the hub, the agents and the desktop app's native endpoint: no port
  mapping, default-route addresses only, no third-party address discovery. §10.5 covers what the hub's endpoint
  accepts.
- **What listens.** No TCP port reachable from the LAN: the app opens no TCP listener, and the hub's REST binds the
  distro's loopback, which `localhostForwarding` also exposes on the Windows host's own loopback, never on its LAN
  addresses (§8.5). The app's device endpoint binds UDP sockets, as the agent's endpoint already does in H1, and accepts
  no incoming connection. The invite listener binds none: it exists only during a join, serves only `p2pc/invite/1` and
  is relay-only, with no IP transport (`direct_addresses = "none"`, §5.4; E10 confirms it). Windows may show its
  firewall prompt on the app's first UDP bind; the app adds no firewall rule (§8.3), and it works whichever answer the
  user gives, because its connections are outbound or relayed (E10 records the prompt; the beta guide explains it).
  Service ports exist only on the container's loopback (§11.2). On the internet, the project's footprint is the static
  host and the relay. SI-H2-10 and SI-H2-11 test it.

### 10.5 The hub's iroh endpoint

On the hub PC, the hub's iroh endpoint is the one long-lived P2PC endpoint that accepts incoming connections (a joining
PC's invite listener accepts the two relay-only exchanges of one join, §5.4, §6.2). It does so as H1's server already
does, but now by default on a home PC that is also a node, so its exposure is stated here, and so is the hard-rule
exception it needs, proposed and not yet in force (below).

- **Where it binds.** The UDP sockets `p2pc-net` binds for it, inside the distro, on the WSL side. With WSL's default
  NAT networking the WSL VM sits behind the Windows host's NAT, so nothing on the LAN or the internet can send it an
  unsolicited packet: a peer reaches it only through a relay, or directly once iroh's hole punching, coordinated through
  that relay, has opened the path from inside. The hub keeps H1's address hygiene (no port mapping, default-route
  addresses only, §10.4) and binds no TCP port beyond the loopback REST listener (§8.5).
- **Mirrored networking.** With `networkingMode=mirrored` (an opt-in in `.wslconfig`, which the app never edits) the
  sockets sit on the host's own addresses, so a LAN peer that knows the port can send to them directly; what it accepts
  is the same set below. `p2pc-wsl` detects mirrored mode (for example with `wslinfo --networking-mode` run in the
  distro), the app warns, and `p2pc-agent doctor` says so. E10 records whether the Hyper-V firewall drops unsolicited
  inbound UDP in that mode.
- **What it accepts from any NodeId** (unauthenticated surface), per ALPN:
  - `p2pc/agent/1`: only `Join` with a valid join token, under H1's "Before `Join`" limits (H1 §6: 64 connections,
    16 pending `Join`s, 10 s, 10 failures a minute per NodeId), with the fix of §6.1: no failure total refuses a
    `Join` with a valid token (T2-17);
  - `p2pc/http/1`: HTTP requests that each need an API key (H1 §10), inside H1's tunnel budget (128 streams) and slow
    client limits, and refused with H1's same `401` without one;
  - `p2pc/pair/1`: one `Pair` with a pairing ticket, under the limits of §5.3 (32 connections, 8 pending, 10 s, 4 KiB,
    failures counted per NodeId and per ticket-hash prefix). **It is served only while a pairing ticket is open**
    (unexpired and unrevoked; a consumed ticket stays open until its expiry, for the idempotent retry of §5.2).
    Otherwise the hub removes it from the endpoint's accepted ALPNs, so the TLS handshake fails before any message, and
    adds it back when a ticket is created; if E12 shows the ALPN list cannot change at run time, the hub closes every
    `p2pc/pair/1` connection at once, before reading a frame;
  - `p2pc/device/1`: nothing from a NodeId that is not a live device: the connection is closed with `not_paired`
    right after the handshake (§5.5), under the pre-auth limits of §6.3 (32 unchecked connections, 5 s, 10
    `not_paired` a minute per NodeId).
- **Hard rule 4 and H1 §10: a proposed, bounded exception for the hub PC (ADR-016, not in force with this spec).**
  Hard rule 4 says nodes never listen on the network, and H1 §10 that nodes never listen on a TCP or UDP port
  reachable from outside beyond what iroh needs for outbound QUIC. The hub PC is also a node, and its distro hosts the
  hub's endpoint, which accepts inbound QUIC by default, so H2 does not read the rules as covering agents only: it
  proposes an exception, bounded as follows.
  - **Where:** only on the hub PC, only while `hub.enabled` exists (§8.5), and only the hub's own iroh endpoint (plus
    a joining PC's invite listener, below). The agent on that PC and every other node keep the rules unchanged: they
    only dial out.
  - **What:** the UDP sockets `p2pc-net` binds for that endpoint under H1's address hygiene; no TCP listener beyond the
    loopback REST listener (§8.5); every ALPN behind a ticket, a token, a key or a paired NodeId, under the pre-auth
    limits above, and `p2pc/pair/1` only while a ticket is open.
  - **Reachability:** through a relay or hole punching under WSL's NAT networking; with mirrored networking, LAN peers
    reach the same surface directly, and the app warns (above).
  - **The joining PC's invite listener** (§5.4) falls under the same exception: an endpoint of the app on a PC whose
    agent is installed, relay-only with no IP transport (§5.4), accepting the two `p2pc/invite/1` exchanges of one join
    (`InviteOpen`, then `Invite`, both from the one phone it binds to) under the §6.2 limits while the invite is valid.
  - **In force only through O-16.** Like the volume exception (§4.3, ADR-015), this one takes effect only through the
    separate O-16 change, which amends hard rule 4 and H1 §10 together with hard rule 3 and H1 §9 and marks ADR-015
    and ADR-016 Accepted. Until then no code makes the hub's endpoint on a node PC, or the invite listener, accept a
    connection, and T2-11, T2-41, T2-43 and T2-44 are blocked (§17). SI-H2-11 probes the bounds.

## 11. Sandbox additions

### 11.1 What stays

Every fixed `podman run` argument of H1 §9 applies to services too: `--rm`, `--network=none`, `--cap-drop=all`,
`no-new-privileges`, the pids limit, `--userns=auto` on WSL2, the memory and CPU limits, the per-lease cgroup, the
shim as entrypoint, the egress proxy socket. A service is the same sandbox that lives longer. Inside the WSL2 distro
Podman runs as root of the appliance with `--userns=auto` (H1 §9.0), not as a rootless user; containers are still
unprivileged.

**Added arguments:**
- `-v <volume dir>:<mount>:rw,U` per volume (§11.3): the one host path beyond the three per-job directories, allowed
  only once the proposed hard-rule change of §4.3 ("Sandbox and hard rules", ADR-015, O-16) is in force, and nothing
  more. Until then no code passes this argument. `<volume dir>` is always the agent's own
  `/var/lib/p2pc/volumes/<account_id>/<hash>/data`, never a string from the JobSpec, only for a service or template job
  of that account, and only after the check of §11.3 "Check before every mount" passed. E11 measures whether `:U` (a
  recursive chown on each mount, because `--userns=auto` may pick another range each time) is cheap enough for a model
  directory, or whether `:idmap` replaces it, and **whether `:U` follows symbolic links** (Podman is believed to use
  `lchown`; E11 confirms it with a planted link to a file outside the volume).
- `--label p2pc.kind=service` for services (orphan sweeps and `doctor`).
- `/.p2pc/ports.json` (in the existing read-only `/.p2pc` mount): the ports the shim may forward.
- With `ports.json`, the agent's `ingress.sock` in the same directory (§11.2).

### 11.2 The ingress bridge

- **The problem.** The container has no network, so nothing outside can connect to its port. H1 already bridges the
  other direction (the egress socket). H2 adds an ingress bridge without giving the container a network.
- **Reverse dial.** The **agent** listens on `<job>/p2pc/ingress.sock` (created 0600 inside a 0700 staging directory,
  bound by directory descriptor to stay under the `sun_path` limit, exactly like the egress socket). The **shim**,
  when `/.p2pc/ports.json` exists, keeps up to 4 idle connections open to it. For each port stream (§6.1) the agent
  takes an idle connection and writes a 3-byte header (version 1, port as u16 big-endian). The shim checks the port
  against `ports.json`, connects to `127.0.0.1:<port>` (then `[::1]:<port>`), answers one status byte (0 ok,
  1 refused, 2 not listed) and splices both ways. It then dials a fresh idle connection.
- **Why reverse.** The agent never `connect()`s to a path the container could create or replace: `connect()` on a unix
  socket follows symlinks, and a container-planted link could point the agent at a host socket such as Podman's. The
  only socket is the agent's own, inside a read-only mount (SI-H2-7).
- **A job that is not the shim** can connect to `ingress.sock` too (any process in the container can). It then only
  receives connections meant for its own service. The agent bounds the idle connections it keeps per lease (8; extra
  ones are closed), times out a header answer after 5 s and tries another connection (`connect_failed` after 3).
- **Health checks** use the same bridge: the agent opens a bridged connection and sends
  `GET <path> HTTP/1.1` with `Host: localhost`, `Connection: close`. The response comes from an untrusted container,
  so the agent reads only its status line, at most 1 KiB (a longer line, or one that is not
  `HTTP/1.x <3 digits> …` ending in CRLF, fails the check), and then closes the connection without reading headers or
  body; any 2xx or 3xx status within `timeout_s` passes. For `tcp: true`, a status byte 0 passes.
- **Old shims.** An image built before H2 cannot exist: the shim is injected by the agent at run time (H1 §9), so the
  agent and the shim always come from the same release.

### 11.3 Volumes on the node

Volumes rest on the proposed exception to hard rule 3 (§4.3, ADR-015 **Proposed**). Nothing in this section is
implemented before the separate change that puts it in force (O-16); T2-22 waits for it.

- **Layout.** `/var/lib/p2pc/volumes/<account_id>/<hex(sha256(name))[..32]>/` with `data/` (mounted) and `meta.json`
  (name, created, last used). The agent creates these directories itself (0700, created with `mkdirat` under
  directory descriptors, never following a link). Names never become paths directly, and no path from the JobSpec
  is ever mounted.
- **Who may mount.** The agent mounts a volume only into a lease whose job is `kind = "service"` or carries `template`,
  and only from the directory of that job's account; anything else is rejected as `invalid_job` (the hub already
  refuses it with `422 volumes_not_allowed`, §7.1).
- **One holder at a time.** A volume is mounted by at most one container. The agent takes an exclusive lock for a
  lease and rejects a second lease while it is held (`insufficient_capacity`, with the reason logged). The scheduler
  knows holders from `VolumeReport` and does not offer such a lease.
  - **The lock lasts as long as the container, not the lease.** It is taken before `podman run` and released only
    when Podman confirms that the lease's container is gone: `podman rm` succeeded, or `podman container exists` on
    its name reports it absent. A lease that ends, is cancelled or is lost keeps the lock until then; if the removal
    fails, the lock stays, the volume is reported `in_use_by` that lease, and the agent retries the removal at every
    sweep.
  - **It survives agent restarts.** The lock is persisted: `meta.json` records the holder (lease id and container
    name) with a write-to-temporary, `fsync` and `rename` before `podman run`, and clears it only after the
    confirmation above. At start the agent treats every recorded holder as held; its orphan sweep removes the
    containers of leases it no longer runs (the `p2pc` labels, §11.1), confirms each one absent the same way, and only
    then clears their locks. No walk and no mount of a volume happens before the lock is free and the sweep has
    finished for it.
- **Size.** Measured every 2 s, as H1 measures job disk (H1 §9 "Limits and status"), with H1's fail-closed disk
  measurement (larger of apparent and allocated size, entry budget, three failures count as over). Over `max_mb` → the
  lease stops with `error="volume_limit"`.
- **Budget.** `volumes_mb` (the share of §8.2) covers every volume on the node. Placement of a lease needs
  `volumes_mb − Σ max_mb of volumes in use by other leases ≥ max_mb` for each of its volumes. Unused volumes do not
  count: when a new or growing volume needs room, the agent evicts unused volumes, least recently used first. A
  volume whose `max_mb` exceeds `volumes_mb` makes the node ineligible, with a `reason`.
- **Retention.** An unused volume is deleted after `volume_retention_days` (default 30), on `VolumeDelete`, and with
  the distro on uninstall. Under the H1 disk floor the agent evicts unused volumes before it kills jobs.
- **Check before every mount.** A service that held the volume before may have left links in it, and `:U` changes the
  owner of everything it reaches. So before every mount the agent recreates the volume's directory chain
  (`volumes/<account_id>/<hash>/data`) with `mkdirat` under directory descriptors if it is missing, and otherwise
  verifies it and walks the whole tree without following links: `openat(O_NOFOLLOW | O_DIRECTORY)` for directories
  and `fstatat(AT_SYMLINK_NOFOLLOW)` (an lstat) for every entry. Any symbolic link, any entry that is neither a
  directory nor a regular file (FIFO, socket, device), and any regular file with more than one hard link (a chown
  through it would reach its other name) refuses the mount: the lease fails before start with
  `error="volume_unsafe"` (a `start_failed`-class error, H1 §9 "Podman failures are not job exits") and the volume is
  kept for the owner to delete (`VolumeDelete`), never repaired in place. The walk uses H1's entry budget of the disk
  measurement; over it the mount is refused the same way. The walk runs only after the lock is free (no container
  of an earlier lease exists, as Podman confirmed, even across an agent restart; "One holder at a time", above) and
  is taken for the new lease, so nothing can change the tree between the walk and the mount. E11 confirms that the
  template images write no links into their volumes.
- **Deletion** walks the tree with `openat(O_NOFOLLOW)` and `unlinkat`, never following a link (SI-H2-9).
- **Namespace.** `tpl:` volumes are created only by template launches (§7.1), so an arbitrary image cannot read or
  plant files in a template's model cache.

### 11.4 Long-running jobs and H1 limits

- **Wall-clock limit.** Services keep H1's enforcement of `timeout_s` (the agent stops the attempt; the hub marks it
  `timed_out` at `timeout_s + 60 s` if no report came), with their 30-day maximum (§7.1). No sandbox runs without one.
- **Logs.** A batch attempt keeps H1's 64 MiB cap with a truncation marker. A service keeps the **most recent**
  64 MiB, as a ring of 1 MiB segments on the agent and on the hub; a marker records the dropped range, and `since_seq`
  inside a dropped range starts at the oldest kept chunk.
- **Liveness.** SI-13 holds for services: a partitioned agent stops them after `agent_lease_ttl_s`, and the hub then
  requeues them per `restart`. A hub restart shorter than that keeps them running (H1 "Server restart").
- **Disk polling, the disk floor, image pulls** (`IfNotPresent`, shared pulls, the size cap) are unchanged.
- **Usage reports.** For services the agent adds `used_cpu_ms` (cumulative) and `max_rss_mb` (the attempt's peak so
  far), both from the lease cgroup, to each `Heartbeat.running[]` entry, at most once a minute, for the daily split
  (§12).

### 11.5 Residual sandbox risks added by H2

- The hub shares the distro with the jobs (D1). A container escape reaches the hub's database, blobs and identity, on
  top of the node identity it already reached in H1.
- Volumes outlive jobs (§11.3). A compromised service can leave files in its volume that a later job of the same
  account and volume name reads; for templates those are model files, read as data (below).
- Templates run third-party images (Ollama, whisper.cpp) with egress to model hosts. They are pinned by digest and
  reviewed, but they are not our code.
- Model files come from the internet: the template's declared models, which only the hub pulls (§7.6). The default
  models are GGUF files read as data **(H: E11 confirms that the
  chosen images load only GGUF and do not execute code from model files)**.
- These go into `docs/security/residual-risks.md` (task T2-61).

## 12. Metering

- **Units are unchanged** (H1 §11): 1 unit = 1 vCPU-hour reserved, a GPU-hour = 10 units, milli-units, no money.
- **Services** are metered like batch attempts: reserved resources × the time the attempt held them.
- **Slices.** The ledger keeps one row per finished **slice** of an attempt (H1: one row per finished attempt, H1 §11):
  - a **batch** attempt is one slice, from its start to its end, written when it ends, exactly as in H1 (a batch
    attempt lasts at most 24 h, §7.1);
  - a **service** attempt is cut at every 00:00 UTC it runs through. At 00:00 the hub writes the row of the slice that
    just ended (from the attempt's start or the previous midnight, to this midnight), with reserved time exact and
    `used_cpu_ms` from the latest cumulative `Heartbeat` value (§11.4) minus what earlier slices of the attempt
    recorded. The attempt's end writes its last slice. A hub that was down at midnight writes the missed slices at
    start, one per UTC day, before it serves requests;
  - a slice whose used CPU comes from no report is `estimated = 1`. A service attempt that ends with no report (lost,
    watchdog, cancel on an unreachable node) gets H1's estimate, cut into slices the same way.

  `GET /v1/usage` and the caps count the same rows (H1 rule), so a week-long chat service shows up day by day.
- **`GET /v1/usage` over slices and principals.** The response keeps H1's shape (fields may only be added) and its
  selection (rows that ended in `[from, to)`). With slices and device principals each field means:
  - the sums (`reserved_cpu_ms`, `reserved_gpu_ms`, `used_cpu_ms`, `units`) add every selected row, slices included;
    `max_rss_mb` is the maximum over the selected rows;
  - `attempts` counts finished attempts: the selected rows with `last_slice = 1` (H1 counted every row, which is the
    same for batch jobs, whose only row is their last slice). A running service's midnight slices add to the sums but
    not to `attempts`;
  - `estimated_attempts` keeps its H1 meaning, how many of `attempts` are server estimates: selected rows with
    `last_slice = 1` and `estimated = 1`. The additive `estimated_slices` counts every selected row with
    `estimated = 1`, so a midnight slice estimated for lack of reports is visible too;
  - `group_by=key` groups rows by `key_id` and leaves device rows out of the groups; `group_by=device` groups by
    `device_id` and leaves key rows out; `group_by=template` leaves out rows with no template. A group is never null:
    a row whose grouping column is NULL is filtered out in the query, never decoded. `group_by=job`, `node` and `kind`
    cover every row. The response's `total` always covers every selected row, so with devices in use the `key`
    groups may add up to less than the total; `group_by=principal` (new) covers every row, labelled `key:<id>` or
    `device:<id>`.
- **Ledger columns and key.** `usage_records` is rebuilt (§5.6) with:
  - the principal: `key_id` or `device_id`, exactly one (§5.6);
  - `kind` (`batch` or `service`) and `template_id` (nullable);
  - `slice_start` and `slice_end` (`slice_start <= slice_end`), and `last_slice` (0 or 1; 1 on the attempt's last
    row);
  - `charge_day`: 00:00 UTC of the day the row is charged to (Unix seconds, `CHECK (charge_day % 86400 = 0)`). For a
    service slice it is the day the slice lies in; for a batch slice it is the UTC day of its job's creation, the day
    whose cap admitted the job, as H1 charges it;
  - `started_at` keeps the attempt's start, and `ended_at` is the slice's end (`= slice_end`), so H1's
    `CHECK (ended_at >= started_at)` holds and `GET /v1/usage` keeps H1's selection (rows that ended in `[from, to)`);
  - `max_rss_mb`: for a last slice, the agent's final report, as in H1; for a midnight slice, the latest
    `Heartbeat.running[].max_rss_mb` of the attempt (its peak so far, §11.4), so never below the slice's own peak;
    with no report, 0 and the slice is `estimated = 1`, as H1's estimates record it.

  The key `UNIQUE (job_id, attempt, slice_start)` replaces H1's `UNIQUE (job_id, attempt)`. `lease_id` stays
  `NOT NULL REFERENCES leases (id)` but is no longer `UNIQUE`, since every slice of an attempt names its lease. A
  partial unique index on `(job_id, attempt) WHERE last_slice = 1` keeps one last slice per attempt, and the cap reads
  the indexes `(key_id, charge_day) WHERE key_id IS NOT NULL` and `(device_id, charge_day) WHERE device_id IS NOT NULL`.
  The append-only triggers are created again unchanged: a slice is written once and never updated.
- **Property test.** Invariant 6 of H1's scheduler property test (`crates/p2pc-server/src/scheduler/tests/props.rs`),
  "`usage_records` has exactly one row per finished attempt", becomes **"exactly one row per finished slice"**: the rows
  of each attempt tile `[started_at, ended_at]` with no gap and no overlap, cut only at 00:00 UTC and only for
  services; a finished attempt has exactly one `last_slice = 1` row and a running one has none; a running service
  attempt has one row for each midnight it crossed and none for its current slice. The property test drives the clock
  across midnights. T2-16 changes the test together with the code.
- **Grouping.** `GET /v1/usage?group_by=` gains `device`, `principal`, `kind` and `template` (above), and each group
  keeps `estimated_attempts` and gains `estimated_slices`.
- **The cap query.** A principal P's cap for the UTC day D is checked against `spent(P, D)`, which replaces H1's
  `spent_between` (`crates/p2pc-server/src/store/leases.rs`, which counts jobs by `created_at`). In milli-units, it is
  the sum of:
  1. the `units` of P's ledger rows with `charge_day = D`;
  2. for each **batch** job of P created on D: its `units_reserved` while it is not terminal (its current or next
     attempt may still use it), and, once it is terminal with no ledger row, H1's rule (nothing if it was cancelled
     before it ever ran, its reservation otherwise);
  3. for each **service** of P that is not terminal and holds a reservation for D (`service_state.cap_day = D`):
     `max(0, cap_reserved_units − the units of that job's rows with charge_day = D)`.

  Term 3 is what stops double counting: a slice written against a day's reservation uses it up instead of adding to
  it, so no unit is counted both as reserved and as recorded. A service's `jobs.units_reserved` is 0; its reservation
  lives only in `service_state`. For batch jobs terms 1 and 2 give exactly H1's numbers, because every batch row is
  charged to its job's creation day; H1's cap tests keep passing unchanged (AC-H2-12).
- **Caps for services.** For batch jobs nothing changes: at creation the estimate is resources × `timeout_s` (H1,
  `402 cap_exceeded`). A service would reserve up to 30 days that way, more than any daily cap, so for a service whose
  principal has a `daily_unit_cap` the cap **charges per day of runtime, reserved daily**:
  - at creation, and again at each 00:00 UTC while the service is not terminal, the hub sets the service's
    reservation for that UTC day (`cap_day`, `cap_reserved_units`): its reserved rate (units per second, from its
    resources) × the runtime left in the day, bounded by what is left of `timeout_s` and by the day's cap minus
    `spent(P, D)` without this reservation;
  - creation (and template launch, §7.6) is refused with `402 cap_exceeded` when that gives under 15 minutes of
    runtime. At a day boundary, a reservation under 15 minutes stops the service at once;
  - the midnight step is one `BEGIN IMMEDIATE` transaction per service: write the slice of the day that ended
    (`charge_day` = that day), then replace the reservation with the new day's. The day that ended then counts rows
    only, and no instant counts the slice and its reservation both, or neither;
  - while the service runs, `cap_deadline` (§7.2) is the instant at which its rows for the day plus its current slice
    at the reserved rate reach `cap_reserved_units`. If the service reaches it before the day ends, the hub stops it:
    `cancelled`, `reason: "cap_reached"`. The app and the web app show a notice: "Stopped: the daily limit of
    <principal> was reached. You can start it again tomorrow, or raise the limit";
  - the ledger keeps recording what the service actually held (the slices above); the unused part of a day's
    reservation is released when the service ends (term 3 no longer counts it) or the day closes.
- **Service traffic** is recorded, not billed: `service_traffic(job_id, day, bytes_in, bytes_out, connections)`,
  returned in `GET /v1/jobs/{id}` as today's totals.
- **Blob storage** is recorded, not billed: `GET /v1/blobs` returns the account's total and quota.

## 13. Storage

- **Hub data dir.** In app mode `/var/lib/p2pc-server` inside the hub PC's distro (0700, root); otherwise H1 §12.
  - New tables (additive migrations): `devices` and `pairing_tickets` (both with `daily_unit_cap`, `allowed_images`, the
    device expiry and `blobs_quota_mb`, §5.2), `join_requests` (with the listener commitment, the hub nonce and the
    revealed listener nonce, §5.4), `blobs` (with the GC tombstone `deleting_at`, §7.5), `blob_uploaders` (one claim
    per uploading principal, §5.6), `blob_refs`, `volume_reports`, `service_state` (health, last activity, consecutive
    unhealthy attempts, node-loss restart times of the last 24 h, the model download's `setup` state, and the day's cap
    reservation as `cap_day` and `cap_reserved_units`, §12),
    `service_traffic`, `template_bundle_state` (one row: the high-water `bundle_version` and its SHA-256, §7.6), and the
    node columns `approval` and `enrolled_by`.
  - Rebuilt tables (one forward-only migration that keeps every append-only trigger, §5.6): `jobs`, `usage_records`
    (principal and slice columns, the new key, §12), `join_tokens` and `audit_events`.
  - Blobs: `<data>/blobs/<account_id>/sha256/<aa>/<bb>/<hex>` (per account, §7.5), staging in
    `<data>/blobs/staging/`. The sweep deletes a staging file only when no upload in progress holds it (the hub keeps
    the set of its open staging files) and its last write is over 1 h old; it never goes by creation time, since a
    slow upload may legitimately run longer than an hour (the 16 KiB/s floor of §7.5 lets a 2 GiB upload take about
    36 h). At start no upload is in progress, so every staging file is swept.
  - Template bundles: `<data>/templates/`.
  - **Backup.** The hub's state lives in the distro's virtual disk. The app's upgrade archives it (§8.3); nothing else
    backs it up in H2. Losing the hub PC's disk loses the cloud: devices pair again with a new hub, PCs join again
    (O-12).
- **Node.** Volumes (§11.3) under `/var/lib/p2pc/volumes/`. Blob inputs are copied into the job directory and deleted
  with it.
- **Desktop app.** `%LOCALAPPDATA%\P2PC\` (distro, backups, logs, `setup.json`, `device.key`) and the Tauri app's own
  data folders. §8.7 removes all of it except the backups of failed upgrades, which it keeps unless the user ticks
  the box.
- **Phone.** IndexedDB of the web app's origin: the wrapped device key, the hub's NodeId and relays, chat history.

## 14. Updates, versions and signing

### 14.1 The app

- **Tauri's updater plugin** with `latest.json` on GitHub Releases, one file per channel (`beta`, `stable`). Signatures
  are mandatory and cannot be disabled; the public key is compiled into the app [S5]. Windows install mode `passive`
  (a progress window, no questions) [S5].
- **The endpoint's answer is not signed;** only the artifact is [S11]. So:
  - artifacts are signed with the app version in the signature's trusted comment, and the app requires it
    (`requireSignedVersion`, tauri-cli ≥ 2.12 [S11]);
  - the app MUST refuse an artifact whose signed version is not greater than its own (no downgrade), SI-H2-15;
  - **automatic checks are opt-in** (hard rule 6): only when the user said yes at first run (§8.2 step 1) or in
    Settings does the app check on its own, at most once a day, and after 14 days without a successful check it shows
    "Could not check for updates since <date>", so a frozen endpoint is visible. Without opt-in, the app contacts the
    update endpoint only when the user clicks "Check for updates" (Settings and tray); Settings shows the date of the
    last check, and after 30 days without one the app shows a local reminder, sending nothing.
- **When.** The app downloads in the background and installs when the user agrees or at the next start; never in the
  middle of the first run.
- **Template bundles** (§7.6) travel the same way and are part of the update check, not a third kind of request: each
  release publishes `templates.json` and its minisign signature on GitHub Releases, and a bundle-only release (a
  security fix that moves an image digest) publishes them alone. The channel's `templates-latest.json` names the current
  bundle's URL and `bundle_version`. The app on the hub PC fetches it in the same check, under the same opt-in
  (automatically only when the user said yes; otherwise on "Check for updates"), carrying no identifier. When the named
  version is above the hub's current one (`GET /v1/templates`), or the hub serves none, it downloads the bundle and its
  signature, verifies the signature against the public key compiled into the app, and copies both into the distro's
  `<data>/templates/` through `wsl.exe` with byte-exact pipes, as the upgrade does (§8.3): each file goes to the stdin
  of a command run inside the distro, never through `/mnt/c` or `\\wsl$`. The hub verifies again and applies §7.6's
  anti-rollback rule; the app's own check only saves a useless copy. Like `latest.json`, `templates-latest.json` is not
  signed, so a stale or hostile endpoint can at most withhold a bundle or offer an older one, which the hub refuses.

### 14.2 The distro (agent, hub, image)

- Each app release pins one node image version and its SHA-256 (§8.3). After the app updates, it upgrades the distro
  with §8.3's state-preserving procedure.
- **Interruptions.** An upgrade stops the distro: running jobs are lost and retried (H1), services restart per §7.2,
  and on the hub PC the phone loses the cloud for about a minute **(H)**. If anything runs, the app asks: "Update now",
  "Tonight at 03:00" or "Later" (at most 72 h, then it updates at the next moment with nothing running).
- **Order: hub first.** H1 upgrades servers before agents. The hub PC's app upgrades its distro (hub and local agent)
  as soon as it can. A joined PC's app reads the hub version (`Welcome.server_version`, shown by
  `p2pc-agent status --json`); if the new image's `min_server_version` is above it, it waits and shows "Waiting for your
  hub PC to update".

### 14.3 Version skew

| Pair | Rule | When broken |
|---|---|---|
| hub ↔ agent | agent ≥ hub's `min_agent_version` (H1); hub ≥ the image's `min_server_version`; an agent newer than its hub sends only what the hub knows (H1) | `agent_too_old` exit 6 (H1); the joined PC waits (§14.2) |
| app ↔ distro | the app manages exactly the image version it pins; it never downgrades a distro | a distro newer than the app (another tool upgraded it) → the app updates itself first |
| web app ↔ hub | `GET /v1/server` returns `api_version` and `min_web_version`; each web build's signed manifest carries `min_hub_version` (§9.6), raised only by a change the older hubs cannot serve, and the build works with every hub at or above it, using a newer hub's features only when `api_version` says the hub has them | web app too old → it reloads to update; hub below the build's `min_hub_version` → the web app shows "Update the P2PC app on your hub PC" and sends nothing but `GET /v1/server`, and the hub PC's app says so after its verification (§9.6); hub too old for one feature → that feature shows the same message |
| template bundle ↔ hub | `min_hub_version` and the high-water `bundle_version` (§7.6) | the hub ignores the bundle and keeps the highest bundle it may serve; below the high-water mark it serves none (`templates_unavailable`) |
| device protocol | ALPN `p2pc/device/1` (and `/pair/1`, `/invite/1`); a breaking change takes `/2` and the hub serves both for one release | a phone on `/1` after the hub dropped it → "Update the web app" |

### 14.4 Windows code signing

- **Beta: unsigned.** Windows SmartScreen shows "Windows protected your PC" for an unsigned, little-known download;
  the tester clicks "More info", then "Run anyway". The beta guide shows this with screenshots, and the release page
  publishes the installer's SHA-256. Unsigned binaries may also draw more antivirus false positives **(H, E10
  records it)**.
- The Tauri updater's signature (§14.1) is independent of Authenticode, so updates are verified even while the
  installer is unsigned.
- **A public H2 release requires Authenticode signing** of the installer, the app and the uninstaller. Which entity
  signs, with what kind of certificate or signing service, and its cost are owner decisions (O-1).

### 14.5 From beta to public release

The public H2 release needs, beyond the acceptance criteria: code signing (O-1); our own relay in production, with
monitoring and a spending cap (O-3); the official domain for the web app and relay (O-2); an external security review
of pairing, the device protocol, the web app and port forwarding; a privacy notice that says what the relay and the
static host can see (O-14); a license review of template images and default models (O-5); and the self-hosting
guide.

## 15. Security

### 15.1 Security invariants (each one MUST have a test)

H1's SI-1 to SI-13 stay in force and keep their tests.

| ID | Invariant |
|---|---|
| SI-H2-1 | No secret appears in logs, `Debug` output, errors, audit events, the app's logs or the browser console: device keys, pairing tickets, invite codes, listener nonces before their reveal, join tokens, API keys. A test scans the outputs of every pairing, invite and join path. |
| SI-H2-2 | Pairing tickets are single-use and expire, checked against the hub's row, never the payload. Two concurrent `Pair`s for one ticket create exactly one device; a retry from the same NodeId is idempotent while its device is live; a retry from the same NodeId after that device was revoked gets `invalid_ticket` and creates nothing; every failure is the same `invalid_ticket`. Tests: the concurrent pair, the retry, the retry after revocation (by an `admin` and by the device itself), a retry from another NodeId. |
| SI-H2-3 | A device principal exists only on `p2pc/device/1`. No request on the TCP listener or `p2pc/http/1` can carry one (no header, no query parameter); a device stream with an `Authorization` header gets `400`. |
| SI-H2-4 | Revoking a device closes its live connections and its open service streams within 5 s, and later connections get the same `not_paired` as a NodeId never paired. A device reaching its `expires_at` gets the same, through the 2 s liveness sweep (§5.5): with an injected clock, an open device port connection with traffic flowing is closed within 5 s of `expires_at`. Paired non-`admin` devices cannot keep the owner from revoking: with every non-`admin` device at its per-device stream cap and the non-`admin` share of the device budget full (§6.3), an `admin` device still opens streams from its reserve and revokes; an idle device port connection closes after `port_idle_s`. With the 32 pre-check slots of `p2pc/device/1` held full by unknown NodeIds, the hub PC's app still revokes a phone through the offline `p2pc-server devices revoke` while the hub runs, and the hub closes that phone's connections and service streams within 5 s. Device streams and the TCP REST listener have separate budgets (§6.3): with the TCP listener's connection cap held full by unauthenticated loopback connections (from the Windows host or another WSL2 distro), an `admin` device still opens streams and revokes, and with the whole device budget in use, a TCP client with an API key still gets a connection. Tested with an injectable clock and a real in-process hub. |
| SI-H2-5 | Opening a service port requires `services:connect` (or `templates:launch` for a template service of the caller's template view, §5.5), the job's account and project, a `running` service and a listed port, through one code path for every transport. Cross-account, unlisted-port and template-view negative tests: a phone-profile device gets `404` on a `p2pc service run` service and on another device's non-singleton template service. |
| SI-H2-6 | `PortOpen` and `BlobFetch` are fenced by `(lease_id, epoch)` on the hub and on the agent; a stale one is refused. |
| SI-H2-7 | The agent never connects to a socket path inside a job's directories except its own `ingress.sock`, which it created in the read-only mount; the shim refuses unlisted ports. The agent reads only the status line of a health check response, at most 1 KiB (§11.2). Tests: a symlink planted where a socket could be, an unlisted port, a fake shim, a health check answered with an endless status line or an endless body (the check fails or passes on the status line alone, and the agent reads no more than 1 KiB). |
| SI-H2-8 | Blobs are per account, in the database and on disk: `HEAD`, upload deduplication and `inputs` never see another account's blobs; the file lives under `<data>/blobs/<account_id>/`, and the lock is keyed by `(account_id, digest)`. The declared size is checked before the body is read, with `checked_add` against the quota; the hash is verified on upload and again on the node. Tests (with two accounts in the store, although H2 serves one): the same digest uploaded in both, then GC and `DELETE` in one, leave the other's file and row intact and readable by its job; concurrent upload in one account and GC in the other do not wait on each other's lock. |
| SI-H2-9 | Volumes follow the one proposed exception to hard rule 3 of §4.3 and nothing more, and only once it is in force (O-16): a volume directory is created by the agent, per account and named by hash, never taken from the JobSpec; it is mounted only into a service or template job of its account; before every mount the agent recreates or verifies the directory chain and walks the tree without following links, refusing any symlink, any entry that is not a directory or a regular file, and any regular file with more than one link; `tpl:` volumes are created only by template launches; size limits hold; deletion never follows a link. Tests: a batch non-template job with `volumes` (`422` at the hub, `invalid_job` at the agent), a cross-account lease, names with `/`, `..` and NUL, a symlink planted inside a volume before deletion, **a symlink (to a file and to a directory outside the volume), a FIFO and a hard-linked file planted inside a volume before it is mounted again with `:U` or `:idmap`** (the mount is refused with `volume_unsafe`, and the link's target keeps its owner), a symlink replacing `data/` or `<hash>/` itself, a golden argv test of the `-v` arguments; **the one-holder lock**: a lease that ends while `podman rm` fails keeps the lock and a second lease is rejected; an agent restarted with an orphaned container still holding the volume walks and mounts nothing until its sweep has removed the container and Podman reports it absent. |
| SI-H2-10 | A service container keeps `--network=none` (golden argv test) and its ports are reachable only through the bridge: a scan from the distro's network namespace, the Windows host and another LAN machine finds them closed. |
| SI-H2-11 | P2PC adds no listener reachable from the LAN. TCP: the hub's REST is not reachable from another machine, and the desktop app opens no TCP listener. UDP: the app's only sockets are its device endpoint's, which accepts no incoming connection; the invite listener exists only during a join, serves only `p2pc/invite/1` and has no IP transport (§5.4). The hub's endpoint accepts only what §10.5 lists, and serves `p2pc/pair/1` only while a pairing ticket is open. Tests: socket enumeration of the app process (no TCP listener; UDP sockets only from its device endpoint), the same enumeration during a join (the invite listener binds no LAN-reachable UDP socket) and a direct QUIC probe of the invite listener from the LAN machine that gets no answer, a TCP scan and a UDP probe of the Windows host from the LAN machine (with NAT networking, no reply from the hub's sockets), an incoming QUIC connection to the device endpoint that is refused, and probes of the hub's endpoint from an unknown NodeId through a relay: `p2pc/pair/1` with no ticket open fails at the handshake (or closes before a frame), `p2pc/device/1` gets `not_paired`, `p2pc/http/1` without a key gets `401`, and `p2pc/agent/1` without a valid `Join` is closed. |
| SI-H2-12 | The web app and the desktop UI never turn untrusted text into HTML: a lint rule bans `innerHTML`, `outerHTML`, `insertAdjacentHTML`, `document.write`, `eval` and `new Function`; a DOM test feeds model output with `<script>`, `<img onerror>` and `javascript:` links and checks they render inert. The deployed header files contain the CSP of §9.5 (a test parses them). |
| SI-H2-13 | Every template image is pinned by digest, and parameters reach the job only through the targets of §7.6: whole env values, whole argv elements, a field of the closed list (`service.idle_timeout_s`, `timeout_s`) within the template's bounds, which lie inside the JobSpec range, an `inputs` entry at the template's fixed path, or the `pull` model of a chat template (an enum value). A test runs over the bundle (the shipped `private-chat` and `transcribe` pass it; a fixture with a `field:` target outside the list, or with bounds outside the JobSpec range, fails); a property test feeds shell metacharacters as parameter values and checks the resulting JobSpec; out-of-type and out-of-bounds values get `422 invalid_params`. |
| SI-H2-14 | The hub loads a template bundle only with a valid release signature, a `bundle_version` above the embedded one and not below its persisted high-water mark (equal only with the recorded SHA-256), and a satisfied `min_hub_version`, and it never serves a bundle below the mark. Fixtures for each failure, plus: a validly signed bundle below the mark (the rollback case) is refused, also after a hub restart; a different bundle with the mark's version is refused; with the file at the mark deleted, the hub serves no template (`503 templates_unavailable`) rather than the older embedded bundle. |
| SI-H2-15 | The app's updater refuses an artifact with a bad signature, without a signed version, or with a signed version not greater than its own. |
| SI-H2-16 | An invite code is single-use; the hub phrase is a pure function of (hub NodeId, listener NodeId, code), the approval phrase of (hub NodeId, agent NodeId, listener nonce, hub nonce) and the node phrase of (node NodeId), each 6 words (66 bits) with test vectors; the app joins only after the explicit confirmation. **Join requests resist an offline search** (§5.4 steps 3-5): the hub draws the hub nonce only after the request, with its agent NodeId and listener commitment, is stored; it computes and shows the approval phrase only after a reveal that matches the commitment; the listener reveals its nonce once, to the first phone with the valid code, and accepts `Invite` only from that phone. Tests: vectors for each rejected input of `POST /v1/nodes/join-requests` (`invite_expires_at` equal to now, in the past, and 1 s beyond now + 15 min + 120 s; a `listener_node_id` and an `iroh_node_id` of 32 bytes that do not decode to a curve point, and of the wrong length; a commitment of the wrong length), each `422 invalid_join_request` with no row created; two requests with identical inputs get different hub nonces and different phrases; `approve` of an `awaiting_reveal` request gets `409` and the hub PC shows no phrase for it; a reveal that does not match the commitment gets `409`, sets `rejected` and allows no second reveal; on the listener, a second phone's `InviteOpen` or `Invite` gets `already_open`, a repeated `InviteOpen` with another hub nonce gets `already_open`, an `Invite` before any `InviteOpen` gets `invalid_code`, and an `Invite` whose join token names another hub than the `InviteOpen` gets `hub_mismatch` and is not joined. The hub PC's approval screens show the phrase, the source device as recorded at pairing and the request or enrollment time; `approve` and `token` of a join request created more than 15 minutes ago get `409 join_request_closed`, also while the expiry sweep has not run (an injected clock with the sweep stopped, for a `pending` and for an `approved` request); a join token of a join request enrolls only its bound agent NodeId (another NodeId gets H1's invalid-token answer and the token stays unused); one device cannot hold more than 2 open join requests or create more than 6 an hour (`429`). |
| SI-H2-17 | `p2pc/pair/1` and `p2pc/invite/1` enforce their pre-auth limits (connections, pending exchanges, deadline, 4 KiB frames, failure rates: §5.3 and §6.2), and `p2pc/device/1` its limits before the device check (§6.3: 32 unchecked connections, 5 s, 10 `not_paired` a minute per NodeId); their decoders are fuzzed or property-tested. The limits never lock the owner out: with failure counters over their limits from other NodeIds and other ticket-hash prefixes, a `Pair` with a valid ticket that gets a connection slot still pairs (§5.3), an `Invite` with the valid code still gets `InviteAck` (§6.2), and a live device still connects (§6.3). The same holds for `p2pc/agent/1` (§6.1, T2-17): with H1's 60-a-minute total of failed `Join`s reached by other NodeIds, a `Join` with a valid token from a fresh NodeId that gets a slot still enrolls, and a NodeId over its own 10 a minute is still refused without the token lookup. **The aggregate failure cap** (§5.3) holds on every one of these ALPNs: with failures spread over fresh NodeIds and every ticket-hash or token-hash prefix, beyond 60 a minute no failure gets a detailed answer or is logged or audited one by one (one aggregated audit event a minute counts them), while a valid credential that gets a slot still succeeds. |
| SI-H2-18 | No escalation for devices: pairing tickets carry a subset of the creator's power (scopes, `daily_unit_cap`, image allowlist, expiry, device expiry, `blobs_quota_mb`), set through the ticket's body (§5.2; tests: a ticket from a capped creator without a cap, with a higher cap, or with an image pattern not in the creator's list gets `403 escalation_denied`, and a device paired with a cap and a list is refused a job beyond them; a ticket from an expiring key with no `device_expires_in_s`, or with one beyond the key's `expires_at`, gets `403 escalation_denied`; a device past its `expires_at` gets `not_paired`); a device's cap is enforced against its own principal (§12), never against the key or device that paired it; `nodes:join` creates tokens of at most 900 s and nothing else; `nodes:invite` creates only join requests; only `admin` creates pairing tickets; the last unrestricted `admin` principal cannot be revoked (`409 last_admin_key` for a key, `409 last_admin_device` for a device); a restricted `admin` principal revoking an unrestricted device gets `403 escalation_denied`; a non-`admin` device sees only itself: `GET /v1/devices` returns a one-item list and `GET /v1/devices/{id}` of another device gets `404`. **The default phone profile reaches only what §5.5 lists**, pinned by a negative test per route with a phone-profile device in a project that also holds a developer batch job, a `p2pc service run` service, another device's `transcribe` job and a `private-chat` instance launched by the owner: `POST /v1/jobs` gets `403`; `GET /v1/jobs` lists only its own template jobs and the singleton instance; `GET /v1/jobs/{id}`, `…/logs`, `…/outputs` and `…/outputs/{path}` of the developer jobs and of the other device's job get `404`; logs and outputs of the owner's singleton instance get `404`; `…/ports/{port}/connect` on the developer service gets `404`; `…/cancel` of the developer jobs and the other device's job gets `404` (and with `jobs:write`, H1's project-wide cancel still works); `GET /v1/usage`, `POST /v1/estimate`, `GET /v1/blobs`, `POST /v1/nodes/join-tokens`, `POST /v1/devices/pairing-tickets`, node drain, resume and delete, key and audit routes get `403`; `DELETE /v1/blobs/{sha256}` of a blob the owner uploaded gets `403`, a third concurrent upload gets `429 too_many_uploads`, and an upload beyond the device's `blobs_quota_mb` gets `507`; after the owner uploads a digest the phone uploaded first, the phone's `DELETE` removes only its own claim and the owner's job still finds the blob. Blob quota and device expiry: a ticket from a creator with `blobs_quota_mb` without one or with a higher one gets `403 escalation_denied`, as does a revocation by such a creator of a device without one; `device_expires_in_s` of 0, not above `expires_in_s`, or overflowing gets `422 out_of_range`. **The private chat's port is filtered by its `allowed_routes`** (§7.4): through the phone-profile device, `POST /api/chat` (streamed) and `GET /api/tags` work; `POST /api/pull`, `POST /api/create`, `POST /api/blobs/<digest>` and `HEAD` of it, `POST /api/copy`, `DELETE /api/delete`, `POST /api/push`, an unknown path, an allowed path with a query string and an allowed path with the wrong method get `403 route_not_allowed` and reach nothing in the container (a fake service records every byte); headers over 8 KiB get `431`, a body over 1 MiB gets `413`, `Transfer-Encoding` gets `400`, and bytes after an allowed request's body are not forwarded; a developer device on the same port still gets a raw connection; the hub's own model pull at launch fills `service.setup`. |
| SI-H2-19 | No PC gets work without an `admin`'s approval. The default phone profile has no `nodes:join`. A node enrolled with a token minted by a non-`admin` principal is `pending_approval`, and the scheduler never offers it a lease until an `admin` principal approves it; a join request yields a token only after an `admin` approval, only to the requesting device and only once. An invite text minted by an `admin` device gives a pending node unless it was minted with `pre_approved`, which only an `admin` principal may set, for at most 900 s. Tests: a property test over the scheduler with pending and approved nodes (no lease ever reaches a pending one); approval by a non-`admin` principal gets `403`; a `nodes:join` device's token gives a pending node; an `admin` device's token gives a pending node without `pre_approved` and an approved one with it; `pre_approved` from a non-`admin` principal gets `403` and with `expires_in_s` over 900 gets `422`; an `admin` API key's token gives an approved node (H1); first-run step 4 run against a real hub enrolls the hub PC's own node `approved`, and that node gets a lease; a join request's token call before approval, after delivery, after the approving principal was revoked, and from another device gets `409` or `404`; the phone profile's scope list is pinned by a test. |
| SI-H2-20 | Ledger and caps stay exact with two kinds of principal and daily slices (§5.6, §12). Every row of `jobs`, `usage_records` and `join_tokens` names exactly one principal (`CHECK`); idempotency deduplicates per principal for keys and for devices alike; the ledger stays append-only after the rebuild; `spent(P, D)` never counts a service's reservation and the slices written against it twice, and gives H1's numbers for batch jobs. Tests: inserts with both or neither principal column set fail; two submissions with one idempotency key from one device give one job, and from two devices or from a device and a key give two; `UPDATE` and `DELETE` on `usage_records` fail after the migration; the migration test of §5.6; a property test with an injectable clock over batch and service jobs of key and device principals crossing midnights (reservations, slices, requeues, cancels), checking after every step that `spent(P, D)` equals the reference sum of §12, that a service's rows for a day exceed that day's `cap_reserved_units` only by an estimated slice of an attempt the hub could not reach at `cap_deadline` (up to the end it observed), and that ledger invariant 6 (one row per finished slice) holds; H1's cap tests pass unchanged. `GET /v1/usage` over the same histories: `attempts` counts last slices only (a service that crossed three midnights is one attempt), `estimated_attempts` and `estimated_slices` match the reference, `group_by=key` with device rows present returns key groups only and never fails to decode, `group_by=principal` covers every row, and a midnight slice's `max_rss_mb` is the attempt's peak so far. |
| SI-H2-21 | The MCP tool `p2pc_blob_put` reads only regular, non-hidden files inside the configured upload directory, of at most `max_blob_mb`, through no symbolic link in any component, from one descriptor (§7.8). `p2pc mcp` creates the directory 0700 and refuses an unsafe one. Tests (each refused with `path_not_allowed` and nothing uploaded): `../` traversal and a `..` component in the middle; an absolute path outside the directory (`/etc/passwd`, the CLI's credentials file); a symbolic link inside the directory to a file outside it, one to a directory outside it used as a middle component, and the upload directory itself replaced by a link; a hidden file and a file under a hidden directory; a FIFO (the call does not block), a socket and a device node; a sparse file over `max_blob_mb`; a file that grows during the upload. Start-up tests: an upload directory with group or other access, one that is the home directory, and one that contains the credentials directory are refused. |
| SI-H2-22 | The desktop app's web app verification (§9.6) accepts a deployed build only with a manifest signed by the release key and a `web_version` at or above its persisted high-water mark, which starts at its own release's web build version and never goes down; a newer valid build is a notice, never the tampering warning. Tests with test-signed fixtures: the app's own build (verified); a newer valid build (verified, a notice, the mark rises); then the previous build, validly signed (the rollback warning, also after an app restart); a missing manifest, a bad signature and a manifest signed with another key (the unsigned warning offering a self-hosted copy; "Not verified: self-built copy" when `web_app_origin` is not the official origin); a valid manifest with one changed file (the red tampering warning); a valid build whose `min_hub_version` is above the local hub (the update-the-hub notice). |

### 15.2 Threat model additions

| Threat | Mitigation | Residual |
|---|---|---|
| Stolen, unlocked phone | Bounded scopes and the template view (§5.5, SI-H2-18); revocation in ≤ 5 s; devices listed with `last_seen_at`; no `nodes:join` in the default profile, and every PC approved on the hub PC against a check phrase (SI-H2-16, SI-H2-19); at most 2 open join requests per device | Until revoked or expired: use the shared chat service through its `allowed_routes` only (chat with the owner's models, list them; stop it), launch templates and read the state, logs and outputs of the template jobs it launched, see the PCs, upload blobs, test whether a blob of a known digest exists and withdraw its own claims, and open join requests that the owner must approve on the hub PC. Not: pulling, writing, replacing or deleting models; developer jobs, other devices' template jobs, non-template services, chat history of other devices. |
| Misbehaving or many paired phones | Per-device stream cap, a share of the device budget reserved for `admin` devices, idle limits on device port connections (§6.3, SI-H2-4) | They can slow each other down; not the hub PC's app. |
| Local processes on the hub PC (other Windows sessions too) and the user's other WSL2 distros (Docker Desktop's too) at the loopback REST listener | API key on every request (H1 §10); device streams have their own budget, outside the TCP connection cap (§6.3, SI-H2-4) | They can fill the TCP cap and delay API-key clients on that PC; never the devices, nor the owner's revocation. |
| Prompt-injected agent behind MCP | `p2pc_blob_put` reads only regular, non-hidden files inside one upload directory, through no symbolic link (§7.8, SI-H2-21); H1's capped key and image allowlist | Files the user put in the upload directory can be uploaded and used as job inputs. |
| XSS in the web app | CSP, Trusted Types, no HTML sinks, no third-party code, SRI | A bug in our own code can still leak the device key. |
| Malicious or compromised static host | Reproducible build; a signed, versioned manifest for every web build at the origin; the desktop app's verification with its anti-rollback mark (SI-H2-22); self-hosted copy (§9.6) | Targeted tampering of one client is not detected; a host can withhold a newer build. |
| Malicious or compromised relay | End-to-end encryption [S1] | Sees NodeIds, timing and volume; can drop traffic. |
| Photographed pairing QR | 10-minute, single-use ticket; the app shows each new device | A race inside the window. |
| Photographed invite QR, or a compromised web app origin on the owner's phone during a join | Hub phrase and approval phrase, 6 words each (§5.4); the approval phrase rests on the listener's commitment and the hub's nonce, so no offline search finds a match (1 in 2^66 per join request); the request's NodeIds and expiry are checked; the listener binds to the first phone; the join request's token is bound to the agent NodeId (SI-H2-16) | A user who confirms without comparing; a photographer who opens the listener first blocks that join (the owner starts again). |
| Leaked invite text (pasted into a chat app) | 15 minutes, single use; its node starts `pending_approval` and is approved on the hub PC against the node phrase, unless the owner chose "Pre-approve" (§5.4, SI-H2-19) | With "Pre-approve", whoever uses the text first within 15 minutes joins and gets work; without it, a user who approves without comparing. |
| Container escape | H1 sandbox; owner's jobs only (SI-1); digest-pinned templates | Now also reaches the hub (D1, §11.5). |
| Compromised upstream template image | Digest pinning, reviewed bumps, signed bundle, and the hub's anti-rollback high-water mark, so a stale or hostile update endpoint cannot bring back a replaced digest (§7.6, SI-H2-14) | Trust in upstream at pin time; an endpoint can withhold a fix (the 14-day notice of §14.1 makes a frozen endpoint visible). |
| Unauthenticated peers at the hub's iroh endpoint | Reachable only through a relay or hole punching under WSL NAT; every ALPN behind a token, a ticket, a key or a paired NodeId; H1's pre-auth limits (with the `Join` fix of §6.1) and §5.3's; `p2pc/pair/1` served only while a ticket is open (§10.5, SI-H2-11) | Pre-auth parsing bugs; with mirrored networking, LAN peers reach the same surface directly. |
| The hub relays service bytes in clear | It is the owner's own machine | A compromised hub sees chats. |
| Loss of the hub PC | Joined PCs give up after 14 days unreachable (`hub_gone`, §8.8); uninstalling the hub removes the other nodes first (§8.7) | The cloud is gone; pair and join again (O-12). |
| Fake installer (unsigned beta) | Published hash, official links only | Users may be tricked until signing (O-1). |
| npm supply chain | Lockfile, `--ignore-scripts`, license and advisory checks, few dependencies, SBOM | A compromised dependency at build time. |

## 16. Beta acceptance criteria

**Lab.** (a) A clean Windows 11 VM with nested virtualization, from a snapshot, for install and uninstall; (b) the
**reference PC**: Windows 11, an NVIDIA GPU with at least 6 GiB of VRAM, an SSD with at least 150 GiB free, 100 Mbit/s
down; it is the hub; (c) a second Windows 11 PC (a laptop) as a joined node; (d) an iPhone with current iOS Safari and
an Android phone with current Chrome, on 4G/5G with Wi-Fi off; (e) a Linux machine on the same LAN for scans. Scripted
criteria live in `tests/acceptance-h2/`; **manual** ones have a written protocol there and a filled-in result sheet in
the release PR.

| ID | Criterion | How |
|---|---|---|
| AC-H2-1 | Install to "Your cloud is ready": ≤ 5 min (reboot time excluded), ≤ 1 reboot, ≤ 1 UAC prompt; on the clean VM both without WSL and with WSL already installed. | **Manual**, timed; the app logs step timestamps, which the sheet copies. |
| AC-H2-2 | Join the second PC with the phone-assisted invite (join request approved in the hub PC's app after comparing the approval phrase) in ≤ 3 min, and with the invite text (the node waits as `pending_approval` until it is approved on the hub PC against the node phrase; with "Pre-approve" it is approved at once). A node enrolled with a token from a `nodes:join` test device stays `pending_approval` and gets no job until approved. | **Manual**, plus a scripted check of the pending node. |
| AC-H2-3 | Pair the iPhone (home-screen path) and the Android phone in ≤ 2 min each, on 4G. The hub reports the connection as relayed. | **Manual**, plus a scripted check of `GET /v1/devices`. |
| AC-H2-4 | Private chat from the phone on 4G: launch → healthy; first model download with visible progress; with the model cached, service start to healthy ≤ 60 s **(H)**; first token ≤ 3 s after sending **(H)**; a 20-message conversation without error. | **Manual**; the web app's debug panel records the timings. |
| AC-H2-5 | Transcribe a 30-minute audio file (≈ 30 MB) uploaded from the phone; the transcript arrives within 10 minutes on the reference GPU **(H)**, also when the tab was closed during the job. The same flow passes through the CLI (`p2pc blobs put`, `p2pc templates launch transcribe`). | Manual (phone) + **scripted** (CLI). |
| AC-H2-6 | Service isolation: the chat port is closed from the distro's network namespace, the Windows host and the LAN machine; `podman inspect` shows `--network=none`; the port works through `p2pc service connect`. | **Scripted**. |
| AC-H2-7 | Revocation: two test devices (native `p2pc-device` clients); revoking one closes its connections and streams within 5 s and refuses it afterwards; the other is unaffected. Repeated by hand mid-chat on the phone. | **Scripted** + manual. |
| AC-H2-8 | Pause, resume, stop sharing and "Turn off my cloud" do what §8.4 says; a share change is visible in `GET /v1/nodes/{id}` within 10 s. | **Scripted** (through `p2pc-agent share set` and the API) + manual (UI). |
| AC-H2-9 | Uninstall leaves nothing: a before/after inventory of the user profile, `HKCU`, scheduled tasks and `wsl -l -v` on the VM differs only by the uninstall log in `%TEMP%`; with a planted failed-upgrade backup, it is kept (and listed) by default and deleted with the checkbox (§8.7); a joined PC disappears from the hub's node list. Uninstalling the hub PC makes a connected joined PC's agent exit 7 (`node_removed`), and a joined PC kept offline during it reaches `hub_gone` with an injected 14-day clock. | **Scripted**. |
| AC-H2-10 | Update from release N to N+1 (test-signed fixtures) while the chat runs: the app, then the hub, then the joined PC update in order; node and device identities, volumes and pairings survive; the chat comes back; a downgrade fixture is refused. | **Scripted** in part (fixtures, version checks) + manual. |
| AC-H2-11 | Every SI-H2 test and every H1 SI test passes; the deployed web app returns the §9.5 headers (a `curl` script); an internal pentest of pairing, invites, the device protocol, the web app and port forwarding finds no critical issue. | **Scripted** + manual pentest. |
| AC-H2-12 | H1 regression: the H1 acceptance suite (AC-1 to AC-12) passes against an H2 hub, and the v0.1 CLI, SDK and MCP work unchanged against it. | **Scripted**. |
| AC-H2-13 | Relays: the phone reaches the hub through our own HTTP-mode relay and through n0's; with the production relay map (§10.3) a job with egress on a WSL2 node opens the egress gate and downloads a model. | **Scripted** (from E12) + manual (phone). |
| AC-H2-14 | Docs: a beta tester guide (install with SmartScreen, the first-run choice on automatic checks, where it asks testers to choose "Yes", the possible Windows firewall prompt, share, pair, chat, transcribe, uninstall), a self-hosting guide (relay and web app), and updated `SECURITY.md` and residual risks let a tester do AC-H2-1 to AC-H2-5 without help. | Manual: one tester who did not build it. |

Checked against the limits: a 30 MB audio file is well under `max_blob_mb` (2 GiB) and the template's `disk_mb`
(4 GiB); with the §8.2 formula the default 90 GiB disk share gives jobs `min(50 GiB, 90 GiB / 2)` = 45 GiB and volumes
90 − 45 = 45 GiB, which holds the two template volumes (20 GiB + 5 GiB = 25 GiB, also within the 50 GiB minimum share
of §8.2); and the reference PC's free space allows the default share on the hub PC with the full blob quota (§8.2
"Disk arithmetic": 90 GiB share + 16 GiB images **(H)** + 20 GiB blobs + the 20 GiB floor = 146 GiB ≤ 150 GiB).

## 17. Work breakdown

Each task is one PR of 1-3 days **(H)**. "Depends" lists the tasks that must be merged first. Tasks that can run at the
same time (in different lanes, or in one lane with no dependency path between them) touch disjoint files, so up to six
workers run in parallel once T2-00 to T2-02 land. Files that several server tasks need are ordered by dependencies:
T2-10 writes every H2 migration of §13 and every new server config key of §5-§12 (with defaults and start-up checks), so
later server tasks add neither; `app.rs` (the router), `jobs_api.rs`, `store/jobs.rs` and `conn.rs` are edited only by
tasks on one dependency chain (T2-10 → T2-12 → T2-13 → T2-14 → T2-15). In `apps/web`, the shell (T2-31) loads every page
under `apps/web/src/desktop/` by directory convention, so T2-43 and T2-44 only add files there. The experiments (§18)
run first, in throwaway `spikes/` directories, and their results amend this spec before the tasks that depend on them
start.

| Task | Title | Depends | Touches | Notes |
|---|---|---|---|---|
| T2-00 | Workspace scaffold for H2 | — | root `Cargo.toml`, `deny.toml`, CI workflow, new empty crates `p2pc-device`, `p2pc-wsl`, `apps/desktop`, `apps/web`, `templates/`, `deploy/relay`, `deploy/web` | So that no later task edits the root files. Windows CI runner for `p2pc-wsl` and the app. |
| T2-01 | Proto: JobSpec extension | T2-00 | `p2pc-proto` `api.rs`, `validate/` | §7.1 table, states and `service` view types, blobs, volumes, templates, devices, errors; proptests. |
| T2-02 | Proto: protocol additions | T2-00 | `p2pc-proto` `protocol.rs`, new `pair.rs`, `device.rs`, `invite.rs`, `lib.rs` (ALPN constants) | §6: capabilities, new messages (`Heartbeat.running[]` with `used_cpu_ms` and `max_rss_mb`), stream headers, pairing, invite (the QR payload with the agent NodeId), the listener commitment, `InviteOpen`/`InviteReveal`, the three 6-word check phrase functions (hub, approval, node; §5.4, §5.5) with vectors; decoder fuzzing (SI-H2-17). |
| **Server lane** | | | | |
| T2-10 | Server: devices and principals | T2-01, T2-02 | `p2pc-server` `auth.rs`, `store/devices.rs`, `store/jobs.rs` (principal columns and idempotency), `store/join_tokens.rs`, `store/audit.rs`, new `devices_api.rs`, migrations (every H2 table of §13), `config.rs` (every new key), `app.rs`, `init.rs`, `recover.rs` | §5.2, §5.5, §5.6: principals, scopes, pairing tickets REST (retry after revocation), revocation (`last_admin_device`), `GET /v1/devices` filtered for non-`admin` devices, `init --owner-device`, `devices add`, `whoami`, audit; **the §5.6 rebuild migration** of `jobs`, `usage_records` (the slice columns and key of §12 too, so the ledger is rebuilt once), `join_tokens` and `audit_events`, with its migration test; join requests (input checks, hub nonce, the reveal against the listener commitment, limits, the 15-minute rule for approval and token minting, approval phrase, tokens bound to the agent NodeId), pairing tickets with `daily_unit_cap` and `allowed_images`, the offline `devices revoke` and the 2 s re-check of live devices' revocation, `pre_approved` join tokens and node approval with the node phrase (§5.4, §5.5, SI-H2-2, SI-H2-16, SI-H2-18, SI-H2-19, SI-H2-20). |
| T2-11 | Server: `p2pc/pair/1` and `p2pc/device/1` | T2-10, T2-17, **O-16** | `gateway/pair.rs`, `gateway/device.rs`, `gateway/limits.rs`, `gateway/mod.rs`, `gateway/endpoint.rs` | **Blocked** until the separate change of §4.3 puts the listening exception in force (O-16, ADR-016). In-process HTTP serving with the device principal, limits that never lock out a valid ticket, the device stream budget (per-device cap, `admin` reserve, idle limit of device port connections, outside the TCP REST cap, §6.3), the limits before the device check (§6.3), `p2pc/pair/1` served only while a ticket is open (§10.5), the aggregate failure cap (§5.3), active close on revocation (SI-H2-3/4/11/17). |
| T2-12 | Server: service jobs | T2-10 | `scheduler/`, `jobs_api.rs`, `store/leases.rs`, `store/jobs.rs` | §7.2: restart policy and its 5-per-24-h cap, affinity wait, health from agents, idle cancel, the template view of the job routes (§5.5) and the cancel rule (H1's for `jobs:write`; the template view for `templates:launch`), `kind` filter, capabilities in placement, no lease to `pending_approval` nodes (SI-H2-18, SI-H2-19). |
| T2-13 | Server: service ports | T2-11, T2-12 | new `ports_api.rs`, `gateway/ports.rs`, `conn.rs`, `app.rs` | §7.4 upgrade endpoint (with the template-view check and its `allowed_routes` filter) and hub-opened `PortOpen` streams, idle accounting, traffic counters (SI-H2-5/6). |
| T2-14 | Server: blobs | T2-12, T2-13 | new `blobs_api.rs`, `store/blobs.rs`, `gateway/blob_fetch.rs`; `gc.rs`, `jobs_api.rs` and `store/jobs.rs` (the blob check and reference insert in the job-creation transaction), `conn.rs` (the dispatcher for agent-opened streams), `app.rs` | §7.5 (with the tombstone GC), the staging sweep by last write that skips uploads in progress (§13), blob `inputs` at job creation, `BlobFetch` (SI-H2-8). |
| T2-15 | Server: templates and volumes API | T2-14, T2-16, T2-50 | new `templates.rs`, `templates_api.rs`, `volumes_api.rs`, `app.rs` | §7.6 bundle loading with the anti-rollback high-water mark, parameter targets, launch (cap check for capped principals, through T2-16's `spent(P, D)` and daily service reservation: no cap logic of its own and no edit of `store/leases.rs`), §7.3 volumes, with the percent-encoded `{name}` segment and a route test for a `tpl:` name (SI-H2-13/14). |
| T2-16 | Server: metering additions | T2-10, T2-12 | `units.rs`, `usage_api.rs`, `store/leases.rs` (`insert_usage`, `usage_report`, `spent_between` replaced by `spent(P, D)`), `store/usage.rs`, `scheduler/tests/props.rs` | §12: service slices at 00:00 UTC (and the catch-up at start) with their `max_rss_mb`, `charge_day`, new groups, `GET /v1/usage` over slices and principals (`attempts` from last slices, `estimated_slices`, no null group), the cap query `spent(P, D)` per principal and per slice day, the daily reservation of services and `cap_reached`; invariant 6 of the scheduler property test becomes "exactly one row per finished slice"; the cap property test of SI-H2-20. |
| T2-17 | Server: `Join` failure limits (fix of pre-existing H1 behaviour) | — | `p2pc-server` `gateway/limits.rs`, `gateway/agent.rs` and their tests, nothing else | §6.1: a `Join` with a valid token is never refused because other `Join`s failed; when only the 60-a-minute total is exhausted the token is looked up first, or the total stops refusing and failures are counted per NodeId and per token-hash prefix; either way the total stays as the aggregate cap on failure answers and logging (§5.3); the per-NodeId limit, the connection and pending caps stay as in H1 (SI-H2-17). Needs no H2 type, so it starts at once and lands before T2-11, which also edits `gateway/limits.rs`. |
| **Agent lane** | | | | |
| T2-20 | Agent: service lifecycle | T2-02 | `p2pc-agent` `executor/`, `sandbox/driver.rs`, `sandbox/engine.rs` | Services with H1's wall-clock enforcement up to 30 days, health state machine, `ServiceHealth`, log ring, `used_cpu_ms` and `max_rss_mb` in heartbeats. |
| T2-21 | Shim and agent: ingress bridge and port streams | T2-20 | `p2pc-shim`, agent new `sandbox/ingress.rs`, `connection/streams.rs` | §11.2 (health checks read only the status line, at most 1 KiB) and the stream dispatcher for hub-opened streams (SI-H2-7). |
| T2-22 | Agent: volumes | T2-21, **O-16** | agent new `volumes.rs`, `sandbox/engine.rs` (argv), `inventory.rs` | **Blocked** until the separate change of §4.3 puts the hard-rule exception in force (O-16). §11.3, `VolumeReport`, `VolumeDelete`, budget, eviction, GC, the persisted one-holder lock released only when Podman confirms the container gone (across agent restarts, after the orphan sweep), the no-follow check before every mount, mounts only into service or template jobs of the account (SI-H2-9). Uses E11's `:U` vs `:idmap` result and its answer on whether `:U` follows links. |
| T2-23 | Agent: blob fetch, share changes, pause, leave | T2-21 | agent new `blobs.rs`, `config.rs`, `main.rs` (subcommands), `connection/session.rs` | `BlobFetch` client, `share set`, `owner_paused`, `leave`, `approval` (`Welcome.pending_approval`, `NodeApproved`), `status --json` additions (`iroh_node_id` before enrollment, the node phrase). |
| **Device and web lane** | | | | |
| T2-30 | `p2pc-device` crate | T2-02, E9 | `crates/p2pc-device` | Pairing and invite clients, device connection, HTTP/1.1 over streams, `open_port`; native and `wasm32` builds in CI; a native test client for AC-H2-7. |
| T2-31 | Web app shell, pairing and key storage | T2-30 | `apps/web` (shell, `/pair`, `/settings`, storage, QR scanner), lint config | §9.1-§9.3, §9.5 lint rules and headers (SI-H2-12), the build's `min_hub_version` check (§14.3). |
| T2-32 | Web app: home, jobs and chat | T2-31 | `apps/web` pages `/`, `/jobs`, `/chat`, the Markdown-subset renderer | §9.4 chat. |
| T2-33 | Web app: transcribe, uploads and invites | T2-31 | `apps/web` pages `/transcribe`, `/invite`, upload module | §9.4 transcribe, §5.4 phone side (join request with the QR's NodeIds, expiry and commitment, the `InviteOpen` and reveal of §5.4 step 4, wait for approval, hand-over). |
| T2-34 | Web build, manifest and deploy configs | T2-31 | `deploy/web/`, `scripts/web-manifest`, CI | Reproducible build; signed `web-manifest.json` per web build (`web_version`, `min_hub_version`, file hashes) served at the origin; deploying a release's web build before its app update (§9.6); Cloudflare Pages, Vercel and nginx configs. |
| **Desktop lane** | | | | |
| T2-40 | `p2pc-wsl`: checks, download, import, task | T2-00 | `crates/p2pc-wsl` (`checks.rs`, `image.rs`, `import.rs`, `task.rs`) | §8.3 first half. |
| T2-41 | WSL image: hub in the distro | **O-16** | `deploy/wsl/` (`build-rootfs.sh`, `p2pc-run`, `test-distro.sh`, `install.ps1` upgrade list) | **Blocked** until O-16 puts the listening exception in force (§4.3, ADR-016): it makes the hub's endpoint accept connections on a node PC. §8.5: `p2pc-server` in the image, `p2pc-run`, `hub.enabled`, upgrade carries `/var/lib/p2pc-server`. |
| T2-42 | Tauri app shell | T2-00 | `apps/desktop` (`src-tauri` core, tray, single instance, autostart, capabilities, DPAPI key) | §8.1, §8.4 states, §8.9. Embeds a placeholder UI until T2-31 lands. |
| T2-43 | First run | T2-40, T2-41, T2-42, T2-10, **O-16** | `apps/desktop` `setup/` module and the setup pages in `apps/web/src/desktop/` | §8.2 steps 1-5 (including the opt-in choice of step 1, the disk arithmetic, the hub's blob quota and the `pre_approved` token of the hub PC's own node at "Create my cloud"), `setup.json` resume, §8.8 errors, the mirrored-networking warning (§10.5). |
| T2-44 | Join flow | T2-43, T2-30, **O-16** | `apps/desktop` `invite/` module, `apps/web/src/desktop/join` | **Blocked** until O-16 (the invite listener rests on ADR-016). §5.4 PC side (relay-only invite listener built through `p2pc-net` with `direct_addresses = "none"`, no IP transport, with the §6.2 limits and its binding to one phone, QR with the agent NodeId and the listener commitment, the approval phrase shown after `InviteReveal`), invite text (pending by default, the explicit "Pre-approve" option on the hub PC only), hub phrase (SI-H2-16); on the hub PC, approving join requests and pending nodes with the approval and node phrases, the source device and the time; `join_pending` with the node phrase and `hub_gone` (§8.8). |
| T2-45 | `p2pc-wsl` upgrade and uninstall; app updater | T2-43 | `crates/p2pc-wsl` (`upgrade.rs`, `uninstall.rs`), `apps/desktop` `update/`, `uninstall/`, NSIS hooks | §8.3 second half, §8.7 (the hub deletes the other nodes first; failed-upgrade backups kept unless the box is ticked), §14.1-§14.2 (opt-in automatic checks, template bundle delivery), web app verification with the signed manifest and its high-water mark (§9.6, SI-H2-22), parity test with `install.ps1` (SI-H2-15). |
| **Infrastructure and clients lane** | | | | |
| T2-50 | Templates data and bundle | T2-01, E11 | `templates/`, `scripts/templates-bundle` | The two templates (with `allowed_routes` and the `pull` parameter), bundle compiler and signer, bundle tests (SI-H2-13). |
| T2-51 | Relay deployment and relay-map rules | E12 | `deploy/relay/`, `p2pc-net` (relay-map validation), `p2pc-agent` `doctor.rs` | §10.2-§10.3. |
| T2-52 | Release pipeline | T2-45, T2-34, T2-50 | `.github/workflows/`, `scripts/release/` | Tauri artifacts and `latest.json` per channel, signed versions, image hash pinning, signed web manifest and template bundle. |
| T2-53 | CLI and client additions | T2-01 | `p2pc-cli` commands, `p2pc-client` | §7.8 CLI (including `nodes approve`, `devices pair --cap/--image` and the percent-encoded name of `volumes rm`); tested against the mock server, which learns the new endpoints. |
| T2-54 | Python SDK and MCP additions | T2-53 | `sdk/python`, `p2pc-cli/src/mcp` | §7.8 SDK and MCP, including the upload-directory rule of `p2pc_blob_put` (SI-H2-21). |
| **Closing** | | | | |
| T2-60 | Acceptance suite and docs | all | `tests/acceptance-h2/`, `docs/` | §16, the beta guide, the self-hosting guide, OpenAPI drift. |
| T2-61 | Security pass | all | `docs/security/residual-risks.md`, `SECURITY.md` | §11.5 and §15.2 into the residual risks; internal pentest (AC-H2-11). |

Lanes once T2-01 and T2-02 land:
- server: T2-17 at once (H1 code only); T2-10 → T2-11 (after T2-17, and once O-16 is closed) and T2-12 (both edit
  after T2-10's principal storage) → T2-13 → T2-14 → T2-15 (after T2-16 and T2-50 too); T2-12 → T2-16, beside T2-13
  and T2-14;
- agent: T2-20 → T2-21 → T2-23; T2-22 after T2-21 once O-16 is closed (the hard-rule change, §4.3). Until then the
  templates cannot keep their models (both use volumes), so the beta needs O-16 closed;
- device and web: T2-30 → T2-31 → T2-32 / T2-33 → T2-34;
- desktop: T2-40 and T2-42 start at once (no proto dependency); T2-41 once O-16 is closed (the listening exception,
  §4.3) → T2-43 → T2-44 → T2-45;
- infrastructure and clients: T2-53 → T2-54; T2-51 after E12; T2-50 after E11; T2-52 last.

Critical path **(H)**: T2-00 (1 d) → T2-01/T2-02 (3 d) → T2-10 (3 d) → T2-11 or T2-12 (3 d) → T2-13 (3 d) → T2-14
(3 d) → T2-15 (2 d) → T2-60 (3 d), about 21 working days plus review rounds; T2-16 (after T2-12) runs beside T2-13 and
T2-14 and must land before T2-15. The desktop lane (T2-40 → T2-45) is about 14 days and runs beside it. T2-11 and T2-41
wait for O-16, so this path holds only if E11 and the architect's acceptance close O-16 before T2-10 lands (about day
7) **(H)**. That is consistent with a beta in 4-6 weeks only if E9, E10 and E11 pass without a design change.

## 18. Open items and experiments

### 18.1 Experiments

| Experiment | What to measure | Pass | Fail means |
|---|---|---|---|
| **E9** · iroh WASM in mobile Safari and Chrome Android | WASM size (target ≤ 3 MB compressed **(H)**); pairing through the browser; relay-only connection through n0 and through a plain-HTTP `iroh-relay` behind a TLS PaaS; connect time (p50/p95); chat stream overhead per token; 50 MB upload time on 4G; what happens when the tab goes to the background (how long until the WebSocket drops, reconnect time on return); key persistence across browser restart; iOS Safari vs home-screen storage isolation and Android tab → installed app; hyper's HTTP/1.1 client over an iroh stream in WASM; whether iroh can use a non-extractable WebCrypto key. | Pairing and a streamed chat work on both phones; reconnect ≤ 5 s after returning; 50 MB upload ≤ 2 min on 4G through our relay **(H)**. | A native shell (for example Capacitor) around the same web app, or WebTransport; the spec changes §9 before T2-30. |
| **E10** · Tauri 2 first run on a clean Windows 11 VM | Time to ready with and without WSL; reboots; UAC prompts; the `wsl --install --no-distribution` path (inbox, Store, already present, too old); SmartScreen and Defender behaviour on the unsigned installer; WebView2 presence; whether the hub's REST is reachable on Windows' loopback through `localhostForwarding`, and never from the LAN; the Windows firewall prompt on the app's first iroh (UDP) bind, for the device endpoint, and what each answer changes; whether the invite listener works relay-only with `direct_addresses = "none"`, with no IP transport (§5.4; if not, this spec and ADR-016 are amended before O-16); whether the hub's UDP sockets get any unsolicited packet from the LAN under NAT networking, and under mirrored networking whether the Hyper-V firewall drops it (§10.5); sleep and resume; the uninstall inventory. | AC-H2-1 targets met: ≤ 5 min (reboot excluded), ≤ 1 reboot, ≤ 1 UAC. | Revisit step order, bundling the image in the installer, or the WSL install path. |
| **E11** · GPU service in Podman inside the WSL2 distro | Ollama and whisper.cpp image sizes on disk (they fix the image allowance `I` of §8.2) and pull time; start to healthy with cached image and model; GPU visible (CUDA, not CPU fallback); the port reachable only through the ingress bridge; model download size, time and **the exact hosts** the egress allowlist needs (Ollama's registry and its CDN; Hugging Face for whisper models); Ollama through `HTTPS_PROXY`; `:U` vs `:idmap` on a model volume; **whether `:U` follows symbolic links** (a link planted in the volume to a file and to a directory outside it, then a remount: the targets' owners must not change), and that the template images write no symlinks, FIFOs or hard links into their volumes (§11.3); VRAM and tokens/s of candidate default models; whisper.cpp speed on a 30-minute file; that the images load only GGUF. Its volume measurements run in a throwaway `spikes/` directory, never in product code (§17), and feed the decision of O-16. | Healthy ≤ 60 s with cached model **(H)**; downloads work through the egress proxy; no port reachable except through the bridge. | Change the template's image, model or command; a pre-pull step by the agent. |
| **E12** · relay map (proposed by this spec) | `iroh-relay` in plain-HTTP mode on Railway with native and browser clients; home-relay selection with a mixed map (our HTTP relay plus n0's relays); QUIC address discovery through n0 while relaying through ours; the egress gate opening on a WSL2 node with the production map; whether the hub's endpoint can drop and re-add `p2pc/pair/1` from its accepted ALPNs at run time (§10.5); relay throughput and cost per GB on the PaaS. | AC-H2-13 passes. | A relay on a host with UDP (and TLS) for production, or n0's paid relays. |

### 18.2 Open items

| ID | Question | Who decides | Default in this spec |
|---|---|---|---|
| O-1 | Windows code signing: entity, certificate type or signing service, cost. | Owner | Unsigned beta; signing required before public H2. |
| O-2 | Official domain and origin of the web app and relay. | Owner | `<web app origin>`, `relay.<domain>` placeholders. |
| O-3 | Relay hosting plan, budget and abuse limits. | Owner (money) | n0 relays for the beta; Railway for the official deployment. |
| O-4 | Should a join token created by a phone (`nodes:join`) need approval on the hub PC before the node gets work? | Architect | **Closed (spec v1): yes.** The default phone profile has no `nodes:join` (it opens join requests with `nodes:invite`, approved on the hub PC); `nodes:join` stays in the opt-in developer device profile, and every node enrolled with a token minted by a non-`admin` principal starts `pending_approval` (§5.4, §5.5, SI-H2-19). |
| O-5 | Default chat model and license review of template images and models. | Architect; owner for legal | An Apache-2.0 or MIT model of ≤ ~4 B parameters, chosen in E11. |
| O-6 | Direct device → node connections for service traffic. | Architect | H3. |
| O-7 | Opening a service's own web UI in the phone (service-worker proxy over iroh). | Architect | H3. |
| O-8 | Restarting a crashed service in place. | Architect | Not in H2. |
| O-9 | App-level unlock on the phone (PIN, passkey). | Architect | H3. |
| O-10 | Running the node and hub with no signed-in user. | Architect | Not in H2 (§8.5). |
| O-11 | Resumable uploads. | Architect | Not in H2. |
| O-12 | Hub backup, export and migration to another PC. | Architect | H3. |
| O-13 | UI languages of the beta. | Owner | English; strings externalized. |
| O-14 | Privacy notice: what the relay and static host see; the GDPR role of the project. | Owner (legal) | Required before public release. |
| O-15 | Windows 10 support in the app. | Owner | Not in the beta. |
| O-16 | Putting the two proposed hard-rule exceptions of §4.3 in force: persistent volumes (ADR-015) and inbound iroh connections on the hub PC (ADR-016, §10.5). | Architect | **Open.** ADR-015 and ADR-016 are Proposed. When the architect accepts this spec after E11, one separate change amends CONTRIBUTING hard rule 3 and H1 §9's "Never" line, and hard rule 4 and H1 §10, together, and marks ADR-015 and ADR-016 Accepted. Until then those rules stand, no code mounts a volume or makes a P2PC process on a node PC accept an inbound connection, and T2-22, T2-11, T2-41, T2-43 and T2-44 are blocked (§17); the beta needs it, because both templates keep their models in volumes and the hub runs on the hub PC. |

## 19. Sources

External facts used above. Retrieved on 2026-11-10.

- **[S1]** iroh documentation, "WebAssembly and Browsers": <https://docs.iroh.computer/languages/wasm-browser>.
  Browser connections are relay-only and end-to-end encrypted; build with `default-features = false`.
- **[S2]** `iroh-relay` server configuration: <https://docs.rs/iroh-relay/latest/iroh_relay/server/struct.RelayConfig.html>
  and <https://github.com/n0-computer/iroh/blob/main/iroh-relay/src/main.rs>. Without `tls`, all services on plain
  HTTP; QUIC address discovery requires TLS.
- **[S3]** Railway, "Public networking: specs and limits":
  <https://docs.railway.com/networking/public-networking/specs-and-limits>, and "TCP Proxy":
  <https://docs.railway.com/networking/tcp-proxy>. HTTP/1.1 and HTTP/2, WebSockets over HTTP/1.1, idle HTTP/1.1
  connections closed after 60 s (not WebSockets); raw TCP through the TCP proxy; no UDP offered.
- **[S4]** Tauri 2, "Windows Installer": <https://v2.tauri.app/distribute/windows-installer/>. Per-user install by
  default, no administrator rights, `%LOCALAPPDATA%`; WebView2 install modes.
- **[S5]** Tauri 2, "Updater" plugin: <https://v2.tauri.app/plugin/updater/>. Mandatory signatures, `pubkey`,
  `endpoints`, Windows `installMode` (`passive`).
- **[S6]** Microsoft Learn, "Install WSL": <https://learn.microsoft.com/en-us/windows/wsl/install>. `wsl --install` needs
  an administrator prompt and a restart.
- **[S7]** Microsoft Learn, "Advanced settings configuration in WSL":
  <https://learn.microsoft.com/en-us/windows/wsl/wsl-config>. `memory` defaults to 50 % of the host's memory;
  `localhostForwarding` defaults to true.
- **[S8]** Tauri 2, "Content Security Policy": <https://v2.tauri.app/security/csp/>, and "Capabilities":
  <https://v2.tauri.app/security/capabilities/>.
- **[S9]** WebKit, "Tracking Prevention in WebKit": <https://webkit.org/tracking-prevention/>. 7-day cap on
  script-writable storage; home-screen web apps exempt, with storage isolated from Safari.
- **[S10]** "Ed25519 Support Lands in Chrome" (Igalia, 2025):
  <https://blogs.igalia.com/jfernandez/2025/08/25/ed25519-support-lands-in-chrome-what-it-means-for-developers-and-the-web/>.
  Ed25519 in WebCrypto in Chrome 137, Firefox 129 and Safari 17.
- **[S11]** Tauri, `tauri-cli` 2.12.0 release notes: <https://v2.tauri.app/release/tauri-cli/v2.12.0/>. The update
  endpoint response is not signed; the version is recorded in the signature's trusted comment;
  `requireSignedVersion`.
- **[S12]** Ollama FAQ: <https://docs.ollama.com/faq>. `OLLAMA_HOST`; `HTTPS_PROXY` for model downloads. License (MIT):
  <https://github.com/ollama/ollama/blob/main/LICENSE>.
- **[S13]** whisper.cpp (MIT): <https://github.com/ggml-org/whisper.cpp>. Images `ghcr.io/ggml-org/whisper.cpp:main`
  and `main-cuda`, with `ffmpeg` included.

Internal references: the H1 spec (`docs/specs/H1-personal-cloud.md`), its experiments E1 (WSL2 isolation) and E4 (iroh
paths and relay figures) as summarized there, `deploy/README.md`, and `docs/security/residual-risks.md`.
