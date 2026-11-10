# Milestone 2 · P2PC Desktop App and Phone Access (v0.2): specification

- **Status:** draft for review (spec v0, 2026-11-10). Implementation starts when the architect marks it accepted.
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
  she scans it with her already-paired phone, checks that both screens show the same 4-word check phrase, and taps
  "Join" on the laptop. No token is typed. (Without a phone, she can paste an invite text instead, §5.4.)
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
  container images and model files, the scheduled task, the app's files and registry entries. Uninstalling a joined
  PC also removes it from the cloud. Uninstalling the hub PC warns that this deletes the cloud.
- **U11 · Updates.** The app updates itself from signed releases, and updates the distro (agent, hub, image) after it.
  Ana is told before a running chat or job is interrupted.
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
- **Telemetry.** The app, the web app and the hub send nothing to the P2PC project. Crash and diagnostic data stay on
  the PC unless the user exports them.

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
    (§8.5). The hub's state lives in `/var/lib/p2pc-server` inside the distro. The Windows host gets no service, no
    open port and no firewall rule.
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

**Stays exactly as in H1:** the agent control-stream framing and limits, leases, epochs and fencing, the two-sided
liveness rule (SI-13), the scheduler's fit and offer-cap rules, the sandbox's fixed arguments (extended only), the
egress proxy and its deny ranges, API keys, join tokens, the audit table, the REST error format, the CLI exit codes, the
MCP server, and every existing endpoint's request and response shape. The Linux installers are unchanged.

**Changes (all additive unless marked):**

| Area | Change | Section |
|---|---|---|
| JobSpec | `kind` (`batch` default, `service`), `service` block, `volumes`, blob `inputs`, `template` (read-only). Old clients send none of them and get H1 behaviour. | §7.1 |
| Job states | Unchanged words. A service's `running` adds `health` (`starting`, `healthy`, `unhealthy`). Stopping a service ends it `cancelled` with a `reason`. | §7.2 |
| Principals | A request is authenticated by an API key **or** by a paired device. Every place that reads `key_id` reads a `principal` that is one of the two. | §5.5 |
| Scopes | New: `services:connect`, `templates:launch`, `blobs:write`, `nodes:join`. `admin` covers them. | §5.5 |
| Agent protocol | New messages and server-opened streams behind the agent capabilities `service_jobs`, `volumes`, `blob_inputs`, `leave` in `Hello.features`. No new ALPN. | §6.1 |
| New ALPNs | `p2pc/pair/1` and `p2pc/device/1` on the hub; `p2pc/invite/1` on a joining PC's app. | §6 |
| `init` | `p2pc-server init --owner-device <NodeId>` registers a device instead of printing an API key (the H1 form still works). New offline command `p2pc-server devices add`. | §5.3 |
| Usage ledger | Rows gain `device_id` (nullable), `kind`, `template_id` and the slice bounds; long attempts are split at UTC midnight. | §12 |
| WSL image | Ships `p2pc-server`; `p2pc-node-run` becomes `p2pc-run` (agent, and hub when enabled); the upgrade carries `/var/lib/p2pc-server` too. | §8.5 |
| Agent config | Share limits can change at run time (`p2pc-agent share set`), sent as `InventoryUpdate`. | §8.2 |
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

- **Created by** `POST /v1/devices/pairing-tickets` (`admin` scope). Body: `{label?, scopes?, expires_in_s?}`. The
  default scopes are the **phone profile** (§5.5). `expires_in_s` defaults to 600 and is at most 3,600.
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
  the same answer again. Any other NodeId gets `invalid_ticket`.
- **Listing and revoking.** `GET /v1/devices/pairing-tickets` and `DELETE /v1/devices/pairing-tickets/{id}` (`admin`),
  like join tokens. The desktop app revokes the ticket it showed when its QR screen closes.
- **Audit.** `pairing_ticket_created`, `device_paired`, `pairing_ticket_revoked`, `device_revoked`, failed pairings
  aggregated per minute (H1 §5 "Audit" rules).

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

**Before pairing** the hub accepts `p2pc/pair/1` from any NodeId, so it is unauthenticated surface. It gets the H1 §6
"Before `Join`" limits, counted **separately** from the agent ALPN: at most 32 connections at once and 8 pending
`Pair`s; one `Pair` per connection, within 10 s; failed pairings limited to 10 a minute per NodeId and 30 a minute in
total; a frame limit of 4 KiB. Beyond these limits the connection closes with no detail.

**Who creates the owner's first device.** `p2pc-server init --owner-device <NodeId> [--label <text>]` creates the
account, the default project and an **owner device** with the `admin` scope, and prints no API key. The desktop app
generates its own device key first and passes its public NodeId. `p2pc-server devices add --data-dir <dir> --node-id
<NodeId> --scopes <list> --label <text>` does the same offline later (local data-dir access, audited as
`device_added_offline`, the H1 `keys recover` pattern). Plain `p2pc-server init` keeps its H1 behaviour.

### 5.4 Joining another PC (invites)

The H1 join token is about 90 base32 characters: too long to type, and a desktop PC often has no camera. A short code
would need a rendezvous service to resolve it, which H2 does not have (D4). So:

- **Primary path: phone-assisted invite.**
  1. The new PC's app starts an **invite listener**: a temporary iroh endpoint in the app with a fresh key, serving
     only ALPN `p2pc/invite/1`. The phone is relay-only, so this connection always goes through a relay.
  2. It shows a QR code: `https://<web app origin>/invite#p2pc_inv_<base32: listener NodeId, relays, 16-byte code,
     expiry (10 min)>`.
  3. The owner scans it with the paired phone. The web app calls `POST /v1/nodes/join-tokens`. H1 reserves that
     endpoint to `admin`; H2 also allows it with the narrow scope **`nodes:join`**, which the phone profile has
     (§5.5), limited to `expires_in_s <= 900`.
  4. The phone dials the listener on `p2pc/invite/1` and sends `Invite{code, join_token, hub_name}`. The app checks the
     code (constant time, single use) and answers `InviteAck{}`.
  5. Both screens show a **check phrase**: 4 words from a fixed 2,048-word list, derived from
     `BLAKE3("p2pc-invite-v1" || hub NodeId || listener NodeId || code)`. The owner taps "Join" on the PC only if they
     match. This defeats someone who photographed the QR and pushes their own hub's token: the PC would otherwise join
     a stranger's cloud and run the stranger's jobs (H1 SI-1 protects the owner of the cloud, not a node joined to the
     wrong cloud).
  6. The app feeds the join token to `p2pc-agent join -` through stdin (H1 §7 CLI conventions) and closes the
     listener.
- **Fallback: invite text.** The hub PC's app shows "Copy invite": the H1 join token as text (15 min, single use),
  for the owner to carry by any private channel; the new PC's app has a "Paste invite" field. The text never goes on a
  command line (H1 §7). The app shows the hub name from the join result and asks for confirmation before the node
  takes leases.
- **Re-joining** a PC that is already a live node (reinstall without uninstall) follows H1 §5 "Re-enrolling the same
  machine": same node id.

### 5.5 Principals and scopes

- **Principal.** Every authenticated request carries a principal: `Key{key_id}` (H1) or `Device{device_id}`. Ownership
  (`account_id`, `project_id`), scopes, caps and image allowlists come from the principal's row. Audit events, the usage
  ledger and `GET /v1/whoami` name the principal (`whoami` gains `principal: {kind, id}`; `key_id` stays, `null` for
  a device).
- **A device principal exists only on `p2pc/device/1`.** Requests on the TCP REST listener and on `p2pc/http/1` are
  authenticated by API key only. No header can turn a request into a device request (SI-H2-3): device requests are
  served in-process with the principal attached as a request extension, never relayed to the TCP listener.
- **New scopes:** `services:connect` (open a service port, §7.4), `templates:launch` (§7.6), `blobs:write` (§7.5),
  `nodes:join` (create a join token valid at most 15 minutes, §5.4). `admin` covers all of them. `jobs:write` already
  allows services and blob inputs.
- **Profiles** (presets for the UI; the API takes scope lists):

  | Profile | Scopes | Used by |
  |---|---|---|
  | Owner | `admin` | The desktop app on the hub PC (created by `init --owner-device`). |
  | Phone (default) | `jobs:read`, `nodes:read`, `templates:launch`, `services:connect`, `blobs:write`, `nodes:join` | Phones and browsers paired from the app. |
  | Developer device | Phone + `jobs:write` | Opt-in in the app's pairing screen ("allow running any container"). |

  The default phone profile cannot submit arbitrary JobSpecs: a stolen, unlocked phone or an XSS in the web app can
  launch only vetted templates (§7.6), read job state and open services. That bounds what an attacker with a device
  key can run on the owner's PCs.
- **No escalation** (H1 §5) applies to devices: a pairing ticket's scopes, cap and expiry are a subset of its
  creator's. Only `admin` principals create pairing tickets in H2.
- **Revocation.** `DELETE /v1/devices/{id}` (`admin`) sets `revoked_at`, closes every live `p2pc/device/1` connection of
  that NodeId and every service stream it opened, within 5 s (SI-H2-4). A device can revoke itself ("Forget this
  cloud" in the web app). The hub refuses to revoke the last live unrestricted `admin` principal, device or key, with
  `409 last_admin` (H1 "Last admin key", extended to devices). The offline `devices add` and `keys recover` remain the
  way back.
- **Unknown or revoked device.** A `p2pc/device/1` connection from a NodeId that is not a live device gets the same
  close code (`not_paired`) whether it was never paired, revoked or belongs to nothing. Revoked rows are kept.
- **`last_seen_at`** is written at most once a minute, as H1 `last_used_at`.
- **Nodes enrolled by a phone.** A node row records `enrolled_by` (the principal that created its join token). When
  that principal is not `admin`, the desktop app on the hub PC shows "New PC joined: <name>, added from <device>",
  and revoking a device offers "also remove the PCs this device added". A stolen phone can therefore enroll a machine
  that the thief controls, and that machine could receive the owner's template jobs until the owner notices; §15.2
  records this residual risk and open item O-4 asks whether the beta should require approval on the hub PC instead.

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

**New agent → hub messages:**
- `ServiceHealth{lease_id, epoch, state:"starting"|"healthy"|"unhealthy", since, detail?}`: sent on every change of
  the health state of a service lease, and repeated in each `Heartbeat` as `running[].health`.
- `VolumeReport{volumes:[{name, size_mb, last_used_at, in_use_by?}]}`: after `Hello` and every 10 minutes, and when a
  lease that mounted a volume ends.
- `Leave{reason}`: "remove me". The hub deletes the node as `DELETE /v1/nodes/{id}` would, audits `node_left`, closes
  the connection and answers nothing. The agent then exits with code 7 (H1 "removed from the server"), so H1's terminal
  stop rules switch off its supervisor. Sent by `p2pc-agent leave`, which the app runs on uninstall (§8.7).

**Changed agent → hub messages (additive):** `Heartbeat.running[]` gains `health` for service leases and, at most once a
minute, `used_cpu_ms` (cumulative, from the lease cgroup) for service leases, used by the daily split (§12).
`Inventory` gains `volumes_mb` (the disk share for volumes, apart from `offered.disk_mb`, §11.3) and `owner_paused`
(bool, §8.4): while it is true the scheduler treats the node as draining, and the agent rejects new leases with
`draining`. Both come with `share_update`; an agent without it sends neither.

**New hub → agent messages:**
- `Lease` is unchanged in shape. Its `job` now may carry `kind`, `service`, `volumes` and blob `inputs` (§7.1). An
  agent that does not declare the capability never receives such a lease; if one arrives anyway it answers
  `LeaseRejected{reason:"invalid_job"}` (H1 "must understand").
- `Cancel{lease_id, epoch, reason}` gains reasons `stopped`, `idle_timeout` and `health_check_failed` (informative;
  the agent's behaviour is the H1 cancel sequence).
- `VolumeDelete{name}`: delete a node-local volume that no lease uses. The agent answers with a fresh `VolumeReport`.

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
  streams are **not** timed out by the hub (a chat may idle for minutes); the service's `idle_timeout_s` (§7.1) ends
  the whole service instead.
- **Blob integrity.** The agent hashes what it receives and refuses a mismatch (`error="input_integrity"`, a
  `start_failed`-class error, H1 §9 "Podman failures are not job exits").

### 6.2 Pairing and invite messages

`p2pc/pair/1`: `Pair{ticket, label, platform}`, `Paired{…}`, `PairError{code}` (§5.3). `p2pc/invite/1`:
`Invite{code, join_token, hub_name}`, `InviteAck{}`, `InviteError{code}` (`invalid_code`, `expired`). One exchange per
connection, frame limit 4 KiB, 10 s deadline.

### 6.3 Device protocol (ALPN `p2pc/device/1`)

- **Each bidirectional stream carries one HTTP/1.1 connection** to the hub's REST API, served **in-process** by the same
  axum router as the TCP listener, with `Principal::Device` attached. Keep-alive is allowed; HTTP/2 is not used.
- A request on a device stream that carries an `Authorization` header gets `400 unexpected_authorization`: mixing two
  principals on one request is refused, so a confused client cannot run as an API key over a device connection.
- **Same limits as the REST listener** (H1 §10 "Slow clients": 10 s headers, 30 s body and request, 60 s keep-alive
  idle; streaming routes and port connections excluded), plus: at most 32 concurrent streams per device connection and
  2 connections per device NodeId; device streams count against their own budget (default 96), which with the H1
  tunnel budget stays **below** the REST connection cap. The hub refuses to start with a config that breaks this.
- **The hub checks the device at connection time and on every request.** A revocation is seen at the next request,
  and the hub also closes the connection actively (§5.5).
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
  "timeout_s": null,
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

**Validation** (in `p2pc-proto`, unit-tested; H1 rules unchanged for every existing field):

| Field | Rule |
|---|---|
| `kind` | `"batch"` (default) or `"service"`. |
| `timeout_s` | `batch`: H1 (1-86,400, default 3,600). `service`: `null` (until stopped, the default) or 60-2,592,000 (30 days). A principal with a `daily_unit_cap` MUST give a `timeout_s` of at most 86,400 for a service, so that its estimate is finite (§12). |
| `service` | Required when `kind = "service"`, forbidden otherwise. |
| `service.ports` | 1-8 entries. `port` 1-65,535, unique; `name` `[a-z][a-z0-9-]{0,31}`, unique. The shim refuses to forward any port not listed (§11.2). |
| `service.health` | Optional. Exactly one of `http_get` (an absolute path, at most 256 bytes, no `..`, no CR/LF/NUL) or `tcp: true`; `port` must be in `ports`. `interval_s` 2-300 (default 10), `timeout_s` 1-60 (default 3), `start_period_s` 0-3,600 (default 300), `failure_threshold` 1-20 (default 3). Without `health`, the service is `healthy` as soon as a connection to its first port succeeds through the bridge. |
| `service.idle_timeout_s` | `null` (never) or 300-604,800. Default 3,600. Idle = no open port connection and no byte forwarded for that long, measured by the hub (§7.4). |
| `service.restart` | `"never"` or `"on_node_loss"` (default). See §7.2. |
| `volumes` | 0-4 entries. `name`: `[a-z0-9][a-z0-9._-]{0,62}`, or `tpl:<template id>/<name>`, which only a template launch may use (SI-H2-9). `mount`: absolute, under `/volumes/`, no `..`, not a prefix of another mount. `max_mb`: 64-262,144. Two entries may not share a name. |
| `inputs` | 0-32 entries `{path, blob}`. `path` follows the `files` path rules (under `/inputs`, no `..`, no path a directory of another, no clash with `files`). `blob` is `sha256:<64 lowercase hex>` and must exist in the caller's account when the job is created (`422 unknown_blob`). The sum of blob sizes and inline `files` must fit in `resources.disk_mb` minus 64 MiB (`422 inputs_exceed_disk`). |
| `template` | Read-only. Set by `POST /v1/templates/{id}/launch` (`{id, version}`); a client that sends it gets `422 read_only_field`. |
| `resources.gpu` | 0 or 1, as H1. |
| `idempotency_key` | H1 rules. |

The Lease frame limit (1 MiB, H1 §6) still applies to the whole job; blob inputs do not count, inline `files` do.

### 7.2 Service lifecycle and states

- **States.** The H1 words are kept: `queued → assigned → running → {succeeded | failed | timed_out | cancelled | lost}`.
  A running service adds `service.health`: `starting` (from `JobStarted` until the first passing check, at most
  `start_period_s`), `healthy`, or `unhealthy` (the last `failure_threshold` checks failed).
- **Ends of a service:**
  - stopped by a principal → `cancelled`, `reason: "stopped"`;
  - idle for `idle_timeout_s` → `cancelled`, `reason: "idle_timeout"`;
  - `timeout_s` reached → `timed_out`;
  - still `starting` after `start_period_s`, or `unhealthy` for `failure_threshold` consecutive checks after it was
    healthy → the agent stops it (H1 cancel sequence) → `failed`, `error: "health_check_failed"`;
  - the process exits by itself → `succeeded` (code 0) or `failed`. H2 never restarts a service in place; that is
    O-8;
  - node loss → see restart.
- **Restart on node loss.** With `restart: "on_node_loss"`, a service whose node is lost is requeued like an H1 batch
  job, with one difference: `retry.max_attempts` (1-5, default 3 for services) counts **consecutive attempts that never
  became healthy**. An attempt that was `healthy` for at least 10 minutes resets the count. A gaming PC that sleeps every
  night therefore brings its chat back every morning, while a service that crashes the node at start stops after 3
  tries. With `"never"`, the first node loss ends the job `lost`.
- **Waiting for the same node.** A requeued service with a volume prefers the node that holds the volume (§11.3): when
  that node is eligible but offline or busy, the scheduler waits up to `volume_affinity_wait_s` (default 900 s) before
  placing it elsewhere with an empty volume. `reason` says so while it waits.
- **Who can stop a service.** `POST /v1/jobs/{id}/cancel` needs `jobs:write`, **or** `templates:launch` when the job was
  launched from a template by the same principal.
- **`GET /v1/jobs/{id}`** adds, for services, `service: {health, health_since, ports:[{port, name}], open_connections,
  last_activity_at, idle_deadline}`; `idle_deadline` is `null` while a connection is open or when
  `idle_timeout_s` is `null`. `GET /v1/jobs` gains the filter `kind`.

### 7.3 Endpoints added

| Method and path | Scope | Notes |
|---|---|---|
| `POST /v1/jobs/{id}/ports/{port}/connect` | services:connect | HTTP/1.1 upgrade to a raw byte stream into the service (§7.4). |
| `POST /v1/blobs` | blobs:write | Upload one blob (§7.5). |
| `HEAD /v1/blobs/{sha256}` | blobs:write or jobs:read | `200` with `Content-Length` if the caller's account has it, else `404`. |
| `GET /v1/blobs` | jobs:read | `{sha256, size, created_at, referenced_by, expires_at}`, cursor pagination. |
| `DELETE /v1/blobs/{sha256}` | blobs:write | `409 blob_in_use` while a non-terminal job references it. |
| `GET /v1/volumes` | nodes:read | `{name, node_id, size_mb, max_mb, last_used_at, in_use_by}` from the latest `VolumeReport`s. |
| `DELETE /v1/volumes/{node_id}/{name}` | admin | Sends `VolumeDelete`. `409 volume_in_use`; `503 node_offline` (the deletion is not queued). |
| `GET /v1/templates` | jobs:read or templates:launch | The loaded template bundle (§7.6), with `bundle_version`. |
| `POST /v1/templates/{id}/launch` | templates:launch | `{params, idempotency_key?}` → `201` with `Job`, or `200` with the running instance of a `singleton` template. |
| `POST /v1/devices/pairing-tickets`, `GET …`, `DELETE …/{id}` | admin | §5.2. `POST` returns `{ticket, url, expires_at}` once. |
| `GET /v1/devices`, `GET /v1/devices/{id}` | admin, or the device itself | `{id, label, platform, scopes, created_at, last_seen_at, revoked_at, paired_by}`. |
| `DELETE /v1/devices/{id}` | admin, or the device itself | Revoke (§5.5). |
| `POST /v1/nodes/join-tokens` | admin, or nodes:join | H1, plus `nodes:join` with `expires_in_s <= 900` (§5.4). |
| `GET /v1/server` | any principal | H1 fields plus `api_version` (integer, 2 for H2), `min_web_version`, `hub_name`. |
| `PATCH /v1/server` | admin | `{hub_name}` (1-64 printable characters). |

No endpoint returns blob contents: the hub is not a file store.

### 7.4 Service ports

- **Request.** `POST /v1/jobs/{id}/ports/{port}/connect` with `Connection: Upgrade` and `Upgrade: p2pc-port/1`, no body.
  On success the hub answers `101 Switching Protocols` and the connection becomes a raw, bidirectional byte stream to
  `127.0.0.1:<port>` inside the service's container.
- **Errors before the upgrade:** `404` (unknown job, or not visible to the principal), `409 service_not_running`,
  `409 service_not_ready` (health is `starting`; `?wait_ready=true` waits up to 30 s instead),
  `422 port_not_exposed`, `429 too_many_connections`, `502 node_unreachable` (the hub could not open the stream or the
  agent answered `PortOpenAck{ok:false}`; the agent's `reason` is in `detail`).
- **The same endpoint serves every client:** devices over `p2pc/device/1`, API keys over TCP REST or `p2pc/http/1`
  (H1 tunnel) and behind a TLS reverse proxy that passes upgrades. One code path, one authorization check
  (SI-H2-5).
- **Limits.** The upgraded connection leaves the H1 whole-request limit; it has no idle limit of its own (§6.1). At most
  64 open connections per service and 16 per principal per service. Bytes are counted per service per UTC day
  (§12), never logged.
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
- **Checks before reading the body:** `Content-Length <= max_blob_mb` (default 2,048 MiB, `413 too_large`); then,
  with `checked_add`, the account's stored bytes plus in-flight reservations plus this size `<= blobs_quota_mb`
  (default 20,480 MiB, `507 quota_exceeded`). The reservation is taken in the same short transaction and released on
  every exit path.
- **Writing.** The body streams to `<data>/blobs/staging/<random>` while hashing. A short body, a hash mismatch
  (`422 digest_mismatch`) or a broken connection deletes the staging file. On success: `fsync`, rename to
  `<data>/blobs/sha256/<aa>/<bb>/<hex>`, then insert the row (two short transactions with no I/O under the write
  lock; the H1 rule).
- **Timeouts.** The upload route leaves the 30 s body limit; it has a 60 s idle limit instead, and a floor of 16 KiB/s
  averaged over any 60 s window. An upload of 2 GiB at 9 Mbit/s (E4's relay figure) takes about 30 minutes **(H)**:
  allowed, but the web app warns above 200 MiB.
- **Namespacing.** Blobs are content-addressed **per account**: deduplication never crosses accounts, and `HEAD` in one
  account says nothing about another (SI-H2-8).
- **Lifetime.** A blob expires 24 h after it was uploaded or after the last job that references it became terminal,
  whichever is later, plus the artifact retention when a job references it (H1 §12, 7 days). A non-terminal job keeps
  it alive. GC follows H1's retry-queue rule (`ORDER BY last_attempt_at`) and deletes the file before the row.
- **Delivery to a node** is the `BlobFetch` stream (§6.1), into the job's `inputs/` directory, read-only in the
  container like inline files.

### 7.6 Templates

- **A template** is a vetted JobSpec plus a UI entry. It is data: `templates/<id>.toml` in the repository, reviewed like
  code. Fields: `id`, `version`, `title`, `description`, `kind`, `ui` (`chat`, `transcribe` or `none`), `singleton`
  (bool), `requirements` (`gpu = "required" | "preferred" | "none"`, `min_vram_mb`), `params` (typed: `enum` with
  values, `int` with bounds, `bool`), `resources` (default, min and max), the `spec` (a JobSpec), `licenses` (the image
  and model licenses, shown in the UI), and `download_mb` (an estimate of the first-run download, shown before launch).
- **Rules every template MUST meet** (checked by a test over the whole bundle):
  - the image is pinned by `@sha256:` digest;
  - parameters reach the job only as **whole env values or whole argv elements**, never interpolated into a shell
    string or a path; enum values come from the template;
  - egress is a fixed list in the template; volumes use the `tpl:<id>/` namespace;
  - every field passes the normal JobSpec validation.
- **Bundle.** CI compiles `templates/*.toml` into `templates.json` and signs it with the release key (minisign,
  §5.1). The hub embeds the bundle of its own release. It may load a newer bundle from `<data>/templates/` (put there
  by the desktop app's updater, §14), only if the signature verifies against the embedded public key, its
  `bundle_version` is higher than the embedded one and its `min_hub_version` is at most the hub's version. Otherwise it
  logs why and keeps the embedded bundle. This lets a security fix move an image digest without a hub release.
- **Launch.** `POST /v1/templates/{id}/launch` validates `params` against the template (unknown parameter → `422`),
  builds the JobSpec, sets `template: {id, version}` and creates the job with the caller as principal. Caps, image
  allowlists and placement apply as for any job. For a `singleton` template, a launch while an instance is `queued`,
  `assigned` or `running` returns that instance (`200`).
- **Placement hints.** `requirements.gpu = "preferred"` launches with `gpu: 1` when the account has an eligible GPU
  node and with `gpu: 0` otherwise; the UI says "running on CPU: slow".

**Templates shipped with the beta:**

| Template | Kind | What | Status |
|---|---|---|---|
| `private-chat` | service, singleton, `ui = "chat"` | Ollama (MIT [S12]) with its API on port 11434, models in `tpl:private-chat/models` (20 GiB cap), `idle_timeout_s` a parameter (15 min to 24 h, default 1 h). Parameter `model`: an enum of small models whose licenses allow this use; default **a model of at most ~4 B parameters with an Apache-2.0 or MIT license (H)**, chosen in E11 by quality, size (about 2.5 GB **(H)**) and VRAM (fits 6 GB **(H)**). Ollama follows `HTTPS_PROXY` for downloads [S12], which the shim sets (H1 §9). | E11 pins the image digest, the model list and the egress hosts. |
| `transcribe` | batch, `ui = "transcribe"` | whisper.cpp (MIT; upstream publishes `ghcr.io/ggml-org/whisper.cpp:main-cuda` with ffmpeg included [S13]) with a fixed script (`/inputs/.template/transcribe.sh`, shipped as an inline `files` entry of the template, so it is read-only in the container): convert the input with ffmpeg, run the model, write `transcript.txt`, `.srt` and `.vtt` to `/outputs`. Parameters: `language` (enum, default `auto`), `model` (`base`, `small` default, `medium`). Models in `tpl:transcribe/models` (5 GiB cap). | E11 chooses the image (an upstream image with ffmpeg and CUDA, or our own build published by digest) and the model download hosts. |

The chat UI is part of the web app (§9.4): it talks to Ollama's HTTP API (`/api/tags`, `/api/pull` with streamed
progress, `/api/chat` with `stream: true`) through §7.4. Nothing of a third-party web UI is loaded into the phone.

### 7.7 Errors added

`invalid_ticket`, `not_paired`, `unexpected_authorization`, `last_admin`, `service_not_running`, `service_not_ready`,
`port_not_exposed`, `too_many_connections`, `node_unreachable`, `unknown_blob`, `inputs_exceed_disk`,
`digest_mismatch`, `quota_exceeded`, `blob_in_use`, `volume_in_use`, `node_offline`, `read_only_field`,
`unknown_template`, `invalid_params`. Every one is in the OpenAPI document with its HTTP status.

### 7.8 Clients (CLI, SDK, MCP)

Additive. H1 client rules (credentials, retries of idempotent calls only, outage tracking, exit codes, escaping job
output) apply to every new command.

- **CLI.**
  - `p2pc service run [--port <p>[:<name>]]… [--health-http <path> | --health-tcp] [--idle <dur>|--no-idle]
    [--restart never|on-node-loss] [--volume <name>:<mount>[:<size>]]… <run options> -- <command>`: prints the job
    ID; `--wait-ready` waits for `healthy`.
  - `p2pc service connect <job> --port <p> [--listen <addr>]`: a long-running local forwarder. It exits when the
    service becomes terminal: 0 for `cancelled` or `succeeded`, otherwise the H1 code of that outcome (75 lost, 124
    timed out, the exit code or 125 for `failed`). SIGTERM → 0 and Ctrl-C → 130, as `p2pc proxy`.
  - `p2pc service stop <job>` (alias of `cancel`), `p2pc service list`.
  - `p2pc blobs put <file>` (HEAD first; prints the digest), `p2pc blobs ls`, `p2pc blobs rm <digest>`.
  - `p2pc run --input <local file>:<container path>`: uploads the file as a blob (HEAD first) and adds the `inputs`
    entry. Inline `--file` keeps the H1 512 KiB limit.
  - `p2pc templates ls`, `p2pc templates launch <id> [--param k=v]…`.
  - `p2pc devices ls`, `p2pc devices revoke <id>`, `p2pc devices pair [--scopes …]`: prints the pairing URL once, as a
    secret, and a QR code in the terminal when stdout is a TTY.
  - `p2pc volumes ls`, `p2pc volumes rm <node> <name>`.
- **Python SDK.** `client.blobs.put(path)`, `client.jobs.run(..., inputs={"/inputs/x": blob})`,
  `client.services.run(...)`, `client.services.connect(job, port)`, `client.templates.list()/launch(...)`.
- **MCP.** `p2pc_run` accepts `inputs` with blob digests; a new tool `p2pc_blob_put` uploads a local file. No service
  tools in H2.

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
| 1 | **Welcome** | What P2PC does and does not do, in five lines: it runs only what you start, nothing is visible on your network, you can stop or uninstall at any time, no account, no telemetry. "Start". | — |
| 2 | **Checks** | Windows build ≥ 22000 (Windows 10 21H2+ works for H1 but is not supported by the beta app); virtualization on in the firmware; WSL present and ≥ 2.0; WSL default version 2; ≥ 20 GB free on the profile's drive; NVIDIA driver present (warning only). These are `install.ps1`'s checks (H1 deploy README), same thresholds. In the background the node image download starts (§8.3). | 15 s |
| 2a | **Install WSL** (only if missing or too old) | Explains why, then runs `wsl.exe --install --no-distribution` **elevated** (one UAC prompt) [S6]. If the Virtual Machine Platform had to be enabled, asks for the **one reboot** and registers a `HKCU\…\RunOnce` entry so the app reopens at step 2 after it. | 1-2 min + reboot |
| 3 | **Share** | Three controls: CPU cores (1 … the WSL VM's processors), RAM (1 GiB … the WSL VM's memory, which WSL caps at 50 % of the host's RAM by default [S7]; the app never edits `.wslconfig`, H1 §9.0), GPU on/off (only if the node reports an offerable GPU), and one "Disk space for P2PC" control (jobs get `min(50 GiB, half)`, volumes the rest; default 90 GiB, at most free space − 20 GiB). A "Keep this PC awake while sharing" switch (§8.6). Meanwhile the image is verified and imported (`wsl --import … --version 2`). | 30-90 s (import < 1 min, H1 deploy README) |
| 4 | **Create or join** | "Create my cloud" (first PC) or "Join my cloud" (§5.4). Create: writes `hub.enabled`, runs `p2pc-server init --owner-device <the app's device NodeId> --hub-name "My cloud"`, starts the hub, makes a join token over the app's own device connection and joins the local agent through stdin. | 15-30 s |
| 5 | **Add my phone** | A QR code with a pairing ticket (phone profile, 10 min), the web app URL as text, and "Skip for now". Shows "Paired: <platform>" when it happens. | 30-60 s |
| — | **Ready** | "Your cloud is ready", the PC list, the phone list, and (hub PC) the sentence of §8.6. | — |

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
  `localhost:<port>` [S7]; that is acceptable because
  every REST request needs an API key (H1 §10) and devices never use TCP, but it MUST NOT be reachable from the LAN
  (SI-H2-11 tests it from a second machine).
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
   your phone and your other PCs will lose it.") with an explicit checkbox. Cancelling stops the uninstall.
2. **Joined PC:** `p2pc-agent leave` (best effort, 10 s), so the hub drops the node (§6.1).
3. Stop and delete the scheduled task "P2PC node" and its wrapper (H1 `-Uninstall`, exit 37 rule: if the task cannot
   be removed, stop here and tell the user).
4. `wsl --unregister p2pc-node`: deletes the distro, its container images, volumes (model files) and, on the hub, the
   cloud's database and blobs.
5. Delete `%LOCALAPPDATA%\P2PC\` entirely: `wsl\`, `backups\` (every kind, including failed-upgrade backups: the user is
   leaving, and the uninstaller lists them before deleting), `logs\`, `setup.json`, `device.key`.
6. Delete the app's data folders (`%APPDATA%\<app identifier>`, `%LOCALAPPDATA%\<app identifier>` including WebView2's
   `EBWebView`), the `Run` and `RunOnce` values. NSIS removes the install folder and its uninstall registry key.
7. **WSL itself stays installed**: it is part of Windows and may serve other things. The final page says how to remove
   it.

AC-H2-9 checks the result with a before/after inventory of the user profile, `HKCU`, scheduled tasks and `wsl -l -v`.

### 8.8 Errors

| Code | Cause | The app shows | Then |
|---|---|---|---|
| `virtualization_off` | Firmware virtualization disabled | "Turn on virtualization in your PC's firmware settings" and a guide | Stays at step 2 |
| `wsl_install_failed` | `wsl --install` failed or was declined at UAC | The step, the exit code, "Try again" | Stays at 2a |
| `wsl_too_old` | WSL < 2.0 and no update possible | How to update from the Microsoft Store | Stays at 2 |
| `disk_low` | < 20 GB free | How much is needed | Stays at 2 |
| `image_download_failed` / `image_hash_mismatch` | Network, or a corrupt or tampered file | "Try again"; a mismatch is never retried silently | Stays at 3 |
| `import_failed` | `wsl --import` error | WSL's message (sanitized), "Try again" | Stays at 3 |
| `distro_unhealthy` | Boot status or isolation checks fail (H1 `p2pc-test-distro` subset) | Which check | `attention` |
| `hub_unreachable` | Joined PC cannot reach the hub | "Your hub PC is off or offline" | `attention`, retries |
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
| `/invite` | Phone-assisted join of a PC (§5.4): check phrase, then hands over the join token. |
| `/` (home) | Hub name and online state; PCs (name, online, sharing or paused, GPU); running services; shortcuts to the templates. |
| `/chat` | The private chat (§9.4). |
| `/transcribe` | Upload, launch, follow, read the transcript (§9.4). |
| `/jobs` | Read-only list of recent jobs and their state. |
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
  the thief can do until then. A screen lock is the user's first defence; an app-level PIN or passkey unlock is H3
  (O-9).

### 9.4 Template UIs

- **Private chat** (`ui = "chat"`).
  - Start: launches `private-chat` (singleton; launching again returns the running instance), shows `queued` reasons in
    words ("Your GPU PC is off", "The GPU is busy"), then the health state.
  - First run: lists models with `/api/tags`; if the default is missing, calls `/api/pull` and shows its streamed
    progress, with the size from the template (`download_mb`).
  - Chat: `/api/chat` with `stream: true`; tokens appear as they arrive.
  - **History stays on the device** (IndexedDB, encrypted with the same `CryptoKey`), with "Clear history". Nothing of
    the conversation is stored on the hub; the service's own volume holds only model files.
  - Interruptions: if the stream breaks (tab in the background, network change), the partial answer is kept and
    marked "interrupted" with "Retry". Streams are not resumable in H2.
  - "Stop the chat service" cancels the job (allowed by §7.2); otherwise `idle_timeout_s` stops it.
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

1. **Reproducible build.** CI builds `apps/web` with pinned toolchains and publishes, with each release,
   `web-manifest.json`: every file's path and SHA-256, signed with the release key. Anyone can rebuild and compare.
2. **The desktop app verifies the deployed web app** against the manifest of its own release, at start and daily
   ("Verify web app" in Settings): it fetches every listed file from the configured origin and compares hashes. A
   mismatch shows a red warning and offers to revoke the phone devices. This detects untargeted tampering only: a host
   can serve different bytes to different clients.
3. **A self-hosted copy.** The desktop app's `web_app_origin` setting changes the origin that pairing QR codes point
   to. Keys are bound to the origin (browser storage is per origin), so moving means pairing again.
4. **Bounded device power** (§5.5): a stolen device key can launch vetted templates, open services, read job state,
   upload blobs and create 15-minute join tokens. It cannot run arbitrary containers or create pairing tickets. The
   join-token part is the most dangerous and is open item O-4.
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
  mapping, default-route addresses only, no third-party address discovery.
- **Nothing new listens.** The Windows host gets no listening TCP port from P2PC (the app opens none; the hub's REST is
  inside the distro, §8.5). Service ports exist only on the container's loopback (§11.2). On the internet, the
  project's footprint is the static host and the relay. SI-H2-10 and SI-H2-11 test it.

## 11. Sandbox additions

### 11.1 What stays

Every fixed `podman run` argument of H1 §9 applies to services too: `--rm`, `--network=none`, `--cap-drop=all`,
`no-new-privileges`, the pids limit, `--userns=auto` on WSL2, the memory and CPU limits, the per-lease cgroup, the
shim as entrypoint, the egress proxy socket. A service is the same sandbox that lives longer. Inside the WSL2 distro
Podman runs as root of the appliance with `--userns=auto` (H1 §9.0), not as a rootless user; containers are still
unprivileged.

**Added arguments:**
- `-v <volume dir>:<mount>:rw,U` per volume (§11.3). E11 measures whether `:U` (a recursive chown on each mount,
  because `--userns=auto` may pick another range each time) is cheap enough for a model directory, or whether `:idmap`
  replaces it.
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
  `GET <path> HTTP/1.1` with `Host: localhost`, `Connection: close`; any 2xx or 3xx within `timeout_s` passes; for
  `tcp: true`, a status byte 0 passes.
- **Old shims.** An image built before H2 cannot exist: the shim is injected by the agent at run time (H1 §9), so the
  agent and the shim always come from the same release.

### 11.3 Volumes on the node

- **Layout.** `/var/lib/p2pc/volumes/<account_id>/<hex(sha256(name))[..32]>/` with `data/` (mounted) and `meta.json`
  (name, created, last used). Names never become paths directly.
- **One holder at a time.** A volume is mounted by at most one lease; the agent takes an exclusive lock and rejects a
  second lease (`insufficient_capacity`, with the reason logged). The scheduler knows holders from `VolumeReport` and
  does not offer such a lease.
- **Size.** Measured every 60 s with H1's fail-closed disk measurement (larger of apparent and allocated size, entry
  budget, three failures count as over). Over `max_mb` → the lease stops with `error="volume_limit"`.
- **Budget.** `volumes_mb` (the share of §8.2) covers every volume on the node. Placement of a lease needs
  `volumes_mb − Σ max_mb of volumes in use by other leases ≥ max_mb` for each of its volumes. Unused volumes do not
  count: when a new or growing volume needs room, the agent evicts unused volumes, least recently used first. A
  volume whose `max_mb` exceeds `volumes_mb` makes the node ineligible, with a `reason`.
- **Retention.** An unused volume is deleted after `volume_retention_days` (default 30), on `VolumeDelete`, and with
  the distro on uninstall. Under the H1 disk floor the agent evicts unused volumes before it kills jobs.
- **Deletion** walks the tree with `openat(O_NOFOLLOW)` and `unlinkat`, never following a link (SI-H2-9).
- **Namespace.** `tpl:` volumes are created only by template launches (§7.1), so an arbitrary image cannot read or
  plant files in a template's model cache.

### 11.4 Long-running jobs and H1 limits

- **Logs.** A batch attempt keeps H1's 64 MiB cap with a truncation marker. A service keeps the **most recent**
  64 MiB, as a ring of 1 MiB segments on the agent and on the hub; a marker records the dropped range, and `since_seq`
  inside a dropped range starts at the oldest kept chunk.
- **Liveness.** SI-13 holds for services: a partitioned agent stops them after `agent_lease_ttl_s`, and the hub then
  requeues them per `restart`. A hub restart shorter than that keeps them running (H1 "Server restart").
- **Disk polling, the disk floor, image pulls** (`IfNotPresent`, shared pulls, the size cap) are unchanged.
- **Usage reports.** For services the agent adds `used_cpu_ms` (cumulative, from the lease cgroup) to each
  `Heartbeat.running[]` entry, at most once a minute, for the daily split (§12).

### 11.5 Residual sandbox risks added by H2

- The hub shares the distro with the jobs (D1). A container escape reaches the hub's database, blobs and identity, on
  top of the node identity it already reached in H1.
- Templates run third-party images (Ollama, whisper.cpp) with egress to model hosts. They are pinned by digest and
  reviewed, but they are not our code.
- Model files come from the internet. The default models are GGUF files read as data **(H: E11 confirms that the
  chosen images load only GGUF and do not execute code from model files)**.
- These go into `docs/security/residual-risks.md` (task T2-61).

## 12. Metering

- **Units are unchanged** (H1 §11): 1 unit = 1 vCPU-hour reserved, a GPU-hour = 10 units, milli-units, no money.
- **Services** are metered like batch attempts: reserved resources × the time the attempt held them.
- **Daily split.** For every attempt that is still running at 00:00 UTC, the hub writes a ledger row for the part of
  the attempt in the day that just ended (`slice_start`, `slice_end`), with reserved time exact and `used_cpu_ms` from
  the latest cumulative `Heartbeat` value (§11.4) minus what earlier slices recorded. The final row covers the rest.
  Daily caps and `GET /v1/usage` keep counting the same rows (H1 rule), so a week-long chat service shows up day by
  day. A slice whose used CPU comes from no report is `estimated = 1`.
- **New columns:** `device_id` (nullable, the principal when it is a device), `kind`, `template_id` (nullable),
  `slice_start`, `slice_end`. `GET /v1/usage?group_by=` gains `device`, `kind` and `template`, and each group keeps
  `estimated_attempts`.
- **Caps.** At creation, the estimate is resources × `timeout_s`, as H1. That is why a capped principal must give a
  service `timeout_s ≤ 86,400` (§7.1).
- **Service traffic** is recorded, not billed: `service_traffic(job_id, day, bytes_in, bytes_out, connections)`,
  returned in `GET /v1/jobs/{id}` as today's totals.
- **Blob storage** is recorded, not billed: `GET /v1/blobs` returns the account's total and quota.

## 13. Storage

- **Hub data dir.** In app mode `/var/lib/p2pc-server` inside the hub PC's distro (0700, root); otherwise H1 §12.
  - New tables (additive migrations): `devices`, `pairing_tickets`, `blobs`, `blob_refs`, `volume_reports`,
    `service_state` (health, last activity, consecutive unhealthy attempts), `service_traffic`, and the new ledger
    columns.
  - Blobs: `<data>/blobs/sha256/<aa>/<bb>/<hex>`, staging in `<data>/blobs/staging/`, swept after 1 h.
  - Template bundles: `<data>/templates/`.
  - **Backup.** The hub's state lives in the distro's virtual disk. The app's upgrade archives it (§8.3); nothing else
    backs it up in H2. Losing the hub PC's disk loses the cloud: devices pair again with a new hub, PCs join again
    (O-12).
- **Node.** Volumes (§11.3) under `/var/lib/p2pc/volumes/`. Blob inputs are copied into the job directory and deleted
  with it.
- **Desktop app.** `%LOCALAPPDATA%\P2PC\` (distro, backups, logs, `setup.json`, `device.key`) and the Tauri app's own
  data folders. §8.7 removes all of it.
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
  - the app checks at most once a day and, after 14 days without a successful check, shows "Could not check for
    updates since <date>", so a frozen endpoint is visible.
- **When.** The app downloads in the background and installs when the user agrees or at the next start; never in the
  middle of the first run.

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
| web app ↔ hub | `GET /v1/server` returns `api_version` and `min_web_version` | web app too old → it reloads to update; hub too old for a feature → "Update the P2PC app on your hub PC" |
| template bundle ↔ hub | `min_hub_version` (§7.6) | the hub keeps its embedded bundle |
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
| SI-H2-1 | No secret appears in logs, `Debug` output, errors, audit events, the app's logs or the browser console: device keys, pairing tickets, invite codes, join tokens, API keys. A test scans the outputs of every pairing, invite and join path. |
| SI-H2-2 | Pairing tickets are single-use and expire, checked against the hub's row, never the payload. Two concurrent `Pair`s for one ticket create exactly one device; a retry from the same NodeId is idempotent; every failure is the same `invalid_ticket`. |
| SI-H2-3 | A device principal exists only on `p2pc/device/1`. No request on the TCP listener or `p2pc/http/1` can carry one (no header, no query parameter); a device stream with an `Authorization` header gets `400`. |
| SI-H2-4 | Revoking a device closes its live connections and its open service streams within 5 s, and later connections get the same `not_paired` as a NodeId never paired. Tested with an injectable clock and a real in-process hub. |
| SI-H2-5 | Opening a service port requires `services:connect`, the job's account and project, a `running` service and a listed port, through one code path for every transport. Cross-account and unlisted-port negative tests. |
| SI-H2-6 | `PortOpen` and `BlobFetch` are fenced by `(lease_id, epoch)` on the hub and on the agent; a stale one is refused. |
| SI-H2-7 | The agent never connects to a socket path inside a job's directories except its own `ingress.sock`, which it created in the read-only mount; the shim refuses unlisted ports. Tests: a symlink planted where a socket could be, an unlisted port, a fake shim. |
| SI-H2-8 | Blobs are per account: `HEAD`, upload deduplication and `inputs` never see another account's blobs. The declared size is checked before the body is read, with `checked_add` against the quota; the hash is verified on upload and again on the node. |
| SI-H2-9 | `tpl:` volumes are created only by template launches; volume directories are per account and named by hash; deletion never follows a link. |
| SI-H2-10 | A service container keeps `--network=none` (golden argv test) and its ports are reachable only through the bridge: a scan from the distro's network namespace, the Windows host and another LAN machine finds them closed. |
| SI-H2-11 | P2PC adds no listener reachable from the LAN: the hub's REST is not reachable from another machine; the desktop app opens no TCP listener (socket enumeration test). |
| SI-H2-12 | The web app and the desktop UI never turn untrusted text into HTML: a lint rule bans `innerHTML`, `outerHTML`, `insertAdjacentHTML`, `document.write`, `eval` and `new Function`; a DOM test feeds model output with `<script>`, `<img onerror>` and `javascript:` links and checks they render inert. The deployed header files contain the CSP of §9.5 (a test parses them). |
| SI-H2-13 | Every template image is pinned by digest, and parameters reach the job only as whole env values or argv elements. A test runs over the bundle; a property test feeds shell metacharacters as parameter values and checks the resulting JobSpec. |
| SI-H2-14 | The hub loads a template bundle only with a valid release signature, a higher `bundle_version` and a satisfied `min_hub_version`; fixtures for each failure. |
| SI-H2-15 | The app's updater refuses an artifact with a bad signature, without a signed version, or with a signed version not greater than its own. |
| SI-H2-16 | An invite code is single-use; the check phrase is a pure function of (hub NodeId, listener NodeId, code) with test vectors; the app joins only after the explicit confirmation. |
| SI-H2-17 | `p2pc/pair/1` and `p2pc/invite/1` enforce their pre-auth limits (connections, pending exchanges, deadline, 4 KiB frames, failure rates); their decoders are fuzzed or property-tested. |
| SI-H2-18 | No escalation for devices: pairing tickets carry a subset of the creator's power; `nodes:join` creates tokens of at most 900 s and nothing else; only `admin` creates pairing tickets; the last unrestricted `admin` principal cannot be revoked. |

### 15.2 Threat model additions

| Threat | Mitigation | Residual |
|---|---|---|
| Stolen, unlocked phone | Bounded scopes (§5.5); revocation in ≤ 5 s; devices listed with `last_seen_at`; enrollments by a device flagged | Until revoked: open the chat (read and write), launch templates, read job state, upload blobs, and enroll a machine the thief controls, which could then receive the owner's template jobs (O-4). |
| XSS in the web app | CSP, Trusted Types, no HTML sinks, no third-party code, SRI | A bug in our own code can still leak the device key. |
| Malicious or compromised static host | Reproducible build, signed manifest, the desktop app's verification, self-hosted copy (§9.6) | Targeted tampering of one client is not detected. |
| Malicious or compromised relay | End-to-end encryption [S1] | Sees NodeIds, timing and volume; can drop traffic. |
| Photographed pairing QR | 10-minute, single-use ticket; the app shows each new device | A race inside the window. |
| Photographed invite QR | Check phrase (§5.4) | A user who confirms without comparing. |
| Container escape | H1 sandbox; owner's jobs only (SI-1); digest-pinned templates | Now also reaches the hub (D1, §11.5). |
| Compromised upstream template image | Digest pinning, reviewed bumps, signed bundle | Trust in upstream at pin time. |
| The hub relays service bytes in clear | It is the owner's own machine | A compromised hub sees chats. |
| Loss of the hub PC | — | The cloud is gone; pair and join again (O-12). |
| Fake installer (unsigned beta) | Published hash, official links only | Users may be tricked until signing (O-1). |
| npm supply chain | Lockfile, `--ignore-scripts`, license and advisory checks, few dependencies, SBOM | A compromised dependency at build time. |

## 16. Beta acceptance criteria

**Lab.** (a) A clean Windows 11 VM with nested virtualization, from a snapshot, for install and uninstall; (b) the
**reference PC**: Windows 11, an NVIDIA GPU with at least 6 GB of VRAM, an SSD with at least 130 GB free, 100 Mbit/s
down; it is the hub; (c) a second Windows 11 PC (a laptop) as a joined node; (d) an iPhone with current iOS Safari and
an Android phone with current Chrome, on 4G/5G with Wi-Fi off; (e) a Linux machine on the same LAN for scans. Scripted
criteria live in `tests/acceptance-h2/`; **manual** ones have a written protocol there and a filled-in result sheet in
the release PR.

| ID | Criterion | How |
|---|---|---|
| AC-H2-1 | Install to "Your cloud is ready": ≤ 5 min (reboot time excluded), ≤ 1 reboot, ≤ 1 UAC prompt; on the clean VM both without WSL and with WSL already installed. | **Manual**, timed; the app logs step timestamps, which the sheet copies. |
| AC-H2-2 | Join the second PC with the phone-assisted invite in ≤ 3 min, and with the invite text. | **Manual**. |
| AC-H2-3 | Pair the iPhone (home-screen path) and the Android phone in ≤ 2 min each, on 4G. The hub reports the connection as relayed. | **Manual**, plus a scripted check of `GET /v1/devices`. |
| AC-H2-4 | Private chat from the phone on 4G: launch → healthy; first model download with visible progress; with the model cached, service start to healthy ≤ 60 s **(H)**; first token ≤ 3 s after sending **(H)**; a 20-message conversation without error. | **Manual**; the web app's debug panel records the timings. |
| AC-H2-5 | Transcribe a 30-minute audio file (≈ 30 MB) uploaded from the phone; the transcript arrives within 10 minutes on the reference GPU **(H)**, also when the tab was closed during the job. The same flow passes through the CLI (`p2pc blobs put`, `p2pc templates launch transcribe`). | Manual (phone) + **scripted** (CLI). |
| AC-H2-6 | Service isolation: the chat port is closed from the distro's network namespace, the Windows host and the LAN machine; `podman inspect` shows `--network=none`; the port works through `p2pc service connect`. | **Scripted**. |
| AC-H2-7 | Revocation: two test devices (native `p2pc-device` clients); revoking one closes its connections and streams within 5 s and refuses it afterwards; the other is unaffected. Repeated by hand mid-chat on the phone. | **Scripted** + manual. |
| AC-H2-8 | Pause, resume, stop sharing and "Turn off my cloud" do what §8.4 says; a share change is visible in `GET /v1/nodes/{id}` within 10 s. | **Scripted** (through `p2pc-agent share set` and the API) + manual (UI). |
| AC-H2-9 | Uninstall leaves nothing: a before/after inventory of the user profile, `HKCU`, scheduled tasks and `wsl -l -v` on the VM differs only by the uninstall log in `%TEMP%`; a joined PC disappears from the hub's node list. | **Scripted**. |
| AC-H2-10 | Update from release N to N+1 (test-signed fixtures) while the chat runs: the app, then the hub, then the joined PC update in order; node and device identities, volumes and pairings survive; the chat comes back; a downgrade fixture is refused. | **Scripted** in part (fixtures, version checks) + manual. |
| AC-H2-11 | Every SI-H2 test and every H1 SI test passes; the deployed web app returns the §9.5 headers (a `curl` script); an internal pentest of pairing, invites, the device protocol, the web app and port forwarding finds no critical issue. | **Scripted** + manual pentest. |
| AC-H2-12 | H1 regression: the H1 acceptance suite (AC-1 to AC-12) passes against an H2 hub, and the v0.1 CLI, SDK and MCP work unchanged against it. | **Scripted**. |
| AC-H2-13 | Relays: the phone reaches the hub through our own HTTP-mode relay and through n0's; with the production relay map (§10.3) a job with egress on a WSL2 node opens the egress gate and downloads a model. | **Scripted** (from E12) + manual (phone). |
| AC-H2-14 | Docs: a beta tester guide (install with SmartScreen, share, pair, chat, transcribe, uninstall), a self-hosting guide (relay and web app), and updated `SECURITY.md` and residual risks let a tester do AC-H2-1 to AC-H2-5 without help. | Manual: one tester who did not build it. |

Checked against the limits: a 30 MB audio file is well under `max_blob_mb` (2 GiB) and the template's `disk_mb`
(4 GiB); the two template volumes (20 GiB + 4-5 GiB) fit the default volume budget (90 GiB disk share − 50 GiB for jobs
= 40 GiB), which the reference PC's free space allows (90 GiB + the 20 GiB floor of §8.2).

## 17. Work breakdown

Each task is one PR of 1-3 days **(H)**. "Depends" lists the tasks that must be merged first. Tasks in different lanes
touch disjoint files, so up to six workers run in parallel once T2-00 to T2-02 land. The experiments (§18) run first,
in throwaway `spikes/` directories, and their results amend this spec before the tasks that depend on them start.

| Task | Title | Depends | Touches | Notes |
|---|---|---|---|---|
| T2-00 | Workspace scaffold for H2 | — | root `Cargo.toml`, `deny.toml`, CI workflow, new empty crates `p2pc-device`, `p2pc-wsl`, `apps/desktop`, `apps/web`, `templates/`, `deploy/relay`, `deploy/web` | So that no later task edits the root files. Windows CI runner for `p2pc-wsl` and the app. |
| T2-01 | Proto: JobSpec extension | T2-00 | `p2pc-proto` `api.rs`, `validate/` | §7.1 table, states and `service` view types, blobs, volumes, templates, devices, errors; proptests. |
| T2-02 | Proto: protocol additions | T2-00 | `p2pc-proto` `protocol.rs`, new `pair.rs`, `device.rs`, `invite.rs`, `lib.rs` (ALPN constants) | §6: capabilities, new messages, stream headers, pairing, invite, check phrase function with vectors; decoder fuzzing (SI-H2-17). |
| **Server lane** | | | | |
| T2-10 | Server: devices and principals | T2-01, T2-02 | `p2pc-server` `auth.rs`, `store/devices.rs`, new `devices_api.rs`, migrations, `init.rs`, `recover.rs` | §5.2, §5.5: principals, scopes, pairing tickets REST, revocation, `init --owner-device`, `devices add`, `whoami`, audit. |
| T2-11 | Server: `p2pc/pair/1` and `p2pc/device/1` | T2-10 | `gateway/pair.rs`, `gateway/device.rs`, `gateway/limits.rs`, `gateway/mod.rs` | In-process HTTP serving with the device principal, limits, active close on revocation (SI-H2-3/4/17). |
| T2-12 | Server: service jobs | T2-01, T2-02 | `scheduler/`, `jobs_api.rs`, `store/leases.rs`, `store/jobs.rs` | §7.2: restart policy, affinity wait, health from agents, idle cancel, cancel by template launcher, `kind` filter, capabilities in placement. |
| T2-13 | Server: service ports | T2-11, T2-12 | new `ports_api.rs`, `gateway/ports.rs`, `conn.rs` | §7.4 upgrade endpoint and hub-opened `PortOpen` streams, idle accounting, traffic counters (SI-H2-5/6). |
| T2-14 | Server: blobs | T2-01, T2-02 | new `blobs_api.rs`, `store/blobs.rs`, `gc.rs`, `gateway/blob_fetch.rs` | §7.5 and `BlobFetch` (SI-H2-8). |
| T2-15 | Server: templates and volumes API | T2-12, T2-50 | new `templates.rs`, `templates_api.rs`, `volumes_api.rs` | §7.6 bundle loading and launch, §7.3 volumes (SI-H2-13/14). |
| T2-16 | Server: metering additions | T2-12 | `units.rs`, `usage_api.rs`, `store/usage.rs` | §12 daily split, new columns and groups. |
| **Agent lane** | | | | |
| T2-20 | Agent: service lifecycle | T2-02 | `p2pc-agent` `executor/`, `sandbox/driver.rs`, `sandbox/engine.rs` | No timeout for services, health state machine, `ServiceHealth`, log ring, `used_cpu_ms` in heartbeats. |
| T2-21 | Shim and agent: ingress bridge and port streams | T2-20 | `p2pc-shim`, agent new `sandbox/ingress.rs`, `connection/streams.rs` | §11.2 and the stream dispatcher for hub-opened streams (SI-H2-7). |
| T2-22 | Agent: volumes | T2-21 | agent new `volumes.rs`, `sandbox/engine.rs` (argv), `inventory.rs` | §11.3, `VolumeReport`, `VolumeDelete`, budget, eviction, GC (SI-H2-9). Measures `:U` vs `:idmap` with E11's data. |
| T2-23 | Agent: blob fetch, share changes, pause, leave | T2-21 | agent new `blobs.rs`, `config.rs`, `main.rs` (subcommands), `connection/session.rs` | `BlobFetch` client, `share set`, `owner_paused`, `leave`, `status --json` additions. |
| **Device and web lane** | | | | |
| T2-30 | `p2pc-device` crate | T2-02, E9 | `crates/p2pc-device` | Pairing and invite clients, device connection, HTTP/1.1 over streams, `open_port`; native and `wasm32` builds in CI; a native test client for AC-H2-7. |
| T2-31 | Web app shell, pairing and key storage | T2-30 | `apps/web` (shell, `/pair`, `/settings`, storage, QR scanner), lint config | §9.1-§9.3, §9.5 lint rules and headers (SI-H2-12). |
| T2-32 | Web app: home, jobs and chat | T2-31 | `apps/web` pages `/`, `/jobs`, `/chat`, the Markdown-subset renderer | §9.4 chat. |
| T2-33 | Web app: transcribe, uploads and invites | T2-31 | `apps/web` pages `/transcribe`, `/invite`, upload module | §9.4 transcribe, §5.4 phone side. |
| T2-34 | Web build, manifest and deploy configs | T2-31 | `deploy/web/`, `scripts/web-manifest`, CI | Reproducible build, signed `web-manifest.json`, Cloudflare Pages, Vercel and nginx configs. |
| **Desktop lane** | | | | |
| T2-40 | `p2pc-wsl`: checks, download, import, task | T2-00 | `crates/p2pc-wsl` (`checks.rs`, `image.rs`, `import.rs`, `task.rs`) | §8.3 first half. |
| T2-41 | WSL image: hub in the distro | — | `deploy/wsl/` (`build-rootfs.sh`, `p2pc-run`, `test-distro.sh`, `install.ps1` upgrade list) | §8.5: `p2pc-server` in the image, `p2pc-run`, `hub.enabled`, upgrade carries `/var/lib/p2pc-server`. |
| T2-42 | Tauri app shell | T2-00 | `apps/desktop` (`src-tauri` core, tray, single instance, autostart, capabilities, DPAPI key) | §8.1, §8.4 states, §8.9. Embeds a placeholder UI until T2-31 lands. |
| T2-43 | First run | T2-40, T2-41, T2-42, T2-10 | `apps/desktop` `setup/` module and the setup pages in `apps/web/src/desktop/` | §8.2 steps 1-5, `setup.json` resume, §8.8 errors. |
| T2-44 | Join flow | T2-43, T2-30 | `apps/desktop` `invite/` module, `apps/web/src/desktop/join` | §5.4 PC side, invite text, check phrase (SI-H2-16). |
| T2-45 | `p2pc-wsl` upgrade and uninstall; app updater | T2-43 | `crates/p2pc-wsl` (`upgrade.rs`, `uninstall.rs`), `apps/desktop` `update/`, `uninstall/`, NSIS hooks | §8.3 second half, §8.7, §14.1-§14.2, web app verification (§9.6), parity test with `install.ps1` (SI-H2-15). |
| **Infrastructure and clients lane** | | | | |
| T2-50 | Templates data and bundle | T2-01, E11 | `templates/`, `scripts/templates-bundle` | The two templates, bundle compiler and signer, bundle tests (SI-H2-13). |
| T2-51 | Relay deployment and relay-map rules | E12 | `deploy/relay/`, `p2pc-net` (relay-map validation), `p2pc-agent` `doctor.rs` | §10.2-§10.3. |
| T2-52 | Release pipeline | T2-45, T2-34, T2-50 | `.github/workflows/`, `scripts/release/` | Tauri artifacts and `latest.json` per channel, signed versions, image hash pinning, signed web manifest and template bundle. |
| T2-53 | CLI and client additions | T2-01 | `p2pc-cli` commands, `p2pc-client` | §7.8 CLI; tested against the mock server, which learns the new endpoints. |
| T2-54 | Python SDK and MCP additions | T2-53 | `sdk/python`, `p2pc-cli/src/mcp` | §7.8 SDK and MCP. |
| **Closing** | | | | |
| T2-60 | Acceptance suite and docs | all | `tests/acceptance-h2/`, `docs/` | §16, the beta guide, the self-hosting guide, OpenAPI drift. |
| T2-61 | Security pass | all | `docs/security/residual-risks.md`, `SECURITY.md` | §11.5 and §15.2 into the residual risks; internal pentest (AC-H2-11). |

Lanes once T2-01 and T2-02 land:
- server: T2-10 → T2-11 → T2-13; T2-12 → T2-16; T2-14; then T2-15;
- agent: T2-20 → T2-21 → T2-22 → T2-23;
- device and web: T2-30 → T2-31 → T2-32 / T2-33 → T2-34;
- desktop: T2-41 and T2-40 (start at once, no proto dependency) → T2-42 → T2-43 → T2-44 → T2-45;
- infrastructure and clients: T2-53 → T2-54; T2-51 after E12; T2-50 after E11; T2-52 last.

Critical path **(H)**: T2-00 (1 d) → T2-01/T2-02 (3 d) → T2-10 (3 d) → T2-11 (3 d) → T2-13 (3 d) → T2-60 (3 d), about 16
working days plus review rounds; the desktop lane (T2-40 → T2-45) is about 14 days and runs beside it. That is
consistent with a beta in 4-6 weeks only if E9, E10 and E11 pass without a design change.

## 18. Open items and experiments

### 18.1 Experiments

| Experiment | What to measure | Pass | Fail means |
|---|---|---|---|
| **E9** · iroh WASM in mobile Safari and Chrome Android | WASM size (target ≤ 3 MB compressed **(H)**); pairing through the browser; relay-only connection through n0 and through a plain-HTTP `iroh-relay` behind a TLS PaaS; connect time (p50/p95); chat stream overhead per token; 50 MB upload time on 4G; what happens when the tab goes to the background (how long until the WebSocket drops, reconnect time on return); key persistence across browser restart; iOS Safari vs home-screen storage isolation and Android tab → installed app; hyper's HTTP/1.1 client over an iroh stream in WASM; whether iroh can use a non-extractable WebCrypto key. | Pairing and a streamed chat work on both phones; reconnect ≤ 5 s after returning; 50 MB upload ≤ 2 min on 4G through our relay **(H)**. | A native shell (for example Capacitor) around the same web app, or WebTransport; the spec changes §9 before T2-30. |
| **E10** · Tauri 2 first run on a clean Windows 11 VM | Time to ready with and without WSL; reboots; UAC prompts; the `wsl --install --no-distribution` path (inbox, Store, already present, too old); SmartScreen and Defender behaviour on the unsigned installer; WebView2 presence; whether the hub's REST is reachable on Windows' loopback through `localhostForwarding`; sleep and resume; the uninstall inventory. | AC-H2-1 targets met: ≤ 5 min (reboot excluded), ≤ 1 reboot, ≤ 1 UAC. | Revisit step order, bundling the image in the installer, or the WSL install path. |
| **E11** · GPU service in Podman inside the WSL2 distro | Ollama image size and pull time; start to healthy with cached image and model; GPU visible (CUDA, not CPU fallback); the port reachable only through the ingress bridge; model download size, time and **the exact hosts** the egress allowlist needs (Ollama's registry and its CDN; Hugging Face for whisper models); Ollama through `HTTPS_PROXY`; `:U` vs `:idmap` on a model volume; VRAM and tokens/s of candidate default models; whisper.cpp speed on a 30-minute file; that the images load only GGUF. | Healthy ≤ 60 s with cached model **(H)**; downloads work through the egress proxy; no port reachable except through the bridge. | Change the template's image, model or command; a pre-pull step by the agent. |
| **E12** · relay map (proposed by this spec) | `iroh-relay` in plain-HTTP mode on Railway with native and browser clients; home-relay selection with a mixed map (our HTTP relay plus n0's relays); QUIC address discovery through n0 while relaying through ours; the egress gate opening on a WSL2 node with the production map; relay throughput and cost per GB on the PaaS. | AC-H2-13 passes. | A relay on a host with UDP (and TLS) for production, or n0's paid relays. |

### 18.2 Open items

| ID | Question | Who decides | Default in this spec |
|---|---|---|---|
| O-1 | Windows code signing: entity, certificate type or signing service, cost. | Owner | Unsigned beta; signing required before public H2. |
| O-2 | Official domain and origin of the web app and relay. | Owner | `<web app origin>`, `relay.<domain>` placeholders. |
| O-3 | Relay hosting plan, budget and abuse limits. | Owner (money) | n0 relays for the beta; Railway for the official deployment. |
| O-4 | Should a join token created by a phone (`nodes:join`) need approval on the hub PC before the node gets work? | Architect | No approval; notification and "remove PCs this device added" (§5.5). |
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
