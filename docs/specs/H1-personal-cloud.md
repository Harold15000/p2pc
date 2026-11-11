# Milestone 1 · P2PC Personal Cloud (v0.1): specification

- **Status:** accepted for implementation (spec v1, 2026-11-05).
- **Owner:** the P2PC architect. Only the architect changes this file. Implementers who find a problem report it in
  their PR instead of editing the spec.
- **Normative words:** MUST, SHOULD and MAY are used as in RFC 2119.

## 1. Goal

A **self-hostable personal compute cloud**. It has three parts:
- **One control plane**, `p2pc-server`.
- **An agent**, `p2pc-agent`, on each of the owner's machines: Linux natively, and Windows through a dedicated WSL2
  distro.
- **Clients:** the REST API, the `p2pc` CLI, the Python SDK and an MCP server for AI agents.

The owner runs batch jobs (an OCI image, a command and resources) on their own machines from anywhere, **without
opening ports** on any node.

Users of v0.1 are developers and AI agents. The non-technical app is Milestone 2, so v0.1 MUST be scriptable and
headless.

## 2. User stories (what "done" means)

- **U1 · Server.** I install the server on one always-on machine with a single command, in under 10 minutes. I get an
  admin API key, shown once.
- **U2 · Enroll a machine.** I create a join token. On another machine I run one command and paste the token when
  asked: `sudo sh install-node.sh --from <dist dir>` on Linux, or `.\install.ps1 -Join` on Windows. The token never
  goes on a command line. The machine appears in `p2pc machines` with its inventory: CPU, RAM, GPU, OS, sandbox
  capabilities and state.
- **U3 · Run a job.** `p2pc run --image python:3.12-slim --cpu 2 --mem 4G -- python -c "print(6*7)"` prints a job ID.
  I see the logs live, then the exit code. `p2pc results <id>` downloads the files written to `/outputs`.
- **U4 · GPU.** `--gpu 1` runs on a node with an NVIDIA GPU, whether native Linux or WSL2, for example `nvidia-smi` or
  a PyTorch matmul.
- **U5 · Egress.** `--egress pypi.org,files.pythonhosted.org` lets `pip install` work through the egress proxy.
  - Every other destination is refused.
  - The LAN, the host and tailnets are always refused, even if allowlisted.
- **U6 · Reliability.** If a node disappears mid-job, the job is retried on another node when attempts remain.
  Otherwise it ends as `lost`. A node coming back never runs a stale attempt.
- **U7 · AI agents.** With the MCP server (`p2pc mcp`), an agent can estimate, run, check, read logs, fetch results
  and cancel. It uses its own key, which has a daily cap in compute units and an image allowlist.
- **U8 · Usage.** `p2pc usage` shows reserved and used compute per job, per node and per key.
- **U9 · Owner control.** On each node I can set the share of CPU, RAM and GPU it offers. I can pause or drain a node
  from the CLI.
- **U10 · Python.**
  ```python
  p2pc.Client(...).jobs.run(image=..., command=[...]).wait()
  ```
  returns the status, the logs and the outputs.

## 3. Non-goals for v0.1

- A GUI app (that is Milestone 2).
- Payments, a marketplace, third-party code, teams and multi-tenancy (Milestones 3-5).
- VMs, SSH sessions, long-running services, hosting, multi-node jobs, Windows or macOS guests.
- macOS nodes: the Mac is a client only.
- Postgres (SQLite only, behind a thin repository layer) and S3 (artifacts go on local disk).
- An OpenAI-compatible endpoint and the JS SDK (Milestone 3).
- Retrying jobs that fail by themselves. Only node loss triggers a retry in v0.1.
- Large inputs. Inputs travel inline in the job (`files`, at most 512 KiB in total). A job fetches bigger data itself,
  through its egress allowlist (for example from S3 or Hugging Face). Input uploads, as content-addressed blobs, come
  in v0.2.

## 4. Architecture

```
 CLI · Python SDK · MCP · curl
        │  HTTPS REST (+ the same REST tunnelled over iroh by `p2pc proxy`)
        ▼
 ┌──────────────── p2pc-server (control plane, AGPL-3.0) ─────────────────┐
 │ axum REST API · auth · scheduler · node gateway · metering · artifacts  │
 │ SQLite (WAL) · data dir on disk · iroh endpoint (server NodeId)         │
 └─────────────────────────────▲──────────────────────────────────────────┘
                               │  iroh QUIC, always dialled BY the agent (NAT/CGNAT ok, relay fallback)
 ┌─────────────────────────────┴───────────── p2pc-agent (per node) ───────┐
 │ identity key · inventory · heartbeats · leases · sandbox driver (Podman)│
 │ per-job egress proxy (unix socket) · log streaming · output upload      │
 └─────────────────────────────┬──────────────────────────────────────────┘
                               ▼
        rootless Podman container, --network=none, /.p2pc/shim as entrypoint
```

### Crates and binaries

| Crate | Binary | License | Role |
|---|---|---|---|
| `p2pc-proto` | — | Apache-2.0 | API and protocol types, framing, validation. No I/O. |
| `p2pc-server` | `p2pc-server` | AGPL-3.0-only | Control plane. |
| `p2pc-agent` | `p2pc-agent` | Apache-2.0 | Node daemon. |
| `p2pc-cli` | `p2pc` | Apache-2.0 | CLI, MCP server (`p2pc mcp`), API tunnel (`p2pc proxy`). |
| `p2pc-shim` | `p2pc-shim` | Apache-2.0 | Static (musl) helper injected into every sandbox. |
| `sdk/python` | — | Apache-2.0 | Python package `p2pc`. |

## 5. Identities and authentication

- **Server identity.** An iroh secret key is generated on first start and stored in the data dir with mode 0600. Its
  public key, the server's `NodeId`, is how agents and `p2pc proxy` address the server.
- **Owner and projects.** v0.1 is single-owner: one `account` per server, created at install. Each account has at
  least one `project`, and the default one is named `default`. The data model keeps `account_id` and `project_id` on
  every object, so that Milestone 3 (teams) needs no migration of meaning.
- **API keys.**
  - Format: `p2pc_sk_<key_id>_<secret>`. The `key_id` is 12 characters of lowercase base32. The `secret` is 32
    random bytes in lowercase base32.
  - Storage: the `key_id` plus SHA-256 of the secret. The secret has high entropy, so a slow hash is not needed.
    Comparison is constant-time.
  - Shown once. The create response is flat: the key's metadata (`id`, `label`, `scopes`, caps, `expires_at`, …) plus
    `key`, which holds the full `p2pc_sk_…` string.
  - Each key has scopes (`admin`, `jobs:write`, `jobs:read`, `nodes:read`, `nodes:write`).
  - Optional per key: `daily_unit_cap` and `allowed_images` (glob patterns on the normalized image reference).
  - **Lifecycle** (from E8, Headscale):
    - optional `label` and `expires_at`;
    - the server keeps `last_used_at`, written at most once a minute, and `revoked_at`. Revoking a key sets
      `revoked_at`; the row is never deleted.
  - **No escalation.** A key can never create a key with more power than it has itself:
    - the new key's scopes must be a subset of the creator's scopes (`admin` covers every scope);
    - if the creator has a `daily_unit_cap`, the new key must have one too, at or below the creator's;
    - if the creator has `allowed_images`, the new key must have a list made only of patterns from the creator's
      list, compared exactly;
    - if the creator has `expires_at`, the new key must have one too, at or before the creator's (a longer life is
      more power);
    - a violation gets `403 escalation_denied`.
  - **Revoking** follows the same rule. A key can revoke itself, or any key that it could have created
    (`check_no_escalation` applied to the target's scopes, cap, images and expiry). Anything else gets
    `403 escalation_denied`.
  - **Last admin key.** The server refuses to revoke the account's last live **unrestricted** admin key, meaning one
    with no `expires_at`, no `daily_unit_cap` and no `allowed_images`. The answer is `409 last_admin_key`.
  - **Offline recovery.** `p2pc-server keys recover --data-dir <dir>` needs local access to the data directory. It
    creates a new unrestricted admin key, prints it once and records a `key_recovered` audit event. It works while
    the server is running. This is the way back for an owner who has lost every admin key.
  - **Stored digest.** The digest is versioned (`sha256:<hex>`), with a database CHECK on its length, and `key_id` is
    unique.
  - **Authentication order:** parse, look up `key_id`, verify the secret, then check expiry and revocation. An unknown
    `key_id`, a wrong secret, an expired key and a revoked key all get the same `401` with the same `code`. On a
    lookup miss, a dummy constant-time comparison keeps the timing equal.
  - **Re-checked at the point of use.** Every operation that grants or removes power, such as creating or revoking
    keys or join tokens, reloads the caller's key **inside the same transaction** that performs it. If the key was
    revoked or has expired since the request was authenticated, the answer is the same `401`, and nothing changes. A
    revocation therefore stops a client that is already connected.
- **Join tokens.**
  - Created by `POST /v1/nodes/join-tokens` (admin scope).
  - The token is the string `p2pc_join_<base32 payload>`. The payload holds:
    - the server NodeId;
    - relay URL hints;
    - a 16-byte random code;
    - the expiry.
  - Single-use. Valid for 15 minutes by default (maximum 24 h).
  - The server stores only SHA-256 of the code.
  - **The payload is not authenticated.** The server never trusts its expiry. It looks the token up by the hash of
    the code, compared in constant time, and uses the expiry and the single-use flag from its own row.
  - **Consuming is atomic.** One
    `UPDATE … SET consumed_at = ?, node_id = ? WHERE code_hash = ? AND consumed_at IS NULL AND expires_at > ?` runs in
    the same transaction that inserts the node. With two concurrent `Join`s for one token, exactly one succeeds.
  - **Retrying is idempotent.** If the agent lost the `Welcome`, the same token from the **same** NodeId gets the same
    `Welcome` again. Any other NodeId gets `invalid_token`.
  - **Re-enrolling the same machine** (`join --force` with a new token, from a NodeId that is already a live node).
    - If the token's account owns that node, the join **re-enrolls** it. It keeps the same node id, refreshes the
      inventory, takes the project from the token, consumes the token, and is audited as `node_reenrolled`.
    - If another account owns it, the join is refused like an invalid token.
    - Before this rule, a re-join to the same server failed with "unknown, expired, revoked or already used" while
      the node still existed (T14b2 real run; amended 2026-11-06).
  - **Ownership.** The node's `account_id` and project come from the token row, never from the `Join` message or the
    inventory.
  - **Listing and revoking.** `GET /v1/nodes/join-tokens` lists the tokens: id, label, created-by key, expiry and
    the node that consumed it. `DELETE /v1/nodes/join-tokens/{id}` revokes an unused token. Both need the admin
    scope.
- **Node identity.**
  - Each agent generates its own iroh secret key at first start, stored 0600.
  - Joining binds the agent's NodeId to a new `node` row, owned by the token's account.
  - From then on, the server accepts the agent protocol only from enrolled NodeIds. The only exception is the
    `Join` message.
  - iroh's TLS authenticates the peer's NodeId, so the node needs no separate password.
  - **Names.** The agent reports its hostname. The server derives a sanitized `name` that is unique per account
    (`base`, `base-1`, …, compared case-insensitively). An explicit rename that collides is refused. Names are never
    used for authentication.
  - **Deletion.** `DELETE /v1/nodes/{id}` closes the node's live connection and refuses reconnects. A `Hello` from a
    NodeId that is not enrolled gets `Error{code:"not_enrolled"}`, the same answer whether or not that NodeId was
    ever enrolled.
  - **Lost key.** If an agent loses its key, the owner deletes the node and joins again. T14 documents this.
- **Owner-only execution (security invariant SI-1).**
  - Every lease carries the job's `account_id`.
  - The agent stores the `account_id` it was enrolled into, and MUST reject (`LeaseRejected{reason:"not_owner"}`) a
    lease for any other account.
  - v0.1 has a single account, but the check MUST exist and be tested. It is the hook that keeps untrusted code out
    of non-VM sandboxes.
- **Audit** (from E8, Headscale).
  - An append-only `audit_events` table records:
    - key created and revoked;
    - join token created, consumed and revoked;
    - node enrolled and deleted;
    - keys recovered offline;
    - failed authentications, aggregated per minute rather than one row each. They are recorded off the request path,
      through a bounded queue, so a `401` never waits for the database. When the queue is full, events are dropped
      and counted.
  - `GET /v1/audit` (admin scope) reads it, with cursor pagination.
  - No event ever contains a secret.

## 6. Agent protocol (ALPN `p2pc/agent/1`)

- **Transport.** The agent opens an iroh connection to the server. Its first bidirectional stream is the **control
  stream**: length-prefixed frames (u32 big-endian length, then a UTF-8 JSON message).
  - Maximum frame size: 1 MiB.
  - Messages are serde enums tagged by `"type"`.
  - JSON keeps v0.1 easy to debug. A binary encoding can come later behind a new ALPN.
- **Uploads.** Each output file gets its own bidirectional stream: a JSON header frame (`UploadHeader{lease_id, epoch,
  path, size, sha256}`), then the raw bytes. The server answers `UploadAck{ok, reason?}`.
  - Decided on 2026-11-05 (T10):
    - every upload ends **before** `JobFinished`;
    - the server stages each file, fenced and verified, and publishes the staged files that `JobFinished.outputs`
      lists, with the same size and sha256;
    - an unlisted staged file is deleted;
    - a listed file that is missing or mismatched is left out, and the job's `error` gets `outputs_incomplete: N`;
    - finalising is idempotent.
- **Agent → server messages:**
  - `Join{token, inventory}`: only on the first connection.
  - `Hello{agent_version, features:[…], inventory, running:[{lease_id, epoch}]}`.
  - `Heartbeat{seq, load:{cpu_pct, mem_used_mb, gpu_util_pct?}, running:[…]}`, every `heartbeat_interval_s`
    (default 5).
    - `running` lists every lease that still **holds resources** on the node: running, uploading, or being cleaned
      up. A lease leaves `running` when its resources are free: the container is removed and the job directory
      is deleted.
    - The agent sends a `Heartbeat` at once when a lease's resources become free, without waiting for the
      interval.
    - The agent frees a lease's resources when its cleanup ends. Keeping the `JobFinished` report until it is
      confirmed does not hold them.
    - Amended 2026-11-08 (ACC-1 round 3, see §8 "Reservations are held until confirmed").
  - `InventoryUpdate{inventory}`: sent when the agent's periodic re-detection, every 10 minutes, finds a change (for
    example a driver installed after start). The server replaces the stored inventory and recomputes the offered
    capacity.
  - `LeaseAccepted{lease_id, epoch}` and `LeaseRejected{lease_id, epoch, reason}`.
    - `reason` is one of the `LeaseRejectReason` constants: `not_owner`, `invalid_job`, `agent_not_ready` (no
      executor yet, or the node is not ready, for example while its RAM is unknown), `insufficient_capacity`,
      `draining` and `deadline_passed`. A receiver treats an unknown reason as a generic rejection (amended
      2026-11-05, T05b).
    - While the agent cannot measure its RAM, it reports the node as **not ready**. `Inventory.memory_mb` then carries
      a placeholder, and the scheduler must not use it.
    - The reasons are `not_owner`, `unsupported_sandbox`, `insufficient_capacity`, `draining`, `invalid_job` and
      `gpu_selection_unsupported`.
    - The last one means the node cannot pin the requested GPU, for example WSL2 with more than one GPU. The
      inventory should already mark such GPUs as not offerable, so this is a fallback.
    - Every rejection counts as a rejected offer, never as an attempt.
  - `JobStarted{lease_id, epoch, started_at}`.
  - `LogChunk{lease_id, epoch, stream:"stdout"|"stderr", seq, data_b64}`: at most 64 KiB per chunk.
  - `JobFinished{lease_id, epoch, outcome:"exited"|"timed_out"|"cancelled"|"error", exit_code?, error?, usage, outputs:[{path,size,sha256}]}`.
- **Server → agent messages:**
  - `Welcome{server_version, node_id, account_id, heartbeat_interval_s, lease_ttl_s}`. The agent stores `account_id`
    at `Join` (SI-1) and refuses a later `Welcome` with a different one. It checks
    `agent_lease_ttl_s + 10 <= lease_ttl_s`, and if that fails it lowers its own timer and logs a warning.
  - `HeartbeatAck{seq}`: the answer to every `Heartbeat`, and the agent's proof that the server is alive.
  - `Lease{lease_id, epoch, job, account_id, deadline}`. The frame decodes `job` **leniently**, so that the agent can
    always read `lease_id`. The agent then parses `job` strictly as `JobSpec` and answers
    `LeaseRejected{reason:"invalid_job"}` if it does not understand it ("must understand"). That counts as a
    rejected offer, not as an attempt, so the connection never churns.
  - `Cancel{lease_id, epoch, reason}`.
  - `Drain{}` and `Resume{}`.
  - `Error{code, message}`.
- **Leases and fencing.**
  - Each lease of a job, meaning each offer, gets the job's next epoch (1, 2, …). The epoch increases strictly per
    job. It is **not** the attempt number: rejected or unanswered offers take an epoch but no attempt, so
    `epoch >= attempt` (amended 2026-11-05, T06).
  - Any agent message whose `(lease_id, epoch)` is not the job's current lease is rejected. The server answers
    `Cancel` for that lease, and the agent MUST kill that execution.
  - A lease expires if the node sends no heartbeat for `lease_ttl_s` (default **60**).
- **Liveness on both sides** (from E8, HTCondor). Epochs fence the *reports* of a partitioned node. They do not stop
  its *execution*.
  - If the agent hears nothing from the server (no `HeartbeatAck` or any other message) for `agent_lease_ttl_s`
    (default 45, on a monotonic clock), it stops every running job with the §9 sequence: SIGTERM, 10 s of grace,
    then SIGKILL. It then forgets those leases.
  - The agent validates `agent_lease_ttl_s + 10 <= lease_ttl_s` when it loads its config, so a partitioned agent
    always stops before the server requeues (SI-13).
  - While it has running leases, the agent caps its reconnect backoff at 5 s instead of 30 s.
- **Server restart.** On boot, the server treats every node with active leases as seen at boot time. Agents can then
  reconnect and reconcile through `Hello` before any lease expires, so a server restart never cancels healthy jobs.
- **Idempotency.**
  - Messages that repeat after a reconnect are deduplicated by `(lease_id, epoch, seq)`, or by kind for
    `JobStarted`/`JobFinished`.
  - Sending `JobFinished` twice is harmless.
  - **A `JobFinished` is confirmed** once the server answers a `Heartbeat` that the agent sent after it on the same
    control stream. The server reads that stream in order, so the answer proves the report was processed.
    - Until then, the agent keeps the report. After a reconnect it lists that lease in `Hello.running`, so the server
      does not declare it lost, and it sends the `JobFinished` again right after `Welcome`.
    - A report lost with a dropped connection therefore never turns a finished job into a requeue (amended
      2026-11-06, T10a).
- **Reconnects.**
  - The agent reconnects with exponential backoff and jitter: 1 s doubling to a 30 s cap.
  - In its `Hello` the agent lists its running leases, and the server reconciles them. A lease that is still valid
    continues. Anything else gets `Cancel`.
  - A lease that the server holds for this node but that is **absent** from a fresh `Hello.running` is lost at once.
    The job is requeued if it has attempts left, with the same accounting as node loss. The server does not wait
    for the ttl.
- **Before `Join`** (from E8, Headscale). `Join` is the only message accepted from unknown NodeIds, so it is
  unauthenticated attack surface:
  - at most 64 connections from unknown NodeIds at once, and 16 pending `Join`s;
  - one `Join` attempt per connection, which must arrive within 10 s;
  - failed `Join`s are rate-limited to 10 a minute per NodeId and 60 a minute in total;
  - beyond these limits, the connection is closed with no detail.
- **Two-phase assignment.** The server sends `Lease`, and the agent must answer `LeaseAccepted` within 10 s. If it
  does not, the server revokes the lease and requeues the job, with the attempt not counted.
- **Compatibility within `p2pc/agent/1`** (decided 2026-11-05, while reviewing T02):
  - Receivers **ignore unknown fields** in protocol messages, so additive changes need no new ALPN. The CLI and SDK
    also ignore unknown fields in REST *responses*. REST *request* bodies (`JobSpec`, key creation and so on) keep
    rejecting unknown fields, which catches typos.
  - An unknown message `type` is not fatal. It decodes to an `Unknown` variant; the receiver answers
    `Error{code:"unsupported_message"}` and keeps the connection.
  - A change that a peer must understand to stay safe, such as a new restriction on a `Lease`, is never just an added
    field. Either it requires a capability the agent declared in `Hello{…, features:[…]}`, so the server sends such
    leases only to agents that declared it, or it takes a new ALPN.
  - `agent_version` and `server_version` are semver. The server refuses agents older than its `min_agent_version`
    with `Error{code:"agent_too_old"}`.
  - `Inventory` carries `offered`: the capacity the owner chose to share, as `cpu`, `memory_mb`, `gpu` and `disk_mb`.
    `disk_mb` is the disk for job directories from the share limits (default 50 GiB, never more than the
    filesystem). The scheduler (§8) uses all four. `offered` may not exceed the reported hardware.
    - `Inventory.disk_total_mb` (optional) is the size of the filesystem that holds the job directories. It is what
      "the reported hardware" means for disk: `offered.disk_mb` may not exceed it, and the server refuses an inventory
      that breaks this. Without it, only the protocol's ceiling applies.
    - Amended 2026-11-07 (ACC-1 round 2). Without `disk_mb` the scheduler offered leases that the agent refused for
      disk (`insufficient_capacity`). Three AC-10 jobs reached the offer cap and stayed `queued` with both nodes
      idle. An agent without the field (older than this amendment) is placed by CPU, memory and GPU only.
      `disk_total_mb` was added in T06c, which needed a filesystem size to check against.
- **GPU inventory** (from E8, GPUStack and BOINC). Each GPU reports:
  - `uuid`, which is the key. It is never identified by its index.
  - `index`, `name`, `driver_version`, `cuda_driver_version`, `compute_capability`, `vram_mb`, `pci_bdf` and `mig`
    (bool).

  The inventory also carries:
  - `gpu_status`: `ok`, `no_driver`, `nvml_error`, `not_found`, `cdi_missing` or `cdi_stale`, with a `reason`;
  - `platform`: `linux` or `wsl2`;
  - `dxg` (bool).

  Rules:
  - A card with MIG enabled is reported but **not offerable** in v0.1.
  - Unknown VRAM makes a GPU not offerable. It is never guessed.
  - Detection uses NVML, with `nvidia-smi` as the fallback. On WSL2 the agent calls NVML directly, with no PCI sysfs
    check.
  - The agent re-detects on every `Hello` and every 10 minutes, and never caches a failure.
  - On WSL2, the inventory adds a health block: the distro version stamp, the Podman version, whether the CDI spec is
    present, `/dev/dxg`, and the result of a once-per-boot smoke container.
  - Enums nested inside messages (`SandboxClass`, `Outcome` and so on) stay closed. A peer only sends values its
    counterpart knows. The server is upgraded before its agents. An agent that is newer than its server sends only
    the values that exist in the server's version, which it learns from `Welcome.server_version`, or values covered
    by a capability.

## 7. Jobs API (REST)

The OpenAPI 3.1 document is generated from the server code (utoipa). It is served at `GET /v1/openapi.json` and
committed as `docs/api/openapi.json`. A test fails if the committed copy drifts from the code.

- **Authentication:** `Authorization: Bearer p2pc_sk_…`.
- **Errors:** RFC 9457 `application/problem+json` with `type`, `title`, `status`, `detail` and a stable `code`.
- **Lists:** cursor pagination (`limit` ≤ 100, `cursor`).

### JobSpec (`POST /v1/jobs`)

```json
{
  "name": "optional label",
  "image": "docker.io/library/python:3.12-slim",
  "command": ["python", "-c", "print(6*7)"],
  "env": {"KEY": "value"},
  "files": [{"path": "/inputs/data.csv", "content_b64": "…"}],
  "resources": {"cpu": 2, "memory_mb": 4096, "gpu": 0, "disk_mb": 10240},
  "timeout_s": 3600,
  "egress": {"allow": ["pypi.org", "files.pythonhosted.org"]},
  "outputs": {"max_mb": 1024},
  "placement": {"pools": ["mine"], "node_id": null, "labels": {}},
  "retry": {"max_attempts": 2},
  "idempotency_key": "optional"
}
```

**Validation** (all of it lives in `p2pc-proto` and is unit-tested):

| Field | Rule |
|---|---|
| `image` | A valid OCI reference. The registry must be in the server's allowed list (default: `docker.io`, `ghcr.io`, `quay.io`, `nvcr.io`, `registry.gitlab.com`). An `@sha256:` digest is allowed. |
| `command` | 1-256 args, at most 64 KiB in total. It is an argv: there is no shell unless the user's argv calls one. |
| `env` | At most 64 variables, 32 KiB in total. Names match `[A-Z_][A-Z0-9_]*`. Names starting with `P2PC_` are reserved. Values may not contain NUL, `\n` or `\r`, because they go into Podman's line-based `--env-file` and a newline would inject another variable. Encode multi-line secrets (base64), or pass them as `files`. Values are **never logged**, and **API responses never return them** (see Endpoints). |
| `files` | Absolute paths under `/inputs`, with no `..`. No path may be a directory of another. At most **512 KiB** in total, decoded. In addition, the whole job as delivered in a `Lease` must fit in one 1 MiB frame (§6). The server checks the exact serialized size when the job is submitted and answers `422 too_large` if it does not fit. Larger inputs arrive in Milestone 2, through storage or a separate stream. |
| `resources.cpu` | 0.25-256 (fractional allowed), a multiple of 0.001. Units are computed from the value rounded to the nearest milli-vCPU, so float error never adds a milli-unit. |
| `resources.memory_mb` | 128-1,048,576. |
| `resources.gpu` | 0 or 1 in v0.1 (a whole GPU). |
| `resources.disk_mb` | At least 1. Default **2,048**. It is both the job's disk limit ("Limits and status" in §9) and what the scheduler holds on the node. *Amended 08-11-2026 (ACC-1 round 4, the first GPU-less Ubuntu node):* the default was 10,240. With the default 50 GiB disk share, that capped every node at 5 concurrent default jobs whatever its CPUs, and a node with a 30 GB disk at 2. A job that needs more scratch passes `--disk` (`disk_mb`); without it, it ends with `disk_limit`, and the clients say how to raise it. |
| `timeout_s` | 1-86,400. Default 3,600. |
| `egress.allow` | At most 32 domain names, lowercase, no wildcards, no IP literals. An entry matches itself and its subdomains on whole labels. |
| `placement.pools` | Only `["mine"]` in v0.1. Any other value → `422 unsupported_pool`. |
| `retry.max_attempts` | 1-5. Default 2. Attempts are consumed only by node loss. |
| `idempotency_key` | The same key with the same body returns the existing job (200). The same key with a different body → `409`. Idempotency keys are scoped to the **API key** that submitted the job, and responses never include them. Otherwise another key could resubmit a visible spec with guessed `env` values and learn from `200` versus `409` whether a secret guess was right. |

### Endpoints

**Job representation in responses.** `Job` nests the submitted spec under `spec`. In every response, the values of
`spec.env` are replaced by the string `"<redacted>"`, and `spec.files` lists `{path, size, sha256}` with no
content. Secrets submitted by a `jobs:write` key are therefore never readable through the API, and a page of jobs
stays small.

| Method and path | Scope | Notes |
|---|---|---|
| `POST /v1/jobs` | jobs:write | 201 with `Job`. Checks the key's `allowed_images` and `daily_unit_cap`, using the estimate (resources × timeout). |
| `GET /v1/jobs`, `GET /v1/jobs/{id}` | jobs:read | Filter by `status` and `node_id`. |
| `GET /v1/jobs/{id}/logs` | jobs:read | `?follow=true&since_seq=N&attempt=K` (`attempt` defaults to the latest). NDJSON stream of `{seq, stream, ts, data}`. `since_seq` is **inclusive**: the stream starts at the first chunk with `seq >= N`, so a client resumes with `last_seq + 1` (T12's `next_seq`). Capped at 64 MiB per attempt; after that, a single truncation marker. **How a follow ends** (amended 2026-11-06, T10d and T13f): the body ends cleanly only when the attempt is over and every line was sent. The idle limit (60 s with no line) and internal errors **break** the body, because a client would read a clean end as "complete". Clients (CLI, SDK, MCP) reopen from `next_seq` after any end that comes before the job is final. **Outages are tracked per route** (the log stream, and the job check), and each one ends only with a success on its own route. A stream that delivered a line, or stayed open for 10 s, is a success of the log route even if it then breaks: the client checks the job and reopens. A stream that fails to open (connection error, 429, 5xx) or breaks at once is a failure. Waits go from 1 s to 30 s. **An outage of a route** is a run of failures of that route, from the start of its first failed request, with no success on that route and no gap longer than 30 s (the longest wait) between two of its requests. A longer gap, because the client was busy with healthy work on the other route, starts a new outage. One outage lasts at most 5 minutes. So a job route that keeps failing gives up 5 minutes after the logs end, a long, healthy stream never leaves a stale outage behind, and one failed check before and one after a 6-minute stream are two short outages (amended 2026-11-06, T13g review). |
| `POST /v1/jobs/{id}/cancel` | jobs:write | Idempotent. |
| `GET /v1/jobs/{id}/outputs` | jobs:read | The list, with sha256, for the latest attempt or `?attempt=K`. After GC, entries show `expired: true`. |
| `GET /v1/jobs/{id}/outputs/{path}` | jobs:read | Download, from the latest attempt or `?attempt=K`. The path is validated: no traversal, and symlinks are never followed. Sends `X-P2PC-SHA256`. After GC: `410 Gone`. |
| `POST /v1/estimate` | jobs:read | `{feasible, matching_nodes, would_queue, units_per_hour, reason?}`. |
| `GET /v1/nodes`, `GET /v1/nodes/{id}` | nodes:read | Inventory, state, `last_seen`, free capacity. |
| `POST /v1/nodes/{id}/drain`, `POST /v1/nodes/{id}/resume`, `DELETE /v1/nodes/{id}` | nodes:write | |
| `POST /v1/nodes/join-tokens`, `GET /v1/nodes/join-tokens`, `DELETE /v1/nodes/join-tokens/{id}` | admin | `POST` returns `{join_token, expires_at}`. `DELETE` revokes an unused token (§5). |
| `POST /v1/keys`, `GET /v1/keys`, `DELETE /v1/keys/{id}` | admin | `POST` returns the key once. `DELETE` revokes: it sets `revoked_at` (§5). |
| `GET /v1/audit` | admin | Append-only audit events (§5), with cursor pagination. |
| `GET /v1/usage` | jobs:read | `?from&to&group_by=job\|node\|key`. |
| `GET /v1/whoami` | any valid key | `{account_id, project_id, key_id, scopes, label, daily_unit_cap, allowed_images, expires_at}`: the caller's own key, never its secret. `p2pc login` uses it to check a key, and `p2pc mcp` to check that its key is capped. |
| `GET /v1/server` | any valid key | `{node_id, relays, address, version}`. `address` is the server address of §10; `p2pc login` stores it for the tunnel. |
| `GET /healthz` | none | Liveness only, with no data. |

### Job states

`queued → assigned → running → {succeeded | failed | timed_out | cancelled | lost}`. On node loss, a job in
`assigned` or `running` with attempts left goes back to `queued` with `attempt + 1`. Terminal states are immutable.

- `succeeded`: exit code 0.
- `failed`: an exit code other than 0, or a sandbox error.
- A job that is never placed stays `queued`. There is no expiry in v0.1, but cancel works.
- Each attempt gets a `job_attempts` row: epoch, node, outcome, reason code, and start and end times.
  `GET /v1/jobs/{id}` returns them as `attempts`, oldest first:
  `[{attempt, node_id, outcome, reason, started_at, ended_at}]`. `outcome` uses the job-state words: `running` while
  the attempt runs, then `succeeded`, `failed`, `timed_out`, `cancelled` or `lost`. An attempt that was replaced
  after node loss, and so is fenced, is `lost`. `reason` is the reason code, or `null`. `started_at` is `null` until
  `JobStarted`, for example while the image is pulled, and stays `null` if the attempt never starts. Rejected offers are not
  listed. Lists of jobs leave the field out (amended 2026-11-06, for AC-6 and U6).
- The state enum is extensible. A non-terminal `held` state may be added in Milestone 2 as an additive change.
- `assigned → timed_out` is also legal: it is the server watchdog's backstop for an agent that accepted a lease and
  then hung before `JobStarted`, for example during an image pull (see §8, Timeouts).

### CLI conventions (`p2pc`)

- **Profiles and files.** `config.toml` and `credentials.toml` live in one directory:
  - `$P2PC_CONFIG_DIR`, if it is set;
  - otherwise `$XDG_CONFIG_HOME/p2pc` (default `~/.config/p2pc`) on Linux and macOS, and `%APPDATA%\p2pc` on
    Windows.

  Each profile has a `server`: an `https://` or `http://` URL, or a server address `p2pc_srv_…` (§10).
- **Credentials.**
  - `credentials.toml` holds the API key of each profile. Its mode is 0600. On Unix the CLI refuses to read it if
    the group or others can read it, as `ssh` does.
  - `P2PC_SERVER`, `P2PC_API_KEY` and `P2PC_PROFILE` override the files.
  - The key is never accepted as a command-line argument, because it would end up in the shell history and in `ps`.
    `p2pc login` reads it from a hidden prompt or from `--key-stdin`, and checks it with `GET /v1/whoami`.
  - The same applies to **join tokens** (decided 2026-11-05, while reviewing T15a). `p2pc-agent join` still accepts
    `<token>` for a person typing it, but it also reads the token from stdin when the argument is `-` or missing.
    Our installers and the acceptance harness always use stdin. On Windows, argv shows up on the Windows command
    line.
- **Output.** Human-readable by default. `--json` prints the API types as JSON (NDJSON for streams), so scripts and
  agents get stable fields.
- **`p2pc run`.**
  - By default it follows the job: the job ID goes to stderr, the job's stdout to stdout and its stderr to stderr.
  - `--detach` prints only the job ID, on stdout.
  - Ctrl-C detaches and does **not** cancel. The CLI then prints how to follow or cancel the job.
- **Retries.** `p2pc run` always sends an idempotency key, generated if the user gave none. It retries connection
  errors and `502`/`503`/`504` up to 3 times with the same key, so a retry never creates a second job.
- **Exit codes:**

  | Code | Meaning |
  |---|---|
  | 0 | The job succeeded, or the command worked. |
  | 1-255 | The job's own exit code, when it failed with one. |
  | 75 | The job was lost (`lost`). Retrying may work. |
  | 124 | The job timed out. |
  | 125 | p2pc could not run the job or the command: validation, authentication, the network, or a job that failed before it started (for example, an image pull). |
  | 130 | Interrupted with Ctrl-C (SIGINT), or the job was cancelled, or `run` **detached** because its stdout was closed (`p2pc run … \| head -1`) while the job was still running; the job keeps running and the detach hint goes to stderr. If the job had already ended when the output closed, `run` returns the job's own code instead (amended 2026-11-06, T11b3). A long-running command such as `p2pc proxy` that is stopped by SIGTERM (a service manager) ends cleanly with 0 (amended 2026-11-06, T11b1). |

  A job's own exit code can collide with these codes. `--json` always gives the exact outcome.

### MCP server (`p2pc mcp`)

- **Transport.** v0.1 speaks MCP over stdio only, for example `claude mcp add p2pc -- p2pc mcp --profile agent`. It
  opens no listening socket.
- **Its own, limited key.** On start, the server calls `GET /v1/whoami`, and it refuses to run with a key that has the
  `admin` scope or no `daily_unit_cap`. `--allow-admin` and `--allow-uncapped` override this, with a warning on
  stderr. An agent should never be able to spend without a cap (U7, AC-9).
- **Tools:**
  - `p2pc_estimate`;
  - `p2pc_run`, which returns the job ID at once and accepts an optional short `wait_s` (at most 60);
  - `p2pc_status`, `p2pc_logs`, `p2pc_results`, `p2pc_cancel` and `p2pc_machines`.

  The input schemas follow `JobSpec`. Every tool description states that jobs spend the key's daily cap.
- **No duplicate jobs.** `p2pc_run` takes an optional `idempotency_key`: 1 to 128 characters of `[A-Za-z0-9._:-]`.
  - The MCP server sends it as the job's `idempotency_key`, prefixed `mcp:`. The API's rules then apply: the same
    key with the same body gives the existing job, and with a different body, `409`.
  - Without it, every call is a new job.
  - The tool description asks agents to set one, and to send the same one when they retry a call.
  - The JSON-RPC request ID is never part of it. MCP forbids reusing a request ID within a session (Basic
    protocol, Requests), so a retry always comes with a new one.
  - Amended 2026-11-07 (ACC-1, AC-9). The first design derived the key from the session and the request ID, so
    it deduplicated only repeated IDs, which no compliant client sends.
- **Bounded answers.**
  - `p2pc_logs` returns at most 64 KiB per call, with a `next_seq` cursor.
  - `p2pc_results` returns small text files inline (at most 64 KiB each) and saves the rest under a results directory
    (default `./p2pc-results/<job_id>/`), with the same path checks as SI-9 and the sha256 verified.
- **Job output is data, not instructions.** Logs and file contents come back in a structured field that is marked as
  untrusted output of the job, never as text the agent should follow.

## 8. Scheduler

- **When it runs:** a loop runs on events (a job is created, a node changes) and every 1 s as a fallback.
  Queued jobs are taken in FIFO order of `created_at`.
- **Eligible nodes:**
  - online and not draining;
  - in the same `account_id`;
  - pool `mine`;
  - labels match;
  - when `gpu = 1`, a free GPU;
  - a sandbox driver available;
  - free capacity that covers the request: CPU, memory, GPUs **and disk** (`resources.disk_mb`).

  Free capacity = offered capacity − the reservations of the node's active leases. Offered capacity = hardware ×
  the owner's share limits (agent config). The default share is 75 % of logical CPUs (at least 1), 75 % of RAM, and
  every offerable GPU.
- **GPUs:** the server reserves a GPU **count** per node. The agent picks the concrete devices, which are free
  offerable GPU UUIDs, when it accepts the lease, and rejects it with `insufficient_capacity` if none is free. `Lease`
  has no GPU field in v0.1 (amended 2026-11-05, T06).
- **Reservations are held until confirmed** (from E8, HTCondor). An attempt that is lost but may still be running keeps
  its reservation on the node until its lease is confirmed dead: the attempt is absent from a `Hello`, or
  `lease_ttl_s` has passed. The same holds for a job cancelled on an unreachable node, even though its state becomes
  `cancelled` at once. This prevents double-booking (AC-10).
  - **A finished attempt keeps its reservation too, until the node frees it.** That is the node's first `Heartbeat`
    that no longer lists the lease in `running`. Only then does the capacity come back, and the offer cap is
    re-armed.
  - Older agents list only running jobs, so for them that heartbeat comes at most one interval after
    `JobFinished`.
  - Seeing a finished lease in `running` is normal: it is being cleaned up. It never revives the job, and it is
    never an error.
  - Amended 2026-11-08, from ACC-1 round 3. The server freed the reservation on `JobFinished`, while the agent
    held it through cleanup. So in AC-10 the server offered slots that Omarchy still held: 115 offers were refused
    with `insufficient_capacity`, against 60 accepted.
- **Offer cap.** A lease that is rejected, or not accepted within 10 s, does not count as an attempt. Each job counts
  these offers, though:
  - after 10 failed offers, the job stays `queued` with a `reason`, which is shown by `GET /v1/jobs/{id}` and by
    `estimate`, and it gets no more offers **until an eligible node changes**: it connects or reconnects, sends an
    `InventoryUpdate`, is resumed, a new node joins, or **one of its leases ends** (its capacity comes back). The
    count then starts over, so a job is never stuck after the node it was waiting for becomes ready or free
    (amended 2026-11-05, T06; "a lease ends" added 2026-11-07, ACC-1 round 2, where 3 of 100 jobs stayed
    `queued` forever after 10 refusals of a busy node);
  - the same (job, node) pair is not offered again for 60 s.
- **Retries** prefer a node other than the one that just lost the lease.
- **Disconnection log.** Each node disconnection gets one row: last contact, when it was resolved, and whether it
  `recovered` or `requeued`. This is how `lease_ttl_s` gets tuned on real home networks.
- **Choice:** best fit, meaning the least free capacity left after placement. A tie goes to the node idle longest.
- **Atomicity:** placement and lease creation happen in one SQLite transaction, so a node can never be
  double-booked.
- **Timeouts:** the agent enforces `timeout_s`. The server also marks a job `timed_out` at `timeout_s + 60 s` if the
  agent never reports. The clock starts at `JobStarted`, or at lease acceptance while the job is still `assigned`;
  in the second case the image pull timeout is added, so a hung pull ends as `assigned → timed_out`.
- **Time:** all scheduler and lease logic takes an injectable clock, so tests run without real sleeps.

## 9. Sandbox, v0.1 driver: Podman

### 9.0 Platform profiles (from experiment E1, 2026-11-05)

| | Linux host | Windows: dedicated WSL2 distro |
|---|---|---|
| Who runs Podman | The dedicated unprivileged user `p2pc`, **rootless**: a systemd user session with cgroup delegation (the installer runs `loginctl enable-linger p2pc`). | **Root inside the dedicated distro.** The distro is the appliance and the agent is its only tenant. |
| User namespace | The rootless default: container root is the `p2pc` user's subuid range. | `--userns=auto`, **always**. Container root is an unprivileged subuid range. `/etc/subuid` and `/etc/subgid` contain `containers:2147483647:2147483648`. |
| cgroups | systemd (rootless delegation). | `cgroup_manager = "cgroupfs"`, and **`systemd=false` in `wsl.conf`**: all WSL2 distros share one cgroup v2 root, and a second systemd would fight over it. |
| GPU | CDI from `nvidia-ctk cdi generate`. | CDI from `nvidia-ctk cdi generate --mode=wsl` (`/dev/dxg` plus `/usr/lib/wsl`). No driver inside the distro. |
| Network | `--network=none` plus the egress proxy. | The same, and it is **mandatory**. All WSL2 distros of a Windows user share **one network namespace**: E1 measured the dedicated distro seeing the other distros' interfaces, Docker bridges and Tailscale. Never filter with iptables, because it would affect every distro. |
| Windows interop | Not applicable. | **Off**, and checked: `[interop] enabled=false` and `appendWindowsPath=false` in `wsl.conf`, no `WSL_INTEROP` in the agent's environment, no Windows `PATH` entries, and no drvfs or 9p mounts. Any of those makes the node not ready. The `WSLInterop` entry in `binfmt_misc` is **not** a signal: binfmt_misc is shared by every distro of the WSL VM, so it is there whenever another distro keeps interop on. On 2026-11-05 a Windows `.exe` failed to run inside `p2pc-node` even with that entry present and `WSL_INTEROP` set by hand. `doctor` shows the entry as a note (amended 2026-11-05, after the T05b real run). |

**Which Linux** (decided 2026-11-06, in the first real acceptance run):
- The server and the native Linux node run on any Linux with systemd, on x86_64 or aarch64. Both are static (musl)
  binaries, so the installers check what they really need, one requirement at a time:
  - for both: root, a running systemd, `runuser`, `useradd`, `sha256sum`, `tar`, and `curl` or `wget`;
  - for a node, also Podman >= 4.9, crun and cgroup delegation (`setup-host.sh`).
- **Tested platforms:** Ubuntu 22.04, 24.04 and 26.04; Debian 12 and 13; Arch Linux, which is the acceptance lab's.
- **Any other distribution** gets one warning line ("not a tested platform"), never a refusal. Refusing a machine that
  meets every requirement, only because of its name, contradicts U1.

**How the Windows agent stays up** (decided 2026-11-06, T14b2):
- A per-user Scheduled Task, "P2PC node", runs
  `conhost.exe --headless wsl.exe -d p2pc-node -u root --exec /usr/local/sbin/p2pc-node-run`.
- **Its triggers** (from the T14b2 real run):
  - a time trigger that repeats every 5 minutes, with IgnoreNew. It works as a watchdog: the node is back within
    5 minutes after `wsl --terminate`, a WSL update, or any exit, which restart-on-failure does not catch (wsl.exe
    then ends with 0). A non-elevated user can register it;
  - an at-logon trigger **for this user only** (`New-ScheduledTaskTrigger -AtLogOn -User <the user>`), always,
    elevated or not. A normal, non-elevated user can register it: tested with a Limited, medium-integrity token.
    Windows refuses only a logon trigger for any user (`-AtLogOn` with no user, or `schtasks /SC ONLOGON`), and P2PC
    never uses one. If registering it fails anyway, the installer registers the time trigger alone and says the node
    starts within 5 minutes of signing in.
  - *Corrected 2026-11-06:* the earlier "only when elevated" came from a test with `runas /trustlevel:0x20000`. Its
    restricted token cannot reach CIM at all, so that test proved nothing about logon triggers.
- **Stopping it:** `Stop-ScheduledTask` kills only `conhost`, and the `wsl.exe` children keep the agent running. So
  `install.ps1 -Stop` disables the task and runs `wsl --terminate p2pc-node`, and `-Start` enables it and starts it.
  A second runner waits on the runner lock instead of exiting, so a task instance always supervises the agent.
- The attached `wsl.exe` keeps the distro running. The installer never changes the user's `.wslconfig`:
  `instanceIdleTimeout` would affect every distro.
- `p2pc-node-run` waits for a fresh boot status and restarts the agent with a backoff. It logs to
  `/var/log/p2pc/agent.log`, rotated by size, because the distro has no journald.
- **Terminal exits stop the node for good, watchdog included** (amended 2026-11-06, fourth T14b2 review). The
  terminal codes are 6 (too old), 7 (removed from the server) and 8 (not joined). Since the 5-minute trigger, a task
  that simply ends would start again within 5 minutes, forever: it would boot the WSL VM on a family PC and dial the
  server with a revoked identity. So:
  - on a terminal code, `p2pc-node-run` writes `node-run.status` and exits with **64**;
  - the task's action is a small user-owned wrapper (`%LOCALAPPDATA%\P2PC\node-task.cmd`, run through
    `conhost.exe --headless cmd.exe /c`), which runs the `wsl.exe` line above;
  - on exit 64, the wrapper **disables the task** (`schtasks /Change /DISABLE`), and writes why next to itself
    (`stopped-by-node`, with the code). The PC then runs nothing of P2PC until the user acts;
  - `-Join` and `-Start` enable the task again, and so does `-Upgrade` when the reason was 6 (too old). `-Status`
    shows the reason and what to run (a new token for 7 and 8, a newer image for 6);
  - an ordinary end (exit 0, `wsl --terminate`, a WSL update) still leaves the task enabled, so the watchdog brings
    the node back.
- The H2 app will take this role over.

E1 numbers, on an RTX 5070 Ti with Podman 4.9.3 and NVIDIA Container Toolkit 1.20.1:
- **Startup:** the distro starts in 0.78 s with the WSL VM already running, and `podman run` adds 113-150 ms with a
  cached image.
- **GPU:** CUDA vectorAdd passed through CDI.
- **Network:** `--network=none` blocked the internet, the host's loopback services and the tailnet.
- **Limits and privileges:**
  - the memory limit was enforced (exit 137);
  - CapEff and CapBnd were 0;
  - NoNewPrivs was 1;
  - the seccomp filter was on.

The node needs:
- Podman ≥ 4.9, with cgroup v2 and crun. Rootless on Linux; see §9.0 for WSL2.
- For GPUs, the NVIDIA Container Toolkit CDI spec:
  - on native Linux: `nvidia-ctk cdi generate`;
  - on WSL2: `--mode=wsl`.

The agent detects what is present and reports it in its inventory. It never installs anything by itself.

On WSL2 (from E8, BOINC):
- **CDI at boot.** The installer configures a distro boot step that regenerates the CDI spec
  (`nvidia-ctk cdi generate --mode=wsl`) when the spec is missing or older than the Windows driver libraries. The
  agent only detects the state and reports `cdi_stale`.
- **The distro.** It is fixed (`p2pc-node`), and the agent never falls back to another distro. It ships as a
  pre-built, pinned, hash-verified rootfs: nothing is installed with apt at first launch.
- **Agent identity.** The agent's identity key and state live inside the distro, in `/var/lib/p2pc`. Re-importing the
  distro requires exporting that directory first, or the node must re-enrol. T14 documents this.

### Fixed `podman run` arguments

The job cannot change any of these. They are built as an argv, never a shell string:
- `--rm`
- `--network=none`
- `--http-proxy=false`: Podman would otherwise copy the host's `HTTP(S)_PROXY`, `FTP_PROXY` and `NO_PROXY` into the
  container, and those may hold the owner's credentials. The agent also removes those variables, in both cases,
  from the environment of every `podman` command it runs.
- `--cap-drop=all`
- `--security-opt=no-new-privileges`
- `--pids-limit=2048`
- `--userns=auto` on the WSL2 profile (§9.0)
- `--memory=<m>m --memory-swap=<m>m`
- `--cpus=<c>`
- `--tmpfs /tmp:rw,nosuid,nodev,size=<min(disk, 4096)>m`
- `-v <job>/inputs:/inputs:ro,U`
- `-v <job>/outputs:/outputs:rw,U`
- `-v <job>/p2pc:/.p2pc:ro,U` (holds the shim and the egress socket)

  `U` makes Podman hand the directory to the container's mapped root. Under `--userns=auto` (WSL2) that root is an
  unprivileged subordinate uid, which could otherwise neither read `inputs/` nor write `outputs/`. With rootless
  Podman on Linux it changes nothing. Measured on the WSL2 node in T08: the real-Podman tests pass with it.
- `--entrypoint /.p2pc/shim`
- `--env-file <0600 file>`: Podman copies it into the container's config at `create`, so the agent deletes it right
  after `podman create`, whether or not that succeeded
- `--label p2pc.lease=<id>`
- `--cgroup-parent=<the lease's own cgroup>`: `/p2pc/<lease_id>` with cgroupfs on WSL2, or a
  `p2pc-<lease_id>.slice` under the `p2pc` user's delegated tree on Linux. The agent creates it before the run and
  removes it after cleanup. It is how the agent reads the job's `memory.events` and `pids.events` (see Limits and
  status).
- `--name p2pc-<lease_id>`
- with a GPU: `--device nvidia.com/gpu=<uuid>` on Linux. On WSL2, where the CDI spec only offers `all`, it is
  `--device nvidia.com/gpu=all`, used only when the node has exactly one offerable GPU (from E1 and E8)
- then the image, `--`, and the command

**Never:** `--privileged`, host network or namespaces, the Podman socket, or host paths beyond the three per-job
directories. The one exception is H2's persistent volumes (ADR-015): agent-created, per-account directories named by
hash, never a path from the JobSpec, mounted with `:U` (or `:idmap` only if a later H2 E11 run shows it works) only
into service and template jobs of their account, size-limited, checked without following links before every mount
and deleted without following links (H2 §11.1, §11.3, SI-H2-9), and nothing else (amended by O-16, H2 §4.3,
2026-11-11).

### Shim (`p2pc-shim`, static musl)

- **Egress bridge.** If `/.p2pc/egress.sock` exists, the shim listens on `127.0.0.1:3128` inside the container and
  bridges each connection to the socket. It then sets `HTTP_PROXY`, `HTTPS_PROXY` and their lowercase forms to
  `http://127.0.0.1:3128`, and `NO_PROXY=localhost,127.0.0.1`.
- **Process.** It execs the user's command and forwards SIGTERM and SIGINT. It reaps zombies, acting as PID 1.
- **Exit.** It exits with the child's status.

### Egress proxy (in the agent, one per job)

- **Socket.** Only when `egress.allow` is non-empty: an HTTP proxy on a unix socket in `<job>/p2pc/`. It supports
  `CONNECT host:port` and absolute-URI plain HTTP.
- **Allowed requests.** The host must match the allowlist on whole labels. The port must be in `{80, 443}`.
- **One request per plain-HTTP connection.** The proxy forwards exactly the declared body (`Content-Length`, or
  chunked up to the last chunk) and then closes, so a pipelined request never reaches the upstream unchecked. A
  `Connection` header that names `content-length`, `transfer-encoding` or `host` gets `400`.
- **Socket permissions.** Each job's socket directory is bind-mounted with Podman's `:U` option, so it belongs to
  the container's (mapped) root. The socket is created with mode 0600, inside a 0700 staging directory, so there
  is no window where the umask leaves it wider. This works under `--userns=auto`.
- **DNS and addresses.**
  - The proxy resolves DNS itself.
  - It rejects a resolved IP in any deny range: loopback, RFC 1918, `100.64.0.0/10`, link-local, `fc00::/7`,
    multicast, unspecified, broadcast, the host's own addresses, and IPv4-mapped or IPv4-compatible IPv6 forms of
    all of these.
  - It then connects to **exactly that IP**, which defeats DNS rebinding.
  - **The owner's LAN, beyond RFC 1918** (from the T09 review):
    - for every global-unicast IPv6 address on any interface, the containing **/56**, configurable
      (`lan_ipv6_prefix`, default 56). A /128 from DHCPv6 still blocks the LAN around it, and so do neighbouring
      /64s delegated from the same /56;
    - the destinations of on-link routes, IPv4 (`/proc/net/route`) and IPv6, meaning routes with no gateway. The
      default route and on-link routes wider than /8 (IPv4) or /32 (IPv6) are **not** added, because they come from
      point-to-point links or full-tunnel VPNs rather than a LAN, and denying them would deny everything. They are
      logged once as a warning instead;
    - the node's own **public** addresses as observed by iroh (QUIC address discovery). The agent passes them to the
      proxy, which stops hairpin NAT into port-forwarded LAN services, such as a NAS on 443.
  - **Residual paths the proxy cannot close,** documented in the threat analysis: domain fronting on shared CDN IPs,
    exfiltration to an allowed domain, and VPN routes to public-looking ranges. In WSL2 NAT mode the distro has no
    IPv6 at all.
  - IP literals are always refused.
- **Accounting.** It logs the destination host and the byte counts. It never logs the payloads.
- **Test vectors** (from E8: these are the gaps found in Bacalhau's gateway). At least:
  - `evilexample.com` and `example.com.evil.net` against `example.com`;
  - a trailing dot and uppercase;
  - IPv4 and IPv6 literals, including bracketed and IPv4-mapped forms;
  - `user@host` and `host/path`;
  - `CONNECT` to a port that is not allowed.

### Limits and status

- **Disk.** Every 2 s the agent measures the size of `outputs/` and the container's writable layer. Over
  `resources.disk_mb` → kill, with outcome `error` and `error="disk_limit"`. The measurement **fails closed**:
  - each file counts as the larger of its apparent size and its allocated blocks, so `fallocate` cannot hide space;
  - reaching the entry budget counts as over the limit;
  - a measurement that fails three times in a row counts as over the limit.

  v0.1 polls, so a very fast writer can briefly overshoot. That is acceptable only because v0.1 runs the owner's own
  jobs (SI-1). Third-party code (Milestone 4) runs in VMs with fixed-size disks.
- **Disk floor.** Whatever the per-job accounting says, if free space on the agent's data disk falls below the larger
  of 5 GiB and 5 %, the agent kills its running jobs (`error="disk_floor"`) and rejects new leases
  (`insufficient_capacity`) until space recovers. The owner's disk always comes first.
- **Images.** Before pulling, the agent reads the remote manifest's layer sizes, with `skopeo inspect --raw` where
  the node has it, or `podman manifest inspect`. An image over the configured cap is refused without being pulled,
  and anything a refused or failed pull left behind is removed.
  - Measured in T08 on the WSL2 node: Podman 4.9's `manifest inspect` cannot read a single-image OCI manifest, only a
    manifest list. The node image therefore ships `skopeo` (T14b).
  - If neither tool can read the manifest, the agent pulls, checks the size and removes an over-cap image. The disk
    floor still protects the owner's disk.
  - **Pull only what is missing** (decided 2026-11-06, in the first real acceptance run, where 100 jobs on one image
    hit Docker Hub's anonymous pull limit). When the image is already in the node's store, the agent neither reads the
    remote manifest nor pulls: no registry request at all. This holds for a digest and for any tag except `latest`
    (an image with no tag is `latest`). Those two are pulled for every attempt, like Kubernetes' `IfNotPresent`
    default. The size cap of an image already in the store is checked against its local size.
  - Pulls of the same image on one node are shared: while one pull runs, other leases for that image wait for it
    instead of starting their own.
- **Podman failures are not job exits.** If the container never started (for example, a missing CDI device), the
  outcome is `error` with `error="start_failed"`, never `exited` with Podman's own 125/126/127. If the agent loses
  track of a running container's exit, it stops it with the usual SIGTERM, grace and SIGKILL sequence, removes it,
  and reports `error="lost_exit_code"`. Cleanup always runs.
- **Timeout.** SIGTERM, then 10 s of grace, then SIGKILL. The outcome is `timed_out`.
- **Cancel.** The same SIGTERM, grace and SIGKILL sequence.
- **Memory.** The outcome is `error` with `error="memory_limit"` when the lease cgroup's `memory.events` shows
  `oom_kill > 0`, or when Podman reports `OOMKilled`. Exit code 137 alone is not enough. The T14a test run measured
  this: Podman 4.9.3 with conmon 2.1.10 and cgroupfs on WSL2 **never** sets `OOMKilled`, and emits no `oom` event,
  while the kernel's `memory.events` in the parent cgroup counted `oom_kill 1`.
- **Logs on the node.** The agent caps what it reads and spools per attempt at 64 MiB. It then sends one truncation
  marker and keeps draining the pipe, so the job never blocks and the owner's disk never fills.
- **No checkpointing in v0.1.** An agent restart or a reboot makes running jobs lost, and they are retried per §7.
- **Outputs.** After exit, the agent uploads regular files under `outputs/` (no symlinks), up to `outputs.max_mb`.
  It then deletes the job directory.
- **Optional gVisor.** If the agent config sets `runtime = "runsc"` and runsc works, the agent adds
  `--runtime=runsc` and reports the class `container-gvisor`. This is optional in v0.1.

## 10. Networking and exposure

- **iroh endpoints.** Both the server and the agents run an iroh 1.x endpoint (check the current docs.rs API).
  - Relays: by default, the public n0 relays, which are meant for development. A `relays = [...]` config option
    accepts a self-hosted `iroh-relay`, and the docs show how to run one.
  - Join tokens include the relay hints.
- **REST API.**
  - Binds `127.0.0.1:7477` by default. A localhost connection does **not** bypass authentication.
  - Option A: bind elsewhere behind a TLS reverse proxy (documented).
  - Option B: `p2pc proxy --listen 127.0.0.1:7477`. The CLI connects to the server's NodeId on ALPN
    `p2pc/http/1`, and each local TCP connection is tunnelled over one QUIC bidirectional stream. The API key is
    still required. This is how a laptop on 4G uses a home server with no open ports.
  - **Server address.** The server has a non-secret address, `p2pc_srv_<base32 payload>`. The payload holds the
    server's NodeId and relay hints, in the join-token payload format without the code or the expiry.
    - `p2pc-server init` prints it with the admin key, and `GET /v1/server` returns it.
    - A CLI profile whose `server` is such an address reaches the API through the tunnel, with no separate
      `p2pc proxy` process.
  - **Slow clients.** Every connection gets these limits:
    - 10 s to read the request headers;
    - 30 s to read the body, and 30 s for the whole request;
    - 60 s idle on keep-alive.

    Streaming routes, such as following logs (T10), opt out of the whole-request limit explicitly and use an idle
    limit instead. At most 256 connections are open at once; this is configurable. The same limits apply to
    connections tunnelled by `p2pc proxy`.
    - **Tunnel budget** (decided 2026-11-05, while reviewing T05). Tunnelled streams also have their own total cap:
      128 by default, and always **below** the REST cap. The server refuses to start with a config where it is not.
      NodeIds cost nothing to make, so anonymous tunnel peers must never be able to take every REST slot and lock
      out local clients.
- **Nodes** never listen on a TCP or UDP port that is reachable from outside, beyond what iroh needs for outbound
  QUIC. The one exception (ADR-016, amended by O-16, H2 §4.3, 2026-11-11): on the H2 hub PC, only while the hub is
  enabled, the hub's own iroh endpoint accepts incoming QUIC on the UDP sockets `p2pc-net` binds for it under the
  address hygiene below, every ALPN gated by a ticket, a token, a key or a paired NodeId and under pre-auth limits;
  on a joining PC, the app's relay-only invite listener (no IP transport) accepts the two `p2pc/invite/1` exchanges
  of one join (open, then hand-over, both from one phone) while the invite is valid. Nothing else listens beyond the
  loopback REST listener, and agents still only dial out (H2 §10.5). The invite-listener clause is subject to E10
  (H2 §18), which is pending: no code builds the invite listener until E10's invite-listener check passes. If that
  check fails, that clause lapses until one reviewed change amends hard rule 4, H1 §10 and ADR-016 together. A
  joining-PC listener with an IP transport is never covered.
- **Address hygiene (from experiment E4, 2026-11-05).** iroh 1.x advertises every local address by default. E4 saw
  the public IP, a Tailscale address and container-bridge addresses, and it picked the Tailscale path on its own.
  Agents and the server therefore MUST:
  - build the endpoint **without port mapping**: no UPnP or NAT-PMP, so nothing asks the owner's router to open a port;
  - **not advertise or use** addresses in `100.64.0.0/10`, link-local addresses, or container and VM bridge networks
    (Docker or Podman bridges, `virbr*`, `vEthernet*`);
  - by default, advertise only the addresses of the interface that carries the default route, with a config
    override (`direct_addresses = "default-route" | "none" | [<cidr>...]`). `"none"` means relay-only;
  - not publish addresses to third-party discovery services; addresses travel only inside join tokens and
    connections.

  Measured in E4 with n0's public relay: a WSL2-NAT node and a peer on the same home LAN got **no direct path**, so
  the traffic stayed on the relay, at about 97 ms RTT and 9 Mbit/s. Production needs our own relays (ADR-003).

## 11. Metering and caps

- **Units.** 1 unit = 1 vCPU-hour reserved. 1 GPU-hour = 10 units, configurable on the server. Memory is not billed
  in v0.1, but it is recorded.
- **Ledger.** `usage_records` is append-only, with one row per attempt that ran or held a reservation and has ended,
  whether it finished, timed out, was cancelled or was **lost**. When the agent never reported the attempt's usage (a
  lost attempt, the watchdog, or a cancel on an unreachable node), the server writes its own **estimate**: the
  reservation, from the start (or acceptance) to the end it observed. That row has `estimated = 1`; rows the agent
  reported have `estimated = 0`. `GET /v1/usage` is grouped, so it returns `estimated_attempts` per group and in
  the total: how many of those rows are server estimates. The daily cap
  and `GET /v1/usage` count the same rows (amended 2026-11-06, T06). Columns:
  - `job_id`, `attempt`, `node_id`, `key_id`, `account_id`;
  - `started_at`, `ended_at`;
  - reserved CPU and GPU time, in milliseconds (`reserved_cpu_ms`, `reserved_gpu_ms`);
  - used CPU time, in milliseconds (`used_cpu_ms`, from cgroup stats);
  - `max_rss_mb`;
  - `units` (an integer, in milli-units);
  - `estimated` (0 or 1, see above).
- **Caps.** When a job is created, its estimate (resources × timeout) is checked against the key's
  `daily_unit_cap`, minus the units used or reserved in the current UTC day. If the cap would be exceeded →
  `402 cap_exceeded`. No money exists in v0.1: the word "units" is deliberate.

## 12. Storage

- **SQLite** in WAL mode, through sqlx, with migrations in `crates/p2pc-server/migrations/`. Queries go through a
  repository module, ready for Postgres later. Only bound parameters.
- **Data dir:**
  - `$P2PC_DATA_DIR`;
  - as a system service, `/var/lib/p2pc-server`: the systemd unit sets `P2PC_DATA_DIR` (amended 2026-11-05, so that
    it never collides with a node's `/var/lib/p2pc` on the same machine);
  - otherwise `~/.local/share/p2pc-server`.
- **Artifacts:** `<data>/artifacts/<job_id>/<attempt>/…`, kept for 7 days by default (`[storage] retention_days`),
  with a GC loop. GC also deletes the staging directories of attempts that never finalised, after 1 hour. Job rows
  stay.
- **Logs:** `<data>/logs/<job_id>/<attempt>.ndjson`.

## 13. Security invariants (each one MUST have a test)

| ID | Invariant |
|---|---|
| SI-1 | The agent rejects a lease whose `account_id` is not its enrolled owner. |
| SI-2 | Containers always run with the fixed arguments of §9. A unit test asserts the exact argv, and a negative test shows that job input cannot inject arguments. |
| SI-3 | With no egress list, the container has no network: a TCP connect to `1.1.1.1:443` fails. |
| SI-4 | With an egress list, the proxy refuses private, loopback, CGNAT, link-local, ULA and the host's own addresses, including DNS rebinding and IPv4-mapped IPv6. A table-driven test covers every deny range. |
| SI-5 | Only allowlisted domains get through, on whole labels: `evilexample.com` does not match `example.com`. |
| SI-6 | API keys and join codes are stored hashed. Tests assert that no secret appears in logs, `Debug` output or errors. |
| SI-7 | Every object read or write is filtered by the authenticated principal's `account_id` and `project_id`. Tests include a cross-account negative case. |
| SI-8 | Stale epochs are fenced: a message for an old lease is rejected and yields `Cancel`. |
| SI-9 | Output paths cannot escape the job directory: no `..`, absolute paths or symlinks, on the agent or on the server download. |
| SI-10 | Protocol frames over 1 MiB or malformed JSON close the connection without panicking. An unknown message type decodes to `Unknown` and gets `Error{code:"unsupported_message"}` (§6). Fuzz or proptest the decoder. |
| SI-11 | Join tokens are single-use and expire, checked against the server's own row and never the payload. Consuming a token is atomic: with two concurrent `Join`s, exactly one node is created. A retry from the same NodeId is idempotent. |
| SI-12 | The agent opens no listening socket reachable from outside. A test enumerates its sockets. |
| SI-13 | A partitioned agent stops its running jobs before the server requeues them (`agent_lease_ttl_s + 10 <= lease_ttl_s`). Tested with injectable clocks on both sides. |

## 14. Acceptance criteria for the v0.1 release (scripted in `tests/acceptance/`)

They run on real machines: a Linux node with an NVIDIA GPU, a WSL2 node with an NVIDIA GPU and a client on another
network.

| ID | Criterion |
|---|---|
| AC-1 | Server install to admin key: ≤ 10 min, one command. Join a node: ≤ 2 min, one command. |
| AC-2 | CPU job round trip (`print(6*7)`): logs, exit 0, `succeeded`. Overhead from submit to start ≤ 5 s when the image is cached. |
| AC-3 | GPU job (`nvidia-smi`, and a PyTorch matmul on `cuda`) succeeds on both Linux and WSL2. |
| AC-4 | Egress: `pip install requests` works with the PyPI allowlist. A connection to the LAN gateway, the host, `100.64.0.1` or another domain fails. |
| AC-5 | `/inputs` (inline, up to 512 KiB) and `/outputs` (up to 1 GiB) round trip with sha256 verification. |
| AC-6 | Kill the node's network mid-job. The job is retried on the other node, and the first node cannot report back for the old attempt. |
| AC-7 | Cancel and timeout: the job stops within 15 s and the container is gone. |
| AC-8 | A client on another network (4G) uses `p2pc proxy`. Neither the server nor the nodes have open ports. |
| AC-9 | The MCP server works from Claude Code with a capped key. The cap and the image allowlist are enforced. |
| AC-10 | Run 100 jobs, with 4 concurrent per node. No double booking, no lost jobs, and the ledger totals match. |
| AC-11 | Negative tests for SI-1 to SI-12 pass. An internal pentest from a separate machine finds no critical issue. |
| AC-12 | `cargo deny check`, the secret scan, the SBOM and `SECURITY.md` are in place, and the docs let a stranger do AC-1 to AC-3. |

## 15. Work breakdown

Each task is a PR. "Depends" lists the tasks that must be merged first.

| Task | Title | Depends | Notes |
|---|---|---|---|
| T01 | Workspace scaffold | — | All crates as stubs, licenses and SPDX headers, `rust-toolchain`, lint and CI workflow, `cargo deny`, the `p2pc-proto` validation skeleton. |
| T02 | `p2pc-proto`: API and protocol types, validation and framing | T01 | JobSpec validation table (§7), messages (§6), codec with limits, proptest. |
| T03 | Server core | T02 | Config, data dir, SQLite migrations, accounts, projects, keys, auth middleware, problem+json, `/healthz`, OpenAPI generation and the drift test. |
| T04 | Jobs API and state machine | T03 | Endpoints of §7 (except logs and outputs streaming), idempotency, caps, estimate. |
| T05 | Node gateway (server) | T02, T03 | iroh endpoint, address hygiene (`p2pc_proto::net`), join tokens, `Join`/`Hello`/`Heartbeat`/`HeartbeatAck`, node registry, `p2pc/agent/1`, the `p2pc/http/1` tunnel. |
| T05b | Agent connection | T02, T07, T05 (for the `net` module) | `join`, `run`: `Hello`, heartbeats, the agent-side lease timer (SI-13), reconnect backoff, `InventoryUpdate`, routing of leases to traits. |
| T06 | Scheduler and leases | T04, T05 | §8, fencing, reconnect reconciliation, injectable clock, property tests (no double booking). |
| T07 | Agent core | T02 | Identity, config (share limits), inventory (CPU, RAM, NVIDIA via NVML or `nvidia-smi`, Podman and CDI detection), platform profile. No network: the connection is T05b. |
| T08 | Sandbox driver (Podman) and shim | T07 | §9 argv builder (SI-2), lifecycle, limits, log capture, outputs, the `p2pc-shim` crate. |
| T09 | Egress proxy | T07 | §9 proxy, deny ranges (SI-4/5) and the unix-socket bridge with the shim. |
| T10a | Agent lease executor | T05b, T08 | `LeaseHandler`/`LeaseSupervisor` on top of `Sandbox`: admission, run, `LogChunk`, uploads, `JobFinished`, cancel, drain, SI-13 `stop_all`. |
| T10b | Server logs and outputs | T04, T05, T06 | `LogSink`, NDJSON endpoint (page and follow), upload streams with staging, publishing on `JobFinished`, download, GC. |
| T11a | `p2pc-client` and the CLI core over REST | T02 | The typed client crate (Apache-2.0) and `login`, `whoami`, `run` (follow by polling, `--detach`), `estimate`, `jobs`, `status`, `cancel`, `machines`, `join-token`, `keys`, `audit`, `completion`. Tested against a mock server; it never depends on `p2pc-server`. |
| T11b1 | CLI and client: the tunnel | T05, T11a | `p2pc_srv_` profiles through the tunnel, `p2pc proxy`, the client-side address hygiene, and the T11a, T12 and T05 review carry-over. |
| T11b2 | CLI: logs, results and usage | T10b, T06, T11b1 | `run` following live logs, `logs`, `results` (sha256-checked) and `usage`. |
| T12 | MCP server (`p2pc mcp`) | T11a (T11b for logs and results) | Tools: `p2pc_estimate`, `p2pc_run`, `p2pc_status`, `p2pc_logs`, `p2pc_results`, `p2pc_cancel`, `p2pc_machines`. Uses the official Rust MCP SDK (`rmcp`). |
| T13 | Python SDK | T04 | `httpx` client, typed models, `jobs.run().wait()`, log iterator, outputs download, pytest with a mock server. |
| T14a | Node images and host setup | — | The WSL distro builder (`deploy/wsl/`: a pinned, verified Ubuntu 24.04 rootfs with Podman, the NVIDIA toolkit and the boot-time CDI refresh), `install.ps1` (with upgrade that keeps `/var/lib/p2pc`), `test-distro.sh`, and `deploy/linux/setup-host.sh`. |
| T14b1 | Server packaging and release artifacts | T03, T05 | Static musl binaries, `SHA256SUMS` and SBOM, a hardened `p2pc-server.service`, and `install-server.sh` (one command to the admin key, AC-1). |
| T14b2 | Node packaging | T05b, T08, T14b1 | The agent's rootless systemd user unit, `install-node.sh` (join through stdin), the agent inside the WSL image, and the T14a2 carry-overs. |
| T15 | Acceptance suite and docs | all | `tests/acceptance/` scripts for AC-1 to AC-12, plus the README quick start. |

Parallel lanes once T02 lands:
- server: T03 → T04 → T06;
- agent: T07 → T05b → T08 → T09 (T09 started early on top of T02);
- clients: T11a (now, against a mock server), T13, then T12 and T11b.

## 16. Open items tied to experiments

| Experiment | Question | Decision it affects |
|---|---|---|
| E1 | **Done (2026-11-05): it works.** Podman with CDI on `/dev/dxg` passes CUDA. The network namespace and the cgroup root ARE shared with the other distros. | §9.0 platform profiles: root inside the distro with `--userns=auto`, `systemd=false`, and `--network=none` mandatory. |
| E2 | Firecracker inside WSL2 and on Linux. | The VM-class driver for Milestone 4. It does not block v0.1. |
| E3 | gVisor nvproxy with the node's NVIDIA driver version. | Whether `container-gvisor` with a GPU is offered on Linux in v0.1. |
| E4 | **Part 1 done (2026-11-05):** iroh advertises every local address (§10, address hygiene). A WSL2-NAT node ↔ a LAN peer stays on the relay (97 ms, 9 Mbit/s on n0's relay). Part 2 (4G/CGNAT) is pending. | Relay sizing. Whether `p2pc proxy` is good enough for interactive use. |
