# p2pc: Python SDK for P2PC

Run batch jobs (an OCI image, a command and resources) on your own machines through the
P2PC control plane. This package wraps the Jobs API (§7 of the v0.1 spec) with typed models,
client-side validation, log streaming and verified output downloads.

- Python 3.11 or newer.
- Runtime dependencies: `httpx` and `pydantic` v2.
- A synchronous `Client` and an `AsyncClient` with the same surface.

## Install

From a checkout of this repository:

```sh
uv pip install ./sdk/python        # or: pip install ./sdk/python
```

The package is not published to PyPI yet.

## Quick start

```python
import p2pc

client = p2pc.Client()  # reads P2PC_API_URL and P2PC_API_KEY

job = client.jobs.run(
    image="docker.io/library/python:3.12-slim",
    command=["python", "-c", "print(6*7)"],
    cpu=2,
    memory_mb=4096,
).wait()

print(job.status, job.exit_code)  # succeeded 0
for line in job.logs():
    print(line.stream, line.data, end="")
for out in job.outputs():  # files written to /outputs
    print(out.path, out.size, out.sha256)
```

`jobs.run` is an alias of `jobs.create`. `wait()` polls until the job reaches a terminal state
(`succeeded`, `failed`, `timed_out`, `cancelled` or `lost`) and raises `TimeoutError` if you
pass `timeout=` and it elapses.

### Inputs, egress and outputs

```python
job = client.jobs.run(
    image="docker.io/library/python:3.12-slim",
    command=["python", "/inputs/main.py"],
    files={
        "/inputs/main.py": "print(open('/inputs/data.csv').read())",
        "/inputs/data.csv": b"a,b\n1,2\n",
    },
    env={"GREETING": "hello"},  # values are never logged by the SDK
    egress=["pypi.org", "files.pythonhosted.org"],  # everything else is refused
    timeout_s=600,
    idempotency_key="nightly-report",  # a retry returns the same job
).wait(timeout=900)

for out in job.outputs():
    # Streams to results/<out.path>, verifies size and sha256 against the listing and the
    # server's X-P2PC-SHA256 header, and refuses paths that would escape the directory. A
    # failed or tampered download leaves nothing behind.
    job.download_output(out.path, "results")  # or client.jobs.download_output(job.id, ...)
```

Downloads are capped, and a file over the cap is refused before any byte is fetched:

- `job.download_output(...)` uses the **job's own `outputs.max_mb`** as the cap, even above
  1 GiB, up to the server's maximum of 10,240 MiB (it is the most the job can collect, so no
  honest file is bigger). A job without an `outputs` limit uses 1 GiB.
- `client.jobs.download_output(job_id, ...)` has no job to ask, so the default stays **1 GiB**.
  Pass `max_bytes=` to lower it, or to raise it explicitly (never above 10,240 MiB).

A body longer than the announced size stops at the first excess chunk.

The server sends the file's sha256 in `X-P2PC-SHA256`. If it differs from the listing, the
download is refused before any byte is stored; if the bytes do not hash to the listed digest,
the temporary file is discarded. Both raise `ChecksumMismatchError` (`code="checksum_mismatch"`),
and the message says what was announced and what arrived.

An entry whose retention has passed (`out.expired`), or a download the server answers with
`410 Gone`, raises `NotFoundError` with the code `output_expired` (`status` is 410).

The async download can be cancelled safely, for example with `asyncio.timeout`: the
cancellation is delivered once the worker thread that is running has finished, and then the
temporary file, the directories the download created and a file it had just renamed into place
are removed. A file that existed before is never deleted.

### Following logs

```python
job = client.jobs.run(
    image="docker.io/library/python:3.12-slim",
    command=["python", "-u", "-c", "import time\nfor i in range(3): print(i); time.sleep(1)"],
)
for line in client.jobs.logs(job.id, follow=True):  # ends when the job's log does
    print(line.seq, line.stream, line.data, end="")
```

Every line is `{seq, stream, ts, data}`: `stream` is `"stdout"` or `"stderr"`. Past 64 MiB per
attempt the server stores one last `stderr` line with `line.truncated` true.

Without `follow` you get one page: what is stored now with `seq >= since_seq` (an empty page for
a job with no logs yet). `since_seq` is **inclusive**, so resuming at `last_seq + 1` never
repeats a line.

`follow=True` follows the job the way `p2pc logs --follow` does. The server may end a stream
before the job is over (after 60 s without a new line, or on an internal error), so a stream
that ends proves nothing, and neither does a `404` or an empty page before the attempt is over.
The SDK reads again from `last_seq + 1`, after a beat (1 s, doubling to 5 s), until the job is
final or a later attempt exists. Only a read that **began after** that point ends the log, so a
job that stays silent for minutes is followed to its end and no line is lost or repeated: a line
below the next expected `seq` (one the server sends again after a reconnect) is dropped, as in the
CLI. A stream that stays silent for `follow_idle_timeout` seconds (default 300) is reopened too.
Without `attempt=`, a requeued job goes on with its next attempt, whose `seq` starts again at 0.

**Outages.** The server also *breaks* a followed body (it does not end it) on its 60 s idle cut and
on internal errors, and the network can drop at any time. A follow survives that, as the CLI does,
on the log stream and on the `GET /v1/jobs/{id}` checks alike. These errors are transient: a
broken stream, a connection error, a timeout, `429` and `5xx`. The SDK waits 1 s, doubling to a
maximum of 30 s (or the `Retry-After` the server sends, if longer), and reopens from the next
`seq`.

Outages are tracked **per route**, the log stream and the job check, and each one ends only
with a success on its own route. A stream that delivered a line, or stayed open for 10 s, is a
success of the log route even if it then breaks (the server's 60 s idle cut, the normal case for a
quiet job): the job is checked and the stream reopened, as many times as it takes, so a job quiet
for an hour is followed to its end. A `404` from the log route (an attempt that has not started
yet) is an answer from a working route and also ends its outage. A stream that fails to open (a
connection error, `429`, `5xx`), breaks straight away, or sends no response headers within
`follow_idle_timeout` is a failure; a timeout *after* the headers, on a body that worked, is not. A
job check succeeds when `GET /v1/jobs/{id}` does. When a job check fails, the SDK records it,
waits, and goes back to reading the logs (as the CLI does), so lines keep arriving while the job
route is down. Each outage may last **at most 5 minutes** of wall-clock time from the start of
its first failed request (a log route that hangs for `follow_idle_timeout` has used up that much
of it); then the follow raises
`P2PCConnectionError`, naming the route. So a job route that keeps failing gives up while logs
flow, and a long healthy stream never leaves an old outage behind to count against a later,
unrelated failure. `401`,
`403`, `404` on the job and `422` are permanent and raise at once.

**What counts as one outage.** An outage of a route is a run of failures of that route with no
success on it in between, and no *gap* of more than 30 s between the time its next request was
due and the time it started. In plain words: after a failure the SDK waits (up to 30 s) and
tries that route again; if it was busy for longer than 30 s with healthy work on the *other* route
in the meantime (for example a log stream that ran for six minutes), the next failure is not the
same outage but a new one, with its own 5 minutes, announced again through `on_outage`. The wait
the SDK scheduled itself is not part of the gap. So one failed job check before a six-minute
stream and one after it are two short outages, not one that gave up; while a job route that keeps
failing after the logs end gives up 5 minutes after its first failure. The SDK never prints; to be told
about an outage, pass `on_outage` (called once per outage, with its first error; on `AsyncClient` it
may also be an `async def`, which is awaited; on the sync `Client` an `async def` raises
`TypeError`, because nothing would await it) or listen to the `p2pc` logger (INFO):

```python
for line in client.jobs.logs(
    job.id, follow=True, on_outage=lambda err: print("reconnecting:", err)
):
    ...
```

Logs and outputs are **per attempt**. Without `attempt=` the server serves the latest one;
pass `attempt=K` (1-based) to pin an attempt, which is what you want when following a job that
may be retried. A pinned follow ends with that attempt, and raises `NotFoundError` if it has no
log once it is over:

```python
for line in client.jobs.logs(job.id, follow=True, attempt=1):
    ...
client.jobs.outputs(job.id, attempt=1)
```

### Async

```python
import asyncio, p2pc


async def main() -> None:
    async with p2pc.AsyncClient() as client:
        job = await client.jobs.run(
            image="docker.io/library/python:3.12-slim", command=["python", "-c", "print(6*7)"]
        )
        job = await job.wait()
        async for line in job.logs():
            print(line.data, end="")
        # To stop early, close the iterator: `async with contextlib.aclosing(job.logs()) as logs:`


asyncio.run(main())
```

### Blobs, services and templates (H2)

```python
# A file as a job input: uploaded once (the hub is asked first), read-only in the job.
blob = client.blobs.put("audio.wav")  # a regular file; hashed and sent from one descriptor
job = client.jobs.run(
    image="docker.io/library/python:3.12-slim",
    command=["python", "/inputs/main.py"],
    inputs={"/inputs/audio": blob},  # a Blob, or a "sha256:<hex>" string; never a path
)

# A long-lived service, and a local loopback port that forwards to it.
svc = client.services.run(
    image="docker.io/library/python:3.12-slim",
    command=["python", "-m", "http.server", "8000"],
    ports=[8000],
    health_tcp=True,
    idle_timeout_s=3600,  # None = never; leave it out for the default
)
with client.services.connect(svc, 8000) as local_port:
    ...  # talk to http://127.0.0.1:{local_port}; the block ends the listener
client.jobs.cancel(svc.id)

# Templates: the hub's vetted job recipes.
for template in client.templates.list():
    print(template.id, [p.name for p in template.params])
job = client.templates.launch("transcribe", {"audio": blob, "model": "small"})
```

`services.connect` listens on `127.0.0.1` only, opens one upgraded connection to the hub per
local connection (at most 16 at once) and does not go through an HTTP proxy. A refused upgrade
(`service_not_running`, `port_not_exposed` …) closes that local connection and is kept in
`.last_error` of the returned object. Every call has an `AsyncClient` twin
(`async with client.services.connect(...)`).

### Everything else

```python
client.jobs.get(id)
client.jobs.cancel(id)
for job in client.jobs.list(status="running", limit=50):
    ...  # lazy, follows cursor pages
client.estimate(image, command, cpu=2, gpu=1, timeout_s=3600)  # feasible? units per hour?
me = client.whoami()  # the presented key and its limits (never its secret)
me.scopes, me.daily_unit_cap, me.allowed_images, me.expires_at
client.server()  # node_id, relays, address (p2pc_srv_...) and version of the server
for node in client.nodes.list(state="online"):  # online (draining included) | offline
    node.name, node.draining, node.free.cpu, node.inventory.gpus
client.nodes.get(id)
client.nodes.drain(id)  # returns the node; idempotent
client.nodes.resume(id)
client.nodes.delete(id)
client.join_tokens.create(ttl_s=900, label="laptop")  # admin
client.join_tokens.list()  # admin: metadata only, never the tokens
client.join_tokens.revoke(token_id)  # admin: an unused token
key = client.keys.create(  # admin
    ["jobs:read", "jobs:write"],
    daily_unit_cap=10_000,  # milli-units: 10 units
    allowed_images=["docker.io/library/*"],
    label="ci",
    expires_at=datetime(2027, 1, 1, tzinfo=UTC),
)
key.key.get_secret_value()  # the full p2pc_sk_... key, shown ONCE: store it now
client.keys.list()  # metadata, revoked keys included: label, last_used_at, revoked_at...
client.keys.revoke(id)  # sets revoked_at; the row stays (`delete` is an alias)
for event in client.audit(kind="key_created"):  # admin, newest first
    ...
report = client.usage(from_=..., to=..., group_by="job")  # job | node | key
for group in report.items:  # every page of groups is followed
    print(group.key, group.units, group.attempts, group.estimated_attempts)
print(report.total.units)  # the total of the whole range; report.total.key is None
```

Without `from_`/`to` the server reports the current UTC day. The range of the first page is sent
on every later page, so a call that crosses 00:00 UTC still reports one day. `usage()` loads at
most 10,000 groups and raises `InvalidResponseError` naming the limit beyond that: narrow the
range or group by something coarser.

### Units

Compute is counted in **milli-units**: 1 unit = 1,000 milli-units = one vCPU-hour reserved.
`Job.estimated_units`, `Estimate.units_per_hour`, `daily_unit_cap` and `UsageTotals.units` are
all integers in milli-units, so a 2-vCPU job with a one-hour timeout estimates `2000`. Usage
times (`reserved_cpu_ms`, `reserved_gpu_ms`, `used_cpu_ms`) are in milliseconds and
`max_rss_mb` is in MiB. `estimated_attempts` counts the attempts of a group whose usage is a
server estimate (the node never reported it).

### What a job looks like

The submitted spec is nested under `job.spec`. Environment values are never returned (they are
the string `"<redacted>"`) and files list `{path, size, sha256}` without content:

```python
job = client.jobs.get(id)
job.spec.image, job.spec.command, job.spec.resources.cpu  # also: job.image, job.command
job.spec.env  # {"GREETING": "<redacted>"}
job.spec.files[0].sha256
job.estimated_units, job.reason, job.cancel_requested_at
```

Idempotency keys are scoped to the API key that submitted the job and are never returned, so a
`Job` has no `idempotency_key`.

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| `P2PC_API_URL` | `http://127.0.0.1:7477` | Base URL of the control plane (or of `p2pc proxy`). |
| `P2PC_API_KEY` | none | API key, `p2pc_sk_<key_id>_<secret>`. A missing key raises `ConfigurationError` at the first call. |

Arguments to `Client(api_url=None, api_key=None, timeout=30.0, http_client=None)` take
precedence over the environment. Pass your own `httpx.Client` as `http_client` to control TLS
or proxies; the SDK never closes it. The keyword-only `follow_idle_timeout=300.0` bounds the
silence of a followed log stream. The API key is sent over HTTP: use HTTPS (a reverse
proxy) for anything other than a loopback address. `http://` to a host that is not loopback is
allowed (the spec allows HTTP behind your own proxy), but each client logs one warning on the
`p2pc` logger that the key travels in clear text. `api_url` must not carry credentials
(`user:pass@host`): they would replace the bearer header, so the SDK raises `ConfigurationError`.

## Errors

Every error derives from `p2pc.P2PCError` and carries `status`, `code`, `title`, `detail`,
`type` and `errors` (the per-field problems of a 422) from the server's
`application/problem+json` body. The class is chosen by HTTP status, so an unknown `code`
still maps to the closest class:

| Status | Class | `code` values the server sends |
|---|---|---|
| 401 | `AuthenticationError` | `unauthenticated` |
| 402 | `CapExceededError` | `cap_exceeded` |
| 403 | `PermissionDeniedError` | `forbidden`, `image_not_allowed`, `escalation_denied` |
| 404 | `NotFoundError` | `not_found` |
| 409 | `ConflictError` | `idempotency_conflict`, `last_admin_key`, `token_consumed` |
| 410 | `NotFoundError` | `output_expired` (the server's `expired`) |
| 422 | `UnprocessableError` | `validation_failed`, `unsupported_pool`, `too_large`, `invalid_body` |
| 429 | `RateLimitError` (`retry_after`) | |
| 5xx | `ServerError` | `internal` |
| 400, 405, 408, 413, 415 | `P2PCError` | `invalid_json`, `invalid_query`, `invalid_body` (400: the body cannot be read), `method_not_allowed`, `request_timeout`, `payload_too_large`, `unsupported_media_type` |
| transport failure | `P2PCConnectionError` | |

`err.errors` is a tuple of `FieldError(field, code, message)`, for example
`FieldError("files[0].path", "invalid_format", "...")`; their `code` is one of
`p2pc.FIELD_ERROR_CODES`. Messages never contain env values or file contents.

Other errors: `ConfigurationError` (no key, bad URL), `InvalidResponseError`,
`ChecksumMismatchError` and `UnsafePathError` (output downloads).

### Checked before sending

Mistakes in the job spec raise `pydantic.ValidationError` (a `ValueError`) before any request.
They mirror §7 of the spec; the server stays the authority and may reject more (for example a
registry that is not on its allowlist, or a job that does not fit one 1 MiB lease frame):

- image reference, `command` (1-256 arguments, 64 KiB), `egress.allow`, `timeout_s`, retries;
- `env`: at most 64 variables and 32 KiB, names `[A-Z_][A-Z0-9_]*` without the `P2PC_` prefix,
  and values **without NUL, `\n` or `\r`** (encode multi-line values as base64, or pass files);
- `files`: absolute paths under `/inputs`, at most **512 KiB** in total once decoded;
- `idempotency_key`: 1-255 printable ASCII characters, no spaces; `outputs_max_mb`: 1-10,240;
- `resources.cpu`: 0.25-256 and a **multiple of 0.001**.

## Security notes

- The API key is never shown: `repr()`, logs and exception messages mask it (`p2pc_sk_abc…`).
- `NewApiKey.key` and `JoinToken.join_token` are `pydantic.SecretStr`: call
  `.get_secret_value()` when you really need the value. Listed keys never carry one.
- Environment values and file contents are kept out of `repr()` and validation errors.
- The SDK logs method, path and status at DEBUG on the `p2pc` logger, never headers or bodies.
- No telemetry: the SDK only talks to the URL you configure.

## Development

```sh
uv run --project sdk/python pytest -q
uv run --project sdk/python ruff check && uv run --project sdk/python ruff format --check
uv run --project sdk/python mypy --strict sdk/python/p2pc
uv build --project sdk/python
```

All wire models live in `p2pc/models.py`. `tests/test_openapi_contract.py` compares every
request and response model with `docs/api/openapi.json` (field names, required fields and
types), so it fails when the server's OpenAPI drifts from the SDK. It reads the file and makes no
network calls, and it loads the file lazily, so outside the repository (an sdist) it is skipped.
Every model and every route the SDK uses must be in the document: there are no `xfail`s. A
model or route that the server does not publish yet waits for its server task.

## Changelog

### Unreleased

H2 additions (T2-54, spec §7.8): `client.blobs.put(path)`, `jobs.run(..., inputs={...})` (also on
`estimate`), `client.services.run(...)` and `client.services.connect(job, port)`, and
`client.templates.list()` / `launch(...)`, each on `Client` and `AsyncClient`. New request
models: `ServiceSpec`, `ServicePort`, `HealthCheck`, `VolumeSpec`, `BlobInput`; `JobSpec` gains
`kind`, `service`, `volumes` and `inputs`. `TemplateInfo`, `TemplateList`, `TemplateParam` and
`TemplateRequirements` are wire models of `p2pc.models`, held against the OpenAPI document like
the others (T2-15: `TemplateInfo.requirements` is now a model, not a `dict`); `Blob` stays in
`p2pc.h2`.

Aligned with the server's scheduler and ledger (T06) and the T13b review:

- **Breaking, usage:** `client.usage()` returns a `UsageReport` (it is no longer an iterator of
  `UsageRecord`, which is gone): `from_` (`"from"` on the wire), `to`, `group_by`, `items` (the
  groups, as `UsageTotals`) and `total`. Every page of groups is followed. `UsageTotals` has
  `key`, `attempts`, `estimated_attempts`, `reserved_cpu_ms`, `reserved_gpu_ms`, `used_cpu_ms`,
  `max_rss_mb` and `units`. `AsyncClient.usage()` is now a coroutine.
- New: `Job.attempts` (only in `jobs.get`): a list of `JobAttempt` (`attempt`, `node_id`,
  `outcome` in job-state words, `reason`, `started_at` -- `None` until the job process starts --
  and `ended_at`).
- Error messages also mask `p2pc_join_…` and `p2pc_srv_…` values (as they already did API keys).
- Timestamps: `keys.create(expires_at=)` is sent in whole seconds, UTC (strings and naive
  `datetime`s too). `usage(from_=, to=)` is sent as given: that endpoint takes fractions of a
  second, and truncating the exclusive `to` would drop attempts.
- Fixes from the T13b review: the changelog text on the download cap, the boundary test of the
  default 1 GiB cap, and the contract test loads `docs/api/openapi.json` lazily.
- Logs and outputs, aligned with the server's OpenAPI (T10b, T13d):
  - `LogLine` is `{seq, stream, ts, data}` and all four are required (`LOG_STREAMS`); the
    truncation marker is `line.truncated`. `OutputFile` requires `path`, `size` and `sha256`.
    A record or listing entry that lacks one raises `InvalidResponseError` (before, the model
    accepted `seq` alone and filled in defaults).
  - `logs(follow=True)` follows like the CLI: a stream the server ends early is reopened from
    `last_seq + 1` until the attempt is over, `attempt=K` is sent on every read, and a requeued job
    goes on with its next attempt. Without `follow` it is one page.
    Before, an early clean end of the stream ended the iterator.
  - Follows survive outages (T13f): a broken stream, a connection error, a timeout, `429` and `5xx`,
    on the stream and on the job checks, are retried (1 s doubling to 30 s, honouring
    `Retry-After`) and the stream is reopened from the next `seq`. One outage lasts at most
    5 minutes from its first failure and ends only with a success on its own route (outages are
    tracked per route, the log stream and the job check; a stream that worked and is then cut, as
    at the server's idle limit, is a success); then
    `P2PCConnectionError` is raised. New keyword `on_outage=` on `logs()` (and `Job.logs`), and
    `ServerError.retry_after`. Before, a dropped stream raised `P2PCConnectionError` at once, and a
    `5xx` on the logs ended the follow.
  - Follow polish (T13g): a failed job check no longer blocks the logs (the follow goes back to
    reading them while the job route is down); a `404` from the log route ends a log-route outage;
    a log route that sends no headers within `follow_idle_timeout` is a failure and gives up after
    5 minutes; on `AsyncClient` an `async def` `on_outage` is awaited.
  - Outage rules (T13h): an outage is timed from the start of its first failed request (a log route
    that hangs for the default `follow_idle_timeout` of 300 s gives up after those 300 s, not
    after about 10 minutes), and a gap of more than 30 s between a route's requests (not counting
    the wait the SDK scheduled) starts a new outage, so a failed job check before and one after a
    long healthy stream no longer add up to one that gives up. The sync `Client` raises
    `TypeError` for an `async def` `on_outage`, which it could never await.
  - Fixes from the T13d review: closing an async follow early (`aclose()`) releases the HTTP
    stream at once, and a log line whose `seq` is below the next expected one is dropped.
  - `download_output` checks `X-P2PC-SHA256` against the listing; a `410` is `output_expired`.
- Fixes from the T13c review: `usage()` without a range sends the first page's `from`/`to` on
  every later page (it could mix two days across 00:00 UTC), and stops at 10,000 groups with an
  `InvalidResponseError`.

### 0.1.1

Aligned with the server's final contract (`docs/api/openapi.json`):

- **Breaking, keys:** `keys.create` returns a flat `NewApiKey` whose full key is `key` (a
  `SecretStr`); the old `secret` member is gone. Keys have `project_id`, `label`, `expires_at`,
  `last_used_at` and `revoked_at`; `keys.create` takes `label` and `expires_at`, and
  `keys.revoke` is the name of `keys.delete` (still an alias).
- **Breaking, jobs:** `Job.spec` is the nested, redacted spec (`env` values `"<redacted>"`,
  files as `{path, size, sha256}`). New: `project_id`, `estimated_units`, `reason`,
  `cancel_requested_at`. `Job.image`, `.command` and `.resources` read through `spec`. A `Job`
  never has an `idempotency_key`.
- **Breaking, units:** `Estimate.units_per_hour`, `daily_unit_cap` and `UsageRecord.units` are
  integers in milli-units; usage times are in milliseconds (`reserved_cpu_ms`, `reserved_gpu_ms`,
  `used_cpu_ms`).
- New: `client.whoami()`, `client.audit()`, `client.server()`, `join_tokens.list()` and
  `join_tokens.revoke()` (`409 token_consumed` is a `ConflictError`), `nodes.list(state=)`,
  `P2PCError.errors` (per-field problems), the server's problem codes in the docs.
- **Breaking, nodes:** `Node` is the server's shape (`name`, `hostname`, `state`, `draining`,
  `free`, `inventory` with CPU, GPUs, sandbox drivers and WSL2 health, `labels`, `created_at`,
  `last_seen`); `nodes.drain()` and `nodes.resume()` return the node (they never return `None`).
  `JoinToken` has `id` and a required `expires_at`; `JoinTokenInfo` lists tokens without the
  token itself.
- Validation before sending: `env` values with NUL, `\n` or `\r`; `files` over 512 KiB in total
  (it was 1 MiB); `cpu` that is not a multiple of 0.001.
- The contract test against `docs/api/openapi.json`.
- Fixes from the 0.1.0 review:
  - cancelling an async `download_output` (for example with `asyncio.timeout`) leaves no
    `.p2pc-*.part` file and no new directories, whichever step it lands on;
  - the listing must announce `size` as well as `sha256`; a file larger than the cap is refused
    before any byte is fetched. The cap is 1 GiB by default, and `Job.download_output` uses the
    job's own `outputs.max_mb` instead (up to 10,240 MiB, so it can be above 1 GiB);
  - `api_url` with `user:pass@` is rejected; `http://` to a non-loopback host logs a
    warning once per client;
  - `logs`, `outputs` and `download_output` take `attempt=K` (latest by default); `since_seq` is
    inclusive; expired outputs are reported as such;
  - `Job` and `AsyncJob` ignore the bound client in `==`, and copies share it;
  - examples use TEST-NET addresses.
- Review fixes (PR #17): `Job.download_output` caps at the job's own `outputs.max_mb` (up to
  10,240 MiB), the default without a job stays 1 GiB; `idempotency_key` and `outputs.max_mb` are
  checked before sending; the error table lists `token_consumed`, `invalid_query` and
  `invalid_body`.
- Version bump to 0.1.1.

### 0.1.0

First release: jobs, logs, outputs, nodes, join tokens, keys and usage, sync and async.

Licensed under Apache-2.0.
