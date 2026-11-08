# The `p2pc` command line

`p2pc` is the client of a P2PC server. It talks to the server's REST API (spec §7), either at an `https://` or
`http://` URL, or through the server's **address** `p2pc_srv_…`, which reaches a home server with no open port over an
encrypted iroh tunnel (see [Reaching a home server from anywhere](#reaching-a-home-server-from-anywhere)).

- [Quick start](#quick-start)
- [Global flags](#global-flags)
- [Configuration](#configuration)
- [Commands](#commands)
- [Exit codes](#exit-codes)
- [JSON output](#json-output)
- [Retries](#retries)
- [Reaching a home server from anywhere](#reaching-a-home-server-from-anywhere)
- [Examples](#examples)

## Quick start

```sh
p2pc login --server https://p2pc.example.invalid     # asks for the API key, hidden
p2pc whoami
p2pc run --image python:3.12-slim --cpu 2 --mem 4G -- python -c "print(6*7)"
```

## Global flags

| Flag | Meaning |
|---|---|
| `--profile NAME` | The profile to use. |
| `--server URL\|ADDRESS` | The server's `https://` or `http://` URL, or its address `p2pc_srv_…` (through the tunnel). |
| `--json` | Print the API's JSON instead of text. See [JSON output](#json-output). |

They work before or after the subcommand. **There is no `--key` flag, on any command.** A key on the command line ends up
in your shell history and in `ps`, so the key only comes from the hidden prompt of `p2pc login`, from `--key-stdin`,
from the `P2PC_API_KEY` variable or from `credentials.toml`.

## Configuration

### Where the files are

`config.toml` and `credentials.toml` live in one directory:

| System | Directory |
|---|---|
| any, when `P2PC_CONFIG_DIR` is set | `$P2PC_CONFIG_DIR` |
| Linux and macOS | `$XDG_CONFIG_HOME/p2pc`, or `~/.config/p2pc` |
| Windows | `%APPDATA%\p2pc` |

```toml
# config.toml
default_profile = "home"          # optional

[profiles.home]
server = "https://p2pc.example.invalid"
```

```toml
# credentials.toml
[profiles.home]
api_key = "p2pc_sk_…"
```

`p2pc login` writes both files. A profile's `server` is an `https://` or `http://` URL, or a server **address**
`p2pc_srv_…`, which every command then reaches through the tunnel. A value that starts with `p2pc_srv_` but does not
decode is refused before anything is sent.

### Precedence

The first of these that is set wins:

| Setting | Order |
|---|---|
| Profile | `--profile`, `P2PC_PROFILE`, `default_profile` in `config.toml`, then `default` |
| Server | `--server`, `P2PC_SERVER`, the profile's `server` |
| API key | `P2PC_API_KEY`, the profile's `api_key` in `credentials.toml` |

### Environment variables

| Variable | Meaning |
|---|---|
| `P2PC_CONFIG_DIR` | The directory of the two files. |
| `P2PC_PROFILE` | The profile. |
| `P2PC_SERVER` | The server URL or address. |
| `P2PC_API_KEY` | The API key. Handy for CI. When it is set, `credentials.toml` is not read. |

### Protecting the key

- `credentials.toml` is written through a temporary file in the same directory that is created with mode `0600`
  **before** the key is written to it, and then renamed over the old file. The directory is created with mode `0700`.
- **On Linux and macOS the CLI refuses to read `credentials.toml` if the group or others can read it**, as `ssh` does,
  and says how to fix it: `chmod 600 <path>`. `p2pc login` replaces such a file, without reading it, with a private
  one that holds only the new key, and warns: log in again for any other profile, and treat the keys the old file held
  as exposed (revoke them).
- **On Windows** there is no mode to check. The CLI relies on the ACL of `%APPDATA%`, which is per user and denies other
  users by default. Do not point `P2PC_CONFIG_DIR` at a shared folder.
- The key never appears in output, in error messages, in `Debug` output or in logs. `p2pc keys create` is the one
  command that prints a key, once. A malformed `credentials.toml` is reported by line, never quoted.
- With an `http://` URL on another machine, the key travels unencrypted: the CLI warns. Use `https://`. A private CA
  works as long as the operating system trusts it (the CLI uses the OS certificate store).

## Commands

### `p2pc login [--server URL|ADDRESS] [--key-stdin] [--via-tunnel]`

Reads the API key from a hidden prompt, or from one line of stdin with `--key-stdin` (for scripts:
`p2pc login --server URL --key-stdin < keyfile`). It checks the key with `GET /v1/whoami`, and only then stores it and
the server in the profile. It prints the account, project, key ID and scopes. With no terminal and no `--key-stdin` it
refuses.

With a server address (`--server p2pc_srv_…`) the check goes through the tunnel. With `--via-tunnel` and the server's
URL (on the server machine itself, `http://127.0.0.1:7477`), `login` checks the key there, reads the server's address
from `GET /v1/server`, checks the key again through the tunnel and stores the **address**, so that the profile works
from any network.

### `p2pc logout`

Removes the profile's key from `credentials.toml`.

### `p2pc whoami`

Prints the account, project, key ID and scopes of the key in use.

### `p2pc run [flags] -- CMD…`

Submits a job and follows it. The command after `--` is an argv: there is no shell unless you run one
(`-- sh -c "a | b"`).

| Flag | Meaning |
|---|---|
| `--image IMAGE` | **Required.** The OCI image. |
| `--cpu N` | vCPUs, 0.25 to 256. Default 1. |
| `--mem SIZE` | Memory. Default `2G`. |
| `--gpu 0\|1` | Whole GPUs. Default 0. |
| `--disk SIZE` | Disk for outputs and the writable layer. Default `2G`. It is also the job's disk limit. |
| `--env KEY=VALUE` | An environment variable. Repeatable. |
| `--env KEY` | Takes the value from your environment. It is an error if it is not set. |
| `--env-file PATH` | `KEY=VALUE` lines (see below). `--env` wins over it. |
| `--file LOCAL[:/inputs/PATH]` | Puts a local file in the job. Without a path it goes to `/inputs/<file name>`. Repeatable. At most 512 KiB in total. |
| `--egress a.example.com,b.example.com` | The domains the job may reach. Without it the job has no network. |
| `--timeout DURATION` | `90s`, `2h`, `1h30m`. Default 1h, at most 24h. |
| `--name NAME` | A label for the job. |
| `--node NODE_ID` | Run only on this machine. |
| `--label KEY=VALUE` | Only machines with this label. Repeatable. |
| `--retries N` | Retries after the machine is lost, 0 to 4. Default 1. |
| `--idempotency-key KEY` | See [Retries](#retries). Generated when not given. |
| `-d`, `--detach` | Print only the job ID on stdout and return at once. |

**Sizes** are a number and an optional unit: `512M`, `4G`, `4GiB`, `1.5G`, `2T`, `1024K`. A bare number is MiB. All units
are binary (`G`, `GB` and `GiB` are all 1024 MiB), case does not matter, and fractions round up to a whole MiB.

**Images.** Each node keeps the images it has pulled and pulls only what it does not have. An image that is already on
the node is used as it is, with no request to the registry, when you give a tag other than `latest` (`python:3.12-slim`)
or a digest (`python@sha256:…`). `latest`, spelled out or implied by a missing tag, is pulled for every job, so pin a
tag or a digest. Jobs that need the same image at the same moment on one node share a single pull. The node refuses an
image larger than its size cap (20 GiB by default) with `image_too_large`, whether it was just pulled or already there.
Docker Hub limits anonymous pulls per public IP address, and every node of a home shares one IP: a batch of jobs on
`latest`, or on an image no node has yet, can reach the limit and fail with `image_pull_failed`. Pin a tag or a digest
so each node pulls the image once.

**`--env-file`** holds `KEY=VALUE` lines. Blank lines and lines starting with `#` are ignored, `export ` is accepted, and
one pair of single or double quotes around a value is removed. There are no escapes, no multi-line values and no
comments after a value. Errors name the line number and never quote the line.

**`--retries N`** counts retries, so `--retries 0` means one attempt in total (`retry.max_attempts = N + 1`). Only the
loss of a machine consumes an attempt: a job that fails by itself is never retried.

**Validation** runs locally first with the same rules as the server (`p2pc-proto`), so a typo costs no round trip. The
server stays the authority: it also checks the registry allowlist, the key's image patterns and its daily cap.

**Following.** The job ID goes to **stderr**. While the job waits in the queue, `run` polls it (at once, then every
second, backing off to five); once it runs, `run` shows its **log live**, the way `p2pc logs --follow` does:

- the job's **stdout goes to your stdout** and its **stderr to your stderr**, so `p2pc run … > out.txt` captures the
  job's output and nothing else;
- the job ID and every change of state (`queued`, `running on node_…`, a new attempt after a machine was lost) go to
  stderr, between the job's lines;
- when the job ends, `run` prints how it ended on stderr (`job succeeded`, `job failed with exit code 3`, …) and exits
  with the [exit code](#exit-codes): the job's own code, 124 if it timed out, 75 if it was lost, 130 if it was
  cancelled, 125 if p2pc could not run it (a validation or network error, or a job that failed before it started, such as
  an image pull);
- if the machine is lost and the job is retried, `run` goes on with the new attempt's log, whose lines are numbered
  from 0 again.

**The job's output is untrusted.** On a terminal, `run` (like `logs`) shows control characters instead of acting on them,
so a job cannot clear your screen, recolour it, change the window title or write to your clipboard (see
[`p2pc logs`](#p2pc-logs-job_id---follow---attempt-k---since-seq-n---raw)). Piped or redirected, the bytes are written
as stored.

With `--json`, stdout is NDJSON: one `{"seq", "stream", "ts", "data"}` record per log line as it arrives, then the final job
as the last line. `--detach` prints only the job ID on stdout (or the job, with `--json`) and does not follow.

**A short outage does not stop the follow.** If the server cannot be reached, or answers `5xx`, `408` or `429`, `run`
prints one `reconnecting…` line and keeps trying (1 s, doubling, at most 30 s apart) for up to 5 minutes; the job keeps
running on its machine meanwhile. A log connection that drops resumes from the last line it printed, so no line is
printed twice or lost. A permanent error (`401`, `404`, a validation error) ends the follow with 125 and the job ID, at
once.

`run` asks for two things, the log stream and the job's state, and counts an outage of each one on its own:

- An outage is a run of failures of one of them, counted from the start of its first failed request. It ends when that
  same request works again. A stream that delivered a line, or stayed open for 10 s, counts as working even if it then
  breaks.
- It also ends if more than 30 s (the longest wait) pass between two requests of the same kind, because `run` was busy
  with healthy work on the other one, for example reading a long log. The next failure then starts a new outage: it is
  announced again, and it has its own 5 minutes.
- So a job check that keeps failing gives up 5 minutes after its first failure, even while the log flows; and one
  failed check before a long stream and one after it are two short outages, not one long one.

**Ctrl-C detaches and does not cancel.** `run` prints how to follow the job again and how to stop it, and exits with 130:

```
detached: job job_01J… keeps running. To follow it again or to stop it:
  p2pc logs --follow job_01J…
  p2pc cancel job_01J…
```

**A closed stdout detaches too.** In `p2pc run … | head -1`, once the reader has gone, `run` stops following. It looks
at the job first:

- **still running:** it prints the same hint on stderr and exits with 130. The job keeps running (and spending units)
  until it ends or you cancel it;
- **already ended** (a short job whose whole log arrived at once, or the reader left before the final `--json`
  record): it prints the usual one-line outcome on stderr and exits with the job's own code, as if the output had stayed
  open. It does not say that the job "keeps running".

If the server cannot be asked within a few seconds, `run` goes by the last state it saw. Any other failure to write the
log (a full disk, for example) prints the same, then the error, and exits with 125. The exit codes are the ones in
[the spec, §7](specs/H1-personal-cloud.md#7-jobs-api-rest).

A closed **stderr** does not stop the follow: the job's own stderr lines and the status notes are dropped, stdout keeps
flowing, and the exit code is still the job's.

A Ctrl-C **during the submission** (or its retries) also exits with 130. The job may or may not have been created, so
`run` prints its idempotency key: running the same command with `--idempotency-key KEY` returns that job, or submits
it, without ever creating a second one.

### `p2pc estimate [same flags as run] -- CMD…`

Asks the server whether the job could run, how many machines match, whether it would queue and what it reserves per
hour. Nothing is submitted.

### `p2pc jobs [--status STATE] [--node NODE_ID] [--limit N] [--all]`

Lists jobs in the order the server returns them. Without `--all` it shows one page (`--limit`, default 20, at most 100) and says when there is
more. With `--all` it fetches every page.

### `p2pc status JOB_ID` and `p2pc cancel JOB_ID`

`status` shows a job. Its exit code is 0 whatever the job's state, because the command worked. `cancel` is idempotent
on the server.

### `p2pc machines`

Lists the machines: name, ID, state (`online`, `offline`, plus `(draining)`), platform, CPU, RAM and GPU **free/offered**,
and when the machine was last seen.

`p2pc machines show|drain|resume|rm ID_OR_NAME` take a machine's **name or ID**.

- A name is resolved by listing the machines, ignoring case, and falls back to the hostname the agent reported. A name
  that matches more than one machine is an error that lists the candidates with their IDs.
- `drain` stops new jobs from going to the machine (running jobs finish); `resume` undoes it.
- `rm` removes the machine; its agent has to join again with a new token. It asks for confirmation on a terminal.
  **Without a terminal it needs `--yes`**, and it refuses before sending anything.

### `p2pc logs JOB_ID [--follow] [--attempt K] [--since-seq N] [--raw]`

Shows a job's log: the job's stdout on your stdout, and its stderr on your stderr, exactly as it wrote them (no line
end is added).

| Flag | Meaning |
|---|---|
| `-f`, `--follow` | Keep the log open and print lines as the job writes them, until the job ends. Ctrl-C stops following (exit 130) and does **not** touch the job. |
| `--attempt K` | An attempt of the job. Default: the latest. A job whose machine was lost is retried as a new attempt, with its own log. |
| `--since-seq N` | Start at line `N`, counted from 0, inclusive. |
| `--raw` | On a terminal, write the job's output as stored (see below). |

Without `--follow` the command prints what the log holds now, a page at a time, and returns. With `--follow` it first
waits for the job to start, then streams; a connection that drops is reopened from the last line it printed, so nothing
is repeated or lost. A log that is not there yet (the server answers `404` or an empty log while the job starts) is not
the end: the log is read once more after the job is seen to have ended, so the output of a very fast job is not lost, and a
stream that the server closes while the job still runs is reopened. When the job has ended (its log is over) the command returns 0: the command worked, whatever the
job's outcome (`p2pc status` has that). With `--follow`, a job that is retried after losing its machine is followed into its
next attempt; with `--follow --attempt K`, only that attempt is followed.

**The job's output is untrusted.** When stdout (or stderr) is a terminal, `p2pc logs` does not send the job's bytes
to it. It shows every character a terminal would act on, so a job cannot clear your screen, recolour it, move the cursor,
change the window title or write to your clipboard (OSC 52):

| In the job's output | On a terminal you see |
|---|---|
| `ESC` and the other C0 controls except newline and tab (`BEL`, `BS`, `NUL`, …), and `DEL` | `\x1b`, `\x07`, … |
| a bare carriage return (`CR` not followed by a newline), which would overwrite the line | `\r` |
| the 8-bit C1 controls (U+0080 to U+009F, such as `CSI` U+009B) | `\u{009b}`, … |
| the bidirectional overrides and isolates (U+202A to U+202E, U+2066 to U+2069), which reorder the text after them | `\u{202e}`, … |

So a red `ERROR` reads `\x1b[31mERROR\x1b[0m`. When the stream is a pipe or a file, the bytes are written **as stored**,
so `p2pc logs ID | less -R` and `> log.txt` keep colours. `--raw` forces the stored bytes on a terminal too; use it only
for a job you wrote and trust. `--json` prints the log's NDJSON records (`{"seq", "stream", "ts", "data"}`, one per line).
JSON escapes the C0 controls itself; when stdout is a terminal and `--raw` is not set, `DEL`, the C1 controls and the
bidirectional controls are also written as `\uXXXX`, so the line is still valid JSON and means the same to a parser, but
shows nothing the terminal would act on. Piped, or with `--raw`, the line is written exactly as `serde` produced it.

### `p2pc results JOB_ID [--attempt K] [--out DIR] [--file PATH]… [--force]`

Downloads a job's output files (what it wrote to `/outputs`).

| Flag | Meaning |
|---|---|
| `--out DIR` | Where to put them. Default: `./p2pc-results/<job_id>/`. |
| `--file PATH` | Only this output, by the path the job listed it under (`results/a.csv`). Repeatable. |
| `--attempt K` | An attempt of the job. Default: the latest. |
| `--force` | Replace files that already exist. |

- **Nothing is overwritten without `--force`.** If any file would land on one that exists (a symbolic link too, even a
  dangling one), the command stops **before downloading anything** and lists them. Without `--force` the write itself
  also refuses, atomically, a file that appears while it runs.
- **Paths are checked again** on your machine: a name with `..`, an absolute path, an empty segment or a control character
  is refused (and nothing is downloaded), and files are never written through a symbolic link, whatever the server said
  (SI-9).
- **Every file is verified** against the size and the SHA-256 the job listed, in a temporary file that replaces the
  destination only when it matches; a file that fails leaves nothing behind, and the command exits with 125.
- The output ends with a summary on stdout: `2 files, 11 B saved to p2pc-results/job_01J… (sha256 verified)`.
- A job with more than 10,000 output files is refused with a message, before anything is downloaded: the list is never
  silently cut.
- A job with no output files says so (`Job … has no output files`) and exits 0.
- The server keeps outputs for 7 days by default. After that they are deleted (`410 Gone`): `results` says
  `the output files of job … have expired`, downloads nothing and exits with 125 (`{"error": {"kind": "outputs_expired", …}}`
  with `--json`).
- `--json` prints `{"job_id", "directory", "files": [{"path", "size", "sha256", "saved_to"}], "bytes"}`.

### `p2pc usage [--from DATE] [--to DATE] [--by job|node|key]`

Shows what the project's jobs reserved and used (spec §11), one row per job, machine or key, and a total:

```
2026-11-06T00:00:00Z to 2026-11-07T00:00:00Z (UTC)
JOB          ATTEMPTS  UNITS   CPU RESERVED  CPU USED  GPU RESERVED  ESTIMATED
job_01J…     1         1.000   1h 0m         12.3s     0             0
job_01J…     1         ≈2.000  2h 0m         0         0             ≈1
TOTAL        2         ≈3.000  3h 0m         12.3s     0             ≈1
```

- **Units** are compute units (1 unit = 1 vCPU-hour reserved; a GPU-hour is 10). **CPU reserved/used** and **GPU
  reserved** are vCPU-time and GPU-time, not wall-clock time.
- **`≈`** marks a number that includes the server's own **estimate**. When a machine never reports an attempt's usage (it
  was lost, or unreachable when the job was cancelled) the server counts what it had reserved, from the start of the attempt
  to the end it observed; the `ESTIMATED` column counts those attempts (`estimated_attempts` in the API), and a note on
  stderr explains the mark. Rows without it were reported by the machines.
- **The range** is in UTC. `--from` and `--to` take a date (`2026-11-01`, midnight UTC) or an RFC 3339 time
  (`2026-11-01T08:30:00+02:00`), and are sent as whole seconds in UTC. `--to` is exclusive, like the API's: `--from
  2026-11-01 --to 2026-11-02` is one day. The default is **today in UTC**; with only `--from` the range runs to the end of
  today, and with only `--to` it starts a day earlier.
- `--by` chooses the rows: `job` (default), `node` or `key`. Every page of groups is fetched, so the table adds up to its
  total.
- `--json` prints the report as the API returns it (all pages merged into one `items` list).

### `p2pc join-token create [--expires 15m] [--label TEXT] [--token-only]`

Creates a single-use token (valid 15 minutes by default, at most 24h) and prints it **once**, on a line of its own,
then how to use it on the new machine. No command it prints carries the token: a token on a command line would end up
in argv (visible to every user in `ps`) and in that machine's shell history, so the installers and the agent ask for it
instead (hidden input on a terminal, or stdin):

```
Join token (single use, expires 2026-11-05T12:15:00Z):
  p2pc_join_…

On the new machine, paste it when asked:
  On Linux:   sudo sh install-node.sh --from <dist dir>
  On Windows: .\install.ps1 -Join
  Or, where the agent is already installed: p2pc-agent join   (it asks for the token)
```

With `--token-only` it prints just the token and a newline, so a script can save it
(`p2pc join-token create --token-only > token.txt`, then `install-node.sh < token.txt`). It cannot be combined with
`--json`, which prints the whole response (`join_token` included).

See `deploy/README.md`, "Join a Linux machine", "Join a Windows machine" and "Scripted or CI install".

`p2pc join-token list` shows the tokens and whether each is unused, used, revoked or expired.
`p2pc join-token revoke ID` revokes an unused token (the ID is `jtk_…`, not the token). Needs an admin key.

### `p2pc keys create --label TEXT --scope SCOPE… [--cap UNITS] [--image PATTERN]… [--expires 30d]`

Creates an API key and prints it **once, on stdout**, with a warning on stderr to store it now. So
`KEY=$(p2pc keys create …)` captures only the key.

| Flag | Meaning |
|---|---|
| `--scope` | `admin`, `jobs:write`, `jobs:read`, `nodes:read` or `nodes:write`. Repeatable, at least one. |
| `--cap UNITS` | Daily cap in compute units (1 unit = 1 vCPU-hour reserved), for example `10` or `2.5`. |
| `--image PATTERN` | An image glob on the normalized reference, for example `docker.io/library/python:*`. Repeatable. Without any, every image is allowed. |
| `--expires DURATION` | When the key expires, for example `30d`. |

A key can never be more powerful than the key that creates it: the server answers `escalation_denied` otherwise.
`p2pc keys list` shows the keys and `p2pc keys revoke ID` revokes one (the ID is the 12 characters after `p2pc_sk_`).
The server refuses to revoke the last unrestricted admin key (`last_admin_key`). Needs an admin key.

### `p2pc audit [--limit N] [--all]`

Shows the audit log: key and join-token events, nodes enrolled and deleted, failed authentications. Needs an admin key.

### `p2pc mcp [--allow-admin] [--allow-uncapped] [--results-dir DIR]`

Serves the MCP protocol over stdio, so that an AI agent can estimate, run, check and cancel jobs, read their logs and
fetch their results with its own capped key: `claude mcp add p2pc -- p2pc mcp --profile agent`. It refuses a key that
has the `admin` scope or no daily cap (exit code 125) unless `--allow-admin` or `--allow-uncapped` says otherwise, with a
warning. Stdout carries only the protocol; logs go to stderr. See [mcp.md](mcp.md).

### `p2pc proxy [--listen 127.0.0.1:7477] [--allow-non-loopback]`

Serves the REST API of the profile's server **address** on a local port, for tools that speak HTTP (the Python SDK,
`curl`, a browser). Each local TCP connection goes over its own stream of one tunnel connection. **The proxy never adds
an API key**: clients send their own (`Authorization: Bearer …`), exactly as to the server itself.

- It listens on loopback by default. Any other `--listen` needs `--allow-non-loopback` and prints a warning: **that
  exposes your server's API to that network**, where anyone who can reach the port can try keys against it.
- At most 64 local connections are served at once; more wait. A connection with no traffic for 5 minutes is closed.
- Ctrl-C or `SIGTERM` stops it cleanly: no new connections, the open ones end, the tunnel is closed. The exit code
  is 130 after Ctrl-C and 0 after `SIGTERM` (a service manager's normal stop), as in [Exit codes](#exit-codes).

See [Reaching a home server from anywhere](#reaching-a-home-server-from-anywhere).

### `p2pc completion bash|zsh|fish|powershell`

Prints a completion script on stdout, for example `p2pc completion bash > /etc/bash_completion.d/p2pc`.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | The job succeeded, or the command worked. |
| 1–255 | The job's own exit code, when it failed with one. |
| 75 | The job was lost: its machine went away and no attempts were left. Retrying may work. |
| 124 | The job timed out. |
| 125 | p2pc could not run the job or the command: bad arguments, validation, authentication, the network, or a job that failed before it started (an image pull, for example). |
| 130 | Interrupted with Ctrl-C (SIGINT), or the job was cancelled, or `p2pc run` detached because its stdout closed while the job was still running (if the job had ended, `run` returns the job's own code). `p2pc proxy` stopped by `SIGTERM` exits with 0. |

A job's own exit code can collide with these codes (a job that exits with 124 looks like a timeout). **`--json` always
gives the exact outcome:** the job's `status`, `exit_code` and `error`.

Only `p2pc run` returns the job's outcome. Every other command returns 0 when it worked and 125 when it did not (a usage
error, a refusal, an answer from the server that is an error, no answer at all, a file `p2pc results` would overwrite or
outputs that expired). `p2pc logs --follow` returns 130 on Ctrl-C and 0 when the job's log ended. `p2pc machines rm` returns 130 when
you answer no to the question.

## JSON output

`--json` prints exactly the API's JSON, with the same field names:

- a single object for `whoami`, `status`, `cancel`, `estimate`, `machines show`, `run --detach`, `usage` and `results`;
- NDJSON, one record per line, for `logs` (the log's `{"seq", "stream", "ts", "data"}` records) and for `run` (the log
  records, then the final job);
- an **array of the fetched items** for `jobs`, `machines`, `join-token list`, `keys list` and `audit` (with `--all`,
  every page; without it, the first page);
- `keys create --json` includes the `key` field, and `join-token create --json` the `join_token`;
- `drain` and `resume` print the node; `machines rm`, `keys revoke` and `join-token revoke` print `{"deleted": ID}` or
  `{"revoked": ID}`.

Errors in `--json` mode are one JSON object on **stderr**:

```json
{"error": {"kind": "api", "status": 422, "code": "validation_failed", "title": "…", "detail": "…",
           "errors": [{"field": "resources.cpu", "code": "out_of_range", "message": "…"}]}}
```

`kind` is `api`, `network`, `unexpected_response`, `validation`, `outputs_expired` or `error` (for example a request that could not be
built on this machine, which is never retried). In text mode the same error reads
`error: validation_failed: …` followed by one line per field path.

Job `env` values are never returned by the API (`"<redacted>"`), so they never appear in any output.

## Retries

`p2pc run` **always sends an idempotency key**: the one from `--idempotency-key`, or a generated one. It travels in the
`idempotency_key` field of the job and in the `Idempotency-Key` header. Connection errors and `502`, `503` and `504`
answers are retried up to 3 times, with exponential backoff and jitter, **with the same key**, so a retry never creates a
second job. The same key with the same job returns the existing job; the same key with a different job is a `409`.

Every `GET` is retried the same way. Other `POST`s (cancel, drain, key and token creation) and every `DELETE` are sent
once: repeating them could have effects the first one already had.

Timeouts: 10 s to connect (15 s through the tunnel) and 60 s per request. Redirects are not followed (a redirect would
resend your key to somewhere else); the CLI says so and asks you to check the server URL. A request that cannot even be
built (an idempotency key with a newline, for example) is an error at once: nothing is sent and nothing is retried.

## Reaching a home server from anywhere

The server's REST API listens on `127.0.0.1:7477` and opens no port to the internet. A laptop on 4G, or any machine
away from home, reaches it through the **server address**:

```
p2pc_srv_…
```

It holds the server's iroh NodeId (its public key) and the relays it uses. It is **not a secret** and grants nothing on
its own: every request still needs an API key. `p2pc-server init` prints it, and `GET /v1/server` returns it.

**Log in with it** and every command uses the tunnel, with no other process:

```sh
p2pc login --server p2pc_srv_…            # asks for the key; checks it through the tunnel
p2pc whoami
p2pc run --image python:3.12-slim -- python -c "print(6*7)"
```

On the server machine itself you can log in with the URL and let `login` fetch the address:
`p2pc login --server http://127.0.0.1:7477 --via-tunnel`. The profile then stores the address.

**For other tools, run `p2pc proxy`**, which serves the same tunnel as a local HTTP port:

```sh
p2pc proxy --profile home                  # listens on 127.0.0.1:7477
curl -H "Authorization: Bearer $P2PC_API_KEY" http://127.0.0.1:7477/v1/whoami
```

**What the relay sees.** The two ends connect over QUIC, with TLS 1.3 authenticated by the server's NodeId, end to end.
When no direct path can be found (both ends behind NAT, CGNAT on 4G), the traffic goes through a relay, which forwards
**encrypted QUIC packets only**: it sees the two NodeIds, the timing and the sizes, never a request, a key or a job. By
default the relays are n0's public ones, meant for development; the server's `relays` setting points at your own
`iroh-relay`, and the address carries it.

**Address hygiene.** Like the server and the agents, the CLI's iroh endpoint never asks your router to open a port (no
UPnP or NAT-PMP), never publishes addresses to a discovery service, and binds only the addresses of the interface that
carries the default route: never a Tailscale or CGNAT address, a link-local one or a container or VM bridge. Without a
default route it is relay-only.

**Limits.** One tunnel connection per process; each request uses its own stream and asks the server to close it once
answered.

- A lost connection is re-opened on the next request. Between failed attempts the tunnel waits 250 ms, doubling, at
  most 10 s; a request made inside that wait fails at once with the last error instead of queueing another attempt. A
  connection counts as working only once the server has answered on it, so a server that accepts and then hangs up
  does not reset the wait. A request that is cancelled while the tunnel is connecting (a timeout, a cancelled MCP tool
  call) does not cancel the attempt: its outcome is still recorded for the next request.
- **Network changes.** `p2pc proxy` and `p2pc mcp` watch the network (the same watcher as the server and the agents):
  when the machine's addresses change, for example from Wi-Fi to 4G, the tunnel binds a new endpoint on the new
  default-route addresses. A request in flight at that moment may fail once; the next one reconnects. As a fallback,
  for every command, two failed attempts in a row also bind a new endpoint.
- The server caps tunnel connections at 8 per NodeId and its tunnel streams below its REST connection cap, so remote
  clients can never lock out local ones.

## Examples

### U2 · Enroll a machine

On a machine that has an admin key (your laptop, say):

```sh
p2pc join-token create --label spare-pc
# Join token (single use, expires …):
#   p2pc_join_…
# On the new machine, paste it when asked:
#   On Linux:   sudo sh install-node.sh --from <dist dir>
#   On Windows: .\install.ps1 -Join
#   Or, where the agent is already installed: p2pc-agent join   (it asks for the token)
```

On the new machine, run the installer for its platform and paste the token when it asks. Then, back on the first one:

```sh
p2pc machines
# NAME      ID                         STATE   PLATFORM  CPU FREE/OFFERED  RAM FREE/OFFERED  GPU FREE/OFFERED  LAST SEEN
# spare-pc  node_01J…                  online  linux     8/8               30 GiB/32 GiB     1/1               3s ago
p2pc machines show spare-pc
```

### U3 · Run a job

```sh
p2pc run --image python:3.12-slim --cpu 2 --mem 4G -- python -c "print(6*7)"
# job_01J…                      (stderr: the job ID)
# job_01J…: queued
# job_01J…: running on node_01J…
# job_01J…: succeeded
# job succeeded
echo $?                                      # 0
```

In a script, detach and look later:

```sh
ID=$(p2pc run -d --image python:3.12-slim --egress pypi.org,files.pythonhosted.org -- pip download requests)
p2pc status "$ID"
p2pc cancel "$ID"
p2pc jobs --status running
p2pc status "$ID" --json | jq '{status, exit_code, error}'
```

Inputs and secrets:

```sh
p2pc run --image python:3.12-slim --file job.py --file data.csv --env-file prod.env --env HF_TOKEN \
  -- python /inputs/job.py /inputs/data.csv
```

Logs, results and usage:

```sh
p2pc run --image python:3.12-slim -- python -c "print(6*7)" > answer.txt   # the job's stdout, live; its stderr on yours
p2pc logs job_01J… --follow --attempt 2       # the second attempt, until it ends
p2pc logs job_01J… | grep -i error            # piped: the bytes as stored
p2pc results job_01J… --out ./out             # ./out/<files>, each verified
p2pc results job_01J… --file report.csv --force
p2pc usage --from 2026-11-01 --by node        # since the 1st, per machine
```

### U9 · Owner control of a machine

```sh
p2pc machines drain spare-pc      # no new jobs; running jobs finish
p2pc machines resume spare-pc     # back in service
p2pc machines rm spare-pc         # asks first; use --yes in scripts
```

The share of CPU, RAM and GPU a machine offers is set on the machine itself, in the agent's configuration; `p2pc machines`
shows what is offered and what is free.

### Keys for an AI agent or CI

```sh
KEY=$(p2pc keys create --label ci --scope jobs:write --scope jobs:read \
        --cap 10 --image 'docker.io/library/python:*' --expires 30d)
p2pc keys list
p2pc keys revoke abcdefghijkl
```

For an agent that uses `p2pc mcp`, see [mcp.md](mcp.md): it needs a key with a `--cap`.
