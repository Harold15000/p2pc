# templates

Template definitions (H2 spec §7.6): data files that describe the one-click workloads, reviewed like code and compiled
into a signed bundle at release.

| File | What |
|---|---|
| `bundle.toml` | `bundle_version` and `min_hub_version` of the bundle. Raise `bundle_version` in every change here. |
| `private-chat.toml` | Private AI chat: Ollama as a service, `allowed_routes` `POST /api/chat` and `GET /api/tags`, a `model` parameter with the `pull` target. |
| `transcribe.toml` | Transcribe audio: whisper.cpp as a batch job, a blob input, `language` and `model` parameters. |
| `transcribe/transcribe.sh` | The fixed script of `transcribe`, shipped inline in its spec (`from = "transcribe/transcribe.sh"`). |

A template is the wire type `p2pc_proto::api::Template` written as TOML: the listing fields (`id`, `version`, `title`,
`description`, `kind`, `ui`, `singleton`, `requirements`, `params`, `licenses`, `download_mb`), the `[spec]` (a
JobSpec) and `[[allowed_routes]]`. Unknown keys are refused. `spec.timeout_s` must be written down.
`[[spec.files]]` may say `from = "<file under templates/>"` instead of `content_b64`.

## The rules

`scripts/templates-bundle` checks them over every template (SI-H2-13), and over every JobSpec a launch can produce:

- the image is pinned by `@sha256:` digest;
- a parameter reaches the job only through its one `target`: `env:<NAME>` or `argv:<index>` (a whole value of the
  spec), `field:timeout_s` or `field:service.idle_timeout_s` (an `int` whose bounds lie inside the field's JobSpec
  range), `input:<path>` (a `blob`), or `pull` (an `enum` of a `ui = "chat"` template); enum values are plain words;
- egress is a fixed list, volumes are named `tpl:<id>/<name>`, `timeout_s` is finite;
- `allowed_routes` name ports of `service.ports`, one `GET` or `POST` and an exact absolute path each, never a route
  that pulls, creates, copies, pushes or deletes models;
- every JobSpec passes the normal validation.

```sh
cargo run -p templates-bundle -- check                 # development: a placeholder digest is accepted
cargo run -p templates-bundle -- check --release       # a release: a placeholder digest is refused
```

## Image digests

Both shipped images are pinned by the digest that was checked on a test node: Ollama 0.40.16 for `private-chat`, and
the CPU image of whisper.cpp (`main`) for `transcribe`, which therefore needs no GPU. The `main-cuda` image needs
CUDA 13 and does not start at all without a GPU, so it is not used. To move a digest, take the new one from the
registry (`skopeo inspect docker://<image>:<tag>` or `crane digest <image>:<tag>`), run the image on a test node, and
raise `bundle_version` in `bundle.toml`. Ollama images must be pinned by digest: an old tag can no longer pull
current models.

While a digest is not known yet, a template may carry the all-zero **placeholder**. The development check accepts it;
the release build (`--release`) and the signer refuse it, so a bundle that carries one cannot be signed.

`private-chat` defaults to `qwen3:4b-instruct`, which does not answer with a reasoning block. `qwen3:4b` and
`qwen3:1.7b` do, even with `"think": false`, and a template cannot pass request options, so the chat UI should strip a
leading reasoning block (see the comment in `private-chat.toml`).

The compiler and signer are documented in [`scripts/templates-bundle/README.md`](../scripts/templates-bundle/README.md).
