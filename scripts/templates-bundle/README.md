# templates-bundle

Checks, compiles and signs the template bundle (H2 spec §7.6, §14.1; SI-H2-13). A release tool: it is a workspace
crate so that `cargo test --workspace` runs its tests, but nothing ships it.

```sh
# Check every rule over templates/ (development).
cargo run -p templates-bundle -- check

# Compile templates/ into canonical templates.json. --release is what the release pipeline passes:
# it refuses a placeholder image digest.
cargo run -p templates-bundle -- compile --out templates.json --release

# Sign it with the release key (a minisign secret key file; an encrypted key's password comes from an
# environment variable, never from the command line).
cargo run -p templates-bundle -- sign --bundle templates.json --secret-key release.key \
    --password-env RELEASE_KEY_PASSWORD --out templates.json.minisig

# Verify a bundle against its signature and the public key.
cargo run -p templates-bundle -- verify --bundle templates.json --signature templates.json.minisig --public-key release.pub
```

## What it writes

`templates.json` is `{"bundle_version", "min_hub_version", "templates": [<p2pc_proto::api::Template>…]}` as compact
JSON with the keys of every object sorted, so the same sources always give the same bytes, and the signature covers
exactly what the hub parses. The `.minisig` file is a minisign signature over those bytes whose trusted comment is
`p2pc-templates bundle_version=<n>`; `verify` requires `<n>` to equal the version inside the bundle.

## The library

The crate is also a library, so the hub's verifier and launch can reuse it (T2-15):

- `source`: reads `bundle.toml` and `<id>.toml` (unknown keys refused, `from = "…"` files inlined from inside the
  directory, no symlinks, bounded sizes);
- `check`: the rules of §7.6 over a bundle, in `Mode::Dev` or `Mode::Release`;
- `params::build_spec`: the JobSpec of a launch from a template and its parameter values, through the targets only;
- `bundle`: the `Bundle` type and the canonical bytes;
- `sign`: `sign_bundle` and `verify_bundle` (size first, signature second, parse last).

## The key

No signing key is generated or committed. The release key is the minisign key pair of spec §5.1: the private half
stays offline with the release manager, the public half is compiled into the app and the hub. Tests make a throwaway
key at test time.
