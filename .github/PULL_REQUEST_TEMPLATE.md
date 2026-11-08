<!--
Thanks for contributing to P2PC. Please read CONTRIBUTING.md first: its hard rules (sandbox, egress, secrets,
public-repo hygiene) are not negotiable. Security fixes for an undisclosed vulnerability go through the Security tab,
not a public pull request.
-->

## What and why

<!-- What this pull request changes, and why. Link the issue it closes, if any (for example "Closes #123"). -->

## Tests

<!-- The tests you added or changed, and what you ran, with the results (including the number of tests). -->

- [ ] `cargo fmt --all --check`
- [ ] `cargo clippy --workspace --all-targets --all-features -- -D warnings`
- [ ] `cargo test --workspace`
- [ ] `cargo deny check` (if dependencies changed)
- [ ] `uv run --project sdk/python pytest` (if the Python SDK changed)
- [ ] `deploy/check.sh` (if `deploy/` or `scripts/` changed)

## Checklist

- [ ] Every commit is signed off (`git commit -s`), certifying the
      [Developer Certificate of Origin](https://developercertificate.org/): each one ends with a
      `Signed-off-by: Your Name <you@example.com>` line.
- [ ] No secrets, personal data, real hostnames or IP addresses (use `example.invalid` and the TEST-NET ranges).
- [ ] New source files start with an SPDX header (AGPL-3.0-only in `crates/p2pc-server`, Apache-2.0 elsewhere).
- [ ] The docs (`README.md`, `docs/`, `deploy/README.md`) still match the behaviour.
