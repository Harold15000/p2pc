# SPDX-License-Identifier: Apache-2.0
#
# iroh-relay 1.4.1 in plain-HTTP mode, for a PaaS whose edge terminates TLS (H2 spec §10.2). See README.md.
#
# Build (from the repository root):  podman build -t p2pc-relay deploy/relay
#
# Both base images are pinned by the digest of their multi-platform index (the tag is for humans). README.md says how
# to move them to newer ones.

FROM docker.io/library/rust:1.99.1-slim-trixie@sha256:f6c4a35d21dbb3c89d7a8d056c193e94fc09037f2b58dd858b09c39a47dd02d7 AS build
# The build E12 measured: the published crate with its own lock file.
RUN cargo install iroh-relay --version 1.4.1 --features server --locked --root /out

FROM docker.io/library/debian:trixie-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2
COPY --from=build /out/bin/iroh-relay /usr/local/bin/iroh-relay
COPY relay.toml /etc/iroh-relay/relay.toml
COPY entrypoint.sh /usr/local/bin/p2pc-relay-entrypoint
RUN chmod 0755 /usr/local/bin/p2pc-relay-entrypoint && chmod 0644 /etc/iroh-relay/relay.toml
# The platform routes its public HTTPS to this port (it sets PORT; 8080 when it does not).
ENV PORT=8080
EXPOSE 8080
# nobody:nogroup. The relay needs no privilege: an unprivileged port, nothing written but its rendered config in /tmp.
USER 65534:65534
ENTRYPOINT ["/usr/local/bin/p2pc-relay-entrypoint"]
