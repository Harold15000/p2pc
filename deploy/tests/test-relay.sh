#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Tests for deploy/relay/ (H2 §10.2): the iroh-relay config, its entrypoint and the container image's pins.
# No container runtime and no network: the entrypoint runs against a fake iroh-relay.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
relay="$here/../relay"
# shellcheck source=deploy/tests/lib.sh
source "$here/lib.sh"
# shellcheck source=deploy/relay/entrypoint.sh
source "$relay/entrypoint.sh"
make_scratch

# --- valid_port: the platform's $PORT, digits only, 1-65535.
for p in 1 80 8080 65535; do
  assert_true "port $p is valid" valid_port "$p"
done
# shellcheck disable=SC2016  # the literal text `$PORT`, unexpanded
for p in 0 080 65536 99999 "" "80a" "-1" "8080 " "1;true" '$PORT'; do
  assert_false "port [$p] is refused" valid_port "$p"
done

# --- relay.toml: the E12 config (H2 §10.2), and nothing else that would turn on TLS, QUIC or metrics.
config="$(<"$relay/relay.toml")"
# shellcheck disable=SC2016  # the literal text `$PORT`, unexpanded
for line in \
  'enable_relay = true' \
  'http_bind_addr = "[::]:$PORT"' \
  'enable_quic_addr_discovery = false' \
  'enable_metrics = false' \
  'access = "everyone"' \
  '[limits]' \
  'accept_conn_limit = 10.0' \
  'accept_conn_burst = 40' \
  '[limits.client.rx]' \
  'bytes_per_second = 4194304' \
  'max_burst_bytes = 16777216'; do
  assert_true "relay.toml has: $line" grep -qxF -- "$line" "$relay/relay.toml"
done
assert_false "relay.toml has no tls section (plain HTTP behind the platform's TLS edge)" grep -qE '^\[tls' "$relay/relay.toml"
assert_false "relay.toml sets no metrics address" grep -q 'metrics_bind_addr' "$relay/relay.toml"

# --- render_config: $PORT is the only substitution, everywhere it appears, and the rest is kept byte for byte.
rendered="$(render_config "$relay/relay.toml" 8080)"
assert_contains "$rendered" 'http_bind_addr = "[::]:8080"' "the port is rendered"
# shellcheck disable=SC2016  # the literal text `$PORT`, unexpanded
assert_false "no \$PORT is left" grep -qF '$PORT' <<<"$rendered"
assert_eq "${config//\$PORT/8080}" "$rendered" "nothing else changes"

# The rendered file is valid TOML with the right types, when a TOML parser is at hand (Python >= 3.11).
if python3 -c 'import tomllib' >/dev/null 2>&1; then
  printf '%s\n' "$rendered" >"$SCRATCH/rendered.toml"
  check_toml() {
    python3 -I - "$1" <<'EOF'
import sys, tomllib
c = tomllib.load(open(sys.argv[1], "rb"))
assert c["enable_relay"] is True
assert c["http_bind_addr"] == "[::]:8080"
assert c["enable_quic_addr_discovery"] is False
assert c["enable_metrics"] is False
assert c["access"] == "everyone"
assert "tls" not in c
assert c["limits"]["accept_conn_limit"] == 10.0 and isinstance(c["limits"]["accept_conn_limit"], float)
assert c["limits"]["accept_conn_burst"] == 40
assert c["limits"]["client"]["rx"] == {"bytes_per_second": 4194304, "max_burst_bytes": 16777216}
EOF
  }
  assert_true "the rendered config parses as the E12 config" check_toml "$SCRATCH/rendered.toml"
else
  echo "NOTE: python3 with tomllib is not installed; the TOML parse check is skipped"
fi

# --- main: runs iroh-relay on the rendered config, and refuses a bad port or a missing template.
fakebin="$SCRATCH/bin"
mkdir -p "$fakebin"
cat >"$fakebin/iroh-relay" <<'EOF'
#!/usr/bin/env bash
printf 'args: %s\n' "$*"
[[ "$1" == "--config-path" ]] && cat "$2"
EOF
chmod +x "$fakebin/iroh-relay"

out="$(PATH="$fakebin:$PATH" PORT=4321 RELAY_CONFIG_TEMPLATE="$relay/relay.toml" TMPDIR="$SCRATCH" \
  bash "$relay/entrypoint.sh" 2>&1)"
assert_contains "$out" "args: --config-path $SCRATCH/" "iroh-relay gets the rendered config"
assert_contains "$out" 'http_bind_addr = "[::]:4321"' "on the platform's port"

out="$(PATH="$fakebin:$PATH" RELAY_CONFIG_TEMPLATE="$relay/relay.toml" TMPDIR="$SCRATCH" \
  env -u PORT bash "$relay/entrypoint.sh" 2>&1)"
assert_contains "$out" 'http_bind_addr = "[::]:8080"' "8080 without a PORT"

run_main() { PATH="$fakebin:$PATH" TMPDIR="$SCRATCH" bash "$relay/entrypoint.sh"; }
status=0
out="$(PORT='80;id' RELAY_CONFIG_TEMPLATE="$relay/relay.toml" run_main 2>&1)" || status=$?
assert_eq 64 "$status" "a bad PORT exits 64"
assert_contains "$out" "PORT must be a TCP port number" "and says why"
assert_false "and never starts iroh-relay" grep -q 'args:' <<<"$out"
status=0
out="$(PORT=8080 RELAY_CONFIG_TEMPLATE="$SCRATCH/missing.toml" run_main 2>&1)" || status=$?
assert_eq 66 "$status" "a missing template exits 66 (iroh-relay would silently use its defaults: port 80, metrics on)"
assert_false "and never starts iroh-relay" grep -q 'args:' <<<"$out"

# --- Dockerfile: base images pinned by digest, the E12 build of iroh-relay, a non-root user.
mapfile -t froms < <(grep -E '^FROM ' "$relay/Dockerfile")
assert_eq 2 "${#froms[@]}" "a build stage and a runtime stage"
for f in "${froms[@]}"; do
  assert_true "pinned by digest: $f" grep -qE '^FROM docker\.io/library/[a-z0-9._/-]+:[A-Za-z0-9._-]+@sha256:[0-9a-f]{64}( AS [a-z]+)?$' <<<"$f"
done
assert_true "iroh-relay is built as in E12" \
  grep -qF 'cargo install iroh-relay --version 1.4.1 --features server --locked' "$relay/Dockerfile"
assert_true "the relay runs as a non-root user" grep -qE '^USER [1-9][0-9]*:[1-9][0-9]*$' "$relay/Dockerfile"
assert_true "the entrypoint is the script above" grep -qF 'ENTRYPOINT ["/usr/local/bin/p2pc-relay-entrypoint"]' "$relay/Dockerfile"

# --- railway.toml: the platform's health check is the relay's plain HTTP probe route.
assert_true "health check on /ping" grep -qxF 'healthcheckPath = "/ping"' "$relay/railway.toml"
assert_true "built from the Dockerfile" grep -qxF 'builder = "DOCKERFILE"' "$relay/railway.toml"

# --- No deployment details: no platform-generated domain, no token-looking setting.
assert_false "no platform-generated domain" grep -rqiE '[a-z0-9-]+\.up\.railway\.app' "$relay"
assert_false "no token or secret setting" grep -rqiE '(shared_token|bearer_token|IROH_RELAY_ACCESS_TOKEN|api[_-]?key) *=' "$relay"

finish_tests "test-relay.sh"
