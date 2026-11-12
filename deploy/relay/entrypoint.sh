#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# The relay container's entrypoint (H2 spec §10.2): renders relay.toml with the platform's $PORT and runs iroh-relay
# on it. Sourcing it only defines the functions (deploy/tests/test-relay.sh does).
#
# Environment:
#   PORT                    the TCP port the platform routes to (default 8080)
#   RELAY_CONFIG_TEMPLATE   the config template (default /etc/iroh-relay/relay.toml)
set -euo pipefail

# valid_port <value>: a TCP port number, 1-65535, digits only.
valid_port() {
  [[ "$1" =~ ^[1-9][0-9]{0,4}$ ]] && (($1 <= 65535))
}

# render_config <template> <port>: prints the template with every `$PORT` replaced by <port>, and nothing else changed.
render_config() {
  local text
  text="$(<"$1")"
  printf '%s\n' "${text//\$PORT/$2}"
}

main() {
  local port="${PORT:-8080}" template="${RELAY_CONFIG_TEMPLATE:-/etc/iroh-relay/relay.toml}" config
  if ! valid_port "$port"; then
    echo "error: PORT must be a TCP port number (1-65535), got ${port@Q}" >&2
    exit 64
  fi
  # iroh-relay silently falls back to its built-in defaults (port 80, metrics on) when the file is missing.
  if [[ ! -f "$template" ]]; then
    echo "error: no relay config template at $template" >&2
    exit 66
  fi
  config="$(mktemp "${TMPDIR:-/tmp}/relay-XXXXXX")"
  render_config "$template" "$port" >"$config"
  exec iroh-relay --config-path "$config"
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
fi
