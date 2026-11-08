#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Static lint for the BINARY DATA RULE of deploy/wsl/install.ps1: the bytes of the agent state must never pass through
# PowerShell as text. Windows PowerShell 5.1 re-encodes the stdout of a native command that is piped, captured or
# redirected, which corrupts a tar archive (the upgrade then fails its hash check, exit 23). It needs no PowerShell.
#
# What is flagged (comments are ignored):
#   - a tar that writes its archive to stdout (-cf - / -cpf - / -czf -), or a `cat` of a file, run through
#     Invoke-Wsl / Invoke-InDistro (their stdout is captured as text) or a wsl.exe call
#   - Invoke-WslStream with -OutFile (stdout of wsl.exe copied by PowerShell)
#   - wsl.exe output redirected with > or piped to Out-File / Set-Content / Add-Content / Tee-Object
# shellcheck disable=SC2016  # the fixtures are PowerShell source: nothing in them is meant to expand in bash
set -uo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=deploy/tests/lib.sh
source "$here/lib.sh"
make_scratch

# binary_stream_violations <file>: "line:text" for every line that breaks the rule.
binary_stream_violations() {
  # The one legitimate redirect is the cmd.exe command line of Get-CmdCopyOutArguments (marked by "/d /s /c"): cmd's own
  # redirection is byte-exact, which is the point.
  grep -nE -- '' "$1" | grep -vE '^[0-9]+:[[:space:]]*#' | grep -vF '/d /s /c' | grep -E \
    -e "tar[^|]*-c[a-z]*f[[:space:]'\",]+-([[:space:]'\",)]|\$)" \
    -e "Invoke-(Wsl|InDistro)[^#]*[^A-Za-z]cat[^A-Za-z][^#]*(\\.tar|\\\$inDistro|\\\$state)" \
    -e '-OutFile' \
    -e '(wsl(\.exe)?|Invoke-(Wsl|InDistro))[^#]*(\|[[:space:]]*(Out-File|Set-Content|Add-Content|Tee-Object)|[[:space:]]>[[:space:]]*[$"'"'"'A-Za-z])' || true
}

# --- the lint catches what it must (fixtures) -----------------------------------------------------------------------
bad() { printf '%s\n' "$1" >"$SCRATCH/bad.ps1"; binary_stream_violations "$SCRATCH/bad.ps1"; }
assert_true "tar to stdout in a wsl call" test -n "$(bad "\$r = Invoke-InDistro @('/bin/tar', '-cpf', '-', 'p2pc')")"
assert_true "tar to stdout, one string" test -n "$(bad '$a = "--exec /bin/tar --numeric-owner -C /var/lib -cpf - p2pc"')"
assert_true "cat of an archive through Invoke-InDistro" test -n "$(bad "\$r = Invoke-InDistro @('/bin/cat', '/var/tmp/x.tar')")"
assert_true "cat of the archive variable" test -n "$(bad "\$r = Invoke-InDistro @('/bin/cat', \$inDistroBackup)")"
assert_eq "" "$(bad "\$ver = Invoke-InDistro @('/bin/cat', '/etc/p2pc-distro-version')")" "cat of a text file is fine"
assert_eq "" "$(bad "Write-Log ('wsl {0} -> exit {1}' -f \$a, \$code) 'DEBUG'")" "-> in a log line is not a redirect"
assert_true "-OutFile" test -n "$(bad '$x = Invoke-WslStream -Arguments $a -OutFile $f')"
assert_true "wsl output piped to Out-File" test -n "$(bad 'wsl.exe -d p2pc-node --exec tar -cf x | Out-File -Encoding byte $f')"
assert_true "wsl output piped to Set-Content" test -n "$(bad '& wsl.exe -d x --exec cat y | Set-Content -Path $f')"
assert_true "wsl output redirected with >" test -n "$(bad '& wsl.exe -d x --exec cat y > $f')"
assert_true "tar -czf to stdout" test -n "$(bad "\$r = Invoke-Wsl @('tar', '-czf', '-', 'x')")"
assert_eq "" "$(bad '# Invoke-InDistro @(tar -cpf - p2pc) is what NOT to do')" "a comment is not flagged"
assert_eq "" "$(bad "\$r = Invoke-InDistro @('/usr/bin/sha256sum', \$LinuxPath)")" "a text command is fine"
assert_eq "" "$(bad "\$r = Invoke-InDistro @('/bin/tar', '--numeric-owner', '-C', '/var/lib', '-xpf', \$inDistroTar)")" "extracting a file is fine"
assert_eq "" "$(bad '$s = "set -e; tar -T - -cpf /var/tmp/x.tar; sha256sum /var/tmp/x.tar"')" "tar to a file is fine"

# --- and install.ps1 itself is clean ---------------------------------------------------------------------------------
found="$(binary_stream_violations "$here/../wsl/install.ps1")"
assert_eq "" "$found" "install.ps1 never streams binary data through PowerShell"
assert_true "the export goes through cmd.exe redirection" grep -qF 'cmd.exe' "$here/../wsl/install.ps1"
assert_true "install.ps1 documents the rule" grep -qF 'BINARY DATA RULE' "$here/../wsl/install.ps1"

# --- the platform block is the same in both Linux installers (T14c review P3 2) -------------------------------------------
# "what is a tested platform" must not drift between install-node.sh and install-server.sh: TESTED_PLATFORMS and
# tested_platform() are compared as text.
platform_block() {
  sed -n -e '/^TESTED_PLATFORMS=/p' -e '/^tested_platform() {$/,/^}$/p' "$1"
}
node_block="$(platform_block "$here/../linux/install-node.sh")"
server_block="$(platform_block "$here/../linux/install-server.sh")"
assert_true "the node installer has the platform block" test -n "$node_block"
assert_eq "$node_block" "$server_block" "TESTED_PLATFORMS and tested_platform() are identical in both installers"

finish_tests "test-install-lint"
