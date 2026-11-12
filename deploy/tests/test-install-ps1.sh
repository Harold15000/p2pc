#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Tests the pure helpers of deploy/wsl/install.ps1 by dot-sourcing it in PowerShell (the script does not run its
# Main when dot-sourced). Needs pwsh: without it this test is SKIPPED, unless CHECK_REQUIRE_PWSH=1 (CI sets it),
# in which case a missing pwsh is a failure.
set -uo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ps1="$here/../wsl/install.ps1"

if ! command -v pwsh >/dev/null 2>&1; then
  if [[ "${CHECK_REQUIRE_PWSH:-0}" == 1 ]]; then
    echo "test-install-ps1: pwsh is not installed but CHECK_REQUIRE_PWSH=1" >&2
    exit 1
  fi
  echo "test-install-ps1: SKIPPED (pwsh is not installed)"
  exit 0
fi

# shellcheck disable=SC2016  # PowerShell code: nothing in it is meant to expand in bash
P2PC_PS1="$ps1" P2PC_README="$here/../README.md" pwsh -NoProfile -NonInteractive -Command '
  $ErrorActionPreference = "Stop"
  . $env:P2PC_PS1
  $realGetDistroNow = ${function:Get-DistroNow}
  $realGetAgentStatus = ${function:Get-AgentStatus}
  $realWrapperPath = ${function:Get-NodeTaskWrapperPath}
  $realRegisterNodeTask = ${function:Register-NodeTask}
  $realInvokeInDistro = ${function:Invoke-InDistro}
  $realInvokeWsl = ${function:Invoke-Wsl}
  $realSetNodeTaskSddl = ${function:Set-NodeTaskSddl}
  # The wrapper and the record of a terminal stop, in a scratch dir (the real paths are Windows paths).
  $taskFiles = Join-Path ([System.IO.Path]::GetTempPath()) ("p2pc-taskfiles-" + [guid]::NewGuid().ToString("N"))
  New-Item -ItemType Directory -Force -Path $taskFiles | Out-Null
  function Get-NodeTaskWrapperPath { return (Join-Path $taskFiles "node-task.cmd") }
  function Get-NodeStopRecordPath { return (Join-Path $taskFiles "stopped-by-node") }
  function Write-StopRecord([string]$code) { [System.IO.File]::WriteAllText((Get-NodeStopRecordPath), ("node_exit=64`r`nexit_code=" + $code + "`r`ntime=2026-11-06T10:00:00Z`r`nreason=stub reason " + $code + "`r`ndisabled=yes`r`n")) }
  function Remove-StopRecord { Remove-Item -LiteralPath (Get-NodeStopRecordPath) -Force -ErrorAction SilentlyContinue }
  $fail = 0; $n = 0
  function Check([string]$name, $want, $got) {
    $script:n++
    if ($want -ne $got) { $script:fail++; Write-Host ("FAIL: {0}: want [{1}] got [{2}]" -f $name, $want, $got) }
  }
  # --- Get-StateProbe: absent is believed only on a positive answer -------------------------------------------------
  Check "present"                  "present" (Get-StateProbe -ExitCode 0 -Output "P2PC_STATE=present")
  Check "present with CRLF"        "present" (Get-StateProbe -ExitCode 0 -Output "P2PC_STATE=present`r`n")
  Check "absent"                   "absent"  (Get-StateProbe -ExitCode 0 -Output "P2PC_STATE=absent`n")
  Check "marker among noise"       "absent"  (Get-StateProbe -ExitCode 0 -Output "wsl: some warning`nP2PC_STATE=absent")
  Check "non-zero exit"            "unknown" (Get-StateProbe -ExitCode 1 -Output "P2PC_STATE=absent")
  Check "wsl failure code"         "unknown" (Get-StateProbe -ExitCode -1 -Output "")
  Check "empty output"             "unknown" (Get-StateProbe -ExitCode 0 -Output "")
  Check "no marker"                "unknown" (Get-StateProbe -ExitCode 0 -Output "something else")
  Check "two markers"              "unknown" (Get-StateProbe -ExitCode 0 -Output "P2PC_STATE=present`nP2PC_STATE=absent")
  Check "the same marker twice"    "unknown" (Get-StateProbe -ExitCode 0 -Output "P2PC_STATE=absent`nP2PC_STATE=absent")
  Check "unknown value"            "unknown" (Get-StateProbe -ExitCode 0 -Output "P2PC_STATE=maybe")
  Check "wrong case"               "unknown" (Get-StateProbe -ExitCode 0 -Output "p2pc_state=absent")
  Check "marker inside a longer line" "unknown" (Get-StateProbe -ExitCode 0 -Output "xP2PC_STATE=absent")
  # H2 8.3: the hub data (/var/lib/p2pc-server) without the agent state is its own answer, never "absent"
  Check "hub data only"            "hub-only" (Get-StateProbe -ExitCode 0 -Output "P2PC_STATE=hub-only`n")
  Check "hub data only, wrong case" "unknown" (Get-StateProbe -ExitCode 0 -Output "P2PC_STATE=HUB-ONLY")
  # --- the listing filter (paths are relative to /var/lib: p2pc/... and, on the hub PC, p2pc-server/...) ---------------
  Check "ignores tmp"              $true  (Test-StateListingIgnored "700:0:0:d:p2pc/tmp")
  Check "ignores tmp content"      $true  (Test-StateListingIgnored "600:0:0:f:p2pc/tmp/nvidia-cdi.abc.yaml")
  Check "ignores boot-status"      $true  (Test-StateListingIgnored "600:0:0:f:p2pc/boot-status.json")
  Check "ignores a boot-status temp" $true (Test-StateListingIgnored "600:0:0:f:p2pc/.boot-status.AbC123")
  Check "keeps the identity key"   $false (Test-StateListingIgnored "600:0:0:f:p2pc/identity.key")
  Check "keeps a nested tmp name"  $false (Test-StateListingIgnored "700:0:0:d:p2pc/jobs/tmp")
  Check "keeps the root entry"     $false (Test-StateListingIgnored "700:0:0:d:p2pc")
  Check "keeps the hub root entry" $false (Test-StateListingIgnored "700:0:0:d:p2pc-server")
  Check "keeps the hub database"   $false (Test-StateListingIgnored "600:0:0:f:p2pc-server/p2pc.db")
  Check "keeps the hub tmp (only p2pc-boot files of p2pc/ are skipped)" $false (Test-StateListingIgnored "700:0:0:d:p2pc-server/tmp")
  Check "keeps a hub boot-status name" $false (Test-StateListingIgnored "600:0:0:f:p2pc-server/boot-status.json")
  Check "ignores a socket"         $true  (Test-StateListingIgnored "755:0:0:s:p2pc/run/agent.sock")
  Check "ignores a FIFO"           $true  (Test-StateListingIgnored "600:0:0:p:p2pc/jobs/ctl.fifo")
  Check "ignores a nested socket"  $true  (Test-StateListingIgnored "600:0:0:s:p2pc/a/b/c.sock")
  Check "ignores a hub socket"     $true  (Test-StateListingIgnored "600:0:0:s:p2pc-server/x.sock")
  Check "keeps a file named like a type" $false (Test-StateListingIgnored "600:0:0:f:p2pc/s")
  Check "keeps a directory"        $false (Test-StateListingIgnored "700:0:0:d:p2pc/jobs")
  Check "keeps a symlink"          $false (Test-StateListingIgnored "777:0:0:l:p2pc/link")
  # --- Get-StateListing: one find over /var/lib that lists p2pc and p2pc-server only, paths relative to /var/lib --------
  function Invoke-InDistro { param([string[]]$Command) $script:listingArgs = $Command; return (New-Object psobject -Property @{ ExitCode = 0; Output = "700:0:0:d:p2pc`n600:0:0:f:p2pc/identity.key`n600:0:0:f:p2pc/boot-status.json`n700:0:0:d:p2pc-server`n600:0:0:f:p2pc-server/p2pc.db`n" }) }
  $listing = Get-StateListing
  Set-Item -Path function:local:Invoke-InDistro -Value $realInvokeInDistro
  Check "listing: 26 arguments" 26 $script:listingArgs.Count
  Check "listing: one find from /var/lib" "/usr/bin/find /var/lib -mindepth 1" (($script:listingArgs[0..3]) -join " ")
  Check "listing: everything but p2pc and p2pc-server is pruned" "! -path /var/lib/p2pc ! -path /var/lib/p2pc/* ! -path /var/lib/p2pc-server ! -path /var/lib/p2pc-server/* -prune -o" (($script:listingArgs[4..17]) -join " ")
  Check "listing: paths relative to /var/lib, no sockets or FIFOs" "! -type s ! -type p -printf %m:%U:%G:%y:%P\n" (($script:listingArgs[18..25]) -join " ")
  Check "listing: four entries (the boot status file is not compared)" 4 @($listing).Count
  foreach ($e in @("700:0:0:d:p2pc", "600:0:0:f:p2pc/identity.key", "700:0:0:d:p2pc-server", "600:0:0:f:p2pc-server/p2pc.db")) {
      Check ("listing: compares " + $e) $true ($listing -ccontains $e)
  }
  # --- Get-BackupsToPrune: keep the newest 3 COMPLETED backups, never touch a failed one ------------------------------
  $ok = @("p2pc-state-20261101120000.ok.tar","p2pc-state-20261102120000.ok.tar","p2pc-state-20261103120000.ok.tar","p2pc-state-20261104120000.ok.tar","p2pc-state-20261105120000.ok.tar")
  Check "keeps the newest 3, prunes the 2 oldest" "p2pc-state-20261102120000.ok.tar,p2pc-state-20261101120000.ok.tar" ((Get-BackupsToPrune -Names $ok -Keep 3) -join ",")
  Check "order of the input does not matter" "p2pc-state-20261102120000.ok.tar,p2pc-state-20261101120000.ok.tar" ((Get-BackupsToPrune -Names @($ok[2], $ok[0], $ok[4], $ok[1], $ok[3]) -Keep 3) -join ",")
  Check "3 backups: nothing to prune" 0 (@(Get-BackupsToPrune -Names @($ok[0..2]) -Keep 3).Count)
  Check "fewer than 3: nothing to prune" 0 (@(Get-BackupsToPrune -Names @($ok[0..1]) -Keep 3).Count)
  Check "no backups: nothing to prune" 0 (@(Get-BackupsToPrune -Names @() -Keep 3).Count)
  Check "default keeps 3" 2 (@(Get-BackupsToPrune -Names $ok).Count)
  $mixed = $ok + @("p2pc-state-20260101000000.tar", "p2pc-state-20261106120000.tar", "notes.txt", "p2pc-state-2026.ok.tar")
  Check "a failed upgrade backup (no .ok) is never pruned, however old" "p2pc-state-20261102120000.ok.tar,p2pc-state-20261101120000.ok.tar" ((Get-BackupsToPrune -Names $mixed -Keep 3) -join ",")
  Check "only failed backups: nothing is pruned" 0 (@(Get-BackupsToPrune -Names @("p2pc-state-20261101120000.tar", "p2pc-state-20261102120000.tar", "p2pc-state-20261103120000.tar", "p2pc-state-20261104120000.tar") -Keep 1).Count)
  Check "files of other kinds are never pruned" 0 (@(Get-BackupsToPrune -Names @("a.txt", "b.txt", "c.txt", "d.txt") -Keep 1).Count)
  Check "the keep count is respected" 4 (@(Get-BackupsToPrune -Names $ok -Keep 1).Count)
  # --- binary data never goes through PowerShell: the cmd.exe copy-out command line and its path guards ---------------
  $q = [char]34
  $win = "C:\Users\a b\AppData\Local\P2PC\backups\p2pc-state-1.tar"
  $want = "/d /s /c " + $q + $q + "wsl.exe" + $q + " -d p2pc-node -u root --exec /bin/cat /var/tmp/p2pc-state-1.tar > " + $q + $win + $q + $q
  Check "cmd copy-out line" $want (Get-CmdCopyOutArguments -Distro "p2pc-node" -LinuxPath "/var/tmp/p2pc-state-1.tar" -WinPath $win)
  Check "plain path is cmd-safe"   $true  (Test-CmdSafePath "C:\Users\a b\x.tar")
  Check "ampersand is fine inside quotes" $true (Test-CmdSafePath "C:\Users\A&B\x.tar")
  Check "percent is refused"       $false (Test-CmdSafePath "C:\Users\%USERNAME%\x.tar")
  Check "double quote is refused"  $false (Test-CmdSafePath ("C:\Users\a" + $q + "b\x.tar"))
  Check "empty path is refused"    $false (Test-CmdSafePath "")
  Check "linux path ok"            $true  (Test-LinuxSafePath "/var/tmp/p2pc-state-20261105163011.tar")
  Check "linux path with space"    $false (Test-LinuxSafePath "/var/tmp/a b.tar")
  Check "linux path with quote"    $false (Test-LinuxSafePath ("/var/tmp/a" + $q + "b.tar"))
  Check "linux path with semicolon" $false (Test-LinuxSafePath "/var/tmp/a;rm.tar")
  Check "linux relative path"      $false (Test-LinuxSafePath "var/tmp/a.tar")
  $sc = Get-StateArchiveScript "/var/tmp/p2pc-state-1.tar"
  Check "the output path is filled in everywhere" 0 ([regex]::Matches($sc, "@OUT@")).Count
  Check "the archive script writes the file and hashes it" $true ($sc.Contains("-cpf /var/tmp/p2pc-state-1.tar; sha256sum /var/tmp/p2pc-state-1.tar"))
  $threw = $false
  try { $null = Get-StateArchiveScript "/var/tmp/x; rm -rf /" } catch { $threw = $true }
  Check "an unsafe archive path is refused" $true $threw
  # --- Test-DistroDirNames: only the files WSL owns (ext4.vhdx, shortcut.ico) may be in the distro directory ----------
  Check "empty directory ok"       $true  (Test-DistroDirNames @())
  Check "only the vhdx ok"         $true  (Test-DistroDirNames @("ext4.vhdx"))
  Check "vhdx and shortcut.ico ok (what WSL 2.7.8 leaves)" $true (Test-DistroDirNames @("ext4.vhdx", "shortcut.ico"))
  Check "other case ok"            $true  (Test-DistroDirNames @("EXT4.VHDX", "Shortcut.ICO"))
  Check "only the icon ok"         $true  (Test-DistroDirNames @("shortcut.ico"))
  Check "an extra file is refused" $false (Test-DistroDirNames @("ext4.vhdx", "shortcut.ico", "notes.txt"))
  Check "an extra folder is refused" $false (Test-DistroDirNames @("ext4.vhdx", "backup"))
  Check "a different disk is refused" $false (Test-DistroDirNames @("ext4.vhdx.bak"))
  Check "a similar icon is refused" $false (Test-DistroDirNames @("shortcut.ico.old"))
  Check "only something else is refused" $false (Test-DistroDirNames @("readme.md"))
  Check "foreign names are listed" "notes.txt,backup" ((Get-ForeignNames @("ext4.vhdx", "notes.txt", "shortcut.ico", "backup")) -join ",")
  Check "the allow-list is exactly the two WSL files" "ext4.vhdx,shortcut.ico" ($WslOwnedFiles -join ",")
  # --- -Uninstall: verified backups go, the backup of a FAILED upgrade never does unless -DeleteFailedBackups ----------
  Check "backup name: verified"    $true  (Test-StateBackupName "p2pc-state-20261105163011.ok.tar")
  Check "backup name: unfinished"  $true  (Test-StateBackupName "p2pc-state-20261105163011.tar")
  Check "backup name: other file"  $false (Test-StateBackupName "notes.txt")
  Check "backup name: similar"     $false (Test-StateBackupName "p2pc-state-2026.tar")
  Check "backup name: suffix"      $false (Test-StateBackupName "p2pc-state-20261105163011.tar.bak")
  Check "verified: .ok.tar"        $true  (Test-StateBackupVerified "p2pc-state-20261105163011.ok.tar")
  Check "verified: plain .tar is not" $false (Test-StateBackupVerified "p2pc-state-20261105163011.tar")
  $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("p2pc-uninstall-" + [guid]::NewGuid().ToString("N"))
  $env:LOCALAPPDATA = $tmp
  $script:wslCalls = @()
  $script:unregExit = 0
  $script:asked = ""
  $script:logged = @()
  function Test-Wsl { }
  function Test-DistroExists { return $true }
  function Get-DistroBasePath { return $null }
  function Invoke-Wsl { param([string[]]$WslArgs) $script:wslCalls += ($WslArgs -join " "); return (New-Object psobject -Property @{ ExitCode = $script:unregExit; Output = "" }) }
  function Confirm-Action { param([string]$Question) $script:asked = $Question }
  function Write-Log { param([string]$Message, [string]$Level = "INFO") $script:logged += ($Level + ": " + $Message) }
  # The Scheduled Task, stubbed: every call goes into the same list as the wsl.exe calls, so the order can be checked.
  $script:taskRegistered = $true
  $script:taskRemoveFails = $false
  function Test-NodeTaskRegistered { return $script:taskRegistered }
  function Stop-NodeTask { $script:wslCalls += "task:stop" }
  function Start-NodeTask { $script:wslCalls += "task:start"; return $true }
  function Disable-NodeTask { $script:wslCalls += "task:disable" }
  function Enable-NodeTask { $script:wslCalls += "task:enable"; return $true }
  function Remove-NodeTask { $script:wslCalls += "task:remove"; if ($script:taskRemoveFails) { Fail 37 "stub: could not remove the task" } }
  $bd = Get-BackupDir
  $okA = Join-Path $bd "p2pc-state-20261105163011.ok.tar"
  $okB = Join-Path $bd "p2pc-state-20261105170000.ok.tar"
  $failA = Join-Path $bd "p2pc-state-20261105180000.tar"
  function Reset-Backups([bool]$withOther, [bool]$withFailed) {
      if (Test-Path -LiteralPath $bd) { Remove-Item -LiteralPath $bd -Recurse -Force }
      New-Item -ItemType Directory -Force -Path $bd | Out-Null
      Set-Content -LiteralPath $okA -Value "a"
      Set-Content -LiteralPath $okB -Value "b"
      if ($withFailed) { Set-Content -LiteralPath $failA -Value "f" }
      if ($withOther) { Set-Content -LiteralPath (Join-Path $bd "notes.txt") -Value "c" }
      $script:wslCalls = @(); $script:asked = ""; $script:logged = @()
  }
  $advice = Get-FailedBackupAdvice
  # default: the verified backups are deleted, the failed one is kept and listed by full path
  $KeepBackups = [switch]$false; $DeleteFailedBackups = [switch]$false
  Reset-Backups $false $true
  Invoke-UninstallAction
  Check "default: the task is removed, then the distro is unregistered" "task:remove|--unregister p2pc-node" ($script:wslCalls -join "|")
  Check "default: verified backups deleted"          $false ((Test-Path -LiteralPath $okA) -or (Test-Path -LiteralPath $okB))
  Check "default: the failed backup is KEPT"         $true  (Test-Path -LiteralPath $failA)
  Check "default: the folder stays (it is not empty)" $true (Test-Path -LiteralPath $bd)
  Check "default: the prompt says 2 verified files go" $true ($script:asked.Contains("deletes the 2 verified"))
  Check "default: the prompt lists the failed backup by full path" $true ($script:asked.Contains($failA))
  Check "default: the prompt says it is KEPT"        $true ($script:asked.Contains("KEPT"))
  Check "default: the prompt says it is the only copy of the identity" $true ($script:asked.Contains("only copy of that node"))
  Check "default: the prompt gives the advice sentence" $true ($script:asked.Contains($advice))
  Check "default: the prompt names the switch"       $true ($script:asked.Contains("-DeleteFailedBackups"))
  Check "default: the prompt does not claim it deletes the failed one" $false ($script:asked.Contains("Deleted unfinished"))
  $finalWarn = @($script:logged | Where-Object { $_.StartsWith("WARN: KEPT the backup(s)") })
  Check "default: the final message warns once"      1 $finalWarn.Count
  Check "default: the final message lists the full path" $true ($finalWarn.Count -eq 1 -and $finalWarn[0].Contains($failA))
  Check "default: the final message has the advice sentence" $true ($finalWarn.Count -eq 1 -and $finalWarn[0].Contains($advice))
  # -Force skips the prompt but changes nothing: the failed backup is still kept
  Reset-Backups $false $true
  $Force = [switch]$true
  Invoke-UninstallAction
  $Force = [switch]$false
  Check "-Force: the failed backup is still kept"    $true  (Test-Path -LiteralPath $failA)
  Check "-Force: verified backups deleted"           $false (Test-Path -LiteralPath $okA)
  # default, no failed backup: the folder goes with the last file; a foreign file is never touched
  Reset-Backups $false $false
  Invoke-UninstallAction
  Check "no failed backup: the folder is removed"    $false (Test-Path -LiteralPath $bd)
  Check "no failed backup: no KEPT warning"          0 @($script:logged | Where-Object { $_.Contains("KEPT the backup(s)") }).Count
  Reset-Backups $true $false
  Invoke-UninstallAction
  Check "a foreign file is never touched"            $true (Test-Path -LiteralPath (Join-Path $bd "notes.txt"))
  Check "a foreign file: verified backups deleted"   0 @(Get-StateBackupFiles $bd).Count
  # -DeleteFailedBackups: both kinds are deleted
  $DeleteFailedBackups = [switch]$true
  Reset-Backups $false $true
  Invoke-UninstallAction
  Check "-DeleteFailedBackups: everything is deleted" $false (Test-Path -LiteralPath $bd)
  Check "-DeleteFailedBackups: the prompt names the failed backup it deletes" $true ($script:asked.Contains($failA) -and $script:asked.Contains("-DeleteFailedBackups"))
  Check "-DeleteFailedBackups: no KEPT warning"      0 @($script:logged | Where-Object { $_.Contains("KEPT the backup(s)") }).Count
  $DeleteFailedBackups = [switch]$false
  # -KeepBackups: nothing is deleted
  $KeepBackups = [switch]$true
  Reset-Backups $false $true
  Invoke-UninstallAction
  Check "-KeepBackups: the distro is still unregistered" "task:remove|--unregister p2pc-node" ($script:wslCalls -join "|")
  Check "-KeepBackups: all three files remain"       3 @(Get-StateBackupFiles $bd).Count
  Check "-KeepBackups: the prompt says KEPT and names the folder" $true ($script:asked.Contains("KEPT") -and $script:asked.Contains($bd))
  Check "-KeepBackups: the prompt lists the failed backup" $true ($script:asked.Contains($failA))
  Check "-KeepBackups: the final message says KEPT"  1 @($script:logged | Where-Object { $_.StartsWith("OK:") -and $_.Contains("KEPT every state backup") }).Count
  $KeepBackups = [switch]$false
  # the task cannot be removed: the distro is NOT unregistered, nothing is deleted
  Reset-Backups $false $true
  $script:taskRemoveFails = $true
  $script:ExitCode = 0
  try { Invoke-UninstallAction } catch { }
  Check "task removal failed: exit 37" 37 $script:ExitCode
  Check "task removal failed: the distro is not unregistered" "task:remove" ($script:wslCalls -join "|")
  Check "task removal failed: the backups are all still there" 3 @(Get-StateBackupFiles $bd).Count
  $script:taskRemoveFails = $false
  $script:ExitCode = 0
  # no task registered (an older install): uninstall still works
  Reset-Backups $false $false
  $script:taskRegistered = $false
  Invoke-UninstallAction
  Check "no task: the distro is unregistered" $true (($script:wslCalls -join "|").EndsWith("--unregister p2pc-node"))
  # the wrapper and the record of a terminal stop are the installer files: -Uninstall removes them
  Reset-Backups $false $false
  Set-Content -LiteralPath (Get-NodeTaskWrapperPath) -Value "@echo off"
  Write-StopRecord 7
  Invoke-UninstallAction
  Check "uninstall: the wrapper is removed" $false (Test-Path -LiteralPath (Get-NodeTaskWrapperPath))
  Check "uninstall: the stop record is removed" $false (Test-Path -LiteralPath (Get-NodeStopRecordPath))
  $script:taskRegistered = $true
  # the distro is gone but its task is not (review P3-5): the task is removed, then exit 27
  Reset-Backups $false $false
  function Test-DistroExists { return $false }
  $script:ExitCode = 0
  try { Invoke-UninstallAction } catch { }
  Check "distro gone, task left: exit 27" 27 $script:ExitCode
  Check "distro gone, task left: the task is removed all the same" "task:remove" ($script:wslCalls -join "|")
  function Test-DistroExists { return $true }
  $script:ExitCode = 0
  # a failed unregister deletes nothing
  Reset-Backups $false $true
  $script:unregExit = 1
  try { Invoke-UninstallAction } catch { }
  Check "unregister failed: the backups are all still there" 3 @(Get-StateBackupFiles $bd).Count
  $script:unregExit = 0
  Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
  # the README, the prompt and the end-of-upgrade warning all say the same thing
  $readme = (Get-Content -Raw -LiteralPath $env:P2PC_README) -replace "\r?\n", " "
  $uninstallSection = $readme.Substring($readme.IndexOf("### 5. Uninstall"))
  $uninstallSection = $uninstallSection.Substring(0, $uninstallSection.IndexOf("### Why each setting"))
  foreach ($needle in @("-KeepBackups", "-DeleteFailedBackups", "p2pc-state-<timestamp>.ok.tar", "p2pc-state-<timestamp>.tar", "P2PC\backups", "never deletes it by default", "full path", $advice)) {
      Check ("README section 5 mentions " + $needle) $true ($uninstallSection.Contains($needle))
  }
  $psText = Get-Content -Raw -LiteralPath $env:P2PC_PS1
  Check "the script header documents -KeepBackups" $true ($psText.Contains(".PARAMETER KeepBackups"))
  Check "the script header documents -DeleteFailedBackups" $true ($psText.Contains(".PARAMETER DeleteFailedBackups"))
  Check "the failed-upgrade warning uses the same advice sentence" $true ($psText -match "did not finish\. The backup of the agent state was KEPT[^\r\n]*Get-FailedBackupAdvice")
  # --- the -Upgrade flow itself, with the same stubs as -Uninstall (no WSL, no Windows) -----------------------------
  $env:LOCALAPPDATA = Join-Path ([System.IO.Path]::GetTempPath()) ("p2pc-upgrade-" + [guid]::NewGuid().ToString("N"))
  $bd = Get-BackupDir
  $stateBytes = [byte[]](1..250)
  $sha = [System.Security.Cryptography.SHA256]::Create()
  $stateHash = ([BitConverter]::ToString($sha.ComputeHash($stateBytes)) -replace "-", "").ToLowerInvariant()
  $script:listBefore = @("700:0:0:d:p2pc", "600:0:0:f:p2pc/identity.key", "700:0:0:d:p2pc-server", "600:0:0:f:p2pc-server/p2pc.db")
  $script:listAfter = $script:listBefore
  $script:listCalls = 0
  $script:probeAnswer = "P2PC_STATE=present"
  $script:restoreExit = 0
  $script:importFails = $false
  $script:hashBackOverride = $null
  $script:inDistro = @()
  function Test-Prerequisites { param([string]$Dir) }
  function Assert-UpgradeDirClean { param([string]$Dir) }
  function Test-Image { return "image.tar" }
  function Get-DistroBasePath { return (Join-Path $env:LOCALAPPDATA "distro") }
  function Test-NewDistro { return "image_version=test" }
  function Get-StateListing { $script:listCalls++; if ($script:listCalls -eq 1) { return $script:listBefore } else { return $script:listAfter } }
  function Get-DistroFileHash { param([string]$LinuxPath) if ($script:hashBackOverride) { return $script:hashBackOverride } else { return $stateHash } }
  function Import-Distro { param([string]$TarPath, [string]$Dir) if ($script:importFails) { Fail 20 "wsl --import failed (stub)." }; $script:imported = $true; $script:NewConfigLayout = $null }
  function Invoke-WslStream { param([string]$Arguments, [string]$InFile) return (New-Object psobject -Property @{ ExitCode = 0; Stderr = "" }) }
  function Invoke-WslCopyOut {
      param([string]$LinuxPath, [string]$WinPath)
      [System.IO.File]::WriteAllBytes($WinPath, $stateBytes)
      return (New-Object psobject -Property @{ ExitCode = 0; Stderr = "" })
  }
  function Invoke-InDistro {
      param([string[]]$Command)
      $script:inDistro += ($Command -join " ")
      $ok = { param($out) New-Object psobject -Property @{ ExitCode = 0; Output = $out } }
      # The agent config, modelled: $null (no file), "empty" or "server" (holds [server]), in /etc/p2pc of the old distro
      # and /var/lib/p2pc, then in /var/lib/p2pc of the new distro (the image ships an empty one).
      if ($Command[0] -eq "/bin/sh" -and $Command[2] -eq $ConfigMigrationScript) {
          if ($script:migrationFails) { return (New-Object psobject -Property @{ ExitCode = 1; Output = "install: cannot create (stub)" }) }
          if ($null -ne $script:oldVarConfig) { return (& $ok "P2PC_CONFIG=present") }
          if ($script:oldEtcConfig -eq "server") { $script:oldVarConfig = "server"; return (& $ok "P2PC_CONFIG=moved") }
          $script:oldVarConfig = "empty"
          return (& $ok "P2PC_CONFIG=created")
      }
      if ($Command[0] -eq "/bin/sh") { return (& $ok $script:probeAnswer) }
      if ($Command[0] -eq "/bin/grep" -and $Command[-1] -eq "/var/lib/p2pc/agent.toml") {
          $cfg = $script:oldVarConfig
          if ($script:imported) { $cfg = $script:newVarConfig }
          if ($cfg -eq "server") { return (& $ok "") }
          return (New-Object psobject -Property @{ ExitCode = 1; Output = "" })
      }
      if ($Command[0] -eq "/bin/cat" -and $Command[1] -eq "/var/lib/p2pc/node-run.status") { return (& $ok $script:nodeRunStatus) }
      if ($Command[0] -eq "/bin/bash") {
          $script:archived = $script:oldVarConfig
          $m = [regex]::Match($Command[2], "-cpf (\S+);")
          return (& $ok ($stateHash + "  " + $m.Groups[1].Value))
      }
      if ($Command[0] -eq "/bin/tar") {
          if ($script:restoreExit -eq 0 -and -not $script:restoreDropsConfig) { $script:newVarConfig = $script:archived }
          return (New-Object psobject -Property @{ ExitCode = $script:restoreExit; Output = "tar failed (stub)" })
      }
      return (& $ok "")
  }
  function Reset-Upgrade {
      if (Test-Path -LiteralPath $bd) { Remove-Item -LiteralPath $bd -Recurse -Force }
      New-Item -ItemType Directory -Force -Path $bd | Out-Null
      $script:ExitCode = 0; $script:StateBackup = $null; $script:logged = @(); $script:wslCalls = @(); $script:inDistro = @()
      $script:listCalls = 0; $script:listAfter = $script:listBefore; $script:restoreExit = 0; $script:importFails = $false
      $script:hashBackOverride = $null; $script:probeAnswer = "P2PC_STATE=present"; $script:unregExit = 0
      $script:oldVarConfig = "server"; $script:oldEtcConfig = $null; $script:newVarConfig = "empty"; $script:archived = $null
      $script:imported = $false; $script:migrationFails = $false; $script:restoreDropsConfig = $false; $script:nodeRunStatus = ""
  }
  function Invoke-UpgradeSafely { try { Invoke-UpgradeAction (Join-Path $env:LOCALAPPDATA "distro") } catch { if ($_.Exception.Message -ne $script:FailMarker) { throw } } }
  # The task state and the agent status around the upgrade, stubbed (no Task Scheduler, no WSL, no real sleeps).
  $script:upgradeTaskState = "Running"
  $script:upgradeConnection = "connected (since 2026-11-06T12:00:01Z)"
  $script:upgradeSleeps = 0
  function Get-NodeTaskState { return $script:upgradeTaskState }
  # A fake monotonic clock: Start-Sleep advances it, and so does a slow `wsl.exe` ($script:statusDelay seconds per call).
  $script:fakeNow = 0
  $script:statusDelay = 0
  $script:statusCalls = 0
  function Get-MonotonicSeconds { return $script:fakeNow }
  function Get-AgentStatus { $script:statusCalls++; $script:fakeNow += $script:statusDelay; return (New-Object psobject -Property @{ ExitCode = 0; Output = ("Connection:    " + $script:upgradeConnection) }) }
  function Get-DistroNow { return [DateTimeOffset]::Parse("2026-11-06T12:00:00Z", [System.Globalization.CultureInfo]::InvariantCulture) }
  function Start-Sleep { param([int]$Seconds) $script:fakeNow += $Seconds; if ($Seconds -eq 2) { $script:upgradeSleeps++ } }
  function Reset-UpgradeTask { $script:upgradeTaskState = "Running"; $script:upgradeConnection = "connected (since 2026-11-06T12:00:01Z)"; $script:upgradeSleeps = 0 }
  # Registering the task again (round 4 real run, W1c: an upgraded node kept the action of an older install.ps1)
  function Register-NodeTask { param([switch]$Disabled, [switch]$WarnOnFailure)
      $w = "task:register"
      if ($Disabled) { $w += "-disabled" }
      if (-not $WarnOnFailure) { $w += "-failing" }
      $script:wslCalls += $w
  }
  $KeepBackups = [switch]$false; $DeleteFailedBackups = [switch]$false; $Force = [switch]$false

  # success: the backup becomes .ok.tar and only the newest 3 verified backups are kept; a failed one is never pruned
  Reset-Upgrade
  foreach ($nm in @("p2pc-state-20261101000000.ok.tar", "p2pc-state-20261102000000.ok.tar", "p2pc-state-20261103000000.ok.tar", "p2pc-state-20261104000000.ok.tar", "p2pc-state-20260101000000.tar")) {
      Set-Content -LiteralPath (Join-Path $bd $nm) -Value "old"
  }
  Invoke-UpgradeSafely
  $okNames = @(Get-ChildItem -LiteralPath $bd -Filter "p2pc-state-*.ok.tar" -File | ForEach-Object { $_.Name } | Sort-Object)
  Check "upgrade ok: exit code 0" 0 $script:ExitCode
  Check "upgrade ok: no StateBackup is left pending" $true ($null -eq $script:StateBackup)
  Check "upgrade ok: 3 verified backups kept" 3 $okNames.Count
  Check "upgrade ok: the oldest verified ones were pruned" $false ($okNames -contains "p2pc-state-20261101000000.ok.tar" -or $okNames -contains "p2pc-state-20261102000000.ok.tar")
  Check "upgrade ok: the two newest old ones stay" $true (($okNames -contains "p2pc-state-20261103000000.ok.tar") -and ($okNames -contains "p2pc-state-20261104000000.ok.tar"))
  $newOk = @($okNames | Where-Object { $_ -notmatch "^p2pc-state-2026110[1-4]" -and $_ -notmatch "^p2pc-state-20260101" })
  Check "upgrade ok: the new backup was renamed to .ok.tar" 1 $newOk.Count
  Check "upgrade ok: the new .ok.tar holds the exported bytes" $stateHash ((Get-FileHash -LiteralPath (Join-Path $bd $newOk[0]) -Algorithm SHA256).Hash.ToLowerInvariant())
  Check "upgrade ok: no new unfinished backup remains" 1 @(Get-StateBackupFiles $bd "Unfinished").Count
  Check "upgrade ok: the old failed backup is untouched" $true (Test-Path -LiteralPath (Join-Path $bd "p2pc-state-20260101000000.tar"))
  Check "upgrade ok: the in-distro archive was removed" $true (@($script:inDistro | Where-Object { $_ -like "/bin/rm -f /var/tmp/p2pc-state-*.tar" }).Count -ge 1)
  Check "upgrade ok: the copy in the new distro was removed" $true (@($script:inDistro | Where-Object { $_ -eq "/bin/rm -f /tmp/p2pc-state.tar" }).Count -ge 1)
  Check "upgrade ok: no kept-backup warning" 0 @($script:logged | Where-Object { $_.Contains("did not finish") }).Count
  $calls = $script:wslCalls -join "|"
  Check "upgrade ok: the task is disabled and stopped, and the distro terminated, before anything else" $true ($calls.StartsWith("task:disable|task:stop|--terminate p2pc-node"))
  Check "upgrade ok: the task is enabled and started again at the end" $true ($calls.EndsWith("task:enable|task:start"))
  Check "upgrade ok: and only once" 1 @($script:wslCalls | Where-Object { $_ -eq "task:start" }).Count
  Check "upgrade ok: the task is registered again (the wrapper and the rights of this install.ps1), disabled, then enabled and started" $true ($calls.EndsWith("task:register-disabled|task:enable|task:start"))
  Check "upgrade ok: registered once, and a failed registration only warns" 1 @($script:wslCalls | Where-Object { $_ -like "task:register*" }).Count
  Write-KeptBackupWarning
  Check "upgrade ok: Write-KeptBackupWarning is silent" 0 @($script:logged | Where-Object { $_.Contains("did not finish") }).Count

  # failure 25 (the restore): p2pc-state-<ts>.tar stays, its path is logged and the end-of-run warning names it
  Reset-Upgrade
  $script:restoreExit = 1
  Invoke-UpgradeSafely
  $plain = @(Get-StateBackupFiles $bd "Unfinished")
  Check "fail 25: exit code" 25 $script:ExitCode
  Check "fail 25: the unfinished backup stays" 1 $plain.Count
  Check "fail 25: nothing was renamed to .ok.tar" 0 @(Get-StateBackupFiles $bd "Verified").Count
  Check "fail 25: the path is logged" $true (@($script:logged | Where-Object { $_.Contains($plain[0]) }).Count -ge 1)
  Check "fail 25: StateBackup points at it" $plain[0] $script:StateBackup
  Write-KeptBackupWarning
  $w = @($script:logged | Where-Object { $_.StartsWith("WARN: The upgrade did not finish") })
  Check "fail 25: the end-of-run warning names the file and has the advice" $true ($w.Count -eq 1 -and $w[0].Contains($plain[0]) -and $w[0].Contains($advice))
  Check "fail 25: the copy in the new distro was still removed" $true (@($script:inDistro | Where-Object { $_ -eq "/bin/rm -f /tmp/p2pc-state.tar" }).Count -ge 1)
  Check "fail 25: the new distro has no restored identity, so the task is NOT started" 0 @($script:wslCalls | Where-Object { $_ -eq "task:start" }).Count
  Check "fail 25: nor enabled (its 5-minute trigger stays off)" 0 @($script:wslCalls | Where-Object { $_ -eq "task:enable" }).Count
  Check "fail 25: registered again, disabled, and disabled once more at once" $true (($script:wslCalls -join "|").EndsWith("task:register-disabled|task:disable"))
  Check "fail 25: the log says how to start it again" 1 @($script:logged | Where-Object { $_.Contains("-Start") -and $_.Contains("stays stopped") }).Count
  Check "fail 25: and the log says the task stays stopped" 1 @($script:logged | Where-Object { $_.Contains("Scheduled Task") -and $_.Contains("stays stopped") }).Count

  # failure 25 (the copy into the new distro is corrupted)
  Reset-Upgrade
  $script:hashBackOverride = ("0" * 64)
  Invoke-UpgradeSafely
  Check "fail 25 (hash): exit code" 25 $script:ExitCode
  Check "fail 25 (hash): the unfinished backup stays" 1 @(Get-StateBackupFiles $bd "Unfinished").Count

  # failure 26 (the listing after the restore differs)
  Reset-Upgrade
  $script:listAfter = @("700:0:0:d:")
  Invoke-UpgradeSafely
  $plain = @(Get-StateBackupFiles $bd "Unfinished")
  Check "fail 26: exit code" 26 $script:ExitCode
  Check "fail 26: the unfinished backup stays" 1 $plain.Count
  Check "fail 26: nothing was renamed to .ok.tar" 0 @(Get-StateBackupFiles $bd "Verified").Count
  Check "fail 26: the path is logged" $true (@($script:logged | Where-Object { $_.Contains($plain[0]) }).Count -ge 1)
  Write-KeptBackupWarning
  Check "fail 26: the end-of-run warning names the file" 1 @($script:logged | Where-Object { $_.StartsWith("WARN: The upgrade did not finish") -and $_.Contains($plain[0]) }).Count

  # failure 20 (the import): the state is safe in the plain .tar and the log says where
  Reset-Upgrade
  $script:importFails = $true
  Invoke-UpgradeSafely
  $plain = @(Get-StateBackupFiles $bd "Unfinished")
  Check "fail 20: exit code" 20 $script:ExitCode
  Check "fail 20: the unfinished backup stays" 1 $plain.Count
  Check "fail 20: the log says the state is safe in the file" 1 @($script:logged | Where-Object { $_.Contains("The agent state is safe in: " + $plain[0]) }).Count

  # a failed unregister never reaches the import and keeps the backup too
  Reset-Upgrade
  $script:unregExit = 1
  Invoke-UpgradeSafely
  Check "fail 24: exit code" 24 $script:ExitCode
  Check "fail 24: the unfinished backup stays" 1 @(Get-StateBackupFiles $bd "Unfinished").Count
  $script:unregExit = 0
  # exit 23 (the old distro was never touched): the task is started again
  Reset-Upgrade
  $script:probeAnswer = "garbage"
  Invoke-UpgradeSafely
  Check "fail 23: exit code" 23 $script:ExitCode
  Check "fail 23: the old distro is untouched, so its task is started again" $true (($script:wslCalls -join "|").EndsWith("task:register-disabled|task:enable|task:start"))
  # H2 8.3: the hub data without the agent state is never dropped, not even with -Force (it holds the whole cloud)
  Reset-Upgrade
  $script:probeAnswer = "P2PC_STATE=hub-only"
  $Force = [switch]$true
  Invoke-UpgradeSafely
  $Force = [switch]$false
  Check "hub data only: exit 23, even with -Force" 23 $script:ExitCode
  Check "hub data only: nothing unregistered" 0 @($script:wslCalls | Where-Object { $_ -like "--unregister*" }).Count
  Check "hub data only: nothing archived" 0 @($script:inDistro | Where-Object { $_ -like "/bin/bash -c *" }).Count
  Check "hub data only: the message names the hub data" 1 @($script:logged | Where-Object { $_.Contains("/var/lib/p2pc-server") -and $_.Contains("NOT touched") }).Count
  # the upgrade archives both directories (one archive, one listing)
  Reset-Upgrade
  Invoke-UpgradeSafely
  Check "upgrade ok: the archive script carries /var/lib/p2pc-server too" 1 @($script:inDistro | Where-Object { $_ -like "/bin/bash -c *./p2pc-server*" }).Count
  Check "upgrade ok: the log names both directories" 1 @($script:logged | Where-Object { $_.Contains("Exported /var/lib/p2pc and /var/lib/p2pc-server") }).Count
  # no task registered: the upgrade neither stops nor starts one
  Reset-Upgrade
  $script:taskRegistered = $false
  Invoke-UpgradeSafely
  Check "no task: upgrade ok" 0 $script:ExitCode
  Check "no task: nothing is started" 0 @($script:wslCalls | Where-Object { $_ -like "task:*" }).Count
  $script:taskRegistered = $true
  # A node stopped with -Stop (task disabled) stays stopped through an upgrade (review P3-3)
  Reset-Upgrade; Reset-UpgradeTask
  $script:upgradeTaskState = "Disabled"
  Invoke-UpgradeSafely
  Check "stopped node: the upgrade succeeds" 0 $script:ExitCode
  Check "stopped node: the task is not enabled again" 0 @($script:wslCalls | Where-Object { $_ -eq "task:enable" }).Count
  Check "stopped node: nor started" 0 @($script:wslCalls | Where-Object { $_ -eq "task:start" }).Count
  Check "stopped node: the log says it stays stopped, and how to start it" 1 @($script:logged | Where-Object { $_.StartsWith("WARN:") -and $_.Contains("disabled before the upgrade") -and $_.Contains("-Start") }).Count
  Check "stopped node: the task is registered again (an older action gets the wrapper) and stays Disabled" $true (($script:wslCalls -join "|").EndsWith("task:register-disabled|task:disable"))
  # A node the wrapper disabled after "too old" (6): the newer image is the fix, so the upgrade enables it again
  Reset-Upgrade; Reset-UpgradeTask
  $script:upgradeTaskState = "Disabled"
  Write-StopRecord 6
  Invoke-UpgradeSafely
  Check "stopped as too old: the upgrade succeeds" 0 $script:ExitCode
  Check "stopped as too old: the task is registered again, enabled and started" $true (($script:wslCalls -join "|").EndsWith("task:register-disabled|task:enable|task:start"))
  Check "stopped as too old: the record is gone" $false (Test-Path -LiteralPath (Get-NodeStopRecordPath))
  Check "stopped as too old: the runner record in the distro is cleared too" 1 @($script:inDistro | Where-Object { $_ -eq "/bin/rm -f /var/lib/p2pc/node-run.status" }).Count
  # ... after "removed" (7): a newer image does not help; it stays off, with the advice
  Reset-Upgrade; Reset-UpgradeTask
  $script:upgradeTaskState = "Disabled"
  Write-StopRecord 7
  Invoke-UpgradeSafely
  Check "stopped as removed: the upgrade succeeds" 0 $script:ExitCode
  Check "stopped as removed: the task is not enabled" 0 @($script:wslCalls | Where-Object { $_ -eq "task:enable" -or $_ -eq "task:start" }).Count
  Check "stopped as removed: the record stays" $true (Test-Path -LiteralPath (Get-NodeStopRecordPath))
  Check "stopped as removed: it says to re-enroll with a new token" 1 @($script:logged | Where-Object { $_.StartsWith("WARN:") -and $_.Contains("-Join -Force") -and $_.Contains("join-token create") }).Count
  Check "stopped as removed: registered again, and kept Disabled" $true (($script:wslCalls -join "|").EndsWith("task:register-disabled|task:disable"))
  Remove-StopRecord
  # ... with no code in the record (the wrapper could not read it: Wsl/Service timeouts) and none in the distro: unknown
  Reset-Upgrade; Reset-UpgradeTask
  $script:upgradeTaskState = "Disabled"
  [System.IO.File]::WriteAllText((Get-NodeStopRecordPath), "node_exit=64`r`ndisabled=yes`r`n")
  Invoke-UpgradeSafely
  Check "stopped, code unknown: the upgrade succeeds" 0 $script:ExitCode
  Check "stopped, code unknown: the task stays off" 0 @($script:wslCalls | Where-Object { $_ -eq "task:enable" -or $_ -eq "task:start" }).Count
  Check "stopped, code unknown: it says unknown, see -Status" 1 @($script:logged | Where-Object { $_.StartsWith("WARN:") -and $_.Contains("unknown") -and $_.Contains("-Status") }).Count
  Check "stopped, code unknown: no advice for 7 or 8" 0 @($script:logged | Where-Object { $_.Contains("join-token create") }).Count
  # ... with no code in the record, but node-run.status in the distro has it (7)
  Reset-Upgrade; Reset-UpgradeTask
  $script:upgradeTaskState = "Disabled"
  $script:nodeRunStatus = "state=stopped`ntime=2026-11-06T10:00:00Z`nexit_code=7`nreason=stub"
  [System.IO.File]::WriteAllText((Get-NodeStopRecordPath), "node_exit=64`r`ndisabled=yes`r`n")
  Invoke-UpgradeSafely
  Check "stopped, code only in the distro: read from node-run.status (7), the advice for 7" 1 @($script:logged | Where-Object { $_.StartsWith("WARN:") -and $_.Contains("exit 7") -and $_.Contains("join-token create") }).Count
  Remove-StopRecord
  # ... and when the disable FAILED (the record says disabled=no) the task is still Ready: the stop record, not the task
  # state, decides. Resuming it would dial the server once more with a revoked identity (T14b3).
  foreach ($code in @("7", "8")) {
      Reset-Upgrade; Reset-UpgradeTask
      $script:upgradeTaskState = "Ready"
      [System.IO.File]::WriteAllText((Get-NodeStopRecordPath), ("node_exit=64`r`nexit_code=" + $code + "`r`ntime=2026-11-06T10:00:00Z`r`nreason=stub reason " + $code + "`r`ndisabled=no`r`n"))
      Invoke-UpgradeSafely
      Check ("stopped by " + $code + ", task still Ready: the upgrade succeeds") 0 $script:ExitCode
      Check ("stopped by " + $code + ", task still Ready: it is not enabled or started") 0 @($script:wslCalls | Where-Object { $_ -eq "task:enable" -or $_ -eq "task:start" }).Count
      Check ("stopped by " + $code + ", task still Ready: the record stays") $true (Test-Path -LiteralPath (Get-NodeStopRecordPath))
      Check ("stopped by " + $code + ", task still Ready: it is disabled again") $true (($script:wslCalls -join "|").EndsWith("task:register-disabled|task:disable"))
      Check ("stopped by " + $code + ", task still Ready: it says it stays stopped") 1 @($script:logged | Where-Object { $_.StartsWith("WARN:") -and $_.Contains("stays stopped") }).Count
      Remove-StopRecord
  }
  # ... a record with no code anywhere: unknown is not 6, so the same
  Reset-Upgrade; Reset-UpgradeTask
  $script:upgradeTaskState = "Ready"
  [System.IO.File]::WriteAllText((Get-NodeStopRecordPath), "node_exit=64`r`ndisabled=no`r`n")
  Invoke-UpgradeSafely
  Check "stopped, code unknown, task still Ready: it is not enabled or started" 0 @($script:wslCalls | Where-Object { $_ -eq "task:enable" -or $_ -eq "task:start" }).Count
  Check "stopped, code unknown, task still Ready: the record stays" $true (Test-Path -LiteralPath (Get-NodeStopRecordPath))
  Remove-StopRecord
  # ... but "too old" (6) is what a newer image fixes: Ready or Disabled, the upgrade resumes it and forgets the record
  Reset-Upgrade; Reset-UpgradeTask
  $script:upgradeTaskState = "Ready"
  [System.IO.File]::WriteAllText((Get-NodeStopRecordPath), "node_exit=64`r`nexit_code=6`r`ntime=2026-11-06T10:00:00Z`r`nreason=stub reason 6`r`ndisabled=no`r`n")
  Invoke-UpgradeSafely
  Check "stopped as too old, task still Ready: enabled and started" $true (($script:wslCalls -join "|").EndsWith("task:register-disabled|task:enable|task:start"))
  Check "stopped as too old, task still Ready: the record is gone" $false (Test-Path -LiteralPath (Get-NodeStopRecordPath))
  # a task the upgrade cannot register again keeps its old definition: a warning, never a failed upgrade
  Reset-Upgrade; Reset-UpgradeTask
  Invoke-UpgradeSafely
  Check "the upgrade registers the task with -WarnOnFailure (a registration failure is no failed upgrade)" 0 @($script:wslCalls | Where-Object { $_ -like "task:register*-failing" }).Count
  # The wait is a real deadline, not a count of loop turns (T14b3): a slow wsl.exe (25 s per status call) must not stretch
  # "up to 60 s" to many minutes.
  Reset-Upgrade; Reset-UpgradeTask
  $script:upgradeConnection = "not connected"
  $script:statusDelay = 25; $script:statusCalls = 0; $script:fakeNow = 0
  $null = Wait-NodeConnected -NotBefore (Get-DistroNow) -FailIfTaskStopped $false
  Check "slow wsl.exe: the wait ends at the deadline (3 status calls, not 31)" 3 $script:statusCalls
  Check "slow wsl.exe: about 60 s of the fake clock passed, plus the last slow call" $true ($script:fakeNow -ge 60 -and $script:fakeNow -le 90)
  Check "slow wsl.exe: it warns that it is not connected" 1 @($script:logged | Where-Object { $_.StartsWith("WARN:") -and $_.Contains("not connected since the task started") }).Count
  $script:statusDelay = 0
  # a fast one still polls every 2 s up to the deadline
  Reset-Upgrade; Reset-UpgradeTask
  $script:upgradeConnection = "not connected"
  $script:statusCalls = 0; $script:fakeNow = 0
  $null = Wait-NodeConnected -NotBefore (Get-DistroNow) -FailIfTaskStopped $false
  Check "fast wsl.exe: 31 status calls over 60 s" 31 $script:statusCalls
  Check "fast wsl.exe: and 30 sleeps of 2 s" 30 $script:upgradeSleeps
  # The node resumed after an upgrade must connect after the restart: a stale "connected" is not taken (real run)
  Reset-Upgrade; Reset-UpgradeTask
  $script:upgradeConnection = "connected (since 2026-11-06T11:49:00Z)"
  Invoke-UpgradeSafely
  Check "upgrade, stale connected: still exit 0 (the agent keeps trying)" 0 $script:ExitCode
  Check "upgrade, stale connected: it waits, then warns" 1 @($script:logged | Where-Object { $_.StartsWith("WARN:") -and $_.Contains("not connected since the task started") }).Count
  Check "upgrade, stale connected: it waited" $true ($script:upgradeSleeps -ge 25)
  Reset-Upgrade; Reset-UpgradeTask
  Invoke-UpgradeSafely
  Check "upgrade, fresh connected: accepted at once" 0 $script:upgradeSleeps
  Check "upgrade, fresh connected: no warning" 0 @($script:logged | Where-Object { $_.Contains("not connected") }).Count

  # --- the enrollment survives an upgrade (T14b2 review P2: the agent config lives in /var/lib/p2pc) -------------------
  # 0.2.2 layout, joined: [server] is in /var/lib/p2pc/agent.toml and comes along with the archive
  Reset-Upgrade; Reset-UpgradeTask
  Invoke-UpgradeSafely
  Check "0.2.2 layout, joined: exit 0" 0 $script:ExitCode
  Check "0.2.2 layout, joined: [server] is in the new distro" "server" $script:newVarConfig
  $calls = $script:inDistro -join "|"
  Check "the migration runs before the listing and the archive" $true ($calls.IndexOf($ConfigMigrationScript) -ge 0 -and $calls.IndexOf($ConfigMigrationScript) -lt $calls.IndexOf("/bin/bash -c"))
  # 0.2.1 layout, joined: [server] in /etc/p2pc/agent.toml is copied into /var/lib/p2pc first, so it survives
  Reset-Upgrade; Reset-UpgradeTask
  $script:oldVarConfig = $null; $script:oldEtcConfig = "server"
  Invoke-UpgradeSafely
  Check "0.2.1 layout, joined: exit 0" 0 $script:ExitCode
  Check "0.2.1 layout, joined: [server] is in the new distro (no new token)" "server" $script:newVarConfig
  Check "0.2.1 layout, joined: the log says it was copied" 1 @($script:logged | Where-Object { $_.StartsWith("OK:") -and $_.Contains("Copied /etc/p2pc/agent.toml") }).Count
  # 0.2.1 layout, never joined: an empty config is carried, and nothing is claimed
  Reset-Upgrade; Reset-UpgradeTask
  $script:oldVarConfig = $null; $script:oldEtcConfig = $null
  Invoke-UpgradeSafely
  Check "0.2.1 layout, not joined: exit 0" 0 $script:ExitCode
  Check "0.2.1 layout, not joined: an empty config in the new distro" "empty" $script:newVarConfig
  # the migration fails: exit 23 before anything is unregistered
  Reset-Upgrade; Reset-UpgradeTask
  $script:migrationFails = $true
  Invoke-UpgradeSafely
  Check "migration failed: exit 23" 23 $script:ExitCode
  Check "migration failed: nothing unregistered" 0 @($script:wslCalls | Where-Object { $_ -like "--unregister*" }).Count
  # the restore comes back without [server] (the bug the review found): exit 38, the backup kept, the task not started
  Reset-Upgrade; Reset-UpgradeTask
  $script:restoreDropsConfig = $true
  Invoke-UpgradeSafely
  Check "[server] lost: exit 38" 38 $script:ExitCode
  Check "[server] lost: the message says what to run" 1 @($script:logged | Where-Object { $_.Contains("-Join -Force") }).Count
  Check "[server] lost: the backup is kept as unfinished" 1 @(Get-StateBackupFiles $bd "Unfinished").Count
  Check "[server] lost: the task is not started" 0 @($script:wslCalls | Where-Object { $_ -eq "task:start" }).Count
  # the agent stops for good after the upgrade with exit 8 or 7: a failed upgrade, never exit 0 with a warning
  foreach ($code in @(8, 7)) {
      Reset-Upgrade; Reset-UpgradeTask
      $script:upgradeConnection = "not enrolled"
      $script:nodeRunStatus = "state=stopped`ntime=2026-11-06T12:00:05Z`nexit_code=$code`nreason=stub"
      Invoke-UpgradeSafely
      Check ("agent stopped with exit {0} after the upgrade: exit 38" -f $code) 38 $script:ExitCode
      Check ("exit {0}: it says what to run" -f $code) 1 @($script:logged | Where-Object { $_.StartsWith("ERROR:") -and $_.Contains("exit $code") }).Count
  }
  Reset-Upgrade; Reset-UpgradeTask
  $script:upgradeConnection = "connecting (since 2026-11-06T12:00:01Z)"
  $script:nodeRunStatus = "state=restarting`nexit_code=1"
  Invoke-UpgradeSafely
  Check "an agent still trying after the upgrade: a warning, exit 0" 0 $script:ExitCode
  Check "Get-ConfigMigrationResult: moved" "moved" (Get-ConfigMigrationResult -ExitCode 0 -Output "P2PC_CONFIG=moved`n")
  Check "Get-ConfigMigrationResult: failure" $null (Get-ConfigMigrationResult -ExitCode 1 -Output "P2PC_CONFIG=moved")
  Check "Get-ConfigMigrationResult: two markers" $null (Get-ConfigMigrationResult -ExitCode 0 -Output "P2PC_CONFIG=moved`nP2PC_CONFIG=created")
  Check "Get-ConfigMigrationResult: garbage" $null (Get-ConfigMigrationResult -ExitCode 0 -Output "P2PC_STATE=present")
  Remove-Item -LiteralPath $env:LOCALAPPDATA -Recurse -Force -ErrorAction SilentlyContinue
  # --- the boot status race: the status of THIS start of the distro, by identity (T14a2 review) ----------------------
  # p2pc-boot records init_starttime, field 22 of /proc/1/stat; fresh means it EQUALS the starttime of the distro init now.
  $proc1 = "1 (init) S 0 1 1 0 -1 4194560 100 0 0 0 5 6 0 0 20 0 1 0 12345 4096 100 18446744073709551615"
  Check "init starttime = field 22 of /proc/1/stat" "12345" (Get-ProcStarttime $proc1)
  Check "a command name with spaces and a parenthesis" "12345" (Get-ProcStarttime "1 (in it)x) S 0 1 1 0 -1 4194560 100 0 0 0 5 6 0 0 20 0 1 0 12345 4096")
  Check "starttime: short proc stat" $null (Get-ProcStarttime "1 (init) S 0 1")
  Check "starttime: garbage"         $null (Get-ProcStarttime "garbage")
  Check "the time-based Get-DistroStartEpoch is gone" $false ([bool](Get-Command Get-DistroStartEpoch -ErrorAction SilentlyContinue))
  $js = "{`"time`":`"2026-11-05T21:45:13Z`",`"init_starttime`":12345,`"cdi`":`"fresh`",`"cdi_regenerated`":false,`"errors`":[],`"notes`":[]}"
  $f = Get-BootStatusFields $js
  Check "status init_starttime"         "12345" $f.InitStarttime
  Check "status cdi"                    "fresh" $f.Cdi
  Check "status: no errors"             0 @($f.Errors).Count
  Check "status: no notes"              0 @($f.Notes).Count
  $js2 = "{`"time`":`"2026-11-05T21:45:13Z`",`"init_starttime`":12345,`"cdi`":`"nvidia_smi_failed`",`"cdi_regenerated`":false,`"errors`":[`"nvidia-smi -L failed; spec kept`",`"two \`"q\`"`"],`"notes`":[`"moved a, b ] x`"]}"
  $f2 = Get-BootStatusFields $js2
  Check "status: cdi nvidia_smi_failed" "nvidia_smi_failed" $f2.Cdi
  Check "status: two errors"            2 @($f2.Errors).Count
  Check "status: error text"            "nvidia-smi -L failed; spec kept" $f2.Errors[0]
  Check "status: escaped quote is unescaped" "two `"q`"" $f2.Errors[1]
  Check "status: a note with a bracket and a comma" "moved a, b ] x" $f2.Notes[0]
  Check "status: garbage has no init_starttime" $null (Get-BootStatusFields "not json").InitStarttime
  Check "status: null init_starttime"   $null (Get-BootStatusFields "{`"init_starttime`":null,`"cdi`":`"x`"}").InitStarttime
  Check "fresh: the same init"          $true  (Test-BootStatusFresh $f "12345")
  Check "stale: another init"           $false (Test-BootStatusFresh $f "12346")
  Check "stale: equality, not order"    $false (Test-BootStatusFresh $f "12344")
  Check "stale: no identity recorded"   $false (Test-BootStatusFresh (Get-BootStatusFields "{`"time`":`"2026-11-05T21:45:13Z`",`"cdi`":`"x`"}") "12345")
  Check "stale: unknown current init"   $false (Test-BootStatusFresh $f $null)
  # Wait-BootStatus with a scripted distro: the status file is read from a queue, one entry per poll
  # The file of the previous start: another init, and a LATER time (the clock stepped): time decides nothing.
  $oldJs = ($js -replace "12345", "11111") -replace "21:45:13", "23:59:59"
  $newJs = $js
  $script:statusQueue = @()
  $script:statusReads = 0
  $script:sleeps = 0
  function Start-Sleep { param([int]$Seconds) $script:sleeps++ }
  function Invoke-InDistro {
      param([string[]]$Command)
      $ok = { param($out) New-Object psobject -Property @{ ExitCode = 0; Output = $out } }
      if ($Command[0] -eq "/bin/cat" -and $Command[1] -eq "/proc/1/stat") { return (& $ok $proc1) }
      if ($Command[0] -eq "/bin/cat" -and $Command[1] -eq "/var/lib/p2pc/boot-status.json") {
          $i = [math]::Min($script:statusReads, $script:statusQueue.Count - 1)
          $script:statusReads++
          $v = $script:statusQueue[$i]
          if ($null -eq $v) { return (New-Object psobject -Property @{ ExitCode = 1; Output = "cat: No such file" }) }
          return (& $ok $v)
      }
      return (& $ok "")
  }
  # the status is already fresh: no sleep
  $script:statusQueue = @($newJs); $script:statusReads = 0; $script:sleeps = 0
  $w = Wait-BootStatus -Seconds 30
  Check "wait: a fresh status is returned at once" "fresh" $w.Cdi
  Check "wait: no sleep when it is already there" 0 $script:sleeps
  # file missing, then the OLD status from the previous start, then the new one: three polls
  $script:statusQueue = @($null, $oldJs, $oldJs, $newJs); $script:statusReads = 0; $script:sleeps = 0
  $w = Wait-BootStatus -Seconds 30
  Check "wait: the stale status is not accepted, the new one is" "12345" $w.InitStarttime
  Check "wait: it polled once a second until then" 3 $script:sleeps
  # never fresh: gives up after the limit, returns null (a warning, not an error)
  $script:statusQueue = @($oldJs); $script:statusReads = 0; $script:sleeps = 0
  $w = Wait-BootStatus -Seconds 5
  Check "wait: a status that never gets fresh returns null" $null $w
  Check "wait: it slept 5 times for a 5 s limit"      5 $script:sleeps
  $script:statusQueue = @($null); $script:statusReads = 0; $script:sleeps = 0
  Check "wait: no file at all returns null"           $null (Wait-BootStatus -Seconds 3)
  # Show-BootStatus messages
  $script:logged = @(); $script:statusQueue = @($newJs); $script:statusReads = 0; $script:sleeps = 0
  Show-BootStatus
  Check "show: a clean status is an OK line" 1 @($script:logged | Where-Object { $_.StartsWith("OK: p2pc-boot: cdi=fresh, no errors") }).Count
  $script:logged = @(); $script:statusQueue = @($js2); $script:statusReads = 0
  Show-BootStatus
  Check "show: nvidia_smi_failed is a WARN with the errors" 1 @($script:logged | Where-Object { $_.StartsWith("WARN: p2pc-boot: cdi=nvidia_smi_failed; errors: nvidia-smi -L failed; spec kept; two") }).Count
  Check "show: the notes are printed"       1 @($script:logged | Where-Object { $_.Contains("p2pc-boot note: moved a, b ] x") }).Count
  $script:logged = @(); $script:statusQueue = @($oldJs); $script:statusReads = 0
  Show-BootStatus
  Check "show: no fresh status is a WARN, not an error" 1 @($script:logged | Where-Object { $_.StartsWith("WARN: p2pc-boot has not written a fresh") }).Count
  Check "show: ... and not an ERROR"        0 @($script:logged | Where-Object { $_.StartsWith("ERROR:") }).Count
  Check "the upgrade and install flows call Show-BootStatus" 3 ([regex]::Matches((Get-Content -Raw -LiteralPath $env:P2PC_PS1), "(?m)^    Show-BootStatus$|^        Show-BootStatus$")).Count
  # --- T14b2: the Scheduled Task "P2PC node" ------------------------------------------------------------------------
  $env:SystemRoot = "C:\Windows"
  $td = Get-NodeTaskDefinition
  Check "task name"                    "P2PC node" $td.Name
  Check "task action: conhost.exe"     "C:\Windows\System32\conhost.exe" $td.Execute
  $savedLad = $env:LOCALAPPDATA
  $env:LOCALAPPDATA = "C:\Users\a b\AppData\Local"
  Check "the wrapper lives in %LOCALAPPDATA%\P2PC" "C:\Users\a b\AppData\Local\P2PC\node-task.cmd" (& $realWrapperPath)
  $env:LOCALAPPDATA = $savedLad
  Check "task action: headless cmd.exe running the wrapper, its path quoted (spec 9.0)" ("--headless cmd.exe /d /s /c " + [char]34 + [char]34 + (Get-NodeTaskWrapperPath) + [char]34 + [char]34) $td.Argument
  # --- the wrapper (node-task.cmd): it cannot run here (no cmd.exe); its lines are checked one by one ---------------
  $w = @(Get-NodeTaskWrapperContent)
  $iRun = [array]::IndexOf($w, "wsl.exe -d p2pc-node -u root --exec /usr/local/sbin/p2pc-node-run")
  $iGate = [array]::IndexOf($w, "if not " + [char]34 + "%P2PC_RC%" + [char]34 + "==" + [char]34 + "64" + [char]34 + " exit /b %P2PC_RC%")
  $iDisable = [array]::IndexOf($w, "schtasks /Change /TN " + [char]34 + "\P2PC node" + [char]34 + " /DISABLE >nul 2>&1")
  Check "wrapper: it runs the supervisor, the same wsl.exe line as before" $true ($iRun -ge 0)
  Check "wrapper: the exit code is kept right after it" ("set " + [char]34 + "P2PC_RC=%ERRORLEVEL%" + [char]34) $w[$iRun + 1]
  Check "wrapper: any code but 64 is passed on at once (the task is NOT disabled)" ($iRun + 2) $iGate
  Check "wrapper: it disables the task only after that gate" $true ($iDisable -gt $iGate)
  Check "wrapper: exactly one schtasks call" 1 @($w | Where-Object { $_ -match "schtasks" }).Count
  Check "wrapper: it records why next to itself, starting with node_exit=64" $true (@($w | Where-Object { $_.StartsWith("> " + [char]34 + "%~dp0stopped-by-node" + [char]34 + " echo node_exit=64") }).Count -eq 1)
  Check "wrapper: the code, time and reason come from node-run.status" $true (@($w | Where-Object { $_.Contains("/bin/grep -E") -and $_.Contains("exit_code|time|reason") -and $_.Contains("/var/lib/p2pc/node-run.status") }).Count -eq 1)
  Check "wrapper: whether the disable worked is recorded" $true (@($w | Where-Object { $_.Contains("disabled=no") -and $_.Contains("disabled=yes") }).Count -eq 1)
  Check "wrapper: it ends with exit 64" "exit /b 64" $w[-1]
  # round 4 real run, R1: the disabled node left an empty distro Running (and the WSL VM with it): terminated, best effort
  $iTerm = [array]::IndexOf($w, ">nul 2>&1 wsl.exe --terminate p2pc-node")
  $iRecordLast = -1
  for ($i = 0; $i -lt $w.Count; $i++) { if ($w[$i].Contains("stopped-by-node")) { $iRecordLast = $i } }
  Check "wrapper: after a terminal stop it terminates the distro" $true ($iTerm -gt $iDisable)
  Check "wrapper: only after the record is complete" $true ($iTerm -gt $iRecordLast)
  Check "wrapper: and its result changes neither the exit code nor the record (exit /b 64 right after)" ($iTerm + 1) ([array]::IndexOf($w, "exit /b 64"))
  Check "wrapper: one terminate, only on 64" $true (@($w | Where-Object { $_.Contains("--terminate") }).Count -eq 1 -and $iTerm -gt $iGate)
  Check "wrapper: ASCII only" 0 @($w | Where-Object { $_ -match "[^\x00-\x7F]" }).Count
  Check "wrapper: it names no user path (it finds itself with %~dp0)" 0 @($w | Where-Object { $_ -match "(?i)Users|AppData" }).Count
  $wp = Write-NodeTaskWrapper
  $bytes = [System.IO.File]::ReadAllBytes($wp)
  Check "Write-NodeTaskWrapper: the file is the content, CRLF lines" ((($w -join "`r`n") + "`r`n")) ([System.Text.Encoding]::ASCII.GetString($bytes))
  function Get-NodeTaskWrapperPath { return (Join-Path $taskFiles "a%b\node-task.cmd") }
  $threw = $null
  try { $null = Write-NodeTaskWrapper } catch { $threw = $_.Exception.Message }
  Check "Write-NodeTaskWrapper: a path cmd.exe cannot quote is refused (Register-NodeTask makes it exit 35)" $true (([string]$threw).Contains("cannot be quoted for cmd.exe"))
  $script:ExitCode = 0
  function Get-NodeTaskWrapperPath { return (Join-Path $taskFiles "node-task.cmd") }
  # --- the rights: the user can always disable their own task (a security descriptor with the user) ----------------
  Check "the task SDDL: full control for SYSTEM, Administrators and the user" "D:(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;S-1-5-21-1-2-3-1001)" (Get-NodeTaskSddl -UserSid "S-1-5-21-1-2-3-1001")
  # --- registering the task, against mocks of the REAL ScheduledTasks objects (round 4 real run, the P1: on Windows
  # PowerShell 5.1 New-ScheduledTask returns a CIM MSFT_ScheduledTask, which has no RegistrationInfo, and the old mock had
  # one). Every mock below has properties of the real CIM class and nothing else, and the registration runs under
  # Set-StrictMode -Version Latest: reading a property the real object lacks fails, and so does writing one (always).
  function New-CimShape([hashtable]$Properties) { return (New-Object psobject -Property $Properties) }
  $script:taskCalls = @()
  $script:registerThrows = $null
  $script:sddlThrows = $false
  function New-ScheduledTaskTrigger { param([switch]$AtLogOn, $User, [switch]$Once, $At, $RepetitionInterval)
      # MSFT_TaskRepetitionPattern; MSFT_TaskLogonTrigger / MSFT_TaskTimeTrigger
      $rep = New-CimShape @{ Duration = $null; Interval = $null; StopAtDurationEnd = $false }
      if ($RepetitionInterval) { $rep.Interval = ("PT{0}M" -f [int]$RepetitionInterval.TotalMinutes); $rep.Duration = "P1D" }
      $p = @{ Enabled = $true; EndBoundary = $null; ExecutionTimeLimit = $null; Id = $null; Repetition = $rep; StartBoundary = "2026-11-06T12:00:00" }
      if ($AtLogOn) { $p.Delay = $null; $p.UserId = $User } else { $p.RandomDelay = $null }
      return (New-CimShape $p)
  }
  function New-ScheduledTaskAction { param($Execute, $Argument)
      return (New-CimShape @{ Arguments = $Argument; Execute = $Execute; Id = $null; WorkingDirectory = $null })   # MSFT_TaskExecAction
  }
  function New-ScheduledTaskPrincipal { param($UserId, $LogonType, $RunLevel)
      return (New-CimShape @{ DisplayName = $null; GroupId = $null; Id = "Author"; LogonType = $LogonType; RunLevel = $RunLevel; UserId = $UserId; ProcessTokenSidType = $null; RequiredPrivilege = $null })   # MSFT_TaskPrincipal2
  }
  function New-ScheduledTaskSettingsSet { param([switch]$AllowStartIfOnBatteries, [switch]$DontStopIfGoingOnBatteries, $ExecutionTimeLimit, $RestartCount, $RestartInterval, $MultipleInstances, [switch]$StartWhenAvailable, [switch]$Disable)
      # MSFT_TaskSettings3 (some of its properties)
      return (New-CimShape @{ AllowDemandStart = $true; DisallowStartIfOnBatteries = (-not $AllowStartIfOnBatteries); StopIfGoingOnBatteries = (-not $DontStopIfGoingOnBatteries); Enabled = (-not $Disable); ExecutionTimeLimit = $ExecutionTimeLimit; RestartCount = $RestartCount; RestartInterval = $RestartInterval; MultipleInstances = $MultipleInstances; StartWhenAvailable = [bool]$StartWhenAvailable; Hidden = $false })
  }
  function New-ScheduledTask { param($Action, $Trigger, $Principal, $Settings, $Description)
      # What New-ScheduledTask returns: Actions, Principal, Settings, Triggers and Description; NO RegistrationInfo.
      $script:newTask = New-CimShape @{ Actions = @($Action); Description = $Description; Principal = $Principal; Settings = $Settings; Triggers = @($Trigger) }
      return $script:newTask
  }
  function Register-ScheduledTask { param($InputObject, $TaskName, $TaskPath, [switch]$Force, $ErrorAction)
      $script:taskCalls += ("register " + $TaskPath + $TaskName + " force=" + [bool]$Force)
      $script:registeredInput = $InputObject
      if ($script:registerThrows) { throw $script:registerThrows }
      $state = "Ready"; if (-not $InputObject.Settings.Enabled) { $state = "Disabled" }
      return (New-CimShape @{ Actions = $InputObject.Actions; Description = $InputObject.Description; Principal = $InputObject.Principal; Settings = $InputObject.Settings; State = $state; TaskName = $TaskName; TaskPath = $TaskPath; Triggers = $InputObject.Triggers })
  }
  function Set-NodeTaskSddl { param([string]$Sddl) $script:taskCalls += ("sddl " + $Sddl); if ($script:sddlThrows) { throw "Access is denied (stub)" } }
  function Get-CurrentUserName { return "HOST\user" }
  function Get-CurrentUserSid { return "S-1-5-21-1-2-3-1001" }
  function Invoke-StrictRegistration([string[]]$Kinds, [bool]$Disabled) {
      $script:taskCalls = @(); $script:logged = @(); $script:registeredInput = $null
      Remove-Item -LiteralPath (Get-NodeTaskWrapperPath) -Force -ErrorAction SilentlyContinue
      & { Set-StrictMode -Version Latest; Register-NodeTaskWithTriggers -Kinds $Kinds -Disabled:$Disabled }
  }
  $sddlUser = "D:(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;S-1-5-21-1-2-3-1001)"
  $threw = $null
  try { Invoke-StrictRegistration @("Every5Minutes", "AtLogOn") $false } catch { $threw = $_.Exception.Message }
  Check "registration against the real object shape: nothing throws (no RegistrationInfo is touched)" $null $threw
  Check "registration: Register-ScheduledTask by name in the root folder, -Force, then the rights through Set-NodeTaskSddl" ("register \P2PC node force=True|sddl " + $sddlUser) ($script:taskCalls -join "|")
  Check "registration: what is registered is the New-ScheduledTask object" $true ([object]::ReferenceEquals($script:registeredInput, $script:newTask))
  Check "registration: the wrapper is written before" $true (Test-Path -LiteralPath (Get-NodeTaskWrapperPath))
  $ri = $script:registeredInput
  Check "registration: the action runs the wrapper" ($td.Execute + " " + $td.Argument) ($ri.Actions[0].Execute + " " + $ri.Actions[0].Arguments)
  Check "registration: two triggers" 2 @($ri.Triggers).Count
  Check "registration: the time trigger repeats every 5 minutes with no end (empty Duration)" "PT5M|" ($ri.Triggers[0].Repetition.Interval + "|" + $ri.Triggers[0].Repetition.Duration)
  Check "registration: the logon trigger is for this user" "HOST\user" $ri.Triggers[1].UserId
  Check "registration: Interactive, Limited" "Interactive|Limited" ($ri.Principal.LogonType + "|" + $ri.Principal.RunLevel)
  Check "registration: enabled by default" $true $ri.Settings.Enabled
  Check "registration: no warning" 0 @($script:logged | Where-Object { $_.StartsWith("WARN:") }).Count
  Invoke-StrictRegistration @("Every5Minutes") $true
  Check "registration -Disabled: registered disabled (no window in which a trigger could start it)" $false $script:registeredInput.Settings.Enabled
  # the rights cannot be set: a warning, the task stays registered (the runner stamp still keeps the node off the server)
  $script:sddlThrows = $true
  $threw = $null
  try { Invoke-StrictRegistration @("Every5Minutes", "AtLogOn") $false } catch { $threw = $_.Exception.Message }
  $script:sddlThrows = $false
  Check "rights refused: no failure" $null $threw
  Check "rights refused: the task was registered all the same" $true (($script:taskCalls -join "|").StartsWith("register \P2PC node"))
  Check "rights refused: a warning that says what it means" 1 @($script:logged | Where-Object { $_.StartsWith("WARN:") -and $_.Contains("Access is denied (stub)") -and $_.Contains("disable") -and $_.Contains("never dials the server") }).Count
  # the registration itself is refused: that throws (Register-NodeTask decides), and no rights are set
  $script:registerThrows = "Access is denied (stub register)"
  $threw = $null
  try { Invoke-StrictRegistration @("Every5Minutes", "AtLogOn") $false } catch { $threw = $_.Exception.Message }
  $script:registerThrows = $null
  Check "registration refused: it throws" "Access is denied (stub register)" $threw
  Check "registration refused: no rights are set" 0 @($script:taskCalls | Where-Object { $_.StartsWith("sddl") }).Count
  $code = ($psText -split "`n" | Where-Object { $_ -notmatch "^\s*#" }) -join "`n"
  Check "install.ps1 never touches RegistrationInfo (the CIM task has none)" 0 ([regex]::Matches($code, "RegistrationInfo")).Count
  # Set-NodeTaskSddl: the Task Scheduler COM API, as proven on the Windows test PC (round 4: sd-probe.ps1)
  $script:com = @()
  & {
      function New-Object { param([string]$ComObject)
          $script:com += ("new " + $ComObject)
          $task = [pscustomobject]@{ Name = "t" }
          $task | Add-Member -MemberType ScriptMethod -Name SetSecurityDescriptor -Value { param($s, $f) $script:com += ("set " + $s + " flags=" + $f) }
          $folder = [pscustomobject]@{ T = $task }
          $folder | Add-Member -MemberType ScriptMethod -Name GetTask -Value { param($n) $script:com += ("task " + $n); return $this.T }
          $svc = [pscustomobject]@{ F = $folder }
          $svc | Add-Member -MemberType ScriptMethod -Name Connect -Value { $script:com += "connect" }
          $svc | Add-Member -MemberType ScriptMethod -Name GetFolder -Value { param($p) $script:com += ("folder " + $p); return $this.F }
          return $svc
      }
      Set-Item -Path function:local:Set-NodeTaskSddl -Value $realSetNodeTaskSddl
      Set-NodeTaskSddl -Sddl $sddlUser
  }
  Check "Set-NodeTaskSddl: Schedule.Service, Connect, the root folder, the task, SetSecurityDescriptor(sddl, 0)" ("new Schedule.Service|connect|folder \|task P2PC node|set " + $sddlUser + " flags=0") ($script:com -join "|")
  # --- the record of a terminal stop ------------------------------------------------------------------------------------
  Write-StopRecord 7
  $rec = Read-NodeStopRecord
  Check "record: the code" 7 $rec.Code
  Check "record: the time" "2026-11-06T10:00:00Z" $rec.Time
  Check "record: disabled" "yes" $rec.Disabled
  Check "advice for 7: a new token and -Join -Force" $true ((Get-NodeStopAdvice 7).Contains("join-token create") -and (Get-NodeStopAdvice 7).Contains("-Join -Force"))
  Check "advice for 8: the same" (Get-NodeStopAdvice 7) (Get-NodeStopAdvice 8)
  Check "advice for 6: a newer image and -Upgrade" $true ((Get-NodeStopAdvice 6).Contains("-Upgrade"))
  Remove-StopRecord
  Check "no record: null" $null (Read-NodeStopRecord)
  # a record with no code (the wrapper could not read node-run.status: Wsl/Service timeouts, round 4 real run): the code
  # is read from node-run.status in the distro, through the WSL retry
  [System.IO.File]::WriteAllText((Get-NodeStopRecordPath), "node_exit=64`r`ndisabled=yes`r`n")
  $script:wslOnce = 0
  $rec = & {
      Set-Item -Path function:local:Invoke-InDistro -Value $realInvokeInDistro
      Set-Item -Path function:local:Invoke-Wsl -Value $realInvokeWsl
      function Invoke-WslOnce { param([string[]]$WslArgs)
          $script:wslOnce++
          if ($script:wslOnce -eq 1) { return (New-Object psobject -Property @{ ExitCode = -1; Output = "Error code: Wsl/Service/0x8007274c" }) }
          if (($WslArgs -join " ") -eq "-d p2pc-node -u root --exec /bin/cat /var/lib/p2pc/node-run.status") { return (New-Object psobject -Property @{ ExitCode = 0; Output = "state=stopped`nexit_code=8`nreason=stub" }) }
          return (New-Object psobject -Property @{ ExitCode = 1; Output = "" })
      }
      Read-NodeStopRecord
  }
  Check "record without a code: read from node-run.status in the distro" 8 $rec.Code
  Check "record without a code: through the WSL retry" 2 $script:wslOnce
  Check "record without a code: still disabled=yes" "yes" $rec.Disabled
  $rec = Read-NodeStopRecord
  Check "record without a code, none in the distro either: unknown" $null $rec.Code
  $adv = Get-NodeStopAdvice $null
  Check "advice when the code is unknown: unknown, see -Status" $true ($adv.Contains("unknown") -and $adv.Contains(".\install.ps1 -Status"))
  Check "advice when the code is unknown: not the advice for 7 or 8" $false ($adv.Contains("join-token create"))
  Remove-StopRecord
  Check "task: no time limit"          ([TimeSpan]::Zero) $td.ExecutionTimeLimit
  Check "task: allowed on battery"     $true $td.AllowOnBattery
  Check "task: restarts on failure"    $true ($td.RestartCount -ge 1 -and $td.RestartIntervalMinutes -ge 1)
  Check "task: at logon of this user, never elevated" "Limited" $td.RunLevel
  Check "task: a 5-minute watchdog repetition" 5 $td.RepeatMinutes
  Check "task: IgnoreNew (the watchdog does nothing while it runs)" "IgnoreNew" $td.MultipleInstances
  Check "task: StartWhenAvailable"     $true $td.StartWhenAvailable
  Check "triggers: the 5-minute trigger and the per-user sign-in trigger, always (spec 9.0, d0a9ec3)" "Every5Minutes,AtLogOn" ((Get-NodeTaskTriggerKinds) -join ",")
  Check "no elevation test any more" $false ([bool](Get-Command Test-Elevated -ErrorAction SilentlyContinue))
  # Register-NodeTask with the registration itself stubbed: what it asks Windows for, and what it does when refused.
  Set-Item -Path function:Register-NodeTask -Value $realRegisterNodeTask
  $script:registered = @()
  $script:refuseLogon = $false
  $script:refuseAll = $false
  $script:logged = @()
  function Register-NodeTaskWithTriggers {
      param([string[]]$Kinds, [switch]$Disabled)
      if ($script:refuseAll -or ($script:refuseLogon -and ($Kinds -contains "AtLogOn"))) { throw (New-Object System.UnauthorizedAccessException "Access is denied") }
      $w = ($Kinds -join ",")
      if ($Disabled) { $w += " disabled" }
      $script:registered += $w
  }
  # -Disabled is passed on; -WarnOnFailure (the upgrade) turns the exit 35 into a warning
  $script:registered = @(); $script:logged = @()
  $null = Register-NodeTask -Disabled
  Check "Register-NodeTask -Disabled: registered disabled" "Every5Minutes,AtLogOn disabled" ($script:registered -join "|")
  $script:registered = @(); $script:logged = @(); $script:refuseAll = $true; $script:ExitCode = 0
  $got = Register-NodeTask -Disabled -WarnOnFailure
  $script:refuseAll = $false
  Check "Register-NodeTask -WarnOnFailure, refused: no failure" 0 $script:ExitCode
  Check "Register-NodeTask -WarnOnFailure, refused: returns nothing" $null $got
  Check "Register-NodeTask -WarnOnFailure, refused: a warning that the task keeps its previous definition, no error" "1|0" ("{0}|{1}" -f @($script:logged | Where-Object { $_.StartsWith("WARN:") -and $_.Contains("previous definition") }).Count, @($script:logged | Where-Object { $_.StartsWith("ERROR:") }).Count)
  $script:registered = @(); $script:logged = @()
  $null = Register-NodeTask
  Check "a normal user: both triggers, in one registration" "Every5Minutes,AtLogOn" ($script:registered -join "|")
  Check "a normal user: no advice" 0 @($script:logged | Where-Object { $_.Contains("within 5 minutes") }).Count
  $script:registered = @(); $script:logged = @(); $script:refuseLogon = $true
  $null = Register-NodeTask
  Check "the sign-in trigger refused: registered again with the 5-minute trigger only" "Every5Minutes" ($script:registered -join "|")
  Check "refused: it says the node starts within 5 minutes of signing in" 1 @($script:logged | Where-Object { $_.StartsWith("WARN:") -and $_.Contains("the node starts within 5 minutes of signing in") }).Count
  Check "refused: no advice to run it elevated" 0 @($script:logged | Where-Object { $_.Contains("elevated") }).Count
  $script:registered = @(); $script:logged = @(); $script:refuseAll = $true; $script:ExitCode = 0
  try { $null = Register-NodeTask } catch { if ($_.Exception.Message -ne $script:FailMarker) { throw } }
  Check "even the time trigger refused: exit 35, no other fallback" 35 $script:ExitCode
  $script:refuseLogon = $false; $script:refuseAll = $false; $script:ExitCode = 0
  Check "install.ps1 no longer advises running it elevated to start at sign-in" 0 ([regex]::Matches($psText, "(?i)elevated PowerShell[^\r\n]*sign-in|sign-in[^\r\n]*elevated PowerShell")).Count
  $readmeFlat = ((Get-Content -Raw -LiteralPath $env:P2PC_README) -replace "\s+", " ")
  Check "the README no longer says the logon trigger needs elevation" $false ($readmeFlat -match "(?i)only (when|from an) [^.]*elevated")
  Check "the README carries the fallback sentence" $true ($readmeFlat.Contains("the node starts within 5 minutes of signing in"))

  # --- the WSL service timeout (Wsl/Service/0x8007274c) is retried, and nothing else is ----------------------------------
  Check "timeout recognised"            $true  (Test-WslServiceTimeout "Error code: Wsl/Service/0x8007274c")
  Check "timeout, other case"           $true  (Test-WslServiceTimeout "WSL/SERVICE/0X8007274C")
  Check "another error is not retried"  $false (Test-WslServiceTimeout "Error code: Wsl/Service/0x80070005")
  Check "empty output is not a timeout" $false (Test-WslServiceTimeout "")
  $script:sleeps = 0
  function Start-Sleep { param([int]$Seconds) $script:sleeps++; $script:lastSleep = $Seconds; $script:fakeNow += $Seconds }
  $script:attempts = 0
  $script:failFirst = 2
  $flaky = { $script:attempts++; if ($script:attempts -le $script:failFirst) { New-Object psobject -Property @{ ExitCode = -1; Output = "Wsl/Service/0x8007274c" } } else { New-Object psobject -Property @{ ExitCode = 0; Output = "ok" } } }
  $r = Invoke-WithWslRetry $flaky "test"
  Check "retry: succeeds on the third attempt" 0 $r.ExitCode
  Check "retry: three attempts" 3 $script:attempts
  Check "retry: two pauses" 2 $script:sleeps
  Check "retry: 5 s apart" 5 $script:lastSleep
  $script:attempts = 0; $script:sleeps = 0; $script:failFirst = 99
  $r = Invoke-WithWslRetry $flaky "test"
  Check "retry: gives up after 3 retries (4 attempts)" 4 $script:attempts
  Check "retry: and returns the failure" -1 $r.ExitCode
  $script:attempts = 0; $script:sleeps = 0
  $other = { $script:attempts++; New-Object psobject -Property @{ ExitCode = 1; Output = "some other error" } }
  $r = Invoke-WithWslRetry $other "test"
  Check "retry: another failure is not retried" 1 $script:attempts
  Check "retry: no pause for it" 0 $script:sleeps
  # Invoke-WslWithSecret: the same SecureString goes to every attempt (the token stays in memory only)
  $script:secretSeen = @()
  $script:attempts = 0; $script:sleeps = 0
  function Invoke-WslWithSecretOnce {
      param([string]$Arguments, [System.Security.SecureString]$Secret)
      $script:attempts++
      $script:secretSeen += (New-Object System.Net.NetworkCredential("", $Secret)).Password
      if ($script:attempts -eq 1) { return (New-Object psobject -Property @{ ExitCode = -1; Output = "Wsl/Service/0x8007274c" }) }
      return (New-Object psobject -Property @{ ExitCode = 0; Output = "Enrolled" })
  }
  $sec = New-ReadOnlySecret "p2pc_join_testonlyretrytoken"
  $r = Invoke-WslWithSecret -Arguments "-d p2pc-node join -" -Secret $sec
  Check "join retry: the second attempt succeeds" 0 $r.ExitCode
  Check "join retry: both attempts got the token" "p2pc_join_testonlyretrytoken|p2pc_join_testonlyretrytoken" ($script:secretSeen -join "|")
  Check "Invoke-Wsl goes through the retry" $true ($psText -match "(?s)function Invoke-Wsl \{.*?Invoke-WithWslRetry")
  Check "Invoke-WslStream goes through the retry" $true ($psText -match "(?s)function Invoke-WslStream \{.*?Invoke-WithWslRetry")

  # --- the token as a SecureString: built char by char, read-only, never through ConvertTo-SecureString (review P3-7) ---
  $sec = New-ReadOnlySecret "p2pc_join_testonlyabc"
  Check "the secret holds the text" "p2pc_join_testonlyabc" (New-Object System.Net.NetworkCredential("", $sec)).Password
  Check "the secret is read-only" $true $sec.IsReadOnly()
  $code = ($psText -split "`n" | Where-Object { $_ -notmatch "^\s*#" }) -join "`n"
  Check "install.ps1 never calls ConvertTo-SecureString" 0 ([regex]::Matches($code, "ConvertTo-SecureString")).Count
  $psText = Get-Content -Raw -LiteralPath $env:P2PC_PS1
  Check "the installer never changes .wslconfig" 0 ([regex]::Matches(($psText -split "`n" | Where-Object { $_ -notmatch "^\s*#" }) -join "`n", "(?i)(Set-Content|Add-Content|Out-File|WriteAll)[^\r\n]*wslconfig")).Count
  Check "registering the task never falls back to anything but the time trigger: then exit 35" $true ($psText -match "(?s)function Register-NodeTask \{.*?Fail 35 [^\r\n]*even with a time trigger only")

  # --- T14b2: the token is never a parameter -------------------------------------------------------------------------
  $paramBlock = [regex]::Match($psText, "(?s)\nparam\((.*?)\n\)").Groups[1].Value
  Check "the param block was found" $true ($paramBlock.Length -gt 0)
  Check "no parameter takes pipeline input by name or value" $false ($paramBlock -match "ValueFromPipeline")
  Check "no parameter is named like a token or a secret" $false ($paramBlock -match "(?i)\x24\w*(token|secret|code)\b")
  $readToken = [regex]::Match($psText, "(?s)function Read-JoinToken \{.*?\n\}").Value
  Check "Read-JoinToken prompts with hidden input" $true ($readToken -match "Read-Host[^\r\n]*-AsSecureString")
  Check "Read-JoinToken never prompts in clear" 0 ([regex]::Matches($readToken, "Read-Host(?![^\r\n]*-AsSecureString)")).Count
  Check "the token is never logged: no Write-Log line mentions a token variable" 0 ([regex]::Matches($psText, "(?im)^[^#\r\n]*Write-(Log|Host)[^\r\n]*\x24(token|secret)")).Count

  # --- T14b2: -Join ----------------------------------------------------------------------------------------------------
  $fakeToken = "p2pc_join_testonlyfaketokentestonlyfaketoken"   # gitleaks:allow
  $script:distroExists = $true
  $script:agentPresent = $true
  $script:enrolled = $false
  $script:connection = "connected (since 2026-11-06T10:00:00Z)"
  $script:joinExit = 0
  $script:joinArgs = $null
  $script:joinSecret = $null
  $script:taskState = "Running"
  $script:readHostSecure = $null
  $script:stdinRedirected = $false
  function Test-DistroExists { return $script:distroExists }
  function Register-NodeTask { $script:wslCalls += "task:register" }
  function Get-NodeTaskState { return $script:taskState }
  function Test-StdinRedirected { return $script:stdinRedirected }
  function Read-Host { param([string]$Prompt, [switch]$AsSecureString) $script:readHostSecure = [bool]$AsSecureString; return (ConvertTo-SecureString $fakeToken -AsPlainText -Force) }
  function Invoke-WslWithSecret {
      param([string]$Arguments, [System.Security.SecureString]$Secret)
      $script:wslCalls += "join"
      $script:joinArgs = $Arguments
      $script:joinSecret = (New-Object System.Net.NetworkCredential("", $Secret)).Password
      if ($script:joinExit -eq 0) { $script:enrolled = $true; if ($script:connectionAfterJoin) { $script:connection = $script:connectionAfterJoin } }
      return (New-Object psobject -Property @{ ExitCode = $script:joinExit; Output = $script:joinOutput })
  }
  function Get-DistroNow { return [DateTimeOffset]::Parse("2026-11-06T12:00:00Z", [System.Globalization.CultureInfo]::InvariantCulture) }
  # the real Get-AgentStatus again (the upgrade tests replaced it): it asks the stubbed distro below
  Set-Item -Path function:Get-AgentStatus -Value $realGetAgentStatus
  # starting the task makes it Running, unless the test says it dies at once
  function Start-NodeTask { $script:wslCalls += "task:start"; if (-not $script:taskDies) { $script:taskState = "Running" }; return $true }
  function Invoke-Wsl { param([string[]]$WslArgs) $script:wslCalls += ($WslArgs -join " "); return (New-Object psobject -Property @{ ExitCode = 0; Output = "" }) }
  function Invoke-InDistro {
      param([string[]]$Command)
      $c = $Command -join " "
      $r = { param($code, $out) New-Object psobject -Property @{ ExitCode = $code; Output = $out } }
      if ($c -eq "/usr/bin/test -x /usr/local/bin/p2pc-agent") { if ($script:agentPresent) { return (& $r 0 "") } else { return (& $r 1 "") } }
      if ($c -eq "/usr/bin/test -x /usr/local/bin/p2pc-shim") { if ($script:shimPresent) { return (& $r 0 "") } else { return (& $r 1 "") } }
      if ($c -eq "/usr/bin/pgrep -x p2pc-agent") { if ($script:agentProcess) { return (& $r 0 "4242") } else { return (& $r 1 "") } }
      if ($c -eq "/bin/grep -q P2PC_AGENT_CONFIG= /usr/local/sbin/p2pc-node-run") { if ($script:oldLayout) { return (& $r 1 "") } else { return (& $r 0 "") } }
      if ($c -eq "/bin/date -u +%s") { return (& $r 0 "1793966400") }
      if ($c -like "*/usr/local/bin/p2pc-agent status") {
          $script:statusCalls += $c
          if ($script:enrolled) { return (& $r 0 ("Enrolled:      yes (node nod_testonly, account acc_testonly)`nServer NodeId: srvtestonly`nConnection:    " + $script:connection + "`nLast Welcome:  never")) }
          return (& $r 0 "Enrolled:      no (run ``p2pc-agent join`` with a join token)`nConnection:    not enrolled")
      }
      if ($c -eq "/bin/cat /var/lib/p2pc/node-run.status") {
          if ($script:noNodeRunStatus) { return (& $r 1 "cat: /var/lib/p2pc/node-run.status: No such file or directory") }
          return (& $r 0 "state=stopped`nexit_code=7`nreason=stub reason")
      }
      return (& $r 0 "")
  }
  # Get-ScheduledTask: an MSFT_ScheduledTask as Windows returns it (real properties only), with its exec action
  $wrapperArgs = (Get-NodeTaskDefinition).Argument
  $oldArgs = "--headless wsl.exe -d p2pc-node -u root --exec /usr/local/sbin/p2pc-node-run"
  function Get-ScheduledTask { param($TaskName, $TaskPath, $ErrorAction)
      if (-not $script:taskRegistered) { return $null }
      $a = New-CimShape @{ Arguments = $script:taskArgs; Execute = "C:\Windows\System32\conhost.exe"; Id = $null; WorkingDirectory = $null }
      return (New-CimShape @{ Actions = @($a); Author = $null; Date = $null; Description = "P2PC node"; Documentation = $null; Principal = $null; SecurityDescriptor = $null; Settings = $null; Source = $null; State = $script:taskState; TaskName = $TaskName; TaskPath = $TaskPath; Triggers = @(); URI = ($TaskPath + $TaskName); Version = $null })
  }
  function Reset-Join {
      $script:ExitCode = 0; $script:logged = @(); $script:wslCalls = @(); $script:sleeps = 0
      $script:distroExists = $true; $script:agentPresent = $true; $script:enrolled = $false; $script:joinExit = 0
      $script:joinArgs = $null; $script:joinSecret = $null; $script:taskState = "Running"; $script:readHostSecure = $null
      $script:connection = "connected (since 2026-11-06T12:00:01Z)"; $script:stdinRedirected = $false
      $script:PipedInput = @(); $script:shimPresent = $true; $script:agentProcess = $false; $script:connectionAfterJoin = $null
      $script:joinOutput = "Enrolled: node nod_testonly (hostname x)."; $script:taskDies = $false
      $script:oldLayout = $false; $script:NewConfigLayout = $null; $script:statusCalls = @()
      $script:noNodeRunStatus = $false; $script:taskArgs = $wrapperArgs
      Set-Content -LiteralPath (Get-NodeTaskWrapperPath) -Value "@echo off"
  }
  function Invoke-JoinSafely { try { Invoke-JoinAction } catch { if ($_.Exception.Message -ne $script:FailMarker) { throw } } }
  $Force = [switch]$false
  $noToken = { param($what) Check ($what + ": the token is in no log line") 0 @($script:logged | Where-Object { $_.Contains($fakeToken) }).Count }

  # piped token, fresh node: the token goes to the agent stdin, then the task is registered and started
  Reset-Join
  $script:PipedInput = @($fakeToken)
  Invoke-JoinSafely
  Check "join: exit 0" 0 $script:ExitCode
  Check "join: the exact command, with the config in /var/lib/p2pc; the token is not in it" "-d p2pc-node -u root --exec /usr/bin/env P2PC_AGENT_CONFIG=/var/lib/p2pc/agent.toml P2PC_AGENT_SUPERVISED=1 /usr/local/bin/p2pc-agent join -" $script:joinArgs
  Check "join: every status call names the config in /var/lib/p2pc" 0 @($script:statusCalls | Where-Object { $_ -ne "/usr/bin/env P2PC_AGENT_CONFIG=/var/lib/p2pc/agent.toml /usr/local/bin/p2pc-agent status" }).Count
  Check "join: the agent got the piped token on stdin" $fakeToken $script:joinSecret
  Check "join: then the task is registered and started" "join|task:register|task:start" ($script:wslCalls -join "|")
  Check "join: it ends with Joined: <node> on <server>" 1 @($script:logged | Where-Object { $_.Contains("Joined: nod_testonly on srvtestonly") }).Count
  Check "join: the status line is shown" 1 @($script:logged | Where-Object { $_.Contains("Connection:    connected") }).Count
  & $noToken "join"
  # interactive: hidden prompt
  Reset-Join
  Invoke-JoinSafely
  Check "prompt: exit 0" 0 $script:ExitCode
  Check "prompt: Read-Host -AsSecureString" $true $script:readHostSecure
  Check "prompt: the typed token reaches the agent" $fakeToken $script:joinSecret
  & $noToken "prompt"
  # two piped lines: refused before anything runs
  Reset-Join
  $script:PipedInput = @($fakeToken, "second line")
  Invoke-JoinSafely
  Check "two lines: usage error" 2 $script:ExitCode
  Check "two lines: nothing ran" 0 $script:wslCalls.Count
  & $noToken "two lines"
  # already enrolled: no join, the task is (re)registered and started
  Reset-Join
  $script:enrolled = $true
  Invoke-JoinSafely
  Check "enrolled: exit 0" 0 $script:ExitCode
  Check "enrolled: no join, no prompt" $true (-not ($script:wslCalls -contains "join") -and $null -eq $script:readHostSecure)
  Check "enrolled: the task is registered and started" "task:register|task:start" ($script:wslCalls -join "|")
  Check "enrolled: it says so, and how to enroll again" 1 @($script:logged | Where-Object { $_.Contains("already enrolled") -and $_.Contains("-Force") }).Count
  Check "enrolled: worded already enrolled (node ...), no colon" 1 @($script:logged | Where-Object { $_.Contains("already enrolled (node nod_testonly") }).Count
  Check "enrolled: the task already ran, so its current connection is taken at once" 0 $script:sleeps
  Check "enrolled: -Force re-enrolls this machine, the same node (spec 5)" 1 @($script:logged | Where-Object { $_.Contains("re-enroll this machine (the same node)") }).Count
  Check "enrolled: no more talk of a new node" 0 @($script:logged | Where-Object { $_.Contains("new node") }).Count
  # the node stopped for good as removed (7): -Join without -Force refuses, and leaves the task off
  Reset-Join
  $script:enrolled = $true
  Write-StopRecord 7
  Invoke-JoinSafely
  Check "removed node, -Join without -Force: exit 34" 34 $script:ExitCode
  Check "removed node, -Join without -Force: the task is not touched" 0 @($script:wslCalls | Where-Object { $_ -like "task:*" }).Count
  Check "removed node, -Join without -Force: it says to use a new token and -Join -Force" 1 @($script:logged | Where-Object { $_.StartsWith("ERROR:") -and $_.Contains("join-token create") -and $_.Contains("-Join -Force") }).Count
  Check "removed node: the record stays" $true (Test-Path -LiteralPath (Get-NodeStopRecordPath))
  # a record with no code, and none in the distro: -Join refuses all the same, and says the code is unknown
  Reset-Join
  $script:enrolled = $true
  $script:noNodeRunStatus = $true
  [System.IO.File]::WriteAllText((Get-NodeStopRecordPath), "node_exit=64`r`ndisabled=yes`r`n")
  Invoke-JoinSafely
  Check "stopped, code unknown, -Join: exit 34" 34 $script:ExitCode
  Check "stopped, code unknown, -Join: unknown, see -Status" 1 @($script:logged | Where-Object { $_.StartsWith("ERROR:") -and $_.Contains("unknown") -and $_.Contains("-Status") }).Count
  Check "stopped, code unknown, -Join: no advice for 7 or 8" 0 @($script:logged | Where-Object { $_.Contains("join-token create") }).Count
  Check "stopped, code unknown, -Join: no exit with an empty code in the text" 0 @($script:logged | Where-Object { $_ -match "exit ," -or $_ -match "exit \)" }).Count
  Write-StopRecord 7
  # ... with -Force and a new token: re-enrolled, the record forgotten, the task registered (enabled) and started
  Reset-Join
  $script:enrolled = $true
  $script:PipedInput = @($fakeToken)
  $Force = [switch]$true
  Invoke-JoinSafely
  $Force = [switch]$false
  Check "removed node, -Join -Force: exit 0" 0 $script:ExitCode
  Check "removed node, -Join -Force: the record is gone" $false (Test-Path -LiteralPath (Get-NodeStopRecordPath))
  Check "removed node, -Join -Force: the task is registered and started" $true (($script:wslCalls -join "|").EndsWith("join|task:register|task:start"))
  # enrolled, the task NOT running before (after -Stop): it is started, and a connection from before does not count (real run)
  Reset-Join
  $script:enrolled = $true
  $script:taskState = "Disabled"
  $script:connection = "connected (since 2026-11-06T11:49:00Z)"
  Invoke-JoinSafely
  Check "enrolled, task was stopped, stale connected: exit 0" 0 $script:ExitCode
  Check "enrolled, task was stopped, stale connected: it waits, then warns" 1 @($script:logged | Where-Object { $_.StartsWith("WARN:") -and $_.Contains("not connected since the task started") }).Count
  Check "enrolled, task was stopped, stale connected: it waited" $true ($script:sleeps -ge 25)
  Reset-Join
  $script:enrolled = $true
  $script:taskState = "Disabled"
  $script:connection = "connected (since 2026-11-06T12:00:05Z)"
  Invoke-JoinSafely
  Check "enrolled, task was stopped, fresh connected: accepted at once" 0 $script:sleeps
  Check "enrolled, task was stopped, fresh connected: no warning" 0 @($script:logged | Where-Object { $_.Contains("not connected") }).Count
  # -Force: the running agent is stopped first, then join --force -
  Reset-Join
  $script:enrolled = $true
  $script:PipedInput = @($fakeToken)
  $Force = [switch]$true
  Invoke-JoinSafely
  $Force = [switch]$false
  Check "-Force: exit 0" 0 $script:ExitCode
  Check "-Force: join --force -" "-d p2pc-node -u root --exec /usr/bin/env P2PC_AGENT_CONFIG=/var/lib/p2pc/agent.toml P2PC_AGENT_SUPERVISED=1 /usr/local/bin/p2pc-agent join --force -" $script:joinArgs
  Check "-Force: task disabled and stopped, and the distro terminated, before the join" "task:disable|task:stop|--terminate p2pc-node|join|task:register|task:start" ($script:wslCalls -join "|")
  # -Force, and the join fails: the task that ran before is enabled and started again (review P3-2, real run W6)
  Reset-Join
  $script:enrolled = $true
  $script:PipedInput = @($fakeToken)
  $script:joinExit = 4
  $Force = [switch]$true
  Invoke-JoinSafely
  $Force = [switch]$false
  Check "-Force refused: exit 33" 33 $script:ExitCode
  Check "-Force refused: the task runs again on the old enrollment" "task:disable|task:stop|--terminate p2pc-node|join|task:enable|task:start" ($script:wslCalls -join "|")
  # -Force, and wsl.exe keeps timing out (after its retries): exit 33 that says so, and the task runs again
  Reset-Join
  $script:enrolled = $true
  $script:PipedInput = @($fakeToken)
  $script:joinExit = -1
  $script:joinOutput = "Error code: Wsl/Service/0x8007274c"
  $Force = [switch]$true
  Invoke-JoinSafely
  $Force = [switch]$false
  Check "-Force timeout: exit 33" 33 $script:ExitCode
  Check "-Force timeout: the message names the WSL timeout" 1 @($script:logged | Where-Object { $_.StartsWith("ERROR:") -and $_.Contains("0x8007274c") }).Count
  Check "-Force timeout: the task runs again" $true (($script:wslCalls -join "|").EndsWith("task:enable|task:start"))
  # -Force: a "connected" from before the restart (the old agent state file) does not count (review P3-4)
  Reset-Join
  $script:enrolled = $true
  $script:PipedInput = @($fakeToken)
  $script:connection = "connected (since 2026-11-06T09:00:00Z)"
  $Force = [switch]$true
  Invoke-JoinSafely
  $Force = [switch]$false
  Check "-Force, stale connected: not taken as connected (a warning after the wait)" 1 @($script:logged | Where-Object { $_.StartsWith("WARN:") -and $_.Contains("not connected since the task started") }).Count
  Check "-Force, stale connected: it waited" $true ($script:sleeps -ge 25)
  Reset-Join
  $script:enrolled = $true
  $script:PipedInput = @($fakeToken)
  $script:connection = "connected (since 2026-11-06T09:00:00Z)"
  $script:connectionAfterJoin = "connected (since 2026-11-06T12:00:03.25Z)"
  $Force = [switch]$true
  Invoke-JoinSafely
  $Force = [switch]$false
  Check "-Force, connected since the restart: accepted at once" 0 $script:sleeps
  Check "-Force, connected since the restart: no warning" 0 @($script:logged | Where-Object { $_.StartsWith("WARN:") -and $_.Contains("not connected") }).Count
  # Test-ConnectedSince on its own
  $t0 = [DateTimeOffset]::Parse("2026-11-06T12:00:00.700Z", [System.Globalization.CultureInfo]::InvariantCulture)
  Check "since: no time required"        $true  (Test-ConnectedSince "connected (since 2026-01-01T00:00:00Z)" $null)
  Check "since: later"                   $true  (Test-ConnectedSince "connected (since 2026-11-06T12:00:05Z)" $t0)
  Check "since: the same second"         $true  (Test-ConnectedSince "connected (since 2026-11-06T12:00:00Z)" $t0)
  Check "since: up to 2 s earlier (two readings of the distro clock)" $true (Test-ConnectedSince "connected (since 2026-11-06T11:59:59Z)" $t0)
  Check "since: more than 2 s earlier"   $false (Test-ConnectedSince "connected (since 2026-11-06T11:59:58Z)" $t0)
  # Get-DistroNow reads the clock of the distro (review P3-2), not the clock of Windows
  Check "Get-DistroNow: the distro clock" "2026-11-06T12:00:00.0000000+00:00" ((& $realGetDistroNow).ToString("o"))
  Check "since: not connected"           $false (Test-ConnectedSince "connecting (since 2026-11-06T12:00:05Z)" $null)
  Check "since: unreadable time"         $false (Test-ConnectedSince "connected (since yesterday)" $t0)
  # refused token: exit 33, no task
  Reset-Join
  $script:PipedInput = @($fakeToken)
  $script:joinExit = 4
  Invoke-JoinSafely
  Check "refused: exit 33" 33 $script:ExitCode
  Check "refused: no task registered" 0 @($script:wslCalls | Where-Object { $_ -like "task:*" }).Count
  Check "refused: the message says the server refused it" 1 @($script:logged | Where-Object { $_.StartsWith("ERROR:") -and $_.Contains("refused the token") }).Count
  & $noToken "refused"
  Reset-Join
  $script:PipedInput = @($fakeToken)
  $script:joinExit = 5
  Invoke-JoinSafely
  Check "expired: exit 33" 33 $script:ExitCode
  Check "expired: the message says expired" 1 @($script:logged | Where-Object { $_.StartsWith("ERROR:") -and $_.Contains("expired") }).Count
  # not installed / no agent in the image
  Reset-Join
  $script:distroExists = $false
  Invoke-JoinSafely
  Check "not installed: exit 31" 31 $script:ExitCode
  Reset-Join
  $script:agentPresent = $false
  Invoke-JoinSafely
  Check "no agent in the image: exit 32" 32 $script:ExitCode
  Check "no agent: points at -Upgrade" 1 @($script:logged | Where-Object { $_.Contains("-Upgrade") }).Count
  Reset-Join
  $script:shimPresent = $false
  Invoke-JoinSafely
  Check "no p2pc-shim in the image: exit 32" 32 $script:ExitCode
  Reset-Join
  $script:oldLayout = $true
  $script:PipedInput = @($fakeToken)
  Invoke-JoinSafely
  Check "an image up to 0.2.1 (config in /etc): exit 32" 32 $script:ExitCode
  Check "up to 0.2.1: no join" $false ($script:wslCalls -contains "join")
  Check "up to 0.2.1: points at -Upgrade" 1 @($script:logged | Where-Object { $_.Contains("-Upgrade") -and $_.Contains("0.2.2") }).Count
  & $noToken "old layout"
  Reset-Join
  $script:oldLayout = $true
  $script:enrolled = $true
  function Get-NodeTaskInfoText { return "Running" }
  Invoke-StatusAction
  Check "status on an image up to 0.2.1: the agent runs without P2PC_AGENT_CONFIG (it reads /etc)" "/usr/local/bin/p2pc-agent status" ($script:statusCalls -join "|")
  Check "status on an image up to 0.2.1: a warning to upgrade" 1 @($script:logged | Where-Object { $_.StartsWith("WARN:") -and $_.Contains("older than 0.2.2") }).Count
  Reset-Join
  $script:shimPresent = $false
  Invoke-JoinSafely
  Check "no p2pc-shim: named" $true (@($script:logged | Where-Object { $_.StartsWith("ERROR:") -and $_.Contains("has no /usr/local/bin/p2pc-shim") }).Count -eq 1)
  # the task does not stay up: exit 35 with what p2pc-node-run wrote
  Reset-Join
  $script:PipedInput = @($fakeToken)
  $script:connection = "connecting (since 2026-11-06T10:00:00Z)"
  $script:taskState = "Ready"
  $script:taskDies = $true
  Invoke-JoinSafely
  Check "task not running: exit 35" 35 $script:ExitCode
  Check "task not running: node-run.status is shown" 1 @($script:logged | Where-Object { $_.Contains("stub reason") }).Count
  # running but not connected within 60 s: a warning, not a failure (the agent keeps trying)
  Reset-Join
  $script:PipedInput = @($fakeToken)
  $script:connection = "connecting (since 2026-11-06T10:00:00Z)"
  Invoke-JoinSafely
  Check "not connected yet: exit 0" 0 $script:ExitCode
  Check "not connected yet: a warning" 1 @($script:logged | Where-Object { $_.StartsWith("WARN:") -and $_.Contains("not connected") }).Count
  Check "not connected yet: it waited about 60 s" $true ($script:sleeps -ge 25 -and $script:sleeps -le 31)

  # --- T14b2: -Status -----------------------------------------------------------------------------------------------------
  Reset-Join
  $script:enrolled = $true
  function Get-NodeTaskInfoText { return "Running (last run 2026-11-06 10:00:00, last result 0x41301)" }
  Invoke-StatusAction
  $text = $script:logged -join "`n"
  Check "status: exit 0" 0 $script:ExitCode
  Check "status: the task first" $true ($text.IndexOf("P2PC node") -ge 0 -and $text.IndexOf("P2PC node") -lt $text.IndexOf("Enrolled:"))
  Check "status: then p2pc-agent status" $true ($text.Contains("Connection:    connected"))
  Check "status: and the p2pc-node-run status" $true ($text.Contains("stub reason"))
  Check "status: no orphan reported when the task runs" 0 @($script:logged | Where-Object { $_.Contains("ORPHAN") }).Count
  # an orphan: the task is not running, the agent is (real run W5)
  Reset-Join
  $script:enrolled = $true
  $script:taskState = "Ready"
  $script:agentProcess = $true
  Invoke-StatusAction
  Check "status: an orphan is reported" 1 @($script:logged | Where-Object { $_.StartsWith("WARN: ORPHAN") }).Count
  Check "status: with what to run" 1 @($script:logged | Where-Object { $_.Contains("-Stop") -and $_.Contains("-Start") }).Count
  Reset-Join
  $script:taskState = "Ready"
  $script:agentProcess = $false
  Invoke-StatusAction
  Check "status: a stopped task with no agent is no orphan" 0 @($script:logged | Where-Object { $_.Contains("ORPHAN") }).Count
  Reset-Join
  $script:distroExists = $false
  try { Invoke-StatusAction } catch { if ($_.Exception.Message -ne $script:FailMarker) { throw } }
  Check "status, not installed: exit 31" 31 $script:ExitCode

  # --- T14b2: -Stop and -Start (spec 9.0) -----------------------------------------------------------------------------------
  function Invoke-ActionSafely([scriptblock]$a) { try { & $a } catch { if ($_.Exception.Message -ne $script:FailMarker) { throw } } }
  Reset-Join
  $script:taskRegistered = $true
  Invoke-ActionSafely { Invoke-StopAction }
  Check "-Stop: disable, stop, then terminate the distro (stopping the task alone leaves the node running)" "task:disable|task:stop|--terminate p2pc-node" ($script:wslCalls -join "|")
  Check "-Stop: exit 0" 0 $script:ExitCode
  Check "-Stop: says how to start it again" 1 @($script:logged | Where-Object { $_.StartsWith("OK:") -and $_.Contains("-Start") }).Count
  Reset-Join
  $script:enrolled = $true
  Invoke-ActionSafely { Invoke-StartAction }
  Check "-Start: enable, then start" "task:enable|task:start" ($script:wslCalls -join "|")
  Check "-Start: exit 0" 0 $script:ExitCode
  Check "-Start: it waits for the connection (fresh here: at once)" 0 $script:sleeps
  # -Start after -Stop: the connection from before the stop does not count (real run: 03:31 taken for 03:43)
  Reset-Join
  $script:enrolled = $true
  $script:taskState = "Disabled"
  $script:connection = "connected (since 2026-11-06T11:49:00Z)"
  Invoke-ActionSafely { Invoke-StartAction }
  Check "-Start, stale connected: exit 0" 0 $script:ExitCode
  Check "-Start, stale connected: it waits, then warns" 1 @($script:logged | Where-Object { $_.StartsWith("WARN:") -and $_.Contains("not connected since the task started") }).Count
  Check "-Start, stale connected: it waited" $true ($script:sleeps -ge 25)
  Reset-Join
  $script:enrolled = $true
  $script:taskState = "Disabled"
  $script:connection = "connected (since 2026-11-06T12:00:02Z)"
  Invoke-ActionSafely { Invoke-StartAction }
  Check "-Start, fresh connected: accepted at once" 0 $script:sleeps
  Check "-Start, fresh connected: the status line is shown" 1 @($script:logged | Where-Object { $_.Contains("Connection:    connected (since 2026-11-06T12:00:02Z)") }).Count
  Reset-Join
  $script:taskRegistered = $false
  Invoke-ActionSafely { Invoke-StartAction }
  Check "-Start without a task: exit 35" 35 $script:ExitCode
  Reset-Join
  Invoke-ActionSafely { Invoke-StopAction }
  Check "-Stop without a task: the distro is terminated all the same" "--terminate p2pc-node" ($script:wslCalls -join "|")
  $script:taskRegistered = $true
  Reset-Join
  $script:distroExists = $false
  Invoke-ActionSafely { Invoke-StopAction }
  Check "-Stop, not installed: exit 31" 31 $script:ExitCode
  # -Start after a terminal stop: the record is forgotten, the task enabled and started (spec 9.0)
  Reset-Join
  $script:enrolled = $true
  $script:taskState = "Disabled"
  Write-StopRecord 7
  Invoke-ActionSafely { Invoke-StartAction }
  Check "-Start after a terminal stop: enable, then start" "task:enable|task:start" ($script:wslCalls -join "|")
  Check "-Start after a terminal stop: the record is gone" $false (Test-Path -LiteralPath (Get-NodeStopRecordPath))
  Check "-Start after a terminal stop: it warns it may stop again, with the advice" 1 @($script:logged | Where-Object { $_.StartsWith("WARN:") -and $_.Contains("stopped for good") -and $_.Contains("-Join -Force") }).Count
  # -Status shows the reason and what to run
  foreach ($code in @("7", "6")) {
      Reset-Join
      $script:enrolled = $true
      $script:taskState = "Disabled"
      Write-StopRecord $code
      Invoke-StatusAction
      Check ("-Status, stopped by " + $code + ": the reason is shown") 1 @($script:logged | Where-Object { $_.StartsWith("WARN: STOPPED FOR GOOD") -and $_.Contains("exited " + $code) -and $_.Contains("stub reason " + $code) }).Count
      $want = "-Join -Force"
      if ($code -eq "6") { $want = "-Upgrade" }
      Check ("-Status, stopped by " + $code + ": what to run") 1 @($script:logged | Where-Object { $_.StartsWith("WARN:") -and $_.Contains($want) -and -not $_.StartsWith("WARN: STOPPED") }).Count
  }
  # -Status, a record with no code and none in the distro: the code is unknown, and it says where to look
  Reset-Join
  $script:enrolled = $true
  $script:taskState = "Disabled"
  $script:noNodeRunStatus = $true
  [System.IO.File]::WriteAllText((Get-NodeStopRecordPath), "node_exit=64`r`ndisabled=yes`r`n")
  Invoke-StatusAction
  Check "-Status, code unknown: STOPPED FOR GOOD with an unknown code" 1 @($script:logged | Where-Object { $_.StartsWith("WARN: STOPPED FOR GOOD") -and $_.Contains("unknown") }).Count
  Check "-Status, code unknown: it points at the agent log" 1 @($script:logged | Where-Object { $_.StartsWith("WARN:") -and $_.Contains("/var/log/p2pc/agent.log") }).Count
  Check "-Status, code unknown: no advice for 7 or 8" 0 @($script:logged | Where-Object { $_.Contains("join-token create") }).Count
  Remove-StopRecord
  # -Status: a task registered by an older install.ps1 (no wrapper) is named, with what to run (round 4 real run, W1c)
  Check "the task action is current: the wrapper (a real-shaped task, strict mode)" $true (& { Set-StrictMode -Version Latest; Test-NodeTaskActionCurrent })
  $script:taskArgs = $oldArgs
  Check "the task action is not current: the action of round 1" $false (& { Set-StrictMode -Version Latest; Test-NodeTaskActionCurrent })
  $script:taskArgs = $wrapperArgs
  Remove-Item -LiteralPath (Get-NodeTaskWrapperPath) -Force
  Check "the task action is not current: the wrapper file is missing" $false (Test-NodeTaskActionCurrent)
  $script:taskRegistered = $false
  Check "no task: nothing to compare" $null (Test-NodeTaskActionCurrent)
  $script:taskRegistered = $true
  Reset-Join
  $script:enrolled = $true
  $script:taskArgs = $oldArgs
  Invoke-StatusAction
  Check "-Status, an old action: a warning that it never stops the node for good" 1 @($script:logged | Where-Object { $_.StartsWith("WARN:") -and $_.Contains("node-task.cmd") -and $_.Contains("for good") }).Count
  Check "-Status, an old action: what to run" 1 @($script:logged | Where-Object { $_.StartsWith("WARN:") -and $_.Contains(".\install.ps1 -Join") -and -not $_.Contains("-Force") }).Count
  Reset-Join
  $script:enrolled = $true
  Invoke-StatusAction
  Check "-Status, the wrapper: no such warning" 0 @($script:logged | Where-Object { $_.Contains("node-task.cmd") }).Count
  Reset-Join
  $script:taskRegistered = $false
  Invoke-StatusAction
  Check "-Status, no task: no action warning" 0 @($script:logged | Where-Object { $_.Contains("node-task.cmd") }).Count
  $script:taskRegistered = $true

  if ($fail -gt 0) { Write-Host ("test-install-ps1: {0} of {1} assertions FAILED" -f $fail, $n); exit 1 }
  Write-Host ("test-install-ps1: {0} assertions passed" -f $n)
'
status=$?

# --- the whole script, in a child pwsh: a join token put on the command line is refused (exit 2) before anything runs,
# and it is echoed nowhere: not on the console, not in the log (T14b2).
tok="p2pc_join_testonlycommandlinetoken" # gitleaks:allow
scratch="$(mktemp -d "${TMPDIR:-/tmp}/p2pc-ps1-test.XXXXXX")"
trap 'rm -rf "$scratch"' EXIT
child_fail=0
for variant in positional unknown; do
  log="$scratch/$variant.log"
  if [[ "$variant" == positional ]]; then
    out="$(LOCALAPPDATA="$scratch" pwsh -NoProfile -NonInteractive -File "$ps1" -Join "$tok" -LogPath "$log" </dev/null 2>&1)"
  else
    out="$(LOCALAPPDATA="$scratch" pwsh -NoProfile -NonInteractive -File "$ps1" -Join -Token "$tok" -LogPath "$log" </dev/null 2>&1)"
  fi
  rc=$?
  if [[ "$rc" != 2 ]]; then
    echo "FAIL: a token on the command line ($variant): want exit 2, got $rc: $out" >&2
    child_fail=1
  fi
  if [[ "$out" == *"$tok"* ]] || grep -qF "$tok" "$log" 2>/dev/null; then
    echo "FAIL: a token on the command line ($variant) was echoed to the console or the log" >&2
    child_fail=1
  fi
  if [[ "$out" != *"Never put the join token on the command line"* ]]; then
    echo "FAIL: a token on the command line ($variant): the message does not say why: $out" >&2
    child_fail=1
  fi
done
# A token given as the value of a string parameter (review P3-1): refused before the log is opened (-LogPath itself may
# be the token), nothing echoed, and no file of that name created.
for param in Tar Sha256Path InstallDir LogPath; do
  run_dir="$scratch/cwd-$param"
  mkdir -p "$run_dir"
  out="$(cd "$run_dir" && LOCALAPPDATA="$scratch/la-$param" pwsh -NoProfile -NonInteractive -File "$ps1" "-$param" "$tok" </dev/null 2>&1)"
  rc=$?
  if [[ "$rc" != 2 ]]; then
    echo "FAIL: a token as -$param: want exit 2, got $rc: $out" >&2
    child_fail=1
  fi
  if [[ "$out" == *"$tok"* ]]; then
    echo "FAIL: a token as -$param was echoed" >&2
    child_fail=1
  fi
  if [[ -n "$(find "$run_dir" "$scratch" -name "*$tok*" 2>/dev/null)" ]]; then
    echo "FAIL: a token as -$param: a file named after it was created" >&2
    child_fail=1
  fi
  if grep -rqF "$tok" "$scratch/la-$param" 2>/dev/null; then
    echo "FAIL: a token as -$param reached a log" >&2
    child_fail=1
  fi
done
# A confirmation prompt with stdin redirected (an SSH session, a pipe) can never be answered: it must fail at once with
# exit 30 and point at -Force, not wait (T14b2 real run: -Upgrade waited forever over SSH). The 60 s limit only turns
# a hang into a failure.
# shellcheck disable=SC2016  # PowerShell code: nothing in it is meant to expand in bash
out="$(P2PC_PS1="$ps1" timeout 60 pwsh -NoProfile -NonInteractive -Command '
  . $env:P2PC_PS1
  $script:LogFile = $null
  try { Confirm-Action "Really replace the distro?" } catch { }
  exit $script:ExitCode
' </dev/null 2>&1)"
rc=$?
if [[ "$rc" != 30 ]]; then
  echo "FAIL: a confirmation with stdin redirected: want exit 30 at once, got $rc: $out" >&2
  child_fail=1
fi
if [[ "$out" != *"-Force"* ]]; then
  echo "FAIL: a confirmation with stdin redirected: the message does not point at -Force: $out" >&2
  child_fail=1
fi
if ((child_fail)); then
  exit 1
fi
echo "test-install-ps1: a token on the command line is refused and never echoed (6 cases); an unanswerable prompt fails at once (1 case)"
exit "$status"
