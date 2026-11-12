# SPDX-License-Identifier: Apache-2.0
<#
.SYNOPSIS
  Installs, upgrades or removes the dedicated "p2pc-node" WSL2 distro (spec 9.0). Windows PowerShell 5.1 compatible.

.DESCRIPTION
  The installer only ever creates, replaces or removes the distro named p2pc-node. It never touches other distros,
  .wslconfig or Windows features: when one of those is the problem it tells you what to run, and stops.

  Install   :  .\install.ps1 -Tar .\p2pc-node-0.2.2.tar.gz
  Join      :  .\install.ps1 -Join [-Force]          then paste the join token when asked (the input is hidden)
               Get-Content .\token.txt | .\install.ps1 -Join      the token from the pipeline instead
  Status    :  .\install.ps1 -Status
  Stop/Start:  .\install.ps1 -Stop    |    .\install.ps1 -Start
  Upgrade   :  .\install.ps1 -Upgrade -Tar .\p2pc-node-0.3.0.tar.gz
  Uninstall :  .\install.ps1 -Uninstall [-Force] [-KeepBackups | -DeleteFailedBackups]
  Check only:  .\install.ps1 -CheckOnly [-Tar <file>]

  The tar must have a "<tar>.sha256" file next to it (build-rootfs.sh writes one); it is verified before import.

  -Join enrolls the node and keeps its agent running. The join token is NEVER a parameter (a command line is visible to
  other programs and kept in the shell history): it is read with Read-Host -AsSecureString, or taken from the pipeline,
  and written only to the stdin of
    wsl.exe -d p2pc-node -u root --exec /usr/local/bin/p2pc-agent join -
  Then it registers and starts the per-user Scheduled Task "P2PC node" (spec 9.0), running
    conhost.exe --headless cmd.exe /d /s /c ""%LOCALAPPDATA%\P2PC\node-task.cmd""
  a wrapper the installer writes and owns, which runs
    wsl.exe -d p2pc-node -u root --exec /usr/local/sbin/p2pc-node-run
  and, when that ends with 64 (the agent stopped for good: 6 too old, 7 removed, 8 not joined), disables the task and
  writes why in %LOCALAPPDATA%\P2PC\stopped-by-node (spec 9.0: the 5-minute trigger must not start such a node again
  and again), then terminates the distro (best effort). -Join and -Start enable it again, -Upgrade too after "too old",
  and -Status shows the reason. Once registered, the task's security descriptor is set (Task Scheduler COM API) to give
  the user full control, so the user's own wrapper can disable it even when -Join ran elevated. No window opens; no time
  limit, restarted on failure, allowed on battery, IgnoreNew, StartWhenAvailable. Its
  triggers (spec 9.0): a time trigger repeating every 5 minutes with no end (a watchdog that does nothing while the
  node runs and starts it again after it ended, for example after `wsl --terminate`), and a logon trigger for this user
  only, always, elevated or not (a normal user may register it; Windows refuses only a logon trigger for ANY user,
  which P2PC never asks for). If Windows refuses the registration anyway, -Join registers the time trigger alone and
  says the node starts within 5 minutes of signing in. The attached wsl.exe keeps the
  distro running; .wslconfig is never changed (instanceIdleTimeout would affect every distro). This script is
  deliberately not an advanced script ([CmdletBinding()]): that is what lets the pipeline carry the token without any
  parameter.
  -Status shows the task's state, then `p2pc-agent status` and p2pc-node-run's status from the distro, and reports an
  orphan (the agent runs but the task does not), and a task that does not run the wrapper (an older install.ps1).
  -Stop disables and stops the task, then terminates the distro: stopping the task alone does not stop the node (its
  wsl.exe survives). -Start enables and starts it again.
  -Uninstall stops and removes the task before it unregisters the distro (and removes it even when the distro is
  gone); -Upgrade disables and stops it, upgrades, registers it again (disabled: an older install.ps1's task gets the
  wrapper), and enables and starts it again unless it was disabled before.

  -Upgrade keeps the agent's identity AND its enrollment: all mutable node state lives in /var/lib/p2pc, the agent's
  config included (/var/lib/p2pc/agent.toml, named by P2PC_AGENT_CONFIG; images up to 0.2.1 kept it in
  /etc/p2pc/agent.toml, and -Upgrade copies it over first). On the PC that hosts the hub it also keeps the hub's data,
  /var/lib/p2pc-server (H2 spec 8.3: the cloud's database, keys, blobs and hub.enabled). Both directories are exported
  from the old distro to one backup file under
  %LOCALAPPDATA%\P2PC\backups (not %TEMP%, where Windows Storage Sense deletes old files), the old distro is
  unregistered, the new image is imported, both are restored with the same modes and owners, and the result
  is verified. After a successful upgrade the backup is renamed to p2pc-state-<time>.ok.tar and only the newest 3 of
  those are kept. The backup of an upgrade that failed is never deleted, and its path is printed.

  Exit codes
     0  success
     1  unexpected error
     2  bad usage / bad parameters
    10  Windows build is too old
    11  WSL is not installed (or `wsl --version` does not work)
    12  WSL is older than the minimum version
    13  WSL default version is not 2
    14  virtualization is disabled in the firmware
    15  not enough free disk space
    16  the p2pc-node distro already exists (use -Upgrade)
    17  the tar or its .sha256 file is missing or unreadable
    18  SHA-256 mismatch
    19  the install directory is not empty (-Upgrade: it holds something besides the files WSL owns, ext4.vhdx and
        shortcut.ico; checked BEFORE the old distro is unregistered, so nothing has been touched)
    20  wsl --import failed
    21  verification of the new distro failed
    22  -Upgrade: p2pc-node is not installed
    23  -Upgrade: exporting /var/lib/p2pc (and /var/lib/p2pc-server) failed, or it could not be determined whether
        /var/lib/p2pc exists, or it does not exist and -Force was not given, or /var/lib/p2pc-server exists without
        it (with or without -Force) (the old distro is never touched in these cases)
    24  -Upgrade: unregistering the old distro failed
    25  -Upgrade: restoring /var/lib/p2pc (and /var/lib/p2pc-server) failed
    26  -Upgrade: verification after restore failed (the exported state file is kept)
    27  -Uninstall: p2pc-node is not installed
    29  -Uninstall: wsl --unregister failed
    30  cancelled at the confirmation prompt (nothing changed)
    31  -Join / -Status / -Stop / -Start: p2pc-node is not installed
    32  -Join: the image has no agent or no p2pc-shim (/usr/local/bin), or is older than 0.2.2 (its agent config is
        outside /var/lib/p2pc): upgrade to an image built with --agent-from
    33  -Join: the enrollment failed (the token was refused or has expired, or the agent could not reach the server)
    34  -Join: the node is already enrolled with another identity and the agent refuses (use -Force)
    35  -Join / -Start: the Scheduled Task could not be registered, enabled or started, or it does not stay running
    37  -Uninstall: the Scheduled Task could not be removed (the distro was NOT touched)
    38  -Upgrade: the node did not come back enrolled (no [server] in /var/lib/p2pc/agent.toml after the restore, or the
        agent stopped with exit 8 or 7): it says what to run

.PARAMETER Tar
  The image: p2pc-node-<version>.tar.gz.
.PARAMETER Sha256Path
  The checksum file. Default: "<Tar>.sha256".
.PARAMETER InstallDir
  Where WSL keeps the distro's virtual disk. Default: %LOCALAPPDATA%\P2PC\wsl\p2pc-node
.PARAMETER Join
  Enroll the node (the token is asked for, hidden, or read from the pipeline: never a parameter), then register and
  start the Scheduled Task "P2PC node" that keeps the agent running. Rerun it to re-register the task.
.PARAMETER Status
  Show the Scheduled Task's state, `p2pc-agent status` and p2pc-node-run's status (/var/lib/p2pc/node-run.status).
.PARAMETER Stop
  Take the node offline: disable and stop the Scheduled Task, then terminate the distro. It stays offline (no start at
  sign-in or from the 5-minute trigger) until -Start.
.PARAMETER Start
  Enable and start the Scheduled Task again.
.PARAMETER Force
  Skip the confirmation prompt of -Upgrade and -Uninstall. -Upgrade also needs it to go on when the old distro has no
  /var/lib/p2pc (no agent identity to carry over: the node will have to re-enrol). With -Join: enroll again even if the
  node is already enrolled: it re-enrolls this machine (the same node, spec 5). To retire a machine instead, remove it
  on the server with p2pc machines rm.
.PARAMETER KeepBackups
  Only with -Uninstall. By default -Uninstall also deletes the VERIFIED -Upgrade state backups
  (p2pc-state-<time>.ok.tar under %LOCALAPPDATA%\P2PC\backups; they hold the agent identity key): an uninstall must
  really remove the identity. With -KeepBackups every backup is left where it is.
.PARAMETER DeleteFailedBackups
  Only with -Uninstall. The backup of an upgrade that did not finish (p2pc-state-<time>.tar, no .ok) is the only copy
  of the identity of that node, so -Uninstall never deletes it by default (with or without -Force): it lists it by
  its full path. -DeleteFailedBackups deletes those too. It cannot be combined with -KeepBackups.
.PARAMETER MinFreeGB
  Minimum free space on the install drive. Default 20.
.PARAMETER LogPath
  Log file. Default: %LOCALAPPDATA%\P2PC\logs\install-<timestamp>.log
#>
param(
    [string]$Tar,
    [string]$Sha256Path,
    [string]$InstallDir,
    [switch]$Upgrade,
    [switch]$Uninstall,
    [switch]$Join,
    [switch]$Status,
    [switch]$Stop,
    [switch]$Start,
    [switch]$CheckOnly,
    [switch]$Force,
    [switch]$KeepBackups,
    [switch]$DeleteFailedBackups,
    [int]$MinFreeGB = 20,
    [string]$LogPath
)

$ErrorActionPreference = 'Stop'

$DistroName = 'p2pc-node'
# Windows 10 21H2 (19044) is the oldest build the Store version of WSL supports.
$MinWindowsBuild = 19044
$MinWslVersion = [version]'2.0.0'
$LxssKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Lxss'
# The agent and the supervisor inside the image (build-rootfs.sh), and the task that runs the supervisor (spec 9.0).
$AgentPath = '/usr/local/bin/p2pc-agent'
# The agent's executor takes no lease without p2pc-shim next to it.
$ShimPath = '/usr/local/bin/p2pc-shim'
$NodeRunPath = '/usr/local/sbin/p2pc-node-run'
$NodeRunStatusPath = '/var/lib/p2pc/node-run.status'
# All mutable node state lives in /var/lib/p2pc, the one directory -Upgrade carries over: the agent's config too. As root
# the agent would read /etc/p2pc/agent.toml, which an upgrade replaces with the image's (T14b2 review: [server] was lost),
# so every agent call names this file through P2PC_AGENT_CONFIG (p2pc-node-run does the same). Images up to 0.2.1 kept
# [server] in /etc/p2pc/agent.toml; -Upgrade copies it here (see $ConfigMigrationScript).
$AgentConfigPath = '/var/lib/p2pc/agent.toml'
$TaskName = 'P2PC node'
# How long -Join waits for the agent to say "connected" once the task runs.
$ConnectWaitSeconds = 60

# What -Upgrade carries over (H2 spec 8.3): /var/lib/p2pc (the agent's identity, enrollment and state) and, on the PC
# that hosts the hub, /var/lib/p2pc-server (the hub's database, keys, blobs and hub.enabled). Nothing else of /var/lib.
# The probe for "does the agent state exist?": prints exactly one marker. Absent is only believed on a positive answer.
# The hub's data without the agent state is its own answer (hub-only): -Upgrade refuses it, with or without -Force.
$StateProbeScript = 'if [ -d /var/lib/p2pc ]; then echo P2PC_STATE=present; elif [ -e /var/lib/p2pc-server ]; then echo P2PC_STATE=hub-only; else echo P2PC_STATE=absent; fi'
# The state archive, as a bash script run inside the distro. It WRITES the archive to a file inside the distro (@OUT@,
# replaced by Get-StateArchiveScript with a validated path, mode 0600 through umask) and prints its SHA-256 there:
# binary data is never streamed through PowerShell, which cannot be trusted to keep bytes (see Invoke-WslCopyOut). It
# lists the files with find and hands the list to tar, because tar cannot exclude by file type: sockets and FIFOs are
# left out (a socket cannot be archived, a FIFO would be re-created, and neither is identity; one of them would
# otherwise make the before/after listing differ and fail every upgrade, exit 26). The boot step's own files in p2pc
# (tmp/, boot-status.json, .boot-status.*) are left out too: they are not identity and change at every start.
# find starts at /var/lib and prunes every entry that is neither p2pc nor p2pc-server, so a node without the hub
# directory archives p2pc alone (naming p2pc-server as a start point would fail there); %P keeps the member names
# relative to /var/lib (p2pc/..., p2pc-server/...), as before.
# One line, no double quote, no dollar sign, no backtick, no && (tests/test-install-archive.sh checks all of it).
$StateArchiveScript = "set -e; set -o pipefail; umask 077; cd /var/lib; find . -mindepth 1 ! -path ./p2pc ! -path './p2pc/*' ! -path ./p2pc-server ! -path './p2pc-server/*' -prune -o -type s -prune -o -type p -prune -o -path ./p2pc/tmp -prune -o -path ./p2pc/boot-status.json -prune -o -path './p2pc/.boot-status.*' -prune -o -printf '%P\0' | tar --numeric-owner --no-recursion --null -T - -cpf @OUT@; sha256sum @OUT@"

# Before the old distro is archived: when /var/lib/p2pc/agent.toml does not exist yet (an image up to 0.2.1), it is
# created there, as a copy of /etc/p2pc/agent.toml (which holds [server] on a joined node) or empty, mode 0600, so the
# archive carries the enrollment and the before/after listing of /var/lib/p2pc matches. Prints exactly one marker.
# One line, no double quote, no dollar sign, no backtick, no && (tests/test-install-archive.sh checks all of it).
$ConfigMigrationScript = "if [ -e /var/lib/p2pc/agent.toml ]; then echo P2PC_CONFIG=present; elif [ -s /etc/p2pc/agent.toml ]; then install -m 0600 -o 0 -g 0 /etc/p2pc/agent.toml /var/lib/p2pc/agent.toml; echo P2PC_CONFIG=moved; else install -m 0600 -o 0 -g 0 /dev/null /var/lib/p2pc/agent.toml; echo P2PC_CONFIG=created; fi"

# How many completed -Upgrade backups of /var/lib/p2pc (the agent identity) are kept under %LOCALAPPDATA%\P2PC\backups
# (not %TEMP%, which Windows Storage Sense empties). See Get-BackupsToPrune.
$BackupKeep = 3

# The files WSL itself keeps in a distro's directory (WSL 2.7.8 measured: ext4.vhdx and, since the import, shortcut.ico).
# This is the ONLY place the list lives: the pre-unregister check of -Upgrade and the check in Import-Distro both use
# it (Test-DistroDirNames), compared case-insensitively. Anything else in that directory is somebody's file and the
# installer never deletes files it did not create.
$WslOwnedFiles = @('ext4.vhdx', 'shortcut.ico')

$script:ExitCode = 0
$script:LogFile = $null
$script:FailMarker = 'P2PC-INSTALLER-STOP'
# The export of /var/lib/p2pc of a running -Upgrade that has not been verified yet (null when there is none).
$script:StateBackup = $null
# Whether the image keeps the agent config in /var/lib/p2pc (Test-NewConfigLayout); $null until asked.
$script:NewConfigLayout = $null

# ---------------------------------------------------------------------------------------------------------------
# Logging and failing
# ---------------------------------------------------------------------------------------------------------------
function Write-Log {
    param([string]$Message, [string]$Level = 'INFO')
    $line = '{0} [{1}] {2}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $Message
    if ($script:LogFile) {
        try { Add-Content -LiteralPath $script:LogFile -Value $line -Encoding UTF8 } catch { }
    }
    switch ($Level) {
        'ERROR' { Write-Host $Message -ForegroundColor Red }
        'WARN'  { Write-Host $Message -ForegroundColor Yellow }
        'OK'    { Write-Host $Message -ForegroundColor Green }
        'DEBUG' { }   # log file only
        default { Write-Host $Message }
    }
}

# Fail: log the problem with its hints, remember the exit code and stop the run.
function Fail {
    param([int]$Code, [string]$Message, [string[]]$Hints = @())
    Write-Log ("Error {0}: {1}" -f $Code, $Message) 'ERROR'
    foreach ($h in $Hints) { Write-Log ("  " + $h) 'ERROR' }
    $script:ExitCode = $Code
    throw $script:FailMarker
}

# ---------------------------------------------------------------------------------------------------------------
# wsl.exe helpers
# ---------------------------------------------------------------------------------------------------------------
# A WSL service timeout under load: wsl.exe fails with "Wsl/Service/0x8007274c" before anything runs in the distro
# (T14b2 real run, W6). Only that error is retried, up to $WslRetryCount times, $WslRetryDelaySeconds apart: the command
# never reached the distro, so running it again is safe (for -Join: the agent never got the token).
$WslRetryCount = 3
$WslRetryDelaySeconds = 5

# Test-WslServiceTimeout <text>: the output of a wsl.exe call names the WSL service timeout.
function Test-WslServiceTimeout {
    param([string]$Text)
    return ([bool]$Text -and ($Text -match '(?i)0x8007274c'))
}

# Invoke-WithWslRetry <attempt> <what>: runs the attempt (a script block returning an object with ExitCode and Output
# and/or Stderr) and runs it again, after a pause, while it fails with the WSL service timeout.
function Invoke-WithWslRetry {
    param([scriptblock]$Attempt, [string]$What)
    $wslRetryResult = & $Attempt
    for ($wslRetry = 1; $wslRetry -le $WslRetryCount; $wslRetry++) {
        $wslRetryText = [string]$wslRetryResult.Output + "`n" + [string]$wslRetryResult.Stderr
        if ($wslRetryResult.ExitCode -eq 0 -or -not (Test-WslServiceTimeout $wslRetryText)) { return $wslRetryResult }
        Write-Log ("wsl.exe failed with Wsl/Service/0x8007274c (a WSL service timeout) on {0}: retry {1} of {2} in {3} s." -f $What, $wslRetry, $WslRetryCount, $WslRetryDelaySeconds) 'WARN'
        Start-Sleep -Seconds $WslRetryDelaySeconds
        $wslRetryResult = & $Attempt
    }
    return $wslRetryResult
}

function Invoke-Wsl {
    param([string[]]$WslArgs)
    return (Invoke-WithWslRetry { Invoke-WslOnce $WslArgs } ('wsl ' + ($WslArgs -join ' ')))
}

# wsl.exe writes its own messages in UTF-16, which PowerShell 5.1 shows with NUL characters between letters.
# Strip them. Output of the Linux commands we run is plain text.
function Invoke-WslOnce {
    param([string[]]$WslArgs)
    $old = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'   # native stderr must not become a terminating error in 5.1
    try {
        $out = & wsl.exe @WslArgs 2>&1
        $code = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $old
    }
    $text = (($out | ForEach-Object { "$_" }) -join "`n") -replace "`0", ''
    $text = $text.Trim([char]0xFEFF).Trim()
    $shown = $text
    if ($shown.Length -gt 600) { $shown = $shown.Substring(0, 600) + '...' }
    Write-Log ("wsl {0} -> exit {1}; {2}" -f ($WslArgs -join ' '), $code, ($shown -replace "`r?`n", ' | ')) 'DEBUG'
    return New-Object psobject -Property @{ ExitCode = $code; Output = $text }
}

# Runs a command inside the distro as root, without a shell.
function Invoke-InDistro {
    param([string[]]$Command)
    return Invoke-Wsl (@('-d', $DistroName, '-u', 'root', '--exec') + $Command)
}

function Get-DistroNames {
    $r = Invoke-Wsl @('--list', '--quiet')
    $names = @()
    foreach ($line in ($r.Output -split "`r?`n")) {
        $n = $line.Trim()
        if ($n) { $names += $n }
    }
    return $names
}

function Test-DistroExists {
    return ((Get-DistroNames) -contains $DistroName)
}

# BasePath of the registered distro, read from the registry (read-only), or $null.
function Get-DistroBasePath {
    try {
        foreach ($k in (Get-ChildItem -Path $LxssKey -ErrorAction Stop)) {
            $p = Get-ItemProperty -Path $k.PSPath -ErrorAction SilentlyContinue
            if ($p -and ($p.DistributionName -eq $DistroName) -and $p.BasePath) {
                return ($p.BasePath -replace '^\\\\\?\\', '')
            }
        }
    } catch { }
    return $null
}

# BINARY DATA RULE: the bytes of the agent state never pass through PowerShell as text or objects. Windows PowerShell 5.1
# re-encodes the stdout of a native command that is piped, captured or redirected with > (it decodes the bytes with
# the console code page and writes them back as text), which corrupts a tar archive. So:
#   - the state archive is WRITTEN INSIDE the distro, by a command whose stdout is not used (see $StateArchiveScript);
#   - it is copied OUT by cmd.exe's own redirection, which is byte-exact (Invoke-WslCopyOut);
#   - it is copied IN by .NET streams: raw bytes from a FileStream to the child's stdin BaseStream (Invoke-WslStream);
#   - every copy is checked with SHA-256 against a hash computed on the other side.
# tests/test-install-lint.sh enforces this on this file.

# Test-CmdSafePath <path>: a Windows path that can sit inside double quotes on a cmd.exe command line. Inside quotes
# cmd treats everything literally except %VAR% expansion, and a quote ends the string; so those two are refused.
function Test-CmdSafePath {
    param([string]$Path)
    return ([bool]$Path -and ($Path -notmatch '[%"]'))
}

# Test-LinuxSafePath <path>: an absolute path with only characters that need no quoting in any of the shells involved.
function Test-LinuxSafePath {
    param([string]$Path)
    return ($Path -match '^/[A-Za-z0-9._/-]+$')
}

# Get-CmdCopyOutArguments: the raw command line for cmd.exe that runs `wsl.exe ... cat <file>` with stdout redirected
# to a Windows file. /d skips AutoRun, /s makes cmd strip exactly the outer pair of quotes and keep the rest as written.
function Get-CmdCopyOutArguments {
    param([string]$Distro, [string]$LinuxPath, [string]$WinPath)
    return ('/d /s /c ""wsl.exe" -d {0} -u root --exec /bin/cat {1} > "{2}""' -f $Distro, $LinuxPath, $WinPath)
}

# Copies a file out of the distro to $WinPath, byte for byte, with cmd.exe's redirection (the \\wsl.localhost share is
# not available from non-interactive sessions such as SSH, and a PowerShell pipe or > would re-encode the bytes: see the
# BINARY DATA RULE above). Nothing is read by PowerShell: cmd is started without redirecting its own streams except
# stderr, which is text. Returns an object with ExitCode (-1 when it could not even run) and Stderr.
function Invoke-WslCopyOut {
    param([string]$LinuxPath, [string]$WinPath)
    $code = -1
    $errText = ''
    if (-not (Test-CmdSafePath $WinPath)) {
        $errText = 'the backup path contains a percent sign or a double quote, which cmd.exe cannot carry safely: ' + $WinPath
    } elseif (-not (Test-LinuxSafePath $LinuxPath)) {
        $errText = 'unsafe path inside the distro: ' + $LinuxPath
    } else {
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = 'cmd.exe'
        $psi.Arguments = Get-CmdCopyOutArguments -Distro $DistroName -LinuxPath $LinuxPath -WinPath $WinPath
        $psi.UseShellExecute = $false
        $psi.CreateNoWindow = $true
        $psi.RedirectStandardError = $true
        $proc = $null
        try {
            $proc = [System.Diagnostics.Process]::Start($psi)
            $errTask = $proc.StandardError.ReadToEndAsync()
            $proc.WaitForExit()
            $code = $proc.ExitCode
            $errText = ($errTask.Result -replace "`0", '').Trim()
        } catch {
            $errText = $_.Exception.Message
            if ($proc -and -not $proc.HasExited) { try { $proc.Kill() } catch { } }
        }
    }
    Write-Log ("cmd.exe {0} -> exit {1}; {2}" -f $psi.Arguments, $code, ($errText -replace "`r?`n", ' | ')) 'DEBUG'
    return New-Object psobject -Property @{ ExitCode = $code; Stderr = $errText }
}

# Runs wsl.exe with the given command line and feeds it the file $InFile on stdin (this is what carries /var/lib/p2pc INTO
# the new distro). The bytes are copied by .NET streams (a FileStream to the child's stdin BaseStream): no PowerShell
# pipeline, no cmd, no re-encoding. stdout is drained and discarded, it is never used. The result is checked by hash
# inside the distro by the caller. Returns an object with ExitCode (-1 when the copy itself failed) and Stderr.
function Invoke-WslStream {
    param([string]$Arguments, [string]$InFile)
    return (Invoke-WithWslRetry { Invoke-WslStreamOnce -Arguments $Arguments -InFile $InFile } ('wsl ' + $Arguments))
}

function Invoke-WslStreamOnce {
    param([string]$Arguments, [string]$InFile)
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = 'wsl.exe'
    $psi.Arguments = $Arguments
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $psi.RedirectStandardInput = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $code = -1
    $errText = ''
    $proc = $null
    try {
        $proc = [System.Diagnostics.Process]::Start($psi)
        # Both text streams are drained concurrently, so a chatty child can never block on a full pipe.
        $errTask = $proc.StandardError.ReadToEndAsync()
        $null = $proc.StandardOutput.ReadToEndAsync()
        if ($InFile) {
            $fs = [System.IO.File]::Open($InFile, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read)
            try { $fs.CopyTo($proc.StandardInput.BaseStream) } finally { $fs.Dispose() }
        }
        $proc.StandardInput.Close()   # EOF for the child
        $proc.WaitForExit()
        $code = $proc.ExitCode
        $errText = ($errTask.Result -replace "`0", '').Trim()
    } catch {
        $errText = $_.Exception.Message
        if ($proc -and -not $proc.HasExited) { try { $proc.Kill() } catch { } }
    }
    Write-Log ("wsl {0} (stream in={1}) -> exit {2}; {3}" -f $Arguments, [bool]$InFile, $code, ($errText -replace "`r?`n", ' | ')) 'DEBUG'
    return New-Object psobject -Property @{ ExitCode = $code; Stderr = $errText }
}

# Get-StateArchiveScript <linux path>: $StateArchiveScript with the output path filled in (validated: no quoting needed).
function Get-StateArchiveScript {
    param([string]$OutPath)
    if (-not (Test-LinuxSafePath $OutPath)) { throw ("unsafe archive path: " + $OutPath) }
    return $StateArchiveScript.Replace('@OUT@', $OutPath)
}

# ---------------------------------------------------------------------------------------------------------------
# Checks before installing (each one has its own message and exit code)
# ---------------------------------------------------------------------------------------------------------------
function Test-WindowsBuild {
    $build = 0
    try { $build = [int](Get-CimInstance -ClassName Win32_OperatingSystem).BuildNumber } catch { $build = [Environment]::OSVersion.Version.Build }
    if ($build -lt $MinWindowsBuild) {
        Fail 10 ("Windows build {0} is too old (need {1} or newer)." -f $build, $MinWindowsBuild) @(
            'Update Windows (Windows 10 21H2 / Windows 11 or newer), then run this installer again.')
    }
    Write-Log ("Windows build {0}: OK" -f $build) 'OK'
}

function Test-Wsl {
    $cmd = Get-Command wsl.exe -ErrorAction SilentlyContinue
    if (-not $cmd) {
        Fail 11 'WSL is not installed (wsl.exe was not found).' @(
            'Install it from an elevated terminal:   wsl --install --no-distribution',
            'then reboot and run this installer again. This installer does not enable Windows features.')
    }
    $r = Invoke-Wsl @('--version')
    $m = [regex]::Match($r.Output, '\d+\.\d+\.\d+(\.\d+)?')
    if ($r.ExitCode -ne 0 -or -not $m.Success) {
        Fail 11 'WSL is not installed, or it is too old to report its version (`wsl --version` failed).' @(
            'Install or update it from an elevated terminal:   wsl --install --no-distribution   then   wsl --update',
            'Reboot if asked, then run this installer again.')
    }
    $v = [version]$m.Value
    if ($v -lt $MinWslVersion) {
        Fail 12 ("WSL {0} is older than the minimum {1}." -f $v, $MinWslVersion) @(
            'Update it from a terminal:   wsl --update', 'then run this installer again.')
    }
    Write-Log ("WSL {0}: OK" -f $v) 'OK'
}

function Test-WslDefaultVersion {
    $p = Get-ItemProperty -Path $LxssKey -Name DefaultVersion -ErrorAction SilentlyContinue
    if ($p -and $p.DefaultVersion -ne 2) {
        Fail 13 ("The WSL default version is {0}, not 2." -f $p.DefaultVersion) @(
            'Set it yourself:   wsl --set-default-version 2', 'then run this installer again.')
    }
    Write-Log 'WSL default version is 2 (or unset, which means 2): OK' 'OK'
}

function Test-Virtualization {
    $hv = $null
    $fw = @()
    try { $hv = (Get-CimInstance -ClassName Win32_ComputerSystem).HypervisorPresent } catch { }
    try { $fw = @(Get-CimInstance -ClassName Win32_Processor | ForEach-Object { $_.VirtualizationFirmwareEnabled }) } catch { }
    # With the hypervisor already running (as it is once WSL2 works) the firmware flag can read False, so trust the hypervisor first.
    if ($hv -eq $true) {
        Write-Log 'Virtualization: the hypervisor is running: OK' 'OK'
    } elseif ($fw -contains $true) {
        Write-Log 'Virtualization is enabled in the firmware: OK' 'OK'
    } elseif ($fw -contains $false) {
        Fail 14 'Virtualization is disabled in the firmware (BIOS/UEFI).' @(
            'Reboot into the firmware setup and enable Intel VT-x / AMD-V (SVM), then run this installer again.',
            'This installer does not change firmware or Windows features.')
    } else {
        Write-Log 'Virtualization: could not be determined (running in a VM?). Continuing; the import will fail clearly if it is off.' 'WARN'
    }
}

function Test-DiskSpace {
    param([string]$Dir)
    $full = [System.IO.Path]::GetFullPath($Dir)
    $root = [System.IO.Path]::GetPathRoot($full)
    if ($root.StartsWith('\\')) {
        Fail 2 ("The install directory must be on a local drive, not a network path: {0}" -f $full)
    }
    $drive = New-Object System.IO.DriveInfo($root)
    $freeGB = [math]::Floor($drive.AvailableFreeSpace / 1GB)
    if ($freeGB -lt $MinFreeGB) {
        Fail 15 ("Only {0} GB free on {1}; at least {2} GB are needed (image, container images, job data)." -f $freeGB, $root, $MinFreeGB) @(
            'Free some space, or choose another drive with -InstallDir, then run this installer again.')
    }
    Write-Log ("Free space on {0}: {1} GB: OK" -f $root, $freeGB) 'OK'
}

function Test-Prerequisites {
    param([string]$Dir)
    Test-WindowsBuild
    Test-Wsl
    Test-WslDefaultVersion
    Test-Virtualization
    Test-DiskSpace $Dir
}

# Verifies the tar against its .sha256 file. Returns the verified tar path.
function Test-Image {
    if (-not $Tar) { Fail 2 'Missing -Tar <path to p2pc-node-<version>.tar.gz>.' }
    if (-not (Test-Path -LiteralPath $Tar -PathType Leaf)) { Fail 17 ("Image not found: {0}" -f $Tar) }
    $shaFile = $Sha256Path
    if (-not $shaFile) { $shaFile = $Tar + '.sha256' }
    if (-not (Test-Path -LiteralPath $shaFile -PathType Leaf)) {
        Fail 17 ("Checksum file not found: {0}" -f $shaFile) @('Download the .sha256 file that belongs to the image and keep it next to it.')
    }
    $line = (Get-Content -LiteralPath $shaFile -TotalCount 1)
    $m = [regex]::Match([string]$line, '^\s*([0-9a-fA-F]{64})\b')
    if (-not $m.Success) { Fail 17 ("{0} does not start with a SHA-256 (64 hex digits)." -f $shaFile) }
    $want = $m.Groups[1].Value.ToLowerInvariant()
    $got = (Get-FileHash -LiteralPath $Tar -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($got -ne $want) {
        Fail 18 'SHA-256 mismatch: the image is corrupt or not the one the checksum file describes.' @(
            ("expected {0}" -f $want), ("computed {0}" -f $got), 'Download it again. Nothing was installed.')
    }
    Write-Log ("Image SHA-256 verified: {0}" -f $got) 'OK'
    return (Resolve-Path -LiteralPath $Tar).Path
}

function Confirm-Action {
    param([string]$Question)
    if ($Force) { return }
    Write-Host $Question
    # With stdin redirected (an SSH session, a pipe) Read-Host waits for an answer that can never come (T14b2 real run):
    # stop at once instead.
    if (Test-StdinRedirected) {
        Write-Log 'No answer can be read here (stdin is not a terminal, for example an SSH session). Nothing was changed. Rerun with -Force to confirm.' 'ERROR'
        $script:ExitCode = 30
        throw $script:FailMarker
    }
    $answer = ''
    try { $answer = Read-Host "Type 'yes' to continue" } catch { $answer = '' }
    if ($answer -ne 'yes') {
        Write-Log 'Cancelled. Nothing was changed.' 'WARN'
        $script:ExitCode = 30
        throw $script:FailMarker
    }
}

# ---------------------------------------------------------------------------------------------------------------
# Distro operations
# ---------------------------------------------------------------------------------------------------------------
# Test-DistroDirNames <names>: true if a distro directory holds nothing but the files WSL owns ($WslOwnedFiles), or
# nothing at all. `wsl --unregister` removes the disk image and leaves, or WSL recreates, the rest, so any other file
# would still be there when the new image is imported into the same directory, and the import would be refused (exit
# 19) after the old distro is already gone. -Upgrade therefore checks this up front, and Import-Distro uses the same rule.
function Test-DistroDirNames {
    param([string[]]$Names)
    foreach ($n in @($Names)) {
        if ($n -and ($WslOwnedFiles -notcontains $n.ToLowerInvariant())) { return $false }
    }
    return $true
}

# The names in a directory that are not WSL's own.
function Get-ForeignNames {
    param([string[]]$Names)
    return @(@($Names) | Where-Object { $_ -and ($WslOwnedFiles -notcontains $_.ToLowerInvariant()) })
}

# Fails with 19, before anything is unregistered, if the distro's directory holds anything but WSL's own files.
function Assert-UpgradeDirClean {
    param([string]$Dir)
    if (-not (Test-Path -LiteralPath $Dir)) { return }
    $names = @(Get-ChildItem -LiteralPath $Dir -Force -ErrorAction SilentlyContinue | ForEach-Object { $_.Name })
    if (-not (Test-DistroDirNames $names)) {
        $extra = Get-ForeignNames $names
        Fail 19 ("The directory of the old distro holds files that WSL does not own: {0}" -f $Dir) @(
            ("Found: {0}   (WSL's own files are: {1})" -f ($extra -join ', '), ($WslOwnedFiles -join ', ')),
            'After the old distro is unregistered the new image could not be imported into it. Move or delete those files, then run the upgrade again.',
            'The old distro was NOT touched.')
    }
    Write-Log ("Distro directory {0} holds only files WSL owns ({1}): OK" -f $Dir, ($WslOwnedFiles -join ', ')) 'OK'
}

function Import-Distro {
    param([string]$TarPath, [string]$Dir)
    if (Test-Path -LiteralPath $Dir) {
        $names = @(Get-ChildItem -LiteralPath $Dir -Force -ErrorAction SilentlyContinue | ForEach-Object { $_.Name })
        if (-not (Test-DistroDirNames $names)) {
            Fail 19 ("The install directory is not empty: {0}" -f $Dir) @(
                ("Found: {0}   (WSL's own files, which are fine, are: {1})" -f ((Get-ForeignNames $names) -join ', '), ($WslOwnedFiles -join ', ')),
                'Choose an empty directory with -InstallDir. This installer does not delete files it did not create.')
        }
    }
    New-Item -ItemType Directory -Force -Path $Dir | Out-Null
    Write-Log ("Importing {0} into {1} (this can take a few minutes)..." -f $DistroName, $Dir)
    $r = Invoke-Wsl @('--import', $DistroName, $Dir, $TarPath, '--version', '2')
    if ($r.ExitCode -ne 0) {
        Fail 20 ("wsl --import failed (exit {0})." -f $r.ExitCode) @($r.Output)
    }
}

# ---------------------------------------------------------------------------------------------------------------
# The boot status: p2pc-boot is the distro's [boot] command, which WSL runs asynchronously, and it now runs
# `nvidia-smi -L` (up to about 10 s) at every start. So /var/lib/p2pc/boot-status.json can appear a few seconds AFTER the
# distro is up, and an older file (from the previous start) can still be there. "Fresh" means: written in THIS start of
# the distro, decided by identity, never by time: p2pc-boot records "init_starttime", the raw start ticks of the
# distro's init (field 22 of /proc/1/stat), and the status is fresh when it EQUALS that field read now. Every start of
# the distro has its own init; a time comparison had 1-2 s of slack and broke when the clock stepped after the host
# slept (T14a2 review). deploy/wsl/boot-status.sh is the same rule in bash.
# ---------------------------------------------------------------------------------------------------------------
$BootStatusWaitSeconds = 30

# Get-ProcStarttime <text of /proc/PID/stat>: field 22 (starttime, raw clock ticks) as a string of digits, or $null.
function Get-ProcStarttime {
    param([string]$ProcStat)
    if (-not $ProcStat) { return $null }
    $close = $ProcStat.LastIndexOf(')')   # the command name sits in parentheses and may hold spaces
    if ($close -lt 0 -or $close + 2 -ge $ProcStat.Length) { return $null }
    $fields = @($ProcStat.Substring($close + 2).Trim() -split '\s+')
    if ($fields.Count -lt 20 -or $fields[19] -notmatch '^[0-9]+$') { return $null }   # fields[19] = field 22
    return [string]$fields[19]
}

# Get-BootStatusFields <json text>: InitStarttime (digits or $null), Time (epoch seconds or $null; shown, never compared),
# Cdi, Errors (array of strings), Notes (array). The
# file is one line written by p2pc-boot; it is read with regular expressions, not ConvertFrom-Json, which turns the ISO
# time into a DateTime in PowerShell 7 and keeps a string in 5.1.
function Get-BootStatusFields {
    param([string]$Json)
    $time = $null
    $tm = [regex]::Match($Json, '"time":"([0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z)"')
    if ($tm.Success) {
        $dt = [DateTimeOffset]::MinValue
        if ([DateTimeOffset]::TryParseExact($tm.Groups[1].Value, 'yyyy-MM-ddTHH:mm:ssZ', [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AssumeUniversal, [ref]$dt)) {
            $time = $dt.ToUnixTimeSeconds()
        }
    }
    $init = $null
    $im = [regex]::Match($Json, '"init_starttime":([0-9]+)[,}]')
    if ($im.Success) { $init = $im.Groups[1].Value }
    $cdi = ''
    $cm = [regex]::Match($Json, '"cdi":"([^"]*)"')
    if ($cm.Success) { $cdi = $cm.Groups[1].Value }
    $lists = @{}
    foreach ($key in @('errors', 'notes')) {
        $items = @()
        $lm = [regex]::Match($Json, ('"' + $key + '":\[((?:[^\]"]|"(?:[^"\\]|\\.)*")*)\]'))
        if ($lm.Success) {
            foreach ($im in [regex]::Matches($lm.Groups[1].Value, '"((?:[^"\\]|\\.)*)"')) { $items += ($im.Groups[1].Value -replace '\\(.)', '$1') }
        }
        $lists[$key] = $items
    }
    return New-Object psobject -Property @{ InitStarttime = $init; Time = $time; Cdi = $cdi; Errors = @($lists['errors']); Notes = @($lists['notes']) }
}

# Test-BootStatusFresh <fields> <starttime of the distro's init now>: the status records exactly this init.
function Test-BootStatusFresh {
    param($Fields, $InitStarttime)
    if ($null -eq $Fields -or $null -eq $Fields.InitStarttime -or $null -eq $InitStarttime) { return $false }
    return ([string]$Fields.InitStarttime -ceq [string]$InitStarttime)
}

# Wait-BootStatus: polls once a second, up to $BootStatusWaitSeconds, for the boot-status.json of this start of the
# distro. Returns the parsed fields, or $null when none appeared (never throws: it is a warning, not an error).
function Wait-BootStatus {
    param([int]$Seconds = $BootStatusWaitSeconds)
    $init = $null
    for ($i = 0; $i -le $Seconds; $i++) {
        if ($null -eq $init) {
            $p1 = Invoke-InDistro @('/bin/cat', '/proc/1/stat')
            if ($p1.ExitCode -eq 0) { $init = Get-ProcStarttime $p1.Output }
        }
        if ($null -ne $init) {
            $r = Invoke-InDistro @('/bin/cat', '/var/lib/p2pc/boot-status.json')
            if ($r.ExitCode -eq 0) {
                $f = Get-BootStatusFields $r.Output
                if (Test-BootStatusFresh $f $init) { return $f }
            }
        }
        if ($i -lt $Seconds) { Start-Sleep -Seconds 1 }
    }
    return $null
}

# Show-BootStatus: prints the CDI state at the end of an install or upgrade. A status that does not appear is a warning.
function Show-BootStatus {
    $f = Wait-BootStatus
    if ($null -eq $f) {
        Write-Log ("p2pc-boot has not written a fresh /var/lib/p2pc/boot-status.json within {0} s of this start of the distro (it can take longer when nvidia-smi is slow). The GPU state is unknown yet; check it with: wsl -d {1} -u root --exec /bin/cat /var/lib/p2pc/boot-status.json" -f $BootStatusWaitSeconds, $DistroName) 'WARN'
        return
    }
    if ($f.Cdi -eq 'nvidia_smi_failed' -or $f.Errors.Count -gt 0) {
        Write-Log ("p2pc-boot: cdi={0}; errors: {1}" -f $f.Cdi, ($f.Errors -join '; ')) 'WARN'
    } else {
        Write-Log ("p2pc-boot: cdi={0}, no errors." -f $f.Cdi) 'OK'
    }
    foreach ($note in $f.Notes) { Write-Log ("p2pc-boot note: {0}" -f $note) 'INFO' }
}

# Checks the freshly imported distro; returns the image version line.
function Test-NewDistro {
    $problems = @()
    $ver = Invoke-InDistro @('/bin/cat', '/etc/p2pc-distro-version')
    if ($ver.ExitCode -ne 0) { $problems += '/etc/p2pc-distro-version is missing' }
    $mode = Invoke-InDistro @('/usr/bin/stat', '-c', '%a', '/var/lib/p2pc')
    if ($mode.ExitCode -ne 0 -or $mode.Output.Trim() -ne '700') { $problems += ('/var/lib/p2pc mode is not 700 (got: ' + $mode.Output.Trim() + ')') }
    $c = Invoke-InDistro @('/usr/bin/test', '!', '-e', '/mnt/c')
    if ($c.ExitCode -ne 0) { $problems += '/mnt/c exists inside the distro (automount is not off)' }
    $boot = Invoke-InDistro @('/usr/bin/test', '-x', '/usr/local/sbin/p2pc-boot')
    if ($boot.ExitCode -ne 0) { $problems += '/usr/local/sbin/p2pc-boot is missing' }
    if ($problems.Count -gt 0) {
        Fail 21 'The new distro did not pass verification.' $problems
    }
    $first = ($ver.Output -split "`r?`n") | Where-Object { $_ -like 'image_version=*' } | Select-Object -First 1
    Write-Log ("Distro verified ({0})" -f $first) 'OK'
    return $first
}

# Parses the answer of the state probe (see $StateProbeScript). Returns 'present', 'absent', 'hub-only' or 'unknown'.
# 'absent' is a POSITIVE answer: the command exited 0 and printed exactly one marker line, and it was the absent one.
# A transient error (the distro would not start, wsl.exe hiccuped, empty or garbled output) is 'unknown', which must
# never be treated as "there is no agent identity to save". 'hub-only': /var/lib/p2pc-server exists without /var/lib/p2pc.
function Get-StateProbe {
    param([int]$ExitCode, [string]$Output)
    if ($ExitCode -ne 0) { return 'unknown' }
    $markers = @()
    foreach ($line in ($Output -split "`r?`n")) {
        $t = $line.Trim()
        if ($t -match '^P2PC_STATE=') { $markers += $t }
    }
    if ($markers.Count -ne 1) { return 'unknown' }
    if ($markers[0] -ceq 'P2PC_STATE=present') { return 'present' }
    if ($markers[0] -ceq 'P2PC_STATE=absent') { return 'absent' }
    if ($markers[0] -ceq 'P2PC_STATE=hub-only') { return 'hub-only' }
    return 'unknown'
}

# Get-ConfigMigrationResult: the answer of $ConfigMigrationScript: 'present', 'moved' or 'created', or $null when the
# script failed or answered anything else.
function Get-ConfigMigrationResult {
    param([int]$ExitCode, [string]$Output)
    if ($ExitCode -ne 0) { return $null }
    $markers = @($Output -split "`r?`n" | ForEach-Object { $_.Trim() } | Where-Object { $_ -match '^P2PC_CONFIG=' })
    if ($markers.Count -ne 1) { return $null }
    switch -CaseSensitive ($markers[0]) {
        'P2PC_CONFIG=present' { return 'present' }
        'P2PC_CONFIG=moved' { return 'moved' }
        'P2PC_CONFIG=created' { return 'created' }
    }
    return $null
}

# What the state listing ignores: p2pc-boot rewrites p2pc/boot-status.json and uses p2pc/tmp/ at every distro start,
# and sockets and FIFOs (type s and p) are not archived, so they must not be compared either (see $StateArchiveScript).
# Paths are relative to /var/lib; nothing of p2pc-server is ignored but its sockets and FIFOs.
function Test-StateListingIgnored {
    param([string]$Line)
    if ($Line -match '^[0-9]+:[0-9]+:[0-9]+:[sp]:') { return $true }
    return ($Line -match ':p2pc/(tmp|tmp/.*|boot-status\.json|\.boot-status\..*)$')
}

# Where the upgrade keeps the export of /var/lib/p2pc.
function Get-BackupDir {
    return (Join-Path $env:LOCALAPPDATA 'P2PC\backups')
}

# Which backups to delete: of the COMPLETED ones (p2pc-state-<14 digits>.ok.tar, renamed only after a verified upgrade)
# all but the newest $Keep. Anything else, in particular p2pc-state-<time>.tar, the backup of an upgrade that failed or
# is still running, is never listed: it is the only copy of the agent identity.
function Get-BackupsToPrune {
    param([string[]]$Names, [int]$Keep = 3)
    $done = @(@($Names) | Where-Object { $_ -match '^p2pc-state-[0-9]{14}\.ok\.tar$' } | Sort-Object -Descending)
    if ($done.Count -le $Keep) { return @() }
    return @($done | Select-Object -Skip $Keep)
}

# One line per entry: mode:uid:gid:type:path, sorted, so before/after can be compared exactly. It lists what the upgrade
# carries: /var/lib/p2pc and, when it exists, /var/lib/p2pc-server (every other entry of /var/lib is pruned, as in
# $StateArchiveScript), with paths relative to /var/lib (p2pc, p2pc/agent.toml, p2pc-server/...).
function Get-StateListing {
    # Sockets and FIFOs are not archived (see $StateArchiveScript), so they are not listed.
    $r = Invoke-InDistro @('/usr/bin/find', '/var/lib', '-mindepth', '1', '!', '-path', '/var/lib/p2pc', '!', '-path', '/var/lib/p2pc/*', '!', '-path', '/var/lib/p2pc-server', '!', '-path', '/var/lib/p2pc-server/*', '-prune', '-o', '!', '-type', 's', '!', '-type', 'p', '-printf', '%m:%U:%G:%y:%P\n')
    if ($r.ExitCode -ne 0) { return $null }
    # p2pc-boot rewrites boot-status.json and uses tmp/ every time the distro starts (including the start that runs
    # the verification), so those are not part of the identity and are left out of the before/after comparison.
    $lines = @($r.Output -split "`r?`n" | Where-Object { $_ -and -not (Test-StateListingIgnored $_) })
    return @($lines | Sort-Object -CaseSensitive)
}

function Get-DistroFileHash {
    param([string]$LinuxPath)
    $r = Invoke-InDistro @('/usr/bin/sha256sum', $LinuxPath)
    $m = [regex]::Match($r.Output, '^([0-9a-f]{64})')
    if ($r.ExitCode -ne 0 -or -not $m.Success) { return $null }
    return $m.Groups[1].Value
}

# ---------------------------------------------------------------------------------------------------------------
# Actions
# ---------------------------------------------------------------------------------------------------------------
function Invoke-Install {
    param([string]$Dir)
    Test-Prerequisites $Dir
    if (Test-DistroExists) {
        Fail 16 ("A distro named {0} already exists." -f $DistroName) @(
            'To replace it with a newer image and keep the agent identity:   .\install.ps1 -Upgrade -Tar <new image>',
            'To remove it:   .\install.ps1 -Uninstall')
    }
    if ($CheckOnly -and -not $Tar) { return }
    $tarPath = Test-Image
    if ($CheckOnly) { return }
    Import-Distro $tarPath $Dir
    $null = Test-NewDistro
    Write-Log ("Installed {0} in {1}." -f $DistroName, $Dir) 'OK'
    Show-BootStatus
    Write-Host ''
    Write-Host 'Next, check the node profile end to end (the image ships the test):'
    Write-Host ("  wsl -d {0} -u root --exec /usr/local/sbin/p2pc-test-distro" -f $DistroName)
    Write-Host 'Then join it to your server (paste the token from `p2pc join-token create` when asked):'
    Write-Host '  .\install.ps1 -Join'
}

function Invoke-UpgradeAction {
    param([string]$DefaultDir)
    Test-Wsl
    if (-not (Test-DistroExists)) {
        Fail 22 ("{0} is not installed, so there is nothing to upgrade." -f $DistroName) @('Install it with:   .\install.ps1 -Tar <image>')
    }
    $dir = Get-DistroBasePath
    if (-not $dir) { $dir = $DefaultDir }
    Test-Prerequisites $dir
    Assert-UpgradeDirClean $dir
    if ($CheckOnly -and -not $Tar) { return }
    $tarPath = Test-Image
    if ($CheckOnly) { return }

    Confirm-Action ("This stops {0} (running jobs are lost and retried elsewhere), replaces its filesystem with the new image and restores /var/lib/p2pc (the agent identity) and, on the hub PC, /var/lib/p2pc-server (the hub's data)." -f $DistroName)

    # The Scheduled Task is disabled and stopped for the upgrade (so its 5-minute trigger cannot start the old or the
    # half-imported distro meanwhile), and enabled and started again when the node is back with its identity, or when
    # the old distro was never touched.
    # A node the user stopped with -Stop (the task disabled) stays stopped: the upgrade never turns it back on (review P3-3).
    # A node the wrapper disabled after a terminal stop comes back only when the reason was 6 (too old), which a newer
    # image is meant to fix; after 7, 8 or an unknown code it stays off until -Join -Force with a new token (spec 9.0),
    # even when its task is still Ready because the disable failed.
    $taskRegistered = Test-NodeTaskRegistered
    $taskWasEnabled = $false
    $stop = Read-NodeStopRecord
    if ($taskRegistered) {
        if ($null -eq $stop) {
            $taskWasEnabled = ((Get-NodeTaskState) -ne 'Disabled')
        } else {
            # A stop record decides, whatever the task's state: when the wrapper's disable failed (disabled=no) the task is
            # still Ready, and treating it as enabled would resume it and dial the server once more with a revoked identity.
            # Only 6 (too old) is fixed by a newer image; 7, 8 and an unknown code stay stopped.
            $taskWasEnabled = ($stop.Code -eq 6)
        }
        Suspend-NodeTask
    }
    $script:UpgradeTouched = $false
    $script:UpgradeDone = $false
    $script:UpgradeWasEnrolled = $false
    $startedAt = $null
    try {
        Invoke-UpgradeSteps -TarPath $tarPath -Dir $dir
    } finally {
        if ($taskRegistered) {
            # Registered again, so that a task from an older install.ps1 gets this one's action (the wrapper) and rights
            # (T14b2 real run 4, W1c: an upgraded node kept round 1's action, and a terminal exit never disabled it). It is
            # registered DISABLED (a new registration is enabled, and its triggers could start the node at once); what
            # follows enables it again or leaves it off, as before the upgrade. A failure only warns: the old task stays.
            $null = Register-NodeTask -Disabled -WarnOnFailure
        }
        if ($taskRegistered -and -not $taskWasEnabled -and $null -ne $stop) {
            Disable-NodeTask   # again: it must stay off even if Windows ignored the disabled setting
            Write-Log ("The node had stopped for good ({0}): it stays stopped. {1}" -f (Format-NodeStop $stop), (Get-NodeStopAdvice $stop.Code)) 'WARN'
        } elseif ($taskRegistered -and -not $taskWasEnabled) {
            Disable-NodeTask
            Write-Log ("The Scheduled Task '{0}' was disabled before the upgrade (.\install.ps1 -Stop), so the node stays stopped. Start it with:   .\install.ps1 -Start" -f $TaskName) 'WARN'
        } elseif ($taskRegistered) {
            if ($script:UpgradeDone -and $null -ne $stop) {
                # Stopped as too old (6): the newer image is the fix, so the record goes.
                Clear-NodeStop
            }
            if ($script:UpgradeDone -or -not $script:UpgradeTouched) {
                $startedAt = Get-DistroNow
                if (-not (Resume-NodeTask)) { $startedAt = $null }
            } else {
                Disable-NodeTask
                Write-Log ("The Scheduled Task '{0}' stays stopped and disabled: the new distro does not hold the agent identity yet. Once the node is back, start it with:   .\install.ps1 -Start" -f $TaskName) 'WARN'
            }
        }
    }
    # After a finished upgrade the node must come back: only a connection made since the task was started counts. An
    # agent that stopped for good on "not joined" (8) or "removed" (7) is a failed upgrade, never a warning.
    if ($script:UpgradeDone -and $null -ne $startedAt) {
        $text = Wait-NodeConnected -NotBefore $startedAt -FailIfTaskStopped $false
        if (-not (Test-ConnectedSince (Get-StatusField $text 'Connection') $startedAt)) {
            $code = Get-NodeRunStop
            if ($code -eq 8) {
                Fail 38 ('After the upgrade the agent stopped with exit 8: it finds no enrollment in {0}.' -f $AgentConfigPath) @(
                    'Enroll it again with a new token from p2pc join-token create:   .\install.ps1 -Join -Force')
            }
            if ($code -eq 7) {
                Fail 38 'After the upgrade the agent stopped with exit 7: the server says this node is not enrolled (it was removed).' @(
                    'Enroll it again with a new token from p2pc join-token create:   .\install.ps1 -Join -Force')
            }
        }
    }
}

# The steps of -Upgrade after the confirmation (Invoke-UpgradeAction stops and starts the task around them).
function Invoke-UpgradeSteps {
    param([string]$TarPath, [string]$Dir)
    $tarPath = $TarPath
    $dir = $Dir

    # 1. Archive /var/lib/p2pc (and /var/lib/p2pc-server, the hub's data, when it exists) INSIDE the distro, hash it
    #    there, copy it out byte-exact (see the BINARY DATA RULE).
    $null = Invoke-Wsl @('--terminate', $DistroName)
    $inDistroTar = '/tmp/p2pc-state.tar'
    $backupDir = Get-BackupDir
    $stamp = Get-Date -Format 'yyyyMMddHHmmss'
    $stateFile = Join-Path $backupDir ('p2pc-state-{0}.tar' -f $stamp)
    $inDistroBackup = ('/var/tmp/p2pc-state-{0}.tar' -f $stamp)
    # Only a POSITIVE "absent" lets the upgrade go on without the state. Anything else (the distro would not start,
    # wsl.exe failed, garbled output) stops here, before anything is unregistered.
    $probe = Invoke-InDistro @('/bin/sh', '-c', $StateProbeScript)
    $probeResult = Get-StateProbe -ExitCode $probe.ExitCode -Output $probe.Output
    if ($probeResult -eq 'unknown') {
        Fail 23 'Could not tell whether /var/lib/p2pc exists in the old distro (the probe failed or answered nothing sensible). The old distro was NOT touched.' @(
            ("probe exit code {0}, output: {1}" -f $probe.ExitCode, $probe.Output), 'Check that the distro starts (wsl -d p2pc-node -u root --exec /bin/true), then run the upgrade again.')
    }
    if ($probeResult -eq 'hub-only') {
        # The hub's data is the whole cloud (its database, keys and blobs): never dropped, not even with -Force.
        Fail 23 '/var/lib/p2pc-server (the hub data: the database, keys and blobs of your cloud) exists, but /var/lib/p2pc (the agent state) does not. This installer carries them only together. The old distro was NOT touched.' @(
            'Back up /var/lib/p2pc-server by hand before you replace this distro (see deploy/README.md, "Recovering from a failed upgrade").')
    }
    $hasState = ($probeResult -eq 'present')
    $before = $null
    $hashOutside = $null
    if (-not $hasState) {
        # An older or hand-made image: there is no identity to carry over. Losing it is a decision, so it needs -Force.
        if (-not $Force) {
            Fail 23 '/var/lib/p2pc does not exist in the old distro, so there is no agent identity to carry over. The old distro was NOT touched.' @(
                'If that is expected (an older or hand-made image), run the upgrade again with -Force: the node will then have to re-enrol.')
        }
        Write-Log '/var/lib/p2pc does not exist in the old distro (confirmed by the probe) and -Force was given: continuing without restoring anything. The node will have to re-enrol after the upgrade.' 'WARN'
    } else {
        # The agent's config (and [server], the enrollment) into /var/lib/p2pc first, so that the archive carries it.
        $mig = Invoke-InDistro @('/bin/sh', '-c', $ConfigMigrationScript)
        $migResult = Get-ConfigMigrationResult -ExitCode $mig.ExitCode -Output $mig.Output
        if ($null -eq $migResult) {
            Fail 23 'Could not put the agent config into /var/lib/p2pc in the old distro. Nothing was archived and the old distro was not unregistered.' @(("exit code {0}, output: {1}" -f $mig.ExitCode, $mig.Output))
        }
        if ($migResult -eq 'moved') { Write-Log ('Copied /etc/p2pc/agent.toml (the enrollment of an image up to 0.2.1) to {0}, so the upgrade carries it.' -f $AgentConfigPath) 'OK' }
        $script:UpgradeWasEnrolled = (Test-ServerSection)
        $before = Get-StateListing
        if ($null -eq $before) { Fail 23 'Could not list /var/lib/p2pc and /var/lib/p2pc-server in the old distro.' }
        New-Item -ItemType Directory -Force -Path $backupDir | Out-Null
        try {
            # The archive (mode 0600, umask 077) is made and hashed inside the distro; nothing binary reaches PowerShell.
            $a = Invoke-InDistro @('/bin/bash', '-c', (Get-StateArchiveScript $inDistroBackup))
            $m = [regex]::Match($a.Output, '(?m)^([0-9a-f]{64})  ' + [regex]::Escape($inDistroBackup) + '\s*$')
            if ($a.ExitCode -ne 0 -or -not $m.Success) {
                Fail 23 'Could not archive /var/lib/p2pc and /var/lib/p2pc-server inside the old distro. The old distro was NOT touched.' @($a.Output)
            }
            $hashInside = $m.Groups[1].Value
            $x = Invoke-WslCopyOut -LinuxPath $inDistroBackup -WinPath $stateFile
            if ($x.ExitCode -ne 0 -or -not (Test-Path -LiteralPath $stateFile -PathType Leaf)) {
                Remove-Item -LiteralPath $stateFile -Force -ErrorAction SilentlyContinue
                Fail 23 'Could not copy the state archive out of the old distro. The old distro was NOT touched.' @($x.Stderr)
            }
            $hashOutside = (Get-FileHash -LiteralPath $stateFile -Algorithm SHA256).Hash.ToLowerInvariant()
            if ($hashOutside -ne $hashInside) {
                Remove-Item -LiteralPath $stateFile -Force -ErrorAction SilentlyContinue
                Fail 23 'The state archive changed on its way out of the old distro (copy error). The old distro was NOT touched.' @(
                    ("SHA-256 inside the distro: {0}" -f $hashInside), ("SHA-256 of the copy:         {0}" -f $hashOutside))
            }
        } finally {
            # On every path: the archive holds the identity key and must not stay in the old distro's /var/tmp.
            $null = Invoke-InDistro @('/bin/rm', '-f', $inDistroBackup)
        }
        Write-Log ("Exported /var/lib/p2pc and /var/lib/p2pc-server (when this PC hosts the hub) to {0}, SHA-256 {1} (this file holds the agent's identity key, and on the hub PC the cloud's database and keys: it is kept until the upgrade is verified, and the newest {2} verified backups are kept after that)" -f $stateFile, $hashOutside, $BackupKeep) 'OK'
        # From here on the file is the only copy of the identity once the old distro is gone: Main prints its path if the run does not end well.
        $script:StateBackup = $stateFile
    }

    # 2. Unregister the old distro and import the new one.
    $script:UpgradeTouched = $true
    $u = Invoke-Wsl @('--unregister', $DistroName)
    if ($u.ExitCode -ne 0) { Fail 24 'wsl --unregister failed; the old distro may still be there.' @($u.Output, ("State file kept: {0}" -f $stateFile)) }
    try {
        Import-Distro $tarPath $dir
    } catch {
        if ($_.Exception.Message -eq $script:FailMarker -and $hasState) {
            Write-Log ("The new image could not be imported. The agent state is safe in: {0}" -f $stateFile) 'ERROR'
            Write-Log '  Fix the problem, then run:   .\install.ps1 -Tar <image>     and restore the state by hand (see deploy/README.md, "Recovering from a failed upgrade").' 'ERROR'
        }
        throw
    }

    # A new image: whether it keeps the config in /var/lib/p2pc is asked again.
    $script:NewConfigLayout = $null

    # 3. Restore /var/lib/p2pc (and /var/lib/p2pc-server) with the same modes and owners: stream the file into the new
    #    distro, check its hash there, then extract it.
    if ($hasState) {
        try {
            # Create the file first, mode 0600 (it is the agent identity), then stream into it: dd truncates and keeps the mode.
            $mk = Invoke-InDistro @('/usr/bin/install', '-m', '0600', '/dev/null', $inDistroTar)
            if ($mk.ExitCode -ne 0) { Fail 25 'Could not create the state file in the new distro.' @($mk.Output, ("State file kept: {0}" -f $stateFile)) }
            $x = Invoke-WslStream -Arguments ("-d {0} -u root --exec /bin/dd of={1} bs=1M status=none" -f $DistroName, $inDistroTar) -InFile $stateFile
            if ($x.ExitCode -ne 0) { Fail 25 'Could not copy the state file into the new distro.' @($x.Stderr, ("State file kept: {0}" -f $stateFile)) }
            $hashBack = Get-DistroFileHash $inDistroTar
            if ($hashBack -ne $hashOutside) { Fail 25 'The state file was corrupted on its way into the new distro.' @(("State file kept: {0}" -f $stateFile)) }
            $r = Invoke-InDistro @('/bin/tar', '--numeric-owner', '-C', '/var/lib', '-xpf', $inDistroTar)
            if ($r.ExitCode -ne 0) { Fail 25 'Could not restore /var/lib/p2pc and /var/lib/p2pc-server.' @($r.Output, ("State file kept: {0}" -f $stateFile)) }
        } finally {
            # On every path (success, any Fail, any exception): the copy of the identity must not stay in the new distro's /tmp.
            $null = Invoke-InDistro @('/bin/rm', '-f', $inDistroTar)
        }
    }
    # Restart the distro so that p2pc-boot runs again and rewrites boot-status.json with fresh information.
    $null = Invoke-Wsl @('--terminate', $DistroName)

    # 4. Verify; only then delete the temporary file.
    try {
        $null = Test-NewDistro
    } catch {
        Write-Log ("The new distro failed verification. The agent state is safe in: {0}" -f $stateFile) 'ERROR'
        throw
    }
    if (-not $hasState) {
        Write-Log 'Upgrade complete. There was no agent state to restore; the node has to enrol again (.\install.ps1 -Join).' 'OK'
        $script:UpgradeDone = $true
        Show-BootStatus
        return
    }
    $after = Get-StateListing
    if ($null -eq $after -or (($before -join "`n") -ne ($after -join "`n"))) {
        Fail 26 '/var/lib/p2pc or /var/lib/p2pc-server after the restore differs from before (names, modes or owners).' @(("State file kept: {0}" -f $stateFile))
    }
    # The enrollment must have come along: a node that was joined must still hold [server] where the new agent reads it.
    if ($script:UpgradeWasEnrolled -and -not (Test-ServerSection)) {
        Fail 38 ('The node was enrolled, but after the upgrade {0} holds no [server]: the agent would stop with exit 8.' -f $AgentConfigPath) @(
            ("State file kept: {0}" -f $stateFile), 'Enroll it again with a new token from p2pc join-token create:   .\install.ps1 -Join -Force')
    }
    # Verified: mark the backup as completed (the only kind that is ever pruned) and keep the newest $BackupKeep of them.
    $doneFile = $stateFile -replace '\.tar$', '.ok.tar'
    Move-Item -LiteralPath $stateFile -Destination $doneFile -Force
    $script:StateBackup = $null
    $names = @(Get-ChildItem -LiteralPath $backupDir -Filter 'p2pc-state-*.ok.tar' -File -ErrorAction SilentlyContinue | ForEach-Object { $_.Name })
    foreach ($old in @(Get-BackupsToPrune -Names $names -Keep $BackupKeep)) {
        Remove-Item -LiteralPath (Join-Path $backupDir $old) -Force -ErrorAction SilentlyContinue
        Write-Log ("Removed the old state backup {0} (only the newest {1} are kept)." -f $old, $BackupKeep) 'DEBUG'
    }
    Write-Log ("Upgrade complete; /var/lib/p2pc (and /var/lib/p2pc-server, if any) restored identically ({0} entries). Backup of the state (holds the identity key, and the hub's data on the hub PC): {1}" -f $after.Count, $doneFile) 'OK'
    $script:UpgradeDone = $true
    Show-BootStatus
}

# Test-StateBackupName <file name>: a state backup made by -Upgrade: p2pc-state-<14 digits>.tar (in progress or from an
# upgrade that failed) or p2pc-state-<14 digits>.ok.tar (a verified one). Nothing else in the folder is ever touched.
function Test-StateBackupName {
    param([string]$Name)
    return ($Name -match '^p2pc-state-[0-9]{14}(\.ok)?\.tar$')
}

# Test-StateBackupVerified <file name>: the backup of an upgrade that finished and was verified (.ok.tar).
function Test-StateBackupVerified {
    param([string]$Name)
    return ($Name -match '^p2pc-state-[0-9]{14}\.ok\.tar$')
}

# The state backups in a directory (full paths; empty when there is none). -Kind: All, Verified (.ok.tar) or Unfinished
# (p2pc-state-<time>.tar: the backup of an upgrade that failed or never finished).
function Get-StateBackupFiles {
    param([string]$Dir, [ValidateSet('All', 'Verified', 'Unfinished')][string]$Kind = 'All')
    if (-not $Dir -or -not (Test-Path -LiteralPath $Dir -PathType Container)) { return @() }
    return @(Get-ChildItem -LiteralPath $Dir -File -Force -ErrorAction SilentlyContinue |
        Where-Object {
            (Test-StateBackupName $_.Name) -and
            (($Kind -eq 'All') -or (($Kind -eq 'Verified') -eq (Test-StateBackupVerified $_.Name)))
        } | ForEach-Object { $_.FullName })
}

# THE sentence about a backup that was kept: used, word for word, by the warning at the end of a failed upgrade, by the
# -Uninstall prompt and final message, and by README section 5 (tests/test-install-ps1.sh checks that they agree).
function Get-FailedBackupAdvice {
    return "It holds the agent identity key. Delete it by hand, or with '.\install.ps1 -Uninstall -DeleteFailedBackups' (which also uninstalls the node), when you no longer need it."
}

# The confirmation text of -Uninstall. It says exactly what is deleted, what is kept and where. -Mode: Default (delete
# the verified backups, keep the unfinished ones), Keep (-KeepBackups: delete nothing) or DeleteAll (-DeleteFailedBackups).
function Get-UninstallPrompt {
    param([string]$BackupDir, [string[]]$Verified = @(), [string[]]$Unfinished = @(), [ValidateSet('Default', 'Keep', 'DeleteAll')][string]$Mode = 'Default')
    $nv = @($Verified).Count
    $text = ("This permanently deletes the {0} distro, including the agent's identity and all container images in it. The node will have to be enrolled again." -f $DistroName)
    switch ($Mode) {
        'Keep' {
            $text += (" -KeepBackups: the {0} verified state backup file(s) (p2pc-state-*.ok.tar) in {1} are KEPT, and so is every unfinished backup listed below; they hold the agent identity key." -f $nv, $BackupDir)
        }
        'DeleteAll' {
            $text += (" -DeleteFailedBackups: it also deletes the {0} verified state backup file(s) (p2pc-state-*.ok.tar) and the {1} backup(s) of an unfinished upgrade (p2pc-state-*.tar) in {2}, and that folder if it is then empty." -f $nv, @($Unfinished).Count, $BackupDir)
        }
        default {
            $text += (" It also deletes the {0} verified state backup file(s) (p2pc-state-*.ok.tar, which hold the agent identity key) in {1}, and that folder if it is then empty. It never deletes the backup of an upgrade that failed (p2pc-state-*.tar); use -KeepBackups to keep the verified ones too." -f $nv, $BackupDir)
        }
    }
    if (@($Unfinished).Count -gt 0) {
        if ($Mode -eq 'DeleteAll') {
            $text += (" Deleted unfinished backup(s): {0}." -f (@($Unfinished) -join '; '))
        } else {
            $text += (" KEPT backup(s) of an upgrade that did not finish, each the only copy of that node's identity: {0}. {1}" -f (@($Unfinished) -join '; '), (Get-FailedBackupAdvice))
        }
    }
    return $text
}

# Deletes the state backups of $Dir of the given kind and then the folder if it is empty. Returns the number of files
# deleted.
function Remove-StateBackups {
    param([string]$Dir, [ValidateSet('All', 'Verified', 'Unfinished')][string]$Kind = 'Verified')
    $n = 0
    foreach ($f in @(Get-StateBackupFiles $Dir $Kind)) {
        try {
            Remove-Item -LiteralPath $f -Force -ErrorAction Stop
            $n++
        } catch {
            Write-Log ("Could not delete the state backup {0}: {1}. Delete it yourself, it holds the agent identity key." -f $f, $_.Exception.Message) 'WARN'
        }
    }
    if ((Test-Path -LiteralPath $Dir -PathType Container) -and (@(Get-ChildItem -LiteralPath $Dir -Force -ErrorAction SilentlyContinue).Count -eq 0)) {
        Remove-Item -LiteralPath $Dir -Force -ErrorAction SilentlyContinue
    }
    return $n
}

# Remove-NodeTaskFiles: the wrapper and the record of a terminal stop, which the installer owns.
function Remove-NodeTaskFiles {
    foreach ($f in @((Get-NodeTaskWrapperPath), (Get-NodeStopRecordPath))) {
        if (Test-Path -LiteralPath $f) { Remove-Item -LiteralPath $f -Force -ErrorAction SilentlyContinue }
    }
}

function Invoke-UninstallAction {
    Test-Wsl
    if (-not (Test-DistroExists)) {
        # The task of a distro that is gone would only fail every 5 minutes: it goes anyway (review P3-5).
        if (Test-NodeTaskRegistered) {
            Remove-NodeTask
            Write-Log ("{0} is not installed, but its Scheduled Task '{1}' was: removed it." -f $DistroName, $TaskName) 'WARN'
        }
        Remove-NodeTaskFiles
        Fail 27 ("{0} is not installed." -f $DistroName)
    }
    $dir = Get-DistroBasePath
    $backupDir = Get-BackupDir
    $verified = @(Get-StateBackupFiles $backupDir 'Verified')
    $unfinished = @(Get-StateBackupFiles $backupDir 'Unfinished')
    $mode = 'Default'
    if ($KeepBackups) { $mode = 'Keep' } elseif ($DeleteFailedBackups) { $mode = 'DeleteAll' }
    Confirm-Action (Get-UninstallPrompt -BackupDir $backupDir -Verified $verified -Unfinished $unfinished -Mode $mode)
    # The task first: it would otherwise start the agent of a distro that no longer exists at the next logon.
    if (Test-NodeTaskRegistered) { Remove-NodeTask }
    $r = Invoke-Wsl @('--unregister', $DistroName)
    if ($r.ExitCode -ne 0) { Fail 29 'wsl --unregister failed.' @($r.Output) }
    if ($dir -and (Test-Path -LiteralPath $dir) -and (@(Get-ChildItem -LiteralPath $dir -Force -ErrorAction SilentlyContinue).Count -eq 0)) {
        Remove-Item -LiteralPath $dir -Force -ErrorAction SilentlyContinue
    }
    Remove-NodeTaskFiles
    $done = ("Removed {0}, the Scheduled Task '{1}' and its wrapper. Other distros, .wslconfig and Windows features were not touched." -f $DistroName, $TaskName)
    if ($mode -eq 'Keep') {
        Write-Log ("{0} KEPT every state backup in {1} (-KeepBackups): {2} verified, {3} unfinished; they hold the agent identity key." -f $done, $backupDir, $verified.Count, $unfinished.Count) 'OK'
    } else {
        $kind = 'Verified'
        if ($mode -eq 'DeleteAll') { $kind = 'All' }
        $n = Remove-StateBackups $backupDir $kind
        Write-Log ("{0} Deleted {1} state backup file(s) in {2}." -f $done, $n, $backupDir) 'OK'
    }
    # Whatever is still there from a failed upgrade is the only copy of that identity: say so, with the full paths.
    $left = @(Get-StateBackupFiles $backupDir 'Unfinished')
    if ($left.Count -gt 0) {
        Write-Log ("KEPT the backup(s) of an upgrade that did not finish, each the only copy of that node's identity: {0}. {1}" -f ($left -join '; '), (Get-FailedBackupAdvice)) 'WARN'
    }
}

# ---------------------------------------------------------------------------------------------------------------
# The Scheduled Task "P2PC node" (spec 9.0, "How the Windows agent stays up")
# ---------------------------------------------------------------------------------------------------------------
# Get-NodeTaskDefinition: everything the task is, in one place (Register-NodeTask builds it from this; the tests read it).
function Get-NodeTaskDefinition {
    return New-Object psobject -Property @{
        Name = $TaskName
        # conhost --headless: no console window. The attached wsl.exe keeps the distro running for as long as the task
        # runs; nothing in .wslconfig is changed.
        Execute = ($env:SystemRoot.TrimEnd('\') + '\System32\conhost.exe')
        # The action is the user-owned wrapper (Get-NodeTaskWrapperContent), run by cmd.exe. /d skips AutoRun; /s makes
        # cmd strip exactly the outer pair of quotes, so the quoted path survives spaces and & ( ) in a user name.
        Argument = ('--headless cmd.exe /d /s /c ""{0}""' -f (Get-NodeTaskWrapperPath))
        ExecutionTimeLimit = [TimeSpan]::Zero      # no time limit
        AllowOnBattery = $true                     # start on battery, and keep running when unplugged
        RestartCount = 999                         # restarted on failure, every minute (p2pc-node-run exits 0 when
        RestartIntervalMinutes = 1                 # it stops for good, so that is not a failure)
        RunLevel = 'Limited'                       # as you, never elevated
        # The watchdog (spec 9.0): a time trigger that repeats every 5 minutes, with no end. With MultipleInstances
        # IgnoreNew it does nothing while the task runs, and it starts it again within 5 minutes when it ended (for
        # example after `wsl --terminate p2pc-node`, which ends the task with 0x0 and no restart: T14b2 real run, W5).
        # StartWhenAvailable runs a start that was missed (asleep, or signed out). It is also what starts the node after
        # sign-in when the logon trigger could not be registered.
        RepeatMinutes = 5
        MultipleInstances = 'IgnoreNew'
        StartWhenAvailable = $true
        Description = 'P2PC node: keeps the p2pc-node WSL distro and its agent running (installed by install.ps1 -Join).'
    }
}

# Get-NodeTaskTriggerKinds: the triggers the task gets (spec 9.0, corrected in d0a9ec3): the 5-minute repetition and the
# logon trigger FOR THIS USER, always, elevated or not. A Limited, medium-integrity token registers a per-user logon
# trigger fine (measured); Windows refuses only a logon trigger for any user, which P2PC never asks for.
function Get-NodeTaskTriggerKinds {
    return @('Every5Minutes', 'AtLogOn')
}

# The sentence -Join ends with when Windows refused the logon trigger and only the 5-minute trigger was registered.
function Get-TimeTriggerOnlyAdvice {
    return 'Windows refused the sign-in trigger, so only the 5-minute trigger was registered: the node starts within 5 minutes of signing in.'
}

# The task's action (spec 9.0, "Terminal exits stop the node for good, watchdog included"): a small wrapper the installer
# writes, owns and removes, next to the record of why the node stopped for good.
function Get-NodeTaskWrapperPath {
    return ($env:LOCALAPPDATA.TrimEnd('\') + '\P2PC\node-task.cmd')
}

function Get-NodeStopRecordPath {
    return ($env:LOCALAPPDATA.TrimEnd('\') + '\P2PC\stopped-by-node')
}

# Get-NodeTaskWrapperContent: the lines of node-task.cmd. It runs the node's supervisor in the distro and passes its
# exit code on. On 64 (the agent stopped for good: 6 too old, 7 removed, 8 not joined) it writes why next to itself, in
# stopped-by-node (node_exit=64, then exit_code, time and reason from node-run.status, then whether the disable worked),
# and disables the task: its 5-minute trigger must not start a node that cannot work, again and again. Then it
# terminates the distro, best effort: nothing runs in it any more, and an idle distro left Running keeps the WSL VM and
# its memory up (T14b2 real run 4, R1); the result changes neither the record nor the exit code. ASCII only.
function Get-NodeTaskWrapperContent {
    return @(
        '@echo off',
        'rem P2PC node: the action of the Scheduled Task "P2PC node". Written by install.ps1 (-Join rewrites it); do not edit.',
        'rem On exit 64 (the agent stopped for good) it disables the task and writes why in stopped-by-node, next to it.',
        'rem install.ps1 -Join, -Start (and -Upgrade after "too old") enable the task again (spec 9.0).',
        ('wsl.exe -d {0} -u root --exec {1}' -f $DistroName, $NodeRunPath),
        'set "P2PC_RC=%ERRORLEVEL%"',
        'if not "%P2PC_RC%"=="64" exit /b %P2PC_RC%',
        '> "%~dp0stopped-by-node" echo node_exit=64',
        ('>> "%~dp0stopped-by-node" wsl.exe -d {0} -u root --exec /bin/grep -E "^(exit_code|time|reason)=" {1}' -f $DistroName, $NodeRunStatusPath),
        ('schtasks /Change /TN "\{0}" /DISABLE >nul 2>&1' -f $TaskName),
        'if errorlevel 1 (>> "%~dp0stopped-by-node" echo disabled=no) else (>> "%~dp0stopped-by-node" echo disabled=yes)',
        ('>nul 2>&1 wsl.exe --terminate {0}' -f $DistroName),
        'exit /b 64'
    )
}

# Write-NodeTaskWrapper: writes node-task.cmd (ASCII, CRLF), only when its path can sit inside quotes on a cmd.exe
# command line (no % and no "). Returns its path. Throws otherwise (Register-NodeTask turns that into exit 35).
function Write-NodeTaskWrapper {
    $path = Get-NodeTaskWrapperPath
    if (-not (Test-CmdSafePath $path)) {
        throw ('The task wrapper path cannot be quoted for cmd.exe (it holds a percent sign or a double quote): {0}' -f $path)
    }
    New-Item -ItemType Directory -Force -Path (Split-Path -Parent $path) | Out-Null
    [System.IO.File]::WriteAllText($path, (((Get-NodeTaskWrapperContent) -join "`r`n") + "`r`n"), [System.Text.Encoding]::ASCII)
    return $path
}

# Read-NodeStopRecord: what the wrapper wrote when the node stopped for good: Code (6, 7, 8 or $null when unknown), Time,
# Reason, Disabled ('yes', 'no' or ''), or $null when there is no record. The wrapper reads the code from the distro,
# and that read can fail (Wsl/Service/0x8007274c under load, T14b2 real run 4): then the code, time and reason come from
# node-run.status in the distro now (Get-NodeRunStop, through the WSL retry), when it still says stopped.
function Read-NodeStopRecord {
    $path = Get-NodeStopRecordPath
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { return $null }
    $text = [System.IO.File]::ReadAllText($path)
    $field = { param($t, $k) $m = [regex]::Match($t, ('(?m)^' + $k + '=(.*?)\s*$')); if ($m.Success) { $m.Groups[1].Value } else { '' } }
    $code = $null
    $c = & $field $text 'exit_code'
    if ($c -match '^[0-9]+$') { $code = [int]$c }
    $time = & $field $text 'time'
    $reason = & $field $text 'reason'
    if ($null -eq $code) {
        $r = Invoke-InDistro @('/bin/cat', $NodeRunStatusPath)
        $code = Get-NodeRunStop -Result $r
        if ($null -ne $code) {
            if (-not $time) { $time = & $field ([string]$r.Output) 'time' }
            if (-not $reason) { $reason = & $field ([string]$r.Output) 'reason' }
        }
    }
    return New-Object psobject -Property @{ Code = $code; Time = $time; Reason = $reason; Disabled = (& $field $text 'disabled') }
}

# Format-NodeStop <record>: "exit 7 at <time>" for a message; "exit unknown" when the record and the distro have no code.
function Format-NodeStop {
    param($Stop)
    $text = 'exit unknown'
    if ($null -ne $Stop.Code) { $text = 'exit {0}' -f $Stop.Code }
    if ($Stop.Time) { $text += ' at {0}' -f $Stop.Time }
    return $text
}

# Get-NodeStopAdvice <code>: what to run after a terminal stop. An unknown code gets no guess: 7 or 8 would mean a new
# token, 6 a newer image.
function Get-NodeStopAdvice {
    param($Code)
    if ($null -eq $Code) { return 'The exit code is unknown (the record has none, and the distro did not say): see   .\install.ps1 -Status' }
    if ($Code -eq 6) { return 'The server refuses this agent version. Install a newer image:   .\install.ps1 -Upgrade -Tar <newer image>' }
    return 'Get a new token from p2pc join-token create, then re-enroll this machine:   .\install.ps1 -Join -Force'
}

# Clear-NodeStop: forget a terminal stop before the node is started again on purpose (-Join, -Start, -Upgrade after 6):
# the wrapper's record, and the runner's in the distro (which would otherwise make it exit 64 at once while nothing
# changed: see p2pc-node-run).
function Clear-NodeStop {
    $path = Get-NodeStopRecordPath
    if (Test-Path -LiteralPath $path) { Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue }
    $null = Invoke-InDistro @('/bin/rm', '-f', $NodeRunStatusPath)
}

# Get-NodeTaskSddl <user SID>: the task's security descriptor: full control for SYSTEM, Administrators and the user.
# Registered from an elevated session, a task otherwise gives the user only FR, and the user's own NON-elevated wrapper
# cannot disable it (schtasks /Change: access denied; measured in T14b2 real run 4). With this (Set-NodeTaskRights) the
# user can always disable and enable it.
function Get-NodeTaskSddl {
    param([string]$UserSid)
    return ('D:(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;{0})' -f $UserSid)
}

function Get-CurrentUserSid {
    return [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
}

function Get-CurrentUserName {
    return [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
}

function Get-NodeTask {
    return (Get-ScheduledTask -TaskName $TaskName -TaskPath '\' -ErrorAction SilentlyContinue)
}

function Test-NodeTaskRegistered {
    return [bool](Get-NodeTask)
}

# The task's State as a string (Running, Ready, Disabled, ...), or $null when it is not registered.
function Get-NodeTaskState {
    $t = Get-NodeTask
    if (-not $t) { return $null }
    return [string]$t.State
}

# Test-NodeTaskActionCurrent: $true when the registered task runs this install.ps1's action (the wrapper, Get-
# NodeTaskDefinition) and the wrapper file exists; $false otherwise (an action from an older install.ps1); $null when
# no task is registered.
function Test-NodeTaskActionCurrent {
    $t = Get-NodeTask
    if (-not $t) { return $null }
    $want = (Get-NodeTaskDefinition).Argument
    $actions = @($t.Actions)
    if ($actions.Count -ne 1 -or [string]$actions[0].Arguments -ne $want) { return $false }
    return (Test-Path -LiteralPath (Get-NodeTaskWrapperPath) -PathType Leaf)
}

function Get-NodeTaskInfoText {
    $t = Get-NodeTask
    if (-not $t) { return 'not registered (.\install.ps1 -Join registers it)' }
    $i = Get-ScheduledTaskInfo -InputObject $t -ErrorAction SilentlyContinue
    if (-not $i) { return [string]$t.State }
    return ('{0} (last run {1}, last result 0x{2:X})' -f $t.State, $i.LastRunTime, $i.LastTaskResult)
}

# Test-AccessDenied <error record>: Windows refused the operation for lack of rights (HRESULT 0x80070005, or the CIM
# provider's 0x80041003), in any display language.
function Test-AccessDenied {
    param($ErrorRecord)
    $e = $ErrorRecord.Exception
    if ($e.HResult -eq -2147024891 -or $e.HResult -eq -2147217405) { return $true }
    if ($ErrorRecord.CategoryInfo -and $ErrorRecord.CategoryInfo.Category -eq 'PermissionDenied') { return $true }
    return ($e.Message -match 'Access is denied|0x80070005|0x80041003')
}

# Register-NodeTaskWithTriggers <kinds> [-Disabled]: writes the wrapper, then creates or replaces (idempotent) the task
# with those triggers, and gives the user full control of it (Set-NodeTaskRights). -Disabled registers it disabled, so
# that no trigger can start it before the caller decides (-Upgrade). Throws when the registration fails.
function Register-NodeTaskWithTriggers {
    param([string[]]$Kinds, [switch]$Disabled)
    $null = Write-NodeTaskWrapper
    $d = Get-NodeTaskDefinition
    $user = Get-CurrentUserName
    $triggers = @()
    foreach ($k in $Kinds) {
        if ($k -eq 'AtLogOn') {
            $triggers += New-ScheduledTaskTrigger -AtLogOn -User $user
        } else {
            $t = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes $d.RepeatMinutes)
            # No RepetitionDuration: an empty duration repeats with no end.
            $t.Repetition.Duration = ''
            $triggers += $t
        }
    }
    $action = New-ScheduledTaskAction -Execute $d.Execute -Argument $d.Argument
    $principal = New-ScheduledTaskPrincipal -UserId $user -LogonType Interactive -RunLevel $d.RunLevel
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit $d.ExecutionTimeLimit -RestartCount $d.RestartCount -RestartInterval (New-TimeSpan -Minutes $d.RestartIntervalMinutes) -MultipleInstances $d.MultipleInstances -StartWhenAvailable -Disable:$Disabled
    # New-ScheduledTask returns a CIM MSFT_ScheduledTask (Actions, Principal, Settings, Triggers, Description): it has
    # no RegistrationInfo, so the security descriptor cannot ride along with it (T14b2 real run 4: every registration
    # failed). The task is registered as it is, and its rights are set afterwards.
    $task = New-ScheduledTask -Action $action -Trigger $triggers -Principal $principal -Settings $settings -Description $d.Description
    $null = Register-ScheduledTask -InputObject $task -TaskName $TaskName -TaskPath '\' -Force -ErrorAction Stop
    Set-NodeTaskRights
}

# Set-NodeTaskRights: gives the user full control of the registered task (Get-NodeTaskSddl), so that the user's own
# NON-elevated wrapper can disable it after a terminal stop. Never fails: when Windows refuses, the task stays
# registered with its default rights and the user is told what that means (p2pc-node-run's own fallback still keeps a
# stopped node from dialing the server, though the 5-minute trigger then keeps starting the distro).
function Set-NodeTaskRights {
    try {
        Set-NodeTaskSddl -Sddl (Get-NodeTaskSddl -UserSid (Get-CurrentUserSid))
    } catch {
        Write-Log ("Could not give you full control of the Scheduled Task '{0}' ({1}). It stays registered. If it was registered from an elevated PowerShell, the node may not be able to disable it after a terminal stop; it still never dials the server again until something changes." -f $TaskName, $_.Exception.Message) 'WARN'
    }
}

# Set-NodeTaskSddl <sddl>: sets the task's security descriptor through the Task Scheduler COM API (measured on
# the Windows test PC, T14b2 real run 4: a task registered elevated gives the user only FR, and its non-elevated
# /DISABLE is denied; after this call it is allowed). Flags 0. Throws on failure.
function Set-NodeTaskSddl {
    param([string]$Sddl)
    $svc = New-Object -ComObject Schedule.Service
    $svc.Connect()
    $svc.GetFolder('\').GetTask($TaskName).SetSecurityDescriptor($Sddl, 0)
}

# Register-NodeTask [-Disabled] [-WarnOnFailure]: the task with both triggers (Get-NodeTaskTriggerKinds). If Windows
# refuses that for lack of rights, it is registered again with the 5-minute trigger alone, and the user is told the node
# starts within 5 minutes of signing in. Never falls back to anything else. Returns the trigger kinds it registered.
# -Disabled registers it disabled. When even that fails: exit 35, or with -WarnOnFailure (-Upgrade, where the task
# already exists) a warning that it keeps its previous definition, and $null.
function Register-NodeTask {
    param([switch]$Disabled, [switch]$WarnOnFailure)
    $kinds = Get-NodeTaskTriggerKinds
    try {
        Register-NodeTaskWithTriggers -Kinds $kinds -Disabled:$Disabled
        Write-Log ("Scheduled Task '{0}' registered: at your sign-in and every 5 minutes (a watchdog: it does nothing while the node runs), no time limit, restart on failure, allowed on battery." -f $TaskName) 'OK'
        return $kinds
    } catch {
        if (-not (Test-AccessDenied $_)) {
            if ($WarnOnFailure) {
                Write-Log ("Could not register the Scheduled Task '{0}' again ({1}): it keeps its previous definition." -f $TaskName, $_.Exception.Message) 'WARN'
                return $null
            }
            Fail 35 ("Could not register the Scheduled Task '{0}': {1}" -f $TaskName, $_.Exception.Message)
        }
        Write-Log ("Windows refused the sign-in trigger (access denied): registering '{0}' with the 5-minute trigger only." -f $TaskName) 'WARN'
    }
    $kinds = @('Every5Minutes')
    try {
        Register-NodeTaskWithTriggers -Kinds $kinds -Disabled:$Disabled
    } catch {
        if ($WarnOnFailure) {
            Write-Log ("Could not register the Scheduled Task '{0}' again, even with a time trigger only ({1}): it keeps its previous definition." -f $TaskName, $_.Exception.Message) 'WARN'
            return $null
        }
        Fail 35 ("Could not register the Scheduled Task '{0}', even with a time trigger only: {1}" -f $TaskName, $_.Exception.Message) @(
            'Nothing falls back to another way of starting the agent. The node is enrolled, but its agent does not run until the task exists.')
    }
    Write-Log ("Scheduled Task '{0}' registered: every 5 minutes (a watchdog: it does nothing while the node runs), no time limit, restart on failure, allowed on battery." -f $TaskName) 'OK'
    Write-Log (Get-TimeTriggerOnlyAdvice) 'WARN'
    return $kinds
}

# Start-NodeTask: returns $true when the task was started (or already runs), $false (with a warning) otherwise.
function Start-NodeTask {
    try {
        Start-ScheduledTask -TaskName $TaskName -TaskPath '\' -ErrorAction Stop
        return $true
    } catch {
        Write-Log ("Could not start the Scheduled Task '{0}': {1}" -f $TaskName, $_.Exception.Message) 'WARN'
        return $false
    }
}

function Stop-NodeTask {
    try {
        Stop-ScheduledTask -TaskName $TaskName -TaskPath '\' -ErrorAction Stop
        Write-Log ("Stopped the Scheduled Task '{0}'." -f $TaskName)
    } catch {
        Write-Log ("Could not stop the Scheduled Task '{0}': {1}" -f $TaskName, $_.Exception.Message) 'WARN'
    }
}

function Disable-NodeTask {
    try {
        $null = Disable-ScheduledTask -TaskName $TaskName -TaskPath '\' -ErrorAction Stop
        Write-Log ("Disabled the Scheduled Task '{0}'." -f $TaskName)
    } catch {
        Write-Log ("Could not disable the Scheduled Task '{0}': {1}" -f $TaskName, $_.Exception.Message) 'WARN'
    }
}

# Enable-NodeTask: returns $true when the task is enabled.
function Enable-NodeTask {
    try {
        $null = Enable-ScheduledTask -TaskName $TaskName -TaskPath '\' -ErrorAction Stop
        return $true
    } catch {
        Write-Log ("Could not enable the Scheduled Task '{0}': {1}" -f $TaskName, $_.Exception.Message) 'WARN'
        return $false
    }
}

# Suspend-NodeTask: really stops the node. Disabled first, so that neither the 5-minute trigger nor a sign-in starts it
# again meanwhile; stopped; and the distro terminated, because stopping the task kills conhost but leaves its wsl.exe,
# p2pc-node-run and the agent running (T14b2 real run, W5).
function Suspend-NodeTask {
    Disable-NodeTask
    Stop-NodeTask
    $null = Invoke-Wsl @('--terminate', $DistroName)
}

# Resume-NodeTask: enabled again and started. Returns $true when it was started.
function Resume-NodeTask {
    if (-not (Enable-NodeTask)) { return $false }
    return (Start-NodeTask)
}

# Remove-NodeTask: stop, then unregister. A failure stops the run (exit 37) before the distro is touched.
function Remove-NodeTask {
    Stop-NodeTask
    try {
        Unregister-ScheduledTask -TaskName $TaskName -TaskPath '\' -Confirm:$false -ErrorAction Stop
    } catch {
        Fail 37 ("Could not remove the Scheduled Task '{0}': {1}. The distro was NOT touched." -f $TaskName, $_.Exception.Message) @(
            ("Remove it yourself (Task Scheduler, or:  Unregister-ScheduledTask -TaskName '{0}'), then run -Uninstall again." -f $TaskName))
    }
    Write-Log ("Removed the Scheduled Task '{0}'." -f $TaskName) 'OK'
}

# ---------------------------------------------------------------------------------------------------------------
# The join token: never a parameter, never logged, never in a plain variable longer than it takes to wrap it.
# ---------------------------------------------------------------------------------------------------------------
function Test-StdinRedirected {
    return [Console]::IsInputRedirected
}

# New-ReadOnlySecret <text>: a read-only SecureString built character by character. A piped token arrives as plain text
# whatever we do; it is wrapped at once, never handed to ConvertTo-SecureString, and the plain variables are dropped.
function New-ReadOnlySecret {
    param([string]$Text)
    $secret = New-Object System.Security.SecureString
    foreach ($c in $Text.ToCharArray()) { $secret.AppendChar($c) }
    $secret.MakeReadOnly()
    return $secret
}

# Read-JoinToken: the token as a read-only SecureString: the one line of the pipeline, else one line of a redirected
# stdin, else a hidden prompt.
function Read-JoinToken {
    $lines = @(@($script:PipedInput) | ForEach-Object { [string]$_ } | Where-Object { $_.Trim() })
    if ($lines.Count -gt 1) {
        Fail 2 'The pipeline gave more than one line: pipe only the join token, on one line.'
    }
    if ($lines.Count -eq 1) {
        $secret = New-ReadOnlySecret $lines[0].Trim()
        $lines = $null
        $script:PipedInput = @()
        return $secret
    }
    if (Test-StdinRedirected) {
        $line = [Console]::In.ReadLine()
        if (-not $line -or -not $line.Trim()) { Fail 2 'No join token on stdin.' }
        $secret = New-ReadOnlySecret $line.Trim()
        $line = $null
        return $secret
    }
    Write-Host 'Paste the join token from `p2pc join-token create` (the input is hidden):'
    $secret = Read-Host -Prompt 'Join token' -AsSecureString
    if (-not $secret -or $secret.Length -eq 0) { Fail 2 'No join token was given.' }
    $secret.MakeReadOnly()
    return $secret
}

# Invoke-WslWithSecret <arguments> <secret>: runs wsl.exe and writes the secret, plus a newline, to its stdin, as ASCII
# bytes taken straight from the SecureString's unmanaged copy (zeroed afterwards). The secret is never in the arguments,
# the log or a PowerShell string. Returns ExitCode and Output (stdout and stderr, text). A WSL service timeout is retried
# (Invoke-WithWslRetry) with the same SecureString: the token stays in memory only, and that wsl.exe never ran the agent.
function Invoke-WslWithSecret {
    param([string]$Arguments, [System.Security.SecureString]$Secret)
    return (Invoke-WithWslRetry { Invoke-WslWithSecretOnce -Arguments $Arguments -Secret $Secret } ('wsl ' + $Arguments + ' (the token on stdin)'))
}

function Invoke-WslWithSecretOnce {
    param([string]$Arguments, [System.Security.SecureString]$Secret)
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = 'wsl.exe'
    $psi.Arguments = $Arguments
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $psi.RedirectStandardInput = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $code = -1
    $text = ''
    $proc = $null
    $ptr = [IntPtr]::Zero
    $bytes = $null
    try {
        $proc = [System.Diagnostics.Process]::Start($psi)
        $outTask = $proc.StandardOutput.ReadToEndAsync()
        $errTask = $proc.StandardError.ReadToEndAsync()
        $ptr = [System.Runtime.InteropServices.Marshal]::SecureStringToGlobalAllocUnicode($Secret)
        $bytes = New-Object byte[] ($Secret.Length + 1)
        for ($i = 0; $i -lt $Secret.Length; $i++) {
            $c = [System.Runtime.InteropServices.Marshal]::ReadInt16($ptr, 2 * $i)
            if ($c -lt 33 -or $c -gt 126) { throw 'the join token holds a character that cannot be in a token' }
            $bytes[$i] = [byte]$c
        }
        $bytes[$Secret.Length] = 10
        $proc.StandardInput.BaseStream.Write($bytes, 0, $bytes.Length)
        $proc.StandardInput.BaseStream.Flush()
        $proc.StandardInput.Close()   # EOF: the agent reads the token to the end
        $proc.WaitForExit()
        $code = $proc.ExitCode
        $text = (($outTask.Result + "`n" + $errTask.Result) -replace "`0", '').Trim()
    } catch {
        $text = $_.Exception.Message
        if ($proc -and -not $proc.HasExited) { try { $proc.Kill() } catch { } }
    } finally {
        if ($bytes) { [Array]::Clear($bytes, 0, $bytes.Length) }
        if ($ptr -ne [IntPtr]::Zero) { [System.Runtime.InteropServices.Marshal]::ZeroFreeGlobalAllocUnicode($ptr) }
    }
    Write-Log ("wsl {0} (the token on stdin) -> exit {1}" -f $Arguments, $code) 'DEBUG'
    return New-Object psobject -Property @{ ExitCode = $code; Output = $text }
}

# Get-StatusField <status text> <label>: the value after "<label>:" in `p2pc-agent status`, or ''.
function Get-StatusField {
    param([string]$Text, [string]$Label)
    $m = [regex]::Match($Text, ('(?m)^' + [regex]::Escape($Label) + ':[ \t]*(.*?)\s*$'))
    if ($m.Success) { return $m.Groups[1].Value }
    return ''
}

# Test-NewConfigLayout: the image keeps the agent's config in /var/lib/p2pc/agent.toml (0.2.2 and newer: its
# p2pc-node-run sets P2PC_AGENT_CONFIG). Asked once per run; -Upgrade forgets the answer when it imports a new image.
function Test-NewConfigLayout {
    if ($null -eq $script:NewConfigLayout) {
        $r = Invoke-InDistro @('/bin/grep', '-q', 'P2PC_AGENT_CONFIG=', $NodeRunPath)
        $script:NewConfigLayout = ($r.ExitCode -eq 0)
    }
    return $script:NewConfigLayout
}

# Get-AgentCommand: how to run p2pc-agent in the distro: with P2PC_AGENT_CONFIG on the 0.2.2 layout (without a shell:
# /usr/bin/env sets it), plainly on an older image (whose agent reads /etc/p2pc/agent.toml).
function Get-AgentCommand {
    if (Test-NewConfigLayout) { return @('/usr/bin/env', ('P2PC_AGENT_CONFIG=' + $AgentConfigPath), $AgentPath) }
    return @($AgentPath)
}

function Get-AgentStatus {
    return (Invoke-InDistro (@(Get-AgentCommand) + @('status')))
}

# Test-ServerSection: /var/lib/p2pc/agent.toml holds the enrollment ([server]).
function Test-ServerSection {
    return ((Invoke-InDistro @('/bin/grep', '-q', '^\[server\]', $AgentConfigPath)).ExitCode -eq 0)
}

# Get-NodeRunStop [-Result <the cat of node-run.status, already read>]: the exit code p2pc-node-run stopped for good on
# (node-run.status: state=stopped, exit_code=N), or $null when it did not stop, or the distro did not answer.
function Get-NodeRunStop {
    param($Result)
    $r = $Result
    if ($null -eq $r) { $r = Invoke-InDistro @('/bin/cat', $NodeRunStatusPath) }
    if ($r.ExitCode -ne 0) { return $null }
    if ($r.Output -notmatch '(?m)^state=stopped\s*$') { return $null }
    $m = [regex]::Match($r.Output, '(?m)^exit_code=([0-9]+)\s*$')
    if (-not $m.Success) { return $null }
    return [int]$m.Groups[1].Value
}

function Show-NodeRunStatus {
    param([string]$Level = 'INFO')
    $r = Invoke-InDistro @('/bin/cat', $NodeRunStatusPath)
    if ($r.ExitCode -eq 0 -and $r.Output) {
        Write-Log ("p2pc-node-run ({0}):" -f $NodeRunStatusPath) $Level
        foreach ($l in ($r.Output -split "`r?`n")) { if ($l) { Write-Log ("  " + $l) $Level } }
    } else {
        Write-Log ("p2pc-node-run has not written {0} yet." -f $NodeRunStatusPath) $Level
    }
}

# Get-DistroNow: the distro's clock, read just before the task is started: the agent's `since` comes from that clock, and
# WSL2's can lag Windows' after the host slept (review P3-2). Windows' clock only when the distro cannot be asked.
function Get-DistroNow {
    $r = Invoke-InDistro @('/bin/date', '-u', '+%s')
    $secs = 0L
    if ($r.ExitCode -eq 0 -and [int64]::TryParse(([string]$r.Output).Trim(), [ref]$secs)) {
        return [DateTimeOffset]::FromUnixTimeSeconds($secs)
    }
    Write-Log ("Could not read the distro's clock (exit {0}); using Windows' clock." -f $r.ExitCode) 'DEBUG'
    return [DateTimeOffset]::UtcNow
}

# How far a `since` may be before NotBefore and still count: the two readings are whole seconds of the same clock, a
# little apart.
$ConnectedSinceSlackSeconds = 2

# Test-ConnectedSince <Connection field> <not before>: the agent says "connected (since T)", and, when a time is given,
# T is at most $ConnectedSinceSlackSeconds before it. The state file can still say "connected" from the agent that ran
# before: only a connection made after the task was started counts (review P3-4). NotBefore comes from the distro's
# clock (Get-DistroNow), like T.
function Test-ConnectedSince {
    param([string]$Connection, $NotBefore)
    if ($Connection -notlike 'connected*') { return $false }
    if ($null -eq $NotBefore) { return $true }
    $m = [regex]::Match($Connection, '^connected \(since ([^)]+)\)')
    if (-not $m.Success) { return $false }
    $since = [DateTimeOffset]::MinValue
    $styles = [System.Globalization.DateTimeStyles]::AssumeUniversal
    if (-not [DateTimeOffset]::TryParse($m.Groups[1].Value, [System.Globalization.CultureInfo]::InvariantCulture, $styles, [ref]$since)) { return $false }
    $nb = ([DateTimeOffset]$NotBefore).AddSeconds(-$ConnectedSinceSlackSeconds)
    return ($since -ge $nb)
}

# Get-MonotonicSeconds: seconds from a clock that only moves forward (the wall clock can jump); the tests replace it.
function Get-MonotonicSeconds {
    return ([Diagnostics.Stopwatch]::GetTimestamp() / [double][Diagnostics.Stopwatch]::Frequency)
}

# Wait-NodeConnected <not before> <fail if the task stopped>: after install.ps1 started or restarted the task, polls
# `p2pc-agent status` until a deadline of $ConnectWaitSeconds s for a connection made since $NotBefore (the task's start: the state
# file can still say "connected" from before, T14b2 real run). Not connected in time: exit 35 when the task did not stay
# running and $FailIfTaskStopped, a warning otherwise (the agent keeps trying by itself). Returns the status text.
function Wait-NodeConnected {
    param($NotBefore, [bool]$FailIfTaskStopped)
    $text = ''
    # A deadline, not a count of turns: a slow wsl.exe call (a loaded host) must not stretch "up to 60 s".
    $deadline = (Get-MonotonicSeconds) + $ConnectWaitSeconds
    while ($true) {
        $text = (Get-AgentStatus).Output
        if (Test-ConnectedSince (Get-StatusField $text 'Connection') $NotBefore) { break }
        if ((Get-MonotonicSeconds) -ge $deadline) { break }
        Start-Sleep -Seconds 2
    }
    $connection = Get-StatusField $text 'Connection'
    if (-not (Test-ConnectedSince $connection $NotBefore)) {
        $state = Get-NodeTaskState
        if ($state -ne 'Running' -and $FailIfTaskStopped) {
            Show-NodeRunStatus 'ERROR'
            Fail 35 ("The Scheduled Task '{0}' does not stay running (state: {1})." -f $TaskName, $state) @(
                ("Its log is inside the distro:   wsl -d {0} -u root --exec /usr/bin/tail -n 50 /var/log/p2pc/agent.log" -f $DistroName))
        }
        Write-Log ("The agent is not connected since the task started, after {0} s ({1}); it keeps trying by itself. Check later with:   .\install.ps1 -Status" -f $ConnectWaitSeconds, $connection) 'WARN'
    }
    Write-Log ("Connection:    {0}" -f $connection)
    return $text
}

# ---------------------------------------------------------------------------------------------------------------
# -Join, -Status, -Stop and -Start
# ---------------------------------------------------------------------------------------------------------------
function Invoke-JoinAction {
    Test-Wsl
    if (-not (Test-DistroExists)) {
        Fail 31 ("{0} is not installed." -f $DistroName) @('Install it first:   .\install.ps1 -Tar <image>')
    }
    foreach ($bin in @($AgentPath, $ShimPath)) {
        $probe = Invoke-InDistro @('/usr/bin/test', '-x', $bin)
        if ($probe.ExitCode -ne 0) {
            Fail 32 ("This {0} image has no {1}: the node could not run jobs." -f $DistroName, $bin) @(
                'Build the image with the agent and p2pc-shim from the release (build-rootfs.sh --agent-from <dist dir>), then:   .\install.ps1 -Upgrade -Tar <image>')
        }
    }
    if (-not (Test-NewConfigLayout)) {
        Fail 32 ("This {0} image keeps the agent's config in /etc/p2pc/agent.toml, which an upgrade does not carry over (images up to 0.2.1)." -f $DistroName) @(
            'Upgrade to an image of 0.2.2 or newer first (an enrolled node keeps its enrollment):   .\install.ps1 -Upgrade -Tar <image>')
    }
    # The image ships the file; it is created (empty, 0600) if someone removed it, because the agent refuses a config
    # file that is named but missing.
    $null = Invoke-InDistro @('/bin/sh', '-c', ('if [ ! -e {0} ]; then install -m 0600 -o 0 -g 0 /dev/null {0}; fi' -f $AgentConfigPath))
    $status = Get-AgentStatus
    $enrolled = ((Get-StatusField $status.Output 'Enrolled') -like 'yes*')
    $joinedNow = $false
    $stop = Read-NodeStopRecord
    if ($enrolled -and -not $Force -and $null -ne $stop -and $stop.Code -ne 6) {
        # Removed from the server (7): starting the same enrollment again would only stop again. Leave the task off.
        Fail 34 ("The node stopped for good ({0}): starting the same enrollment again would only stop again." -f (Format-NodeStop $stop)) @(Get-NodeStopAdvice $stop.Code)
    }
    if ($enrolled -and -not $Force) {
        Write-Log ("The node is already enrolled {0}. To re-enroll this machine (the same node):   .\install.ps1 -Join -Force" -f ((Get-StatusField $status.Output 'Enrolled') -replace '^yes ', '')) 'OK'
    } else {
        $secret = Read-JoinToken
        # P2PC_AGENT_SUPERVISED=1 (T10e): the Scheduled Task starts the agent, so join ends with "The installer starts the
        # agent." instead of telling the owner to run `p2pc-agent run`.
        $agentArgs = ('/usr/bin/env P2PC_AGENT_CONFIG={0} P2PC_AGENT_SUPERVISED=1 {1}' -f $AgentConfigPath, $AgentPath)
        $joinArgs = ('-d {0} -u root --exec {1} join -' -f $DistroName, $agentArgs)
        $suspended = $false
        if ($enrolled) {
            # -Force on an enrolled node: the running agent must not keep the old enrollment while the new one is made.
            if (Test-NodeTaskRegistered) {
                Suspend-NodeTask
                $suspended = $true
            } else {
                $null = Invoke-Wsl @('--terminate', $DistroName)
            }
            $joinArgs = ('-d {0} -u root --exec {1} join --force -' -f $DistroName, $agentArgs)
        }
        Write-Log 'Enrolling: the token goes to the agent on its stdin, and nowhere else.'
        try {
            $r = Invoke-WslWithSecret -Arguments $joinArgs -Secret $secret
        } finally {
            $secret.Dispose()
        }
        foreach ($l in ($r.Output -split "`r?`n")) { if ($l) { Write-Log ("  " + $l) } }
        if ($r.ExitCode -ne 0 -and $suspended) {
            # The node ran before -Join -Force stopped it: it goes back to running, on its previous enrollment.
            if (Resume-NodeTask) {
                Write-Log ("The enrollment failed: the Scheduled Task '{0}' was started again, on the previous enrollment." -f $TaskName) 'WARN'
            }
        }
        if ($r.ExitCode -ne 0 -and (Test-WslServiceTimeout $r.Output)) {
            Fail 33 ('wsl.exe kept failing with Wsl/Service/0x8007274c (a WSL service timeout), {0} retries included: the agent never got the token.' -f $WslRetryCount) @('Try again in a minute (the same token still works):   .\install.ps1 -Join')
        }
        switch ($r.ExitCode) {
            0 { Write-Log 'Enrolled.' 'OK' }
            3 { Fail 34 'The agent says this node is already enrolled.' @('To re-enroll this machine (the same node):   .\install.ps1 -Join -Force') }
            4 { Fail 33 'The server refused the token, or it is not a join token (exit 4).' @('Create a new one with   p2pc join-token create   and paste it when asked.') }
            5 { Fail 33 'The join token has expired (exit 5).' @('Create a new one with   p2pc join-token create.') }
            6 { Fail 33 'The server refuses this agent version (exit 6).' @('Upgrade the image:   .\install.ps1 -Upgrade -Tar <newer image>') }
            default { Fail 33 ("p2pc-agent join failed (exit {0}); see its message above." -f $r.ExitCode) }
        }
        $joinedNow = $true
    }
    # A task that already runs keeps its agent (IgnoreNew): its connection is current. A task this run starts (after an
    # enrollment, or one that was stopped or disabled) counts only with a connection made since that start.
    $runningBefore = ((Get-NodeTaskState) -eq 'Running')
    # Started again on purpose: a terminal stop from before is forgotten (the wrapper's record and the runner's).
    if ($null -ne $stop) { Clear-NodeStop }
    $null = Register-NodeTask
    $startedAt = Get-DistroNow
    if (-not (Start-NodeTask)) { Fail 35 ("The Scheduled Task '{0}' could not be started." -f $TaskName) }
    $notBefore = $null
    if ($joinedNow -or -not $runningBefore) { $notBefore = $startedAt }
    $text = Wait-NodeConnected -NotBefore $notBefore -FailIfTaskStopped $true
    Write-Log ("Logs:          wsl -d {0} -u root --exec /usr/bin/tail -f /var/log/p2pc/agent.log" -f $DistroName)
    $node = [regex]::Match((Get-StatusField $text 'Enrolled'), '^yes \(node ([^,)]+)').Groups[1].Value
    Write-Log ("Joined: {0} on {1}" -f $node, (Get-StatusField $text 'Server NodeId')) 'OK'
}

function Invoke-StatusAction {
    Test-Wsl
    if (-not (Test-DistroExists)) { Fail 31 ("{0} is not installed." -f $DistroName) }
    Write-Log ("Scheduled Task '{0}': {1}" -f $TaskName, (Get-NodeTaskInfoText))
    if (-not (Test-NewConfigLayout)) {
        Write-Log 'This image is older than 0.2.2: its agent config is /etc/p2pc/agent.toml, which an upgrade does not carry over by itself; -Upgrade to 0.2.2 or newer moves it into /var/lib/p2pc.' 'WARN'
    }
    $r = Get-AgentStatus
    if ($r.ExitCode -ne 0) {
        Write-Log ("p2pc-agent status failed (exit {0}): {1}" -f $r.ExitCode, $r.Output) 'WARN'
    } else {
        foreach ($l in ($r.Output -split "`r?`n")) { if ($l) { Write-Log $l } }
    }
    Show-NodeRunStatus
    $stop = Read-NodeStopRecord
    if ($null -ne $stop) {
        $how = 'the task was disabled'
        if ($stop.Disabled -eq 'no') { $how = 'the task could NOT be disabled, so the node refuses to start until something changes' }
        $what = 'exited with an unknown code'
        if ($null -ne $stop.Code) { $what = 'exited {0}' -f $stop.Code }
        if ($stop.Time) { $what += ' at {0}' -f $stop.Time }
        if ($stop.Reason) { $what += ' ({0})' -f $stop.Reason }
        Write-Log ("STOPPED FOR GOOD: the agent {0}; {1}." -f $what, $how) 'WARN'
        if ($null -eq $stop.Code) {
            Write-Log ("  The exit code is unknown: see the p2pc-node-run lines above, and the agent log:   wsl -d {0} -u root --exec /usr/bin/tail -n 50 /var/log/p2pc/agent.log" -f $DistroName) 'WARN'
        } else {
            Write-Log ('  ' + (Get-NodeStopAdvice $stop.Code)) 'WARN'
        }
    }
    # A task registered by an older install.ps1 runs p2pc-node-run directly, with no wrapper: a terminal exit never
    # disables it (T14b2 real run 4, W1c). -Join registers it again (an -Upgrade does too).
    if ($false -eq (Test-NodeTaskActionCurrent)) {
        Write-Log ("The Scheduled Task '{0}' does not run {1} (it was registered by an older install.ps1, or the file is missing): after a terminal exit it would not stop the node for good." -f $TaskName, (Get-NodeTaskWrapperPath)) 'WARN'
        Write-Log '  Register it again (this starts the node):   .\install.ps1 -Join' 'WARN'
    }
    # An orphan: the agent runs but the task does not, so nothing supervises it and stopping the task does not stop it
    # (Stop-ScheduledTask kills conhost but not its wsl.exe: T14b2 real run, W5).
    $state = Get-NodeTaskState
    $proc = Invoke-InDistro @('/usr/bin/pgrep', '-x', 'p2pc-agent')
    if ($state -ne 'Running' -and $proc.ExitCode -eq 0) {
        $shown = $state
        if (-not $shown) { $shown = 'not registered' }
        Write-Log ("ORPHAN: p2pc-agent runs inside {0}, but the Scheduled Task '{1}' is not running ({2}): nothing supervises it." -f $DistroName, $TaskName, $shown) 'WARN'
        Write-Log '  To put it back under the task:   .\install.ps1 -Stop   then   .\install.ps1 -Start' 'WARN'
    }
}

# -Stop: the node goes offline and stays so (also at sign-in and on the 5-minute trigger) until -Start.
function Invoke-StopAction {
    Test-Wsl
    if (-not (Test-DistroExists)) { Fail 31 ("{0} is not installed." -f $DistroName) }
    if (Test-NodeTaskRegistered) {
        Suspend-NodeTask
    } else {
        Write-Log ("The Scheduled Task '{0}' is not registered; stopping the distro only." -f $TaskName) 'WARN'
        $null = Invoke-Wsl @('--terminate', $DistroName)
    }
    Write-Log ("Stopped: the node is offline. The task '{0}' stays disabled (no start at sign-in, none from its 5-minute trigger) until:   .\install.ps1 -Start" -f $TaskName) 'OK'
}

function Invoke-StartAction {
    Test-Wsl
    if (-not (Test-DistroExists)) { Fail 31 ("{0} is not installed." -f $DistroName) }
    if (-not (Test-NodeTaskRegistered)) {
        Fail 35 ("The Scheduled Task '{0}' is not registered." -f $TaskName) @('Register it (and enroll the node if needed):   .\install.ps1 -Join')
    }
    $stop = Read-NodeStopRecord
    if ($null -ne $stop) {
        Write-Log ("The node had stopped for good ({0}); starting it again, as asked. If nothing changed it stops again. {1}" -f (Format-NodeStop $stop), (Get-NodeStopAdvice $stop.Code)) 'WARN'
        Clear-NodeStop
    }
    $startedAt = Get-DistroNow
    if (-not (Resume-NodeTask)) { Fail 35 ("The Scheduled Task '{0}' could not be enabled or started." -f $TaskName) }
    Write-Log ("Started the Scheduled Task '{0}'." -f $TaskName) 'OK'
    $null = Wait-NodeConnected -NotBefore $startedAt -FailIfTaskStopped $true
}

# At the end of a run: if an -Upgrade did not finish, say where its state backup is (the only copy of the identity).
function Write-KeptBackupWarning {
    if ($script:StateBackup -and (Test-Path -LiteralPath $script:StateBackup)) {
        Write-Log ("The upgrade did not finish. The backup of the agent state was KEPT, and -Uninstall never deletes it unless you ask: {0}. {1}" -f $script:StateBackup, (Get-FailedBackupAdvice)) 'WARN'
    }
}

# Test-TokenLikeParameters: a string parameter holds what looks like a join token (review P3-1). Checked before anything
# else, before the log is even opened (-LogPath could be one), and the value is never shown.
function Test-TokenLikeParameters {
    foreach ($v in @($Tar, $Sha256Path, $InstallDir, $LogPath)) {
        if ($v -and ([string]$v -match '^\s*p2pc_join_')) { return $true }
    }
    return $false
}

# ---------------------------------------------------------------------------------------------------------------
function Main {
    if (Test-TokenLikeParameters) {
        $script:LogFile = $null
        $script:ExitCode = 2
        try { Fail 2 'A parameter holds a join token (not shown, and nothing was written). Never put the join token on the command line: run .\install.ps1 -Join and paste it when asked, or pipe it.' } catch { }
        exit $script:ExitCode
    }
    if (-not $LogPath) {
        $logDir = Join-Path $env:LOCALAPPDATA 'P2PC\logs'
        New-Item -ItemType Directory -Force -Path $logDir | Out-Null
        $LogPath = Join-Path $logDir ('install-{0}.log' -f (Get-Date -Format 'yyyyMMdd-HHmmss'))
    }
    $script:LogFile = $LogPath
    try {
        Write-Log ("p2pc-node installer (PowerShell {0}); only the distro '{1}' is ever touched." -f $PSVersionTable.PSVersion, $DistroName)
        # Never echo what was refused: someone may have put the join token on the command line.
        if (@($script:ExtraArgs).Count -gt 0) { Fail 2 ('Unknown argument(s) (not shown). Never put the join token on the command line: run .\install.ps1 -Join and paste it when asked, or pipe it.') }
        $actions = @($Join, $Status, $Stop, $Start, $Upgrade, $Uninstall) | Where-Object { $_ }
        if (@($actions).Count -gt 1) { Fail 2 'Run one action at a time: -Join, -Status, -Stop, -Start, -Upgrade or -Uninstall.' }
        if (($Join -or $Status -or $Stop -or $Start) -and $CheckOnly) { Fail 2 '-CheckOnly goes with an install or -Upgrade only.' }
        if (($Join -or $Status -or $Stop -or $Start) -and ($Tar -or $Sha256Path)) {
            Fail 2 '-Join, -Status, -Stop and -Start take no image (and no value at all). Never put the join token on the command line (it is visible to other programs and kept in the history): run .\install.ps1 -Join and paste it when asked, or pipe it.'
        }
        if ($Force -and ($Status -or $Stop -or $Start)) { Fail 2 '-Force does not apply to -Status, -Stop or -Start.' }
        if ($Upgrade -and $Uninstall) { Fail 2 '-Upgrade and -Uninstall cannot be combined.' }
        if ($CheckOnly -and $Uninstall) { Fail 2 '-CheckOnly cannot be combined with -Uninstall.' }
        if ($KeepBackups -and -not $Uninstall) { Fail 2 '-KeepBackups only applies to -Uninstall.' }
        if ($DeleteFailedBackups -and -not $Uninstall) { Fail 2 '-DeleteFailedBackups only applies to -Uninstall.' }
        if ($KeepBackups -and $DeleteFailedBackups) { Fail 2 '-KeepBackups and -DeleteFailedBackups cannot be combined.' }
        if (-not $InstallDir) { $InstallDir = Join-Path $env:LOCALAPPDATA 'P2PC\wsl\p2pc-node' }
        # wsl.exe resolves relative paths against the process directory, which can differ from PowerShell's location.
        $InstallDir = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($InstallDir)
        if ($Join) {
            Invoke-JoinAction
        } elseif ($Status) {
            Invoke-StatusAction
        } elseif ($Stop) {
            Invoke-StopAction
        } elseif ($Start) {
            Invoke-StartAction
        } elseif ($Uninstall) {
            Invoke-UninstallAction
        } elseif ($Upgrade) {
            Invoke-UpgradeAction $InstallDir
        } else {
            Invoke-Install $InstallDir
        }
        if ($CheckOnly) { Write-Log 'All checks passed. Nothing was changed.' 'OK' }
    } catch {
        if ($_.Exception.Message -ne $script:FailMarker) {
            Write-Log ("Unexpected error: {0}" -f $_.Exception.Message) 'ERROR'
            Write-Log ($_ | Out-String) 'DEBUG'
            $script:ExitCode = 1
        }
    } finally {
        Write-KeptBackupWarning
        Write-Host ''
        Write-Host ("Log file: {0}" -f $script:LogFile)
    }
    exit $script:ExitCode
}

# What the pipeline gives (the join token, when it is piped in) and any argument no parameter took; taken here, at the
# script level, because inside a function $input and $args are the function's own. $input is kept as the enumerator,
# not read: only -Join reads it (Read-JoinToken).
$script:PipedInput = $input
$script:ExtraArgs = @($args)
if ($MyInvocation.InvocationName -ne '.') { Main }
