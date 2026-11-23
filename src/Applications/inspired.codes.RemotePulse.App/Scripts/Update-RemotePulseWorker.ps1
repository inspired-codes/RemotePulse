<#
.SYNOPSIS
RemotePulse Worker self-update - a predefined command the App sends to a Worker.

.DESCRIPTION
Embedded in the App build and sent verbatim by its "Update Worker" button, with no
arguments, so the defaults below are what runs in practice.

Send with ExecutionMode RunWithHighestLocalPrivileges (SYSTEM on Windows, root on Linux).
That mode runs this script in-process, inside the Worker service itself, so the script
must NOT run the installer inline: Installer.ps1 stops the very service hosting this
runspace (on Linux systemd then kills the whole unit cgroup, installer included), and
the App would never get a result.

Instead it hands the update to a detached one-shot job owned by the OS and returns at
once, so the Worker can post this result before it is restarted:
  - Windows: on-demand scheduled task "RemotePulse Worker Self-Update", runs as SYSTEM
  - Linux:   transient unit "remotepulse-selfupdate.service" (its own cgroup)
After DelaySeconds the job downloads the release zip from the Hub this Worker already
polls (ServerUrl in its appsettings.json - never a hardcoded host), checks it against
the published .sha256 (as get-worker.ps1 does), and runs Installer.ps1 with that Hub as
-HubUrl, prompts disabled. The installer keeps MachineId, keys, pairing and config.

Idempotent: a run already in progress is reported, not duplicated, and a Worker that is
already on the published version (or newer) is left alone unless -Force.

Log of the last run only: <Worker data dir>/selfupdate.log
  C:\ProgramData\RemotePulse\selfupdate.log  |  /var/lib/remotepulse/selfupdate.log
#>
param(
    # Time for the Worker to post this result before the installer stops it.
    [ValidateRange(10, 300)]
    [int]$DelaySeconds = 20,

    # Reinstall even when the published version is not newer (also allows a downgrade).
    [switch]$Force,

    # Optional pins for the release zip, checked on top of the .sha256 sidecar, so that
    # tampering with /downloads alone is not enough. The App does not pass them yet; the
    # plan is to compile the release hashes into its build and send them in the signed command.
    [string]$ExpectedWindowsSha256 = "",
    [string]$ExpectedLinuxSha256 = ""
)

$ErrorActionPreference = "Stop"

# ------------------------------------------------------------------------------
# Platform and privilege
# ------------------------------------------------------------------------------
$onWindows = if ($null -ne $IsWindows) { $IsWindows } else { $true }
$onLinux   = [bool]$IsLinux
if (-not $onWindows -and -not $onLinux) {
    throw "Self-update supports Windows and Linux Workers only."
}

if ($onWindows) {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $elevated = $identity.IsSystem -or ([Security.Principal.WindowsPrincipal]$identity).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
} else {
    $elevated = ((& id -u) -eq 0)
}
if (-not $elevated) {
    throw "Self-update must be sent with ExecutionMode RunWithHighestLocalPrivileges (SYSTEM / root). It ran as '$([Environment]::UserName)'."
}

# Same fixed locations as Installer.ps1 / AppPaths.cs.
if ($onWindows) {
    $TargetDir = Join-Path $env:ProgramFiles "RemotePulse\Worker"
    $DataDir   = Join-Path ([Environment]::GetFolderPath("CommonApplicationData")) "RemotePulse"
    $UpdateDir = Join-Path $env:ProgramFiles "RemotePulse\SelfUpdate"
    $OsLabel   = "windows-x64"
    $WorkerBin = "RemotePulse.Worker.exe"
    $PinnedSha = $ExpectedWindowsSha256
} else {
    $TargetDir = "/opt/remotepulse/worker"
    $DataDir   = "/var/lib/remotepulse"
    $UpdateDir = "/opt/remotepulse/selfupdate"
    $OsLabel   = "linux-x64"
    $WorkerBin = "RemotePulse.Worker"
    $PinnedSha = $ExpectedLinuxSha256
}
$LogPath  = Join-Path $DataDir "selfupdate.log"
$Runner   = Join-Path $UpdateDir "Invoke-SelfUpdate.ps1"
$TaskName = "RemotePulse Worker Self-Update"
$UnitName = "remotepulse-selfupdate"

if ($PinnedSha -and $PinnedSha -notmatch '^[0-9a-fA-F]{64}$') {
    throw "Expected SHA-256 for $OsLabel is malformed ('$PinnedSha')."
}

# ------------------------------------------------------------------------------
# Which Worker is this, and which Hub does it poll?
# ------------------------------------------------------------------------------
# In-process, AppContext.BaseDirectory is the running Worker's own folder, i.e. the
# appsettings.json it actually reads (Program.cs builds its config from there).
$installDir = [AppContext]::BaseDirectory.TrimEnd('\', '/')
if (-not (Test-Path (Join-Path $installDir $WorkerBin))) {
    # Not hosted by the Worker (e.g. run by hand from a console) - assume the default.
    $installDir = $TargetDir
}
$comparison = if ($onWindows) { [StringComparison]::OrdinalIgnoreCase } else { [StringComparison]::Ordinal }
if (-not [string]::Equals([IO.Path]::GetFullPath($installDir), [IO.Path]::GetFullPath($TargetDir), $comparison)) {
    throw "This Worker runs from '$installDir', but Installer.ps1 always deploys to '$TargetDir'. A self-update would leave a second copy behind (on Windows the service would keep starting the old one). Update this machine by hand."
}

$configPath = Join-Path $installDir "appsettings.json"
$cfg = Get-Content -Path $configPath -Raw | ConvertFrom-Json
$serverUrl = [string]$cfg.RemotePulse.ServerUrl
$hubUri = $null
if (-not [Uri]::TryCreate($serverUrl, [UriKind]::Absolute, [ref]$hubUri) -or
    $hubUri.Scheme -ne "https" -or $hubUri.UserInfo -or $hubUri.Query -or $hubUri.Fragment) {
    throw "Refusing to self-update: ServerUrl '$serverUrl' in $configPath is not a plain https:// URL."
}
$hubUrl  = $hubUri.AbsoluteUri
$hubBase = $hubUrl.TrimEnd('/')
if ($cfg.RemotePulse.AllowUntrustedCertificates -eq $true) {
    Write-Warning "AllowUntrustedCertificates is on, but the update download validates TLS normally and fails against an untrusted certificate."
}

# ------------------------------------------------------------------------------
# Is there anything to do?
# ------------------------------------------------------------------------------
$dll = Join-Path $installDir "RemotePulse.Worker.dll"
$current = if (Test-Path $dll) { ([Diagnostics.FileVersionInfo]::GetVersionInfo($dll).ProductVersion -split '\+')[0] } else { $null }
$published = $null
try {
    $published = [string](Invoke-RestMethod -Uri "$hubBase/downloads/worker-version.json" -TimeoutSec 15).version
} catch {
    Write-Warning "Could not read $hubBase/downloads/worker-version.json ($($_.Exception.Message)); updating without a version check."
}
$currentVer = $null
$publishedVer = $null
if (-not $Force -and [version]::TryParse([string]$current, [ref]$currentVer) -and [version]::TryParse([string]$published, [ref]$publishedVer) -and $currentVer -ge $publishedVer) {
    "Nothing to do: this Worker runs $current and $hubBase publishes $published. Send with -Force to reinstall anyway."
    return
}

# ------------------------------------------------------------------------------
# PowerShell 7 for the detached job (Installer.ps1 needs it; the Worker itself does not)
# ------------------------------------------------------------------------------
if ($onWindows) {
    $candidates = @(
        (Join-Path $env:ProgramFiles "PowerShell\7\pwsh.exe"),
        (Get-Command pwsh.exe -CommandType Application -ErrorAction SilentlyContinue | Where-Object { $_.Source -notlike "*\WindowsApps\*" } | Select-Object -First 1 -ExpandProperty Source)
    )
} else {
    $candidates = @(
        (Get-Command pwsh -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty Source),
        "/usr/bin/pwsh", "/opt/microsoft/powershell/7/pwsh", "/usr/local/bin/pwsh", "/snap/bin/pwsh"
    )
}
$pwsh = $candidates | Where-Object { $_ -and (Test-Path $_) } | Select-Object -First 1
if (-not $pwsh) {
    throw "PowerShell 7 (pwsh) was not found in a machine-wide location; Installer.ps1 needs it. Install PowerShell 7 for all users, then retry."
}

# ------------------------------------------------------------------------------
# Detached one-shot job - runs after this script has returned and its result is posted
# ------------------------------------------------------------------------------
$RunnerScript = @'
# Written by Update-RemotePulseWorker.ps1 - one RemotePulse Worker self-update run.
# Started by the OS (scheduled task / transient systemd unit), outside the Worker service.
param(
    [Parameter(Mandatory)] [string]$HubUrl,
    [Parameter(Mandatory)] [ValidateSet("windows-x64", "linux-x64")] [string]$OsLabel,
    [Parameter(Mandatory)] [string]$LogPath,
    [int]$DelaySeconds = 20,
    [string]$ExpectedSha256 = ""
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

$onWindows   = $OsLabel -eq "windows-x64"
$serviceName = if ($onWindows) { "RemotePulseWorker" } else { "remotepulse-worker.service" }
$targetDir   = if ($onWindows) { Join-Path $env:ProgramFiles "RemotePulse\Worker" } else { "/opt/remotepulse/worker" }
$workDir     = Join-Path $PSScriptRoot "work"

# Last run only.
Remove-Item -Path $LogPath -Force -ErrorAction SilentlyContinue
function Write-Log([string]$Message) {
    Add-Content -Path $LogPath -Value ("{0:yyyy-MM-dd HH:mm:ss} {1}" -f (Get-Date), $Message)
}

function Test-WorkerRunning {
    if ($onWindows) { return ((Get-Service -Name $serviceName -ErrorAction SilentlyContinue).Status -eq "Running") }
    return ("$(& systemctl is-active $serviceName 2>$null)".Trim() -eq "active")
}

$exitCode = 1
try {
    Write-Log "Self-update started: PowerShell $($PSVersionTable.PSVersion), Hub $HubUrl. Waiting $DelaySeconds s so the Worker can post its result."
    Start-Sleep -Seconds $DelaySeconds

    $zipName = "RemotePulse-Worker-$OsLabel.zip"
    $zipUrl  = "$($HubUrl.TrimEnd('/'))/downloads/$zipName"
    if (Test-Path $workDir) { Remove-Item -Path $workDir -Recurse -Force }
    $extractDir = Join-Path $workDir "extracted"
    New-Item -ItemType Directory -Path $extractDir -Force | Out-Null
    $zipPath = Join-Path $workDir $zipName

    # Same integrity check as get-worker.ps1: the zip must match its published .sha256.
    Write-Log "Downloading $zipUrl"
    Invoke-WebRequest -Uri $zipUrl -OutFile $zipPath -UseBasicParsing -TimeoutSec 600
    $expected = ((Invoke-WebRequest -Uri "$zipUrl.sha256" -UseBasicParsing -TimeoutSec 30).Content -split '\s+')[0].Trim().ToLower()
    if ($expected -notmatch '^[0-9a-f]{64}$') { throw "Checksum file at $zipUrl.sha256 is malformed ('$expected')." }
    $actual = (Get-FileHash -Path $zipPath -Algorithm SHA256).Hash.ToLower()
    if ($actual -ne $expected) { throw "Checksum mismatch for $zipName (published $expected, downloaded $actual)." }
    if ($ExpectedSha256 -and $actual -ne $ExpectedSha256.ToLower()) { throw "$zipName does not match the SHA-256 pinned by the App ($ExpectedSha256)." }
    Write-Log "SHA-256 OK ($actual)"

    Expand-Archive -Path $zipPath -DestinationPath $extractDir -Force
    $installer = Join-Path $extractDir "Installer.ps1"
    if (-not (Test-Path $installer)) { throw "Installer.ps1 not found in $zipName." }

    # Own process, stdin redirected and closed: the installer's [Console]::KeyAvailable
    # probe then fails, so it skips every Read-Host prompt and the exit countdown, and
    # -NonInteractive turns its unguarded "Press Enter to exit" into an error instead of
    # a hang. Its output is captured into this log.
    $psi = [Diagnostics.ProcessStartInfo]::new([Environment]::ProcessPath)
    foreach ($arg in @("-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", $installer, "-HubUrl", $HubUrl, "-ExitTimeoutSeconds", "1")) {
        $psi.ArgumentList.Add($arg)
    }
    $psi.WorkingDirectory = $extractDir
    $psi.UseShellExecute = $false
    $psi.RedirectStandardInput = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true

    Write-Log "Running Installer.ps1 -HubUrl $HubUrl"
    $proc = [Diagnostics.Process]::Start($psi)
    $proc.StandardInput.Close()
    $stdout = $proc.StandardOutput.ReadToEndAsync()
    $stderr = $proc.StandardError.ReadToEndAsync()
    if (-not $proc.WaitForExit(20 * 60 * 1000)) {
        $proc.Kill($true)
        throw "Installer.ps1 did not finish within 20 minutes."
    }
    $proc.WaitForExit()
    Add-Content -Path $LogPath -Value $stdout.Result
    if ($stderr.Result) { Add-Content -Path $LogPath -Value $stderr.Result }
    $exitCode = $proc.ExitCode
    Write-Log "Installer.ps1 exit code: $exitCode"
}
catch {
    Write-Log "FAILED: $($_.Exception.Message)"
}
finally {
    # Never leave the machine unreachable: if the installer stopped the Worker and then
    # failed, start whatever is installed again.
    if (-not (Test-WorkerRunning)) {
        Write-Log "Worker service is not running - starting it."
        try {
            if ($onWindows) { Start-Service -Name $serviceName } else { & systemctl start $serviceName 2>&1 | ForEach-Object { Write-Log "$_" } }
        } catch {
            Write-Log "Could not start the Worker service: $($_.Exception.Message)"
        }
    }
    $dll = Join-Path $targetDir "RemotePulse.Worker.dll"
    if (Test-Path $dll) {
        Write-Log ("Installed Worker version: {0}" -f ([Diagnostics.FileVersionInfo]::GetVersionInfo($dll).ProductVersion -split '\+')[0])
    }
    Write-Log ("Worker service running: {0}" -f (Test-WorkerRunning))
    Remove-Item -Path $workDir -Recurse -Force -ErrorAction SilentlyContinue
}
exit $exitCode
'@

# ------------------------------------------------------------------------------
# Hand off to the OS scheduler (idempotent: fixed task / unit name)
# ------------------------------------------------------------------------------
$runnerArgs = @("-HubUrl", $hubUrl, "-OsLabel", $OsLabel, "-LogPath", $LogPath, "-DelaySeconds", "$DelaySeconds")
if ($PinnedSha) { $runnerArgs += @("-ExpectedSha256", $PinnedSha.ToLower()) }

if ($onWindows) {
    # The Task Scheduler COM API rather than the ScheduledTasks module: no module
    # autoloading needed inside the Worker's hosted runspace, and no minute rounding.
    $scheduler = New-Object -ComObject "Schedule.Service"
    $scheduler.Connect()
    $folder = $scheduler.GetFolder("\")
    $existing = try { $folder.GetTask($TaskName) } catch { $null }
    if ($existing -and $existing.State -eq 4) {   # TASK_STATE_RUNNING
        "A self-update is already running (scheduled task '$TaskName'). Log: $LogPath"
        return
    }

    # Program Files: only SYSTEM / Administrators can write here (ProgramData is not).
    New-Item -ItemType Directory -Path $UpdateDir -Force | Out-Null
    [IO.File]::WriteAllText($Runner, $RunnerScript)

    $definition = $scheduler.NewTask(0)
    $definition.RegistrationInfo.Description = "One-shot RemotePulse Worker self-update, started on demand from the App. Safe to delete."
    $definition.Principal.UserId = "SYSTEM"
    $definition.Principal.LogonType = 5             # TASK_LOGON_SERVICE_ACCOUNT
    $definition.Principal.RunLevel = 1              # TASK_RUNLEVEL_HIGHEST
    $definition.Settings.MultipleInstances = 2      # TASK_INSTANCES_IGNORE_NEW
    $definition.Settings.ExecutionTimeLimit = "PT30M"
    $definition.Settings.DisallowStartIfOnBatteries = $false
    $definition.Settings.StopIfGoingOnBatteries = $false
    $action = $definition.Actions.Create(0)         # TASK_ACTION_EXEC
    $action.Path = $pwsh
    $action.Arguments = (@("-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", $Runner) + $runnerArgs | ForEach-Object { "`"$_`"" }) -join " "
    $action.WorkingDirectory = $UpdateDir

    # TASK_CREATE_OR_UPDATE (6), TASK_LOGON_SERVICE_ACCOUNT (5). No trigger: started right
    # away by Run(); the runner itself waits DelaySeconds.
    $task = $folder.RegisterTaskDefinition($TaskName, $definition, 6, "SYSTEM", $null, 5)
    [void]$task.Run($null)
    $via = "scheduled task '$TaskName' (SYSTEM)"
} else {
    # Every native command in this part must exit 0 on the happy path: in the Worker's hosted
    # runspace a non-zero exit sets HadErrors even with 2>$null, and the App then shows a
    # scheduled update as failed. "systemctl is-active" exits 3 for an inactive unit, so ask
    # "systemctl show", which exits 0 for any state, including a unit that doesn't exist.
    $state = "$(& systemctl show -p ActiveState --value "$UnitName.service")".Trim()
    if ($state -in @("active", "activating", "deactivating", "reloading")) {
        "A self-update is already running ($UnitName.service is $state). Log: $LogPath"
        return
    }

    New-Item -ItemType Directory -Path $UpdateDir -Force | Out-Null
    & chmod 700 $UpdateDir
    [IO.File]::WriteAllText($Runner, $RunnerScript)

    # A transient unit gets its own cgroup, so the installer's "systemctl stop" of the
    # Worker unit (KillMode=control-group by default) cannot take the update down with it.
    if ($state -eq "failed") {
        # A failed transient unit keeps its name until reset (exits 1 when there's nothing to reset).
        & systemctl reset-failed "$UnitName.service"
    }
    $runOutput = & systemd-run "--unit=$UnitName" "--description=RemotePulse Worker self-update" --collect --quiet `
        "--property=RuntimeMaxSec=1800" "--setenv=HOME=/root" `
        $pwsh -NoProfile -NonInteractive -File $Runner @runnerArgs 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "systemd-run failed (exit code $LASTEXITCODE): $runOutput"
    }
    $via = "transient unit $UnitName.service (root)"
}

$fromTo = if ($published) { "$(if ($current) { $current } else { 'unknown' }) -> $published" } else { "$(if ($current) { $current } else { 'unknown' }) -> latest published" }
"Update scheduled in $DelaySeconds s via $via."
"  Hub     : $hubBase"
"  Version : $fromTo"
"  Log     : $LogPath"
"The Worker will restart and be offline for about a minute. Check its version in the App afterwards."
