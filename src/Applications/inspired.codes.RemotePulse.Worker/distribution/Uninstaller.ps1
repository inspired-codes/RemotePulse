<#
.SYNOPSIS
Uninstalls the RemotePulse Worker service and removes installed files (PowerShell 7).
Cross-platform: Windows Service on Windows, systemd unit on Linux.

.DESCRIPTION
Stops and removes the service, deletes the installed binaries, and optionally
removes local cryptographic keys and pairing state:
  - Windows: service "RemotePulseWorker", %ProgramFiles%\RemotePulse\Worker,
    data in %ProgramData%\RemotePulse.
  - Linux:   unit "remotepulse-worker.service", /opt/remotepulse/worker,
    data in /var/lib/remotepulse.

Every step is best-effort. A status overview is printed at the end.

Requires PowerShell 7 and elevation (Administrator / root); relaunches itself
elevated if needed.

.PARAMETER PurgeAll
Delete all worker data, pairing keys, and logs without prompting.

.PARAMETER PurgeData
Backward-compatible alias for -PurgeAll.

.PARAMETER KeepPairing
Preserve pairing credentials (client_key.dat, pairing.json, machine-identity.json) so the worker reconnects on reinstall.

.PARAMETER KeepLogs
Preserve worker log files (*.log) for diagnostics.

.PARAMETER PurgeLogs
Delete worker log files (*.log) without prompting.
#>

[CmdletBinding()]
param(
    [int]$ExitTimeoutSeconds = 8,
    [switch]$PurgeAll,
    [switch]$PurgeData,
    [switch]$KeepPairing,
    [switch]$KeepLogs,
    [switch]$PurgeLogs
)

# ------------------------------------------------------------------------------
# OS detection + bootstrap (require PowerShell 7 + elevation)
# ------------------------------------------------------------------------------
$onWindows = if ($null -ne $IsWindows) { $IsWindows } else { $true }
$onLinux   = [bool]$IsLinux
if (-not $onWindows -and -not $onLinux) {
    Write-Host "Unsupported OS - the RemotePulse Worker uninstaller targets Windows and Linux." -ForegroundColor Red
    exit 1
}

$isPwsh7 = $PSVersionTable.PSVersion.Major -ge 7
if ($onWindows) {
    $isElevated = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
} else {
    $isElevated = ((& id -u) -eq 0)
}

if (-not $isPwsh7 -or -not $isElevated) {
    if ($isPwsh7) {
        $pwshPath = (Get-Process -Id $PID).Path
    } elseif ($onWindows) {
        $pwshPath = (Get-Command pwsh.exe -ErrorAction SilentlyContinue).Source
    } else {
        $pwshPath = (Get-Command pwsh -ErrorAction SilentlyContinue).Source
    }

    if (-not $pwshPath) {
        Write-Host "PowerShell 7 is required but was not found." -ForegroundColor Red
        if ($onWindows) {
            Write-Host "    winget install --id Microsoft.PowerShell --source winget" -ForegroundColor Cyan
            Read-Host "Press Enter to exit"
        } else {
            Write-Host "    https://learn.microsoft.com/powershell/scripting/install/install-other-linux" -ForegroundColor Cyan
        }
        exit 1
    }

    $extraArgs = @()
    if ($PurgeAll)    { $extraArgs += "-PurgeAll" }
    if ($PurgeData)   { $extraArgs += "-PurgeData" }
    if ($KeepPairing) { $extraArgs += "-KeepPairing" }
    if ($KeepLogs)    { $extraArgs += "-KeepLogs" }
    if ($PurgeLogs)   { $extraArgs += "-PurgeLogs" }

    try {
        if ($onWindows) {
            $winArgs = @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "`"$PSCommandPath`"", "-ExitTimeoutSeconds", $ExitTimeoutSeconds) + $extraArgs
            Start-Process -FilePath $pwshPath -Verb RunAs -WorkingDirectory $PSScriptRoot -ArgumentList $winArgs
            exit
        } else {
            $nixArgs = @("-NoProfile", "-File", $PSCommandPath, "-ExitTimeoutSeconds", $ExitTimeoutSeconds) + $extraArgs
            & sudo $pwshPath @nixArgs
            exit $LASTEXITCODE
        }
    } catch {
        Write-Host "Failed to relaunch elevated: $($_.Exception.Message)" -ForegroundColor Red
        if ($onWindows) { Read-Host "Press Enter to exit" }
        exit 1
    }
}

# ------------------------------------------------------------------------------
# Configuration
# ------------------------------------------------------------------------------
$ErrorActionPreference = "Stop"
$PSNativeCommandUseErrorActionPreference = $false

if ($IsWindows) {
    $Platform    = "Windows"
    $ServiceName = "RemotePulseWorker"
    $TargetDir   = Join-Path $env:ProgramFiles "RemotePulse\Worker"
    $TargetExe   = Join-Path $TargetDir "RemotePulse.Worker.exe"
    $DataDir     = Join-Path $env:ProgramData "RemotePulse"
} else {
    $Platform    = "Linux"
    $ServiceName = "remotepulse-worker.service"
    $UnitPath    = "/etc/systemd/system/remotepulse-worker.service"
    $TargetDir   = "/opt/remotepulse/worker"
    $TargetExe   = Join-Path $TargetDir "RemotePulse.Worker"
    $DataDir     = "/var/lib/remotepulse"
}

$KeyPath      = Join-Path $DataDir "client_key.dat"
$PairingPath  = Join-Path $DataDir "pairing.json"
$IdentityPath = Join-Path $DataDir "machine-identity.json"
$LogPath      = Join-Path $DataDir "worker.log"

$script:HadError     = $false
$script:Status       = [System.Collections.Generic.List[object]]::new()
$script:PairingState = "unknown"
$script:LogsState    = "unknown"

function Add-Status {
    param([string]$Step, [ValidateSet("OK", "FAILED", "SKIPPED", "WARN")] [string]$Result, [string]$Detail = "")
    $script:Status.Add([pscustomobject]@{ Step = $Step; Result = $Result; Detail = $Detail })
}

function Invoke-Step {
    param([string]$Name, [scriptblock]$Action)
    Write-Host "`n>> $Name..." -ForegroundColor Green
    try {
        $detail = & $Action
        Add-Status $Name "OK" ([string]$detail)
    } catch {
        $script:HadError = $true
        Write-Host ("   ERROR: {0}" -f $_.Exception.Message) -ForegroundColor Red
        Add-Status $Name "FAILED" $_.Exception.Message
    }
}

function Invoke-TimedExit {
    param([int]$TimeoutSeconds = 8)
    Write-Host ""
    $canPoll = $true
    try { $null = [Console]::KeyAvailable } catch { $canPoll = $false }
    if (-not $canPoll) { return }

    try { while ([Console]::KeyAvailable) { [void][Console]::ReadKey($true) } } catch { }
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    $lastRemaining = -1

    while ((Get-Date) -lt $deadline) {
        $remaining = [int][Math]::Ceiling(($deadline - (Get-Date)).TotalSeconds)
        if ($remaining -ne $lastRemaining -and $remaining -gt 0) {
            $lastRemaining = $remaining
            $unit = if ($remaining -eq 1) { "second" } else { "seconds" }
            Write-Host -NoNewline ("`rPress [Enter] to exit now - this window closes automatically in {0} {1}...  " -f $remaining, $unit) -ForegroundColor Cyan
        }
        if ([Console]::KeyAvailable) {
            if ([Console]::ReadKey($true).Key -eq [ConsoleKey]::Enter) { break }
        }
        Start-Sleep -Milliseconds 100
    }
    Write-Host ""
}

function Show-StatusOverview {
    Write-Host ""
    Write-Host "==========================================" -ForegroundColor Cyan
    Write-Host "   RemotePulse Worker - Uninstall Summary  " -ForegroundColor Cyan
    Write-Host "==========================================" -ForegroundColor Cyan
    foreach ($item in $script:Status) {
        $color = switch ($item.Result) { "OK" { "Green" } "WARN" { "Yellow" } "SKIPPED" { "DarkGray" } "FAILED" { "Red" } default { "Gray" } }
        $line = "  [{0,-7}] {1}" -f $item.Result, $item.Step
        if ($item.Detail) { $line += " - $($item.Detail)" }
        Write-Host $line -ForegroundColor $color
    }
    Write-Host ""
    Write-Host  "  Platform      : $Platform"
    Write-Host ("  Install dir   : {0}" -f $(if (Test-Path $TargetDir) { "$TargetDir (still present)" } else { "removed" })) -ForegroundColor $(if (Test-Path $TargetDir) { "Yellow" } else { "Green" })
    Write-Host ("  Pairing state : {0}" -f $script:PairingState) -ForegroundColor $(if ($script:PairingState -eq "preserved") { "Cyan" } else { "DarkGray" })
    Write-Host ("  Worker logs   : {0}" -f $script:LogsState) -ForegroundColor $(if ($script:LogsState -eq "preserved") { "Cyan" } else { "DarkGray" })
    Write-Host ("  Worker data   : {0}" -f $(if (Test-Path $DataDir) { "$DataDir (kept)" } else { "removed" }))
    Write-Host ""
    if ($script:HadError) {
        Write-Host "  Result        : UNINSTALL COMPLETED WITH ERRORS" -ForegroundColor Red
    } else {
        Write-Host "  Result        : UNINSTALL SUCCESSFUL" -ForegroundColor Green
    }
    Write-Host "==========================================" -ForegroundColor Cyan
}

# ------------------------------------------------------------------------------
# Main
# ------------------------------------------------------------------------------
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "   RemotePulse Worker - Uninstaller ($Platform)" -ForegroundColor Cyan
Write-Host ("   PowerShell {0}" -f $PSVersionTable.PSVersion) -ForegroundColor DarkGray
Write-Host "==========================================" -ForegroundColor Cyan

# 1. Stop and remove the service
Invoke-Step "Stop and remove service" {
    if ($IsWindows) {
        $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
        if (-not $svc) { return "service was not installed" }
        if ($svc.Status -ne "Stopped") {
            Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
            try { $svc.WaitForStatus("Stopped", (New-TimeSpan -Seconds 15)) } catch { }
        }
        Get-Process -Name "RemotePulse.Worker" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
        Get-Process -ErrorAction SilentlyContinue | Where-Object {
            try { $_.Path -and $_.Path.StartsWith($TargetDir, [System.StringComparison]::OrdinalIgnoreCase) } catch { $false }
        } | Stop-Process -Force -ErrorAction SilentlyContinue
        if (Test-Path $TargetExe) {
            & $TargetExe --uninstall
            if ($LASTEXITCODE -ne 0) { throw "Worker '--uninstall' exited with code $LASTEXITCODE." }
        } else {
            & sc.exe delete $ServiceName | Out-Null
        }
        return "service stopped and removed"
    } else {
        if (-not (Test-Path $UnitPath)) { return "unit was not installed" }
        try { & systemctl disable --now $ServiceName 2>$null } catch { }
        if (Get-Command pkill -ErrorAction SilentlyContinue) {
            try { & pkill -f "$TargetDir/RemotePulse.Worker" 2>$null } catch { }
        }
        Remove-Item -Path $UnitPath -Force -ErrorAction SilentlyContinue
        try { & systemctl daemon-reload 2>$null } catch { }
        return "unit disabled and removed"
    }
}

# 1b. Remove what the App's "Update Worker" command leaves behind: the runner folder and, on
#     Windows, its on-demand scheduled task. The Linux transient unit is --collect, so it is
#     gone once it exits; selfupdate.log is handled with the other logs in step 3.
Invoke-Step "Remove self-update leftovers" {
    $removed = @()
    if ($IsWindows) {
        $selfUpdateDir = Join-Path $env:ProgramFiles "RemotePulse\SelfUpdate"
        try {
            $scheduler = New-Object -ComObject "Schedule.Service"
            $scheduler.Connect()
            $root = $scheduler.GetFolder("\")
            $task = try { $root.GetTask("RemotePulse Worker Self-Update") } catch { $null }
            if ($task) {
                $root.DeleteTask("RemotePulse Worker Self-Update", 0)
                $removed += "scheduled task"
            }
        } catch {
            Write-Host ("   Could not check the self-update scheduled task: {0}" -f $_.Exception.Message) -ForegroundColor DarkGray
        }
    } else {
        $selfUpdateDir = "/opt/remotepulse/selfupdate"
    }
    if (Test-Path $selfUpdateDir) {
        Remove-Item -Path $selfUpdateDir -Recurse -Force
        $removed += $selfUpdateDir
    }
    if ($removed.Count -eq 0) { return "nothing to remove" }
    return "removed " + ($removed -join ", ")
}

# 2. Remove the installed application files
Invoke-Step "Remove application files" {
    if (-not (Test-Path $TargetDir)) { return "nothing to remove ($TargetDir)" }

    # Snapshot MachineId and ServerUrl into $DataDir/machine-identity.json before
    # removing $TargetDir so that a reinstall with preserved pairing keeps the exact
    # same MachineId (X-Client-Id) expected by the Hub.
    try {
        $appsettingsPath = Join-Path $TargetDir "appsettings.json"
        if (Test-Path $appsettingsPath) {
            $cfg = (Get-Content $appsettingsPath -Raw | ConvertFrom-Json)
            $mId = $cfg.RemotePulse.MachineId
            $sUrl = $cfg.RemotePulse.ServerUrl
            if ($mId) {
                if (-not (Test-Path $DataDir)) { New-Item -ItemType Directory -Path $DataDir -Force | Out-Null }
                $idRecord = [ordered]@{
                    MachineId   = [string]$mId
                    ServerUrl   = [string]$sUrl
                    PreservedAt = (Get-Date).ToString("o")
                }
                $idRecord | ConvertTo-Json | Set-Content -Path $IdentityPath -Force
                if ($IsLinux) { & chmod 600 $IdentityPath 2>$null }
            }
        }
    } catch { }

    Remove-Item -Path $TargetDir -Recurse -Force
    $parentDir = Split-Path $TargetDir -Parent
    if ((Test-Path $parentDir) -and -not (Get-ChildItem -Force $parentDir)) {
        Remove-Item -Path $parentDir -Force
    }
    return "removed $TargetDir"
}

# 3. Remove or keep worker data and pairing keys
Invoke-Step "Remove or preserve worker data and keys" {
    if (-not (Test-Path $DataDir)) {
        $script:PairingState = "not present"
        $script:LogsState    = "not present"
        return "no worker data found ($DataDir)"
    }

    $isPurgeAll = $PurgeAll -or $PurgeData

    # Resolve pairing decision:
    #   -PurgeAll / -PurgeData -> $true (purge)
    #   -KeepPairing           -> $false (preserve)
    #   otherwise              -> prompt (default Y = preserve)
    $purgePairing = if ($isPurgeAll) {
        $true
    } elseif ($KeepPairing) {
        $false
    } else {
        $null
    }

    # Resolve logs decision:
    #   -PurgeAll / -PurgeData / -PurgeLogs -> $true (purge)
    #   -KeepLogs                           -> $false (preserve)
    #   otherwise                           -> prompt (default N = purge)
    $purgeLogs = if ($isPurgeAll -or $PurgeLogs) {
        $true
    } elseif ($KeepLogs) {
        $false
    } else {
        $null
    }

    # Interactive prompts if choices were not provided via CLI flags
    $hasPairing = (Test-Path $KeyPath) -or (Test-Path $PairingPath) -or (Test-Path $IdentityPath)
    if ($null -eq $purgePairing) {
        if ($hasPairing) {
            Write-Host "   Found pairing credentials at: $DataDir" -ForegroundColor Yellow
            $answer = Read-Host "   Preserve pairing credentials (client_key.dat, pairing.json) so this machine stays paired on reinstall? (Y/n)"
            $purgePairing = ($answer -match '^\s*(n|no)\s*$')
        } else {
            $purgePairing = $false
        }
    }

    $logFiles = @(Get-ChildItem -Path $DataDir -Filter "*.log" -Recurse -ErrorAction SilentlyContinue)
    if ($null -eq $purgeLogs) {
        if ($logFiles.Count -gt 0) {
            Write-Host "   Found worker log files ($($logFiles.Count)) at: $DataDir" -ForegroundColor Yellow
            $answer = Read-Host "   Preserve worker log files (*.log) for diagnostics? (y/N)"
            $purgeLogs = ($answer -notmatch '^\s*(y|yes)\s*$')
        } else {
            $purgeLogs = $false
        }
    }

    $details = @()

    # 1. Pairing files handling
    if ($purgePairing) {
        Remove-Item -Path $KeyPath, $PairingPath, $IdentityPath -Force -ErrorAction SilentlyContinue
        $script:PairingState = "removed"
        $details += "pairing removed"
    } else {
        if ($hasPairing) {
            $script:PairingState = "preserved"
            $details += "pairing preserved"
        } else {
            $script:PairingState = "not present"
        }
    }

    # 2. Logs handling
    if ($purgeLogs) {
        foreach ($lf in $logFiles) {
            Remove-Item -Path $lf.FullName -Force -ErrorAction SilentlyContinue
        }
        $script:LogsState = "removed"
        $details += "logs removed"
    } else {
        if ($logFiles.Count -gt 0) {
            $script:LogsState = "preserved"
            $details += "logs preserved"
        } else {
            $script:LogsState = "not present"
        }
    }

    # 3. Directory cleanup
    $remaining = @(Get-ChildItem -Path $DataDir -Force -ErrorAction SilentlyContinue)
    if ($remaining.Count -eq 0) {
        Remove-Item -Path $DataDir -Recurse -Force -ErrorAction SilentlyContinue
        $details += "data directory removed"
    } else {
        if ($IsLinux) {
            & chmod 700 $DataDir 2>$null
            if (Test-Path $KeyPath) { & chmod 600 $KeyPath 2>$null }
            if (Test-Path $IdentityPath) { & chmod 600 $IdentityPath 2>$null }
        }
        $details += "$DataDir kept ($($remaining.Count) item(s))"
    }

    return ($details -join ', ')
}

Show-StatusOverview

if ($script:HadError) {
    Write-Host ""
    Write-Host "One or more uninstall steps failed. Review the errors above." -ForegroundColor Red
    if ($IsWindows) { Read-Host "Press Enter to exit" }
    exit 1
} else {
    Invoke-TimedExit -TimeoutSeconds $ExitTimeoutSeconds
}
