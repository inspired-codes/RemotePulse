<#
.SYNOPSIS
Installs and starts the RemotePulse Worker as a background service (PowerShell 7).
Cross-platform: a Windows Service on Windows, a systemd unit on Linux.

.DESCRIPTION
Non-interactive. Installs the Worker binaries from the ./bin directory of the
extracted release package, secures the private key file, and registers + starts
the service:
  - Windows: %ProgramFiles%\RemotePulse\Worker, service "RemotePulseWorker",
    data in %ProgramData%\RemotePulse.
  - Linux:   /opt/remotepulse/worker, unit "remotepulse-worker.service",
    data in /var/lib/remotepulse.

There are no prompts for a Hub URL or an enrollment token - pairing happens
afterward by scanning the QR code at http://localhost:7923/ from the Mobile PWA.

The deployed appsettings.json is stamped with a stable MachineId (the Worker's
identity to the Hub - a persisted value is what keeps the pairing across service
restarts); once set, MachineId and keys are never touched again, update or not.
When -HubUrl is supplied (the get-worker.ps1 bootstrap passes the host that served
it, and also drops a .hub-url marker beside this script) and it names a different
Hub than what's currently configured, ServerUrl is repointed there - including on
an update, since an explicit -HubUrl reflects which one-liner the operator actually
ran. Everything else in an existing appsettings.json is otherwise left alone.

Requires PowerShell 7 and elevation (Administrator / root). If either is missing
the script relaunches itself elevated; on Windows it will also try to install
PowerShell 7 via winget unless -NoPwshInstall is given.
#>

[CmdletBinding()]
param(
    [int]$ExitTimeoutSeconds = 0,   # 0 = auto: 19s on reinstall/update, 8s on fresh install
    [string]$HubUrl = "",
    [switch]$NoPwshInstall,
    [switch]$NoDotnetInstall
)

# ------------------------------------------------------------------------------
# OS detection (this script may start under Windows PowerShell 5.1)
# ------------------------------------------------------------------------------
$onWindows = if ($null -ne $IsWindows) { $IsWindows } else { $true }
$onLinux   = [bool]$IsLinux
if (-not $onWindows -and -not $onLinux) {
    Write-Host "Unsupported OS - the RemotePulse Worker installer targets Windows and Linux." -ForegroundColor Red
    exit 1
}

# ------------------------------------------------------------------------------
# Bootstrap: require PowerShell 7 + elevation, relaunch if needed
# ------------------------------------------------------------------------------
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
        if (-not $pwshPath -and -not $NoPwshInstall) {
            Write-Host "PowerShell 7 not found - attempting to install it via winget..." -ForegroundColor Yellow
            $winget = Get-Command winget -ErrorAction SilentlyContinue
            if ($winget) {
                try {
                    & winget install --id Microsoft.PowerShell --exact --source winget `
                        --accept-package-agreements --accept-source-agreements --disable-interactivity
                } catch {
                    Write-Host "winget install failed: $($_.Exception.Message)" -ForegroundColor DarkYellow
                }
                # winget updates the machine PATH; refresh it for this process
                $env:Path = [Environment]::GetEnvironmentVariable('Path', 'Machine') + ';' + [Environment]::GetEnvironmentVariable('Path', 'User')
                $pwshPath = (Get-Command pwsh.exe -ErrorAction SilentlyContinue).Source
                if (-not $pwshPath) {
                    $guess = Join-Path $env:ProgramFiles "PowerShell\7\pwsh.exe"
                    if (Test-Path $guess) { $pwshPath = $guess }
                }
            } else {
                Write-Host "winget is not available on this system." -ForegroundColor DarkYellow
            }
        }
    } else {
        $pwshPath = (Get-Command pwsh -ErrorAction SilentlyContinue).Source
    }

    if (-not $pwshPath) {
        Write-Host ""
        Write-Host "PowerShell 7 is required but could not be found or installed." -ForegroundColor Red
        if ($onWindows) {
            Write-Host "Install it, then run this installer again:" -ForegroundColor Yellow
            Write-Host "    winget install --id Microsoft.PowerShell --source winget" -ForegroundColor Cyan
            Write-Host "    (or download from https://aka.ms/powershell-release)" -ForegroundColor Cyan
        } else {
            Write-Host "Install it for your distro, then run this installer again:" -ForegroundColor Yellow
            Write-Host "    https://learn.microsoft.com/powershell/scripting/install/install-other-linux" -ForegroundColor Cyan
        }
        Write-Host ""
        if ($onWindows) { Read-Host "Press Enter to exit" }
        exit 1
    }

    $missing = @()
    if (-not $isPwsh7)    { $missing += "PowerShell 7" }
    if (-not $isElevated) { $missing += $(if ($onWindows) { "Administrator rights" } else { "root" }) }
    Write-Host ("Relaunching installer with {0}..." -f ($missing -join " and ")) -ForegroundColor Yellow

    try {
        if ($onWindows) {
            # Start-Process -ArgumentList needs the file path quoted itself.
            $winArgs = @(
                "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "`"$PSCommandPath`"",
                "-ExitTimeoutSeconds", $ExitTimeoutSeconds, "-HubUrl", "`"$HubUrl`""
            )
            if ($NoPwshInstall) { $winArgs += "-NoPwshInstall" }
            if ($NoDotnetInstall) { $winArgs += "-NoDotnetInstall" }
            Start-Process -FilePath $pwshPath -Verb RunAs -WorkingDirectory $PSScriptRoot -ArgumentList $winArgs
            exit
        } else {
            # Native-command splat: bare path, pwsh handles arg quoting.
            $nixArgs = @("-NoProfile", "-File", $PSCommandPath, "-ExitTimeoutSeconds", $ExitTimeoutSeconds, "-HubUrl", $HubUrl)
            if ($NoPwshInstall) { $nixArgs += "-NoPwshInstall" }
            if ($NoDotnetInstall) { $nixArgs += "-NoDotnetInstall" }
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

# Hub URL: -HubUrl wins, else the .hub-url marker get-worker.ps1 dropped here.
if ([string]::IsNullOrWhiteSpace($HubUrl)) {
    $marker = Join-Path $PSScriptRoot ".hub-url"
    if (Test-Path $marker) { $HubUrl = (Get-Content $marker -Raw).Trim() }
}

if ($IsWindows) {
    $Platform    = "Windows"
    $ServiceName = "RemotePulseWorker"
    $TargetDir   = Join-Path $env:ProgramFiles "RemotePulse\Worker"
    $TargetExe   = Join-Path $TargetDir "RemotePulse.Worker.exe"
    $DataDir     = Join-Path $env:ProgramData "RemotePulse"
    $ExpectedBin = "RemotePulse.Worker.exe"
    $ThisOsZip   = "RemotePulse-Worker-windows-x64.zip"
} else {
    $Platform    = "Linux"
    $ServiceName = "remotepulse-worker.service"
    $UnitPath    = "/etc/systemd/system/remotepulse-worker.service"
    $TargetDir   = "/opt/remotepulse/worker"
    $TargetExe   = Join-Path $TargetDir "RemotePulse.Worker"
    $DataDir     = "/var/lib/remotepulse"
    $ExpectedBin = "RemotePulse.Worker"
    $ThisOsZip   = "RemotePulse-Worker-linux-x64.zip"
}
$LogPath       = Join-Path $DataDir "worker.log"
$KeyPath       = Join-Path $DataDir "client_key.dat"
$PairingPath   = Join-Path $DataDir "pairing.json"
$IdentityPath  = Join-Path $DataDir "machine-identity.json"
$OnboardingUrl = "http://localhost:7923/"

$script:HadError    = $false
$script:CurrentStep = "Startup"
$script:Status      = [System.Collections.Generic.List[object]]::new()
$script:DotnetBin   = $null
$script:DotnetRoot  = $null
$script:MachineId   = $null
$isUpdate           = $false

function Add-Status {
    param(
        [string]$Step,
        [ValidateSet("OK", "FAILED", "SKIPPED", "WARN")]
        [string]$Result,
        [string]$Detail = ""
    )
    $script:Status.Add([pscustomobject]@{ Step = $Step; Result = $Result; Detail = $Detail })
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

function Get-ServiceState {
    if ($IsWindows) {
        $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
        if ($svc) { return [string]$svc.Status } else { return "Not installed" }
    } else {
        if (-not (Test-Path $UnitPath)) { return "Not installed" }
        try {
            $active = (& systemctl is-active $ServiceName 2>$null)
            if ($active) { return $active.Trim() } else { return "unknown" }
        } catch {
            return "unknown"
        }
    }
}

function Show-StatusOverview {
    Write-Host ""
    Write-Host "==========================================" -ForegroundColor Cyan
    Write-Host "   RemotePulse Worker - Status Overview    " -ForegroundColor Cyan
    Write-Host "==========================================" -ForegroundColor Cyan

    if ($script:Status.Count -eq 0) { Write-Host "  (no steps completed)" -ForegroundColor DarkGray }
    foreach ($item in $script:Status) {
        $color = switch ($item.Result) {
            "OK" { "Green" } "WARN" { "Yellow" } "SKIPPED" { "DarkGray" } "FAILED" { "Red" } default { "Gray" }
        }
        $line = "  [{0,-7}] {1}" -f $item.Result, $item.Step
        if ($item.Detail) { $line += " - $($item.Detail)" }
        Write-Host $line -ForegroundColor $color
    }

    $state = Get-ServiceState
    Write-Host ""
    Write-Host  "  Platform     : $Platform"
    Write-Host  "  Service name : $ServiceName"
    Write-Host ("  Service state: {0}" -f $state) -ForegroundColor $(if ($state -match 'Running|active') { "Green" } else { "Yellow" })
    Write-Host  "  Install path : $TargetDir"
    Write-Host  "  Onboarding   : $OnboardingUrl"
    Write-Host  "  Worker log   : $LogPath"

    Write-Host ""
    if ($script:HadError) {
        Write-Host "  Result       : INSTALLATION FAILED" -ForegroundColor Red
    } elseif ($script:Status.Where({ $_.Result -eq "WARN" }).Count -gt 0) {
        Write-Host "  Result       : COMPLETED WITH WARNINGS" -ForegroundColor Yellow
    } else {
        Write-Host "  Result       : INSTALLATION SUCCESSFUL" -ForegroundColor Green
    }
    Write-Host "==========================================" -ForegroundColor Cyan
}

function Stop-ExistingService {
    $prevNativePref = $PSNativeCommandUseErrorActionPreference
    try {
        $PSNativeCommandUseErrorActionPreference = $false
        if ($IsWindows) {
            $existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
            if ($existing -and $existing.Status -ne "Stopped") {
                Write-Host "Stopping existing $ServiceName service..." -ForegroundColor Yellow
                try {
                    Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
                    $existing.WaitForStatus("Stopped", (New-TimeSpan -Seconds 15))
                } catch { Write-Host "Warning: service stop timed out; forcing process cleanup." -ForegroundColor DarkYellow }
            }
            Get-Process -Name "RemotePulse.Worker" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
            Get-Process -ErrorAction SilentlyContinue | Where-Object {
                try { $_.Path -and $_.Path.StartsWith($TargetDir, [System.StringComparison]::OrdinalIgnoreCase) } catch { $false }
            } | Stop-Process -Force -ErrorAction SilentlyContinue
        } else {
            if (Test-Path $UnitPath) {
                Write-Host "Stopping existing $ServiceName unit..." -ForegroundColor Yellow
                try { & systemctl stop $ServiceName 2>$null } catch { }
            }
            if (Get-Command pkill -ErrorAction SilentlyContinue) {
                try { & pkill -f "$TargetDir/RemotePulse.Worker" 2>$null } catch { }
            }
        }
    } finally {
        $PSNativeCommandUseErrorActionPreference = $prevNativePref
    }
    Start-Sleep -Milliseconds 1000
}

function Resolve-CanonicalExecutable {
    param([string]$Path)
    if (-not (Test-Path $Path)) { return $Path }
    if ($IsLinux) {
        try {
            $resolved = (& readlink -f "$Path" 2>$null)
            if ($resolved -and (Test-Path $resolved.Trim())) {
                return $resolved.Trim()
            }
        } catch { }
    } elseif ($IsWindows) {
        try {
            $item = Get-Item -LiteralPath $Path -ErrorAction SilentlyContinue
            if ($item -and $item.LinkType) {
                $target = [System.IO.File]::ResolveLinkTarget($Path, $true)
                if ($target -and (Test-Path $target.FullName)) {
                    return $target.FullName
                }
            }
        } catch { }
    }
    return (Get-Item -LiteralPath $Path).FullName
}

function Find-DotnetExecutable {
    $candidates = [System.Collections.Generic.List[string]]::new()

    # 1. PATH lookup
    $cmd = Get-Command dotnet.exe -ErrorAction SilentlyContinue
    if (-not $cmd) { $cmd = Get-Command dotnet -ErrorAction SilentlyContinue }
    if ($cmd -and $cmd.Source) { $candidates.Add($cmd.Source) }

    # 2. DOTNET_ROOT environment variable
    if ($env:DOTNET_ROOT) {
        $cand = Join-Path $env:DOTNET_ROOT $(if ($IsWindows) { "dotnet.exe" } else { "dotnet" })
        if (Test-Path $cand) { $candidates.Add($cand) }
    }

    # 3. Known standard locations
    if ($IsWindows) {
        if ($env:ProgramFiles) {
            $candidates.Add((Join-Path $env:ProgramFiles "dotnet\dotnet.exe"))
        }
        if (${env:ProgramFiles(x86)}) {
            $candidates.Add((Join-Path ${env:ProgramFiles(x86)} "dotnet\dotnet.exe"))
        }
        if ($env:LOCALAPPDATA) {
            $candidates.Add((Join-Path $env:LOCALAPPDATA "Microsoft\dotnet\dotnet.exe"))
        }
        # Registry check for installed .NET location
        try {
            $regLoc = (Get-ItemProperty -Path "HKLM:\SOFTWARE\dotnet\Setup\InstalledVersions\x64" -Name "InstallLocation" -ErrorAction SilentlyContinue).InstallLocation
            if ($regLoc) {
                $candidates.Add((Join-Path $regLoc.TrimEnd('\') "dotnet.exe"))
            }
        } catch { }
    } else {
        if ($env:SUDO_USER) {
            $candidates.Add("/home/$($env:SUDO_USER)/.dotnet/dotnet")
        }
        $candidates.Add("/usr/local/bin/dotnet")
        $candidates.Add("/usr/bin/dotnet")
        $candidates.Add("/usr/share/dotnet/dotnet")
        $candidates.Add("/usr/lib64/dotnet/dotnet")
        if ($HOME) {
            $candidates.Add("$HOME/.dotnet/dotnet")
        }
    }

    foreach ($cand in $candidates) {
        if ([string]::IsNullOrWhiteSpace($cand)) { continue }
        if (Test-Path $cand) {
            return Resolve-CanonicalExecutable $cand
        }
    }
    return $null
}

function Test-Dotnet10Prerequisites {
    param([string]$DotnetPath)
    if (-not $DotnetPath -or -not (Test-Path $DotnetPath)) { return $false }
    try {
        $runtimes = (& $DotnetPath --list-runtimes 2>&1) | Out-String
        if ($runtimes -match 'Microsoft\.AspNetCore\.App\s+10\.' -and $runtimes -match 'Microsoft\.NETCore\.App\s+10\.') {
            return $true
        }
    } catch { }
    return $false
}

function Show-Dotnet10InstallGuidance {
    param([string]$Reason = "Automatic installation was not successful")
    Write-Host ""
    Write-Host "==========================================================================" -ForegroundColor Red
    Write-Host " PREREQUISITE MISSING: .NET 10 / ASP.NET Core Runtime 10.0 (x64)         " -ForegroundColor Red
    Write-Host "==========================================================================" -ForegroundColor Red
    Write-Host " The RemotePulse Worker requires ASP.NET Core Runtime 10.0 (x64)." -ForegroundColor Yellow
    Write-Host " $Reason. Please install it manually:" -ForegroundColor Yellow
    Write-Host ""
    if ($IsWindows) {
        Write-Host " Option 1: Direct Download (.NET 10 Hosting Bundle)" -ForegroundColor Cyan
        Write-Host "   https://aka.ms/dotnet/10.0/dotnet-hosting-win.exe" -ForegroundColor White
        Write-Host ""
        Write-Host " Option 2: WinGet" -ForegroundColor Cyan
        Write-Host "   winget install Microsoft.DotNet.HostingBundle.10" -ForegroundColor White
        Write-Host ""
        Write-Host " Option 3: Official .NET Download Portal" -ForegroundColor Cyan
        Write-Host "   https://dotnet.microsoft.com/download/dotnet/10.0" -ForegroundColor White
        Write-Host "   -> Under 'Run apps - Runtime', download 'Hosting Bundle' (Windows)" -ForegroundColor DarkGray
    } else {
        Write-Host " Install ASP.NET Core Runtime 10.0 for your Linux distribution:" -ForegroundColor Cyan
        Write-Host "   https://learn.microsoft.com/dotnet/core/install/linux" -ForegroundColor White
    }
    Write-Host ""
    Write-Host " Once installed, run this installer again." -ForegroundColor Yellow
    Write-Host "==========================================================================" -ForegroundColor Red
}

function Install-Dotnet10Prerequisites {
    Write-Host "`nASP.NET Core Runtime 10.0 was not detected on this system." -ForegroundColor Yellow
    Write-Host "The RemotePulse Worker requires ASP.NET Core Runtime 10.0 (x64) to host its local" -ForegroundColor Yellow
    Write-Host "onboarding web UI and connect securely to the RemotePulse Hub." -ForegroundColor Yellow

    if ($NoDotnetInstall) {
        Show-Dotnet10InstallGuidance "-NoDotnetInstall was specified"
        throw "ASP.NET Core Runtime 10.0 is missing and -NoDotnetInstall was specified. Install it from https://dotnet.microsoft.com/download/dotnet/10.0 and re-run setup."
    }

    $canPrompt = $true
    try { $null = [Console]::KeyAvailable } catch { $canPrompt = $false }
    if ($canPrompt) {
        Write-Host ""
        $promptResp = Read-Host "Would you like to download and install .NET 10 Hosting Bundle (latest patch) automatically? [Y/n]"
        if ($promptResp -and $promptResp.Trim().ToLower() -in @('n', 'no')) {
            Show-Dotnet10InstallGuidance "Automatic installation was declined by user"
            throw "ASP.NET Core Runtime 10.0 (x64) is required but automatic installation was declined."
        }
    }

    Write-Host "`nAttempting automatic installation of ASP.NET Core Runtime 10.0..." -ForegroundColor Cyan

    if ($IsWindows) {
        # Method 1: Official Microsoft .NET 10 Hosting Bundle (.NET Runtime + ASP.NET Core Runtime)
        Write-Host "  [1/2] Downloading official Microsoft .NET 10 Hosting Bundle..." -ForegroundColor DarkCyan
        $hostingBundleUrl = "https://aka.ms/dotnet/10.0/dotnet-hosting-win.exe"
        $installerExe = Join-Path $env:TEMP "dotnet-hosting-10.0-$([guid]::NewGuid().ToString('N')).exe"
        try {
            $ProgressPreference = 'SilentlyContinue'
            Invoke-WebRequest -Uri $hostingBundleUrl -OutFile $installerExe -UseBasicParsing
            Write-Host "  Installing .NET 10 Hosting Bundle (ASP.NET Core & .NET Runtime)..." -ForegroundColor DarkCyan
            $proc = Start-Process -FilePath $installerExe -ArgumentList "/install", "/quiet", "/norestart" -Wait -PassThru
            if ($proc.ExitCode -ne 0 -and $proc.ExitCode -ne 3010) {
                Write-Host "  Hosting Bundle installer exited with code $($proc.ExitCode)" -ForegroundColor DarkYellow
            }
        } catch {
            Write-Host "  Hosting Bundle installation failed: $($_.Exception.Message)" -ForegroundColor DarkYellow
        } finally {
            if (Test-Path $installerExe) { Remove-Item $installerExe -Force -ErrorAction SilentlyContinue }
        }

        # Refresh PATH for current process
        $env:Path = [Environment]::GetEnvironmentVariable('Path', 'Machine') + ';' + [Environment]::GetEnvironmentVariable('Path', 'User')
        $found = Find-DotnetExecutable
        if ($found -and (Test-Dotnet10Prerequisites $found)) {
            Write-Host "  .NET 10 Hosting Bundle installed successfully." -ForegroundColor Green
            return $found
        }

        # Method 2: WinGet Fallback (Microsoft.DotNet.HostingBundle.10)
        $winget = Get-Command winget.exe -ErrorAction SilentlyContinue
        if ($winget) {
            Write-Host "  [2/2] Attempting winget install (Microsoft.DotNet.HostingBundle.10)..." -ForegroundColor DarkCyan
            try {
                & winget install --id Microsoft.DotNet.HostingBundle.10 --exact --source winget `
                    --accept-package-agreements --accept-source-agreements --disable-interactivity
            } catch {
                Write-Host "  winget execution failed: $($_.Exception.Message)" -ForegroundColor DarkYellow
            }

            # Refresh PATH for current process
            $env:Path = [Environment]::GetEnvironmentVariable('Path', 'Machine') + ';' + [Environment]::GetEnvironmentVariable('Path', 'User')
            $found = Find-DotnetExecutable
            if ($found -and (Test-Dotnet10Prerequisites $found)) {
                Write-Host "  .NET 10 Hosting Bundle installed successfully via WinGet." -ForegroundColor Green
                return $found
            }
        }

        # Method 3: Official Microsoft dotnet-install.ps1 (CI script fallback)
        Write-Host "  [3/3] Downloading official Microsoft dotnet-install.ps1 script..." -ForegroundColor DarkCyan
        $targetDir = Join-Path $env:ProgramFiles "dotnet"
        $installerScript = Join-Path $env:TEMP "dotnet-install-$([guid]::NewGuid().ToString('N')).ps1"
        try {
            $ProgressPreference = 'SilentlyContinue'
            Invoke-WebRequest -Uri "https://dot.net/v1/dotnet-install.ps1" -OutFile $installerScript -UseBasicParsing
            Write-Host "  Installing ASP.NET Core Runtime 10.0 into '$targetDir'..." -ForegroundColor DarkCyan
            & $installerScript -Channel 10.0 -Runtime aspnetcore -InstallDir $targetDir -Architecture x64
        } catch {
            Write-Host "  dotnet-install.ps1 failed: $($_.Exception.Message)" -ForegroundColor DarkYellow
        } finally {
            if (Test-Path $installerScript) { Remove-Item $installerScript -Force -ErrorAction SilentlyContinue }
        }

        # Set environment and registry entries for system-wide and service discovery
        if (Test-Path $targetDir) {
            $env:DOTNET_ROOT = $targetDir
            if ($env:Path -notlike "*$targetDir*") { $env:Path = "$targetDir;$env:Path" }
            try {
                [Environment]::SetEnvironmentVariable("DOTNET_ROOT", $targetDir, [EnvironmentVariableTarget]::Machine)
                $machinePath = [Environment]::GetEnvironmentVariable("Path", [EnvironmentVariableTarget]::Machine)
                if ($machinePath -notlike "*$targetDir*") {
                    [Environment]::SetEnvironmentVariable("Path", "$targetDir;$machinePath", [EnvironmentVariableTarget]::Machine)
                }
                $regPath = "HKLM:\SOFTWARE\dotnet\Setup\InstalledVersions\x64"
                if (-not (Test-Path $regPath)) { New-Item -Path $regPath -Force | Out-Null }
                Set-ItemProperty -Path $regPath -Name "InstallLocation" -Value "$targetDir\" -Force
            } catch { }
        }
    } else {
        # Linux: official dotnet-install.sh
        Write-Host "  Downloading official Microsoft dotnet-install.sh script..." -ForegroundColor DarkCyan
        $installerScript = "/tmp/dotnet-install-$([guid]::NewGuid().ToString('N')).sh"
        $installDir = "/usr/share/dotnet"
        try {
            $ProgressPreference = 'SilentlyContinue'
            Invoke-WebRequest -Uri "https://dot.net/v1/dotnet-install.sh" -OutFile $installerScript -UseBasicParsing
            & chmod +x $installerScript
            Write-Host "  Installing ASP.NET Core Runtime 10.0 into '$installDir'..." -ForegroundColor DarkCyan
            & bash $installerScript --channel 10.0 --runtime aspnetcore --install-dir $installDir
            if (Test-Path "$installDir/dotnet") {
                & ln -sf "$installDir/dotnet" /usr/local/bin/dotnet 2>$null
                try {
                    if (-not (Test-Path "/etc/dotnet")) { New-Item -ItemType Directory -Path "/etc/dotnet" -Force | Out-Null }
                    Set-Content -Path "/etc/dotnet/install_location" -Value $installDir -Force
                    Set-Content -Path "/etc/dotnet/install_location_x64" -Value $installDir -Force
                } catch { }
            }
        } catch {
            Write-Host "  dotnet-install.sh failed: $($_.Exception.Message)" -ForegroundColor DarkYellow
        } finally {
            if (Test-Path $installerScript) { Remove-Item $installerScript -Force -ErrorAction SilentlyContinue }
        }
    }

    # Verify installation
    $verifiedDotnet = Find-DotnetExecutable
    if ($verifiedDotnet -and (Test-Dotnet10Prerequisites $verifiedDotnet)) {
        Write-Host "ASP.NET Core Runtime 10.0 verified successfully ($verifiedDotnet)." -ForegroundColor Green
        return $verifiedDotnet
    }

    # If prerequisite is still missing after attempts, abort with actionable guidance
    Show-Dotnet10InstallGuidance "Automatic installation was not successful"
    throw "ASP.NET Core Runtime 10.0 (x64) is required but could not be found or installed."
}

# ------------------------------------------------------------------------------
# Main
# ------------------------------------------------------------------------------
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "   RemotePulse Worker - Setup ($Platform)  " -ForegroundColor Cyan
Write-Host ("   PowerShell {0}" -f $PSVersionTable.PSVersion) -ForegroundColor DarkGray
Write-Host "==========================================" -ForegroundColor Cyan

try {
    # 1. Validate the package matches this OS
    $script:CurrentStep = "Validate package"
    $sourceBinDir = Join-Path $PSScriptRoot "bin"
    if (-not (Test-Path $sourceBinDir)) {
        throw "The 'bin' directory was not found in '$PSScriptRoot'. Extract the complete zip archive before running the installer."
    }
    if (-not (Test-Path (Join-Path $sourceBinDir $ExpectedBin))) {
        throw "This package has no '$ExpectedBin' - it is not the $Platform build. Download $ThisOsZip for this machine."
    }
    Add-Status $script:CurrentStep "OK"

    # 1b. Environment validation & prerequisite checking (cross-platform)
    $script:CurrentStep = "Validate environment"
    $envDetail = @()

    if ($IsLinux) {
        if (-not (Get-Command systemctl -ErrorAction SilentlyContinue)) {
            throw "systemd (systemctl) is required but was not found on this system."
        }
        try {
            $glibc = (& getconf GNU_LIBC_VERSION 2>$null)
            if ($glibc -match '(\d+)\.(\d+)') {
                if ([int]$Matches[1] -lt 2 -or ([int]$Matches[1] -eq 2 -and [int]$Matches[2] -lt 28)) {
                    Add-Status $script:CurrentStep "WARN" "$glibc < 2.28 - the .NET 10 runtime may not start"
                } else {
                    $envDetail += if ($glibc -match '^glibc\s*') { $glibc } else { "glibc $glibc" }
                }
            }
        } catch { }
    }

    # Detect dotnet binary and verify ASP.NET Core Runtime 10.0
    $script:DotnetBin = Find-DotnetExecutable
    $hasDotnet10 = if ($script:DotnetBin) { Test-Dotnet10Prerequisites $script:DotnetBin } else { $false }

    if (-not $hasDotnet10) {
        $script:DotnetBin = Install-Dotnet10Prerequisites
    }

    $script:DotnetRoot = Split-Path -Parent $script:DotnetBin
    $envDetail += "ASP.NET Core 10 OK ($script:DotnetBin)"

    if ($IsLinux) {
        # Ensure /usr/local/bin/dotnet symlink exists for system-wide access (unless already there)
        if ($script:DotnetBin -ne "/usr/local/bin/dotnet") {
            try { & ln -sf "$script:DotnetBin" /usr/local/bin/dotnet 2>$null } catch { }
        }
        # Register runtime location with .NET apphost (/etc/dotnet)
        try {
            if (-not (Test-Path "/etc/dotnet")) { New-Item -ItemType Directory -Path "/etc/dotnet" -Force | Out-Null }
            Set-Content -Path "/etc/dotnet/install_location" -Value $script:DotnetRoot -Force
            Set-Content -Path "/etc/dotnet/install_location_x64" -Value $script:DotnetRoot -Force
        } catch { }
    } elseif ($IsWindows) {
        $env:DOTNET_ROOT = $script:DotnetRoot
        if ($env:Path -notlike "*$($script:DotnetRoot)*") { $env:Path = "$($script:DotnetRoot);$env:Path" }
        try {
            [Environment]::SetEnvironmentVariable("DOTNET_ROOT", $script:DotnetRoot, [EnvironmentVariableTarget]::Machine)
            $machinePath = [Environment]::GetEnvironmentVariable("Path", [EnvironmentVariableTarget]::Machine)
            if ($machinePath -notlike "*$($script:DotnetRoot)*") {
                [Environment]::SetEnvironmentVariable("Path", "$($script:DotnetRoot);$machinePath", [EnvironmentVariableTarget]::Machine)
            }
            $regPath = "HKLM:\SOFTWARE\dotnet\Setup\InstalledVersions\x64"
            if (-not (Test-Path $regPath)) { New-Item -Path $regPath -Force | Out-Null }
            Set-ItemProperty -Path $regPath -Name "InstallLocation" -Value "$($script:DotnetRoot)\" -Force
        } catch { }
    }

    if ($script:Status.Where({ $_.Step -eq "Validate environment" -and $_.Result -eq "WARN" }).Count -eq 0) {
        Add-Status $script:CurrentStep "OK" ($envDetail -join ', ')
    }

    # 2. Stop any existing service for a clean update / reinstall
    Stop-ExistingService

    # 3. Deploy binaries
    $script:CurrentStep = "Deploy binaries"
    Write-Host "`n[1/3] Deploying binaries to $TargetDir..." -ForegroundColor Green
    if (-not (Test-Path $TargetDir)) { New-Item -ItemType Directory -Path $TargetDir -Force | Out-Null }

    $existingConfig = Join-Path $TargetDir "appsettings.json"
    $backupConfig = if (Test-Path $existingConfig) { Get-Content $existingConfig -Raw } else { $null }

    $maxAttempts = 6
    for ($attempt = 1; $attempt -le $maxAttempts; $attempt++) {
        try {
            Copy-Item -Path (Join-Path $sourceBinDir "*") -Destination $TargetDir -Recurse -Force -ErrorAction Stop
            break
        } catch {
            if ($attempt -lt $maxAttempts) {
                Write-Host "File lock during copy (attempt $attempt/$maxAttempts): $($_.Exception.Message)" -ForegroundColor DarkYellow
                Stop-ExistingService
                Start-Sleep -Seconds 2
            } else { throw $_ }
        }
    }

    if ($IsLinux) {
        & chmod +x $TargetExe
    }

    # $configSource is the config to carry forward: the pre-copy backup on an update
    # (so a manually-tuned setting survives), or the freshly-copied packaged default
    # on a fresh install. Either way it gets the same ServerUrl/MachineId patching
    # below before being written back - unifying these used to mean an update's
    # -HubUrl was silently discarded (the old code just restored $backupConfig
    # verbatim), which is what kept a re-pointed Worker on its old Hub after
    # reinstalling from a different one.
    $isUpdate = [bool]$backupConfig
    $configSource = if ($backupConfig) { $backupConfig } elseif (Test-Path $existingConfig) { Get-Content $existingConfig -Raw } else { $null }

    if ($null -ne $configSource) {
        try {
            $cfg = $configSource | ConvertFrom-Json
            if ($null -eq $cfg.RemotePulse) {
                $cfg | Add-Member -NotePropertyName 'RemotePulse' -NotePropertyValue ([pscustomobject]@{}) -Force
            }
            $detail = @()

            # ServerUrl: repoint whenever -HubUrl names a Hub different from what's
            # currently configured, update or fresh install alike - an explicit
            # -HubUrl (the bootstrap one-liner's own host, or passed by hand) is a
            # deliberate signal of intent. Only a truly absent -HubUrl (e.g. running
            # Installer.ps1 by hand from an already-extracted zip, no marker) leaves
            # an existing ServerUrl untouched.
            if (-not [string]::IsNullOrWhiteSpace($HubUrl)) {
                $existingUrlProp = $cfg.RemotePulse.PSObject.Properties['ServerUrl']
                $previousUrl = if ($existingUrlProp) { $existingUrlProp.Value } else { $null }
                if ($previousUrl -ne $HubUrl) {
                    $cfg.RemotePulse | Add-Member -NotePropertyName 'ServerUrl' -NotePropertyValue $HubUrl -Force
                    $detail += if ($previousUrl) { "ServerUrl changed $previousUrl -> $HubUrl" } else { "ServerUrl=$HubUrl" }
                }
            }

            # MachineId: the Worker's identity to the Hub (X-Client-Id, signed into
            # every request). Program.cs falls back to a fresh Guid.NewGuid() when
            # it's absent, so without a persisted value the Worker changes identity
            # on every service start and loses its pairing on the first restart.
            # Only minted if genuinely missing - never touched otherwise.
            $existingId = $cfg.RemotePulse.PSObject.Properties['MachineId']
            if (-not $existingId -or [string]::IsNullOrWhiteSpace($existingId.Value)) {
                # Check for an existing identity preserved from a previous install / uninstall
                $savedIdentity = if (Test-Path $IdentityPath) {
                    try { Get-Content $IdentityPath -Raw | ConvertFrom-Json } catch { $null }
                } else { $null }

                if ($savedIdentity -and -not [string]::IsNullOrWhiteSpace($savedIdentity.MachineId)) {
                    $newId = [string]$savedIdentity.MachineId
                    $cfg.RemotePulse | Add-Member -NotePropertyName 'MachineId' -NotePropertyValue $newId -Force
                    $detail += "MachineId=$newId (restored)"
                } else {
                    $newId = [guid]::NewGuid().ToString()
                    $cfg.RemotePulse | Add-Member -NotePropertyName 'MachineId' -NotePropertyValue $newId -Force
                    $detail += "MachineId=$newId"
                }
            }

            # Persist machine-identity.json into $DataDir so it survives uninstalls with -KeepPairing
            try {
                $mId = $cfg.RemotePulse.MachineId
                $sUrl = $cfg.RemotePulse.ServerUrl
                if ($mId) {
                    $script:MachineId = [string]$mId
                    if (-not (Test-Path $DataDir)) { New-Item -ItemType Directory -Path $DataDir -Force | Out-Null }
                    $idRecord = [ordered]@{
                        MachineId   = [string]$mId
                        ServerUrl   = [string]$sUrl
                        UpdatedAt   = (Get-Date).ToString("o")
                    }
                    $idRecord | ConvertTo-Json | Set-Content -Path $IdentityPath -Force
                    if ($IsLinux) { & chmod 600 $IdentityPath 2>$null }
                }
            } catch { }

            $cfg | ConvertTo-Json -Depth 10 | Set-Content -Path $existingConfig -Force
            Add-Status $script:CurrentStep "OK" $(if ($detail) { $detail -join ', ' } elseif ($isUpdate) { 'existing appsettings.json preserved' } else { 'appsettings.json unchanged' })
        } catch {
            # Parse error: don't lose config entirely - restore the raw backup
            # verbatim on an update, or leave the freshly-copied packaged default
            # alone on a fresh install.
            if ($backupConfig) { Set-Content -Path $existingConfig -Value $backupConfig -Force }
            Add-Status $script:CurrentStep "WARN" "could not patch appsettings.json: $($_.Exception.Message)"
        }
    } else {
        Add-Status $script:CurrentStep "OK" "packaged appsettings.json default"
    }

    # 4. Secure the private key + data directory
    $script:CurrentStep = "Secure key permissions"
    Write-Host "`n[2/3] Configuring security permissions..." -ForegroundColor Green
    if (-not (Test-Path $DataDir)) { New-Item -ItemType Directory -Path $DataDir -Force | Out-Null }
    if ($IsWindows) {
        if (Test-Path $KeyPath) {
            $adminName  = try { (New-Object System.Security.Principal.SecurityIdentifier("S-1-5-32-544")).Translate([System.Security.Principal.NTAccount]).Value } catch { "*S-1-5-32-544" }
            $systemName = try { (New-Object System.Security.Principal.SecurityIdentifier("S-1-5-18")).Translate([System.Security.Principal.NTAccount]).Value } catch { "*S-1-5-18" }
            icacls "$KeyPath" /inheritance:r /grant "${systemName}:(F)" "${adminName}:(F)" | Out-Null
            if ($LASTEXITCODE -ne 0) { icacls "$KeyPath" /inheritance:r /grant "*S-1-5-18:(F)" "*S-1-5-32-544:(F)" | Out-Null }
            if ($LASTEXITCODE -ne 0) { throw "icacls failed to secure '$KeyPath' (exit code $LASTEXITCODE)." }
            Add-Status $script:CurrentStep "OK" $KeyPath
        } else {
            Add-Status $script:CurrentStep "SKIPPED" "client_key.dat will be generated on startup"
        }
    } else {
        & chmod 700 $DataDir
        if (Test-Path $KeyPath) {
            & chmod 600 $KeyPath
            Add-Status $script:CurrentStep "OK" "$KeyPath (0600), $DataDir (0700)"
        } else {
            Add-Status $script:CurrentStep "SKIPPED" "client_key.dat will be generated on startup ($DataDir secured 0700)"
        }
        if (Test-Path $IdentityPath) { & chmod 600 $IdentityPath 2>$null }
    }

    # 5. Register + start the service
    $script:CurrentStep = "Install service"
    Write-Host "`n[3/3] Registering and starting the service..." -ForegroundColor Green
    if ($IsWindows) {
        if (-not (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue)) {
            Write-Host "Registering service '$ServiceName' via $TargetExe --install..." -ForegroundColor DarkGray
            $installOutput = (& $TargetExe --install 2>&1) | Out-String
            if ($LASTEXITCODE -ne 0) {
                Write-Host ""
                Write-Host "Service registration failed with exit code $LASTEXITCODE." -ForegroundColor Red
                if ($installOutput.Trim()) {
                    Write-Host "Output from Worker executable:" -ForegroundColor Yellow
                    Write-Host $installOutput.Trim() -ForegroundColor DarkYellow
                }
                if ($LASTEXITCODE -eq 2147516547 -or $installOutput -match "You must install \.NET") {
                    throw "Service installation failed: ASP.NET Core Runtime 10.0 was not detected by $TargetExe. Verify that ASP.NET Core Runtime 10.0 (x64) is installed."
                }
                throw "Service installation (--install) failed with exit code ${LASTEXITCODE}: $($installOutput.Trim())"
            }
        }
        Write-Host "Starting service '$ServiceName' via $TargetExe --start..." -ForegroundColor DarkGray
        $startOutput = (& $TargetExe --start 2>&1) | Out-String
        if ($LASTEXITCODE -ne 0) {
            Write-Host ""
            Write-Host "Service start failed with exit code $LASTEXITCODE." -ForegroundColor Red
            if ($startOutput.Trim()) {
                Write-Host "Output from Worker executable:" -ForegroundColor Yellow
                Write-Host $startOutput.Trim() -ForegroundColor DarkYellow
            }
            if ($LASTEXITCODE -eq 2147516547 -or $startOutput -match "You must install \.NET") {
                throw "Service start failed: ASP.NET Core Runtime 10.0 was not detected by $TargetExe. Verify that ASP.NET Core Runtime 10.0 (x64) is installed."
            }
            throw "Service start (--start) failed with exit code ${LASTEXITCODE}: $($startOutput.Trim())"
        }
    } else {
        $unitLines = [System.Collections.Generic.List[string]]::new()
        $unitLines.Add("[Unit]")
        $unitLines.Add("Description=RemotePulse Worker")
        $unitLines.Add("After=network-online.target")
        $unitLines.Add("Wants=network-online.target")
        $unitLines.Add("")
        $unitLines.Add("[Service]")
        $unitLines.Add("Type=simple")
        $unitLines.Add("ExecStart=$TargetExe")
        $unitLines.Add("WorkingDirectory=$TargetDir")
        $unitLines.Add("Restart=always")
        $unitLines.Add("RestartSec=5")
        $unitLines.Add("Environment=DOTNET_ENVIRONMENT=Production")
        if ($script:DotnetRoot) {
            $unitLines.Add("Environment=DOTNET_ROOT=$($script:DotnetRoot)")
            $unitLines.Add("Environment=PATH=$($script:DotnetRoot):/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin")
        }
        $unitLines.Add("")
        $unitLines.Add("[Install]")
        $unitLines.Add("WantedBy=multi-user.target")
        $unit = $unitLines -join "`n"

        Set-Content -Path $UnitPath -Value $unit -Force
        & systemctl daemon-reload
        if ($LASTEXITCODE -ne 0) { throw "systemctl daemon-reload failed (exit code $LASTEXITCODE)." }
        & systemctl enable --now $ServiceName
        if ($LASTEXITCODE -ne 0) { throw "systemctl enable --now $ServiceName failed (exit code $LASTEXITCODE)." }
    }
    Add-Status $script:CurrentStep "OK"

    # 6. Verify running (non-fatal)
    $script:CurrentStep = "Verify service running"
    Start-Sleep -Seconds 2
    $state = Get-ServiceState
    if ($state -match 'Running|active') {
        Add-Status $script:CurrentStep "OK" $state
    } else {
        Add-Status $script:CurrentStep "WARN" "state=$state - check $LogPath"
    }

    # 7. Open onboarding UI (non-fatal), only for a fresh pairing
    $script:CurrentStep = "Open onboarding page"
    $needsPairing = (-not (Test-Path $PairingPath)) -or ((Get-Content $PairingPath -Raw -ErrorAction SilentlyContinue).Trim() -in @('', '[]'))
    if ($needsPairing) {
        try {
            if ($IsWindows) {
                Start-Process $OnboardingUrl
            } elseif (Get-Command xdg-open -ErrorAction SilentlyContinue) {
                & xdg-open $OnboardingUrl 2>$null
            }
            Add-Status $script:CurrentStep "OK" $OnboardingUrl
        } catch {
            Add-Status $script:CurrentStep "WARN" "open $OnboardingUrl manually"
        }
    } else {
        Add-Status $script:CurrentStep "SKIPPED" "already paired"
    }

    if ($needsPairing) {
        Write-Host "`nInstallation complete. Scan the QR code on $OnboardingUrl with the Mobile PWA." -ForegroundColor Green
    } else {
        Write-Host "`nInstallation complete. This machine is already paired with your phone, so no QR code is needed. Status page: $OnboardingUrl" -ForegroundColor Green
    }

    # Prompt operator to send installation confirmation report to developer
    if (-not [string]::IsNullOrWhiteSpace($HubUrl)) {
        try {
            $canPrompt = $true
            try { $null = [Console]::KeyAvailable } catch { $canPrompt = $false }
            $sendSuccessReport = $true
            if ($canPrompt) {
                Write-Host ""
                $resp = Read-Host "Send installation confirmation report to developer? [Y/n]"
                if ($resp -and $resp.Trim().ToLower() -in @('n', 'no')) {
                    $sendSuccessReport = $false
                }
            }

            if ($sendSuccessReport) {
                Write-Host "Sending installation confirmation to $HubUrl..." -ForegroundColor Cyan

                # Extract worker version from installed assembly
                $workerDll = Join-Path $TargetDir "RemotePulse.Worker.dll"
                $workerVer = if (Test-Path $workerDll) {
                    (Get-Item $workerDll).VersionInfo.ProductVersion
                } else { "unknown" }
                if ([string]::IsNullOrWhiteSpace($workerVer)) {
                    $workerVer = "unknown"
                } else {
                    $workerVer = $workerVer.Split('+')[0]
                }

                $installTimeUtc = [DateTime]::UtcNow.ToString("o")

                $successPayload = [ordered]@{
                    Source      = "Installer"
                    LogLevel    = "Information"
                    Message     = "RemotePulse Worker v$workerVer installed successfully"
                    MachineId   = $null
                    DetailsJson = [ordered]@{
                        Status                 = "Installed"
                        WorkerVersion          = $workerVer
                        InstalledAt            = $installTimeUtc
                        Platform               = $Platform
                        PowerShell             = $PSVersionTable.PSVersion.ToString()
                        OS                     = [System.Environment]::OSVersion.ToString()
                        DotnetBin              = $script:DotnetBin
                        DotnetRoot             = $script:DotnetRoot
                        CompletedSteps         = @($script:Status | Select-Object Step, Result, Detail)
                    } | ConvertTo-Json -Depth 5 -Compress
                } | ConvertTo-Json -Depth 6

                $reportUrl = "$($HubUrl.TrimEnd('/'))/api/support/report"
                Invoke-RestMethod -Uri $reportUrl -Method Post -Body $successPayload -ContentType "application/json" -TimeoutSec 5 | Out-Null
                Write-Host "Confirmation report transmitted successfully. Thank you!" -ForegroundColor Green
            }
        } catch {
            Write-Host "Could not transmit confirmation report: $($_.Exception.Message)" -ForegroundColor DarkGray
        }
    }
}
catch {
    $script:HadError = $true
    Add-Status $script:CurrentStep "FAILED" $_.Exception.Message
    Write-Host ""
    Write-Host "==========================================" -ForegroundColor Red
    Write-Host "   INSTALLATION FAILED                     " -ForegroundColor Red
    Write-Host "==========================================" -ForegroundColor Red
    Write-Host ("Step  : {0}" -f $script:CurrentStep) -ForegroundColor Red
    Write-Host ("Error : {0}" -f $_.Exception.Message) -ForegroundColor Red
    if ($_.InvocationInfo -and $_.InvocationInfo.PositionMessage) {
        Write-Host ""
        Write-Host $_.InvocationInfo.PositionMessage -ForegroundColor DarkGray
    }
    Write-Host ""
    Write-Host "Troubleshooting:" -ForegroundColor Yellow
    Write-Host "  - Worker log: $LogPath" -ForegroundColor Yellow
    Write-Host "  - Resolve the issue above, then run this installer again." -ForegroundColor Yellow

    # Prompt operator to send error report to developer (suppressed if operator deliberately declined prerequisite)
    if (-not [string]::IsNullOrWhiteSpace($HubUrl) -and $_.Exception.Message -notlike "*declined*") {
        try {
            $canPrompt = $true
            try { $null = [Console]::KeyAvailable } catch { $canPrompt = $false }
            $sendReport = $true
            if ($canPrompt) {
                Write-Host ""
                $resp = Read-Host "Send error report to developer at $HubUrl? [Y/n]"
                if ($resp -and $resp.Trim().ToLower() -in @('n', 'no')) {
                    $sendReport = $false
                }
            }

            if ($sendReport) {
                Write-Host "Sending failure diagnostics to $HubUrl..." -ForegroundColor Cyan
                $reportPayload = [ordered]@{
                    Source      = "Installer"
                    LogLevel    = "Error"
                    Message     = "Installer failed at step '$($script:CurrentStep)': $($_.Exception.Message)"
                    MachineId   = $(if ($script:MachineId) { $script:MachineId } else { $null })
                    DetailsJson = [ordered]@{
                        FailedStep     = $script:CurrentStep
                        Error          = $_.Exception.Message
                        Platform       = $Platform
                        PowerShell     = $PSVersionTable.PSVersion.ToString()
                        OS             = [System.Environment]::OSVersion.ToString()
                        MachineId      = $(if ($script:MachineId) { $script:MachineId } else { "" })
                        DotnetBin      = $script:DotnetBin
                        DotnetRoot     = $script:DotnetRoot
                        CompletedSteps = @($script:Status | Select-Object Step, Result, Detail)
                    } | ConvertTo-Json -Depth 5 -Compress
                } | ConvertTo-Json -Depth 6

                $reportUrl = "$($HubUrl.TrimEnd('/'))/api/support/report"
                Invoke-RestMethod -Uri $reportUrl -Method Post -Body $reportPayload -ContentType "application/json" -TimeoutSec 5 | Out-Null
                Write-Host "Error report transmitted successfully. Thank you!" -ForegroundColor Green
            }
        } catch {
            Write-Host "Could not transmit error report: $($_.Exception.Message)" -ForegroundColor DarkGray
        }
    }
}
finally {
    Show-StatusOverview
    if ($script:HadError) {
        Write-Host ""
        Write-Host "The installation did not finish successfully. Review the errors above." -ForegroundColor Red
        if ($IsWindows) { Read-Host "Press Enter to exit" }
        exit 1
    } else {
        $timeout = if ($ExitTimeoutSeconds -gt 0) { $ExitTimeoutSeconds } elseif ($isUpdate) { 19 } else { 8 }
        Invoke-TimedExit -TimeoutSeconds $timeout
    }
}
