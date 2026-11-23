<#
.SYNOPSIS
RemotePulse Worker bootstrap - downloads, verifies and launches the installer.

Windows:
    irm https://psrun.inspired.codes/get-worker.ps1 | iex
Linux (PowerShell 7 required):
    pwsh -c "irm https://psrun.inspired.codes/get-worker.ps1 | iex"

The host in that URL is detected and passed to the installer as -HubUrl, so the
Worker is configured to poll whichever Hub served this script. The release zip is
verified against its published .sha256 before anything runs elevated.
#>

param(
    [string]$HubUrl = "",
    [switch]$SkipHashCheck,
    [switch]$NoPwshInstall,
    [switch]$NoDotnetInstall
)

$ErrorActionPreference = "Stop"

# --- OS detection (this script may run under Windows PowerShell 5.1) ------------
$onWindows = if ($null -ne $IsWindows) { $IsWindows } else { $true }
if (-not $onWindows -and $IsMacOS) {
    Write-Host "macOS is not supported by the RemotePulse Worker installer." -ForegroundColor Red
    exit 1
}
$osLabel = if ($onWindows) { "windows-x64" } else { "linux-x64" }

# --- Resolve the Hub URL from the invocation line (or -HubUrl / fallback) ------
# $MyInvocation.Line is empty in this exact "irm URL | iex" shape - the script text
# came in over a pipe/Invoke-Expression, not as a file, so PowerShell has no source
# line to report. $MyInvocation.MyCommand DOES carry the original pipeline text here
# (verified for both `irm URL | iex` typed/pasted at a prompt and `pwsh -c "irm URL |
# iex"`), so match against that instead - this is what makes the one-liner install
# the Worker against whichever Hub actually served this script, not always the
# hardcoded fallback below.
if ([string]::IsNullOrWhiteSpace($HubUrl)) {
    if ("$($MyInvocation.MyCommand)" -match 'https?://([^/\s]+)') {
        $HubUrl = "https://$($Matches[1])/"
    } else {
        $HubUrl = "https://psrun.inspired.codes/"
    }
}
$base = $HubUrl.TrimEnd('/')
$zipName = "RemotePulse-Worker-$osLabel.zip"
$zipUrl = "$base/downloads/$zipName"
$hashUrl = "$zipUrl.sha256"

$tempDir = [System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), "RemotePulse-Bootstrap")
$zipPath = [System.IO.Path]::Combine($tempDir, $zipName)
$extractDir = [System.IO.Path]::Combine($tempDir, "extracted")

if (Test-Path $tempDir) {
    try { Remove-Item -Path $tempDir -Recurse -Force -ErrorAction SilentlyContinue } catch { }
}
New-Item -ItemType Directory -Path $extractDir -Force | Out-Null

# --- 1. Download -------------------------------------------------------------
Write-Host "[1/4] Downloading Worker release ($osLabel)..." -ForegroundColor Green
Write-Host "      From: $zipUrl" -ForegroundColor DarkGray
$ProgressPreference = 'SilentlyContinue'
Invoke-WebRequest -Uri $zipUrl -OutFile $zipPath -UseBasicParsing

# --- 2. Verify against the published SHA-256 --------------------------------
if ($SkipHashCheck) {
    Write-Host "[2/4] Skipping hash verification (-SkipHashCheck)." -ForegroundColor Yellow
} else {
    Write-Host "[2/4] Verifying package integrity..." -ForegroundColor Green
    try {
        $expected = ((Invoke-WebRequest -Uri $hashUrl -UseBasicParsing).Content -split '\s+')[0].Trim().ToLower()
    } catch {
        Remove-Item $zipPath -Force -ErrorAction SilentlyContinue
        throw "Could not fetch the checksum from $hashUrl - refusing to run an unverified package. Re-run with -SkipHashCheck only if you trust the source. ($($_.Exception.Message))"
    }
    if ($expected -notmatch '^[0-9a-f]{64}$') {
        Remove-Item $zipPath -Force -ErrorAction SilentlyContinue
        throw "Checksum file at $hashUrl is malformed ('$expected')."
    }
    $actual = (Get-FileHash -Path $zipPath -Algorithm SHA256).Hash.ToLower()
    if ($actual -ne $expected) {
        Remove-Item $zipPath -Force -ErrorAction SilentlyContinue
        throw "Checksum mismatch for $zipName`n  expected $expected`n  actual   $actual`nAborting - the download may be corrupt or tampered with."
    }
    Write-Host "      SHA-256 OK ($actual)" -ForegroundColor DarkGray
}

# --- 3. Extract ------------------------------------------------------------
Write-Host "[3/4] Extracting package..." -ForegroundColor Green
Expand-Archive -Path $zipPath -DestinationPath $extractDir -Force

$installerScript = Join-Path $extractDir "Installer.ps1"
if (-not (Test-Path $installerScript)) {
    Write-Host "Error: Installer.ps1 not found in downloaded archive." -ForegroundColor Red
    exit 1
}
# Drop a marker so Installer.ps1 still knows the Hub even if run by hand from here.
Set-Content -Path (Join-Path $extractDir ".hub-url") -Value $HubUrl -NoNewline

# --- 4. Launch the installer elevated ------------------------------------
Write-Host "[4/4] Launching RemotePulse Installer..." -ForegroundColor Green
Write-Host ""

if ($onWindows) {
    # Start-Process -ArgumentList needs the file path quoted itself.
    $winArgs = @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "`"$installerScript`"", "-HubUrl", "`"$HubUrl`"")
    if ($NoPwshInstall) { $winArgs += "-NoPwshInstall" }
    if ($NoDotnetInstall) { $winArgs += "-NoDotnetInstall" }
    $pwshCmd = Get-Command pwsh.exe -ErrorAction SilentlyContinue
    $exe = if ($pwshCmd) { $pwshCmd.Source } else { "powershell.exe" }
    Start-Process -FilePath $exe -Verb RunAs -WorkingDirectory $extractDir -ArgumentList $winArgs
    Write-Host "Installer launched in an elevated window. You may close this terminal." -ForegroundColor Cyan
} else {
    # Native-command splat: pass the path bare, pwsh handles arg quoting.
    $nixArgs = @("-NoProfile", "-File", $installerScript, "-HubUrl", $HubUrl)
    if ($NoPwshInstall) { $nixArgs += "-NoPwshInstall" }
    if ($NoDotnetInstall) { $nixArgs += "-NoDotnetInstall" }
    $pwshCmd = Get-Command pwsh -ErrorAction SilentlyContinue
    if (-not $pwshCmd) {
        Write-Host "PowerShell 7 (pwsh) is required to run the installer." -ForegroundColor Red
        Write-Host "Install it for your distro: https://learn.microsoft.com/powershell/scripting/install/install-other-linux" -ForegroundColor Yellow
        exit 1
    }
    Push-Location $extractDir
    try {
        if ((id -u) -eq 0) {
            & $pwshCmd.Source @nixArgs
        } else {
            Write-Host "Elevating with sudo..." -ForegroundColor Cyan
            & sudo $pwshCmd.Source @nixArgs
        }
    } finally {
        Pop-Location
    }
}
