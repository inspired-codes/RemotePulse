<#
.SYNOPSIS
Builds and packages the RemotePulse Worker distribution zips (Windows + Linux).

.DESCRIPTION
For each requested runtime, compiles inspired.codes.RemotePulse.Worker in Release
mode, stages a distribution package (Installer.ps1, Uninstaller.ps1, README.txt,
plus the compiled binaries in /bin) and archives it to
dist/RemotePulse-Worker-<os>-x64.zip. A matching .sha256 sidecar (sha256sum
format) is written next to each zip and both are copied into
src/Applications/inspired.codes.RemotePulse.App/wwwroot/downloads so the web
portal can serve them. get-worker.ps1 downloads the .sha256 and verifies the zip
before running the installer elevated.

.PARAMETER Runtimes
.NET RIDs to build. Default: win-x64 and linux-x64.

.PARAMETER SelfContained
Bundle the .NET runtime into each package (larger, no runtime prerequisite).
Default: framework-dependent (target needs the .NET 10 runtime).
#>

[CmdletBinding()]
param(
    [string]$Configuration = "Release",
    [string[]]$Runtimes = @("win-x64", "linux-x64"),
    [switch]$SelfContained,
    [string]$Title = "",
    [string]$Message = ""
)

$ErrorActionPreference = "Stop"

Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "  RemotePulse Worker - Release Packaging  " -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan

# This script lives in deploy/; the repo root is its parent.
$repoRoot = Split-Path -Parent $PSScriptRoot
$projectPath = Join-Path $repoRoot "src/Applications/inspired.codes.RemotePulse.Worker/inspired.codes.RemotePulse.Worker.csproj"
$distDir = Join-Path $repoRoot "dist"
$distributionTemplates = Join-Path $repoRoot "src/Applications/inspired.codes.RemotePulse.Worker/distribution"
$webDownloadsDir = Join-Path $repoRoot "src/Applications/inspired.codes.RemotePulse.App/wwwroot/downloads"

# RID -> package label (also the value get-worker.ps1 builds from $IsWindows/$IsLinux)
$labelForRid = @{ "win-x64" = "windows-x64"; "linux-x64" = "linux-x64" }

# Extract worker version from csproj
[xml]$projXml = Get-Content -Path $projectPath
$workerVersion = $projXml.Project.PropertyGroup.Version
if (-not $workerVersion) { $workerVersion = "1.0.0" }
Write-Host "Packaging Worker version: $workerVersion" -ForegroundColor Yellow

Add-Type -AssemblyName System.IO.Compression.FileSystem
if (-not (Test-Path $webDownloadsDir)) {
    New-Item -ItemType Directory -Path $webDownloadsDir -Force | Out-Null
}

$results = @()

foreach ($rid in $Runtimes) {
    $label = $labelForRid[$rid]
    if (-not $label) { throw "Unsupported runtime '$rid' (expected one of: $($labelForRid.Keys -join ', '))." }

    Write-Host "`n------------------------------------------" -ForegroundColor Cyan
    Write-Host "  Building $rid -> RemotePulse-Worker-$label.zip" -ForegroundColor Cyan
    Write-Host "------------------------------------------" -ForegroundColor Cyan

    $stagingDir = Join-Path $distDir "staging-$rid"
    $binDir = Join-Path $stagingDir "bin"
    $zipPath = Join-Path $distDir "RemotePulse-Worker-$label.zip"
    $hashPath = "$zipPath.sha256"

    # 1. Clean previous staging / artifacts for this RID
    Write-Host "`n[1/4] Preparing build directories..." -ForegroundColor Green
    if (Test-Path $stagingDir) { Remove-Item -Path $stagingDir -Recurse -Force }
    if (Test-Path $zipPath) { Remove-Item -Path $zipPath -Force }
    if (Test-Path $hashPath) { Remove-Item -Path $hashPath -Force }
    New-Item -ItemType Directory -Path $binDir -Force | Out-Null

    # 2. Publish (no debug symbols - a distribution package doesn't ship .pdb)
    Write-Host "`n[2/4] Publishing RemotePulse Worker ($Configuration, $rid)..." -ForegroundColor Green
    $publishArgs = @(
        "publish", $projectPath,
        "-c", $Configuration,
        "-o", $binDir,
        "-r", $rid,
        "--self-contained", $(if ($SelfContained) { "true" } else { "false" }),
        "-p:DebugType=none",
        "-p:DebugSymbols=false"
    )
    Write-Host "Running: dotnet $($publishArgs -join ' ')" -ForegroundColor DarkGray
    dotnet @publishArgs
    if ($LASTEXITCODE -ne 0) { Write-Error "dotnet publish failed for $rid."; exit 1 }

    # Belt and braces: strip any .pdb the build props still emitted.
    Get-ChildItem -Path $binDir -Recurse -Filter *.pdb -ErrorAction SilentlyContinue | Remove-Item -Force

    # 3. Copy installer scripts + readme
    Write-Host "`n[3/4] Copying installer scripts and documentation..." -ForegroundColor Green
    foreach ($f in @("Installer.ps1", "Uninstaller.ps1", "README.txt")) {
        Copy-Item -Path (Join-Path $distributionTemplates $f) -Destination $stagingDir -Force
    }

    # 4. Zip + sha256 sidecar + portal copy
    Write-Host "`n[4/4] Creating distribution archive ($zipPath)..." -ForegroundColor Green
    [System.IO.Compression.ZipFile]::CreateFromDirectory($stagingDir, $zipPath)
    Remove-Item -Path $stagingDir -Recurse -Force

    $hash = (Get-FileHash -Path $zipPath -Algorithm SHA256).Hash.ToLower()
    # sha256sum-compatible line: "<hash>  <filename>" (two spaces, basename only)
    Set-Content -Path $hashPath -Value ("{0}  RemotePulse-Worker-{1}.zip" -f $hash, $label)

    Copy-Item -Path $zipPath -Destination (Join-Path $webDownloadsDir "RemotePulse-Worker-$label.zip") -Force
    Copy-Item -Path $hashPath -Destination (Join-Path $webDownloadsDir "RemotePulse-Worker-$label.zip.sha256") -Force

    $sizeMb = [Math]::Round((Get-Item $zipPath).Length / 1MB, 2)
    $results += [pscustomobject]@{ Rid = $rid; Zip = "RemotePulse-Worker-$label.zip"; SizeMb = $sizeMb; Sha256 = $hash }
}

Write-Host "`n==========================================" -ForegroundColor Cyan
Write-Host "Worker release packages created successfully!" -ForegroundColor Cyan
foreach ($r in $results) {
    Write-Host ("  {0,-28} {1,6} MB  sha256={2}" -f $r.Zip, $r.SizeMb, $r.Sha256) -ForegroundColor Green
}

# 5. Generate and write modular worker-version.json metadata for portal
Write-Host "`nGenerating modular worker-version.json metadata..." -ForegroundColor Green
$winHash = ($results | Where-Object { $_.Rid -eq "win-x64" }).Sha256
$linuxHash = ($results | Where-Object { $_.Rid -eq "linux-x64" }).Sha256

$announcementTitle = if ($Title) { $Title } else { "RemotePulse Worker v$workerVersion Released" }
$announcementMsg = if ($Message) { $Message } else { "A new RemotePulse Worker version is available." }

$versionData = [ordered]@{
    version = $workerVersion
    releasedAt = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    title = $announcementTitle
    message = $announcementMsg
    link = "#install"
    windowsSha256 = $winHash
    linuxSha256 = $linuxHash
}

$jsonStr = $versionData | ConvertTo-Json -Depth 4
Set-Content -Path (Join-Path $distDir "worker-version.json") -Value $jsonStr -Encoding UTF8
Set-Content -Path (Join-Path $webDownloadsDir "worker-version.json") -Value $jsonStr -Encoding UTF8
Write-Host "  worker-version.json generated for v$workerVersion" -ForegroundColor Green

Write-Host "Staged in: dist/ and $webDownloadsDir" -ForegroundColor DarkGray
Write-Host "==========================================" -ForegroundColor Cyan
