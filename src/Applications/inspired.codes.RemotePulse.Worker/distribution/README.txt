================================================================================
RemotePulse Worker - Installation & Setup Guide
================================================================================

RemotePulse Worker is a lightweight, zero-trust remote administration service. It
securely executes signed, end-to-end encrypted PowerShell commands dispatched from
your RemotePulse Mobile PWA via the central Hub.

This package is OS-specific:
  - RemotePulse-Worker-windows-x64.zip  -> installs a Windows Service
  - RemotePulse-Worker-linux-x64.zip    -> installs a systemd unit
Each zip ships with a matching .sha256 checksum file.


SYSTEM REQUIREMENTS
--------------------------------------------------------------------------------
Common:
  - PowerShell 7 (pwsh) - Windows: winget install --id Microsoft.PowerShell
                          Linux:   https://learn.microsoft.com/powershell/scripting/install/install-other-linux
  - The .NET 10 Runtime (packages are framework-dependent)
  - Elevation: Administrator (Windows) / root (Linux)

Windows:
  - Windows 10 (Build 2004+), Windows 11, or Windows Server 2022+ (x64)

Linux:
  - systemd, glibc 2.28+ (x64)

The installer and uninstaller relaunch themselves elevated if needed - on Windows
under pwsh via UAC (and will try "winget install Microsoft.PowerShell" if pwsh 7
is missing; pass -NoPwshInstall to skip), on Linux via sudo.


RECOMMENDED: ONE-LINER INSTALL
--------------------------------------------------------------------------------
Windows (from any PowerShell prompt):
    irm https://psrun.inspired.codes/get-worker.ps1 | iex

Linux (PowerShell 7 required):
    pwsh -c "irm https://psrun.inspired.codes/get-worker.ps1 | iex"

The bootstrap downloads the OS-matched zip, verifies it against its published
.sha256, extracts it, and runs Installer.ps1 elevated. The Worker is configured to
poll whichever Hub served the script (the host in the URL).


MANUAL INSTALLATION (offline / air-gapped)
--------------------------------------------------------------------------------
1. Extract the entire contents of the zip for your OS.

2. Run the installer elevated:
     - Windows: right-click 'Installer.ps1' -> 'Run with PowerShell', or from an
       admin PowerShell 7 prompt:  pwsh -File .\Installer.ps1
     - Linux:   sudo pwsh ./Installer.ps1

   It is non-interactive - there are no prompts. It deploys the binaries, secures
   the private key file, then registers and starts the service.

   On a fresh install it also writes a stable MachineId into appsettings.json (the
   Worker's identity to the Hub - a persisted value is what keeps the pairing
   across service restarts). An update leaves appsettings.json alone.

3. Hub URL:
   A manual install uses the packaged default (https://psrun.inspired.codes/).
   To point the Worker at a different Hub, either:
     - Windows: "C:\Program Files\RemotePulse\Worker\RemotePulse.Worker.exe" --configure
       Linux:   /opt/remotepulse/worker/RemotePulse.Worker --configure
     - or edit "ServerUrl" in the deployed appsettings.json and restart the service:
         Windows: C:\Program Files\RemotePulse\Worker\appsettings.json
         Linux:   /opt/remotepulse/worker/appsettings.json

4. Service startup & pairing:
   - Windows: the 'RemotePulseWorker' service is installed and started.
     Linux:   the 'remotepulse-worker.service' unit is enabled and started.
   - Your browser opens http://localhost:7923/ (Linux: via xdg-open, if present).

5. Mobile PWA pairing:
   - Open the Mobile PWA: https://psrun.inspired.codes/app
   - Tap 'Pair New Client'.
   - Scan the QR code displayed on http://localhost:7923/.
   - No token is required - co-presence pairing completes in a few seconds.

6. Ready! Your Worker is now registered, securely paired, and online.


UNINSTALLATION
--------------------------------------------------------------------------------
Run the uninstaller from the same package, elevated:
  - Windows: right-click 'Uninstaller.ps1' -> 'Run with PowerShell'
  - Linux:   sudo pwsh ./Uninstaller.ps1
You are prompted whether to keep or wipe the cryptographic pairing keys
(pass -PurgeData to wipe them without prompting).


LOGS & TROUBLESHOOTING
--------------------------------------------------------------------------------
Worker log:
  Windows: C:\ProgramData\RemotePulse\worker.log
  Linux:   /var/lib/remotepulse/worker.log

Follow it live:
  Windows: Get-Content "C:\ProgramData\RemotePulse\worker.log" -Tail 30 -Wait
  Linux:   tail -f /var/lib/remotepulse/worker.log   (or: journalctl -u remotepulse-worker -f)
