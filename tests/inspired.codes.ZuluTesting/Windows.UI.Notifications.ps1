$msgTitle = "Hinweis"
$msgText = "Dies ist eine Benachrichtigung."

# 1. Prüfen, ob BurntToast installiert ist
$burntToastInstalled = Get-Module -ListAvailable -Name BurntToast

if (-not $burntToastInstalled) {
    Write-Host "BurntToast nicht gefunden. Versuche Installation..." -ForegroundColor Yellow
    try {
        # Installation für den aktuellen Benutzer
        Install-Module -Name BurntToast -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop
        $burntToastInstalled = $true
    }
    catch {
        Write-Host "Installation von BurntToast fehlgeschlagen: $($_.Exception.Message)" -ForegroundColor Red
        $burntToastInstalled = $false
    }
}

# 2. Benachrichtigung anzeigen
if ($burntToastInstalled) {
    # Erfolg: BurntToast nutzen
    New-BurntToastNotification -Text $msgTitle, $msgText
}
else {
    # Fallback: Windows Forms
    Write-Host "Verwende Fallback (Windows Forms)..." -ForegroundColor Gray
    Add-Type -AssemblyName System.Windows.Forms
    
    $balloon = New-Object System.Windows.Forms.NotifyIcon
    $path = Get-Process -id $pid | Select-Object -ExpandProperty Path
    $balloon.Icon = [System.Drawing.Icon]::ExtractAssociatedIcon($path)
    $balloon.BalloonTipIcon = "Info"
    $balloon.BalloonTipTitle = $msgTitle
    $balloon.BalloonTipText = $msgText
    $balloon.Visible = $true
    $balloon.ShowBalloonTip(5000)
    
    # Kurze Pause, damit das Icon Zeit hat, das Balloon-Tip zu zeigen
    Start-Sleep -Seconds 6
    $balloon.Dispose()
}