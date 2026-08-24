<#
  skillvet - Windows auto-start installer.

  Registers a Scheduled Task that starts the watcher automatically every time
  you log in, running hidden in the background. Run this ONCE.

  Usage (in PowerShell, from anywhere):
      powershell -ExecutionPolicy Bypass -File .\install-task.ps1

  Remove later with:  .\uninstall-task.ps1
#>

$ErrorActionPreference = "Stop"
$TaskName = "SkillvetWatch"

# Resolve the watcher script (one level up from this windows/ folder).
$here    = Split-Path -Parent $MyInvocation.MyCommand.Path
$watcher = Join-Path (Split-Path -Parent $here) "skillvet_watch.py"
if (-not (Test-Path $watcher)) {
    Write-Error "Could not find skillvet_watch.py at $watcher"
    exit 1
}

# Prefer pythonw.exe (no console window); fall back to python.exe.
$py = (Get-Command pythonw.exe -ErrorAction SilentlyContinue)
if (-not $py) { $py = (Get-Command python.exe -ErrorAction SilentlyContinue) }
if (-not $py) {
    Write-Error "Python not found on PATH. Install Python 3 and re-run."
    exit 1
}
$pyPath = $py.Source

$action   = New-ScheduledTaskAction -Execute $pyPath `
              -Argument ("`"$watcher`" watch --interval 2 --fail-on high")
$trigger  = New-ScheduledTaskTrigger -AtLogOn
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries `
              -DontStopIfGoingOnBatteries -StartWhenAvailable -Hidden

Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger `
    -Settings $settings -Description "skillvet - watch and quarantine risky Agent Skills" `
    -Force | Out-Null

Write-Host "Installed scheduled task '$TaskName'."
Write-Host "It will start the skillvet watcher automatically at each logon."
Write-Host "Start it now without logging out:  Start-ScheduledTask -TaskName $TaskName"
