<#
  skillvet — remove the Windows auto-start task.

  Usage:
      powershell -ExecutionPolicy Bypass -File .\uninstall-task.ps1
#>
$ErrorActionPreference = "SilentlyContinue"
$TaskName = "SkillvetWatch"

Stop-ScheduledTask   -TaskName $TaskName
Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false

Write-Host "Removed scheduled task '$TaskName' (if it existed)."
