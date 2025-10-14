<#!
.SYNOPSIS
    System state heuristics covering uptime, power configuration, and hardware inventory.
#>

. (Join-Path -Path (Split-Path $PSScriptRoot -Parent) -ChildPath 'AnalyzerCommon.ps1')

$systemModuleRoot = Join-Path -Path $PSScriptRoot -ChildPath 'System'
. (Join-Path -Path $systemModuleRoot -ChildPath 'SystemHelpers.ps1')
. (Join-Path -Path $systemModuleRoot -ChildPath 'OperatingSystem.ps1')
. (Join-Path -Path $systemModuleRoot -ChildPath 'Windows11Upgrade.ps1')
. (Join-Path -Path $systemModuleRoot -ChildPath 'Uptime.ps1')
. (Join-Path -Path $systemModuleRoot -ChildPath 'PendingReboot.ps1')
. (Join-Path -Path $systemModuleRoot -ChildPath 'SystemRestore.ps1')
. (Join-Path -Path $systemModuleRoot -ChildPath 'Power.ps1')
. (Join-Path -Path $systemModuleRoot -ChildPath 'Performance.ps1')
. (Join-Path -Path $systemModuleRoot -ChildPath 'Startup.ps1')
. (Join-Path -Path $systemModuleRoot -ChildPath 'MicrosoftStore.ps1')
. (Join-Path -Path $systemModuleRoot -ChildPath 'WindowsSearch.ps1')

function Invoke-SystemHeuristics {
    param(
        [Parameter(Mandatory)]
        $Context
    )

    Write-HeuristicDebug -Source 'System' -Message 'Starting system heuristics' -Data ([ordered]@{
        ArtifactCount = if ($Context -and $Context.Artifacts) { $Context.Artifacts.Count } else { 0 }
    })

    $result = New-CategoryResult -Name 'System'

    Invoke-SystemOperatingSystemChecks -Context $Context -Result $result
    Invoke-SystemWindows11UpgradeChecks -Context $Context -Result $result
    Invoke-SystemUptimeChecks -Context $Context -Result $result
    Invoke-SystemPendingRebootChecks -Context $Context -Result $result
    Invoke-SystemRestoreChecks -Context $Context -Result $result
    Invoke-SystemPowerChecks -Context $Context -Result $result
    Invoke-SystemPerformanceChecks -Context $Context -Result $result
    Invoke-SystemStartupChecks -Context $Context -Result $result
    Invoke-SystemMicrosoftStoreChecks -Context $Context -Result $result
    Invoke-SystemWindowsSearchChecks -Context $Context -Result $result

    return $result
}
