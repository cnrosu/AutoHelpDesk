<#!
.SYNOPSIS
    System state heuristics covering uptime, power configuration, and hardware inventory.
#>

. (Join-Path -Path (Split-Path $PSScriptRoot -Parent) -ChildPath 'AnalyzerCommon.ps1')

$systemModuleRoot = Join-Path -Path (Split-Path $PSScriptRoot -Parent) -ChildPath 'System'
. (Join-Path -Path $systemModuleRoot -ChildPath 'SystemHelpers.ps1')
. (Join-Path -Path $systemModuleRoot -ChildPath 'OperatingSystem.ps1')
. (Join-Path -Path $systemModuleRoot -ChildPath 'Uptime.ps1')
. (Join-Path -Path $systemModuleRoot -ChildPath 'Power.ps1')
. (Join-Path -Path $systemModuleRoot -ChildPath 'Performance.ps1')
. (Join-Path -Path $systemModuleRoot -ChildPath 'Startup.ps1')

function Invoke-SystemHeuristics {
    param(
        [Parameter(Mandatory)]
        $Context
    )

    $result = New-CategoryResult -Name 'System'

    Invoke-SystemOperatingSystemChecks -Context $Context -Result $result
    Invoke-SystemUptimeChecks -Context $Context -Result $result
    Invoke-SystemPowerChecks -Context $Context -Result $result
    Invoke-SystemPerformanceChecks -Context $Context -Result $result
    Invoke-SystemStartupChecks -Context $Context -Result $result

    return $result
}
