<#!
.SYNOPSIS
    System state heuristics covering uptime, power configuration, and hardware inventory.
#>

. (Join-Path -Path (Split-Path $PSScriptRoot -Parent) -ChildPath 'AnalyzerCommon.ps1')

foreach ($script in 'System.OperatingSystem.ps1','System.Uptime.ps1','System.Power.ps1','System.Performance.ps1','System.Startup.ps1') {
    . (Join-Path -Path $PSScriptRoot -ChildPath $script)
}

function Invoke-SystemHeuristics {
    param(
        [Parameter(Mandatory)]
        $Context
    )

    $result = New-CategoryResult -Name 'System'

    Add-SystemOperatingSystemInsights -Context $Context -CategoryResult $result
    Add-SystemUptimeInsights -Context $Context -CategoryResult $result
    Add-SystemPowerInsights -Context $Context -CategoryResult $result
    Add-SystemPerformanceInsights -Context $Context -CategoryResult $result
    Add-SystemStartupInsights -Context $Context -CategoryResult $result

    return $result
}
