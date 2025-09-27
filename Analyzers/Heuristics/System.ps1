<#!
.SYNOPSIS
    System state heuristics covering uptime, power configuration, and hardware inventory.
#>

. (Join-Path -Path (Split-Path $PSScriptRoot -Parent) -ChildPath 'AnalyzerCommon.ps1')

$systemModuleRoot = Join-Path -Path $PSScriptRoot -ChildPath 'System'
if (Test-Path -LiteralPath $systemModuleRoot) {
    Get-ChildItem -Path $systemModuleRoot -Filter 'System.*.ps1' -File |
        Sort-Object Name |
        ForEach-Object { . $_.FullName }
}

function Invoke-SystemHeuristics {
    param(
        [Parameter(Mandatory)]
        $Context
    )

    $result = New-CategoryResult -Name 'System'

    Update-SystemOperatingSystemInsights -Context $Context -Result $result
    Update-SystemUptimeInsights           -Context $Context -Result $result
    Update-SystemPowerInsights            -Context $Context -Result $result
    Update-SystemStabilityInsights        -Context $Context -Result $result
    Update-SystemPerformanceInsights      -Context $Context -Result $result
    Update-SystemPendingRebootInsights    -Context $Context -Result $result
    Update-SystemStartupInsights          -Context $Context -Result $result

    return $result
}
