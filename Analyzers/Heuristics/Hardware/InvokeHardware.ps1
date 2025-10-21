# Ensure supporting hardware heuristic scripts are loaded when this file is dot-sourced.
$hardwareScriptRoot = Split-Path -Parent $PSCommandPath

@(
    'Common.ps1'
    'Normalization.ps1'
    'Inventory.ps1'
    'Events.ps1'
    'Drivers.ps1'
    'Battery.ps1'
) | ForEach-Object {
    $dependencyPath = Join-Path -Path $hardwareScriptRoot -ChildPath $_
    if (Test-Path -LiteralPath $dependencyPath) {
        . $dependencyPath
    }
}

function Invoke-HardwareHeuristics {
    param(
        [Parameter(Mandatory)]
        $Context
    )

    Write-HeuristicDebug -Source 'Hardware' -Message 'Starting hardware heuristics' -Data ([ordered]@{
        ArtifactCount = if ($Context -and $Context.Artifacts) { $Context.Artifacts.Count } else { 0 }
    })

    $result = New-CategoryResult -Name 'Hardware'

    $totalIssueCount = 0

    $batteryIssues = Invoke-HardwareBatteryChecks -Context $Context -CategoryResult $result
    if ($null -ne $batteryIssues) {
        try { $totalIssueCount += [int]$batteryIssues } catch { }
    }

    $driverResult = Invoke-HardwareDriverChecks -Context $Context -CategoryResult $result
    if ($driverResult) {
        if ($driverResult.PSObject.Properties['IssueCount']) {
            try { $totalIssueCount += [int]$driverResult.IssueCount } catch { }
        }
        if ($driverResult.PSObject.Properties['Completed'] -and -not [bool]$driverResult.Completed) {
            return $result
        }
    }

    if ($totalIssueCount -eq 0) {
        Add-CategoryNormal -CategoryResult $result -Title 'Device Manager reports all drivers healthy.' -Subcategory 'Device Manager'
    }

    return $result
}
