function Invoke-HardwareHeuristics {
    param(
        [Parameter(Mandatory)]
        $Context
    )

    Write-HeuristicDebug -Source 'Hardware' -Message 'Starting hardware heuristics' -Data ([ordered]@{
        ArtifactCount = if ($Context -and $Context.Artifacts) { $Context.Artifacts.Count } else { 0 }
    })

    $result = New-CategoryResult -Name 'Hardware'

    $inventorySummary = Get-HardwareInventorySummary -Context $Context
    if ($inventorySummary) {
        $cpuInfo = $inventorySummary.CPU
        $memoryInfo = $inventorySummary.Memory
        $tpmInfo = $inventorySummary.TPM
        $secureBootInfo = $inventorySummary.SecureBoot
        $modelInfo = $inventorySummary.Model
        $biosInfo = $inventorySummary.Bios
        $title = if ($inventorySummary.Title) { [string]$inventorySummary.Title } else { 'Hardware inventory summary' }
        $severity = if ($inventorySummary.Severity) { [string]$inventorySummary.Severity } else { 'info' }
        $evidence = $inventorySummary.Evidence

        Add-CategoryIssue -CategoryResult $result -Severity $severity `
            -Title $title `
            -Evidence $evidence `
            -Subcategory 'Hardware' `
            -Data @{
                Area       = 'Hardware'
                Kind       = 'Inventory'
                CPU        = $cpuInfo
                Memory     = $memoryInfo
                TPM        = $tpmInfo
                SecureBoot = $secureBootInfo
                Model      = $modelInfo
                Bios       = $biosInfo
            }
    }

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
