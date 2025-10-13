function Invoke-HardwareHeuristics {
    param(
        [Parameter(Mandatory)]
        $Context
    )

    Write-HeuristicDebug -Source 'Hardware' -Message 'Starting hardware heuristics' -Data ([ordered]@{
        ArtifactCount = if ($Context -and $Context.Artifacts) { $Context.Artifacts.Count } else { 0 }
    })

    $result = New-CategoryResult -Name 'Hardware'
    $issueCount = 0

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

    $batteryOutcome = Invoke-HardwareBatteryHeuristic -Context $Context -CategoryResult $result
    if ($batteryOutcome -and $batteryOutcome.PSObject.Properties['IssueCount']) {
        $issueCount += [int]$batteryOutcome.IssueCount
    }

    $driverOutcome = Invoke-HardwareDriverHeuristic -Context $Context -CategoryResult $result -StartingIssueCount $issueCount
    if ($driverOutcome) {
        if ($driverOutcome.PSObject.Properties['IssueCount']) {
            $issueCount = [int]$driverOutcome.IssueCount
        }
        if ($driverOutcome.PSObject.Properties['ShouldReturn'] -and $driverOutcome.ShouldReturn) {
            return $result
        }
    }

    return $result
}
