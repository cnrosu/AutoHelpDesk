function Invoke-SystemPerformanceChecks {
    param(
        [Parameter(Mandatory)]
        $Context,
        [Parameter(Mandatory)]
        $Result
    )

    Write-HeuristicDebug -Source 'System/Performance' -Message 'Starting performance checks'

    $performanceArtifact = Get-AnalyzerArtifact -Context $Context -Name 'performance'
    Write-HeuristicDebug -Source 'System/Performance' -Message 'Resolved performance artifact' -Data ([ordered]@{
        Found = [bool]$performanceArtifact
    })
    if (-not $performanceArtifact) { return }

    $payload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $performanceArtifact)
    Write-HeuristicDebug -Source 'System/Performance' -Message 'Evaluating performance payload' -Data ([ordered]@{
        HasPayload = [bool]$payload
    })
    if ($payload -and $payload.Memory -and -not $payload.Memory.Error) {
        $memory = $payload.Memory
        if ($memory.TotalVisibleMemory -and $memory.FreePhysicalMemory) {
            $totalMb = [double]$memory.TotalVisibleMemory
            $freeMb = [double]$memory.FreePhysicalMemory
            if ($totalMb -gt 0) {
                $usedPct = [math]::Round((($totalMb - $freeMb) / $totalMb) * 100, 1)
                Add-CategoryCheck -CategoryResult $Result -Name 'Memory utilization (%)' -Status ([string]$usedPct)
                if ($usedPct -ge 90) {
                    Add-CategoryIssue -CategoryResult $Result -Severity 'medium' -Title 'High memory utilization detected' -Evidence ("Used memory percentage: {0}%" -f $usedPct) -Subcategory 'Performance'
                }
            }
        }
    }

    if ($payload -and $payload.TopCpuProcesses) {
        if (($payload.TopCpuProcesses | Where-Object { $_.Error }).Count -gt 0) {
            Add-CategoryIssue -CategoryResult $Result -Severity 'info' -Title 'Unable to enumerate running processes' -Subcategory 'Performance'
        } else {
            $topProcess = $payload.TopCpuProcesses | Select-Object -First 1
            if ($topProcess -and $topProcess.CPU -gt 0) {
                Add-CategoryCheck -CategoryResult $Result -Name 'Top CPU process' -Status ($topProcess.Name) -Details ("CPU time: {0}" -f $topProcess.CPU)
            }
        }
    }
}
