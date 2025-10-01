function Invoke-SystemPowerChecks {
    param(
        [Parameter(Mandatory)]
        $Context,
        [Parameter(Mandatory)]
        $Result
    )

    Write-HeuristicDebug -Source 'System/Power' -Message 'Starting power configuration checks'

    $powerArtifact = Get-AnalyzerArtifact -Context $Context -Name 'power'
    Write-HeuristicDebug -Source 'System/Power' -Message 'Resolved power artifact' -Data ([ordered]@{
        Found = [bool]$powerArtifact
    })
    if (-not $powerArtifact) { return }

    $payload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $powerArtifact)
    Write-HeuristicDebug -Source 'System/Power' -Message 'Evaluating power payload' -Data ([ordered]@{
        HasPayload = [bool]$payload
    })
    if ($payload -and $payload.FastStartup -and -not $payload.FastStartup.Error) {
        $fast = $payload.FastStartup
        if ($fast.HiberbootEnabled -eq 1) {
            Add-CategoryIssue -CategoryResult $Result -Severity 'warning' -Title 'Fast Startup (Fast Boot) is enabled. Disable Fast Startup for consistent shutdown and troubleshooting.' -Evidence 'Fast Startup keeps Windows in a hybrid hibernation state and can mask reboot-dependent fixes.' -Subcategory 'Power Configuration'
        } else {
            Add-CategoryNormal -CategoryResult $Result -Title 'Fast Startup disabled' -Subcategory 'Power Configuration'
        }
    } elseif ($payload -and $payload.FastStartup -and $payload.FastStartup.Error) {
        Add-CategoryIssue -CategoryResult $Result -Severity 'info' -Title 'Unable to read Fast Startup configuration' -Evidence $payload.FastStartup.Error -Subcategory 'Power Configuration'
    }
}
