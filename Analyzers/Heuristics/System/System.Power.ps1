function Update-SystemPowerInsights {
    param(
        [Parameter(Mandatory)]
        $Context,

        [Parameter(Mandatory)]
        $Result
    )

    $powerArtifact = Get-AnalyzerArtifact -Context $Context -Name 'power'
    if ($powerArtifact) {
        $payload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $powerArtifact)
        if ($payload -and $payload.FastStartup -and -not $payload.FastStartup.Error) {
            $fast = $payload.FastStartup
            if ($fast.HiberbootEnabled -eq 1) {
                Add-CategoryIssue -CategoryResult $Result -Severity 'warning' -Title 'Fast Startup (Fast Boot) is enabled. Disable Fast Startup for consistent shutdown and troubleshooting.' -Evidence 'Fast Startup keeps Windows in a hybrid hibernation state and can mask reboot-dependent fixes.' -Subcategory 'Power Configuration'
            } else {
                Add-CategoryNormal -CategoryResult $Result -Title 'Fast Startup disabled'
            }
        } elseif ($payload -and $payload.FastStartup -and $payload.FastStartup.Error) {
            Add-CategoryIssue -CategoryResult $Result -Severity 'info' -Title 'Unable to read Fast Startup configuration' -Evidence $payload.FastStartup.Error -Subcategory 'Power Configuration'
        }
    }
}
