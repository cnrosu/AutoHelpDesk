function Invoke-SystemRegistryChecks {
    param(
        [Parameter(Mandatory)]
        $Context,
        [Parameter(Mandatory)]
        $Result
    )

    Write-HeuristicDebug -Source 'System/Registry' -Message 'Starting registry heuristics'

    $artifact = Get-AnalyzerArtifact -Context $Context -Name 'registry-health'
    if (-not $artifact) {
        Add-CategoryIssue -CategoryResult $Result -Severity 'info' -Subcategory 'Integrity' -Title 'Registry health artifact missing, so registry hygiene issues cannot be reviewed from this data set.'
        return
    }

    $payload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $artifact)
    if (-not $payload) {
        Add-CategoryIssue -CategoryResult $Result -Severity 'info' -Subcategory 'Integrity' -Title 'Registry health payload empty, so registry hygiene issues cannot be reviewed from this data set.'
        return
    }

    $checksNode = $null
    if ($payload.PSObject.Properties['Checks']) { $checksNode = $payload.Checks }

    $checks = @()
    if ($checksNode) {
        if ($checksNode -is [System.Collections.IEnumerable] -and -not ($checksNode -is [string])) {
            $checks = @($checksNode)
        } else {
            $checks = @($checksNode)
        }
    }

    Write-HeuristicDebug -Source 'System/Registry' -Message 'Registry checks resolved' -Data ([ordered]@{
        Count = $checks.Count
    })

    Add-CategoryCheck -CategoryResult $Result -Name 'Registry checks collected' -Status ([string]$checks.Count)

    $metadata = $null
    if ($payload.PSObject.Properties['Metadata']) { $metadata = $payload.Metadata }
    if ($metadata -and $metadata.PSObject.Properties['GeneratedAt'] -and $metadata.GeneratedAt) {
        Add-CategoryCheck -CategoryResult $Result -Name 'Registry checks generated at' -Status ([string]$metadata.GeneratedAt)
    }

    if ($checks.Count -eq 0) {
        Add-CategoryNormal -CategoryResult $Result -Title 'Registry hygiene checks reported no issues.' -Subcategory 'Integrity'
        return
    }

    $allowedSeverities = @('critical','high','medium','low','warning','info')

    foreach ($check in $checks) {
        if (-not $check) { continue }

        $title = $null
        if ($check.PSObject.Properties['Title']) { $title = [string]$check.Title }
        if ([string]::IsNullOrWhiteSpace($title)) { continue }

        $severity = 'info'
        if ($check.PSObject.Properties['Severity'] -and $check.Severity) {
            $severity = [string]$check.Severity
        }
        $severity = $severity.ToLowerInvariant()
        if ($allowedSeverities -notcontains $severity) { $severity = 'info' }

        $subcategory = 'Integrity'
        if ($check.PSObject.Properties['Subcategory'] -and $check.Subcategory) {
            $subcategory = [string]$check.Subcategory
        }

        $evidence = $null
        if ($check.PSObject.Properties['Evidence']) { $evidence = $check.Evidence }

        $remediation = $null
        if ($check.PSObject.Properties['Remediation']) { $remediation = [string]$check.Remediation }

        $checkId = $null
        if ($check.PSObject.Properties['Id']) { $checkId = [string]$check.Id }

        Add-CategoryIssue -CategoryResult $Result -Severity $severity -Subcategory $subcategory -Title $title -Evidence $evidence -Remediation $remediation -CheckId $checkId
    }
}
