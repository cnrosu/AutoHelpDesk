<#!
.SYNOPSIS
    Service health heuristics reviewing stopped automatic services and query errors.
#>

. (Join-Path -Path (Split-Path $PSScriptRoot -Parent) -ChildPath 'AnalyzerCommon.ps1')

function Invoke-ServicesHeuristics {
    param(
        [Parameter(Mandatory)]
        $Context
    )

    $result = New-CategoryResult -Name 'Services'

    $servicesArtifact = Get-AnalyzerArtifact -Context $Context -Name 'services'
    if ($servicesArtifact) {
        $payload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $servicesArtifact)
        if ($payload -and $payload.Services -and -not $payload.Services.Error) {
            $stoppedAuto = $payload.Services | Where-Object {
                ($_.StartMode -eq 'Auto' -or $_.StartType -eq 'Automatic') -and ($_.State -ne 'Running' -and $_.Status -ne 'Running')
            }
            if ($stoppedAuto.Count -gt 0) {
                $summary = $stoppedAuto | Select-Object -First 5 | ForEach-Object { "{0} ({1})" -f $_.DisplayName, ($_.State ? $_.State : $_.Status) }
                Add-CategoryIssue -CategoryResult $result -Severity 'medium' -Title 'Automatic services not running' -Evidence ($summary -join "`n")
            } else {
                Add-CategoryNormal -CategoryResult $result -Title 'Automatic services running'
            }
        } elseif ($payload.Services.Error) {
            Add-CategoryIssue -CategoryResult $result -Severity 'info' -Title 'Unable to query services' -Evidence $payload.Services.Error
        }
    } else {
        Add-CategoryIssue -CategoryResult $result -Severity 'info' -Title 'Services artifact missing'
    }

    return $result
}
