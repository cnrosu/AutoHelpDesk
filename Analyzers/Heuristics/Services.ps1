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
            $services = $payload.Services
            if ($services -is [System.Collections.IEnumerable] -and -not ($services -is [string])) {
                $services = @($services)
            } else {
                $services = @($services)
            }

            $lookup = @{}
            foreach ($service in $services) {
                if (-not $service) { continue }
                if ($service.PSObject.Properties['Name']) {
                    $lookup[[string]$service.Name] = $service
                }
            }

            if ($lookup.ContainsKey('BITS')) {
                $bits = $lookup['BITS']
                $status = if ($bits.PSObject.Properties['State']) { [string]$bits.State } elseif ($bits.PSObject.Properties['Status']) { [string]$bits.Status } else { 'Unknown' }
                $startMode = if ($bits.PSObject.Properties['StartMode']) { [string]$bits.StartMode } elseif ($bits.PSObject.Properties['StartType']) { [string]$bits.StartType } else { 'Unknown' }
                $statusNorm = if ($status) { $status.ToLowerInvariant() } else { '' }
                $startNorm = if ($startMode) { $startMode.ToLowerInvariant() } else { '' }

                if ($startNorm -like 'auto*' -and $statusNorm -notlike 'running') {
                    Add-CategoryIssue -CategoryResult $result -Severity 'high' -Title 'BITS stopped — background transfers for updates/AV/Office.' -Evidence ("Status: {0}; StartType: {1}" -f $status, $startMode)
                } elseif ($startNorm -eq 'manual' -and $statusNorm -notlike 'running') {
                    Add-CategoryIssue -CategoryResult $result -Severity 'medium' -Title 'BITS stopped (Manual start) — background transfers for updates/AV/Office.' -Evidence ("Status: {0}; StartType: {1}" -f $status, $startMode)
                } elseif ($startNorm -like 'disabled*') {
                    Add-CategoryIssue -CategoryResult $result -Severity 'high' -Title 'BITS disabled — background transfers for updates/AV/Office.' -Evidence ("Status: {0}; StartType: {1}" -f $status, $startMode)
                }
            }

            if ($lookup.ContainsKey('Spooler')) {
                $spooler = $lookup['Spooler']
                $status = if ($spooler.PSObject.Properties['State']) { [string]$spooler.State } elseif ($spooler.PSObject.Properties['Status']) { [string]$spooler.Status } else { 'Unknown' }
                $startMode = if ($spooler.PSObject.Properties['StartMode']) { [string]$spooler.StartMode } elseif ($spooler.PSObject.Properties['StartType']) { [string]$spooler.StartType } else { 'Unknown' }
                if ($status -notmatch '(?i)running') {
                    Add-CategoryIssue -CategoryResult $result -Severity 'high' -Title ("Print Spooler service not running (Status: {0}, StartType: {1})." -f $status, $startMode) -Evidence ("Status: {0}; StartType: {1}" -f $status, $startMode)
                }
            }

            $stoppedAuto = $services | Where-Object {
                ($_.StartMode -eq 'Auto' -or $_.StartType -eq 'Automatic') -and ($_.State -ne 'Running' -and $_.Status -ne 'Running')
            }
            if ($stoppedAuto.Count -gt 0) {
                $summary = $stoppedAuto | Select-Object -First 5 | ForEach-Object { "{0} ({1})" -f $_.DisplayName, ($_.State ? $_.State : $_.Status) }
                Add-CategoryIssue -CategoryResult $result -Severity 'medium' -Title 'Automatic services not running' -Evidence ($summary -join "`n")
            } else {
                Add-CategoryNormal -CategoryResult $result -Title 'Automatic services running'
            }
        } elseif ($payload.Services.Error) {
            Add-CategoryIssue -CategoryResult $result -Severity 'high' -Title 'Unable to query services' -Evidence $payload.Services.Error
        }
    } else {
        Add-CategoryIssue -CategoryResult $result -Severity 'high' -Title 'Services artifact missing'
    }

    return $result
}
