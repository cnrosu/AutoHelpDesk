<#!
.SYNOPSIS
    Active Directory heuristics focused on domain membership and identity posture.
#>

. (Join-Path -Path (Split-Path $PSScriptRoot -Parent) -ChildPath 'AnalyzerCommon.ps1')

function Invoke-ADHeuristics {
    param(
        [Parameter(Mandatory)]
        $Context
    )

    $result = New-CategoryResult -Name 'Active Directory'

    $systemArtifact = Get-AnalyzerArtifact -Context $Context -Name 'system'
    $computerSystem = $null
    if ($systemArtifact) {
        $payload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $systemArtifact)
        if ($payload -and $payload.ComputerSystem -and -not $payload.ComputerSystem.Error) {
            $computerSystem = $payload.ComputerSystem
        }
    }

    if ($computerSystem) {
        if ($computerSystem.PartOfDomain -eq $true) {
            Add-CategoryNormal -CategoryResult $result -Title ("Domain joined: {0}" -f $computerSystem.Domain)
        } else {
            Add-CategoryIssue -CategoryResult $result -Severity 'info' -Title 'Device not joined to an Active Directory domain'
        }
    }

    $identityArtifact = Get-AnalyzerArtifact -Context $Context -Name 'identity'
    if ($identityArtifact) {
        $payload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $identityArtifact)
        if ($payload -and $payload.DsRegCmd) {
            $text = if ($payload.DsRegCmd -is [string[]]) { $payload.DsRegCmd -join "`n" } else { [string]$payload.DsRegCmd }
            if ($text -match 'AzureAdJoined\s*:\s*YES') {
                Add-CategoryNormal -CategoryResult $result -Title 'Azure AD join detected'
            }
            if ($text -match 'DomainJoined\s*:\s*NO' -and $computerSystem.PartOfDomain -ne $true) {
                Add-CategoryIssue -CategoryResult $result -Severity 'low' -Title 'Device not domain joined per dsregcmd'
            }
        }
    }

    $dnsArtifact = Get-AnalyzerArtifact -Context $Context -Name 'dns'
    if ($dnsArtifact) {
        $payload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $dnsArtifact)
        if ($payload -and $payload.Resolution) {
            $adLookups = $payload.Resolution | Where-Object { $_.Name -like '*.outlook.com' -or $_.Name -like '*.microsoft.com' }
            $failures = $adLookups | Where-Object { $_.Success -eq $false }
            if ($failures.Count -gt 0 -and $computerSystem -and $computerSystem.PartOfDomain -eq $true) {
                Add-CategoryIssue -CategoryResult $result -Severity 'medium' -Title 'Domain joined but core DNS lookups failed' -Evidence ($failures | Select-Object -ExpandProperty Name -join ', ')
            }
        }
    }

    return $result
}
