<#!
.SYNOPSIS
    Active Directory health heuristics focused on discovery, reachability, secure channel, time, Kerberos, and GPO posture.
#>

. (Join-Path -Path (Split-Path $PSScriptRoot -Parent) -ChildPath 'AnalyzerCommon.ps1')

$adModuleRoot = Join-Path -Path $PSScriptRoot -ChildPath 'AD'
. (Join-Path -Path $adModuleRoot -ChildPath 'Common.ps1')
. (Join-Path -Path $adModuleRoot -ChildPath 'DomainStatus.ps1')
. (Join-Path -Path $adModuleRoot -ChildPath 'DiscoveryConnectivity.ps1')
. (Join-Path -Path $adModuleRoot -ChildPath 'Time.ps1')
. (Join-Path -Path $adModuleRoot -ChildPath 'SecureChannel.ps1')
. (Join-Path -Path $adModuleRoot -ChildPath 'Kerberos.ps1')
. (Join-Path -Path $adModuleRoot -ChildPath 'GroupPolicy.ps1')
. (Join-Path -Path $adModuleRoot -ChildPath 'Identity.ps1')

function Invoke-ADHeuristics {
    param(
        [Parameter(Mandatory)]
        $Context
    )

    Write-HeuristicDebug -Source 'AD' -Message 'Starting Active Directory heuristics evaluation' -Data ([ordered]@{
        ArtifactCount = $( if ($Context -and $Context.Artifacts) { $Context.Artifacts.Count } else { 0 } )
    })

    $result = New-CategoryResult -Name 'Active Directory Health'

    $adArtifact = Get-AnalyzerArtifact -Context $Context -Name 'ad-health'
    Write-HeuristicDebug -Source 'AD' -Message 'Resolved ad-health artifact' -Data ([ordered]@{
        Found = [bool]$adArtifact
    })
    $adPayload = Get-ArtifactPayloadValue -Artifact $adArtifact -Property $null

    $domainStatusInfo = Resolve-AdDomainStatus -Context $Context -AdPayload $adPayload
    if (-not $domainStatusInfo.Available) {
        Write-HeuristicDebug -Source 'AD' -Message 'Domain status unavailable; reporting collection issue'
        Add-CategoryIssue -CategoryResult $result -Severity 'info' -Title 'AD health data unavailable, so Active Directory reachability is unknown.' -Subcategory 'Collection'
        return $result
    }

    if (-not $domainStatusInfo.DomainJoined) {
        Write-HeuristicDebug -Source 'AD' -Message 'System not domain joined; marking AD as not applicable'
        Add-CategoryNormal -CategoryResult $result -Title 'AD not applicable' -Subcategory 'Discovery'
        return $result
    }

    if ($domainStatusInfo.DomainName) {
        Add-CategoryNormal -CategoryResult $result -Title ("Domain joined: {0}" -f $domainStatusInfo.DomainName) -Subcategory 'Discovery'
    }

    $discovery     = if ($adPayload) { Get-FirstPayloadProperty -Payload $adPayload -Name 'Discovery' } else { $null }
    $reachability  = if ($adPayload) { Get-FirstPayloadProperty -Payload $adPayload -Name 'Reachability' } else { $null }
    $sysvol        = if ($adPayload) { Get-FirstPayloadProperty -Payload $adPayload -Name 'Sysvol' } else { $null }
    $timeInfo      = if ($adPayload) { Get-FirstPayloadProperty -Payload $adPayload -Name 'Time' } else { $null }
    $kerberosInfo  = if ($adPayload) { Get-FirstPayloadProperty -Payload $adPayload -Name 'Kerberos' } else { $null }
    $secureInfo    = if ($adPayload) { Get-FirstPayloadProperty -Payload $adPayload -Name 'Secure' } else { $null }
    $gpoInfo       = if ($adPayload) { Get-FirstPayloadProperty -Payload $adPayload -Name 'Gpo' } else { $null }

    $discoveryState = Add-AdDiscoveryFindings -Result $result -Discovery $discovery
    $connectivityState = Add-AdConnectivityFindings -Result $result -Reachability $reachability -Sysvol $sysvol -Candidates $discoveryState.Candidates

    $timeState = Add-AdTimeFindings -Result $result -TimeInfo $timeInfo -CandidateHosts $discoveryState.CandidateHosts -CandidateAddresses $discoveryState.CandidateAddresses -DomainName $domainStatusInfo.DomainName -DomainJoined $domainStatusInfo.DomainJoined -DomainRoleInt $domainStatusInfo.DomainRoleInt

    $secureChannelState = Add-AdSecureChannelFindings -Result $result -SecureInfo $secureInfo

    $noDcReachable = $connectivityState.FullyReachableHosts.Count -eq 0

    $null = Add-AdKerberosFindings -Result $result -KerberosInfo $kerberosInfo -NoDcReachable $noDcReachable -TimeSkewHigh $timeState.TimeSkewHigh

    Add-AdGroupPolicyFindings -Result $result -GpoInfo $gpoInfo -SharesFailingHosts $connectivityState.SharesFailingHosts -TimeSkewHigh $timeState.TimeSkewHigh

    Add-AdIdentityFindings -Result $result -Context $Context

    $eventsArtifact = Get-AnalyzerArtifact -Context $Context -Name 'events'
    if ($eventsArtifact) {
        $eventsPayload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $eventsArtifact)
        Add-AdGroupPolicyEventLogFindings -Result $result -EventsPayload $eventsPayload
    }

    return $result
}
