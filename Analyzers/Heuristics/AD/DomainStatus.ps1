function Resolve-AdDomainStatus {
    param(
        $Context,
        $AdPayload
    )

    $domainStatus = $null
    if ($AdPayload) {
        $domainStatus = Get-FirstPayloadProperty -Payload $AdPayload -Name 'DomainStatus'
    }

    if (-not $domainStatus) {
        Write-HeuristicDebug -Source 'AD' -Message 'Falling back to system artifact for domain status'
        $systemArtifact = Get-AnalyzerArtifact -Context $Context -Name 'system'
        if ($systemArtifact) {
            $systemPayload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $systemArtifact)
            if ($systemPayload -and $systemPayload.ComputerSystem -and -not $systemPayload.ComputerSystem.Error) {
                $domainStatus = [pscustomobject]@{
                    DomainJoined = $systemPayload.ComputerSystem.PartOfDomain
                    Domain       = $systemPayload.ComputerSystem.Domain
                    Forest       = $null
                    DomainRole   = if ($systemPayload.ComputerSystem.PSObject.Properties['DomainRole']) { $systemPayload.ComputerSystem.DomainRole } else { $null }
                }
            }
        }
    }

    if (-not $domainStatus) {
        return [pscustomobject]@{
            Available = $false
            DomainStatus = $null
            DomainJoined = $false
            DomainName = $null
            DomainRole = $null
            DomainRoleInt = $null
        }
    }

    $domainJoined = $false
    if ($domainStatus.PSObject.Properties['DomainJoined']) {
        $domainJoined = [bool]$domainStatus.DomainJoined
    }

    $domainName = if ($domainStatus.PSObject.Properties['Domain']) { $domainStatus.Domain } else { $null }
    $domainRole = $null
    $domainRoleInt = $null
    if ($domainStatus.PSObject.Properties['DomainRole']) {
        $domainRole = $domainStatus.DomainRole
        try { $domainRoleInt = [int]$domainRole } catch { $domainRoleInt = $null }
    }

    [pscustomobject]@{
        Available     = $true
        DomainStatus  = $domainStatus
        DomainJoined  = $domainJoined
        DomainName    = $domainName
        DomainRole    = $domainRole
        DomainRoleInt = $domainRoleInt
    }
}
