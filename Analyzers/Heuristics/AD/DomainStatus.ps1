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
        Write-HeuristicDebug -Source 'AD' -Message 'Falling back to msinfo32 summary for domain status'
        $msinfoDomain = Get-MsinfoDomainContext -Context $Context
        if ($msinfoDomain) {
            $domainStatus = [pscustomobject]@{
                DomainJoined = $msinfoDomain.PartOfDomain
                Domain       = $msinfoDomain.Domain
                Forest       = $null
                DomainRole   = $msinfoDomain.DomainRole
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
