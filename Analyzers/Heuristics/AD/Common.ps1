function Get-FirstPayloadProperty {
    param(
        $Payload,
        [string]$Name
    )

    if (-not $Payload) { return $null }
    if ($Payload.PSObject.Properties[$Name]) { return $Payload.$Name }
    return $null
}

function Get-ArtifactPayloadValue {
    param(
        $Artifact,
        [string]$Property
    )

    $payload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $Artifact)
    if (-not $payload) { return $null }
    if ($Property) { return Get-FirstPayloadProperty -Payload $payload -Name $Property }
    return $payload
}

function Add-StringFragment {
    param(
        [Parameter(Mandatory)]
        [System.Text.StringBuilder]$Builder,
        [Parameter(Mandatory)]
        [string]$Fragment,
        [string]$Separator = '; '
    )

    if ([string]::IsNullOrWhiteSpace($Fragment)) { return }
    if ($Builder.Length -gt 0 -and $Separator) {
        $null = $Builder.Append($Separator)
    }
    $null = $Builder.Append($Fragment)
}

function Get-CleanTimePeerName {
    param(
        [string]$Value
    )

    if ([string]::IsNullOrWhiteSpace($Value)) { return $null }

    $clean = $Value.Trim()
    $clean = $clean -replace ',0x[0-9a-fA-F]+', ''
    $clean = $clean.Trim()

    if ($clean -match '^(?<host>[^\s\(]+)\s*\(') {
        $clean = $matches['host']
    }

    return $clean.TrimEnd('.')
}

function Test-IsDomainTimePeer {
    param(
        [string]$Peer,
        [string[]]$CandidateHosts,
        [string[]]$CandidateAddresses,
        [string]$DomainName
    )

    if ([string]::IsNullOrWhiteSpace($Peer)) { return $false }

    $peerLower = $Peer.ToLowerInvariant().TrimEnd('.')

    if ($DomainName) {
        $domainLower = $DomainName.ToLowerInvariant().TrimStart('.').TrimEnd('.')
        if ($peerLower -eq $domainLower) { return $true }
        if ($peerLower.EndsWith(".$domainLower")) { return $true }
    }

    if ($CandidateHosts) {
        foreach ($host in $CandidateHosts) {
            if ([string]::IsNullOrWhiteSpace($host)) { continue }
            $hostLower = $host.ToLowerInvariant().TrimEnd('.')
            if ($peerLower -eq $hostLower) { return $true }
            $short = ($hostLower -split '\.')[0]
            if ($short -and $peerLower -eq $short) { return $true }
        }
    }

    if ($CandidateAddresses) {
        foreach ($address in $CandidateAddresses) {
            if ([string]::IsNullOrWhiteSpace($address)) { continue }
            if ($peerLower -eq $address.ToLowerInvariant()) { return $true }
        }
    }

    return $false
}
