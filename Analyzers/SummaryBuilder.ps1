<#!
.SYNOPSIS
    Builds high-level summary metadata for the diagnostics report UI.
#>

. (Join-Path -Path $PSScriptRoot -ChildPath 'AnalyzerCommon.ps1')

function Get-FirstNonEmptyString {
    param(
        [Parameter(ValueFromPipeline)]
        $Value
    )

    process {
        if ($null -eq $Value) { return }
        if ($Value -is [string]) {
            $trimmed = $Value.Trim()
            if ($trimmed) { return $trimmed }
            return
        }

        if ($Value -is [ValueType]) {
            $text = $Value.ToString().Trim()
            if ($text) { return $text }
            return
        }

        if ($Value -is [System.Collections.IEnumerable] -and -not ($Value -is [string])) {
            foreach ($item in $Value) {
                $candidate = Get-FirstNonEmptyString -Value $item
                if ($candidate) { return $candidate }
            }
            return
        }

        foreach ($prop in 'Name','Value','DisplayValue','NextHop','IPAddress','Address') {
            if ($Value.PSObject.Properties[$prop]) {
                $candidate = Get-FirstNonEmptyString -Value $Value.$prop
                if ($candidate) { return $candidate }
            }
        }

        $fallback = [string]$Value
        $fallback = $fallback.Trim()
        if ($fallback) { return $fallback }
    }
}

function Get-AllStrings {
    param(
        [Parameter(Mandatory)]
        $Value
    )

    $results = New-Object System.Collections.Generic.List[string]

    function Add-StringRecursive {
        param($InputValue)

        if ($null -eq $InputValue) { return }
        if ($InputValue -is [string]) {
            $text = $InputValue.Trim()
            if ($text) { $results.Add($text) | Out-Null }
            return
        }

        if ($InputValue -is [ValueType]) {
            $text = $InputValue.ToString().Trim()
            if ($text) { $results.Add($text) | Out-Null }
            return
        }

        if ($InputValue -is [System.Collections.IEnumerable] -and -not ($InputValue -is [string])) {
            foreach ($item in $InputValue) { Add-StringRecursive -InputValue $item }
            return
        }

        foreach ($prop in 'IPAddress','Address','NextHop','Value','DisplayValue','Name') {
            if ($InputValue.PSObject.Properties[$prop]) {
                Add-StringRecursive -InputValue $InputValue.$prop
                return
            }
        }

        $fallback = [string]$InputValue
        $fallback = $fallback.Trim()
        if ($fallback) { $results.Add($fallback) | Out-Null }
    }

    Add-StringRecursive -InputValue $Value
    return ($results | Select-Object -Unique)
}

function Format-DeviceState {
    param(
        [string]$Domain,
        [bool]$PartOfDomain,
        [bool]$IsAzureAdJoined
    )

    if ($PartOfDomain) {
        if ($Domain) { return "Domain joined ($Domain)" }
        return 'Domain joined'
    }

    $domainLabel = if ($Domain) { $Domain } else { 'Unknown domain' }
    if ($IsAzureAdJoined) {
        return "Azure AD joined ($domainLabel)"
    }

    return "Not domain joined (Domain: $domainLabel)"
}

function Parse-HostNameFromSystemInfo {
    param([string]$SystemInfoText)

    if (-not $SystemInfoText) { return $null }

    foreach ($line in [regex]::Split($SystemInfoText, '\r?\n')) {
        if ($line -match '^\s*Host\s+Name\s*:\s*(.+)$') {
            return $matches[1].Trim()
        }
    }

    return $null
}

function Test-IsWindowsServer {
    param([string]$Caption)

    if (-not $Caption) { return $null }
    return ($Caption -match '(?i)windows\s+server')
}

function Get-AzureAdJoinState {
    param([string]$DsRegCmdOutput)

    if (-not $DsRegCmdOutput) { return $false }

    foreach ($line in [regex]::Split($DsRegCmdOutput, '\r?\n')) {
        if ($line -match '^(?i)AzureAdJoined\s*:\s*(Yes|No)') {
            return ($matches[1].ToLowerInvariant() -eq 'yes')
        }
    }

    return $false
}

function Get-AnalyzerSummary {
    param(
        [Parameter(Mandatory)]
        $Context
    )

    $summary = [ordered]@{
        DeviceName      = $null
        DeviceState     = $null
        Domain          = $null
        IsDomainJoined  = $null
        IsAzureAdJoined = $false
        OperatingSystem = $null
        OSVersion       = $null
        OSBuild         = $null
        IsWindowsServer = $null
        IPv4Addresses   = @()
        Gateways        = @()
        DnsServers      = @()
        GeneratedAt     = Get-Date
    }

    $systemArtifact = Get-AnalyzerArtifact -Context $Context -Name 'system'
    if ($systemArtifact) {
        $payload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $systemArtifact)
        if ($payload) {
            if ($payload.SystemInfoText -is [string]) {
                $summary.DeviceName = Parse-HostNameFromSystemInfo -SystemInfoText $payload.SystemInfoText
            }

            if ($payload.OperatingSystem -and -not $payload.OperatingSystem.Error) {
                $os = $payload.OperatingSystem
                $summary.OperatingSystem = $os.Caption
                $summary.OSVersion = $os.Version
                $summary.OSBuild = $os.BuildNumber
                $summary.IsWindowsServer = Test-IsWindowsServer -Caption $os.Caption
            }

            if ($payload.ComputerSystem -and -not $payload.ComputerSystem.Error) {
                $cs = $payload.ComputerSystem
                if ($cs.Domain) { $summary.Domain = $cs.Domain }
                if ($null -ne $cs.PartOfDomain) { $summary.IsDomainJoined = [bool]$cs.PartOfDomain }
            }
        }
    }

    $identityArtifact = Get-AnalyzerArtifact -Context $Context -Name 'identity'
    if ($identityArtifact) {
        $payload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $identityArtifact)
        if ($payload -and $payload.DsRegCmd -is [string]) {
            $summary.IsAzureAdJoined = Get-AzureAdJoinState -DsRegCmdOutput $payload.DsRegCmd
        }
    }

    if (-not $summary.DeviceName) {
        $hostnameArtifact = Get-AnalyzerArtifact -Context $Context -Name 'network'
        if ($hostnameArtifact) {
            $payload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $hostnameArtifact)
            if ($payload -and $payload.IpConfig -is [string]) {
                $candidate = Parse-HostNameFromSystemInfo -SystemInfoText $payload.IpConfig
                if ($candidate) { $summary.DeviceName = $candidate }
            }
        }
    }

    $networkArtifact = Get-AnalyzerArtifact -Context $Context -Name 'network-adapters'
    if ($networkArtifact) {
        $payload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $networkArtifact)
        if ($payload -and $payload.IPConfig) {
            $ipv4 = New-Object System.Collections.Generic.List[string]
            $gateways = New-Object System.Collections.Generic.List[string]
            $dns = New-Object System.Collections.Generic.List[string]

            $configEntries = $payload.IPConfig
            if ($configEntries -isnot [System.Collections.IEnumerable] -or $configEntries -is [string]) {
                $configEntries = @($configEntries)
            }

            foreach ($entry in $configEntries) {
                if ($entry.PSObject.Properties['IPv4Address']) {
                    foreach ($value in Get-AllStrings -Value $entry.IPv4Address) {
                        if ($value -and $value -notmatch '^169\.254\.') { $ipv4.Add($value) | Out-Null }
                    }
                }
                if ($entry.PSObject.Properties['IPv4DefaultGateway']) {
                    foreach ($value in Get-AllStrings -Value $entry.IPv4DefaultGateway) {
                        if ($value) { $gateways.Add($value) | Out-Null }
                    }
                }
                if ($entry.PSObject.Properties['DNSServer']) {
                    foreach ($value in Get-AllStrings -Value $entry.DNSServer) {
                        if ($value) { $dns.Add($value) | Out-Null }
                    }
                }
            }

            if ($ipv4.Count -gt 0) { $summary.IPv4Addresses = ($ipv4 | Select-Object -Unique) }
            if ($gateways.Count -gt 0) { $summary.Gateways = ($gateways | Select-Object -Unique) }
            if ($dns.Count -gt 0) { $summary.DnsServers = ($dns | Select-Object -Unique) }
        }
    }

    $domainText = if ($summary.Domain) { $summary.Domain } else { 'Unknown' }
    $partOfDomain = if ($null -ne $summary.IsDomainJoined) { [bool]$summary.IsDomainJoined } else { $false }
    $summary.DeviceState = Format-DeviceState -Domain $domainText -PartOfDomain $partOfDomain -IsAzureAdJoined $summary.IsAzureAdJoined

    if (-not $summary.DeviceName) { $summary.DeviceName = 'Unknown' }
    if (-not $summary.OperatingSystem) { $summary.OperatingSystem = 'Unknown' }

    return [pscustomobject]$summary
}
