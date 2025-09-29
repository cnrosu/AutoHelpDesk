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

function Convert-ToUniqueStringArray {
    param(
        [Parameter(Mandatory)]
        [System.Collections.IEnumerable]$Values
    )

    $ordered = New-Object System.Collections.Generic.List[string]
    $seen = New-Object System.Collections.Generic.HashSet[string]([System.StringComparer]::OrdinalIgnoreCase)

    foreach ($value in $Values) {
        if ($null -eq $value) { continue }
        $text = [string]$value
        if (-not $text) { continue }
        $trimmed = $text.Trim()
        if (-not $trimmed) { continue }
        if ($seen.Add($trimmed)) {
            $ordered.Add($trimmed) | Out-Null
        }
    }

    if ($ordered.Count -eq 0) { return @() }
    return $ordered.ToArray()
}

function Convert-NetworkFieldToString {
    param(
        [Parameter(ValueFromPipeline)]
        $Value,

        [string[]]$PreferredProperties = @()
    )

    $ordered = New-Object System.Collections.Generic.List[string]
    $seen = New-Object System.Collections.Generic.HashSet[string]([System.StringComparer]::OrdinalIgnoreCase)

    function Add-NetworkString {
        param([string]$Candidate)

        if ([string]::IsNullOrWhiteSpace($Candidate)) { return }
        $trimmed = $Candidate.Trim()
        if (-not $trimmed) { return }
        if ($seen.Add($trimmed)) {
            $ordered.Add($trimmed) | Out-Null
        }
    }

    function Extract-NetworkValues {
        param($Item)

        if ($null -eq $Item) { return }

        if ($Item -is [string]) {
            Add-NetworkString -Candidate $Item
            return
        }

        if ($Item -is [ValueType]) {
            Add-NetworkString -Candidate ($Item.ToString())
            return
        }

        if ($Item -is [System.Collections.IDictionary]) {
            foreach ($value in $Item.Values) { Extract-NetworkValues -Item $value }
            return
        }

        if ($Item -is [System.Collections.IEnumerable] -and -not ($Item -is [string])) {
            foreach ($element in $Item) { Extract-NetworkValues -Item $element }
            return
        }

        if ($Item.PSObject) {
            $propertiesToCheck = New-Object System.Collections.Generic.List[string]
            if ($PreferredProperties -and $PreferredProperties.Count -gt 0) {
                foreach ($prop in $PreferredProperties) {
                    if ($prop -and -not $propertiesToCheck.Contains($prop)) {
                        $propertiesToCheck.Add($prop) | Out-Null
                    }
                }
            }

            foreach ($prop in @('IPAddress','NextHop','ServerAddresses','DNSServerSearchOrder','DefaultIPGateway','Address','Value','DisplayValue')) {
                if (-not $propertiesToCheck.Contains($prop)) {
                    $propertiesToCheck.Add($prop) | Out-Null
                }
            }

            foreach ($prop in @('IPv4Address','IPv4DefaultGateway','DNSServer')) {
                if (-not $propertiesToCheck.Contains($prop)) {
                    $propertiesToCheck.Add($prop) | Out-Null
                }
            }

            $handled = $false
            foreach ($prop in $propertiesToCheck) {
                if (-not $prop) { continue }
                if ($Item.PSObject.Properties[$prop]) {
                    $handled = $true
                    Extract-NetworkValues -Item $Item.$prop
                }
            }

            if ($handled) { return }
        }

        Add-NetworkString -Candidate ([string]$Item)
    }

    Extract-NetworkValues -Item $Value

    if ($ordered.Count -eq 0) { return '' }
    return ($ordered -join ', ')
}

function Parse-IpConfigNetworkValues {
    param([string]$IpConfigText)

    $ipv4 = New-Object System.Collections.Generic.List[string]
    $gateways = New-Object System.Collections.Generic.List[string]
    $dns = New-Object System.Collections.Generic.List[string]

    if ([string]::IsNullOrWhiteSpace($IpConfigText)) {
        return [pscustomobject]@{
            IPv4     = @()
            Gateways = @()
            Dns      = @()
        }
    }

    $lines = [regex]::Split($IpConfigText, '\r?\n')
    $collectingDns = $false
    $collectingGateway = $false

    foreach ($line in $lines) {
        $raw = if ($null -ne $line) { $line.Trim() } else { '' }
        if (-not $raw) { continue }

        if ($raw -match '^(?<label>[A-Za-z0-9\s\.-]+?):\s*(?<value>.*)$') {
            $label = $matches['label'].Trim()
            $value = $matches['value']
            if ($null -ne $value) { $value = $value.Trim() }

            $collectingDns = $false
            $collectingGateway = $false

            switch -Regex ($label) {
                'IPv4\s+Address' {
                    if ($value) {
                        $clean = ($value -replace '\(Preferred\)', '')
                        $clean = ($clean -replace '\s*\(.*$','').Trim()
                        if ($clean -and $clean -notmatch '^169\.254\.') {
                            $ipv4.Add($clean) | Out-Null
                        }
                    }
                }
                'Default\s+Gateway' {
                    if ($value) {
                        $gateways.Add($value) | Out-Null
                    } else {
                        $collectingGateway = $true
                    }
                }
                'DNS\s+Servers' {
                    if ($value) {
                        $dns.Add($value) | Out-Null
                    }
                    $collectingDns = $true
                }
            }

            continue
        }

        if ($collectingGateway) {
            $gateways.Add($raw) | Out-Null
            continue
        }

        if ($collectingDns) {
            $dns.Add($raw) | Out-Null
            continue
        }
    }

    $ipv4Array = Convert-ToUniqueStringArray -Values $ipv4
    $gatewayArray = Convert-ToUniqueStringArray -Values ($gateways | Where-Object { $_ -and $_ -ne '0.0.0.0' })
    $dnsArray = Convert-ToUniqueStringArray -Values $dns

    return [pscustomobject]@{
        IPv4     = $ipv4Array
        Gateways = $gatewayArray
        Dns      = $dnsArray
    }
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
            if ($payload.SystemInfoText) {
                $systemInfoText = $payload.SystemInfoText
                if ($systemInfoText -isnot [string]) {
                    if ($systemInfoText -is [System.Collections.IEnumerable]) {
                        $systemInfoText = ($systemInfoText -join "`n")
                    } else {
                        $systemInfoText = [string]$systemInfoText
                    }
                }

                if ($systemInfoText) {
                    $summary.DeviceName = Parse-HostNameFromSystemInfo -SystemInfoText $systemInfoText
                }
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
            if ($payload -and $payload.IpConfig) {
                $ipConfigText = $payload.IpConfig
                if ($ipConfigText -isnot [string]) {
                    if ($ipConfigText -is [System.Collections.IEnumerable]) {
                        $ipConfigText = ($ipConfigText -join "`n")
                    } else {
                        $ipConfigText = [string]$ipConfigText
                    }
                }

                if ($ipConfigText) {
                    $candidate = Parse-HostNameFromSystemInfo -SystemInfoText $ipConfigText
                    if ($candidate) { $summary.DeviceName = $candidate }
                }
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
                    $ipv4Text = Convert-NetworkFieldToString -Value $entry.IPv4Address -PreferredProperties @('IPAddress','Address','Value')
                    if ($ipv4Text) {
                        foreach ($value in ($ipv4Text -split '\s*,\s*')) {
                            $trimmed = $value.Trim()
                            if ($trimmed -and $trimmed -notmatch '^169\.254\.') { $ipv4.Add($trimmed) | Out-Null }
                        }
                    }
                }
                if ($entry.PSObject.Properties['IPv4DefaultGateway']) {
                    $gatewayText = Convert-NetworkFieldToString -Value $entry.IPv4DefaultGateway -PreferredProperties @('NextHop','IPAddress','Address','DefaultIPGateway','Value')
                    if ($gatewayText) {
                        foreach ($value in ($gatewayText -split '\s*,\s*')) {
                            $trimmed = $value.Trim()
                            if ($trimmed) { $gateways.Add($trimmed) | Out-Null }
                        }
                    }
                }
                if ($entry.PSObject.Properties['DNSServer']) {
                    $dnsText = Convert-NetworkFieldToString -Value $entry.DNSServer -PreferredProperties @('ServerAddresses','Address','IPAddress','DNSServerSearchOrder','Value')
                    if ($dnsText) {
                        foreach ($value in ($dnsText -split '\s*,\s*')) {
                            $trimmed = $value.Trim()
                            if ($trimmed) { $dns.Add($trimmed) | Out-Null }
                        }
                    }
                }
            }

            if ($ipv4.Count -gt 0) { $summary.IPv4Addresses = Convert-ToUniqueStringArray -Values $ipv4 }
            if ($gateways.Count -gt 0) { $summary.Gateways = Convert-ToUniqueStringArray -Values ($gateways | Where-Object { $_ -and $_ -ne '0.0.0.0' }) }
            if ($dns.Count -gt 0) { $summary.DnsServers = Convert-ToUniqueStringArray -Values $dns }
        }
    }

    $hasIpv4 = ($summary.IPv4Addresses -and @($summary.IPv4Addresses).Count -gt 0)
    $hasGateway = ($summary.Gateways -and @($summary.Gateways).Count -gt 0)
    $hasDns = ($summary.DnsServers -and @($summary.DnsServers).Count -gt 0)

    if (-not ($hasIpv4 -and $hasGateway -and $hasDns)) {
        if (-not $hostnameArtifact) {
            $hostnameArtifact = Get-AnalyzerArtifact -Context $Context -Name 'network'
        }

        if ($hostnameArtifact) {
            $payload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $hostnameArtifact)
            if ($payload -and $payload.IpConfig) {
                $ipConfigText = $payload.IpConfig
                if ($ipConfigText -isnot [string]) {
                    if ($ipConfigText -is [System.Collections.IEnumerable]) {
                        $ipConfigText = ($ipConfigText -join "`n")
                    } else {
                        $ipConfigText = [string]$ipConfigText
                    }
                }

                if ($ipConfigText) {
                    $parsed = Parse-IpConfigNetworkValues -IpConfigText $ipConfigText
                    if ($parsed) {
                        if (-not $hasIpv4 -and $parsed.IPv4.Count -gt 0) { $summary.IPv4Addresses = $parsed.IPv4 }
                        if (-not $hasGateway -and $parsed.Gateways.Count -gt 0) { $summary.Gateways = $parsed.Gateways }
                        if (-not $hasDns -and $parsed.Dns.Count -gt 0) { $summary.DnsServers = $parsed.Dns }
                    }
                }
            }
        }
    }

    $domainText = if ($summary.Domain) { $summary.Domain } else { 'Unknown' }
    $partOfDomain = if ($null -ne $summary.IsDomainJoined) { [bool]$summary.IsDomainJoined } else { $false }
    $summary.DeviceState = Format-DeviceState -Domain $domainText -PartOfDomain $partOfDomain -IsAzureAdJoined $summary.IsAzureAdJoined

    if (-not $summary.DeviceName) { $summary.DeviceName = 'Unknown' }
    if (-not $summary.OperatingSystem) { $summary.OperatingSystem = 'Unknown' }

    return [pscustomobject]$summary
}
