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

        $visited = [System.Collections.Generic.HashSet[int]]::new()
        $stack = [System.Collections.Stack]::new()
        $null = $stack.Push($Value)

        while ($stack.Count -gt 0) {
            $current = $stack.Pop()
            if ($null -eq $current) { continue }

            if ($current -is [string]) {
                $trimmed = $current.Trim()
                if ($trimmed) { return $trimmed }
                continue
            }

            if ($current -is [ValueType]) {
                $text = $current.ToString().Trim()
                if ($text) { return $text }
                continue
            }

            $identity = [System.Runtime.CompilerServices.RuntimeHelpers]::GetHashCode($current)
            if (-not $visited.Add($identity)) { continue }

            if ($current -is [System.Collections.IEnumerable] -and -not ($current -is [string])) {
                $items = @()
                foreach ($item in $current) { $items += ,$item }
                for ($index = $items.Count - 1; $index -ge 0; $index--) {
                    $null = $stack.Push($items[$index])
                }
                continue
            }

            $properties = @('Name','Value','DisplayValue','NextHop','IPAddress','Address')
            $pushed = $false
            for ($idx = $properties.Count - 1; $idx -ge 0; $idx--) {
                $prop = $properties[$idx]
                if ($current.PSObject.Properties[$prop]) {
                    $null = $stack.Push($current.$prop)
                    $pushed = $true
                }
            }

            if ($pushed) { continue }

            $fallback = [string]$current
            $fallback = $fallback.Trim()
            if ($fallback) { return $fallback }
        }
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

function Get-AllStrings {
    param(
        [Parameter(Mandatory)]
        $Value
    )

    $results = New-Object System.Collections.Generic.List[string]
    $stringSet = New-Object System.Collections.Generic.HashSet[string]([System.StringComparer]::Ordinal)
    $visited = [System.Collections.Generic.HashSet[int]]::new()
    $stack = [System.Collections.Stack]::new()
    $null = $stack.Push($Value)

    while ($stack.Count -gt 0) {
        $current = $stack.Pop()
        if ($null -eq $current) { continue }

        if ($current -is [string]) {
            $text = $current.Trim()
            if ($text -and $stringSet.Add($text)) { $results.Add($text) | Out-Null }
            continue
        }

        if ($current -is [ValueType]) {
            $text = $current.ToString().Trim()
            if ($text -and $stringSet.Add($text)) { $results.Add($text) | Out-Null }
            continue
        }

        $identity = [System.Runtime.CompilerServices.RuntimeHelpers]::GetHashCode($current)
        if (-not $visited.Add($identity)) { continue }

        if ($current -is [System.Collections.IEnumerable] -and -not ($current -is [string])) {
            $items = @()
            foreach ($item in $current) { $items += ,$item }
            for ($index = $items.Count - 1; $index -ge 0; $index--) {
                $null = $stack.Push($items[$index])
            }
            continue
        }

        $properties = @('IPAddress','Address','NextHop','Value','DisplayValue','Name','ServerAddresses')
        $handled = $false
        for ($idx = $properties.Count - 1; $idx -ge 0; $idx--) {
            $prop = $properties[$idx]
            if ($current.PSObject.Properties[$prop]) {
                $null = $stack.Push($current.$prop)
                $handled = $true
            }
        }

        if ($handled) { continue }

        $fallback = [string]$current
        $fallback = $fallback.Trim()
        if ($fallback -and $stringSet.Add($fallback)) { $results.Add($fallback) | Out-Null }
    }

    return $results
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
