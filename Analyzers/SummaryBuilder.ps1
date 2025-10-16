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

        foreach ($prop in 'IPAddress','Address','NextHop','Value','DisplayValue','Name','ServerAddresses') {
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
        [bool]$IsAzureAdJoined,
        [string]$AzureAdTenant
    )

    if ($PartOfDomain) {
        if ($Domain) { return "Domain joined ($Domain)" }
        return 'Domain joined'
    }

    $domainLabel = if ($Domain) { $Domain } else { 'Unknown domain' }
    if ($IsAzureAdJoined) {
        $tenantLabel = if ($AzureAdTenant) { $AzureAdTenant } else { $domainLabel }
        return "Azure AD joined ($tenantLabel)"
    }

    return "Not domain joined (Domain: $domainLabel)"
}

function ConvertTo-MultilineText {
    param($Value)

    if ($null -eq $Value) { return $null }

    if ($Value -is [string]) {
        $text = $Value
        if (-not $text) { return $null }
        $trimmed = $text.Trim()
        if (-not $trimmed) { return $null }
        return ($trimmed -replace '\r?\n', "`n")
    }

    if ($Value -is [System.Collections.IEnumerable] -and -not ($Value -is [string])) {
        $builder = [System.Text.StringBuilder]::new()
        foreach ($item in $Value) {
            $converted = ConvertTo-MultilineText -Value $item
            if (-not $converted) { continue }
            if ($builder.Length -gt 0) { [void]$builder.AppendLine() }
            [void]$builder.Append($converted)
        }

        if ($builder.Length -eq 0) { return $null }
        return $builder.ToString().Trim()
    }

    $stringValue = [string]$Value
    if (-not $stringValue) { return $null }
    $stringValue = $stringValue.Trim()
    if (-not $stringValue) { return $null }
    return $stringValue
}

function Get-DsRegCmdTextFromArtifact {
    param(
        $Artifact
    )

    if (-not $Artifact) { return $null }

    $payload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $Artifact)
    if ($null -eq $payload) { return $null }

    $candidates = New-Object System.Collections.Generic.List[object]

    if ($payload.PSObject -and $payload.PSObject.Properties['DsRegCmd']) {
        $candidates.Add($payload.DsRegCmd) | Out-Null
    }
    if ($payload.PSObject -and $payload.PSObject.Properties['Output']) {
        $candidates.Add($payload.Output) | Out-Null
    }
    if ($payload.PSObject -and $payload.PSObject.Properties['StdOut']) {
        $candidates.Add($payload.StdOut) | Out-Null
    }
    if ($payload.PSObject -and $payload.PSObject.Properties['Content']) {
        $candidates.Add($payload.Content) | Out-Null
    }

    if ($candidates.Count -eq 0) {
        $candidates.Add($payload) | Out-Null
    }

    foreach ($candidate in $candidates) {
        $text = ConvertTo-MultilineText -Value $candidate
        if ($text) { return $text }
    }

    return $null
}

function Get-DsRegCmdText {
    param(
        $Context
    )

    $artifactNames = @('identity','dsregcmd_status','dsregcmd','dsreg_status','dsreg')
    foreach ($name in $artifactNames) {
        $artifact = Get-AnalyzerArtifact -Context $Context -Name $name
        if (-not $artifact) { continue }

        if ($artifact -is [System.Collections.IEnumerable] -and -not ($artifact -is [string])) {
            foreach ($entry in $artifact) {
                $text = Get-DsRegCmdTextFromArtifact -Artifact $entry
                if ($text) { return $text }
            }
        } else {
            $text = Get-DsRegCmdTextFromArtifact -Artifact $artifact
            if ($text) { return $text }
        }
    }

    return $null
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
        if ($line -match '^(?i)\s*AzureAdJoined\s*:\s*(Yes|No)') {
            return ($matches[1].ToLowerInvariant() -eq 'yes')
        }
    }

    return $false
}

function Get-AzureAdTenantName {
    param([string]$DsRegCmdOutput)

    if (-not $DsRegCmdOutput) { return $null }

    foreach ($line in [regex]::Split($DsRegCmdOutput, '\r?\n')) {
        if ($line -match '^(?i)\s*TenantName\s*:\s*(.+)$') {
            $tenant = $matches[1].Trim()
            if ($tenant) { return $tenant }
        }
    }

    return $null
}

function Get-MdmEnrollmentInfo {
    param([string]$DsRegCmdOutput)

    if (-not $DsRegCmdOutput) {
        return [pscustomobject]@{
            IsEnrolled   = $false
            IsIntune     = $false
            DisplayLabel = $null
        }
    }

    $values = New-Object System.Collections.Generic.List[string]
    foreach ($line in [regex]::Split($DsRegCmdOutput, '\r?\n')) {
        if ($line -notmatch '^(?i)\s*Mdm[a-zA-Z]*\s*:\s*(.+)$') { continue }
        $value = $matches[1]
        if ($null -eq $value) { continue }

        $trimmed = $value.Trim()
        if (-not $trimmed) { continue }
        if ($trimmed -match '^(?i)\(null\)|\(not\s+set\)|none|not\s+configured|n/?a$') { continue }

        if (-not ($values.Contains($trimmed))) {
            $values.Add($trimmed) | Out-Null
        }
    }

    if ($values.Count -eq 0) {
        return [pscustomobject]@{
            IsEnrolled   = $false
            IsIntune     = $false
            DisplayLabel = $null
        }
    }

    foreach ($value in $values) {
        if ($value -match '(?i)intune' -or $value -match '(?i)manage\.microsoft\.com') {
            return [pscustomobject]@{
                IsEnrolled   = $true
                IsIntune     = $true
                DisplayLabel = 'Intune'
            }
        }
    }

    $first = $values[0]
    $label = $first
    $host = $null
    try {
        if ($first -match '^[a-zA-Z][a-zA-Z0-9+\.-]*://') {
            $uri = [Uri]$first
            if ($uri.Host) { $host = $uri.Host }
        }
    } catch {
    }

    if ($host) {
        $label = "Detected ($host)"
    } elseif ($first -match '^[A-Za-z0-9][A-Za-z0-9\.-]*$') {
        $label = "Detected ($first)"
    }

    return [pscustomobject]@{
        IsEnrolled   = $true
        IsIntune     = $false
        DisplayLabel = $label
    }
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
        AzureAdTenant   = $null
        OperatingSystem = $null
        OSVersion       = $null
        OSBuild         = $null
        IsWindowsServer = $null
        IPv4Addresses   = @()
        Gateways        = @()
        DnsServers      = @()
        GeneratedAt     = Get-Date
        IsIntuneManaged = $false
        MdmEnrollment   = $null
    }

    $msinfoIdentity = Get-MsinfoSystemIdentity -Context $Context
    if ($msinfoIdentity) {
        if ($msinfoIdentity.DeviceName) {
            $summary.DeviceName = $msinfoIdentity.DeviceName
        }

        if ($msinfoIdentity.OSName) {
            $summary.OperatingSystem = $msinfoIdentity.OSName
            $summary.IsWindowsServer = Test-IsWindowsServer -Caption $msinfoIdentity.OSName
        }

        if ($msinfoIdentity.OSVersion) {
            $summary.OSVersion = $msinfoIdentity.OSVersion
        } elseif ($msinfoIdentity.OSVersionRaw) {
            $summary.OSVersion = $msinfoIdentity.OSVersionRaw
        }

        if ($msinfoIdentity.OSBuild) {
            $summary.OSBuild = $msinfoIdentity.OSBuild
        }

        if ($msinfoIdentity.Domain) {
            $summary.Domain = $msinfoIdentity.Domain
        }

        if ($null -ne $msinfoIdentity.PartOfDomain) {
            $summary.IsDomainJoined = [bool]$msinfoIdentity.PartOfDomain
        }
    }

    $dsRegText = Get-DsRegCmdText -Context $Context
    if ($dsRegText) {
        $summary.IsAzureAdJoined = Get-AzureAdJoinState -DsRegCmdOutput $dsRegText
        $mdmInfo = Get-MdmEnrollmentInfo -DsRegCmdOutput $dsRegText
        if ($mdmInfo) {
            if ($mdmInfo.IsIntune) { $summary.IsIntuneManaged = $true }
            if ($mdmInfo.DisplayLabel) { $summary.MdmEnrollment = $mdmInfo.DisplayLabel }
            elseif ($mdmInfo.IsEnrolled) { $summary.MdmEnrollment = 'Detected' }
        }
        if ($summary.IsAzureAdJoined) {
            $tenantName = Get-AzureAdTenantName -DsRegCmdOutput $dsRegText
            if ($tenantName) { $summary.AzureAdTenant = $tenantName }
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
                $ipv4Raw = $null
                if ($entry.PSObject.Properties['IPv4Address']) { $ipv4Raw = $entry.IPv4Address }
                if ($null -ne $ipv4Raw) {
                    foreach ($value in Get-AllStrings -Value $ipv4Raw) {
                        if ($value -and $value -notmatch '^169\.254\.') { $ipv4.Add($value) | Out-Null }
                    }
                }
                $gatewayRaw = $null
                if ($entry.PSObject.Properties['IPv4DefaultGateway']) { $gatewayRaw = $entry.IPv4DefaultGateway }
                if ($null -ne $gatewayRaw) {
                    foreach ($value in Get-AllStrings -Value $gatewayRaw) {
                        if ($value) { $gateways.Add($value) | Out-Null }
                    }
                }
                $dnsRaw = $null
                if ($entry.PSObject.Properties['DNSServer']) { $dnsRaw = $entry.DNSServer }
                if ($null -ne $dnsRaw) {
                    foreach ($value in Get-AllStrings -Value $dnsRaw) {
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
    if (-not $summary.MdmEnrollment) {
        if ($dsRegText) {
            $summary.MdmEnrollment = 'None detected'
        } else {
            $summary.MdmEnrollment = 'Unknown'
        }
    }

    $summary.DeviceState = Format-DeviceState -Domain $domainText -PartOfDomain $partOfDomain -IsAzureAdJoined $summary.IsAzureAdJoined -AzureAdTenant $summary.AzureAdTenant

    if (-not $summary.DeviceName) { $summary.DeviceName = 'Unknown' }
    if (-not $summary.OperatingSystem) { $summary.OperatingSystem = 'Unknown' }

    return [pscustomobject]$summary
}
