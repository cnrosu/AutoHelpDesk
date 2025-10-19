<#!
.SYNOPSIS
    Collects DNS diagnostic data including resolution tests and connectivity checks.
#>
[CmdletBinding()]
param(
    [Parameter()]
    [string]$OutputDirectory = (Join-Path -Path (Split-Path -Parent $PSCommandPath) -ChildPath '..\\output')
)

. (Join-Path -Path $PSScriptRoot -ChildPath '..\\CollectorCommon.ps1')

function Test-DnsResolution {
    param(
        [string[]]$Names = @('www.microsoft.com','outlook.office365.com','autodiscover.outlook.com')
    )

    $results = [System.Collections.Generic.List[pscustomobject]]::new()
    foreach ($name in $Names) {
        try {
            $records = Resolve-DnsName -Name $name -ErrorAction Stop
            $null = $results.Add([PSCustomObject]@{
                Name    = $name
                Success = $true
                Records = $records | Select-Object Name, Type, IPAddress
            })
        } catch {
            $null = $results.Add([PSCustomObject]@{
                Name    = $name
                Success = $false
                Error   = $_.Exception.Message
            })
        }
    }
    return $results.ToArray()
}

function Trace-NetworkPath {
    param([string]$Target = 'outlook.office365.com')
    return Invoke-CollectorNativeCommand -FilePath 'tracert.exe' -ArgumentList $Target -ErrorMetadata @{ Target = $Target }
}

function Test-Latency {
    param([string]$Target = '8.8.8.8')

    $attempts = 4
    $summary = [ordered]@{
        Target            = $Target
        Attempts          = $attempts
        SuccessCount      = 0
        FailureCount      = 0
        Status            = 'Unknown'
        AverageLatencyMs  = $null
        MinimumLatencyMs  = $null
        MaximumLatencyMs  = $null
        AttemptsDetail    = @()
    }

    $testConnectionCmd = Get-Command -Name 'Test-Connection' -ErrorAction SilentlyContinue

    if ($null -ne $testConnectionCmd) {
        $attemptDetails = [System.Collections.Generic.List[pscustomobject]]::new()
        for ($i = 1; $i -le $attempts; $i++) {
            try {
                $reply = Test-Connection -ComputerName $Target -Count 1 -ErrorAction Stop
                $latency = $reply | Select-Object -First 1 -ExpandProperty ResponseTime
                $null = $attemptDetails.Add([PSCustomObject]@{
                    Attempt   = $i
                    Success   = $true
                    LatencyMs = $latency
                })
            } catch {
                $null = $attemptDetails.Add([PSCustomObject]@{
                    Attempt = $i
                    Success = $false
                    Error   = $_.Exception.Message
                })
            }
        }

        $attemptDetailsArray = $attemptDetails.ToArray()
        $summary.AttemptsDetail = $attemptDetailsArray
        $summary.SuccessCount = ($attemptDetailsArray | Where-Object { $_.Success }).Count
        $summary.FailureCount = $attempts - $summary.SuccessCount

        if ($summary.SuccessCount -gt 0) {
            $latencies = $attemptDetailsArray | Where-Object { $_.Success } | Select-Object -ExpandProperty LatencyMs
            $measure = $latencies | Measure-Object -Average -Minimum -Maximum
            $summary.AverageLatencyMs = [Math]::Round($measure.Average, 2)
            $summary.MinimumLatencyMs = $measure.Minimum
            $summary.MaximumLatencyMs = $measure.Maximum
        }

        $summary.Status = if ($summary.SuccessCount -eq $attempts) {
            'Success'
        } elseif ($summary.SuccessCount -gt 0) {
            'Partial'
        } else {
            'Failed'
        }

        return [PSCustomObject]$summary
    }

    $pingOutput = Invoke-CollectorNativeCommand -FilePath 'ping.exe' -ArgumentList @('-n', $attempts, $Target) -ErrorMetadata @{ Target = $Target }

    if ($pingOutput -isnot [System.Array]) {
        return $pingOutput
    }

    $summary.AttemptsDetail = $pingOutput

    $packetLine = $pingOutput | Where-Object { $_ -match 'Packets: Sent = (\d+), Received = (\d+), Lost = (\d+)' } | Select-Object -Last 1
    if ($packetLine) {
        $packetMatch = [regex]::Match($packetLine, 'Packets: Sent = (\d+), Received = (\d+), Lost = (\d+)')
        if ($packetMatch.Success) {
            $summary.Attempts = [int]$packetMatch.Groups[1].Value
            $summary.SuccessCount = [int]$packetMatch.Groups[2].Value
            $summary.FailureCount = [int]$packetMatch.Groups[3].Value
        }
    } else {
        $summary.SuccessCount = 0
        $summary.FailureCount = $attempts
    }

    $latencyLine = $pingOutput | Where-Object { $_ -match 'Minimum = (\d+)ms, Maximum = (\d+)ms, Average = (\d+)ms' } | Select-Object -Last 1
    if ($latencyLine) {
        $latencyMatch = [regex]::Match($latencyLine, 'Minimum = (\d+)ms, Maximum = (\d+)ms, Average = (\d+)ms')
        if ($latencyMatch.Success) {
            $summary.MinimumLatencyMs = [int]$latencyMatch.Groups[1].Value
            $summary.MaximumLatencyMs = [int]$latencyMatch.Groups[2].Value
            $summary.AverageLatencyMs = [int]$latencyMatch.Groups[3].Value
        }
    }

    $summary.Status = if ($summary.SuccessCount -eq $summary.Attempts) {
        'Success'
    } elseif ($summary.SuccessCount -gt 0) {
        'Partial'
    } else {
        'Failed'
    }

    return [PSCustomObject]$summary
}

function Test-AutodiscoverDomain {
    param([string]$Domain)

    if ([string]::IsNullOrWhiteSpace($Domain)) { return $false }

    $candidate = $Domain.Trim()
    if (-not $candidate) { return $false }

    if ($candidate.EndsWith('.')) {
        $candidate = $candidate.TrimEnd('.')
        if (-not $candidate) { return $false }
    }

    if ($candidate.Length -gt 253) { return $false }

    $pattern = '^(?i)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$'
    return ($candidate -match $pattern)
}

function Get-AutodiscoverDomainFromAddress {
    param([string]$Address)

    if ([string]::IsNullOrWhiteSpace($Address)) { return $null }

    $candidate = $Address.Trim()
    if (-not $candidate) { return $null }

    $candidate = $candidate -replace '^(?i)smtp:', ''
    if (-not ($candidate -match '@')) { return $null }

    $parts = $candidate -split '@', 2
    if ($parts.Count -lt 2) { return $null }

    $domain = $parts[1].Trim()
    if (-not $domain) { return $null }

    return $domain
}

function Get-AutodiscoverSignInDomains {
    $domains = [System.Collections.Generic.List[pscustomobject]]::new()
    $seen = New-Object System.Collections.Generic.HashSet[string]([System.StringComparer]::OrdinalIgnoreCase)

    $addDomain = {
        param(
            [string]$Domain,
            [string]$Source,
            [bool]$IsPrimary
        )

        if (-not (Test-AutodiscoverDomain $Domain)) { return }

        $normalized = $Domain.Trim().TrimEnd('.')
        try { $normalized = $normalized.ToLowerInvariant() } catch { }

        if (-not $normalized) { return }

        if ($seen.Add($normalized)) {
            $domains.Add([pscustomobject]@{
                Domain    = $normalized
                Source    = $Source
                IsPrimary = [bool]$IsPrimary
            }) | Out-Null
        } elseif ($IsPrimary) {
            $existing = $domains | Where-Object { $_.Domain -eq $normalized } | Select-Object -First 1
            if ($existing) { $existing.IsPrimary = $true }
        }
    }

    $primaryCandidates = New-Object System.Collections.Generic.List[string]

    try {
        $whoamiUpn = whoami.exe /upn 2>$null
        if ($LASTEXITCODE -eq 0 -and $whoamiUpn) {
            $primaryCandidates.Add([string]$whoamiUpn) | Out-Null
        }
    } catch {
    }

    foreach ($candidate in @($env:USERPRINCIPALNAME)) {
        if ($candidate) { $primaryCandidates.Add([string]$candidate) | Out-Null }
    }

    $addedPrimary = $false
    foreach ($candidate in $primaryCandidates) {
        $domain = Get-AutodiscoverDomainFromAddress -Address $candidate
        if (-not $domain) { continue }
        & $addDomain -Domain $domain -Source 'UPN' -IsPrimary:($addedPrimary -eq $false)
        if (-not $addedPrimary) { $addedPrimary = $true }
    }

    foreach ($candidate in @($env:EMAIL, $env:USERDNSDOMAIN)) {
        if (-not $candidate) { continue }
        $domain = if ($candidate -match '@') { Get-AutodiscoverDomainFromAddress -Address $candidate } else { $candidate }
        if (-not $domain) { continue }
        & $addDomain -Domain $domain -Source 'Environment' -IsPrimary:$false
    }

    return $domains.ToArray()
}

function New-AutodiscoverQueryDefinition {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string[]]$Types,
        [string]$Domain,
        [string]$Label,
        [string]$Source,
        [bool]$IsPrimary
    )

    $definition = [ordered]@{
        Name      = $Name
        Types     = $Types
        Domain    = $Domain
        Label     = $Label
        Source    = $Source
        IsPrimary = [bool]$IsPrimary
    }

    return [pscustomobject]$definition
}

function Resolve-AutodiscoverRecords {
    $domains = Get-AutodiscoverSignInDomains

    $queries = [System.Collections.Generic.List[pscustomobject]]::new()
    foreach ($entry in $domains) {
        if (-not $entry) { continue }
        $baseDomain = [string]$entry.Domain
        if (-not $baseDomain) { continue }

        $queries.Add((New-AutodiscoverQueryDefinition -Name "autodiscover.$baseDomain" -Types @('CNAME','A') -Domain $baseDomain -Label 'Autodiscover' -Source $entry.Source -IsPrimary:$entry.IsPrimary)) | Out-Null
        $queries.Add((New-AutodiscoverQueryDefinition -Name "enterpriseenrollment.$baseDomain" -Types @('CNAME') -Domain $baseDomain -Label 'EnterpriseEnrollment' -Source $entry.Source -IsPrimary:$entry.IsPrimary)) | Out-Null
        $queries.Add((New-AutodiscoverQueryDefinition -Name "enterpriseregistration.$baseDomain" -Types @('CNAME') -Domain $baseDomain -Label 'EnterpriseRegistration' -Source $entry.Source -IsPrimary:$entry.IsPrimary)) | Out-Null
    }

    $queries.Add((New-AutodiscoverQueryDefinition -Name 'autodiscover.outlook.com' -Types @('CNAME') -Domain 'outlook.com' -Label 'Autodiscover' -Source 'Global' -IsPrimary:$false)) | Out-Null

    $results = [System.Collections.Generic.List[pscustomobject]]::new()

    foreach ($query in $queries) {
        if (-not $query) { continue }

        $recordTypes = @()
        foreach ($type in $query.Types) {
            if ([string]::IsNullOrWhiteSpace($type)) { continue }
            $recordTypes += [string]$type
        }

        if ($recordTypes.Count -eq 0) { continue }

        $resolved = $false
        $resolution = $null
        $errors = New-Object System.Collections.Generic.List[object]

        foreach ($type in $recordTypes) {
            try {
                $records = Resolve-DnsName -Type $type -Name $query.Name -ErrorAction Stop
                $selection = $records | Select-Object Name, Type, NameHost, IPAddress
                $resolution = [ordered]@{
                    Records   = $selection
                    RecordType = $type
                }
                $resolved = $true
                break
            } catch {
                $errors.Add($_) | Out-Null
            }
        }

        $entry = [ordered]@{
            Query      = $query.Name
            Domain     = $query.Domain
            DomainSource = $query.Source
            Label      = $query.Label
            IsPrimary  = [bool]$query.IsPrimary
        }

        if ($resolved -and $resolution) {
            $entry.RecordType = $resolution.RecordType
            $entry.Records = $resolution.Records
        } elseif ($errors.Count -gt 0) {
            $firstError = [System.Management.Automation.ErrorRecord]$errors[0]
            $message = $firstError.Exception.Message
            $entry.RecordType = $recordTypes[0]
            $entry.Error = $message

            if ($firstError.Exception.PSObject.Properties['DnsResponseCode']) {
                $entry.ResponseCode = [string]$firstError.Exception.DnsResponseCode
            } elseif ($firstError.Exception.PSObject.Properties['ErrorCode']) {
                $entry.ErrorCode = [string]$firstError.Exception.ErrorCode
            } elseif ($firstError.Exception.PSObject.Properties['HResult']) {
                $entry.HResult = [string]$firstError.Exception.HResult
            }

            if ($firstError.FullyQualifiedErrorId) {
                $entry.ErrorId = [string]$firstError.FullyQualifiedErrorId
            }
        }

        $results.Add([pscustomobject]$entry) | Out-Null
    }

    return $results.ToArray()
}

function Get-DnsClientServerInventory {
    try {
        return Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction Stop | Select-Object InterfaceAlias, InterfaceIndex, ServerAddresses
    } catch {
        return [PSCustomObject]@{
            Source = 'Get-DnsClientServerAddress'
            Error  = $_.Exception.Message
        }
    }
}

function Get-DnsClientPolicies {
    try {
        return Get-DnsClient -ErrorAction Stop | Select-Object InterfaceAlias, InterfaceIndex, ConnectionSpecificSuffix, UseSuffixWhenRegistering, RegisterThisConnectionsAddress
    } catch {
        return [PSCustomObject]@{
            Source = 'Get-DnsClient'
            Error  = $_.Exception.Message
        }
    }
}

function Invoke-Main {
    $payload = [ordered]@{
        Resolution      = Test-DnsResolution
        Traceroute      = Trace-NetworkPath
        Latency         = Test-Latency
        Autodiscover    = Resolve-AutodiscoverRecords
        ClientServers   = Get-DnsClientServerInventory
        ClientPolicies  = Get-DnsClientPolicies
    }

    $result = New-CollectorMetadata -Payload $payload
    $outputPath = Export-CollectorResult -OutputDirectory $OutputDirectory -FileName 'dns.json' -Data $result -Depth 6
    Write-Output $outputPath
}

Invoke-Main
