<#!
.SYNOPSIS
    Collects per-domain Autodiscover DNS posture for Exchange Online onboarding parity with AutoL1 heuristics.
.DESCRIPTION
    Enumerates candidate primary SMTP/AD domains from environment and identity telemetry, then resolves
    Autodiscover-related records for each domain to power granular scoring in the analyzer stack.
#>
[CmdletBinding()]
param(
    [Parameter()]
    [string]$OutputDirectory = (Join-Path -Path (Split-Path -Parent $PSCommandPath) -ChildPath '..\output')
)

. (Join-Path -Path $PSScriptRoot -ChildPath '..\CollectorCommon.ps1')

function Get-CollectorStringValues {
    param([object]$Value)

    if ($null -eq $Value) { return @() }

    if ($Value -is [System.Collections.IEnumerable] -and -not ($Value -is [string])) {
        $items = New-Object System.Collections.Generic.List[string]
        foreach ($element in $Value) {
            if ($null -eq $element) { continue }
            if ($element -is [string]) {
                if ($element) { $items.Add($element) | Out-Null }
                continue
            }

            try {
                $items.Add([string]$element) | Out-Null
            } catch {
            }
        }

        return @($items | Where-Object { $_ })
    }

    try {
        $text = [string]$Value
        if ($text) { return @($text) }
    } catch {
    }

    return @()
}

function Get-IdentityEmailAddresses {
    $addresses = New-Object System.Collections.Generic.HashSet[string]([System.StringComparer]::OrdinalIgnoreCase)

    foreach ($candidate in @($env:USERPRINCIPALNAME)) {
        if ([string]::IsNullOrWhiteSpace($candidate)) { continue }
        $trimmed = $candidate.Trim()
        if (-not $trimmed) { continue }
        if ($trimmed -match '@') {
            $addresses.Add($trimmed) | Out-Null
        }
    }

    try {
        $identityRoot = 'HKCU:\Software\Microsoft\Office\16.0\Common\Identity'
        if (Test-Path -Path $identityRoot) {
            $rootProperties = Get-ItemProperty -Path $identityRoot -ErrorAction Stop
            foreach ($prop in $rootProperties.PSObject.Properties) {
                foreach ($value in (Get-CollectorStringValues -Value $prop.Value)) {
                    if ([string]::IsNullOrWhiteSpace($value)) { continue }
                    $normalized = $value.Trim()
                    if (-not $normalized) { continue }
                    if ($normalized -match '^(?i)(smtp:)?[^@\s]+@[^@\s]+$') {
                        $addresses.Add(($normalized -replace '^(?i)smtp:', '')) | Out-Null
                    }
                }
            }

            $identitiesPath = Join-Path -Path $identityRoot -ChildPath 'Identities'
            if (Test-Path -Path $identitiesPath) {
                $identityKeys = Get-ChildItem -Path $identitiesPath -ErrorAction Stop
                foreach ($key in $identityKeys) {
                    try {
                        $props = Get-ItemProperty -Path $key.PSPath -ErrorAction Stop
                        foreach ($prop in $props.PSObject.Properties) {
                            foreach ($value in (Get-CollectorStringValues -Value $prop.Value)) {
                                if ([string]::IsNullOrWhiteSpace($value)) { continue }
                                $normalized = $value.Trim()
                                if (-not $normalized) { continue }
                                if ($normalized -match '^(?i)(smtp:)?[^@\s]+@[^@\s]+$') {
                                    $addresses.Add(($normalized -replace '^(?i)smtp:', '')) | Out-Null
                                }
                            }
                        }
                    } catch {
                    }
                }
            }
        }
    } catch {
    }

    return @($addresses | Where-Object { $_ })
}

function Test-AutodiscoverDomainName {
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

function Get-CandidateDomains {
    param([string[]]$EmailAddresses)

    $domains = New-Object System.Collections.Generic.HashSet[string]([System.StringComparer]::OrdinalIgnoreCase)
    $addresses = if ($EmailAddresses) { $EmailAddresses } else { Get-IdentityEmailAddresses }

    foreach ($address in $addresses) {
        if (-not $address) { continue }
        $parts = $address.Split('@')
        if ($parts.Count -lt 2) { continue }
        $domain = $parts[-1].Trim()
        if (-not $domain) { continue }
        if ($domain -notmatch '\.') { continue }
        if (-not (Test-AutodiscoverDomainName -Domain $domain)) { continue }
        if ($domain.EndsWith('.')) { $domain = $domain.TrimEnd('.') }
        if (-not $domain) { continue }
        $domains.Add($domain) | Out-Null
    }

    return @($domains | Where-Object { $_ })
}

function New-LookupResult {
    param(
        [Parameter(Mandatory)][string]$Label,
        [Parameter(Mandatory)][string]$Query,
        [Parameter(Mandatory)][string]$Type
    )

    return [pscustomobject][ordered]@{
        Label     = $Label
        Query     = $Query
        Type      = $Type
        Success   = $null
        Targets   = @()
        Addresses = @()
        Records   = @()
        Strings   = @()
        Error     = $null
    }
}

function Resolve-DnsRecord {
    param(
        [Parameter(Mandatory)][pscustomobject]$RecordDefinition
    )

    $entry = New-LookupResult -Label $RecordDefinition.Label -Query $RecordDefinition.Name -Type $RecordDefinition.Type

    try {
        $response = Resolve-DnsName -Type $RecordDefinition.Type -Name $RecordDefinition.Name -ErrorAction Stop
        $entry.Success = $true
        switch ($RecordDefinition.Type.ToUpperInvariant()) {
            'CNAME' {
                $targets = $response | ForEach-Object { $_.NameHost }
                $entry.Targets = @($targets | Where-Object { $_ })
            }
            'A' {
                $addresses = $response | ForEach-Object { $_.IPAddress }
                $entry.Addresses = @($addresses | Where-Object { $_ })
            }
            'AAAA' {
                $addresses = $response | ForEach-Object { $_.IPAddress }
                $entry.Addresses = @($addresses | Where-Object { $_ })
            }
            'SRV' {
                $records = foreach ($item in $response) {
                    [pscustomobject]@{
                        Priority = $item.Priority
                        Weight   = $item.Weight
                        Port     = $item.Port
                        Target   = $item.NameTarget
                    }
                }
                $entry.Records = @($records | Where-Object { $_ })
                $entry.Targets = @($entry.Records | ForEach-Object { $_.Target } | Where-Object { $_ })
            }
            'MX' {
                $records = foreach ($item in $response) {
                    [pscustomobject]@{
                        Preference = $item.Preference
                        Target     = $item.NameExchange
                    }
                }
                $entry.Records = @($records | Where-Object { $_ })
                $entry.Targets = @($entry.Records | ForEach-Object { $_.Target } | Where-Object { $_ })
            }
            'TXT' {
                $strings = foreach ($item in $response) {
                    foreach ($text in $item.Strings) {
                        $text
                    }
                }
                $entry.Strings = @($strings | Where-Object { $_ })
            }
            default {
                $entry.Records = @($response)
            }
        }
    } catch {
        $entry.Success = $false
        $entry.Error = $_.Exception.Message
    }

    return $entry
}

function Resolve-DomainAutodiscover {
    param(
        [Parameter(Mandatory)][string]$Domain
    )

    $results = [System.Collections.Generic.List[pscustomobject]]::new()
    $records = @(
        @{ Label = 'Autodiscover';      Name = "autodiscover.$Domain";        Type = 'CNAME' },
        @{ Label = 'AutodiscoverA';     Name = "autodiscover.$Domain";        Type = 'A' },
        @{ Label = 'AutodiscoverAAAA';  Name = "autodiscover.$Domain";        Type = 'AAAA' },
        @{ Label = 'AutodiscoverSrv';   Name = "_autodiscover._tcp.$Domain";  Type = 'SRV' },
        @{ Label = 'Mx';                Name = $Domain;                        Type = 'MX' },
        @{ Label = 'Txt';               Name = $Domain;                        Type = 'TXT' }
    )

    foreach ($record in $records) {
        $results.Add((Resolve-DnsRecord -RecordDefinition ([pscustomobject]$record))) | Out-Null
    }

    return $results.ToArray()
}

function Invoke-Main {
    $emailAddresses = Get-IdentityEmailAddresses
    $domains = Get-CandidateDomains -EmailAddresses $emailAddresses
    $lookups = [System.Collections.Generic.List[pscustomobject]]::new()
    foreach ($domain in $domains) {
        $lookups.Add([pscustomobject]@{
            Domain  = $domain
            Lookups = Resolve-DomainAutodiscover -Domain $domain
        })
    }

    $payload = [ordered]@{
        CapturedAt = (Get-Date).ToString('o')
        Domains    = $domains
        Addresses  = $emailAddresses
        Results    = $lookups.ToArray()
    }

    $metadata = New-CollectorMetadata -Payload $payload
    $outputPath = Export-CollectorResult -OutputDirectory $OutputDirectory -FileName 'autodiscover-dns.json' -Data $metadata -Depth 6
    Write-Output $outputPath
}

Invoke-Main
