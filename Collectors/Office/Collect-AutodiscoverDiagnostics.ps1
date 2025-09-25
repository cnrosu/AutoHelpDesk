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

function Get-CandidateDomains {
    $domains = New-Object System.Collections.Generic.HashSet[string]([System.StringComparer]::OrdinalIgnoreCase)

    foreach ($value in @($env:USERDNSDOMAIN, $env:USERDOMAIN, $env:USERPRINCIPALNAME)) {
        if (-not $value) { continue }
        $normalized = [string]$value
        if ($normalized -match '@') {
            $normalized = $normalized.Split('@')[-1]
        }
        $normalized = $normalized.Trim()
        if ($normalized) { $domains.Add($normalized) | Out-Null }
    }

    try {
        $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
        if ($cs -and $cs.PartOfDomain -eq $true -and $cs.Domain) {
            $domains.Add([string]$cs.Domain) | Out-Null
        }
    } catch { }

    try {
        $regPath = 'HKCU:\Software\Microsoft\Office\16.0\Common\Identity'
        if (Test-Path -Path $regPath) {
            $props = Get-ItemProperty -Path $regPath -ErrorAction Stop
            foreach ($prop in $props.PSObject.Properties) {
                if ($prop.Value -is [string] -and $prop.Value -match '@') {
                    $domains.Add(($prop.Value.Split('@')[-1]).Trim()) | Out-Null
                }
            }
        }
    } catch { }

    return @($domains | Where-Object { $_ })
}

function Resolve-DomainAutodiscover {
    param(
        [Parameter(Mandatory)][string]$Domain
    )

    $results = @()
    $recordTypes = @(
        @{ Label = 'Autodiscover'; Name = "autodiscover.$Domain"; Type = 'CNAME' },
        @{ Label = 'EnterpriseRegistration'; Name = "enterpriseregistration.$Domain"; Type = 'CNAME' },
        @{ Label = 'EnterpriseEnrollment';   Name = "enterpriseenrollment.$Domain";  Type = 'CNAME' }
    )

    foreach ($record in $recordTypes) {
        $entry = [ordered]@{
            Label   = $record.Label
            Query   = $record.Name
            Type    = $record.Type
            Success = $null
            Targets = @()
            Error   = $null
        }

        try {
            $response = Resolve-DnsName -Type $record.Type -Name $record.Name -ErrorAction Stop
            $entry.Success = $true
            $entry.Targets = ($response | Select-Object -ExpandProperty NameHost -ErrorAction SilentlyContinue)
        } catch {
            $entry.Success = $false
            $entry.Error = $_.Exception.Message
        }

        $results += $entry
    }

    return $results
}

function Invoke-Main {
    $domains = Get-CandidateDomains
    $lookups = @()
    foreach ($domain in $domains) {
        $lookups += [ordered]@{
            Domain  = $domain
            Lookups = Resolve-DomainAutodiscover -Domain $domain
        }
    }

    $payload = [ordered]@{
        CapturedAt = (Get-Date).ToString('o')
        Domains    = $domains
        Results    = $lookups
    }

    $metadata = New-CollectorMetadata -Payload $payload
    $outputPath = Export-CollectorResult -OutputDirectory $OutputDirectory -FileName 'autodiscover-dns.json' -Data $metadata -Depth 6
    Write-Output $outputPath
}

Invoke-Main
