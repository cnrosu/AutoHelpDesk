<#!
.SYNOPSIS
    Collects IPv6 routing context including neighbor cache, router advertisements, and IPv6-focused ipconfig output.
#>
[CmdletBinding()]
param(
    [Parameter()]
    [string]$OutputDirectory = (Join-Path -Path (Split-Path -Parent $PSCommandPath) -ChildPath '..\\output')
)

. (Join-Path -Path $PSScriptRoot -ChildPath '..\\CollectorCommon.ps1')

function Get-Ipv6Neighbors {
    return Invoke-CollectorNativeCommand -FilePath 'netsh.exe' -ArgumentList @('interface', 'ipv6', 'show', 'neighbors') -SourceLabel 'netsh interface ipv6 show neighbors'
}

function Get-Ipv6Routers {
    return Invoke-CollectorNativeCommand -FilePath 'netsh.exe' -ArgumentList @('interface', 'ipv6', 'show', 'routers') -SourceLabel 'netsh interface ipv6 show routers'
}

function Get-IpConfigIpv6Sections {
    $ipconfig = Invoke-IpconfigAll
    if (-not $ipconfig) { return $ipconfig }

    if ($ipconfig -is [psobject] -and $ipconfig.PSObject.Properties.Name -contains 'Error') {
        return $ipconfig
    }

    $lines = @()
    if ($ipconfig -is [psobject] -and $ipconfig.PSObject.Properties.Name -contains 'Lines') {
        $lines = @($ipconfig.Lines)
    } elseif ($ipconfig -is [string]) {
        $lines = $ipconfig -split "`r?`n"
    } elseif ($ipconfig -is [System.Collections.IEnumerable] -and -not ($ipconfig -is [string])) {
        foreach ($item in $ipconfig) {
            $lines += if ($null -eq $item) { '' } else { [string]$item }
        }
    } else {
        $lines = @([string]$ipconfig)
    }

    $ipv6Pattern = '(?i)([0-9A-F]{0,4}:){2,}[0-9A-F]{0,4}'
    $results = New-Object System.Collections.Generic.List[string]
    $currentHeader = $null
    $headerEmitted = $false

    foreach ($line in $lines) {
        $text = if ($line -is [string]) { $line } else { [string]$line }
        if ($null -eq $text) { continue }

        $trimmed = $text.Trim()
        if ($trimmed -match '^[^\s].*:$') {
            $currentHeader = $trimmed
            $headerEmitted = $false
            continue
        }

        $containsIpv6 = $false
        if ($text -match '(?i)IPv6' -or ($trimmed -and $trimmed -match $ipv6Pattern)) {
            $containsIpv6 = $true
        }

        if ($containsIpv6) {
            if ($currentHeader -and -not $headerEmitted) {
                $results.Add($currentHeader) | Out-Null
                $headerEmitted = $true
            }
            $results.Add($text) | Out-Null
            continue
        }

        if ($headerEmitted -and [string]::IsNullOrWhiteSpace($trimmed)) {
            $results.Add($text) | Out-Null
            $headerEmitted = $false
        }
    }

    return $results.ToArray()
}

function Invoke-Main {
    $payload = [ordered]@{
        Neighbors    = Get-Ipv6Neighbors
        Routers      = Get-Ipv6Routers
        IpConfigIpv6 = Get-IpConfigIpv6Sections
    }

    $result = New-CollectorMetadata -Payload $payload
    $outputPath = Export-CollectorResult -OutputDirectory $OutputDirectory -FileName 'ipv6-routing.json' -Data $result -Depth 6
    Write-Output $outputPath
}

Invoke-Main
