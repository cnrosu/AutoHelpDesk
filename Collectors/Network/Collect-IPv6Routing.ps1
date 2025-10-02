<#!
.SYNOPSIS
    Collects IPv6 routing and addressing details from Windows networking tools.
#>
[CmdletBinding()]
param(
    [Parameter()]
    [string]$OutputDirectory = (Join-Path -Path (Split-Path -Parent $PSCommandPath) -ChildPath '..\\output')
)

. (Join-Path -Path $PSScriptRoot -ChildPath '..\\CollectorCommon.ps1')

function Get-Ipv6Neighbors {
    return Invoke-CollectorNativeCommand -FilePath 'netsh.exe' -ArgumentList 'interface','ipv6','show','neighbors' -SourceLabel 'netsh interface ipv6 show neighbors'
}

function Get-Ipv6Routers {
    return Invoke-CollectorNativeCommand -FilePath 'netsh.exe' -ArgumentList 'interface','ipv6','show','routers' -SourceLabel 'netsh interface ipv6 show routers'
}

function ConvertTo-Ipv6SectionList {
    param(
        [Parameter(Mandatory)]
        [string[]]$Lines
    )

    $sections = New-Object System.Collections.Generic.List[object]
    $buffer = New-Object System.Collections.Generic.List[string]

    foreach ($line in $Lines) {
        if ($null -eq $line) { continue }
        $text = [string]$line
        if ([string]::IsNullOrWhiteSpace($text)) {
            if ($buffer.Count -gt 0) {
                $sections.Add($buffer.ToArray()) | Out-Null
                $buffer.Clear()
            }
            continue
        }

        $buffer.Add($text) | Out-Null
    }

    if ($buffer.Count -gt 0) {
        $sections.Add($buffer.ToArray()) | Out-Null
        $buffer.Clear()
    }

    $results = New-Object System.Collections.Generic.List[object]

    foreach ($section in $sections) {
        $hasIpv6 = $false
        foreach ($entry in $section) {
            if ($entry -match '(?i)ipv6') { $hasIpv6 = $true; break }
        }
        if (-not $hasIpv6) { continue }

        $firstLine = $section | Select-Object -First 1
        $alias = $null
        $label = $null
        if ($firstLine) {
            $trimmed = $firstLine.Trim()
            $label = $trimmed.TrimEnd(':')
            $match = [regex]::Match($trimmed, '(?i)adapter\s+([^:]+):')
            if ($match.Success) {
                $alias = $match.Groups[1].Value.Trim()
            } else {
                $alias = $label
            }
        }

        $results.Add([pscustomobject]@{
            InterfaceLabel = $label
            Alias          = $alias
            Lines          = $section
        }) | Out-Null
    }

    return $results.ToArray()
}

function Get-IpconfigIpv6Sections {
    $output = Invoke-CollectorNativeCommand -FilePath 'ipconfig.exe' -ArgumentList '/all' -SourceLabel 'ipconfig.exe /all'

    if ($output -isnot [string] -and $output -isnot [string[]]) {
        return $output
    }

    $lines = @()
    foreach ($line in $output) {
        $lines += [string]$line
    }

    return [ordered]@{
        RawLines = $lines
        Sections = ConvertTo-Ipv6SectionList -Lines $lines
    }
}

function Invoke-Main {
    $payload = [ordered]@{
        NetshNeighbors = Get-Ipv6Neighbors
        NetshRouters   = Get-Ipv6Routers
        IpconfigIpv6   = Get-IpconfigIpv6Sections
    }

    $result = New-CollectorMetadata -Payload $payload
    $outputPath = Export-CollectorResult -OutputDirectory $OutputDirectory -FileName 'network-ipv6.json' -Data $result -Depth 6
    Write-Output $outputPath
}

Invoke-Main
