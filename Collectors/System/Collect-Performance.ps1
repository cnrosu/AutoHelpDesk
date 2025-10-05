<#!
.SYNOPSIS
    Collects lightweight performance snapshot including top CPU consumers and memory usage.
#>
[CmdletBinding()]
param(
    [Parameter()]
    [string]$OutputDirectory = (Join-Path -Path (Split-Path -Parent $PSCommandPath) -ChildPath '..\\output')
)

. (Join-Path -Path $PSScriptRoot -ChildPath '..\\CollectorCommon.ps1')

function Get-TopCpuProcesses {
    try {
        return Get-Process | Sort-Object -Property CPU -Descending | Select-Object -First 10 Name, Id, CPU, @{Name='WorkingSetMB';Expression={[math]::Round($_.WorkingSet64 / 1MB,2)}}
    } catch {
        return [PSCustomObject]@{
            Source = 'Get-Process'
            Error  = $_.Exception.Message
        }
    }
}

function Get-MemorySummary {
    $os = Get-CollectorOperatingSystem

    if (Test-CollectorResultHasError -Value $os) {
        return $os
    }

    if (-not $os) { return $null }

    return [PSCustomObject]@{
        TotalVisibleMemory = $os.TotalVisibleMemorySize
        FreePhysicalMemory  = $os.FreePhysicalMemory
        TotalVirtualMemory  = $os.TotalVirtualMemorySize
        FreeVirtualMemory   = $os.FreeVirtualMemory
    }
}

function Invoke-Main {
    $payload = [ordered]@{
        TopCpuProcesses = Get-TopCpuProcesses
        Memory          = Get-MemorySummary
    }

    $result = New-CollectorMetadata -Payload $payload
    $outputPath = Export-CollectorResult -OutputDirectory $OutputDirectory -FileName 'performance.json' -Data $result -Depth 6
    Write-Output $outputPath
}

Invoke-Main
