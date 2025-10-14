<#!
.SYNOPSIS
    Collects Windows Search indexing health snapshot for AutoHelpDesk heuristics.
#>
[CmdletBinding()]
param(
    [Parameter()]
    [string]$OutputDirectory = (Join-Path -Path (Split-Path -Parent $PSCommandPath) -ChildPath '..\output'),

    [int]$EventLookbackHours = 48
)

. (Join-Path -Path $PSScriptRoot -ChildPath '..\CollectorCommon.ps1')
. (Join-Path -Path $PSScriptRoot -ChildPath 'Get-WindowsSearchSnapshot.ps1')

function Invoke-Main {
    Write-Verbose 'Collecting Windows Search snapshot.'

    $snapshot = $null
    try {
        $snapshot = Get-WindowsSearchSnapshot -EventLookbackHours $EventLookbackHours
    } catch {
        $snapshot = [pscustomobject]@{
            Source = 'WindowsSearch'
            Error  = $_.Exception.Message
        }
    }

    if (-not $snapshot) {
        $snapshot = [pscustomobject]@{
            Source = 'WindowsSearch'
            Error  = 'Snapshot collection returned no data.'
        }
    }

    $payload = New-CollectorMetadata -Payload $snapshot
    $outputPath = Export-CollectorResult -OutputDirectory $OutputDirectory -FileName 'windows-search.json' -Data $payload -Depth 6
    Write-Output $outputPath
}

Invoke-Main
