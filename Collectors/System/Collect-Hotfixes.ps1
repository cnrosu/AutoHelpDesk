<#!
.SYNOPSIS
    Collects installed hotfix metadata for recent updates.
#>
[CmdletBinding()]
param(
    [Parameter()]
    [string]$OutputDirectory = (Join-Path -Path (Split-Path -Parent $PSCommandPath) -ChildPath '..\\output')
)

. (Join-Path -Path $PSScriptRoot -ChildPath '..\\CollectorCommon.ps1')

function Get-RecentHotfixes {
    try {
        return Get-HotFix -ErrorAction Stop | Sort-Object -Property InstalledOn -Descending | Select-Object -First 50 HotFixID, Description, InstalledOn, InstalledBy
    } catch {
        return [PSCustomObject]@{
            Source = 'Get-HotFix'
            Error  = $_.Exception.Message
        }
    }
}

function Invoke-Main {
    $payload = [ordered]@{
        Hotfixes = Get-RecentHotfixes
    }

    $result = New-CollectorMetadata -Payload $payload
    $outputPath = Export-CollectorResult -OutputDirectory $OutputDirectory -FileName 'hotfixes.json' -Data $result -Depth 6
    Write-Output $outputPath
}

Invoke-Main
