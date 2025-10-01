<#!
.SYNOPSIS
    Collects Outlook cache file inventory (OST/PST).
#>
[CmdletBinding()]
param(
    [Parameter()]
    [string]$OutputDirectory = (Join-Path -Path (Split-Path -Parent $PSCommandPath) -ChildPath '..\\output')
)

. (Join-Path -Path $PSScriptRoot -ChildPath '..\\CollectorCommon.ps1')

function Get-OstFiles {
    try {
        $rootPaths = @(
            (Join-Path -Path $env:LOCALAPPDATA -ChildPath 'Microsoft\Outlook'),
            (Join-Path -Path $env:USERPROFILE -ChildPath 'Documents\Outlook Files')
        ) | Where-Object { $_ }

        $results = [System.Collections.Generic.List[psobject]]::new()
        foreach ($path in $rootPaths) {
            if (Test-Path -Path $path) {
                $items = Get-ChildItem -Path $path -Include '*.ost','*.pst' -Recurse -ErrorAction Stop | Select-Object Name, FullName, Length, LastWriteTime
                foreach ($item in $items) { $results.Add($item) }
            }
        }
        return $results.ToArray()
    } catch {
        return [PSCustomObject]@{
            Source = 'OutlookCacheScan'
            Error  = $_.Exception.Message
        }
    }
}

function Invoke-Main {
    $payload = [ordered]@{
        Caches = Get-OstFiles
    }

    $result = New-CollectorMetadata -Payload $payload
    $outputPath = Export-CollectorResult -OutputDirectory $OutputDirectory -FileName 'outlook-caches.json' -Data $result -Depth 6
    Write-Output $outputPath
}

Invoke-Main
