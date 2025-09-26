<#!
.SYNOPSIS
    Collects Outlook profile corruption and rebuild signals including OST events and repair logs.
#>
[CmdletBinding()]
param(
    [Parameter()]
    [string]$OutputDirectory = (Join-Path -Path (Split-Path -Parent $PSCommandPath) -ChildPath '..\\output')
)

. (Join-Path -Path $PSScriptRoot -ChildPath '..\\CollectorCommon.ps1')

function Get-OutlookProfileEvents {
    param(
        [datetime]$StartTime
    )

    try {
        $filter = @{ LogName = 'Application'; ProviderName = 'Outlook' }
        if ($StartTime) {
            $filter['StartTime'] = $StartTime
        }

        $events = Get-WinEvent -FilterHashtable $filter -MaxEvents 200 -ErrorAction Stop |
            Select-Object TimeCreated, Id, LevelDisplayName, ProviderName, Message
        return $events
    } catch {
        return [pscustomobject]@{
            Source = 'Get-WinEvent Outlook'
            Error  = $_.Exception.Message
        }
    }
}

function Get-OutlookCacheInventory {
    try {
        $rootPaths = @(
            (Join-Path -Path $env:LOCALAPPDATA -ChildPath 'Microsoft\Outlook'),
            (Join-Path -Path $env:USERPROFILE -ChildPath 'Documents\Outlook Files')
        ) | Where-Object { $_ }

        $results = @()
        foreach ($path in $rootPaths) {
            if (Test-Path -Path $path) {
                $results += Get-ChildItem -Path $path -Include '*.ost','*.pst' -Recurse -ErrorAction Stop |
                    Select-Object Name, FullName, Length, LastWriteTime
            }
        }
        return $results
    } catch {
        return [pscustomobject]@{
            Source = 'OutlookCacheScan'
            Error  = $_.Exception.Message
        }
    }
}

function Get-ScanPstLogs {
    param(
        [datetime]$StartTime
    )

    try {
        $rootPaths = @(
            (Join-Path -Path $env:LOCALAPPDATA -ChildPath 'Microsoft\Outlook'),
            (Join-Path -Path $env:USERPROFILE -ChildPath 'Documents\Outlook Files')
        ) | Where-Object { $_ }

        $results = @()
        foreach ($path in $rootPaths) {
            if (-not (Test-Path -Path $path)) { continue }

            $results += Get-ChildItem -Path $path -Filter 'SCANPST*.log' -Recurse -ErrorAction Stop |
                Select-Object Name, FullName, Length, LastWriteTime
        }

        if ($StartTime) {
            $results = $results | Where-Object { $_.LastWriteTime -ge $StartTime }
        }

        return $results
    } catch {
        return [pscustomobject]@{
            Source = 'ScanPstLogScan'
            Error  = $_.Exception.Message
        }
    }
}

function Invoke-Main {
    $startTime = (Get-Date).AddDays(-30)

    $payload = [ordered]@{
        StartTime    = $startTime.ToString('o')
        Events       = Get-OutlookProfileEvents -StartTime $startTime
        OstFiles     = Get-OutlookCacheInventory
        ScanPstLogs  = Get-ScanPstLogs -StartTime $startTime
    }

    $result = New-CollectorMetadata -Payload $payload
    $outputPath = Export-CollectorResult -OutputDirectory $OutputDirectory -FileName 'outlook-profile-signals.json' -Data $result -Depth 6
    Write-Output $outputPath
}

Invoke-Main
