<#!
.SYNOPSIS
    Collects temporary profile related event log entries and ProfileList registry state.
#>
[CmdletBinding()]
param(
    [Parameter()]
    [string]$OutputDirectory = (Join-Path -Path (Split-Path -Parent $PSCommandPath) -ChildPath '..\\output')
)

. (Join-Path -Path $PSScriptRoot -ChildPath '..\\CollectorCommon.ps1')

function Get-TempProfileEvents {
    $startTime = (Get-Date).AddDays(-30)
    $filter = @{
        LogName      = 'Application'
        ProviderName = 'Microsoft-Windows-User Profiles Service'
        Id           = @(1511, 1515, 1518)
        StartTime    = $startTime
    }

    try {
        return Get-WinEvent -FilterHashtable $filter -ErrorAction Stop |
            Select-Object TimeCreated, Id, LevelDisplayName, Message
    } catch {
        return [PSCustomObject]@{
            Source = 'Get-WinEvent'
            Error  = $_.Exception.Message
        }
    }
}

function Get-ProfileListEntries {
    $baseKey = 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList'

    try {
        return Get-ChildItem -Path $baseKey -ErrorAction Stop | ForEach-Object {
            $key = $_
            try {
                $properties = Get-ItemProperty -Path $key.PSPath -ErrorAction Stop
                $keyName = [string]$key.PSChildName

                [PSCustomObject]@{
                    KeyName          = $keyName
                    FullPath         = $key.Name
                    Sid              = $key.PSChildName
                    ProfileImagePath = $properties.ProfileImagePath
                    Flags            = $properties.Flags
                    State            = $properties.State
                    RefCount         = $properties.RefCount
                    LastWriteTime    = $key.LastWriteTime
                    IsBackup         = if ($keyName -and ($keyName -match '\\.bak$')) { $true } else { $false }
                }
            } catch {
                [PSCustomObject]@{
                    KeyName = $key.PSChildName
                    FullPath = $key.Name
                    Error   = $_.Exception.Message
                }
            }
        }
    } catch {
        return [PSCustomObject]@{
            Source = $baseKey
            Error  = $_.Exception.Message
        }
    }
}

function Invoke-Main {
    $payload = [ordered]@{
        TempProfileEvents = Get-TempProfileEvents
        ProfileList       = Get-ProfileListEntries
    }

    $result = New-CollectorMetadata -Payload $payload
    $outputPath = Export-CollectorResult -OutputDirectory $OutputDirectory -FileName 'userprofiles.json' -Data $result -Depth 6
    Write-Output $outputPath
}

Invoke-Main
