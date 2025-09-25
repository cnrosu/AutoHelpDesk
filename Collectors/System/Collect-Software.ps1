<#!
.SYNOPSIS
    Collects installed software inventory from 32-bit and 64-bit registry locations.
#>
[CmdletBinding()]
param(
    [Parameter()]
    [string]$OutputDirectory = (Join-Path -Path (Split-Path -Parent $PSCommandPath) -ChildPath '..\\output')
)

. (Join-Path -Path $PSScriptRoot -ChildPath '..\\CollectorCommon.ps1')

function Get-UninstallEntries {
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )

    try {
        return Get-ItemProperty -Path $Path -ErrorAction Stop | ForEach-Object {
            $_ | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate, EstimatedSize, UninstallString
        }
    } catch {
        return [PSCustomObject]@{
            Source = $Path
            Error  = $_.Exception.Message
        }
    }
}

function Invoke-Main {
    $payload = [ordered]@{
        Programs64 = Get-UninstallEntries -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
        Programs32 = Get-UninstallEntries -Path 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
    }

    $result = New-CollectorMetadata -Payload $payload
    $outputPath = Export-CollectorResult -OutputDirectory $OutputDirectory -FileName 'software.json' -Data $result -Depth 6
    Write-Output $outputPath
}

Invoke-Main
