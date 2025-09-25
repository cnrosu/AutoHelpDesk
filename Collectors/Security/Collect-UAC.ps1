<#!
.SYNOPSIS
    Collects User Account Control (UAC) policy configuration.
#>
[CmdletBinding()]
param(
    [Parameter()]
    [string]$OutputDirectory = (Join-Path -Path (Split-Path -Parent $PSCommandPath) -ChildPath '..\\output')
)

. (Join-Path -Path $PSScriptRoot -ChildPath '..\\CollectorCommon.ps1')

function Get-UacPolicy {
    try {
        $values = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -ErrorAction Stop | Select-Object * -ExcludeProperty PS*, CIM*, PSEdition
        return $values
    } catch {
        return [PSCustomObject]@{
            Source = 'Policies\\System'
            Error  = $_.Exception.Message
        }
    }
}

function Invoke-Main {
    $payload = [ordered]@{
        Policy = Get-UacPolicy
    }

    $result = New-CollectorMetadata -Payload $payload
    $outputPath = Export-CollectorResult -OutputDirectory $OutputDirectory -FileName 'uac.json' -Data $result -Depth 6
    Write-Output $outputPath
}

Invoke-Main
