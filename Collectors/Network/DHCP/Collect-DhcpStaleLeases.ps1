<#!
.SYNOPSIS
    Collects DHCP lease history data for identifying stale leases that have not renewed recently.
#>
[CmdletBinding()]
param(
    [Parameter()]
    [string]$OutputDirectory = (Join-Path -Path (Split-Path -Parent $PSCommandPath) -ChildPath '..\\..\\output')
)

. (Join-Path -Path $PSScriptRoot -ChildPath '..\\..\\CollectorCommon.ps1')
. (Join-Path -Path $PSScriptRoot -ChildPath 'Dhcp-Common.ps1')

function Invoke-Main {
    $payload = New-DhcpBasePayload
    $payload['CurrentTime'] = (Get-Date).ToString('o')

    $result = New-CollectorMetadata -Payload $payload
    $outputPath = Export-CollectorResult -OutputDirectory $OutputDirectory -FileName 'dhcp-stale-leases.json' -Data $result -Depth 6
    Write-Output $outputPath
}

Invoke-Main
