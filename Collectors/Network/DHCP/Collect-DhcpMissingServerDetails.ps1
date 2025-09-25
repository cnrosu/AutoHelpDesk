<#!
.SYNOPSIS
    Collects adapter state for identifying DHCP-enabled interfaces missing server assignments.
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
    $outputPath = Export-CollectorResult -OutputDirectory $OutputDirectory -FileName 'dhcp-missing-server-details.json' -Data $result -Depth 6
    Write-Output $outputPath
}

Invoke-Main
