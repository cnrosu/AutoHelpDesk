<#!
.SYNOPSIS
    Collects DHCP adapter and event data once for reuse by all DHCP analyzers.
.DESCRIPTION
    Queries adapter configuration and key Microsoft-Windows-DHCP-Client events, then
    writes a consolidated JSON payload (dhcp-base.json) so downstream analyzers and
    automations can derive scenario-specific views without re-querying the endpoint.
#>
[CmdletBinding()]
param(
    [Parameter()]
    [string]$OutputDirectory = (Join-Path -Path (Split-Path -Parent $PSCommandPath) -ChildPath '..\\..\\output')
)

. (Join-Path -Path $PSScriptRoot -ChildPath '..\\..\\CollectorCommon.ps1')
. (Join-Path -Path $PSScriptRoot -ChildPath 'Dhcp-Common.ps1')

# Union of the DHCP client events previously gathered by the specialized collectors.
$script:DhcpEventIds = @(1001, 1003, 1005, 1006, 50013, 1046)

function Invoke-Main {
    $payload = New-DhcpBasePayload -IncludeEvents -EventIds $script:DhcpEventIds -MaxEvents 400
    $payload['CurrentTime'] = (Get-Date).ToString('o')

    $metadata = New-CollectorMetadata -Payload $payload
    $outputPath = Export-CollectorResult -OutputDirectory $OutputDirectory -FileName 'dhcp-base.json' -Data $metadata -Depth 6

    Write-Output $outputPath
}

Invoke-Main
