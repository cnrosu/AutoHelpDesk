<#!
.SYNOPSIS
    Collects recent Microsoft-Windows-DHCP-Client events relevant to lease failures and conflicts.
#>
[CmdletBinding()]
param(
    [Parameter()]
    [string]$OutputDirectory = (Join-Path -Path (Split-Path -Parent $PSCommandPath) -ChildPath '..\\..\\output')
)

. (Join-Path -Path $PSScriptRoot -ChildPath '..\\..\\CollectorCommon.ps1')
. (Join-Path -Path $PSScriptRoot -ChildPath 'Dhcp-Common.ps1')

function Invoke-Main {
    $payload = New-DhcpBasePayload -IncludeEvents -EventIds @(1001,1003,1005,1006,50013,1046) -MaxEvents 400
    $payload['CurrentTime'] = (Get-Date).ToString('o')

    $result = New-CollectorMetadata -Payload $payload
    $outputPath = Export-CollectorResult -OutputDirectory $OutputDirectory -FileName 'dhcp-client-events.json' -Data $result -Depth 6
    Write-Output $outputPath
}

Invoke-Main
