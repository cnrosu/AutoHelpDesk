<#!
.SYNOPSIS
    Collects adapter and DHCP client event data for identifying exhausted DHCP scopes.
#>
[CmdletBinding()]
param(
    [Parameter()]
    [string]$OutputDirectory = (Join-Path -Path (Split-Path -Parent $PSCommandPath) -ChildPath '..\\..\\output')
)

. (Join-Path -Path $PSScriptRoot -ChildPath '..\\..\\CollectorCommon.ps1')
. (Join-Path -Path $PSScriptRoot -ChildPath 'Dhcp-Common.ps1')

function Invoke-Main {
    $payload = New-DhcpBasePayload -IncludeEvents -EventIds @(1046,1003,1005)
    $payload['CurrentTime'] = (Get-Date).ToString('o')

    $result = New-CollectorMetadata -Payload $payload
    $outputPath = Export-CollectorResult -OutputDirectory $OutputDirectory -FileName 'dhcp-scope-exhaustion.json' -Data $result -Depth 6
    Write-Output $outputPath
}

Invoke-Main
