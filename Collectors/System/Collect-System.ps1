<#!
.SYNOPSIS
    Legacy system inventory collector (deprecated in favor of msinfo32).
.DESCRIPTION
    This collector previously queried WMI and systeminfo.exe to assemble
    operating system and hardware metadata. That work now lives in
    Collect-MsInfo.ps1, so this script simply emits a compatibility artifact
    pointing analyzers at msinfo32.json.
#>
[CmdletBinding()]
param(
    [Parameter()]
    [string]$OutputDirectory = (Join-Path -Path (Split-Path -Parent $PSCommandPath) -ChildPath '..\output')
)

. (Join-Path -Path $PSScriptRoot -ChildPath '..\CollectorCommon.ps1')

function Invoke-Main {
    $payload = [ordered]@{
        Source  = 'msinfo32'
        Message = 'System metadata now lives in msinfo32.json.'
        Deprecated = $true
    }

    $result = New-CollectorMetadata -Payload $payload
    $outputPath = Export-CollectorResult -OutputDirectory $OutputDirectory -FileName 'system.json' -Data $result -Depth 3
    Write-Output $outputPath
}

Invoke-Main
