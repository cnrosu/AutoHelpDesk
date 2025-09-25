<#!
.SYNOPSIS
    Collects Kernel DMA protection configuration using fast data sources with msinfo32 fallback.
#>
[CmdletBinding()]
param(
    [Parameter()]
    [string]$OutputDirectory = (Join-Path -Path (Split-Path -Parent $PSCommandPath) -ChildPath '..\output')
)

. (Join-Path -Path $PSScriptRoot -ChildPath '..\CollectorCommon.ps1')
. (Join-Path -Path $PSScriptRoot -ChildPath '..\System\KernelDMAStatus.ps1')

function Invoke-Main {
    $status = Get-KernelDmaStatusData -MsInfoTimeoutSeconds 4

    $payload = [ordered]@{
        DeviceGuard = $status.DeviceGuard
        Registry    = $status.Registry
        MsInfo      = $status.MsInfo
    }

    $result = New-CollectorMetadata -Payload $payload
    $outputPath = Export-CollectorResult -OutputDirectory $OutputDirectory -FileName 'kerneldma.json' -Data $result -Depth 6
    Write-Output $outputPath
}

Invoke-Main
