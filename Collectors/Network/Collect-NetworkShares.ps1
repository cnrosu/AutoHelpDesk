<#!
.SYNOPSIS
    Collects network share configuration using net share.
#>
[CmdletBinding()]
param(
    [Parameter()]
    [string]$OutputDirectory = (Join-Path -Path (Split-Path -Parent $PSCommandPath) -ChildPath '..\\output')
)

. (Join-Path -Path $PSScriptRoot -ChildPath '..\\CollectorCommon.ps1')

function Get-NetShares {
    try {
        return net.exe share 2>$null
    } catch {
        return [PSCustomObject]@{
            Source = 'net share'
            Error  = $_.Exception.Message
        }
    }
}

function Invoke-Main {
    $payload = [ordered]@{
        Shares = Get-NetShares
    }

    $result = New-CollectorMetadata -Payload $payload
    $outputPath = Export-CollectorResult -OutputDirectory $OutputDirectory -FileName 'network-shares.json' -Data $result -Depth 6
    Write-Output $outputPath
}

Invoke-Main
