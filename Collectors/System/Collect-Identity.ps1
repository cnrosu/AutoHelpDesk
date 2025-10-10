<#!
.SYNOPSIS
    Collects device identity posture including Azure AD registration and current user context.
#>
[CmdletBinding()]
param(
    [Parameter()]
    [string]$OutputDirectory
)

function Get-ScriptRoot {
    if ($script:PSScriptRoot -and -not [string]::IsNullOrWhiteSpace($script:PSScriptRoot)) { return $script:PSScriptRoot }
    if ($MyInvocation.MyCommand.Path) { return (Split-Path -Parent $MyInvocation.MyCommand.Path) }
    return (Get-Location).Path
}

$__ScriptRoot = Get-ScriptRoot

if (-not $PSBoundParameters.ContainsKey('OutputDirectory') -or [string]::IsNullOrWhiteSpace($OutputDirectory)) {
    $OutputDirectory = Join-Path -Path $__ScriptRoot -ChildPath '..\output'
}

. (Join-Path -Path $__ScriptRoot -ChildPath '..\CollectorCommon.ps1')

function Get-AzureAdJoinStatus {
    try {
        return dsregcmd.exe /status 2>$null
    } catch {
        return [PSCustomObject]@{
            Source = 'dsregcmd.exe'
            Error  = $_.Exception.Message
        }
    }
}

function Get-WhoAmIContext {
    try {
        return whoami.exe /all 2>$null
    } catch {
        return [PSCustomObject]@{
            Source = 'whoami.exe'
            Error  = $_.Exception.Message
        }
    }
}

function Invoke-Main {
    $payload = [ordered]@{
        DsRegCmd = Get-AzureAdJoinStatus
        WhoAmI   = Get-WhoAmIContext
    }

    $result = New-CollectorMetadata -Payload $payload
    $outputPath = Export-CollectorResult -OutputDirectory $OutputDirectory -FileName 'identity.json' -Data $result -Depth 6
    Write-Output $outputPath
}

Invoke-Main
