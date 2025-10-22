<#!
.SYNOPSIS
    Collects device identity posture including Entra ID registration and current user context.
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

if ([string]::IsNullOrWhiteSpace($__ScriptRoot)) { throw 'Script root unavailable.' }

$collectorCommonPath = Join-Path -Path $__ScriptRoot -ChildPath '..\CollectorCommon.ps1'
if (-not (Test-Path -LiteralPath $collectorCommonPath)) { throw 'Unable to resolve CollectorCommon.ps1 path.' }
. $collectorCommonPath

if (-not (Get-Command -Name Join-PathSafe -ErrorAction SilentlyContinue)) { throw 'Join-PathSafe helper is unavailable.' }

if (-not $PSBoundParameters.ContainsKey('OutputDirectory') -or [string]::IsNullOrWhiteSpace($OutputDirectory)) {
    $defaultOutput = Join-PathSafe $__ScriptRoot '..\output'
    if (-not $defaultOutput) {
        Write-Verbose 'Script root unavailable; defaulting output to current directory.'
        $locationPath = (Get-Location).Path
        $defaultOutput = Join-PathSafe $locationPath '..\output'
        if (-not $defaultOutput) { $defaultOutput = $locationPath }
    }
    $OutputDirectory = $defaultOutput
}


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
