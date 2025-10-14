<#!
.SYNOPSIS
    Collects OneDrive configuration and health signals for the signed-in user.
#>
[CmdletBinding()]
param(
    [Parameter()]
    [string]$OutputDirectory = (Join-Path -Path (Split-Path -Parent $PSCommandPath) -ChildPath '..\\output')
)

. (Join-Path -Path $PSScriptRoot -ChildPath '..\\CollectorCommon.ps1')

$repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$oneDriveModule = Join-Path -Path $repoRoot -ChildPath 'Modules\\Collectors\\Cloud\\OneDrive.ps1'
if (Test-Path -LiteralPath $oneDriveModule) {
    . $oneDriveModule
}

function Invoke-Main {
    $payload = [ordered]@{
        OneDrive = $null
    }

    try {
        if (Get-Command -Name Get-OneDriveState -ErrorAction SilentlyContinue) {
            $payload.OneDrive = Get-OneDriveState
        }
    } catch {
        $payload.OneDrive = [pscustomobject]@{
            Error = $_.Exception.Message
        }
    }

    $result = New-CollectorMetadata -Payload $payload
    $outputPath = Export-CollectorResult -OutputDirectory $OutputDirectory -FileName 'cloud-onedrive.json' -Data $result -Depth 6
    Write-Output $outputPath
}

Invoke-Main
