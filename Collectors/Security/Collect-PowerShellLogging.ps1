<#!
.SYNOPSIS
    Collects PowerShell logging policy configuration.
#>
[CmdletBinding()]
param(
    [Parameter()]
    [string]$OutputDirectory = (Join-Path -Path (Split-Path -Parent $PSCommandPath) -ChildPath '..\\output')
)

. (Join-Path -Path $PSScriptRoot -ChildPath '..\\CollectorCommon.ps1')

function Get-PowerShellPolicy {
    $paths = @(
        'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell',
        'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging',
        'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging',
        'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription'
    )

    $result = @()
    foreach ($path in $paths) {
        try {
            $values = Get-ItemProperty -Path $path -ErrorAction Stop | Select-Object * -ExcludeProperty PS*, CIM*, PSEdition
            $result += [PSCustomObject]@{
                Path   = $path
                Values = $values
            }
        } catch {
            $result += [PSCustomObject]@{
                Path  = $path
                Error = $_.Exception.Message
            }
        }
    }

    return $result
}

function Invoke-Main {
    $payload = [ordered]@{
        Policies = Get-PowerShellPolicy
    }

    $result = New-CollectorMetadata -Payload $payload
    $outputPath = Export-CollectorResult -OutputDirectory $OutputDirectory -FileName 'powershell-logging.json' -Data $result -Depth 6
    Write-Output $outputPath
}

Invoke-Main
