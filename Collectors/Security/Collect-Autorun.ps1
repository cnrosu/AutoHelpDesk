<#!
.SYNOPSIS
    Collects autorun and autoplay policy configuration from registry.
#>
[CmdletBinding()]
param(
    [Parameter()]
    [string]$OutputDirectory = (Join-Path -Path (Split-Path -Parent $PSCommandPath) -ChildPath '..\\output')
)

. (Join-Path -Path $PSScriptRoot -ChildPath '..\\CollectorCommon.ps1')

function Get-ExplorerPolicyValues {
    param(
        [string[]]$Paths
    )

    $result = [System.Collections.Generic.List[pscustomobject]]::new()

    foreach ($path in $Paths) {
        $entry = [ordered]@{
            Path = $path
        }

        if (-not (Test-Path -Path $path)) {
            $entry['Exists'] = $false
            $result.Add([pscustomobject]$entry) | Out-Null
            continue
        }

        $entry['Exists'] = $true

        try {
            $values = Get-ItemProperty -Path $path -ErrorAction Stop | Select-Object * -ExcludeProperty PS*, CIM*, PSEdition
            $entry['Values'] = $values
        } catch {
            $entry['Error'] = $_.Exception.Message
        }

        $result.Add([pscustomobject]$entry) | Out-Null
    }

    return $result.ToArray()
}

function Invoke-Main {
    $paths = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer',
        'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer',
        'HKCU:\SOFTWARE\Policies\Microsoft\Windows\Explorer'
    )

    $payload = [ordered]@{
        ExplorerPolicies = Get-ExplorerPolicyValues -Paths $paths
    }

    $result = New-CollectorMetadata -Payload $payload
    $outputPath = Export-CollectorResult -OutputDirectory $OutputDirectory -FileName 'autorun.json' -Data $result -Depth 6
    Write-Output $outputPath
}

Invoke-Main
