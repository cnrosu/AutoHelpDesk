<#!
.SYNOPSIS
    Collects Autorun and Autoplay hardening policy values.
#>
[CmdletBinding()]
param(
    [Parameter()]
    [string]$OutputDirectory = (Join-Path -Path (Split-Path -Parent $PSCommandPath) -ChildPath '..\\output')
)

. (Join-Path -Path $PSScriptRoot -ChildPath '..\\CollectorCommon.ps1')

function Get-AutorunRegistryValues {
    $paths = @(
        'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer',
        'HKCU:\SOFTWARE\Policies\Microsoft\Windows\Explorer',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
    )

    $results = [System.Collections.Generic.List[pscustomobject]]::new()

    foreach ($path in $paths) {
        try {
            $values = Get-ItemProperty -Path $path -ErrorAction Stop | Select-Object * -ExcludeProperty PS*, CIM*, PSEdition
            $results.Add([pscustomobject]@{
                Path   = $path
                Values = $values
            }) | Out-Null
        } catch {
            $results.Add([pscustomobject]@{
                Path  = $path
                Error = $_.Exception.Message
            }) | Out-Null
        }
    }

    return $results.ToArray()
}

function Invoke-Main {
    $payload = [ordered]@{
        Registry = Get-AutorunRegistryValues
    }

    $result = New-CollectorMetadata -Payload $payload
    $outputPath = Export-CollectorResult -OutputDirectory $OutputDirectory -FileName 'autorun.json' -Data $result -Depth 6
    Write-Output $outputPath
}

Invoke-Main
