<#!
.SYNOPSIS
    Collects SmartScreen and app control policy configuration.
#>
[CmdletBinding()]
param(
    [Parameter()]
    [string]$OutputDirectory = (Join-Path -Path (Split-Path -Parent $PSCommandPath) -ChildPath '..\\output')
)

. (Join-Path -Path $PSScriptRoot -ChildPath '..\\CollectorCommon.ps1')

function Get-SmartScreenPolicies {
    $paths = @(
        'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System',
        'HKCU:\SOFTWARE\Policies\Microsoft\Windows\System',
        'HKLM:\SOFTWARE\Policies\Microsoft\Edge',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost'
    )

    $result = [System.Collections.Generic.List[pscustomobject]]::new()
    foreach ($path in $paths) {
        try {
            $values = Get-ItemProperty -Path $path -ErrorAction Stop | Select-Object * -ExcludeProperty PS*, CIM*, PSEdition
            $result.Add([PSCustomObject]@{
                Path   = $path
                Values = $values
            })
        } catch {
            $result.Add([PSCustomObject]@{
                Path  = $path
                Error = $_.Exception.Message
            })
        }
    }

    return $result.ToArray()
}

function Invoke-Main {
    $payload = [ordered]@{
        Policies = Get-SmartScreenPolicies
    }

    $result = New-CollectorMetadata -Payload $payload
    $outputPath = Export-CollectorResult -OutputDirectory $OutputDirectory -FileName 'smartscreen.json' -Data $result -Depth 6
    Write-Output $outputPath
}

Invoke-Main
