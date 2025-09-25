<#!
.SYNOPSIS
    Collects Microsoft Office security policy configuration from registry locations.
#>
[CmdletBinding()]
param(
    [Parameter()]
    [string]$OutputDirectory = (Join-Path -Path (Split-Path -Parent $PSCommandPath) -ChildPath '..\\output')
)

. (Join-Path -Path $PSScriptRoot -ChildPath '..\\CollectorCommon.ps1')

function Get-OfficeSecurityPolicies {
    $paths = @(
        'HKCU:\SOFTWARE\Policies\Microsoft\Office\16.0\Common\Security',
        'HKLM:\SOFTWARE\Policies\Microsoft\Office\16.0\Common\Security',
        'HKCU:\SOFTWARE\Microsoft\Office\16.0\Word\Security',
        'HKLM:\SOFTWARE\Policies\Microsoft\Office\16.0\Word\Security'
    )

    $result = @()
    foreach ($path in $paths) {
        try {
            if (Test-Path -Path $path) {
                $values = Get-ItemProperty -Path $path -ErrorAction Stop | Select-Object * -ExcludeProperty PS*, CIM*, PSEdition
                $result += [PSCustomObject]@{
                    Path   = $path
                    Values = $values
                }
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
        Policies = Get-OfficeSecurityPolicies
    }

    $result = New-CollectorMetadata -Payload $payload
    $outputPath = Export-CollectorResult -OutputDirectory $OutputDirectory -FileName 'office-policies.json' -Data $result -Depth 6
    Write-Output $outputPath
}

Invoke-Main
