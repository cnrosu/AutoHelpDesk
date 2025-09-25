<#!
.SYNOPSIS
    Collects LSA hardening and NTLM authentication configuration.
#>
[CmdletBinding()]
param(
    [Parameter()]
    [string]$OutputDirectory = (Join-Path -Path (Split-Path -Parent $PSCommandPath) -ChildPath '..\\output')
)

. (Join-Path -Path $PSScriptRoot -ChildPath '..\\CollectorCommon.ps1')

function Get-LsaRegistryValues {
    $paths = @(
        'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa',
        'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0'
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
        Registry = Get-LsaRegistryValues
    }

    $result = New-CollectorMetadata -Payload $payload
    $outputPath = Export-CollectorResult -OutputDirectory $OutputDirectory -FileName 'lsa.json' -Data $result -Depth 6
    Write-Output $outputPath
}

Invoke-Main
