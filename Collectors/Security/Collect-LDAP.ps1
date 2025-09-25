<#!
.SYNOPSIS
    Collects LDAP signing and channel binding configuration.
#>
[CmdletBinding()]
param(
    [Parameter()]
    [string]$OutputDirectory = (Join-Path -Path (Split-Path -Parent $PSCommandPath) -ChildPath '..\\output')
)

. (Join-Path -Path $PSScriptRoot -ChildPath '..\\CollectorCommon.ps1')

function Get-LdapSigningSettings {
    $paths = @(
        'HKLM:\SYSTEM\CurrentControlSet\Services\LDAP',
        'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters'
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
        Registry = Get-LdapSigningSettings
    }

    $result = New-CollectorMetadata -Payload $payload
    $outputPath = Export-CollectorResult -OutputDirectory $OutputDirectory -FileName 'ldap.json' -Data $result -Depth 6
    Write-Output $outputPath
}

Invoke-Main
