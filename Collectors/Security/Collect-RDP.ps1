<#!
.SYNOPSIS
    Collects Remote Desktop Protocol configuration from the registry.
#>
[CmdletBinding()]
param(
    [Parameter()]
    [string]$OutputDirectory = (Join-Path -Path (Split-Path -Parent $PSCommandPath) -ChildPath '..\\output')
)

. (Join-Path -Path $PSScriptRoot -ChildPath '..\\CollectorCommon.ps1')

function Get-RdpConfiguration {
    $paths = @(
        'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server',
        'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp',
        'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
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
        Registry = Get-RdpConfiguration
    }

    $result = New-CollectorMetadata -Payload $payload
    $outputPath = Export-CollectorResult -OutputDirectory $OutputDirectory -FileName 'rdp.json' -Data $result -Depth 6
    Write-Output $outputPath
}

Invoke-Main
