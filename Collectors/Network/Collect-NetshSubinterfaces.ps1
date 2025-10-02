<#!
.SYNOPSIS
    Captures IPv4 and IPv6 subinterface metrics from netsh for MTU analysis.
.DESCRIPTION
    Runs "netsh interface ipv4 show subinterfaces" and the IPv6 equivalent to
    persist raw command output as a JSON artifact for later MTU compliance checks.
    When executed on non-Windows platforms or when netsh is unavailable, the
    collector records the failure message for analyzer visibility.
#>
[CmdletBinding()]
param(
    [Parameter()] 
    [string]$OutputDirectory = (Join-Path -Path (Split-Path -Parent $PSCommandPath) -ChildPath '..\\output')
)

. (Join-Path -Path $PSScriptRoot -ChildPath '..\\CollectorCommon.ps1')

function Invoke-NetshSubinterfacesCommand {
    param(
        [Parameter(Mandatory)]
        [ValidateSet('ipv4','ipv6')]
        [string]$AddressFamily
    )

    $arguments = @('interface', $AddressFamily, 'show', 'subinterfaces')
    $label = 'netsh interface {0} show subinterfaces' -f $AddressFamily
    return Invoke-CollectorNativeCommand -FilePath 'netsh.exe' -ArgumentList $arguments -SourceLabel $label
}

function Invoke-Main {
    $payload = [ordered]@{
        IPv4 = Invoke-NetshSubinterfacesCommand -AddressFamily 'ipv4'
        IPv6 = Invoke-NetshSubinterfacesCommand -AddressFamily 'ipv6'
    }

    $result = New-CollectorMetadata -Payload $payload
    $outputPath = Export-CollectorResult -OutputDirectory $OutputDirectory -FileName 'netsh-subinterfaces.json' -Data $result -Depth 4
    Write-Output $outputPath
}

Invoke-Main
