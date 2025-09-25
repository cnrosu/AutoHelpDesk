<#!
.SYNOPSIS
    Collects local Administrators group membership.
#>
[CmdletBinding()]
param(
    [Parameter()]
    [string]$OutputDirectory = (Join-Path -Path (Split-Path -Parent $PSCommandPath) -ChildPath '..\\output')
)

. (Join-Path -Path $PSScriptRoot -ChildPath '..\\CollectorCommon.ps1')

function Get-LocalAdmins {
    try {
        return Get-LocalGroupMember -Group 'Administrators' -ErrorAction Stop | Select-Object Name, ObjectClass, PrincipalSource
    } catch {
        Write-Verbose "Get-LocalGroupMember failed: $($_.Exception.Message)"
        try {
            $output = & net localgroup Administrators 2>$null
            return [PSCustomObject]@{
                Source    = 'net localgroup'
                RawOutput = $output -join [Environment]::NewLine
            }
        } catch {
            return [PSCustomObject]@{
                Source = 'Get-LocalGroupMember'
                Error  = $_.Exception.Message
            }
        }
    }
}

function Invoke-Main {
    $payload = [ordered]@{
        Members = Get-LocalAdmins
    }

    $result = New-CollectorMetadata -Payload $payload
    $outputPath = Export-CollectorResult -OutputDirectory $OutputDirectory -FileName 'local-admins.json' -Data $result -Depth 6
    Write-Output $outputPath
}

Invoke-Main
