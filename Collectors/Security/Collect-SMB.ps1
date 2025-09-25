<#!
.SYNOPSIS
    Collects SMB server configuration for security review.
#>
[CmdletBinding()]
param(
    [Parameter()]
    [string]$OutputDirectory = (Join-Path -Path (Split-Path -Parent $PSCommandPath) -ChildPath '..\\output')
)

. (Join-Path -Path $PSScriptRoot -ChildPath '..\\CollectorCommon.ps1')

function Get-SmbServerConfig {
    try {
        return Get-SmbServerConfiguration -ErrorAction Stop | Select-Object EnableSMB1Protocol, EnableSMB2Protocol, EncryptData, RejectUnencryptedAccess, EnableLeasing, EnableStrictNameChecking, EnableAuthenticateUserSharing, EnableSecuritySignature
    } catch {
        return [PSCustomObject]@{
            Source = 'Get-SmbServerConfiguration'
            Error  = $_.Exception.Message
        }
    }
}

function Invoke-Main {
    $payload = [ordered]@{
        Configuration = Get-SmbServerConfig
    }

    $result = New-CollectorMetadata -Payload $payload
    $outputPath = Export-CollectorResult -OutputDirectory $OutputDirectory -FileName 'smb.json' -Data $result -Depth 4
    Write-Output $outputPath
}

Invoke-Main
