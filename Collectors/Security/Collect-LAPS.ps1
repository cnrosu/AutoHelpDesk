<#!
.SYNOPSIS
    Collects Local Administrator Password Solution (LAPS) policy and local administrator inventory.
#>
[CmdletBinding()]
param(
    [Parameter()]
    [string]$OutputDirectory = (Join-Path -Path (Split-Path -Parent $PSCommandPath) -ChildPath '..\\output')
)

. (Join-Path -Path $PSScriptRoot -ChildPath '..\\CollectorCommon.ps1')

function Get-RegistryObject {
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )

    try {
        return Get-ItemProperty -Path $Path -ErrorAction Stop | Select-Object * -ExcludeProperty PS*, CIM*, PSEdition
    } catch {
        return $null
    }
}

function Get-LapsPolicyFootprints {
    $policy = Get-RegistryObject -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LAPS'
    $state  = Get-RegistryObject -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\LAPS\State'
    $legacy = Get-RegistryObject -Path 'HKLM:\SOFTWARE\Policies\Microsoft Services\AdmPwd'

    return [ordered]@{
        WindowsLapsPolicy  = $policy
        WindowsLapsState   = $state
        LegacyAdmPwdPolicy = $legacy
    }
}

function Get-LocalAdminInventory {
    try {
        $members = @(Get-LocalGroupMember -Group 'Administrators' -ErrorAction Stop)
        $localUsers = @()
        try {
            $localUsers = @(Get-LocalUser -ErrorAction Stop)
        } catch {
            $localUsers = @()
        }

        $inventory = @()
        foreach ($member in $members) {
            $isLocalUser = ($member.ObjectClass -eq 'User' -and $member.PrincipalSource -in @('Local', 'MicrosoftAccount'))
            $userDetails = $null
            if ($isLocalUser -and $localUsers) {
                $matched = $localUsers | Where-Object Name -eq $member.Name | Select-Object -First 1
                if ($matched) {
                    $lastSet = $null
                    if ($matched.LastPasswordSet) {
                        try { $lastSet = $matched.LastPasswordSet.ToUniversalTime().ToString('o') } catch { $lastSet = $matched.LastPasswordSet }
                    }

                    $userDetails = [PSCustomObject]@{
                        Sid                  = $matched.SID.Value
                        Enabled              = [bool]$matched.Enabled
                        PasswordNeverExpires = [bool]$matched.PasswordNeverExpires
                        LastPasswordSet      = $lastSet
                        IsBuiltInAdmin       = ($matched.SID.Value -match '-500$')
                    }
                }
            }

            $inventory += [PSCustomObject]@{
                Name             = $member.Name
                ObjectClass      = $member.ObjectClass
                PrincipalSource  = $member.PrincipalSource
                IsLocalUser      = [bool]$isLocalUser
                LocalUserDetails = $userDetails
            }
        }

        return $inventory
    } catch {
        try {
            $output = net.exe localgroup administrators 2>&1
            return [PSCustomObject]@{
                Source = 'net localgroup administrators'
                Output = $output
            }
        } catch {
            return [PSCustomObject]@{
                Source = 'LocalAdministrators'
                Error  = $_.Exception.Message
            }
        }
    }
}

function Invoke-Main {
    $payload = [ordered]@{
        Host             = $env:COMPUTERNAME
        LapsPolicies     = Get-LapsPolicyFootprints
        LocalAdministrators = Get-LocalAdminInventory
    }

    $result = New-CollectorMetadata -Payload $payload
    $outputPath = Export-CollectorResult -OutputDirectory $OutputDirectory -FileName 'laps_localadmin.json' -Data $result -Depth 8
    Write-Output $outputPath
}

Invoke-Main
