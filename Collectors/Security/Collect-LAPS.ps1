<#!
.SYNOPSIS
    Collects Local Administrator Password Solution (LAPS) policy footprints
    and a normalized inventory of members of the local Administrators group.
.DESCRIPTION
    - Reads Windows LAPS (2023+) and Legacy LAPS (AdmPwd) registry footprints.
    - Enumerates Administrators group membership.
    - For *local user* members, enriches with Enabled/Password policy/SID/LastPasswordSet.
    - Robust matching uses SID-first, then name (stripping DOMAIN\ prefix).
    - Falls back to `net localgroup administrators` if modern cmdlets are unavailable.
    - Emits a single JSON at collectors\laps_localadmin.json via CollectorCommon helpers.
#>

[CmdletBinding()]
param(
    [Parameter()]
    [string]$OutputDirectory = (Join-Path -Path (Split-Path -Parent $PSCommandPath) -ChildPath '..\output')
)

# Import common collector helpers (New-CollectorMetadata, Export-CollectorResult, etc.)
. (Join-Path -Path $PSScriptRoot -ChildPath '..\CollectorCommon.ps1')

# ------------------------
# Helpers
# ------------------------

function Get-RegistryObject {
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )
    try {
        Get-ItemProperty -Path $Path -ErrorAction Stop |
            Select-Object * -ExcludeProperty PS*, CIM*, PSEdition
    } catch {
        $null
    }
}

function ConvertTo-IsoUtc {
    param([object]$Date)
    if (-not $Date) { return $null }
    try {
        ($Date).ToUniversalTime().ToString('o')
    } catch {
        try {
            $convertedValues = @([DateTime]$Date)
            $utcValues = [System.Collections.Generic.List[string]]::new()
            foreach ($value in $convertedValues) {
                $null = $utcValues.Add($value.ToUniversalTime().ToString('o'))
            }

            if ($utcValues.Count -eq 1) { return $utcValues[0] }
            return $utcValues
        } catch { $null }
    }
}

function Get-ValueIfPresent {
    param(
        [Parameter(Mandatory)] [object]$Object,
        [Parameter(Mandatory)] [string]$Property
    )
    if ($null -eq $Object) { return $null }
    if ($Object.PSObject.Properties[$Property]) {
        return $Object.$Property
    }
    $null
}

# ------------------------
# LAPS footprints
# ------------------------

function Get-LapsPolicyFootprints {
    $policy = Get-RegistryObject -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LAPS'
    $state  = Get-RegistryObject -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\LAPS\State'
    $legacy = Get-RegistryObject -Path 'HKLM:\SOFTWARE\Policies\Microsoft Services\AdmPwd'

    [ordered]@{
        WindowsLapsPolicy  = $policy
        WindowsLapsState   = $state
        LegacyAdmPwdPolicy = $legacy
    }
}

# ------------------------
# Local admin inventory (merged logic)
# ------------------------

function Get-LocalAdminInventory {
    # Try modern cmdlets first
    try {
        $members    = @(Get-LocalGroupMember -Group 'Administrators' -ErrorAction Stop)
        $localUsers = @()
        try {
            $localUsers = @(Get-LocalUser -ErrorAction Stop)
        } catch {
            $localUsers = @()
        }

        $inventory = [System.Collections.Generic.List[pscustomobject]]::new()


        foreach ($member in $members) {
            # Detect if this Administrators member is a *local* user (not a group/domain account)
            $isLocalUser = ($member.ObjectClass -eq 'User' -and $member.PrincipalSource -in @('Local','MicrosoftAccount'))

            # Attempt to enrich local user details using SID-first matching, then name
            $userDetails = $null
            if ($isLocalUser -and $localUsers.Count -gt 0) {
                # Try to read a SID from the member object if it exists
                $memberSid = $null
                if ($member.PSObject.Properties['SID'] -and $member.SID) {
                    try { $memberSid = $member.SID.Value } catch { $memberSid = [string]$member.SID }
                }

                $matched = $null
                if ($memberSid) {
                    $matched = $localUsers |
                        Where-Object { $_.PSObject.Properties['SID'] -and $_.SID -and $_.SID.Value -eq $memberSid } |
                        Select-Object -First 1
                }

                if (-not $matched) {
                    # Fall back to name match; strip DOMAIN\ if present
                    $nameCandidate = $member.Name
                    if ($nameCandidate -match '^[^\\]+\\(.+)$') { $nameCandidate = $matches[1] }
                    $matched = $localUsers | Where-Object { $_.Name -eq $nameCandidate } | Select-Object -First 1
                }

                if ($matched) {
                    $lastSetIso = ConvertTo-IsoUtc (Get-ValueIfPresent -Object $matched -Property 'LastPasswordSet')
                    $sidValue   = (Get-ValueIfPresent -Object $matched -Property 'SID')
                    if ($sidValue -and $sidValue -is [System.Security.Principal.SecurityIdentifier]) {
                        $sidValue = $sidValue.Value
                    }

                    $userDetails = [pscustomobject]@{
                        Sid                  = $sidValue
                        Enabled              = [bool](Get-ValueIfPresent -Object $matched -Property 'Enabled')
                        PasswordNeverExpires = [bool](Get-ValueIfPresent -Object $matched -Property 'PasswordNeverExpires')
                        LastPasswordSet      = $lastSetIso
                        IsBuiltInAdmin       = ($sidValue -match '-500$')  # RID 500
                    }
                }
            }

            # Keep the full membership row (local + non-local), with enrichment only for local user members
            $null = $inventory.Add([pscustomobject]@{
                Name             = $member.Name
                ObjectClass      = $member.ObjectClass
                PrincipalSource  = $member.PrincipalSource
                IsLocalUser      = [bool]$isLocalUser
                LocalUserDetails = $userDetails
            })
        }

        return $inventory.ToArray()


    } catch {
        # Fallback: legacy tool to at least capture membership text
        try {
            $output = net.exe localgroup administrators 2>&1
            $fallback = [System.Collections.Generic.List[pscustomobject]]::new()
            $null = $fallback.Add([pscustomobject]@{
                Source    = 'net localgroup administrators'
                RawOutput = ($output -join "`r`n")
            })
            return $fallback.ToArray()
        } catch {
            $fallbackError = [System.Collections.Generic.List[pscustomobject]]::new()
            $null = $fallbackError.Add([pscustomobject]@{
                Source = 'LocalAdministrators'
                Error  = $_.Exception.Message
            })
            return $fallbackError.ToArray()
        }
    }
}

# ------------------------
# Main
# ------------------------

function Invoke-Main {
    $payload = [ordered]@{
        Host               = $env:COMPUTERNAME
        LapsPolicies       = Get-LapsPolicyFootprints
        LocalAdministrators= Get-LocalAdminInventory
    }

    $result     = New-CollectorMetadata -Payload $payload
    $outputPath = Export-CollectorResult -OutputDirectory $OutputDirectory -FileName 'laps_localadmin.json' -Data $result -Depth 8
    Write-Output $outputPath
}

Invoke-Main
