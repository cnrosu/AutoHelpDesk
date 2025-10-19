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

function Get-LapsOperationalEvents {
    param(
        [Parameter()] [int]$MaxEvents = 200
    )

    try {
        $events = @(Get-WinEvent -LogName 'Microsoft-Windows-LAPS/Operational' -MaxEvents $MaxEvents -ErrorAction Stop)
        if (-not $events) { return @() }

        $normalized = [System.Collections.Generic.List[pscustomobject]]::new()
        foreach ($event in ($events | Select-Object -First $MaxEvents)) {
            if (-not $event) { continue }

            $message = $null
            if ($event.PSObject.Properties['Message'] -and $event.Message) {
                $messageLines = ($event.Message -split "`r?`n")
                $message = if ($messageLines.Count -gt 0) { $messageLines[0] } else { [string]$event.Message }
            }

            $null = $normalized.Add([pscustomobject]@{
                Id               = $event.Id
                LevelDisplayName = $event.LevelDisplayName
                TimeCreatedUtc   = ConvertTo-IsoUtc $event.TimeCreated
                Message          = $message
            })
        }

        return $normalized.ToArray()
    } catch {
        @([pscustomobject]@{
            Source = 'Microsoft-Windows-LAPS/Operational'
            Error  = $_.Exception.Message
        })
    }
}

function Get-LapsDetectionSummary {
    param(
        [object]$State,
        [object[]]$OperationalEvents
    )

    $state = if ($State) { $State } else { [pscustomobject]@{} }
    $signals = [System.Collections.Generic.List[string]]::new()
    $events = @()
    if ($OperationalEvents) {
        foreach ($errorEntry in ($OperationalEvents | Where-Object { $_.PSObject.Properties['Error'] })) {
            if ($errorEntry.Error) {
                $signals.Add("Failed to read LAPS operational log: $($errorEntry.Error)")
            }
        }

        $events = $OperationalEvents | Where-Object { -not ($_.PSObject.Properties['Error']) }
    }
    $recentCutoff = (Get-Date).ToUniversalTime().AddDays(-35)

    $hasAzureExpiry     = $state.PSObject.Properties.Name -contains 'AzurePasswordExpiryTime'
    $hasDirectoryExpiry = $state.PSObject.Properties.Name -contains 'DirectoryPasswordExpiryTime'
    $lastRotationUtc    = $null
    $lastRotationRaw    = $null
    $recentRotation     = $false

    if ($state.PSObject.Properties['LastPasswordUpdateTime'] -and $state.LastPasswordUpdateTime) {
        try {
            $lastRotationRaw = [int64]$state.LastPasswordUpdateTime
            if ($lastRotationRaw -gt 0) {
                $lastRotationUtc = [DateTime]::FromFileTimeUtc($lastRotationRaw)
                if ($lastRotationUtc) {
                    $signals.Add("LastPasswordUpdateTime => $($lastRotationUtc.ToString('u')) (UTC)")
                    if ($lastRotationUtc.ToUniversalTime() -ge $recentCutoff) {
                        $recentRotation = $true
                        $signals.Add('Last password rotation occurred within the last 35 days.')
                    } else {
                        $signals.Add('Last password rotation older than 35 days or timestamp stale.')
                    }
                }
            }
        } catch {
            $signals.Add("Failed to parse LastPasswordUpdateTime: $($_.Exception.Message)")
        }
    } else {
        $signals.Add('LastPasswordUpdateTime registry value missing or zero.')
    }

    if ($hasAzureExpiry) {
        $signals.Add('AzurePasswordExpiryTime present in registry state.')
    }
    if ($hasDirectoryExpiry) {
        $signals.Add('DirectoryPasswordExpiryTime present in registry state.')
    }

    $parsedEvents = @()
    foreach ($event in $events) {
        if (-not $event) { continue }
        $eventTime = $null
        if ($event.PSObject.Properties['TimeCreatedUtc'] -and $event.TimeCreatedUtc) {
            try {
                $eventTime = [DateTime]::Parse($event.TimeCreatedUtc).ToUniversalTime()
            } catch {
                $eventTime = $null
            }
        }

        if ($eventTime -and $eventTime -ge $recentCutoff) {
            $parsedEvents += [pscustomobject]@{
                Id      = $event.Id
                Message = $event.Message
            }
        }
    }

    $azureLogEvents = @($parsedEvents | Where-Object { $_.Id -eq 10010 -or ($_.Message -match 'Azure Active Directory') })
    $adLogEvents    = @($parsedEvents | Where-Object { $_.Id -eq 10009 -or (($_.Message -match 'Active Directory') -and ($_.Message -notmatch 'Azure')) })
    $successEvents  = @($parsedEvents | Where-Object { $_.Id -eq 10004 -or ($_.Message -match 'policy processing succeeded') })

    if ($azureLogEvents.Count -gt 0) {
        $signals.Add(('Operational log recorded Azure backup events (IDs: {0}).' -f (($azureLogEvents | Select-Object -ExpandProperty Id) -join ', ')))
    }
    if ($adLogEvents.Count -gt 0) {
        $signals.Add(('Operational log recorded Active Directory backup events (IDs: {0}).' -f (($adLogEvents | Select-Object -ExpandProperty Id) -join ', ')))
    }
    if ($successEvents.Count -gt 0) {
        $signals.Add(('Operational log recorded policy success events (IDs: {0}).' -f (($successEvents | Select-Object -ExpandProperty Id) -join ', ')))
    }

    $azureActive = ($hasAzureExpiry -and $recentRotation) -or ($azureLogEvents.Count -gt 0 -and $successEvents.Count -gt 0)
    $adActive    = ($hasDirectoryExpiry -and $recentRotation) -or ($adLogEvents.Count -gt 0 -and $successEvents.Count -gt 0)

    $primaryTarget = if ($hasAzureExpiry) {
        'Entra'
    } elseif ($hasDirectoryExpiry) {
        'AD'
    } else {
        'None'
    }

    $backupTarget = if ($primaryTarget -ne 'None') {
        $primaryTarget
    } elseif ($azureLogEvents.Count -gt 0) {
        'Entra'
    } elseif ($adLogEvents.Count -gt 0) {
        'AD'
    } else {
        'Unknown'
    }

    $active = $azureActive -or $adActive -or ($successEvents.Count -gt 0 -and ($azureLogEvents.Count -gt 0 -or $adLogEvents.Count -gt 0))

    [pscustomobject]@{
        LapsActive              = [bool]$active
        AzureActive             = [bool]$azureActive
        ActiveDirectoryActive   = [bool]$adActive
        BackupTarget            = $backupTarget
        RecentRotation          = [bool]$recentRotation
        LastRotationUtc         = if ($lastRotationUtc) { $lastRotationUtc.ToString('o') } else { $null }
        LastPasswordUpdateTime  = $lastRotationRaw
        ManagedRid              = if ($state.PSObject.Properties['LastManagedAccountRid']) { $state.LastManagedAccountRid } else { $null }
        AzureExpiryPresent      = [bool]$hasAzureExpiry
        DirectoryExpiryPresent  = [bool]$hasDirectoryExpiry
        AzureLogHint            = [bool]($azureLogEvents.Count -gt 0)
        ActiveDirectoryLogHint  = [bool]($adLogEvents.Count -gt 0)
        SuccessLogHint          = [bool]($successEvents.Count -gt 0)
        Signals                 = $signals.ToArray()
    }
}

# ------------------------
# LAPS footprints
# ------------------------

function Get-LapsPolicyFootprints {
    $policy = Get-RegistryObject -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LAPS'
    $state  = Get-RegistryObject -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\LAPS\State'
    $legacy = Get-RegistryObject -Path 'HKLM:\SOFTWARE\Policies\Microsoft Services\AdmPwd'
    $events = Get-LapsOperationalEvents
    $detection = Get-LapsDetectionSummary -State $state -OperationalEvents $events

    [ordered]@{
        WindowsLapsPolicy        = $policy
        WindowsLapsState         = $state
        WindowsLapsOperationalLog= $events
        WindowsLapsDetection     = $detection
        LegacyAdmPwdPolicy       = $legacy
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
