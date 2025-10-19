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
        return Get-SmbServerConfiguration -ErrorAction Stop |
            Select-Object EnableSMB1Protocol, EnableSMB2Protocol, EncryptData, RejectUnencryptedAccess,
                          EnableLeasing, EnableStrictNameChecking, EnableAuthenticateUserSharing,
                          EnableSecuritySignature, RequireSecuritySignature
    } catch {
        return [PSCustomObject]@{
            Source = 'Get-SmbServerConfiguration'
            Error  = $_.Exception.Message
        }
    }
}

function Get-SmbServerService {
    try {
        return Get-Service -Name 'LanmanServer' -ErrorAction Stop |
            Select-Object Name, Status, StartType
    } catch {
        return [PSCustomObject]@{
            Source = 'Get-Service'
            Target = 'LanmanServer'
            Error  = $_.Exception.Message
        }
    }
}

function Get-SmbListeners {
    try {
        $listeners = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
            Where-Object { $_.LocalPort -in 445, 139 } |
            Select-Object LocalAddress, LocalPort, State
        if ($null -eq $listeners) { return @() }
        if ($listeners -is [System.Collections.IEnumerable] -and -not ($listeners -is [string])) {
            return @($listeners | Where-Object { $_ })
        }
        return @($listeners)
    } catch {
        return [PSCustomObject]@{
            Source = 'Get-NetTCPConnection'
            Error  = $_.Exception.Message
        }
    }
}

function Get-SmbFirewallRules {
    $portsOfInterest = '445','139','137','138'
    try {
        $rulesAll = Get-NetFirewallRule -Enabled True -Direction Inbound -Action Allow -ErrorAction SilentlyContinue
    } catch {
        return [PSCustomObject]@{
            Source = 'Get-NetFirewallRule'
            Error  = $_.Exception.Message
        }
    }

    $results = [System.Collections.Generic.List[pscustomobject]]::new()

    foreach ($r in $rulesAll) {
        if (-not $r) { continue }

        try {
            $pf = Get-NetFirewallPortFilter -AssociatedNetFirewallRule $r -ErrorAction SilentlyContinue
        } catch {
            $pf = $null
        }
        if (-not $pf) { continue }

        $match = $pf.LocalPort | Where-Object { $_ -in $portsOfInterest }
        if (-not $match) { continue }

        try {
            $af = Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $r -ErrorAction SilentlyContinue
        } catch {
            $af = $null
        }

        $policyStore = $null
        if ($r.PSObject.Properties['PolicyStore']) { $policyStore = $r.PolicyStore }
        elseif ($r.PSObject.Properties['PolicyStoreSourceType']) { $policyStore = $r.PolicyStoreSourceType }
        elseif ($r.PSObject.Properties['PolicyStoreSource']) { $policyStore = $r.PolicyStoreSource }

        $record = [ordered]@{
            Name        = $r.Name
            DisplayName = $r.DisplayName
            Group       = $r.DisplayGroup
            Profile     = $r.Profile
            Action      = $r.Action
            Direction   = $r.Direction
            Enabled     = $r.Enabled
            Ports       = if ($pf.LocalPort) { ($pf.LocalPort -join ',') } else { $null }
            Protocol    = $pf.Protocol
            RemoteAddr  = if ($af -and $af.RemoteAddress) { ($af.RemoteAddress -join ',') } else { $null }
            PolicyStore = $policyStore
        }

        $results.Add([pscustomobject]$record) | Out-Null
    }

    return $results.ToArray()
}

function Get-SmbNetworkProfiles {
    try {
        $profiles = Get-NetConnectionProfile -ErrorAction Stop |
            Select-Object InterfaceAlias, IPv4Connectivity, NetworkCategory
        if ($null -eq $profiles) { return @() }
        if ($profiles -is [System.Collections.IEnumerable] -and -not ($profiles -is [string])) {
            return @($profiles | Where-Object { $_ })
        }
        return @($profiles)
    } catch {
        return [PSCustomObject]@{
            Source = 'Get-NetConnectionProfile'
            Error  = $_.Exception.Message
        }
    }
}

function Get-SmbShares {
    try {
        $shares = Get-SmbShare -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -notin 'ADMIN$','C$','IPC$' } |
            Select-Object Name, Path, EncryptData
        if ($null -eq $shares) { return @() }
        if ($shares -is [System.Collections.IEnumerable] -and -not ($shares -is [string])) {
            return @($shares | Where-Object { $_ })
        }
        return @($shares)
    } catch {
        return [PSCustomObject]@{
            Source = 'Get-SmbShare'
            Error  = $_.Exception.Message
        }
    }
}

function Invoke-Main {
    $payload = [ordered]@{
        Service         = Get-SmbServerService
        Listeners       = Get-SmbListeners
        FirewallRules   = Get-SmbFirewallRules
        NetworkProfiles = Get-SmbNetworkProfiles
        Shares          = Get-SmbShares
        Configuration   = Get-SmbServerConfig
    }

    $result = New-CollectorMetadata -Payload $payload
    $outputPath = Export-CollectorResult -OutputDirectory $OutputDirectory -FileName 'smb.json' -Data $result -Depth 6
    Write-Output $outputPath
}

Invoke-Main
