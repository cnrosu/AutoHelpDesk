$script:SecurityFirewallBaselineRemediation = @(
    @{
        type    = 'note'
        title   = 'Scenario'
        content = 'Security — Windows Firewall baseline for disabled profiles, failed inventories, or exposed RDP/SMB services.'
    }
    @{
        type    = 'code'
        title   = 'Restore baseline firewall rules'
        lang    = 'powershell'
        content = @"
# Enable all profiles
Set-NetFirewallProfile -All -Enabled True

# Restrict RDP exposure to Domain/Private; block Public
Get-NetFirewallRule -DisplayGroup "Remote Desktop" |
  Set-NetFirewallRule -Profile Domain,Private -Enabled True
Get-NetFirewallRule -DisplayGroup "Remote Desktop" |
  Where-Object { $_.Profile -match "Public" } | Disable-NetFirewallRule

# Hygiene: block NetBIOS discovery on Public
Get-NetFirewallRule | Where-Object { $_.DisplayName -match "NetBIOS|mDNS|LLMNR" } |
  Where-Object { $_.Profile -match "Public" } | Disable-NetFirewallRule

# Scope SMB to local subnet (example)
Get-NetFirewallRule | Where-Object { $_.DisplayName -match "File and Printer Sharing" } |
  Set-NetFirewallRule -RemoteAddress LocalSubnet
"@.Trim()
    }
    @{
        type    = 'text'
        title   = 'Validate firewall state'
        content = 'Confirm profiles and remote desktop rules after applying the baseline.'
    }
    @{
        type    = 'code'
        title   = 'Validation commands'
        lang    = 'powershell'
        content = @"
Get-NetFirewallProfile | Format-Table Name,Enabled
Get-NetFirewallRule -DisplayGroup "Remote Desktop" | Format-Table DisplayName,Profile,Enabled
"@.Trim()
    }
) | ConvertTo-Json -Depth 5

function Get-FirewallTokenList {
    param($Value)

    $tokens = [System.Collections.Generic.List[string]]::new()

    foreach ($item in (ConvertTo-List $Value)) {
        if ($null -eq $item) { continue }
        $text = [string]$item
        if ([string]::IsNullOrWhiteSpace($text)) { continue }

        foreach ($segment in ($text -split ',')) {
            $trimmed = $segment.Trim()
            if (-not $trimmed) { continue }
            $tokens.Add($trimmed) | Out-Null
        }
    }

    return $tokens.ToArray()
}

function Get-FirewallRulePropertyValue {
    param(
        $Rule,
        [string]$Name
    )

    if (-not $Rule) { return $null }
    if (-not $Name) { return $null }

    $property = $Rule.PSObject.Properties[$Name]
    if (-not $property) { return $null }

    return $property.Value
}

function Get-FirewallPortEntries {
    param($Value)

    $entries = [System.Collections.Generic.List[pscustomobject]]::new()

    foreach ($token in (Get-FirewallTokenList $Value)) {
        $normalized = $null
        try { $normalized = $token.ToUpperInvariant() } catch { $normalized = $token.ToUpper() }

        if ($normalized -eq 'ANY') {
            $entries.Add([pscustomobject]@{
                Type       = 'Any'
                Token      = $token
                Normalized = $normalized
                Start      = $null
                End        = $null
            }) | Out-Null
            continue
        }

        if ($token -match '^\\d+\\s*-\\s*\\d+$') {
            $parts = $token -split '\\s*-\\s*'
            $start = 0
            $end = 0
            if ([int]::TryParse($parts[0], [ref]$start) -and [int]::TryParse($parts[1], [ref]$end)) {
                if ($start -gt $end) {
                    $temp = $start
                    $start = $end
                    $end = $temp
                }

                $entries.Add([pscustomobject]@{
                    Type       = 'Range'
                    Token      = $token
                    Normalized = $normalized
                    Start      = $start
                    End        = $end
                }) | Out-Null
                continue
            }
        }

        $single = 0
        if ([int]::TryParse($token, [ref]$single)) {
            $entries.Add([pscustomobject]@{
                Type       = 'Single'
                Token      = $token
                Normalized = $normalized
                Start      = $single
                End        = $single
            }) | Out-Null
            continue
        }

        $entries.Add([pscustomobject]@{
            Type       = 'Token'
            Token      = $token
            Normalized = $normalized
            Start      = $null
            End        = $null
        }) | Out-Null
    }

    return $entries.ToArray()
}

function Format-FirewallPortEntries {
    param(
        [pscustomobject[]]$Entries,
        [string]$Fallback = 'Any'
    )

    if (-not $Entries -or $Entries.Count -eq 0) { return $Fallback }

    $parts = [System.Collections.Generic.List[string]]::new()

    foreach ($entry in $Entries) {
        if (-not $entry) { continue }

        switch ($entry.Type) {
            'Range' { $parts.Add(("{0}-{1}" -f $entry.Start, $entry.End)) | Out-Null }
            'Single' { $parts.Add([string]$entry.Start) | Out-Null }
            'Token' { $parts.Add($entry.Token) | Out-Null }
            'Any' { $parts.Add('Any') | Out-Null }
            default {
                if ($entry.Token) { $parts.Add($entry.Token) | Out-Null }
            }
        }
    }

    if ($parts.Count -eq 0) { return $Fallback }
    return ($parts.ToArray() -join ', ')
}

function Normalize-FirewallProtocolSingle {
    param($Value)

    if ($null -eq $Value) { return 'ANY' }

    $text = [string]$Value
    if ([string]::IsNullOrWhiteSpace($text)) { return 'ANY' }

    $trimmed = $text.Trim()

    switch -Regex ($trimmed) {
        '^(?i)TCP$' { return 'TCP' }
        '^(?i)UDP$' { return 'UDP' }
        '^(?i)ANY$' { return 'ANY' }
        '^(?i)ICMPv6?$' { return 'ICMP' }
        '^[0-9]+$' {
            switch ($trimmed) {
                '6' { return 'TCP' }
                '17' { return 'UDP' }
                default {
                    try { return $trimmed.ToUpperInvariant() } catch { return $trimmed.ToUpper() }
                }
            }
        }
        default {
            try { return $trimmed.ToUpperInvariant() } catch { return $trimmed.ToUpper() }
        }
    }
}

function Get-FirewallProtocolList {
    param($Value)

    $list = [System.Collections.Generic.List[string]]::new()
    foreach ($item in (ConvertTo-List $Value)) {
        $normalized = Normalize-FirewallProtocolSingle $item
        if (-not $normalized) { continue }
        if ($list.Contains($normalized)) { continue }
        $list.Add($normalized) | Out-Null
    }
    if ($list.Count -eq 0) { $list.Add('ANY') | Out-Null }
    return $list.ToArray()
}

function Test-IntRangeOverlap {
    param(
        [int]$StartA,
        [int]$EndA,
        [int]$StartB,
        [int]$EndB
    )

    return ($StartA -le $EndB -and $StartB -le $EndA)
}

function Test-FirewallPortMatch {
    param(
        [pscustomobject[]]$PortEntries,
        [int[]]$Ports = @(),
        [pscustomobject[]]$Ranges = @(),
        [string[]]$Tokens = @(),
        [bool]$TreatAnyAsMatch = $false
    )

    if (-not $PortEntries -or $PortEntries.Count -eq 0) {
        return $TreatAnyAsMatch
    }

    $tokenSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($token in (ConvertTo-List $Tokens)) {
        if ($null -eq $token) { continue }
        $tokenSet.Add([string]$token) | Out-Null
    }

    $rangeList = [System.Collections.Generic.List[pscustomobject]]::new()
    foreach ($range in (ConvertTo-List $Ranges)) {
        if (-not $range) { continue }
        if (-not ($range.PSObject.Properties['Start'] -and $range.PSObject.Properties['End'])) { continue }
        $start = [int]$range.Start
        $end = [int]$range.End
        if ($start -gt $end) {
            $temp = $start
            $start = $end
            $end = $temp
        }
        $rangeList.Add([pscustomobject]@{ Start = $start; End = $end }) | Out-Null
    }

    foreach ($entry in (ConvertTo-List $PortEntries)) {
        if (-not $entry) { continue }

        switch ($entry.Type) {
            'Any' {
                if ($TreatAnyAsMatch) { return $true }
                continue
            }
            'Single' {
                if ($Ports -and ($Ports -contains $entry.Start)) { return $true }
                foreach ($range in $rangeList) {
                    if (Test-IntRangeOverlap -StartA $entry.Start -EndA $entry.End -StartB $range.Start -EndB $range.End) { return $true }
                }
            }
            'Range' {
                foreach ($range in $rangeList) {
                    if (Test-IntRangeOverlap -StartA $entry.Start -EndA $entry.End -StartB $range.Start -EndB $range.End) { return $true }
                }
                if ($Ports) {
                    foreach ($port in $Ports) {
                        if ($port -ge $entry.Start -and $port -le $entry.End) { return $true }
                    }
                }
            }
            default {
                if ($tokenSet.Count -gt 0 -and $tokenSet.Contains($entry.Normalized)) { return $true }
                if ($TreatAnyAsMatch -and $entry.Normalized -eq 'ANY') { return $true }
            }
        }
    }

    return $false
}

function Test-FirewallProtocolMatch {
    param(
        [string[]]$RuleProtocols,
        [string[]]$TargetProtocols
    )

    if (-not $TargetProtocols -or $TargetProtocols.Count -eq 0) { return $true }

    $ruleProtocolsList = [System.Collections.Generic.List[string]]::new()
    foreach ($proto in (ConvertTo-List $RuleProtocols)) {
        $normalized = Normalize-FirewallProtocolSingle $proto
        if (-not $normalized) { continue }
        if ($ruleProtocolsList.Contains($normalized)) { continue }
        $ruleProtocolsList.Add($normalized) | Out-Null
    }
    if ($ruleProtocolsList.Count -eq 0) { $ruleProtocolsList.Add('ANY') | Out-Null }

    foreach ($target in (ConvertTo-List $TargetProtocols)) {
        $targetNorm = Normalize-FirewallProtocolSingle $target
        if ($targetNorm -eq 'ANY') { return $true }
        foreach ($ruleProto in $ruleProtocolsList) {
            if ($ruleProto -eq 'ANY') { return $true }
            if ($ruleProto -eq $targetNorm) { return $true }
        }
    }

    return $false
}

function Test-FirewallRemoteAddressTrusted {
    param([string[]]$Addresses)

    $addressList = [System.Collections.Generic.List[string]]::new()
    foreach ($value in (ConvertTo-List $Addresses)) {
        if ($null -eq $value) { continue }
        $text = [string]$value
        if ([string]::IsNullOrWhiteSpace($text)) { continue }
        $addressList.Add($text.Trim()) | Out-Null
    }

    if ($addressList.Count -eq 0) { return $false }

    foreach ($address in $addressList) {
        if (-not $address) { return $false }
        $trimmed = $address.Trim()
        if (-not $trimmed) { return $false }
        $upper = $null
        try { $upper = $trimmed.ToUpperInvariant() } catch { $upper = $trimmed.ToUpper() }

        switch ($upper) {
            'ANY' { return $false }
            'ANY IPV4' { return $false }
            'ANY IPV6' { return $false }
            'ANY REMOTE IP' { return $false }
            'ANYREMOTEIP' { return $false }
            'INTERNET' { return $false }
            'INTERNETSUBNET' { return $false }
            'WORLD' { return $false }
            'PUBLIC' { return $false }
            'NOTAPPLICABLE' { return $false }
        }

        if ($upper -eq 'LOCALSUBNET' -or $upper -eq 'LOCALSUBNET6' -or $upper -eq 'LOOPBACK' -or $upper -eq 'INTRANET' -or $upper -eq 'INTRANETSUBNET') {
            continue
        }

        if ($trimmed -match '^\\d+\\.\\d+\\.\\d+\\.\\d+(?:/\\d+)?$') {
            $ipv4 = $trimmed.Split('/')[0]
            if (Test-IsPrivateIPv4 $ipv4 -or Test-IsApipaIPv4 $ipv4) { continue }
            return $false
        }

        if ($trimmed -match '^\\d+\\.\\d+\\.\\d+\\.\\d+\\s*-\\s*\\d+\\.\\d+\\.\\d+\\.\\d+$') {
            $start = ($trimmed -split '\\s*-\\s*')[0]
            if (Test-IsPrivateIPv4 $start -or Test-IsApipaIPv4 $start) { continue }
            return $false
        }

        if ($trimmed -match '^[0-9A-Fa-f:]+(?:/\\d+)?$') {
            $addressOnly = $trimmed.Split('/')[0]
            $upperAddress = $null
            try { $upperAddress = $addressOnly.ToUpperInvariant() } catch { $upperAddress = $addressOnly.ToUpper() }
            if ($upperAddress.StartsWith('FE80') -or $upperAddress.StartsWith('FD') -or $upperAddress.StartsWith('FC')) { continue }
            return $false
        }

        if ($trimmed -match '\\*') {
            if ($trimmed -match '^10\\.' -or $trimmed -match '^192\\.168\\.' -or $trimmed -match '^172\\.(1[6-9]|2[0-9]|3[0-1])\\.') { continue }
            return $false
        }

        return $false
    }

    return $true
}

function ConvertTo-FirewallRuleInfo {
    param($Rule)

    if (-not $Rule) { return $null }

    $enabled = $null
    if ($Rule.PSObject.Properties['Enabled']) {
        $enabled = ConvertTo-NullableBool $Rule.Enabled
    }

    $action = if ($Rule.PSObject.Properties['Action']) { [string]$Rule.Action } else { '' }
    $direction = if ($Rule.PSObject.Properties['Direction']) { [string]$Rule.Direction } else { '' }

    $directionNormalized = 'UNKNOWN'
    if ($direction) {
        try { $directionNormalized = $direction.Trim().ToUpperInvariant() } catch { $directionNormalized = $direction.Trim().ToUpper() }
    }

    $actionNormalized = 'UNKNOWN'
    if ($action) {
        try { $actionNormalized = $action.Trim().ToUpperInvariant() } catch { $actionNormalized = $action.Trim().ToUpper() }
    }

    $profileTokens = Get-FirewallTokenList (Get-FirewallRulePropertyValue -Rule $Rule -Name 'Profile')
    if (-not $profileTokens -or $profileTokens.Count -eq 0) { $profileTokens = @('Any') }

    $profileNormalized = [System.Collections.Generic.List[string]]::new()
    foreach ($profile in $profileTokens) {
        $upper = $profile
        try { $upper = $profile.ToUpperInvariant() } catch { $upper = $profile.ToUpper() }
        if ($profileNormalized.Contains($upper)) { continue }
        $profileNormalized.Add($upper) | Out-Null
    }

    $protocols = Get-FirewallProtocolList (Get-FirewallRulePropertyValue -Rule $Rule -Name 'Protocol')
    $localPorts = Get-FirewallPortEntries (Get-FirewallRulePropertyValue -Rule $Rule -Name 'LocalPort')
    $remoteAddresses = Get-FirewallTokenList (Get-FirewallRulePropertyValue -Rule $Rule -Name 'RemoteAddress')
    $localAddresses = Get-FirewallTokenList (Get-FirewallRulePropertyValue -Rule $Rule -Name 'LocalAddress')
    $profileText = if ($profileTokens -and $profileTokens.Count -gt 0) { ($profileTokens -join ', ') } else { 'Any' }
    $remoteAddressText = if ($remoteAddresses -and $remoteAddresses.Count -gt 0) { ($remoteAddresses -join ', ') } else { 'Any' }
    $localAddressText = if ($localAddresses -and $localAddresses.Count -gt 0) { ($localAddresses -join ', ') } else { 'Any' }

    $ruleName = if ($Rule.PSObject.Properties['Name']) { [string]$Rule.Name } else { $null }
    $displayName = if ($Rule.PSObject.Properties['DisplayName']) { [string]$Rule.DisplayName } else { $null }
    $group = if ($Rule.PSObject.Properties['Group']) { [string]$Rule.Group } else { $null }
    $policyStore = if ($Rule.PSObject.Properties['PolicyStore']) { [string]$Rule.PolicyStore } else { $null }
    $program = if ($Rule.PSObject.Properties['Program']) { [string]$Rule.Program } else { $null }
    $service = if ($Rule.PSObject.Properties['Service']) { [string]$Rule.Service } else { $null }
    $description = if ($Rule.PSObject.Properties['Description']) { [string]$Rule.Description } else { $null }

    return [pscustomobject]@{
        Name                   = $ruleName
        DisplayName            = $displayName
        Group                  = $group
        DirectionNormalized    = $directionNormalized
        ActionNormalized       = $actionNormalized
        Enabled                = $enabled
        Profiles               = $profileTokens
        ProfilesNormalized     = $profileNormalized.ToArray()
        ProfileText            = $profileText
        Protocols              = $protocols
        ProtocolsNormalized    = $protocols
        LocalPortEntries       = $localPorts
        LocalPortText          = Format-FirewallPortEntries $localPorts
        RemoteAddressList      = $remoteAddresses
        RemoteAddressText      = $remoteAddressText
        RemoteAddressesTrusted = Test-FirewallRemoteAddressTrusted $remoteAddresses
        LocalAddressList       = $localAddresses
        LocalAddressText       = $localAddressText
        PolicyStore            = $policyStore
        Program                = $program
        Service                = $service
        Description            = $description
        Raw                    = $Rule
    }
}

function New-FirewallRuleEvidenceItem {
    param($RuleInfo)

    if (-not $RuleInfo) { return $null }

    $ruleName = $RuleInfo.DisplayName
    if (-not $ruleName) { $ruleName = $RuleInfo.Name }
    if (-not $ruleName) { $ruleName = '(Unnamed rule)' }

    $remoteScope = if ($RuleInfo.RemoteAddressesTrusted) { 'Restricted/private' } else { 'Unrestricted or unknown' }
    $protocolText = if ($RuleInfo.Protocols -and $RuleInfo.Protocols.Count -gt 0) { ($RuleInfo.Protocols -join ', ') } else { 'Any' }

    return [ordered]@{
        Rule        = $ruleName
        Direction   = $RuleInfo.DirectionNormalized
        Action      = $RuleInfo.ActionNormalized
        Profiles    = $RuleInfo.ProfileText
        Protocols   = $protocolText
        LocalPort   = $RuleInfo.LocalPortText
        RemoteAddr  = $RuleInfo.RemoteAddressText
        RemoteScope = $remoteScope
        PolicyStore = $RuleInfo.PolicyStore
        Group       = $RuleInfo.Group
    }
}

function Get-SmbProfileTokenFromCategory {
    param([string]$Category)

    if ([string]::IsNullOrWhiteSpace($Category)) { return $null }

    $trimmed = $Category.Trim()
    if (-not $trimmed) { return $null }

    $upper = $null
    try { $upper = $trimmed.ToUpperInvariant() } catch { $upper = $trimmed.ToUpper() }
    $compact = ($upper -replace '\s', '')

    if ($compact -match 'DOMAIN') { return 'DOMAIN' }
    if ($compact -match 'PRIVATE') { return 'PRIVATE' }
    if ($compact -match 'PUBLIC') { return 'PUBLIC' }

    return $upper
}

function Test-SmbIsListening {
    param($Listeners)

    foreach ($listener in (ConvertTo-List $Listeners)) {
        if (-not $listener) { continue }
        if ($listener.PSObject.Properties['Error'] -and $listener.Error) { continue }
        if (-not $listener.PSObject.Properties['LocalPort']) { continue }

        $portValue = $listener.LocalPort
        $port = 0
        if ($portValue -is [int]) {
            $port = [int]$portValue
        } elseif (-not [int]::TryParse([string]$portValue, [ref]$port)) {
            continue
        }

        if ($port -in 139, 445) { return $true }
    }

    return $false
}

function Test-SmbRuleAppliesToActiveProfile {
    param(
        $Rule,
        [string[]]$ActiveTokens
    )

    if (-not $Rule) { return $false }

    $profiles = ConvertTo-List $Rule.ProfilesNormalized
    if ($profiles.Count -eq 0) { return $true }

    $activeSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($token in (ConvertTo-List $ActiveTokens)) {
        if ($null -eq $token) { continue }
        $activeSet.Add([string]$token) | Out-Null
    }

    foreach ($profile in $profiles) {
        if (-not $profile) { continue }

        $token = [string]$profile
        if (-not $token) { continue }
        try { $token = $token.ToUpperInvariant() } catch { $token = $token.ToUpper() }

        switch ($token) {
            'ANY' { return $true }
            'ALL' { return $true }
            'NOTAPPLICABLE' { return $true }
        }

        if ($activeSet.Count -eq 0) { continue }

        if ($activeSet.Contains($token)) { return $true }

        switch ($token) {
            'DOMAIN' {
                if ($activeSet.Contains('DOMAINAUTHENTICATED')) { return $true }
                continue
            }
            'DOMAINAUTHENTICATED' {
                if ($activeSet.Contains('DOMAIN')) { return $true }
                continue
            }
            default { continue }
        }
    }

    return $false
}

function Test-SmbRemoteScopeIsCrossVlan {
    param($RemoteAddresses)

    $addresses = ConvertTo-List $RemoteAddresses
    if ($addresses.Count -eq 0) { return $true }

    foreach ($address in $addresses) {
        if ($null -eq $address) { return $true }

        $text = [string]$address
        if ([string]::IsNullOrWhiteSpace($text)) { return $true }

        $trimmed = $text.Trim()
        $upper = $null
        try { $upper = $trimmed.ToUpperInvariant() } catch { $upper = $trimmed.ToUpper() }
        $compact = ($upper -replace '\s', '')

        if ($compact -eq 'LOCALSUBNET' -or $compact -eq 'LOCALSUBNET6') { continue }

        return $true
    }

    return $false
}

function Get-SmbServiceSummary {
    param($Service)

    if (-not $Service) { return $null }

    $serviceEntry = $Service
    if ($Service -is [System.Collections.IEnumerable] -and -not ($Service -is [string])) {
        $serviceEntry = ($Service | Select-Object -First 1)
    }

    if (-not $serviceEntry) { return $null }

    if ($serviceEntry.PSObject.Properties['Error'] -and $serviceEntry.Error) {
        return [ordered]@{
            Source = if ($serviceEntry.PSObject.Properties['Source']) { [string]$serviceEntry.Source } else { 'Get-Service LanmanServer' }
            Error  = [string]$serviceEntry.Error
        }
    }

    return [ordered]@{
        Name      = if ($serviceEntry.PSObject.Properties['Name']) { [string]$serviceEntry.Name } else { 'LanmanServer' }
        Status    = if ($serviceEntry.PSObject.Properties['Status']) { [string]$serviceEntry.Status } else { $null }
        StartType = if ($serviceEntry.PSObject.Properties['StartType']) { [string]$serviceEntry.StartType } else { $null }
    }
}

function Get-SmbListenerSummaries {
    param($Listeners)

    $list = [System.Collections.Generic.List[object]]::new()

    foreach ($listener in (ConvertTo-List $Listeners)) {
        if (-not $listener) { continue }

        if ($listener.PSObject.Properties['Error'] -and $listener.Error) {
            $list.Add([ordered]@{
                Source = if ($listener.PSObject.Properties['Source']) { [string]$listener.Source } else { 'Get-NetTCPConnection' }
                Error  = [string]$listener.Error
            }) | Out-Null
            continue
        }

        $list.Add([ordered]@{
            LocalAddress = if ($listener.PSObject.Properties['LocalAddress']) { [string]$listener.LocalAddress } else { $null }
            LocalPort    = if ($listener.PSObject.Properties['LocalPort']) { [string]$listener.LocalPort } else { $null }
            State        = if ($listener.PSObject.Properties['State']) { [string]$listener.State } else { $null }
        }) | Out-Null
    }

    return $list.ToArray()
}

function Get-SmbNetworkProfileSummaries {
    param($Profiles)

    $list = [System.Collections.Generic.List[object]]::new()

    foreach ($profile in (ConvertTo-List $Profiles)) {
        if (-not $profile) { continue }

        if ($profile.PSObject.Properties['Error'] -and $profile.Error) {
            $list.Add([ordered]@{
                Source = if ($profile.PSObject.Properties['Source']) { [string]$profile.Source } else { 'Get-NetConnectionProfile' }
                Error  = [string]$profile.Error
            }) | Out-Null
            continue
        }

        $list.Add([ordered]@{
            InterfaceAlias   = if ($profile.PSObject.Properties['InterfaceAlias']) { [string]$profile.InterfaceAlias } else { $null }
            IPv4Connectivity = if ($profile.PSObject.Properties['IPv4Connectivity']) { [string]$profile.IPv4Connectivity } else { $null }
            NetworkCategory  = if ($profile.PSObject.Properties['NetworkCategory']) { [string]$profile.NetworkCategory } else { $null }
        }) | Out-Null
    }

    return $list.ToArray()
}

function Get-SmbShareSummaries {
    param($Shares)

    $list = [System.Collections.Generic.List[object]]::new()

    foreach ($share in (ConvertTo-List $Shares)) {
        if (-not $share) { continue }

        if ($share.PSObject.Properties['Error'] -and $share.Error) {
            $list.Add([ordered]@{
                Source = if ($share.PSObject.Properties['Source']) { [string]$share.Source } else { 'Get-SmbShare' }
                Error  = [string]$share.Error
            }) | Out-Null
            continue
        }

        $list.Add([ordered]@{
            Name        = if ($share.PSObject.Properties['Name']) { [string]$share.Name } else { $null }
            Path        = if ($share.PSObject.Properties['Path']) { [string]$share.Path } else { $null }
            EncryptData = if ($share.PSObject.Properties['EncryptData']) { $share.EncryptData } else { $null }
        }) | Out-Null
    }

    return $list.ToArray()
}

function Get-SmbConfigurationSummary {
    param($Configuration)

    if (-not $Configuration) { return $null }

    if ($Configuration.PSObject.Properties['Error'] -and $Configuration.Error) {
        return [ordered]@{
            Source = if ($Configuration.PSObject.Properties['Source']) { [string]$Configuration.Source } else { 'Get-SmbServerConfiguration' }
            Error  = [string]$Configuration.Error
        }
    }

    $summary = [ordered]@{}
    foreach ($prop in @('EnableSMB1Protocol','EnableSMB2Protocol','RequireSecuritySignature','EnableSecuritySignature','EncryptData','RejectUnencryptedAccess','EnableLeasing','EnableStrictNameChecking','EnableAuthenticateUserSharing')) {
        if ($Configuration.PSObject.Properties[$prop]) {
            $summary[$prop] = $Configuration.$prop
        }
    }

    return $summary
}

function Get-FirewallSmbExposureAnalysis {
    param(
        $Context,
        [pscustomobject[]]$Rules
    )

    $errors = [System.Collections.Generic.List[string]]::new()
    $service = $null
    $listeners = @()
    $networkProfiles = @()
    $shares = @()
    $configuration = $null

    $artifact = Get-AnalyzerArtifact -Context $Context -Name 'smb'
    if ($artifact) {
        $payload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $artifact)
        if ($payload) {
            if ($payload.PSObject.Properties['Service']) { $service = $payload.Service }
            if ($payload.PSObject.Properties['Listeners']) { $listeners = ConvertTo-List $payload.Listeners } else { $listeners = @() }
            if ($payload.PSObject.Properties['NetworkProfiles']) { $networkProfiles = ConvertTo-List $payload.NetworkProfiles } else { $networkProfiles = @() }
            if ($payload.PSObject.Properties['Shares']) { $shares = ConvertTo-List $payload.Shares } else { $shares = @() }
            if ($payload.PSObject.Properties['Configuration']) { $configuration = $payload.Configuration }
        } else {
            $errors.Add('SMB artifact payload missing or unparsed.') | Out-Null
        }
    } else {
        $errors.Add('SMB collector artifact missing.') | Out-Null
    }

    $isListening = Test-SmbIsListening $listeners

    $activeProfileNames = [System.Collections.Generic.List[string]]::new()
    $activeProfileTokens = [System.Collections.Generic.List[string]]::new()

    foreach ($profile in (ConvertTo-List $networkProfiles)) {
        if (-not $profile) { continue }
        if ($profile.PSObject.Properties['Error'] -and $profile.Error) { continue }

        $category = $null
        if ($profile.PSObject.Properties['NetworkCategory']) { $category = [string]$profile.NetworkCategory }
        if ([string]::IsNullOrWhiteSpace($category)) { continue }

        $trimmed = $category.Trim()
        if (-not $activeProfileNames.Contains($trimmed)) { $activeProfileNames.Add($trimmed) | Out-Null }

        $token = Get-SmbProfileTokenFromCategory $trimmed
        if ($token -and -not $activeProfileTokens.Contains($token)) { $activeProfileTokens.Add($token) | Out-Null }

        $upperOriginal = $null
        try { $upperOriginal = $trimmed.ToUpperInvariant() } catch { $upperOriginal = $trimmed.ToUpper() }
        if (-not [string]::IsNullOrWhiteSpace($upperOriginal) -and -not $activeProfileTokens.Contains($upperOriginal)) {
            $activeProfileTokens.Add($upperOriginal) | Out-Null
        }
    }

    $tcpPorts = @(139,445)
    $udpPorts = @(137,138)

    $tcpRules = [System.Collections.Generic.List[pscustomobject]]::new()
    $udpRules = [System.Collections.Generic.List[pscustomobject]]::new()

    foreach ($rule in (ConvertTo-List $Rules)) {
        if (-not $rule) { continue }

        if ($rule.DirectionNormalized -ne 'INBOUND') { continue }
        if ($rule.ActionNormalized -ne 'ALLOW') { continue }

        if (Test-FirewallProtocolMatch -RuleProtocols $rule.ProtocolsNormalized -TargetProtocols @('TCP')) {
            if (Test-FirewallPortMatch -PortEntries $rule.LocalPortEntries -Ports $tcpPorts -Ranges @() -Tokens @() -TreatAnyAsMatch $false) {
                $tcpRules.Add($rule) | Out-Null
                continue
            }
        }

        if (Test-FirewallProtocolMatch -RuleProtocols $rule.ProtocolsNormalized -TargetProtocols @('UDP')) {
            if (Test-FirewallPortMatch -PortEntries $rule.LocalPortEntries -Ports $udpPorts -Ranges @() -Tokens @() -TreatAnyAsMatch $false) {
                $udpRules.Add($rule) | Out-Null
            }
        }
    }

    $tcpApplies = [System.Collections.Generic.List[pscustomobject]]::new()
    $tcpCross = [System.Collections.Generic.List[pscustomobject]]::new()
    $tcpLocal = [System.Collections.Generic.List[pscustomobject]]::new()
    $tcpOffProfile = [System.Collections.Generic.List[pscustomobject]]::new()

    foreach ($rule in $tcpRules) {
        $applies = Test-SmbRuleAppliesToActiveProfile -Rule $rule -ActiveTokens ($activeProfileTokens.ToArray())
        if ($applies) {
            $tcpApplies.Add($rule) | Out-Null
            if (Test-SmbRemoteScopeIsCrossVlan $rule.RemoteAddressList) {
                $tcpCross.Add($rule) | Out-Null
            } else {
                $tcpLocal.Add($rule) | Out-Null
            }
        } else {
            $tcpOffProfile.Add($rule) | Out-Null
        }
    }

    $udpCross = [System.Collections.Generic.List[pscustomobject]]::new()
    foreach ($rule in $udpRules) {
        if (Test-SmbRemoteScopeIsCrossVlan $rule.RemoteAddressList) {
            $udpCross.Add($rule) | Out-Null
        }
    }

    return [pscustomobject]@{
        Service             = $service
        Listeners           = $listeners
        NetworkProfiles     = $networkProfiles
        Shares              = $shares
        Configuration       = $configuration
        ActiveProfileNames  = $activeProfileNames.ToArray()
        ActiveProfileTokens = $activeProfileTokens.ToArray()
        IsListening         = $isListening
        TcpRules            = $tcpRules.ToArray()
        TcpRulesApplying    = $tcpApplies.ToArray()
        TcpCrossVlanRules   = $tcpCross.ToArray()
        TcpLocalRules       = $tcpLocal.ToArray()
        TcpOffProfileRules  = $tcpOffProfile.ToArray()
        UdpRules            = $udpRules.ToArray()
        UdpCrossVlanRules   = $udpCross.ToArray()
        Errors              = $errors.ToArray()
    }
}

function New-SmbExposureHighEvidence {
    param($Analysis)

    if (-not $Analysis) { return $null }

    $ruleEvidence = [System.Collections.Generic.List[object]]::new()
    foreach ($rule in (ConvertTo-List $Analysis.TcpCrossVlanRules)) {
        $item = New-FirewallRuleEvidenceItem $rule
        if ($item) { $ruleEvidence.Add($item) | Out-Null }
    }

    $evidence = [ordered]@{
        Explanation          = 'The device is listening on SMB and at least one inbound firewall rule for TCP 445/139 allows traffic from beyond the local subnet on the active profile, exposing file shares across VLANs.'
        ActiveNetworkProfile = if ($Analysis.ActiveProfileNames -and $Analysis.ActiveProfileNames.Count -gt 0) { $Analysis.ActiveProfileNames -join ', ' } else { 'Unknown' }
        Service              = Get-SmbServiceSummary $Analysis.Service
        NetworkProfiles      = Get-SmbNetworkProfileSummaries $Analysis.NetworkProfiles
        Listeners            = Get-SmbListenerSummaries $Analysis.Listeners
        Rules                = $ruleEvidence.ToArray()
        Shares               = Get-SmbShareSummaries $Analysis.Shares
        SmbConfiguration     = Get-SmbConfigurationSummary $Analysis.Configuration
        Remediation          = [ordered]@{
            Workstations = @(
                'Disable File and Printer Sharing inbound rules, or restrict them to LocalSubnet only.',
                'If SMB serving is not needed on this device, stop and disable the Server (LanmanServer) service.'
            )
            Servers = @(
                'Restrict SMB (TCP 445) inbound to trusted subnets only (avoid “Any”).',
                'Require SMB signing; enable per-share encryption for sensitive data.'
            )
            Commands = @(
                '# Restrict built-in “File and Printer Sharing” rules to LocalSubnet',
                'Get-NetFirewallRule -DisplayGroup "File and Printer Sharing" | Where-Object Enabled -eq True | ForEach-Object { Set-NetFirewallRule -Name $_.Name -RemoteAddress LocalSubnet }',
                '# OR disable them entirely (workstations)',
                'Disable-NetFirewallRule -DisplayGroup "File and Printer Sharing"',
                '# Stop/disable SMB server if not needed (workstations)',
                'Stop-Service LanmanServer -ErrorAction SilentlyContinue',
                'Set-Service LanmanServer -StartupType Disabled',
                '# Hardening on servers',
                'Set-SmbServerConfiguration -RequireSecuritySignature $true -Force',
                '# Per-share encryption (example)',
                'Set-SmbShare -Name <ShareName> -EncryptData $true',
                '# Disable NB discovery rules if unneeded',
                'Disable-NetFirewallRule -DisplayName "Network Discovery (NB-Name-In)","Network Discovery (NB-Datagram-In)"',
                '# Ensure SMB1 is disabled',
                'Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart',
                'Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force'
            )
        }
    }

    if ($Analysis.UdpRules -and $Analysis.UdpRules.Count -gt 0) {
        $udpEvidence = [System.Collections.Generic.List[object]]::new()
        foreach ($udpRule in (ConvertTo-List $Analysis.UdpRules)) {
            $item = New-FirewallRuleEvidenceItem $udpRule
            if ($item) { $udpEvidence.Add($item) | Out-Null }
        }
        if ($udpEvidence.Count -gt 0) {
            $evidence['NetBiosDiscoveryRules'] = $udpEvidence.ToArray()
        }
    }

    if ($Analysis.Errors -and $Analysis.Errors.Count -gt 0) {
        $evidence['DataWarnings'] = $Analysis.Errors
    }

    return $evidence
}

function New-SmbExposureRestrictedEvidence {
    param($Analysis)

    if (-not $Analysis) { return $null }

    $reasonParts = [System.Collections.Generic.List[string]]::new()
    if ($Analysis.TcpLocalRules -and $Analysis.TcpLocalRules.Count -gt 0) {
        $reasonParts.Add('All inbound SMB firewall rules that match the active profile are scoped to LocalSubnet or trusted ranges.') | Out-Null
    }
    if ($Analysis.TcpOffProfileRules -and $Analysis.TcpOffProfileRules.Count -gt 0) {
        $reasonParts.Add('Some SMB firewall rules target profiles that are not currently active.') | Out-Null
    }
    if (($Analysis.ActiveProfileTokens -and $Analysis.ActiveProfileTokens.Count -eq 0) -or (-not $Analysis.ActiveProfileTokens)) {
        $reasonParts.Add('Active network profile could not be determined, so cross-VLAN exposure cannot be confirmed.') | Out-Null
    }

    $summary = if ($reasonParts.Count -gt 0) { $reasonParts -join ' ' } else { 'SMB firewall rules do not expose TCP 445/139 on the active profile.' }

    $localEvidence = [System.Collections.Generic.List[object]]::new()
    foreach ($rule in (ConvertTo-List $Analysis.TcpLocalRules)) {
        $item = New-FirewallRuleEvidenceItem $rule
        if ($item) { $localEvidence.Add($item) | Out-Null }
    }

    $offProfileEvidence = [System.Collections.Generic.List[object]]::new()
    foreach ($rule in (ConvertTo-List $Analysis.TcpOffProfileRules)) {
        $item = New-FirewallRuleEvidenceItem $rule
        if ($item) { $offProfileEvidence.Add($item) | Out-Null }
    }

    $evidence = [ordered]@{
        Explanation          = $summary
        ActiveNetworkProfile = if ($Analysis.ActiveProfileNames -and $Analysis.ActiveProfileNames.Count -gt 0) { $Analysis.ActiveProfileNames -join ', ' } else { 'Unknown' }
        Service              = Get-SmbServiceSummary $Analysis.Service
        NetworkProfiles      = Get-SmbNetworkProfileSummaries $Analysis.NetworkProfiles
        Listeners            = Get-SmbListenerSummaries $Analysis.Listeners
        LocalScopeRules      = $localEvidence.ToArray()
        OffProfileRules      = $offProfileEvidence.ToArray()
        Shares               = Get-SmbShareSummaries $Analysis.Shares
        SmbConfiguration     = Get-SmbConfigurationSummary $Analysis.Configuration
    }

    if ($Analysis.UdpRules -and $Analysis.UdpRules.Count -gt 0) {
        $udpEvidence = [System.Collections.Generic.List[object]]::new()
        foreach ($udpRule in (ConvertTo-List $Analysis.UdpRules)) {
            $item = New-FirewallRuleEvidenceItem $udpRule
            if ($item) { $udpEvidence.Add($item) | Out-Null }
        }
        if ($udpEvidence.Count -gt 0) {
            $evidence['NetBiosDiscoveryRules'] = $udpEvidence.ToArray()
        }
    }

    if ($Analysis.Errors -and $Analysis.Errors.Count -gt 0) {
        $evidence['DataWarnings'] = $Analysis.Errors
    }

    return $evidence
}

function New-SmbUdpHygieneEvidence {
    param($Analysis)

    if (-not $Analysis) { return $null }

    $udpEvidence = [System.Collections.Generic.List[object]]::new()
    foreach ($rule in (ConvertTo-List $Analysis.UdpRules)) {
        $item = New-FirewallRuleEvidenceItem $rule
        if ($item) { $udpEvidence.Add($item) | Out-Null }
    }

    if ($udpEvidence.Count -eq 0) { return $null }

    $evidence = [ordered]@{
        Explanation          = 'Only NetBIOS discovery rules (UDP 137/138) are enabled. Review and tighten these scopes for hygiene.'
        ActiveNetworkProfile = if ($Analysis.ActiveProfileNames -and $Analysis.ActiveProfileNames.Count -gt 0) { $Analysis.ActiveProfileNames -join ', ' } else { 'Unknown' }
        Rules                = $udpEvidence.ToArray()
        Remediation          = @('Disable-NetFirewallRule -DisplayName "Network Discovery (NB-Name-In)","Network Discovery (NB-Datagram-In)"')
    }

    if ($Analysis.Errors -and $Analysis.Errors.Count -gt 0) {
        $evidence['DataWarnings'] = $Analysis.Errors
    }

    return $evidence
}

function Get-FirewallPortPolicies {
    $rpcDynamicRange = [pscustomobject]@{ Start = 49152; End = 65535 }
    $vncRange = [pscustomobject]@{ Start = 5900; End = 5902 }

    return @(
        [pscustomobject]@{
            Key = 'FirewallRdp'
            Title = 'Firewall exposes RDP to broad networks, so attackers can reach remote desktop without VPN.'
            Severity = 'high'
            CheckId = 'Security/Firewall/RdpExposure'
            Direction = 'INBOUND'
            Protocols = @('TCP','UDP')
            Ports = @(3389)
            Ranges = @()
            PortTokens = @()
            TreatAnyAsMatch = $false
            FlagWhenRemoteUntrusted = $true
            Guidance = 'Do not expose to internet; allow only via RD Gateway, VPN, or management VLAN; require NLA + MFA.'
        },
        [pscustomobject]@{
            Key = 'FirewallTelnet'
            Title = 'Firewall allows Telnet from any network, so legacy plaintext remote access stays exposed.'
            Severity = 'high'
            CheckId = 'Security/Firewall/Telnet'
            Direction = 'INBOUND'
            Protocols = @('TCP')
            Ports = @(23)
            Ranges = @()
            PortTokens = @()
            TreatAnyAsMatch = $false
            FlagWhenRemoteUntrusted = $true
            Guidance = 'Block Telnet (TCP 23).'
        },
        [pscustomobject]@{
            Key = 'FirewallVnc'
            Title = 'Firewall allows VNC ports broadly, so unmanaged remote desktop services are reachable by attackers.'
            Severity = 'high'
            CheckId = 'Security/Firewall/Vnc'
            Direction = 'INBOUND'
            Protocols = @('TCP')
            Ports = @()
            Ranges = @($vncRange)
            PortTokens = @()
            TreatAnyAsMatch = $false
            FlagWhenRemoteUntrusted = $true
            Guidance = 'Block VNC and remote desktop ports unless centrally managed.'
        },
        [pscustomobject]@{
            Key = 'FirewallRpcDynamic'
            Title = 'Firewall opens RPC dynamic ports broadly, so high-risk service endpoints are reachable from untrusted networks.'
            Severity = 'medium'
            CheckId = 'Security/Firewall/RpcDynamic'
            Direction = 'INBOUND'
            Protocols = @('TCP')
            Ports = @()
            Ranges = @($rpcDynamicRange)
            PortTokens = @('RPC DYNAMIC PORTS','RPC-ERPC DYNAMIC PORTS')
            TreatAnyAsMatch = $false
            FlagWhenRemoteUntrusted = $true
            Guidance = 'Avoid opening RPC dynamic port ranges; use RPC over specific proxies or restrict via ACLs.'
        },
        [pscustomobject]@{
            Key = 'FirewallSmbOutbound'
            Title = 'Firewall permits outbound SMB to untrusted networks, so malware can reach internet file shares.'
            Severity = 'high'
            CheckId = 'Security/Firewall/SmbOutbound'
            Direction = 'OUTBOUND'
            Protocols = @('TCP')
            Ports = @(445)
            Ranges = @()
            PortTokens = @()
            TreatAnyAsMatch = $false
            FlagWhenRemoteUntrusted = $true
            Guidance = 'Block outbound 445 to the internet (common exploitation vector).'
        },
        [pscustomobject]@{
            Key = 'FirewallDatabase'
            Title = 'Firewall allows database admin ports broadly, so database services are exposed to remote attacks.'
            Severity = 'high'
            CheckId = 'Security/Firewall/DatabasePorts'
            Direction = 'INBOUND'
            Protocols = @('TCP')
            Ports = @(3306,1433,1521)
            Ranges = @()
            PortTokens = @()
            TreatAnyAsMatch = $false
            FlagWhenRemoteUntrusted = $true
            Guidance = 'Only allow MySQL 3306, MSSQL 1433, and Oracle 1521 from app servers or admin hosts.'
        },
        [pscustomobject]@{
            Key = 'FirewallLdap'
            Title = 'Firewall allows LDAP/LDAPS broadly, so directory services are reachable from untrusted networks.'
            Severity = 'medium'
            CheckId = 'Security/Firewall/Ldap'
            Direction = 'INBOUND'
            Protocols = @('TCP')
            Ports = @(389,636)
            Ranges = @()
            PortTokens = @()
            TreatAnyAsMatch = $false
            FlagWhenRemoteUntrusted = $true
            Guidance = 'Restrict LDAP (389) and LDAPS (636) to domain controllers and management hosts.'
        },
        [pscustomobject]@{
            Key = 'FirewallUpnp'
            Title = 'Firewall leaves UPnP/SSDP open, so discovery traffic can be abused across networks.'
            Severity = 'medium'
            CheckId = 'Security/Firewall/UpnpSsdp'
            Direction = 'INBOUND'
            Protocols = @('UDP')
            Ports = @(1900)
            Ranges = @()
            PortTokens = @()
            TreatAnyAsMatch = $false
            FlagWhenRemoteUntrusted = $true
            Guidance = 'Block UDP 1900 (UPnP/SSDP) to prevent discovery abuse.'
        },
        [pscustomobject]@{
            Key = 'FirewallMdns'
            Title = 'Firewall leaves mDNS open across VLANs, so multicast discovery leaks between segments.'
            Severity = 'medium'
            CheckId = 'Security/Firewall/mDns'
            Direction = 'INBOUND'
            Protocols = @('UDP')
            Ports = @(5353)
            Ranges = @()
            PortTokens = @()
            TreatAnyAsMatch = $false
            FlagWhenRemoteUntrusted = $true
            Guidance = 'Block UDP 5353 (mDNS/Bonjour) across VLANs.'
        },
        [pscustomobject]@{
            Key = 'FirewallSnmp'
            Title = 'Firewall allows SNMP v1/v2 broadly, so monitoring traffic can be sniffed or abused.'
            Severity = 'medium'
            CheckId = 'Security/Firewall/SnmpLegacy'
            Direction = 'INBOUND'
            Protocols = @('UDP')
            Ports = @(161,162)
            Ranges = @()
            PortTokens = @()
            TreatAnyAsMatch = $false
            FlagWhenRemoteUntrusted = $true
            Guidance = 'Avoid SNMP v1/v2 or restrict them to management hosts; prefer SNMPv3.'
        },
        [pscustomobject]@{
            Key = 'FirewallSmtpOutbound'
            Title = 'Firewall lets endpoints send SMTP directly, so compromised hosts can exfiltrate email.'
            Severity = 'medium'
            CheckId = 'Security/Firewall/SmtpOutbound'
            Direction = 'OUTBOUND'
            Protocols = @('TCP')
            Ports = @(25)
            Ranges = @()
            PortTokens = @()
            TreatAnyAsMatch = $false
            FlagWhenRemoteUntrusted = $true
            Guidance = 'Block outbound SMTP (25) from endpoints except authorized mail relays.'
        },
        [pscustomobject]@{
            Key = 'FirewallTftp'
            Title = 'Firewall allows TFTP broadly, so unauthenticated file transfers stay exposed.'
            Severity = 'medium'
            CheckId = 'Security/Firewall/Tftp'
            Direction = 'INBOUND'
            Protocols = @('UDP')
            Ports = @(69)
            Ranges = @()
            PortTokens = @()
            TreatAnyAsMatch = $false
            FlagWhenRemoteUntrusted = $true
            Guidance = 'Block UDP 69 (TFTP).'
        },
        [pscustomobject]@{
            Key = 'FirewallFtp'
            Title = 'Firewall allows FTP service ports broadly, so legacy file transfer services stay exposed.'
            Severity = 'medium'
            CheckId = 'Security/Firewall/FtpLegacy'
            Direction = 'INBOUND'
            Protocols = @('TCP')
            Ports = @(20,21)
            Ranges = @()
            PortTokens = @()
            TreatAnyAsMatch = $false
            FlagWhenRemoteUntrusted = $true
            Guidance = 'Block legacy FTP service ports by default.'
        }
    )
}

function Get-FirewallPolicyMatches {
    param([pscustomobject[]]$Rules)

    $policies = Get-FirewallPortPolicies
    $matches = [System.Collections.Generic.List[pscustomobject]]::new()

    if (-not $Rules) { return @() }

    foreach ($policy in (ConvertTo-List $policies)) {
        if (-not $policy) { continue }

        $direction = 'ANY'
        if ($policy.PSObject.Properties['Direction'] -and $policy.Direction) {
            try { $direction = $policy.Direction.ToUpperInvariant() } catch { $direction = $policy.Direction.ToUpper() }
        }

        $protocols = if ($policy.PSObject.Properties['Protocols']) { $policy.Protocols } else { @() }
        $ports = if ($policy.PSObject.Properties['Ports']) { $policy.Ports } else { @() }
        $ranges = if ($policy.PSObject.Properties['Ranges']) { $policy.Ranges } else { @() }
        $tokens = if ($policy.PSObject.Properties['PortTokens']) { $policy.PortTokens } else { @() }
        $treatAny = ($policy.PSObject.Properties['TreatAnyAsMatch'] -and $policy.TreatAnyAsMatch)

        $policyRules = [System.Collections.Generic.List[pscustomobject]]::new()

        foreach ($rule in (ConvertTo-List $Rules)) {
            if (-not $rule) { continue }
            if ($rule.Enabled -ne $true) { continue }
            if ($rule.ActionNormalized -ne 'ALLOW') { continue }

            if ($direction -ne 'ANY' -and $rule.DirectionNormalized -ne $direction) { continue }

            if (-not (Test-FirewallProtocolMatch -RuleProtocols $rule.ProtocolsNormalized -TargetProtocols $protocols)) { continue }

            if (-not (Test-FirewallPortMatch -PortEntries $rule.LocalPortEntries -Ports $ports -Ranges $ranges -Tokens $tokens -TreatAnyAsMatch $treatAny)) { continue }

            $flagRemote = $false
            if ($policy.PSObject.Properties['FlagWhenRemoteUntrusted']) { $flagRemote = [bool]$policy.FlagWhenRemoteUntrusted }
            if ($flagRemote -and $rule.RemoteAddressesTrusted) { continue }

            if ($policy.PSObject.Properties['AdditionalMatch'] -and $policy.AdditionalMatch) {
                $additionalMatch = $false
                try { $additionalMatch = & $policy.AdditionalMatch $rule } catch { $additionalMatch = $false }
                if (-not $additionalMatch) { continue }
            }

            $policyRules.Add($rule) | Out-Null
        }

        if ($policyRules.Count -gt 0) {
            $matches.Add([pscustomobject]@{
                Policy = $policy
                Rules  = $policyRules.ToArray()
            }) | Out-Null
        }
    }

    return $matches.ToArray()
}



function Invoke-SecurityFirewallChecks {
    param(
        [Parameter(Mandatory)]
        $Context,
        [Parameter(Mandatory)]
        $CategoryResult
    )

    $firewallArtifact = Get-AnalyzerArtifact -Context $Context -Name 'firewall'
    Write-HeuristicDebug -Source 'Security' -Message 'Resolved firewall artifact' -Data ([ordered]@{
        Found = [bool]$firewallArtifact
    })
    $firewallPayload = $null
    if ($firewallArtifact) {
        $firewallPayload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $firewallArtifact)
        Write-HeuristicDebug -Source 'Security' -Message 'Evaluating firewall payload' -Data ([ordered]@{
            HasProfiles = [bool]($firewallPayload -and $firewallPayload.Profiles)
        })
        if ($firewallPayload -and $firewallPayload.Profiles) {
            $disabledProfiles = [System.Collections.Generic.List[string]]::new()
            foreach ($profile in $firewallPayload.Profiles) {
                if ($profile.PSObject.Properties['Enabled']) {
                    $enabled = ConvertTo-NullableBool $profile.Enabled
                    if ($enabled -eq $false) {
                        $disabledProfiles.Add($profile.Name)
                    }
                    Add-CategoryCheck -CategoryResult $CategoryResult -Name ("Firewall profile: {0}" -f $profile.Name) -Status ($(if ($enabled) { 'Enabled' } elseif ($enabled -eq $false) { 'Disabled' } else { 'Unknown' })) -Details ("Inbound: {0}; Outbound: {1}" -f $profile.DefaultInboundAction, $profile.DefaultOutboundAction)
                }
            }

            if ($disabledProfiles.Count -gt 0) {
                Add-CategoryIssue -CategoryResult $CategoryResult -Severity 'high' -Title ('Firewall profiles disabled: {0}, leaving the system unprotected.' -f ($disabledProfiles -join ', ')) -Subcategory 'Windows Firewall' -Remediation $script:SecurityFirewallBaselineRemediation
            } else {
                Add-CategoryNormal -CategoryResult $CategoryResult -Title 'All firewall profiles enabled' -Subcategory 'Windows Firewall'
            }
        } elseif ($firewallPayload -and $firewallPayload.Profiles -and $firewallPayload.Profiles.Error) {
            Add-CategoryIssue -CategoryResult $CategoryResult -Severity 'medium' -Title 'Firewall profile query failed, so the network defense posture is unknown.' -Evidence $firewallPayload.Profiles.Error -Subcategory 'Windows Firewall' -Remediation $script:SecurityFirewallBaselineRemediation
        } else {
            Add-CategoryIssue -CategoryResult $CategoryResult -Severity 'high' -Title 'Windows Firewall not captured, so the network defense posture is unknown.' -Subcategory 'Windows Firewall' -Remediation $script:SecurityFirewallBaselineRemediation
        }

        if ($firewallPayload -and $firewallPayload.Rules) {
            $ruleEntries = ConvertTo-List $firewallPayload.Rules
            $ruleErrors = @($ruleEntries | Where-Object { $_ -and $_.PSObject.Properties['Error'] -and $_.Error })

            if ($ruleErrors.Count -gt 0) {
                $ruleError = $ruleErrors | Select-Object -First 1
                $errorEvidence = if ($ruleError -and $ruleError.Error) { [string]$ruleError.Error } else { 'Unknown error enumerating firewall rules.' }
                Add-CategoryIssue -CategoryResult $CategoryResult -Severity 'medium' -Title 'Firewall rule query failed, so Remote Desktop exposure cannot be verified.' -Evidence $errorEvidence -Subcategory 'Windows Firewall' -Remediation $script:SecurityFirewallBaselineRemediation -CheckId 'Security/RdpPublicProfile'
            } else {
                $rdpRules = [System.Collections.Generic.List[object]]::new()
                $rdpPublicEvidence = [System.Collections.Generic.List[string]]::new()
                $rdpRestrictedEvidence = [System.Collections.Generic.List[string]]::new()

                foreach ($rule in $ruleEntries) {
                    if (-not $rule) { continue }

                    $enabled = $null
                    if ($rule.PSObject.Properties['Enabled']) {
                        $enabled = ConvertTo-NullableBool $rule.Enabled
                    }
                    if ($enabled -ne $true) { continue }

                    $direction = ([string]$rule.Direction).Trim()
                    if (-not $direction) { continue }
                    try {
                        $direction = $direction.ToLowerInvariant()
                    } catch {
                        $direction = $direction.ToLower()
                    }
                    if ($direction -notin @('inbound', 'in')) { continue }

                    $action = ([string]$rule.Action).Trim()
                    if (-not $action) { continue }
                    try {
                        $action = $action.ToLowerInvariant()
                    } catch {
                        $action = $action.ToLower()
                    }
                    if ($action -notin @('allow', 'permitted', 'permit')) { continue }

                    $textCandidates = [System.Collections.Generic.List[string]]::new()
                    if ($rule.PSObject.Properties['DisplayName'] -and $rule.DisplayName) {
                        $textCandidates.Add([string]$rule.DisplayName) | Out-Null
                    }
                    if ($rule.PSObject.Properties['Group'] -and $rule.Group) {
                        $textCandidates.Add([string]$rule.Group) | Out-Null
                    }
                    if ($rule.PSObject.Properties['Description'] -and $rule.Description) {
                        $textCandidates.Add([string]$rule.Description) | Out-Null
                    }

                    $isRdpRule = $false
                    foreach ($text in $textCandidates) {
                        if ([string]::IsNullOrWhiteSpace($text)) { continue }
                        try {
                            $textValue = $text.ToLowerInvariant()
                        } catch {
                            $textValue = $text.ToLower()
                        }

                        if ($textValue -match 'remote\s*desktop' -or $textValue -match '\brdp\b') {
                            $isRdpRule = $true
                            break
                        }
                    }

                    if (-not $isRdpRule) { continue }

                    $null = $rdpRules.Add($rule)

                    $profileText = ([string]$rule.Profile).Trim()
                    $profileTokens = @()
                    if ($profileText) {
                        $profileTokens = $profileText -split '[,;]'
                    }

                    $includesPublic = $false
                    foreach ($token in $profileTokens) {
                        $tokenTrimmed = ([string]$token).Trim()
                        if (-not $tokenTrimmed) { continue }
                        try {
                            $tokenValue = $tokenTrimmed.ToLowerInvariant()
                        } catch {
                            $tokenValue = $tokenTrimmed.ToLower()
                        }

                        if ($tokenValue -in @('public', 'any', 'all')) {
                            $includesPublic = $true
                            break
                        }
                    }

                    $detailParts = [System.Collections.Generic.List[string]]::new()
                    if ($rule.PSObject.Properties['DisplayName'] -and $rule.DisplayName) {
                        $detailParts.Add(("Name={0}" -f $rule.DisplayName)) | Out-Null
                    }
                    if ($rule.PSObject.Properties['Group'] -and $rule.Group) {
                        $detailParts.Add(("Group={0}" -f $rule.Group)) | Out-Null
                    }
                    if ($profileText) {
                        $detailParts.Add(("Profiles={0}" -f $profileText)) | Out-Null
                    }
                    if ($rule.PSObject.Properties['PolicyStore'] -and $rule.PolicyStore) {
                        $detailParts.Add(("PolicyStore={0}" -f $rule.PolicyStore)) | Out-Null
                    }
                    if ($rule.PSObject.Properties['Service'] -and $rule.Service) {
                        $detailParts.Add(("Service={0}" -f $rule.Service)) | Out-Null
                    }

                    $evidenceText = if ($detailParts.Count -gt 0) { $detailParts -join '; ' } else { 'Remote Desktop firewall rule detected' }

                    if ($includesPublic) {
                        $rdpPublicEvidence.Add($evidenceText) | Out-Null
                    } else {
                        $rdpRestrictedEvidence.Add($evidenceText) | Out-Null
                    }
                }

                if ($rdpPublicEvidence.Count -gt 0) {
                    $evidence = $rdpPublicEvidence -join ' | '
                    Add-CategoryIssue -CategoryResult $CategoryResult -Severity 'high' -Title 'Remote Desktop firewall rules allow the Public profile and expose the device to unsolicited internet logon attempts.' -Evidence $evidence -Subcategory 'Windows Firewall' -Remediation $script:SecurityFirewallBaselineRemediation -CheckId 'Security/RdpPublicProfile'
                } elseif ($rdpRules.Count -gt 0) {
                    $evidence = if ($rdpRestrictedEvidence.Count -gt 0) { $rdpRestrictedEvidence -join ' | ' } else { 'Remote Desktop rules detected without Public profile access.' }
                    Add-CategoryNormal -CategoryResult $CategoryResult -Title 'Remote Desktop firewall rules exclude the Public profile so unsolicited internet access is blocked.' -Evidence $evidence -Subcategory 'Windows Firewall' -CheckId 'Security/RdpPublicProfile'
                }
            }
        }
    } else {
        Add-CategoryIssue -CategoryResult $CategoryResult -Severity 'high' -Title 'Windows Firewall not captured, so the network defense posture is unknown.' -Subcategory 'Windows Firewall' -Remediation $script:SecurityFirewallBaselineRemediation
    }

    if ($firewallPayload -and $firewallPayload.PSObject.Properties['Rules']) {
        $ruleEntries = ConvertTo-List $firewallPayload.Rules
        $ruleErrors = [System.Collections.Generic.List[object]]::new()
        $normalizedRules = [System.Collections.Generic.List[pscustomobject]]::new()

        foreach ($ruleEntry in $ruleEntries) {
            if (-not $ruleEntry) { continue }
            if ($ruleEntry.PSObject -and $ruleEntry.PSObject.Properties['Error'] -and $ruleEntry.Error) {
                $ruleErrors.Add($ruleEntry) | Out-Null
                continue
            }

            $normalized = ConvertTo-FirewallRuleInfo $ruleEntry
            if ($normalized) { $normalizedRules.Add($normalized) | Out-Null }
        }

        if ($normalizedRules.Count -gt 0) {
            $smbAnalysis = Get-FirewallSmbExposureAnalysis -Context $Context -Rules ($normalizedRules.ToArray())
            if ($smbAnalysis) {
                $crossVlanRules = ConvertTo-List $smbAnalysis.TcpCrossVlanRules
                $allTcpRules = ConvertTo-List $smbAnalysis.TcpRules
                $udpRules = ConvertTo-List $smbAnalysis.UdpRules

                if ($smbAnalysis.IsListening -and $crossVlanRules.Count -gt 0) {
                    $smbEvidence = New-SmbExposureHighEvidence $smbAnalysis
                    if ($smbEvidence) {
                        Add-CategoryIssue -CategoryResult $CategoryResult -Severity 'high' -Title 'SMB/NetBIOS exposed across VLANs (inbound rule allows 445/139 from unrestricted scope)' -Evidence $smbEvidence -Subcategory 'Windows Firewall' -Remediation $script:SecurityFirewallBaselineRemediation -CheckId 'Security/Firewall/SmbInbound'
                    }
                } else {
                    if ($smbAnalysis.IsListening -and $allTcpRules.Count -gt 0 -and $crossVlanRules.Count -eq 0) {
                        $restrictedEvidence = New-SmbExposureRestrictedEvidence $smbAnalysis
                        if ($restrictedEvidence) {
                            Add-CategoryIssue -CategoryResult $CategoryResult -Severity 'low' -Title 'SMB firewall rules restricted to local scopes or inactive profiles.' -Evidence $restrictedEvidence -Subcategory 'Windows Firewall' -CheckId 'Security/Firewall/SmbInbound'
                        }
                    }

                    if ($crossVlanRules.Count -eq 0 -and $allTcpRules.Count -eq 0 -and $udpRules.Count -gt 0) {
                        $udpEvidence = New-SmbUdpHygieneEvidence $smbAnalysis
                        if ($udpEvidence) {
                            Add-CategoryIssue -CategoryResult $CategoryResult -Severity 'low' -Title 'NetBIOS discovery rules allow inbound UDP 137/138 (hygiene).' -Evidence $udpEvidence -Subcategory 'Windows Firewall' -Remediation $script:SecurityFirewallBaselineRemediation -CheckId 'Security/Firewall/SmbUdpDiscovery'
                        }
                    }
                }
            }

            $policyMatches = Get-FirewallPolicyMatches -Rules ($normalizedRules.ToArray())
            foreach ($match in $policyMatches) {
                if (-not $match) { continue }
                $policy = $match.Policy
                if (-not $policy) { continue }

                $evidenceRules = [System.Collections.Generic.List[object]]::new()
                foreach ($ruleInfo in (ConvertTo-List $match.Rules)) {
                    if (-not $ruleInfo) { continue }
                    $evidenceRules.Add((New-FirewallRuleEvidenceItem $ruleInfo)) | Out-Null
                }

                $evidence = [ordered]@{
                    Guidance = $policy.Guidance
                    Rules    = $evidenceRules.ToArray()
                }

                Add-CategoryIssue -CategoryResult $CategoryResult -Severity $policy.Severity -Title $policy.Title -Evidence $evidence -Subcategory 'Windows Firewall' -CheckId $policy.CheckId
            }
        }

        if ($ruleErrors.Count -gt 0) {
            Add-CategoryIssue -CategoryResult $CategoryResult -Severity 'warning' -Title 'Some firewall rules could not be parsed, so port exposure coverage may be incomplete.' -Evidence ($ruleErrors.ToArray()) -Subcategory 'Windows Firewall' -Remediation $script:SecurityFirewallBaselineRemediation -CheckId 'Security/Firewall/RuleErrors'
        }
    } elseif ($firewallArtifact) {
        Add-CategoryIssue -CategoryResult $CategoryResult -Severity 'warning' -Title 'Firewall rule inventory missing, so port exposure checks could not run.' -Subcategory 'Windows Firewall' -Remediation $script:SecurityFirewallBaselineRemediation -CheckId 'Security/Firewall/MissingRules'
    }
}
