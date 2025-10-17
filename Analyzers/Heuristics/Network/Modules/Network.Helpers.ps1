function Test-NetworkPrivateIpv4 {
    param([string]$Address)

    if (-not $Address) { return $false }
    if ($Address -match '^10\.') { return $true }
    if ($Address -match '^192\.168\.') { return $true }
    if ($Address -match '^172\.(1[6-9]|2[0-9]|3[0-1])\.'){ return $true }
    return $false
}

function Test-NetworkLoopback {
    param([string]$Address)

    if (-not $Address) { return $false }
    return ($Address -match '^127\.')
}

function ConvertTo-NetworkBoolean {
    param(
        $Value,
        $Default = $false
    )

    if ($null -eq $Value) { return $Default }
    if ($Value -is [bool]) { return $Value }

    try {
        return [System.Management.Automation.LanguagePrimitives]::ConvertTo($Value, [bool])
    } catch {
        return $Default
    }
}

function Test-NetworkValidIpv4Address {
    param([string]$Address)

    if (-not $Address) { return $false }

    $trimmed = $Address.Trim()
    if (-not $trimmed) { return $false }

    $clean = $trimmed -replace '/\d+$',''
    $clean = $clean -replace '%.*$',''

    $parsed = $null
    if (-not [System.Net.IPAddress]::TryParse($clean, [ref]$parsed)) { return $false }
    if ($parsed.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork) { return $false }
    if ($clean -match '^(0\.0\.0\.0|169\.254\.)') { return $false }

    return $true
}

function Test-NetworkValidIpv6Address {
    param([string]$Address)

    if (-not $Address) { return $false }

    $trimmed = $Address.Trim()
    if (-not $trimmed) { return $false }

    $clean = $trimmed -replace '/\d+$',''
    $clean = $clean -replace '%.*$',''

    $parsed = $null
    if (-not [System.Net.IPAddress]::TryParse($clean, [ref]$parsed)) { return $false }
    if ($parsed.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetworkV6) { return $false }
    if ($clean -match '^(?i)(::1|::|fe80:)') { return $false }

    return $true
}

function Normalize-NetworkMacAddress {
    param([string]$MacAddress)

    if (-not $MacAddress) { return $null }

    $trimmed = $MacAddress.Trim()
    if (-not $trimmed) { return $null }

    $hex = ($trimmed -replace '[^0-9A-Fa-f]', '').ToUpperInvariant()
    if ($hex.Length -lt 12) { return $null }
    $hex = $hex.Substring($hex.Length - 12)

    $parts = @()
    for ($i = 0; $i -lt 12; $i += 2) { $parts += $hex.Substring($i, 2) }

    return ($parts -join ':')
}

function Get-NetworkMacOui {
    param([string]$MacAddress)

    $normalized = Normalize-NetworkMacAddress $MacAddress
    if (-not $normalized) { return $null }

    return ($normalized.Substring(0, 8))
}

function Get-NetworkCanonicalIpv4 {
    param([string]$Text)

    if (-not $Text) { return $null }

    $match = [regex]::Match($Text, '\b(\d+\.\d+\.\d+\.\d+)\b')
    if ($match.Success) { return $match.Groups[1].Value }

    return $null
}

function Test-NetworkBroadcastIpv4Address {
    param([string]$Address)

    if (-not $Address) { return $false }

    $canonical = Get-NetworkCanonicalIpv4 $Address
    if (-not $canonical) { return $false }

    if ($canonical -eq '255.255.255.255') { return $true }

    return ($canonical -match '^\d+\.\d+\.\d+\.255$')
}

function Test-NetworkMulticastIpv4Address {
    param([string]$Address)

    if (-not $Address) { return $false }

    $canonical = Get-NetworkCanonicalIpv4 $Address
    if (-not $canonical) { return $false }

    $segments = $canonical.Split('.')
    if ($segments.Count -lt 1) { return $false }

    $firstOctet = $null
    if (-not [int]::TryParse($segments[0], [ref]$firstOctet)) { return $false }

    return ($firstOctet -ge 224 -and $firstOctet -le 239)
}

function Test-NetworkInvalidUnicastMac {
    param([string]$MacAddress)

    if ([string]::IsNullOrWhiteSpace($MacAddress)) { return $true }

    $normalized = Normalize-NetworkMacAddress $MacAddress
    if (-not $normalized) { return $true }

    return ($normalized -eq 'FF:FF:FF:FF:FF:FF' -or $normalized -eq '00:00:00:00:00:00')
}

function Test-NetworkStandardMulticastMac {
    param([string]$MacAddress)

    if ([string]::IsNullOrWhiteSpace($MacAddress)) { return $false }

    $normalized = Normalize-NetworkMacAddress $MacAddress
    if (-not $normalized) { return $false }

    return $normalized -like '01:00:5E:*'
}

function Get-NetworkCanonicalIpv6 {
    param([string]$Text)

    if (-not $Text) { return $null }

    $trimmed = $Text.Trim()
    if (-not $trimmed) { return $null }

    $clean = $trimmed -replace '/\d+$',''
    if ($clean -match '%') {
        $clean = $clean.Split('%')[0]
    }

    $parsed = $null
    if (-not [System.Net.IPAddress]::TryParse($clean, [ref]$parsed)) { return $null }
    if ($parsed.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetworkV6) { return $null }

    return $parsed.ToString()
}

function Get-NetworkAliasKeys {
    param([string]$Alias)

    if (-not $Alias) { return @() }

    $set = New-Object System.Collections.Generic.HashSet[string]([System.StringComparer]::OrdinalIgnoreCase)
    $ordered = New-Object System.Collections.Generic.List[string]

    $addKey = {
        param([string]$Key)
        if (-not $Key) { return }
        if ($set.Add($Key)) { $ordered.Add($Key) | Out-Null }
    }

    & $addKey $Alias

    $lower = $null
    try { $lower = $Alias.ToLowerInvariant() } catch { $lower = $Alias.ToLower() }
    & $addKey $lower

    $compact = if ($lower) { [regex]::Replace($lower, '[^a-z0-9]', '') } else { $null }
    & $addKey $compact

    $noSpaces = if ($lower) { [regex]::Replace($lower, '\s+', '') } else { $null }
    & $addKey $noSpaces

    return $ordered.ToArray()
}

function Normalize-NetworkInventoryText {
    param([string]$Text)

    if (-not $Text) { return $null }

    $trimmed = $Text.Trim()
    if (-not $trimmed) { return $null }

    $single = [regex]::Replace($trimmed, '\s+', ' ')

    try { return $single.ToUpperInvariant() } catch { return $single.ToUpper() }
}

function Get-NetworkObjectPropertyValue {
    param(
        [object]$InputObject,
        [string[]]$PropertyNames
    )

    if (-not $InputObject -or -not $PropertyNames) { return $null }

    foreach ($name in $PropertyNames) {
        if (-not $name) { continue }
        if ($InputObject.PSObject -and $InputObject.PSObject.Properties[$name]) {
            $value = $InputObject.$name
            if ($null -ne $value -and $value -ne '') { return $value }
        }
    }

    return $null
}
