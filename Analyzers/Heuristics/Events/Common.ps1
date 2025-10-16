function ConvertTo-EventsDateTimeUtc {
    param(
        [Parameter()]
        $Value
    )

    if ($null -eq $Value) { return $null }

    if ($Value -is [datetime]) {
        try {
            return $Value.ToUniversalTime()
        } catch {
            return $Value
        }
    }

    $text = [string]$Value
    if ([string]::IsNullOrWhiteSpace($text)) { return $null }

    [datetime]$parsedInvariant = [datetime]::MinValue
    if ([datetime]::TryParse($text, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AdjustToUniversal, [ref]$parsedInvariant)) {
        return $parsedInvariant.ToUniversalTime()
    }

    [datetime]$parsedDefault = [datetime]::MinValue
    if ([datetime]::TryParse($text, [ref]$parsedDefault)) {
        return $parsedDefault.ToUniversalTime()
    }

    return $null
}

function Get-EventsEventDataValue {
    param(
        [Parameter()]
        $EventData,

        [Parameter(Mandatory)]
        [string]$Name
    )

    if (-not $EventData) { return $null }

    if ($EventData -is [System.Collections.IDictionary]) {
        foreach ($key in $EventData.Keys) {
            if ($null -eq $key) { continue }
            if ([string]::Equals([string]$key, $Name, [System.StringComparison]::OrdinalIgnoreCase)) {
                return $EventData[$key]
            }
        }
    }

    try {
        if ($EventData.PSObject -and $EventData.PSObject.Properties[$Name]) {
            return $EventData.$Name
        }
    } catch {
    }

    return $null
}

function ConvertTo-EventsArray {
    param($Value)

    if ($null -eq $Value) { return @() }
    if ($Value -is [string]) { return @($Value) }
    if ($Value -is [System.Collections.IEnumerable] -and -not ($Value -is [hashtable])) {
        $items = @()
        foreach ($item in $Value) { $items += $item }
        return $items
    }

    return @($Value)
}

function Test-EventsCorporateDnsServer {
    param([string]$Server)

    if ([string]::IsNullOrWhiteSpace($Server)) { return $false }

    $candidate = $Server.Trim()
    $candidate = $candidate.Split('%')[0]

    $parsed = $null
    if ([System.Net.IPAddress]::TryParse($candidate, [ref]$parsed)) {
        $bytes = $parsed.GetAddressBytes()
        if ($parsed.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork) {
            if ($bytes[0] -eq 10) { return $true }
            if ($bytes[0] -eq 192 -and $bytes[1] -eq 168) { return $true }
            if ($bytes[0] -eq 172 -and $bytes[1] -ge 16 -and $bytes[1] -le 31) { return $true }
            return $false
        }

        if ($parsed.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetworkV6) {
            if (($bytes[0] -band 0xFE) -eq 0xFC) { return $true }
            return $false
        }

        return $false
    }

    return $true
}

function Get-EventsVpnState {
    param($Context)

    $state = [ordered]@{
        Connected = $false
        DnsServers = @()
    }

    if (-not $Context) { return [pscustomobject]$state }

    $artifact = Get-AnalyzerArtifact -Context $Context -Name 'vpn-baseline'
    if (-not $artifact) { return [pscustomobject]$state }

    $payload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $artifact)
    if (-not $payload) { return [pscustomobject]$state }

    $connected = $false
    if ($payload.PSObject.Properties['connections']) {
        foreach ($connection in (ConvertTo-EventsArray -Value $payload.connections)) {
            if (-not $connection) { continue }
            if ($connection.PSObject.Properties['lastStatus']) {
                $status = $connection.lastStatus
                if ($status -and $status.PSObject.Properties['connected'] -and $status.connected -eq $true) {
                    $connected = $true
                    break
                }
            }
        }
    }

    $dnsServers = @()
    if ($payload.PSObject.Properties['network']) {
        $network = $payload.network
        if ($network -and $network.PSObject.Properties['effectiveDnsServers']) {
            $dnsServers = ConvertTo-EventsArray -Value $network.effectiveDnsServers | Where-Object { $_ }
        }
    }

    $state.Connected = $connected
    $state.DnsServers = @($dnsServers)

    return [pscustomobject]$state
}

function ConvertTo-EventsStatusCode {
    param(
        [Parameter(Mandatory)]
        [string]$Code
    )

    if ([string]::IsNullOrWhiteSpace($Code)) { return $null }
    $trimmed = $Code.Trim()

    if ($trimmed -match '^(?i)0x[0-9a-f]+$') {
        try {
            $uintValue = [System.Convert]::ToUInt32($trimmed.Substring(2), 16)
            $hex = ('0x{0:X}' -f $uintValue)
            return [pscustomobject]@{ UIntValue = [uint32]$uintValue; Hex = $hex }
        } catch {
            return $null
        }
    }

    [int]$intValue = 0
    if ([int]::TryParse($trimmed, [ref]$intValue)) {
        $uintValue = [uint32]$intValue
        $hex = ('0x{0:X}' -f $uintValue)
        return [pscustomobject]@{ UIntValue = $uintValue; Hex = $hex }
    }

    return $null
}

function Get-EventsW32tmMetrics {
    param(
        $Status
    )

    $metrics = [ordered]@{
        OffsetSeconds = $null
        Source        = $null
    }

    if (-not $Status) { return [pscustomobject]$metrics }

    $lines = @()
    if ($Status.PSObject.Properties['Output']) {
        $output = $Status.Output
        if ($output -is [System.Collections.IEnumerable] -and -not ($output -is [string])) {
            $lines = @($output)
        } elseif ($output) {
            $lines = @([string]$output)
        }
    }

    foreach ($line in $lines) {
        if (-not $line) { continue }
        $trimmed = $line.Trim()

        if (-not $metrics.Source -and $trimmed -match '^(?i)Source\s*:\s*(?<value>.+)$') {
            $metrics.Source = $matches['value'].Trim()
        }

        if ($null -eq $metrics.OffsetSeconds -and $trimmed -match '(?i)(?:Phase\s+Offset|Clock\s+Skew|Clock\s+Offset|Offset)\s*:\s*(?<value>[-+]?\d+(?:\.\d+)?)(?<unit>\s*(?:ms|milliseconds|s|seconds)?)') {
            $numericValue = [double]$matches['value']
            $unit = $matches['unit']
            if ($unit) {
                $unit = $unit.Trim().ToLowerInvariant()
            }
            if ($unit -eq 'ms' -or $unit -eq 'milliseconds') {
                $numericValue = $numericValue / 1000.0
            }
            $metrics.OffsetSeconds = [int][math]::Round($numericValue)
        }
    }

    return [pscustomobject]$metrics
}

function Normalize-EventsUserName {
    param([string]$UserName)

    if ([string]::IsNullOrWhiteSpace($UserName)) { return $null }

    $value = $UserName.Trim()

    if ($value -match '^[^\\]+\\(?<name>.+)$') {
        $value = $matches['name']
    }

    if ($value -match '^(?<name>[^@]+)@.+$') {
        $value = $matches['name']
    }

    return $value.ToUpperInvariant()
}

function Normalize-EventsHostName {
    param([string]$HostName)

    if ([string]::IsNullOrWhiteSpace($HostName)) { return $null }

    $value = $HostName.Trim()
    if ($value -eq '-' -or $value -eq '--') { return $null }

    if ($value.EndsWith('$')) {
        $value = $value.Substring(0, $value.Length - 1)
    }

    if ($value.Contains('.')) {
        $value = $value.Split('.')[0]
    }

    return $value.ToUpperInvariant()
}

function ConvertTo-EventsMaskedUser {
    param([string]$Value)

    if ([string]::IsNullOrWhiteSpace($Value)) { return $null }

    $text = $Value.Trim()

    if ($text -match '^[^\\]+\\(?<name>.+)$') {
        $text = $matches['name']
    }

    if ($text -match '^(?<name>[^@]+)@.+$') {
        $text = $matches['name']
    }

    if ($text.Length -le 1) { return '***' }
    if ($text.Length -eq 2) { return ('{0}***' -f $text.Substring(0, 1)) }

    return ('{0}***{1}' -f $text.Substring(0, 1), $text.Substring($text.Length - 1))
}

function ConvertTo-EventsMaskedHost {
    param([string]$Value)

    if ([string]::IsNullOrWhiteSpace($Value)) { return $null }

    $text = $Value.Trim()
    if ($text -eq '-' -or $text -eq '--') { return $null }

    if ($text -match '^(?:\d{1,3}\.){3}\d{1,3}$') {
        $octets = $text.Split('.')
        if ($octets.Length -ge 2) {
            return ('{0}.{1}.***' -f $octets[0], $octets[1])
        }

        return ('{0}.***' -f $octets[0])
    }

    if ($text -match '^[0-9a-fA-F:]+$' -and $text.Contains(':')) {
        $prefixLength = [math]::Min(4, $text.Length)
        return ('{0}***' -f $text.Substring(0, $prefixLength))
    }

    if ($text.Contains('-')) {
        $segment = $text.Split('-')[0]
        if ($segment) { return ('{0}-***' -f $segment) }
    }

    if ($text.Contains('.')) {
        $segment = $text.Split('.')[0]
        if ($segment) { return ('{0}.***' -f $segment) }
    }

    if ($text.Length -le 1) { return '***' }
    if ($text.Length -eq 2) { return ('{0}***' -f $text.Substring(0, 1)) }

    return ('{0}***{1}' -f $text.Substring(0, 1), $text.Substring($text.Length - 1))
}

function Get-EventsCurrentDeviceName {
    param($Context)

    if (-not $Context) { return $null }

    $identity = Get-MsinfoSystemIdentity -Context $Context
    if ($identity -and $identity.DeviceName) {
        return [string]$identity.DeviceName
    }

    return $null
}
