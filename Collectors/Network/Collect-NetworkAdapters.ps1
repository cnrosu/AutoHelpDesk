<#!
.SYNOPSIS
    Collects network adapter configuration, IP assignments, and operational state.
#>
[CmdletBinding()]
param(
    [Parameter()]
    [string]$OutputDirectory = (Join-Path -Path (Split-Path -Parent $PSCommandPath) -ChildPath '..\\output')
)

. (Join-Path -Path $PSScriptRoot -ChildPath '..\\CollectorCommon.ps1')

function Convert-ToNetworkStringArray {
    param($Value)

    $results = New-Object System.Collections.Generic.List[string]
    $seen = New-Object System.Collections.Generic.HashSet[string]([System.StringComparer]::OrdinalIgnoreCase)

    $addText = {
        param([string]$Text)

        if (-not $Text) { return }
        $trimmed = $Text.Trim()
        if (-not $trimmed) { return }
        if ($seen.Add($trimmed)) { $results.Add($trimmed) | Out-Null }
    }

    $addNetworkValue = $null
    $addNetworkValue = {
        param($InputValue)

        if ($null -eq $InputValue) { return }

        if ($InputValue -is [string]) {
            & $addText $InputValue
            return
        }

        if ($InputValue -is [ValueType]) {
            & $addText ($InputValue.ToString())
            return
        }

        if ($InputValue -is [System.Net.IPAddress]) {
            & $addText ($InputValue.ToString())
            return
        }

        if ($InputValue -is [System.Collections.IEnumerable] -and -not ($InputValue -is [string])) {
            foreach ($item in $InputValue) { & $addNetworkValue $item }
            return
        }

        foreach ($prop in 'NextHop','IPAddress','IPv4Address','IPv6Address','Address','ServerAddresses','DisplayValue','Value','Name') {
            if ($InputValue.PSObject.Properties[$prop]) {
                & $addNetworkValue $InputValue.$prop
                return
            }
        }

        & $addText ([string]$InputValue)
    }

    & $addNetworkValue $Value
    return $results.ToArray()
}

function ConvertTo-LinkSpeedMbps {
    param($Value)

    if ($null -eq $Value) { return $null }

    if ($Value -is [double] -or $Value -is [single] -or $Value -is [float]) { return [double]$Value }
    if ($Value -is [int] -or $Value -is [long]) { return [double]$Value }

    $text = [string]$Value
    if (-not $text) { return $null }

    $normalized = $text.Trim()
    if (-not $normalized) { return $null }

    $regex = '^(?<value>[0-9]+(?:\.[0-9]+)?)\s*(?<unit>g|m|k)?(bit|bps|b/s|bps)?'
    $match = [regex]::Match($normalized, $regex, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
    if ($match.Success) {
        $number = [double]::Parse($match.Groups['value'].Value, [System.Globalization.CultureInfo]::InvariantCulture)
        $unit = $match.Groups['unit'].Value.ToLowerInvariant()
        switch ($unit) {
            'g' { return $number * 1000 }
            'm' { return $number }
            'k' { return [math]::Round($number / 1000, 3) }
            default {
                if ($normalized -match '(?i)gbps|gbit') { return $number * 1000 }
                if ($normalized -match '(?i)mbps|mbit') { return $number }
                if ($normalized -match '(?i)kbps|kbit') { return [math]::Round($number / 1000, 3) }
                if ($normalized -match '(?i)bps|bit') {
                    return [math]::Round($number / 1000000, 3)
                }
            }
        }
    }

    return $null
}

function Get-DefaultRouteMap {
    param(
        [Parameter(Mandatory)]
        [System.Collections.IEnumerable]$Routes
    )

    $map = @{}

    foreach ($route in $Routes) {
        if (-not $route) { continue }

        $ifIndex = $null
        if ($route.PSObject.Properties['InterfaceIndex']) { $ifIndex = $route.InterfaceIndex }
        if ($null -eq $ifIndex -and $route.PSObject.Properties['IfIndex']) { $ifIndex = $route.IfIndex }
        if ($null -eq $ifIndex) { continue }

        $nextHop = $null
        if ($route.PSObject.Properties['NextHop']) { $nextHop = [string]$route.NextHop }
        if (-not $nextHop) { continue }

        $metric = $null
        if ($route.PSObject.Properties['RouteMetric']) { $metric = $route.RouteMetric }
        elseif ($route.PSObject.Properties['Metric']) { $metric = $route.Metric }

        $metricValue = $null
        if ($metric -is [int] -or $metric -is [long] -or $metric -is [double]) {
            $metricValue = [int][double]$metric
        } elseif ($metric) {
            $metricParsed = 0
            if ([int]::TryParse([string]$metric, [ref]$metricParsed)) {
                $metricValue = $metricParsed
            }
        }

        if (-not $map.ContainsKey($ifIndex)) {
            $map[$ifIndex] = [ordered]@{
                NextHop = $nextHop
                Metric  = $metricValue
            }
            continue
        }

        $existing = $map[$ifIndex]
        if ($existing) {
            $existingMetric = if ($existing.Metric -is [int]) { $existing.Metric } else { $null }
            if ($null -eq $existingMetric -or ($metricValue -ne $null -and $metricValue -lt $existingMetric)) {
                $map[$ifIndex] = [ordered]@{
                    NextHop = $nextHop
                    Metric  = $metricValue
                }
            }
        }
    }

    return $map
}

function Get-NetworkAdapterAdvancedProperties {
    try {
        $properties = @(Get-NetAdapterAdvancedProperty -ErrorAction Stop | Select-Object Name, DisplayName, DisplayValue)
        return $properties | ForEach-Object {
            [pscustomobject]@{
                Name        = if ($_.Name) { [string]$_.Name } else { $null }
                DisplayName = if ($_.DisplayName) { [string]$_.DisplayName } else { $null }
                DisplayValue = if ($_.DisplayValue) { [string]$_.DisplayValue } else { $null }
            }
        }
    } catch {
        return [pscustomobject]@{
            Source = 'Get-NetAdapterAdvancedProperty'
            Error  = $_.Exception.Message
        }
    }
}

function Get-WifiContext {
    $context = @{
        Interfaces = @()
        Status     = 'unavailable'
    }

    try {
        $output = & netsh.exe wlan show interfaces 2>&1
        if ($LASTEXITCODE -ne 0) {
            $context.Status = 'error'
            $context.Error = ($output | Select-Object -First 1)
            return $context
        }

        $lines = @($output)
        $interfaces = New-Object System.Collections.Generic.List[object]
        $current = $null

        foreach ($line in $lines) {
            if (-not $line) { continue }

            if ($line -match '^\s*Name\s*:\s*(.+)$') {
                if ($current) { $interfaces.Add([pscustomobject]$current) | Out-Null }
                $current = [ordered]@{
                    Name = $matches[1].Trim()
                }
                continue
            }

            if (-not $current) { continue }

            if ($line -match '^\s*Description\s*:\s*(.+)$') { $current.Description = $matches[1].Trim(); continue }
            if ($line -match '^\s*State\s*:\s*(.+)$') { $current.State = $matches[1].Trim(); continue }
            if ($line -match '^\s*SSID\s*:\s*(.+)$') { $current.SSID = $matches[1].Trim(); continue }
            if ($line -match '^\s*BSSID\s*:\s*(.+)$') { $current.BSSID = $matches[1].Trim(); continue }
            if ($line -match '^\s*Signal\s*:\s*(.+)$') { $current.Signal = $matches[1].Trim(); continue }
            if ($line -match '^\s*Radio type\s*:\s*(.+)$') { $current.RadioType = $matches[1].Trim(); continue }
        }

        if ($current) { $interfaces.Add([pscustomobject]$current) | Out-Null }

        $context.Status = 'ok'
        $context.Interfaces = $interfaces.ToArray()
    } catch {
        $context.Status = 'error'
        $context.Error = $_.Exception.Message
    }

    return $context
}

function Merge-NetworkInterfaces {
    param(
        $AdapterEntries,
        $IpConfigurations,
        $DefaultRoutesV4,
        $DefaultRoutesV6,
        [string]$CollectedAtUtc
    )

    $interfaceMap = @{}

    function Get-InterfaceKey {
        param($IfIndex, $Alias)

        if ($null -ne $IfIndex) { return 'if:' + $IfIndex }
        if ($Alias) {
            try { return 'alias:' + $Alias.ToLowerInvariant() } catch { return 'alias:' + $Alias }
        }
        return [guid]::NewGuid().ToString()
    }

    foreach ($adapter in $AdapterEntries) {
        if (-not $adapter) { continue }

        $alias = $null
        if ($adapter.PSObject.Properties['Name']) { $alias = [string]$adapter.Name }
        if (-not $alias -and $adapter.PSObject.Properties['InterfaceAlias']) { $alias = [string]$adapter.InterfaceAlias }

        $ifIndex = $null
        if ($adapter.PSObject.Properties['IfIndex']) { $ifIndex = $adapter.IfIndex }
        elseif ($adapter.PSObject.Properties['InterfaceIndex']) { $ifIndex = $adapter.InterfaceIndex }

        $key = Get-InterfaceKey $ifIndex $alias
        if (-not $interfaceMap.ContainsKey($key)) {
            $interfaceMap[$key] = [ordered]@{
                InterfaceAlias       = $alias
                InterfaceDescription = if ($adapter.PSObject.Properties['InterfaceDescription']) { [string]$adapter.InterfaceDescription } else { $null }
                IfIndex              = $ifIndex
                Status               = if ($adapter.PSObject.Properties['Status']) { [string]$adapter.Status } else { $null }
                MacAddress           = if ($adapter.PSObject.Properties['MacAddress']) { [string]$adapter.MacAddress } else { $null }
                MediaType            = if ($adapter.PSObject.Properties['MediaType']) { [string]$adapter.MediaType } else { $null }
                LinkSpeedText        = if ($adapter.PSObject.Properties['LinkSpeed']) { [string]$adapter.LinkSpeed } else { $null }
                LinkSpeedMbps        = ConvertTo-LinkSpeedMbps ($adapter.PSObject.Properties['LinkSpeed'] ? $adapter.LinkSpeed : $null)
                DriverInformation    = if ($adapter.PSObject.Properties['DriverInformation']) { [string]$adapter.DriverInformation } else { $null }
                IPv4                 = @()
                IPv6                 = @()
                IPv4DefaultGateway   = @()
                IPv6DefaultGateway   = @()
                DnsServers           = @()
                RouteDefaultGatewayV4 = $null
                RouteDefaultGatewayV4Metric = $null
                RouteDefaultGatewayV6 = $null
                RouteDefaultGatewayV6Metric = $null
                CollectedAtUtc       = $CollectedAtUtc
            }
        }

        $info = $interfaceMap[$key]
        if (-not $info.InterfaceAlias) { $info.InterfaceAlias = $alias }
        if (-not $info.InterfaceDescription -and $adapter.PSObject.Properties['InterfaceDescription']) {
            $info.InterfaceDescription = [string]$adapter.InterfaceDescription
        }
        if ($null -eq $info.IfIndex -and $null -ne $ifIndex) { $info.IfIndex = $ifIndex }
        if (-not $info.Status -and $adapter.PSObject.Properties['Status']) { $info.Status = [string]$adapter.Status }
        if (-not $info.MacAddress -and $adapter.PSObject.Properties['MacAddress']) { $info.MacAddress = [string]$adapter.MacAddress }
        if (-not $info.MediaType -and $adapter.PSObject.Properties['MediaType']) { $info.MediaType = [string]$adapter.MediaType }
        if (-not $info.LinkSpeedText -and $adapter.PSObject.Properties['LinkSpeed']) { $info.LinkSpeedText = [string]$adapter.LinkSpeed }
        if ($null -eq $info.LinkSpeedMbps) { $info.LinkSpeedMbps = ConvertTo-LinkSpeedMbps ($adapter.PSObject.Properties['LinkSpeed'] ? $adapter.LinkSpeed : $null) }
        if (-not $info.DriverInformation -and $adapter.PSObject.Properties['DriverInformation']) { $info.DriverInformation = [string]$adapter.DriverInformation }
    }

    foreach ($config in $IpConfigurations) {
        if (-not $config) { continue }

        $alias = if ($config.PSObject.Properties['InterfaceAlias']) { [string]$config.InterfaceAlias } else { $null }
        $ifIndex = $null
        if ($config.PSObject.Properties['InterfaceIndex']) { $ifIndex = $config.InterfaceIndex }

        $key = Get-InterfaceKey $ifIndex $alias
        if (-not $interfaceMap.ContainsKey($key)) {
            $interfaceMap[$key] = [ordered]@{
                InterfaceAlias       = $alias
                InterfaceDescription = if ($config.PSObject.Properties['InterfaceDescription']) { [string]$config.InterfaceDescription } else { $null }
                IfIndex              = $ifIndex
                Status               = $null
                MacAddress           = $null
                MediaType            = $null
                LinkSpeedText        = $null
                LinkSpeedMbps        = $null
                DriverInformation    = $null
                IPv4                 = @()
                IPv6                 = @()
                IPv4DefaultGateway   = @()
                IPv6DefaultGateway   = @()
                DnsServers           = @()
                RouteDefaultGatewayV4 = $null
                RouteDefaultGatewayV4Metric = $null
                RouteDefaultGatewayV6 = $null
                RouteDefaultGatewayV6Metric = $null
                CollectedAtUtc       = $CollectedAtUtc
            }
        }

        $info = $interfaceMap[$key]
        if (-not $info.InterfaceAlias) { $info.InterfaceAlias = $alias }
        if (-not $info.InterfaceDescription -and $config.PSObject.Properties['InterfaceDescription']) {
            $info.InterfaceDescription = [string]$config.InterfaceDescription
        }
        if ($null -eq $info.IfIndex -and $null -ne $ifIndex) { $info.IfIndex = $ifIndex }

        if ($config.PSObject.Properties['IPv4Address']) {
            foreach ($value in Convert-ToNetworkStringArray $config.IPv4Address) {
                if (-not ($info.IPv4 -contains $value)) { $info.IPv4 += $value }
            }
        }

        if ($config.PSObject.Properties['IPv6Address']) {
            foreach ($value in Convert-ToNetworkStringArray $config.IPv6Address) {
                if (-not ($info.IPv6 -contains $value)) { $info.IPv6 += $value }
            }
        }

        if ($config.PSObject.Properties['DNSServer']) {
            foreach ($value in Convert-ToNetworkStringArray $config.DNSServer) {
                if (-not ($info.DnsServers -contains $value)) { $info.DnsServers += $value }
            }
        }

        if ($config.PSObject.Properties['IPv4DefaultGateway']) {
            foreach ($value in Convert-ToNetworkStringArray $config.IPv4DefaultGateway) {
                if (-not ($info.IPv4DefaultGateway -contains $value)) { $info.IPv4DefaultGateway += $value }
            }
        }

        if ($config.PSObject.Properties['IPv6DefaultGateway']) {
            foreach ($value in Convert-ToNetworkStringArray $config.IPv6DefaultGateway) {
                if (-not ($info.IPv6DefaultGateway -contains $value)) { $info.IPv6DefaultGateway += $value }
            }
        }
    }

    foreach ($entry in $interfaceMap.Values) {
        if ($entry.IfIndex -ne $null -and $DefaultRoutesV4.ContainsKey($entry.IfIndex)) {
            $routeInfo = $DefaultRoutesV4[$entry.IfIndex]
            $entry.RouteDefaultGatewayV4 = $routeInfo.NextHop
            $entry.RouteDefaultGatewayV4Metric = $routeInfo.Metric
        }

        if ($entry.IfIndex -ne $null -and $DefaultRoutesV6.ContainsKey($entry.IfIndex)) {
            $routeInfo = $DefaultRoutesV6[$entry.IfIndex]
            $entry.RouteDefaultGatewayV6 = $routeInfo.NextHop
            $entry.RouteDefaultGatewayV6Metric = $routeInfo.Metric
        }
    }

    return $interfaceMap.Values
}

function Capture-NetworkSnapshot {
    $timestamp = (Get-Date).ToUniversalTime().ToString('o')

    $adapterEntries = @()
    $adapterError = $null
    try {
        $adapterEntries = @(Get-NetAdapter -ErrorAction Stop)
    } catch {
        $adapterError = $_.Exception.Message
    }

    $ipConfigEntries = @()
    $ipConfigError = $null
    try {
        $ipConfigEntries = @(Get-NetIPConfiguration -ErrorAction Stop)
    } catch {
        $ipConfigError = $_.Exception.Message
    }

    $defaultRoutesV4 = @()
    $routeV4Error = $null
    try {
        $defaultRoutesV4 = @(Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction Stop)
    } catch {
        $routeV4Error = $_.Exception.Message
    }

    $defaultRoutesV6 = @()
    $routeV6Error = $null
    try {
        $defaultRoutesV6 = @(Get-NetRoute -DestinationPrefix '::/0' -ErrorAction Stop)
    } catch {
        $routeV6Error = $_.Exception.Message
    }

    $wifiContext = Get-WifiContext

    $interfaces = @()
    if ($adapterEntries.Count -gt 0 -or $ipConfigEntries.Count -gt 0) {
        $interfaces = @(Merge-NetworkInterfaces -AdapterEntries $adapterEntries -IpConfigurations $ipConfigEntries -DefaultRoutesV4 (Get-DefaultRouteMap -Routes $defaultRoutesV4) -DefaultRoutesV6 (Get-DefaultRouteMap -Routes $defaultRoutesV6) -CollectedAtUtc $timestamp)
    }

    $activeCount = 0
    foreach ($iface in $interfaces) {
        if (-not $iface) { continue }
        $statusText = if ($iface.Status) { [string]$iface.Status } else { '' }
        $normalizedStatus = if ($statusText) { $statusText.Trim().ToLowerInvariant() } else { '' }
        $isUp = ($normalizedStatus -eq 'up' -or $normalizedStatus -eq 'connected' -or $normalizedStatus -like 'up*')
        if (-not $isUp) { continue }

        $hasGateway = ($iface.IPv4DefaultGateway.Count -gt 0) -or ($iface.RouteDefaultGatewayV4) -or ($iface.IPv6DefaultGateway.Count -gt 0) -or ($iface.RouteDefaultGatewayV6)
        if ($hasGateway) { $activeCount++ }
    }

    $status = [ordered]@{}
    $status.NetAdapter = if ($adapterError) { 'error' } else { 'ok' }
    $status.NetIPConfiguration = if ($ipConfigError) { 'error' } else { 'ok' }
    $status.NetRouteV4 = if ($routeV4Error) { 'error' } else { 'ok' }
    $status.NetRouteV6 = if ($routeV6Error) { 'error' } else { 'ok' }
    $status.Wifi = $wifiContext.Status

    $errors = [ordered]@{}
    if ($adapterError) { $errors.NetAdapter = $adapterError }
    if ($ipConfigError) { $errors.NetIPConfiguration = $ipConfigError }
    if ($routeV4Error) { $errors.NetRouteV4 = $routeV4Error }
    if ($routeV6Error) { $errors.NetRouteV6 = $routeV6Error }
    if ($wifiContext.Status -eq 'error' -and $wifiContext.Error) { $errors.Wifi = $wifiContext.Error }

    $pass = [ordered]@{
        CollectedAtUtc        = $timestamp
        Interfaces            = $interfaces
        ActiveInterfaceCount  = $activeCount
        Status                = $status
    }

    if ($wifiContext.Interfaces -and $wifiContext.Interfaces.Count -gt 0) {
        $pass.Wifi = $wifiContext.Interfaces
    }

    if ($errors.Count -gt 0) { $pass.Errors = $errors }

    return $pass
}

function Invoke-Main {
    $passes = New-Object System.Collections.Generic.List[object]

    $firstPass = Capture-NetworkSnapshot
    $passes.Add($firstPass) | Out-Null

    if (($firstPass.ActiveInterfaceCount -as [int]) -eq 0) {
        Start-Sleep -Seconds 5
        $secondPass = Capture-NetworkSnapshot
        $passes.Add($secondPass) | Out-Null
    }

    $payload = [ordered]@{
        Passes = $passes.ToArray()
    }

    if ($passes.Count -gt 0) {
        $payload.FirstPassActiveCount = $passes[0].ActiveInterfaceCount
        if ($passes.Count -gt 1) { $payload.SecondPassActiveCount = $passes[1].ActiveInterfaceCount }
    }

    $advancedProperties = Get-NetworkAdapterAdvancedProperties
    if ($advancedProperties) { $payload.Properties = $advancedProperties }

    $result = New-CollectorMetadata -Payload $payload
    $outputPath = Export-CollectorResult -OutputDirectory $OutputDirectory -FileName 'network-adapters.json' -Data $result -Depth 6
    Write-Output $outputPath
}

Invoke-Main
