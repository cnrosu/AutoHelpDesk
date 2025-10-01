<#!
.SYNOPSIS
    Collects Windows VPN baseline configuration, state, and related telemetry.
.DESCRIPTION
    Captures the RasMan VPN stack configuration including profiles, services,
    network routing/DNS state, and relevant certificate inventory. The collector
    writes artifacts to the Vpn/ folder beneath the requested output directory.
#>
[CmdletBinding()]
param(
    [Parameter()]
    [string]$OutputDirectory = (Join-Path -Path (Split-Path -Parent $PSCommandPath) -ChildPath '..\\output')
)

. (Join-Path -Path $PSScriptRoot -ChildPath '..\\CollectorCommon.ps1')

function Get-VpnHostInfo {
    $computerName = $env:COMPUTERNAME
    if ([string]::IsNullOrWhiteSpace($computerName)) {
        $computerName = [System.Environment]::MachineName
    }

    $userName = $env:USERNAME
    if ([string]::IsNullOrWhiteSpace($userName)) {
        $userName = [System.Environment]::UserName
    }

    $osBuild = $null
    try {
        $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
        if ($os -and $os.PSObject.Properties['BuildNumber']) {
            $osBuild = [string]$os.BuildNumber
        } elseif ($os -and $os.PSObject.Properties['Version']) {
            $osBuild = [string]$os.Version
        }
    } catch {
    }

    if (-not $osBuild) {
        try {
            $osReg = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name CurrentBuild, ReleaseId -ErrorAction Stop
            if ($osReg.CurrentBuild) {
                $osBuild = [string]$osReg.CurrentBuild
                if ($osReg.ReleaseId) {
                    $osBuild = "$osBuild ($($osReg.ReleaseId))"
                }
            }
        } catch {
        }
    }

    return [ordered]@{
        computerName = $computerName
        userName     = $userName
        osBuild      = $osBuild
    }
}

function Get-VpnServiceState {
    param(
        [Parameter(Mandatory)]
        [string]$Name
    )

    try {
        $service = Get-CimInstance -ClassName Win32_Service -Filter ("Name='{0}'" -f $Name) -ErrorAction Stop
        return [ordered]@{
            StartType = if ($service -and $service.PSObject.Properties['StartMode']) { [string]$service.StartMode } else { $null }
            Status    = if ($service -and $service.PSObject.Properties['State']) { [string]$service.State } else { $null }
            Path      = if ($service -and $service.PSObject.Properties['PathName']) { [string]$service.PathName } else { $null }
        }
    } catch {
        try {
            $fallback = Get-Service -Name $Name -ErrorAction Stop
            return [ordered]@{
                StartType = $null
                Status    = [string]$fallback.Status
                Path      = $null
            }
        } catch {
            return [ordered]@{ Error = $_.Exception.Message }
        }
    }
}

function ConvertTo-VpnArray {
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

function Test-VpnPhonebookContainsConnection {
    param(
        [Parameter(Mandatory)]
        [string]$Name,

        [Parameter(Mandatory)]
        [string]$Path
    )

    if (-not (Test-Path -LiteralPath $Path)) { return $false }

    try {
        $escaped = [Regex]::Escape($Name)
        return Select-String -Path $Path -Pattern ("^\[{0}\]" -f $escaped) -Quiet -ErrorAction Stop
    } catch {
        return $false
    }
}

function Get-VpnAuthMetadata {
    param(
        [Parameter(Mandatory)]
        $Connection
    )

    $method = 'Unknown'
    $usesCertificate = $null
    $thumbprint = $null

    $rawMethods = $null
    if ($Connection.PSObject.Properties['AuthenticationMethod']) {
        $rawMethods = $Connection.AuthenticationMethod
    }

    $methods = ConvertTo-VpnArray -Value $rawMethods
    if ($methods.Count -gt 0) {
        $primary = [string]$methods[0]
        if (-not [string]::IsNullOrWhiteSpace($primary)) {
            $normalized = $primary.ToLowerInvariant()
            if ($normalized -match 'eap') {
                $method = 'EAP'
            } elseif ($normalized -match 'mschap') {
                $method = 'MSCHAPv2'
            } elseif ($normalized -match 'cert' -or $normalized -match 'tls') {
                $method = 'TLS'
            } else {
                $method = $primary
            }
        }
    }

    if ($method -eq 'TLS') {
        $usesCertificate = $true
    } elseif ($method -eq 'EAP') {
        $usesCertificate = $null
    } elseif ($method -eq 'MSCHAPv2') {
        $usesCertificate = $false
    }

    foreach ($propertyName in @('MachineCertificateThumbprint','MachineCertificateIssuerName','CertificateThumbprint')) {
        if ($Connection.PSObject.Properties[$propertyName] -and $Connection.$propertyName) {
            $thumbprint = [string]$Connection.$propertyName
            break
        }
    }

    return [ordered]@{
        method                 = $method
        usesCertificate        = $usesCertificate
        certificateThumbprint  = $thumbprint
    }
}

function Get-VpnConnectionStatisticsSnapshot {
    param(
        [Parameter(Mandatory)]
        $Connection
    )

    $parameters = @{ Name = $Connection.Name }
    if ($Connection.PSObject.Properties['AllUserConnection'] -and $Connection.AllUserConnection) {
        $parameters['AllUserConnection'] = $true
    }

    try {
        return Get-VpnConnectionStatistics @parameters -ErrorAction Stop
    } catch {
        return $null
    }
}

function Get-VpnLastStatus {
    param(
        [Parameter(Mandatory)]
        $Connection
    )

    $connected = $false
    $connectedSinceUtc = $null
    $bytesIn = $null
    $bytesOut = $null
    $lastError = $null

    if ($Connection.PSObject.Properties['ConnectionStatus']) {
        $connected = ($Connection.ConnectionStatus -eq 'Connected')
    }

    if ($Connection.PSObject.Properties['LastError'] -and $Connection.LastError) {
        $lastError = [string]$Connection.LastError
    } elseif ($Connection.PSObject.Properties['LastErrorMessage'] -and $Connection.LastErrorMessage) {
        $lastError = [string]$Connection.LastErrorMessage
    }

    $stats = $null
    if ($connected) {
        $stats = Get-VpnConnectionStatisticsSnapshot -Connection $Connection
    }

    if (-not $stats) {
        try {
            $stats = Get-VpnConnectionStatisticsSnapshot -Connection $Connection
        } catch {
            $stats = $null
        }
    }

    if ($stats) {
        if ($stats.PSObject.Properties['BytesIn']) { $bytesIn = [int64]$stats.BytesIn }
        if ($stats.PSObject.Properties['BytesOut']) { $bytesOut = [int64]$stats.BytesOut }
        if ($stats.PSObject.Properties['ConnectionDuration']) {
            try {
                $duration = $stats.ConnectionDuration
                if ($duration -isnot [TimeSpan]) {
                    $duration = [TimeSpan]::Parse([string]$duration)
                }
                if ($duration -is [TimeSpan]) {
                    $connectedSinceUtc = (Get-Date).ToUniversalTime().Add(-$duration).ToString('o')
                }
            } catch {
            }
        }
    }

    return [ordered]@{
        connected          = [bool]$connected
        connectedSinceUtc  = $connectedSinceUtc
        bytesIn            = $bytesIn
        bytesOut           = $bytesOut
        lastError          = $lastError
    }
}

function Get-VpnRoutes {
    param(
        [Parameter(Mandatory)]
        $Connection
    )

    $defaultViaVpn = $null
    $routes = @()

    if ($Connection.PSObject.Properties['Routes'] -and $Connection.Routes) {
        foreach ($route in (ConvertTo-VpnArray -Value $Connection.Routes)) {
            if (-not $route) { continue }
            $prefix = $null
            if ($route.PSObject.Properties['DestinationPrefix']) {
                $prefix = [string]$route.DestinationPrefix
            } elseif ($route.PSObject.Properties['Destination']) {
                $prefix = [string]$route.Destination
            }

            if ($prefix) {
                $routes += $prefix
                if ($prefix -eq '0.0.0.0/0' -or $prefix -eq '::/0') {
                    $defaultViaVpn = $true
                }
            }
        }
    }

    if ($Connection.PSObject.Properties['SplitTunneling']) {
        if ($Connection.SplitTunneling -eq $false -and $null -eq $defaultViaVpn) {
            $defaultViaVpn = $true
        } elseif ($Connection.SplitTunneling -eq $true -and $null -eq $defaultViaVpn) {
            $defaultViaVpn = $false
        }
    }

    return [ordered]@{
        defaultViaVpn  = $defaultViaVpn
        classlessRoutes = ($routes | Where-Object { $_ })
    }
}

function Get-VpnDnsSuffixes {
    param(
        [Parameter(Mandatory)]
        $Connection
    )

    $suffixes = @()
    foreach ($propertyName in @('DnsSuffix','DnsSuffixList','DnsSuffixes')) {
        if ($Connection.PSObject.Properties[$propertyName] -and $Connection.$propertyName) {
            foreach ($item in (ConvertTo-VpnArray -Value $Connection.$propertyName)) {
                if ($item) { $suffixes += [string]$item }
            }
        }
    }

    return $suffixes | Select-Object -Unique
}

function Get-VpnConnectionRecords {
    $results = @()

    $scopes = @(
        @{ Label = 'CurrentUser'; Parameters = @{} },
        @{ Label = 'AllUser';    Parameters = @{ AllUserConnection = $true } }
    )

    foreach ($scope in $scopes) {
        try {
            $connections = Get-VpnConnection @($scope.Parameters) -ErrorAction Stop
        } catch {
            continue
        }

        foreach ($connection in (ConvertTo-VpnArray -Value $connections)) {
            if (-not $connection) { continue }

            $record = [ordered]@{
                name    = [string]$connection.Name
                guid    = if ($connection.PSObject.Properties['Guid']) { [string]$connection.Guid } else { $null }
                type    = if ($connection.PSObject.Properties['TunnelType']) { [string]$connection.TunnelType } else { 'Unknown' }
                serverAddress = if ($connection.PSObject.Properties['ServerAddress']) { [string]$connection.ServerAddress } else { $null }
                splitTunneling = if ($connection.PSObject.Properties['SplitTunneling']) { [bool]$connection.SplitTunneling } else { $null }
                auth    = Get-VpnAuthMetadata -Connection $connection
                dnsSuffixes = Get-VpnDnsSuffixes -Connection $connection
                routes  = Get-VpnRoutes -Connection $connection
                lastStatus = Get-VpnLastStatus -Connection $connection
                source  = [ordered]@{
                    fromGetVpnConnection = $true
                    fromPhonebook       = $false
                }
            }

            $record.type = switch -Regex ($record.type) {
                '^ikev2$'     { 'IKEv2'; break }
                '^l2tp'       { 'L2TP'; break }
                '^pptp'       { 'PPTP'; break }
                '^sstp'       { 'SSTP'; break }
                '^automatic$' { 'Automatic'; break }
                default       { if ($record.type) { $record.type } else { 'Unknown' } }
            }

            $userPbk = Join-Path -Path $env:APPDATA -ChildPath 'Microsoft\Network\Connections\Pbk\rasphone.pbk'
            $programData = $env:ProgramData
            $machinePbk = if ($programData) { Join-Path -Path $programData -ChildPath 'Microsoft\Network\Connections\Pbk\rasphone.pbk' } else { 'C:\\ProgramData\\Microsoft\\Network\\Connections\\Pbk\\rasphone.pbk' }

            if ($record.name) {
                if (Test-VpnPhonebookContainsConnection -Name $record.name -Path $userPbk) {
                    $record.source.fromPhonebook = $true
                } elseif (Test-VpnPhonebookContainsConnection -Name $record.name -Path $machinePbk) {
                    $record.source.fromPhonebook = $true
                }
            }

            $results += $record
        }
    }

    if ($results.Count -gt 1) {
        $unique = @{}
        foreach ($item in $results) {
            $key = if ($item.guid) { $item.guid.ToLowerInvariant() } elseif ($item.name) { $item.name.ToLowerInvariant() } else { [guid]::NewGuid().ToString() }
            if (-not $unique.ContainsKey($key)) {
                $unique[$key] = $item
            }
        }
        return $unique.Values
    }

    return $results
}

function Get-VpnNetworkInterfaces {
    $interfaces = @()

    try {
        $adapters = Get-NetAdapter -ErrorAction Stop
    } catch {
        $adapters = @()
    }

    foreach ($adapter in (ConvertTo-VpnArray -Value $adapters)) {
        if (-not $adapter) { continue }
        $interfaceIndex = $null
        if ($adapter.PSObject.Properties['InterfaceIndex']) {
            $interfaceIndex = [int]$adapter.InterfaceIndex
        } elseif ($adapter.PSObject.Properties['IfIndex']) {
            $interfaceIndex = [int]$adapter.IfIndex
        }

        $name = if ($adapter.PSObject.Properties['Name']) { [string]$adapter.Name } else { $null }
        $status = if ($adapter.PSObject.Properties['Status']) { [string]$adapter.Status } else { $null }

        $ipv4 = @()
        $ipv6 = @()
        $dnsServers = @()

        if ($name) {
            try {
                $config = Get-NetIPConfiguration -InterfaceAlias $name -ErrorAction Stop
                if ($config) {
                    foreach ($ipv4Entry in (ConvertTo-VpnArray -Value $config.IPv4Address)) {
                        if ($ipv4Entry -and $ipv4Entry.PSObject.Properties['IPAddress']) {
                            $ipv4 += [string]$ipv4Entry.IPAddress
                        }
                    }
                    foreach ($ipv6Entry in (ConvertTo-VpnArray -Value $config.IPv6Address)) {
                        if ($ipv6Entry -and $ipv6Entry.PSObject.Properties['IPAddress']) {
                            $ipv6 += [string]$ipv6Entry.IPAddress
                        }
                    }
                    if ($config.DnsServer -and $config.DnsServer.ServerAddresses) {
                        foreach ($dns in (ConvertTo-VpnArray -Value $config.DnsServer.ServerAddresses)) {
                            if ($dns) { $dnsServers += [string]$dns }
                        }
                    }
                }
            } catch {
            }
        }

        $interfaces += [ordered]@{
            ifIndex    = $interfaceIndex
            name       = $name
            status     = $status
            ipv4       = ($ipv4 | Where-Object { $_ })
            ipv6       = ($ipv6 | Where-Object { $_ })
            dnsServers = (($dnsServers | Where-Object { $_ }) | Select-Object -Unique)
        }
    }

    return $interfaces
}

function Get-VpnActiveRoutes {
    $routes = @()

    try {
        $netRoutes = Get-NetRoute -ErrorAction Stop | Where-Object { $_.State -eq 'Active' }
        foreach ($route in (ConvertTo-VpnArray -Value $netRoutes)) {
            if (-not $route) { continue }
            $destination = if ($route.PSObject.Properties['DestinationPrefix']) { [string]$route.DestinationPrefix } else { $null }
            $nextHop = if ($route.PSObject.Properties['NextHop']) { [string]$route.NextHop } else { $null }
            $interfaceAlias = if ($route.PSObject.Properties['InterfaceAlias']) { [string]$route.InterfaceAlias } else { $null }
            if ($destination) {
                $routes += [ordered]@{
                    destination = $destination
                    nexthop     = $nextHop
                    interface   = $interfaceAlias
                }
            }
        }
    } catch {
    }

    return $routes
}

function Get-VpnEffectiveDnsServers {
    param(
        [Parameter(Mandatory)]
        $Interfaces
    )

    $servers = New-Object System.Collections.Generic.List[string]
    foreach ($interface in $Interfaces) {
        if (-not $interface) { continue }
        foreach ($server in (ConvertTo-VpnArray -Value $interface.dnsServers)) {
            if ($server -and -not $servers.Contains($server)) {
                $servers.Add($server) | Out-Null
            }
        }
    }
    return $servers.ToArray()
}

function Get-VpnCertificates {
    $results = @()
    $stores = @(
        @{ Name = 'LocalMachine\\My'; Path = 'Cert:\\LocalMachine\\My' },
        @{ Name = 'CurrentUser\\My';  Path = 'Cert:\\CurrentUser\\My' }
    )

    foreach ($store in $stores) {
        try {
            $certs = Get-ChildItem -Path $store.Path -ErrorAction Stop
        } catch {
            $certs = @()
        }

        foreach ($cert in (ConvertTo-VpnArray -Value $certs)) {
            if (-not $cert) { continue }
            $notBefore = $null
            $notAfter = $null
            try { $notBefore = ($cert.NotBefore.ToUniversalTime().ToString('o')) } catch { }
            try { $notAfter = ($cert.NotAfter.ToUniversalTime().ToString('o')) } catch { }

            $isExpired = $null
            try { $isExpired = ($cert.NotAfter -lt (Get-Date)) } catch { }

            $ekuClient = $false
            try {
                if ($cert.Extensions) {
                    foreach ($ext in $cert.Extensions) {
                        if ($ext -is [System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]) {
                            foreach ($oid in $ext.EnhancedKeyUsages) {
                                if ($oid.Value -eq '1.3.6.1.5.5.7.3.2') { $ekuClient = $true }
                            }
                        }
                    }
                }
                if ($cert.EnhancedKeyUsageList) {
                    foreach ($entry in $cert.EnhancedKeyUsageList) {
                        if ($entry.Value -eq '1.3.6.1.5.5.7.3.2') { $ekuClient = $true }
                    }
                }
            } catch {
            }

            $results += [ordered]@{
                store                   = $store.Name
                subject                 = [string]$cert.Subject
                thumbprint              = [string]$cert.Thumbprint
                notBeforeUtc            = $notBefore
                notAfterUtc             = $notAfter
                isExpired               = $isExpired
                intendedForClientAuth   = $ekuClient
            }
        }
    }

    return $results
}

function Sanitize-VpnEventMessage {
    param([string]$Message)

    if (-not $Message) { return $null }

    $text = $Message
    $text = $text -replace '(?i)(user(name)?\s*[:=]\s*)([^\s\\/]+)', '$1***'
    $text = $text -replace '(?i)(account\s*[:=]\s*)([^\s\\/]+)', '$1***'
    if ($text.Length -gt 200) {
        return $text.Substring(0,200)
    }
    return $text
}

function Get-VpnEvents {
    $events = @()
    $cutoff = (Get-Date).AddDays(-14)
    $channels = @(
        'Microsoft-Windows-RasClient/Operational',
        'Microsoft-Windows-RasMan/Operational',
        'Microsoft-Windows-IKE-EXT/Operational'
    )

    foreach ($channel in $channels) {
        try {
            $winEvents = Get-WinEvent -FilterHashtable @{ LogName = $channel; StartTime = $cutoff } -ErrorAction Stop -MaxEvents 200
        } catch {
            continue
        }

        foreach ($event in (ConvertTo-VpnArray -Value $winEvents)) {
            if (-not $event) { continue }
            $message = $null
            try { $message = $event.Message } catch { }
            $events += [ordered]@{
                timeCreatedUtc = if ($event.PSObject.Properties['TimeCreated']) { ($event.TimeCreated.ToUniversalTime().ToString('o')) } else { $null }
                provider       = if ($event.PSObject.Properties['ProviderName']) { [string]$event.ProviderName } else { $channel }
                level          = if ($event.PSObject.Properties['LevelDisplayName']) { [string]$event.LevelDisplayName } else { $null }
                eventId        = if ($event.PSObject.Properties['Id']) { [int]$event.Id } elseif ($event.PSObject.Properties['RecordId']) { [int]$event.RecordId } else { $null }
                message        = Sanitize-VpnEventMessage -Message $message
            }
        }
    }

    return $events
}

function Invoke-Main {
    $vpnOutputRoot = Resolve-CollectorOutputDirectory -RequestedPath (Join-Path -Path $OutputDirectory -ChildPath 'Vpn')

    $payload = [ordered]@{
        schemaVersion = '1.0'
        generatedUtc  = (Get-Date).ToUniversalTime().ToString('o')
        host          = Get-VpnHostInfo
        services      = [ordered]@{
            RasMan = Get-VpnServiceState -Name 'RasMan'
            IKEEXT = Get-VpnServiceState -Name 'IKEEXT'
        }
        connections   = Get-VpnConnectionRecords
        network       = [ordered]@{}
        certificates  = Get-VpnCertificates
    }

    $interfaces = Get-VpnNetworkInterfaces
    $payload.network.interfaces = $interfaces
    $payload.network.activeRoutes = Get-VpnActiveRoutes
    $payload.network.effectiveDnsServers = Get-VpnEffectiveDnsServers -Interfaces $interfaces

    $baselineResult = New-CollectorMetadata -Payload $payload
    $baselinePath = Export-CollectorResult -OutputDirectory $vpnOutputRoot -FileName 'vpn-baseline.json' -Data $baselineResult -Depth 6

    $events = Get-VpnEvents
    $eventsPath = $null
    if ($events -and $events.Count -gt 0) {
        $eventPayload = New-CollectorMetadata -Payload ([ordered]@{ events = $events })
        $eventsPath = Export-CollectorResult -OutputDirectory $vpnOutputRoot -FileName 'vpn-events.json' -Data $eventPayload -Depth 5
    }

    $paths = @($baselinePath)
    if ($eventsPath) { $paths += $eventsPath }
    Write-Output $paths
}

Invoke-Main
