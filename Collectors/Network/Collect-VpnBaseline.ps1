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
    $os = Get-CollectorOperatingSystem
    if (-not (Test-CollectorResultHasError -Value $os)) {
        if ($os -and $os.PSObject.Properties['BuildNumber']) {
            $osBuild = [string]$os.BuildNumber
        } elseif ($os -and $os.PSObject.Properties['Version']) {
            $osBuild = [string]$os.Version
        }
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

    $result = Get-CollectorServiceByName -Name $Name
    $service = $result.Service

    if ($service) {
        return [ordered]@{
            StartType = if ($service.PSObject.Properties['StartMode']) { [string]$service.StartMode } elseif ($service.PSObject.Properties['StartType']) { [string]$service.StartType } else { $null }
            Status    = if ($service.PSObject.Properties['State']) { [string]$service.State } elseif ($service.PSObject.Properties['Status']) { [string]$service.Status } else { $null }
            Path      = if ($service.PSObject.Properties['PathName']) { [string]$service.PathName } else { $null }
        }
    }

    if ($result.Errors -and $result.Errors.Count -gt 0) {
        return [ordered]@{ Error = ($result.Errors -join '; ') }
    }

    try {
        $fallback = Get-Service -Name $Name -ErrorAction Stop
        return [ordered]@{
            StartType = if ($fallback.PSObject.Properties['StartType']) { [string]$fallback.StartType } else { $null }
            Status    = if ($fallback.PSObject.Properties['Status']) { [string]$fallback.Status } else { $null }
            Path      = $null
        }
    } catch {
        return [ordered]@{ Error = $_.Exception.Message }
    }
}

function ConvertTo-VpnArray {
    param($Value)

    if ($null -eq $Value) { return @() }
    if ($Value -is [string]) { return @($Value) }
    if ($Value -is [System.Collections.IEnumerable] -and -not ($Value -is [hashtable])) {
        $items = [System.Collections.Generic.List[object]]::new()
        foreach ($item in $Value) {
            $null = $items.Add($item)
        }
        return $items.ToArray()
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
    $routes = [System.Collections.Generic.List[string]]::new()

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
                $null = $routes.Add([string]$prefix)
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
        classlessRoutes = ($routes.ToArray() | Where-Object { $_ })
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
    $results = [System.Collections.Generic.List[object]]::new()

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

            $null = $results.Add($record)
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
        return [object[]]$unique.Values
    }

    return $results.ToArray()
}

function Get-VpnNetworkInterfaces {
    $interfaces = [System.Collections.Generic.List[object]]::new()

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

        $ipv4 = [System.Collections.Generic.List[string]]::new()
        $ipv6 = [System.Collections.Generic.List[string]]::new()
        $dnsServers = [System.Collections.Generic.List[string]]::new()

        if ($name) {
            try {
                $config = Get-NetIPConfiguration -InterfaceAlias $name -ErrorAction Stop
                if ($config) {
                    foreach ($ipv4Entry in (ConvertTo-VpnArray -Value $config.IPv4Address)) {
                        if ($ipv4Entry -and $ipv4Entry.PSObject.Properties['IPAddress']) {
                            $null = $ipv4.Add([string]$ipv4Entry.IPAddress)
                        }
                    }
                    foreach ($ipv6Entry in (ConvertTo-VpnArray -Value $config.IPv6Address)) {
                        if ($ipv6Entry -and $ipv6Entry.PSObject.Properties['IPAddress']) {
                            $null = $ipv6.Add([string]$ipv6Entry.IPAddress)
                        }
                    }
                    if ($config.DnsServer -and $config.DnsServer.ServerAddresses) {
                        foreach ($dns in (ConvertTo-VpnArray -Value $config.DnsServer.ServerAddresses)) {
                            if ($dns) { $null = $dnsServers.Add([string]$dns) }
                        }
                    }
                }
            } catch {
            }
        }

        $null = $interfaces.Add([ordered]@{
            ifIndex    = $interfaceIndex
            name       = $name
            status     = $status
            ipv4       = ($ipv4.ToArray() | Where-Object { $_ })
            ipv6       = ($ipv6.ToArray() | Where-Object { $_ })
            dnsServers = (($dnsServers.ToArray() | Where-Object { $_ }) | Select-Object -Unique)
        })
    }

    return $interfaces.ToArray()
}

function Get-VpnActiveRoutes {
    $routes = [System.Collections.Generic.List[object]]::new()

    try {
        $netRoutes = Get-NetRoute -ErrorAction Stop | Where-Object { $_.State -eq 'Active' }
        foreach ($route in (ConvertTo-VpnArray -Value $netRoutes)) {
            if (-not $route) { continue }
            $destination = if ($route.PSObject.Properties['DestinationPrefix']) { [string]$route.DestinationPrefix } else { $null }
            $nextHop = if ($route.PSObject.Properties['NextHop']) { [string]$route.NextHop } else { $null }
            $interfaceAlias = if ($route.PSObject.Properties['InterfaceAlias']) { [string]$route.InterfaceAlias } else { $null }
            if ($destination) {
                $null = $routes.Add([ordered]@{
                    destination = $destination
                    nexthop     = $nextHop
                    interface   = $interfaceAlias
                })
            }
        }
    } catch {
    }

    return $routes.ToArray()
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
    $results = [System.Collections.Generic.List[object]]::new()
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

            $null = $results.Add([ordered]@{
                store                   = $store.Name
                subject                 = [string]$cert.Subject
                thumbprint              = [string]$cert.Thumbprint
                notBeforeUtc            = $notBefore
                notAfterUtc             = $notAfter
                isExpired               = $isExpired
                intendedForClientAuth   = $ekuClient
            })
        }
    }

    return $results.ToArray()
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

function ConvertTo-VpnEventData {
    param($Event)

    if (-not $Event) { return $null }

    $xmlText = $null
    try {
        $xmlText = $Event.ToXml()
    } catch {
        return $null
    }

    if (-not $xmlText) { return $null }

    try {
        $doc = [xml]$xmlText
    } catch {
        return $null
    }

    $map = [ordered]@{}

    if ($doc.Event -and $doc.Event.EventData -and $doc.Event.EventData.Data) {
        foreach ($node in $doc.Event.EventData.Data) {
            if (-not $node) { continue }

            $name = $null
            try { $name = [string]$node.Name } catch { $name = $null }
            if (-not $name) {
                try { $name = [string]$node.GetAttribute('Name') } catch { $name = $null }
            }
            if (-not $name -and $node.Attributes) {
                foreach ($attr in $node.Attributes) {
                    if ($attr -and $attr.Name -eq 'Name') {
                        $name = [string]$attr.Value
                        break
                    }
                }
            }

            $value = $null
            if ($node.'#text') {
                $value = [string]$node.'#text'
            }
            if (-not $value) {
                try { $value = [string]$node.InnerText } catch { $value = $null }
            }

            if ($name) {
                $map[$name] = $value
            } elseif ($value) {
                $map[[string]::Format('Data{0}', $map.Count)] = $value
            }
        }
    }

    if ($doc.Event -and $doc.Event.UserData) {
        foreach ($child in $doc.Event.UserData.ChildNodes) {
            if (-not $child) { continue }
            foreach ($node in $child.ChildNodes) {
                if (-not $node) { continue }
                $name = $null
                try { $name = [string]$node.LocalName } catch { $name = $null }
                $value = $null
                try { $value = [string]$node.InnerText } catch { $value = $null }
                if ($name) {
                    $map[$name] = $value
                } elseif ($value) {
                    $map[[string]::Format('UserData{0}', $map.Count)] = $value
                }
            }
        }
    }

    if ($map.Count -eq 0) { return $null }

    return $map
}

function Get-VpnEvents {
    $events = [System.Collections.Generic.List[object]]::new()
    $cutoffLocal = (Get-Date).AddDays(-7)
    $cutoffUtc = $cutoffLocal.ToUniversalTime()

    $queries = @(
        @{ LogName = 'Microsoft-Windows-RasClient/Operational'; Provider = $null; EventIds = @(20227,20226) },
        @{ LogName = 'Microsoft-Windows-IKE/Operational';     Provider = $null; EventIds = @(4653,4654) },
        @{ LogName = 'Microsoft-Windows-IKE-EXT/Operational'; Provider = $null; EventIds = @(4653,4654) },
        @{ LogName = 'System';                                Provider = 'IKEEXT'; EventIds = @(4653,4654) }
    )

    $seen = New-Object System.Collections.Generic.HashSet[string]

    foreach ($query in $queries) {
        $filter = @{ LogName = $query.LogName; StartTime = $cutoffLocal; Id = $query.EventIds }
        if ($query.Provider) {
            $filter['ProviderName'] = $query.Provider
        }

        try {
            $winEvents = Get-WinEvent -FilterHashtable $filter -ErrorAction Stop -MaxEvents 200
        } catch {
            continue
        }

        foreach ($event in (ConvertTo-VpnArray -Value $winEvents)) {
            if (-not $event) { continue }

            $timeUtc = $null
            if ($event.PSObject.Properties['TimeCreated']) {
                try { $timeUtc = $event.TimeCreated.ToUniversalTime() } catch { $timeUtc = $event.TimeCreated }
            }

            if ($timeUtc -and $timeUtc -lt $cutoffUtc) { continue }

            $provider = $null
            if ($event.PSObject.Properties['ProviderName'] -and $event.ProviderName) {
                $provider = [string]$event.ProviderName
            } elseif ($query.Provider) {
                $provider = $query.Provider
            } else {
                $provider = $query.LogName
            }

            $eventId = $null
            if ($event.PSObject.Properties['Id']) {
                $eventId = [int]$event.Id
            } elseif ($event.PSObject.Properties['RecordId']) {
                $eventId = [int]$event.RecordId
            }

            $recordId = $null
            if ($event.PSObject.Properties['RecordId']) {
                $recordId = [long]$event.RecordId
            }

            $keyBuilder = [System.Text.StringBuilder]::new()
            if ($provider) { $null = $keyBuilder.Append($provider.ToLowerInvariant()) }
            $null = $keyBuilder.Append('|')
            if ($eventId) { $null = $keyBuilder.Append($eventId) }
            $null = $keyBuilder.Append('|')
            if ($timeUtc) { $null = $keyBuilder.Append($timeUtc.ToString('o')) }
            if ($recordId) { $null = $keyBuilder.Append('|').Append($recordId) }
            $key = $keyBuilder.ToString()

            if ($seen.Contains($key)) { continue }
            $seen.Add($key) | Out-Null

            $message = $null
            try { $message = $event.Message } catch { }

            $eventData = ConvertTo-VpnEventData -Event $event

            $null = $events.Add([ordered]@{
                timeCreatedUtc = if ($timeUtc) { $timeUtc.ToString('o') } else { $null }
                provider       = $provider
                level          = if ($event.PSObject.Properties['LevelDisplayName']) { [string]$event.LevelDisplayName } else { $null }
                eventId        = $eventId
                recordId       = $recordId
                message        = Sanitize-VpnEventMessage -Message $message
                eventData      = $eventData
            })
        }
    }

    return $events.ToArray()
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
