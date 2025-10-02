<#!
.SYNOPSIS
    Collects core network diagnostics including IP configuration, routing table, netstat, and ARP cache.
#>
[CmdletBinding()]
param(
    [Parameter()]
    [string]$OutputDirectory = (Join-Path -Path (Split-Path -Parent $PSCommandPath) -ChildPath '..\\output')
)

. (Join-Path -Path $PSScriptRoot -ChildPath '..\\CollectorCommon.ps1')

function Get-IpConfiguration {
    return Invoke-CollectorNativeCommand -FilePath 'ipconfig.exe' -ArgumentList '/all' -SourceLabel 'ipconfig.exe'
}

function Get-RoutingTable {
    return Invoke-CollectorNativeCommand -FilePath 'route.exe' -ArgumentList 'print' -SourceLabel 'route.exe'
}

function Get-NetstatSnapshot {
    return Invoke-CollectorNativeCommand -FilePath 'netstat.exe' -ArgumentList '-ano' -SourceLabel 'netstat.exe'
}

function Get-ArpCache {
    return Invoke-CollectorNativeCommand -FilePath 'arp.exe' -ArgumentList '-a' -SourceLabel 'arp.exe'
}

function ConvertTo-NetworkCollectorArray {
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

function ConvertTo-NetworkProbeStringArray {
    param($Value)

    $items = New-Object System.Collections.Generic.List[string]
    foreach ($entry in (ConvertTo-NetworkCollectorArray $Value)) {
        if ($null -eq $entry) { continue }
        $text = [string]$entry
        if ([string]::IsNullOrWhiteSpace($text)) { continue }
        $candidate = $text.Trim()
        if (-not $items.Contains($candidate)) { $items.Add($candidate) | Out-Null }
    }

    return $items.ToArray()
}

function New-NetworkProbeDefinition {
    param(
        $Entry,
        [string]$DefaultType
    )

    if ($null -eq $Entry) { return $null }

    if ($Entry -is [string]) {
        $text = $Entry.Trim()
        if (-not $text) { return $null }
        if ($text -match '^(?i)https?://') {
            try { $uri = [System.Uri]$text } catch { $uri = $null }
            $host = if ($uri) { $uri.Host } else { $null }
            $allowed = if ($host) { @($host) } else { @() }
            return [pscustomobject]@{
                Name                 = $text
                Type                 = 'http'
                Url                  = $text
                ExpectHost           = $host
                AllowedRedirectHosts = $allowed
                TimeoutSeconds       = 5
            }
        }

        return [pscustomobject]@{
            Name       = $text
            Type       = 'dns'
            Query      = $text
            RecordType = 'A'
        }
    }

    $type = $null
    if ($Entry.PSObject -and $Entry.PSObject.Properties['Type'] -and $Entry.Type) {
        $type = [string]$Entry.Type
    } elseif ($DefaultType) {
        $type = $DefaultType
    }

    $normalizedType = $null
    if ($type) {
        $normalizedType = $type.Trim().ToLowerInvariant()
    }

    switch ($normalizedType) {
        'dns' {
            $query = $null
            if ($Entry.PSObject.Properties['Query'] -and $Entry.Query) {
                $query = [string]$Entry.Query
            } elseif ($Entry.PSObject.Properties['Target'] -and $Entry.Target) {
                $query = [string]$Entry.Target
            } elseif ($Entry.PSObject.Properties['Name'] -and $Entry.Name) {
                $query = [string]$Entry.Name
            }

            if ([string]::IsNullOrWhiteSpace($query)) { return $null }

            $recordType = 'A'
            if ($Entry.PSObject.Properties['RecordType'] -and $Entry.RecordType) {
                $recordType = [string]$Entry.RecordType
            }

            $definition = [ordered]@{
                Name       = if ($Entry.PSObject.Properties['Name'] -and $Entry.Name) { [string]$Entry.Name } else { $query }
                Type       = 'dns'
                Query      = $query
                RecordType = $recordType
            }

            if ($Entry.PSObject.Properties['Server'] -and $Entry.Server) {
                $definition['Server'] = [string]$Entry.Server
            }

            if ($Entry.PSObject.Properties['ExpectedSubnets'] -and $Entry.ExpectedSubnets) {
                $definition['ExpectedSubnets'] = ConvertTo-NetworkProbeStringArray $Entry.ExpectedSubnets
            } elseif ($Entry.PSObject.Properties['ExpectSubnets'] -and $Entry.ExpectSubnets) {
                $definition['ExpectedSubnets'] = ConvertTo-NetworkProbeStringArray $Entry.ExpectSubnets
            }

            if ($Entry.PSObject.Properties['ExpectedAddresses'] -and $Entry.ExpectedAddresses) {
                $definition['ExpectedAddresses'] = ConvertTo-NetworkProbeStringArray $Entry.ExpectedAddresses
            }

            return [pscustomobject]$definition
        }
        default {
            $url = $null
            if ($Entry.PSObject.Properties['Url'] -and $Entry.Url) {
                $url = [string]$Entry.Url
            } elseif ($Entry.PSObject.Properties['Target'] -and $Entry.Target) {
                $url = [string]$Entry.Target
            }

            if ([string]::IsNullOrWhiteSpace($url)) { return $null }

            $timeout = 5
            if ($Entry.PSObject.Properties['TimeoutSeconds'] -and $Entry.TimeoutSeconds) {
                try { $timeout = [int]$Entry.TimeoutSeconds } catch { $timeout = 5 }
            }

            $expectHost = $null
            foreach ($property in @('ExpectedHost','ExpectHost')) {
                if ($Entry.PSObject.Properties[$property] -and $Entry.$property) {
                    $expectHost = [string]$Entry.$property
                    break
                }
            }

            if (-not $expectHost) {
                try { $expectHost = ([System.Uri]$url).Host } catch { $expectHost = $null }
            }

            $allowed = @()
            foreach ($property in @('AllowedRedirectHosts','AllowRedirectHosts')) {
                if ($Entry.PSObject.Properties[$property] -and $Entry.$property) {
                    $allowed = ConvertTo-NetworkProbeStringArray $Entry.$property
                    break
                }
            }

            if (($allowed.Count -eq 0) -and $expectHost) { $allowed = @($expectHost) }

            $definition = [ordered]@{
                Name                 = if ($Entry.PSObject.Properties['Name'] -and $Entry.Name) { [string]$Entry.Name } else { $url }
                Type                 = 'http'
                Url                  = $url
                ExpectHost           = $expectHost
                AllowedRedirectHosts = $allowed
                TimeoutSeconds       = $timeout
            }

            foreach ($property in @('ExpectedStatus','ExpectStatus')) {
                if ($Entry.PSObject.Properties[$property] -and $Entry.$property) {
                    try { $definition['ExpectedStatus'] = [int]$Entry.$property } catch { }
                    break
                }
            }

            foreach ($property in @('ExpectContentPattern','ExpectedContentPattern')) {
                if ($Entry.PSObject.Properties[$property] -and $Entry.$property) {
                    $definition['ExpectContentPattern'] = [string]$Entry.$property
                    break
                }
            }

            return [pscustomobject]$definition
        }
    }
}

function ConvertTo-NetworkProbeDefinitionList {
    param(
        $Value,
        [string]$DefaultType
    )

    $definitions = New-Object System.Collections.Generic.List[object]
    foreach ($entry in (ConvertTo-NetworkCollectorArray $Value)) {
        $definition = New-NetworkProbeDefinition -Entry $entry -DefaultType $DefaultType
        if ($definition) { $definitions.Add($definition) | Out-Null }
    }

    return $definitions.ToArray()
}

function Get-NetworkProbeDefinitions {
    $candidatePaths = New-Object System.Collections.Generic.List[string]

    if ($env:AUTOHELPDESK_NETWORK_PROBES) {
        foreach ($part in ($env:AUTOHELPDESK_NETWORK_PROBES -split ';')) {
            if (-not [string]::IsNullOrWhiteSpace($part)) {
                $candidatePaths.Add($part.Trim()) | Out-Null
            }
        }
    }

    $candidatePaths.Add((Join-Path -Path $PSScriptRoot -ChildPath 'NetworkProbes.json')) | Out-Null
    $parent = Split-Path -Path $PSScriptRoot -Parent
    if ($parent) {
        $candidatePaths.Add((Join-Path -Path $parent -ChildPath 'NetworkProbes.json')) | Out-Null
    }

    $uniquePaths = $candidatePaths | Where-Object { $_ } | Select-Object -Unique
    foreach ($path in $uniquePaths) {
        if (-not (Test-Path -LiteralPath $path)) { continue }

        try {
            $content = Get-Content -Path $path -Raw -ErrorAction Stop
            if ([string]::IsNullOrWhiteSpace($content)) { continue }
            $json = $content | ConvertFrom-Json -ErrorAction Stop
        } catch {
            return [pscustomobject]@{
                Source = $path
                Error  = $_.Exception.Message
            }
        }

        $definitions = New-Object System.Collections.Generic.List[object]

        if ($json.PSObject -and $json.PSObject.Properties['Http']) {
            foreach ($item in (ConvertTo-NetworkProbeDefinitionList -Value $json.Http -DefaultType 'http')) {
                $definitions.Add($item) | Out-Null
            }
        }

        if ($json.PSObject -and $json.PSObject.Properties['Dns']) {
            foreach ($item in (ConvertTo-NetworkProbeDefinitionList -Value $json.Dns -DefaultType 'dns')) {
                $definitions.Add($item) | Out-Null
            }
        }

        if ($definitions.Count -eq 0) {
            foreach ($item in (ConvertTo-NetworkProbeDefinitionList -Value $json -DefaultType $null)) {
                $definitions.Add($item) | Out-Null
            }
        }

        return [pscustomobject]@{
            Source      = $path
            Definitions = $definitions.ToArray()
        }
    }

    return $null
}

function Get-DhcpOptionDetails {
    try {
        $adapters = Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration -Filter "IPEnabled = True" -ErrorAction Stop
    } catch {
        return @([pscustomobject]@{
            Source = 'Get-CimInstance Win32_NetworkAdapterConfiguration'
            Error  = $_.Exception.Message
        })
    }

    $results = New-Object System.Collections.Generic.List[object]

    foreach ($adapter in $adapters) {
        if (-not $adapter) { continue }

        $settingId = if ($adapter.PSObject.Properties['SettingID']) { [string]$adapter.SettingID } else { $null }
        $leaseObtained = $null
        if ($adapter.PSObject.Properties['DHCPLeaseObtained'] -and $adapter.DHCPLeaseObtained) {
            try { $leaseObtained = ([datetime]$adapter.DHCPLeaseObtained).ToString('o') } catch { $leaseObtained = [string]$adapter.DHCPLeaseObtained }
        }
        $leaseExpires = $null
        if ($adapter.PSObject.Properties['DHCPLeaseExpires'] -and $adapter.DHCPLeaseExpires) {
            try { $leaseExpires = ([datetime]$adapter.DHCPLeaseExpires).ToString('o') } catch { $leaseExpires = [string]$adapter.DHCPLeaseExpires }
        }

        $entry = [ordered]@{
            Description    = if ($adapter.PSObject.Properties['Description']) { [string]$adapter.Description } else { $null }
            Caption        = if ($adapter.PSObject.Properties['Caption']) { [string]$adapter.Caption } else { $null }
            InterfaceIndex = if ($adapter.PSObject.Properties['InterfaceIndex']) { $adapter.InterfaceIndex } else { $null }
            Index          = if ($adapter.PSObject.Properties['Index']) { $adapter.Index } else { $null }
            SettingId      = $settingId
            DhcpServer     = if ($adapter.PSObject.Properties['DHCPServer']) { [string]$adapter.DHCPServer } else { $null }
            LeaseObtained  = $leaseObtained
            LeaseExpires   = $leaseExpires
            DhcpOptions    = @{}
        }

        $options = [ordered]@{}
        if ($settingId) {
            $registryPath = "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces\\$settingId"
            if (Test-Path -LiteralPath $registryPath) {
                try {
                    $values = Get-ItemProperty -Path $registryPath -ErrorAction Stop
                    if ($values.PSObject.Properties['DhcpServer'] -and $values.DhcpServer) {
                        $options['ServerIdentifier'] = [string]$values.DhcpServer
                    }
                    if ($values.PSObject.Properties['DhcpDomain'] -and $values.DhcpDomain) {
                        $options['Domain'] = [string]$values.DhcpDomain
                    }
                    if ($values.PSObject.Properties['DhcpClassId'] -and $values.DhcpClassId) {
                        $options['VendorClass'] = [string]$values.DhcpClassId
                    }
                    if ($values.PSObject.Properties['DhcpIPAddress'] -and $values.DhcpIPAddress) {
                        $options['Address'] = [string]$values.DhcpIPAddress
                    }
                    if ($values.PSObject.Properties['DhcpDefaultGateway'] -and $values.DhcpDefaultGateway) {
                        $rawGateway = $values.DhcpDefaultGateway
                        if ($rawGateway -is [System.Collections.IEnumerable] -and -not ($rawGateway -is [string])) {
                            $options['Gateway'] = @($rawGateway | ForEach-Object { [string]$_ })
                        } else {
                            $options['Gateway'] = @([string]$rawGateway)
                        }
                    }
                } catch {
                    $options['ReadError'] = $_.Exception.Message
                }
            } else {
                $options['RegistryMissing'] = $true
            }
        }

        $entry.DhcpOptions = $options
        $results.Add([pscustomobject]$entry) | Out-Null
    }

    return $results.ToArray()
}

function Invoke-NetworkDnsProbe {
    param(
        $Definition
    )

    if (-not $Definition -or -not $Definition.PSObject.Properties['Query']) { return $null }

    $recordType = if ($Definition.PSObject.Properties['RecordType'] -and $Definition.RecordType) { [string]$Definition.RecordType } else { 'A' }
    $result = [ordered]@{
        Name       = if ($Definition.PSObject.Properties['Name'] -and $Definition.Name) { [string]$Definition.Name } else { [string]$Definition.Query }
        Type       = 'dns'
        Query      = [string]$Definition.Query
        RecordType = $recordType
        Definition = [pscustomobject]$Definition
        StartedAt  = (Get-Date).ToString('o')
    }

    if ($Definition.PSObject.Properties['Server'] -and $Definition.Server) {
        $result['Server'] = [string]$Definition.Server
    }

    $addresses = New-Object System.Collections.Generic.List[string]
    $cnames = New-Object System.Collections.Generic.List[string]
    $records = New-Object System.Collections.Generic.List[object]
    $success = $false
    $errorMessage = $null
    $lookupMethod = 'Resolve-DnsName'

    try {
        $parameters = @{ Name = $Definition.Query; ErrorAction = 'Stop' }
        if ($Definition.PSObject.Properties['RecordType'] -and $Definition.RecordType) { $parameters['Type'] = $Definition.RecordType }
        if ($Definition.PSObject.Properties['Server'] -and $Definition.Server) { $parameters['Server'] = $Definition.Server }
        $rawRecords = Resolve-DnsName @parameters

        foreach ($record in $rawRecords) {
            if (-not $record) { continue }
            $entry = [ordered]@{
                Name = if ($record.PSObject.Properties['Name']) { [string]$record.Name } else { $Definition.Query }
                Type = if ($record.PSObject.Properties['QueryType']) { [string]$record.QueryType } elseif ($record.PSObject.Properties['Type']) { [string]$record.Type } else { $recordType }
            }
            if ($record.PSObject.Properties['TTL']) { $entry['TTL'] = $record.TTL }
            if ($record.PSObject.Properties['IPAddress'] -and $record.IPAddress) {
                $ipText = [string]$record.IPAddress
                $entry['IPAddress'] = $ipText
                if (-not $addresses.Contains($ipText)) { $addresses.Add($ipText) | Out-Null }
            }
            if ($record.PSObject.Properties['NameHost'] -and $record.NameHost) {
                $hostText = [string]$record.NameHost
                $entry['NameHost'] = $hostText
                if (-not $cnames.Contains($hostText)) { $cnames.Add($hostText) | Out-Null }
            }
            $records.Add([pscustomobject]$entry) | Out-Null
        }

        $success = $true
    } catch {
        $errorMessage = $_.Exception.Message
        $lookupMethod = 'System.Net.Dns'

        try {
            $fallbackAddresses = [System.Net.Dns]::GetHostAddresses($Definition.Query)
            foreach ($address in $fallbackAddresses) {
                if (-not $address) { continue }
                $text = $address.ToString()
                if ([string]::IsNullOrWhiteSpace($text)) { continue }
                if (-not $addresses.Contains($text)) { $addresses.Add($text) | Out-Null }
            }
            if ($addresses.Count -gt 0) { $success = $true; $errorMessage = $null }
        } catch {
            if (-not $errorMessage) { $errorMessage = $_.Exception.Message }
        }
    }

    $result['LookupMethod'] = $lookupMethod
    $result['CompletedAt'] = (Get-Date).ToString('o')
    $result['Success'] = $success
    $result['Addresses'] = $addresses.ToArray()
    if ($cnames.Count -gt 0) { $result['CanonicalNames'] = $cnames.ToArray() }
    if ($records.Count -gt 0) { $result['Records'] = $records.ToArray() }
    if ($errorMessage) { $result['Error'] = $errorMessage }

    return [pscustomobject]$result
}

function Invoke-NetworkHttpProbe {
    param(
        $Definition
    )

    if (-not $Definition -or -not $Definition.PSObject.Properties['Url']) { return $null }

    $timeout = if ($Definition.PSObject.Properties['TimeoutSeconds'] -and $Definition.TimeoutSeconds) { [int]$Definition.TimeoutSeconds } else { 5 }
    $result = [ordered]@{
        Name                 = if ($Definition.PSObject.Properties['Name'] -and $Definition.Name) { [string]$Definition.Name } else { [string]$Definition.Url }
        Type                 = 'http'
        Url                  = [string]$Definition.Url
        ExpectHost           = if ($Definition.PSObject.Properties['ExpectHost'] -and $Definition.ExpectHost) { [string]$Definition.ExpectHost } else { $null }
        AllowedRedirectHosts = if ($Definition.PSObject.Properties['AllowedRedirectHosts'] -and $Definition.AllowedRedirectHosts) { ConvertTo-NetworkProbeStringArray $Definition.AllowedRedirectHosts } else { @() }
        Definition           = [pscustomobject]$Definition
        TimeoutSeconds       = $timeout
        StartedAt            = (Get-Date).ToString('o')
    }

    if (-not $result.ExpectHost) {
        try { $result.ExpectHost = ([System.Uri]$result.Url).Host } catch { }
    }

    if (($result.AllowedRedirectHosts.Count -eq 0) -and $result.ExpectHost) {
        $result.AllowedRedirectHosts = @($result.ExpectHost)
    }

    if ($Definition.PSObject.Properties['ExpectedStatus'] -and $Definition.ExpectedStatus) {
        try { $result['ExpectedStatus'] = [int]$Definition.ExpectedStatus } catch { }
    }

    if ($Definition.PSObject.Properties['ExpectContentPattern'] -and $Definition.ExpectContentPattern) {
        $result['ExpectContentPattern'] = [string]$Definition.ExpectContentPattern
    }

    $statusCode = $null
    $finalUrl = $null
    $bodyPreview = $null
    $headers = [ordered]@{}
    $success = $false
    $errorMessage = $null

    try {
        $invokeParameters = @{
            Uri                = $result.Url
            MaximumRedirection = 5
            TimeoutSec         = $timeout
            ErrorAction        = 'Stop'
        }

        try {
            $invokeCommand = Get-Command -Name Invoke-WebRequest -ErrorAction SilentlyContinue
            if ($invokeCommand -and $invokeCommand.Parameters.ContainsKey('UseBasicParsing')) {
                $invokeParameters['UseBasicParsing'] = $true
            }
        } catch { }

        $response = Invoke-WebRequest @invokeParameters
        if ($response.StatusCode) { $statusCode = [int]$response.StatusCode }

        if ($response.BaseResponse -and $response.BaseResponse.ResponseUri) {
            $finalUrl = $response.BaseResponse.ResponseUri.AbsoluteUri
        } elseif ($response.Headers -and $response.Headers['Location']) {
            $finalUrl = [string]$response.Headers['Location']
        }

        if ($response.Headers) {
            foreach ($key in $response.Headers.Keys) {
                if (-not $key) { continue }
                $headers[$key] = ($response.Headers[$key] -join ', ')
            }
        }

        if ($response.Content) {
            $text = [string]$response.Content
            if ($text.Length -gt 0) {
                $bodyPreview = if ($text.Length -gt 256) { $text.Substring(0,256) } else { $text }
            }
        }

        $success = $true
    } catch {
        $errorMessage = $_.Exception.Message
        if ($_.Exception.Response) {
            $resp = $_.Exception.Response
            try { $statusCode = [int]$resp.StatusCode } catch { }
            try {
                if ($resp.ResponseUri) {
                    $finalUrl = $resp.ResponseUri.AbsoluteUri
                }
            } catch { }
        }
    }

    if ($statusCode) { $result['StatusCode'] = $statusCode }
    if ($finalUrl) { $result['FinalUrl'] = $finalUrl }
    if ($result.FinalUrl) {
        try { $result['FinalHost'] = ([System.Uri]$result.FinalUrl).Host } catch { }
    }
    if ($headers.Count -gt 0) { $result['Headers'] = $headers }
    if ($bodyPreview) { $result['BodyPreview'] = $bodyPreview }
    if ($errorMessage) { $result['Error'] = $errorMessage }

    $result['Success'] = $success
    $result['CompletedAt'] = (Get-Date).ToString('o')

    return [pscustomobject]$result
}

function Invoke-NetworkProbes {
    $probeResult = [ordered]@{
        CapturedAt    = (Get-Date).ToString('o')
        Http          = @()
        Dns           = @()
        Errors        = @()
        Configuration = $null
    }

    $definitions = Get-NetworkProbeDefinitions
    if ($definitions -and $definitions.PSObject.Properties['Error']) {
        $probeResult.Errors = @([ordered]@{ Source = $definitions.Source; Error = $definitions.Error })
        return [pscustomobject]$probeResult
    }

    if ($definitions -and $definitions.Definitions -and $definitions.Definitions.Count -gt 0) {
        $probeResult.Configuration = [ordered]@{
            Source = $definitions.Source
            Targets = $definitions.Definitions
        }

        $httpResults = New-Object System.Collections.Generic.List[object]
        $dnsResults = New-Object System.Collections.Generic.List[object]

        foreach ($definition in $definitions.Definitions) {
            if (-not $definition) { continue }
            switch ($definition.Type) {
                'http' { $httpResults.Add((Invoke-NetworkHttpProbe -Definition $definition)) | Out-Null; continue }
                'dns'  { $dnsResults.Add((Invoke-NetworkDnsProbe -Definition $definition)) | Out-Null; continue }
            }
        }

        if ($httpResults.Count -gt 0) { $probeResult.Http = $httpResults.ToArray() }
        if ($dnsResults.Count -gt 0) { $probeResult.Dns = $dnsResults.ToArray() }

        if (($probeResult.Http.Count + $probeResult.Dns.Count) -eq 0) {
            $probeResult.Errors = @([ordered]@{ Source = $definitions.Source; Message = 'No probe definitions executed.' })
        }
    } else {
        $probeResult.Errors = @([ordered]@{ Source = 'Collect-Network'; Message = 'No network probe configuration discovered.' })
    }

    return [pscustomobject]$probeResult
}

function Invoke-Main {
    $payload = [ordered]@{
        IpConfig = Get-IpConfiguration
        Route    = Get-RoutingTable
        Netstat  = Get-NetstatSnapshot
        Arp      = Get-ArpCache
        DhcpOptions = Get-DhcpOptionDetails
    }

    $payload['ConnectivityProbes'] = Invoke-NetworkProbes

    $result = New-CollectorMetadata -Payload $payload
    $outputPath = Export-CollectorResult -OutputDirectory $OutputDirectory -FileName 'network.json' -Data $result -Depth 6
    Write-Output $outputPath
}

Invoke-Main
