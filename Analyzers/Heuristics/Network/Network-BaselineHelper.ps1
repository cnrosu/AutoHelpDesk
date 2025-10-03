<#!
.SYNOPSIS
    Shared helper functions for resolving corporate network baseline expectations.
#>

function ConvertTo-NetworkBaselineArray {
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

function ConvertTo-NetworkBaselineStringList {
    param($Value)

    $results = New-Object System.Collections.Generic.List[string]
    foreach ($item in (ConvertTo-NetworkBaselineArray $Value)) {
        if ($null -eq $item) { continue }
        try {
            $text = [string]$item
        } catch {
            $text = $item.ToString()
        }

        if ([string]::IsNullOrWhiteSpace($text)) { continue }
        $trimmed = $text.Trim()
        if (-not $results.Contains($trimmed)) {
            $results.Add($trimmed) | Out-Null
        }
    }

    return $results.ToArray()
}

function ConvertTo-NetworkBaselineIpv4Int {
    param([string]$Address)

    if ([string]::IsNullOrWhiteSpace($Address)) { return $null }

    $candidate = $Address.Trim()
    if (-not $candidate) { return $null }

    $candidate = $candidate.Split('%')[0]

    $ip = $null
    if (-not [System.Net.IPAddress]::TryParse($candidate, [ref]$ip)) { return $null }
    if ($ip.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork) { return $null }

    $bytes = $ip.GetAddressBytes()
    if ([System.BitConverter]::IsLittleEndian) { [Array]::Reverse($bytes) }

    return [System.BitConverter]::ToUInt32($bytes, 0)
}

function ConvertTo-NetworkBaselineSubnetSpec {
    param($Value)

    if ($null -eq $Value) { return $null }

    if ($Value -is [string]) {
        $text = $Value.Trim()
        if (-not $text) { return $null }

        if ($text -match '^\d+\.\d+\.\d+\.\d+/\d{1,2}$') {
            $parts = $text.Split('/')
            if ($parts.Count -ne 2) { return $null }
            $networkInt = ConvertTo-NetworkBaselineIpv4Int $parts[0]
            if ($null -eq $networkInt) { return $null }
            $prefix = [int]$parts[1]
            if ($prefix -lt 0 -or $prefix -gt 32) { return $null }

            return [pscustomobject]@{
                Type       = 'cidr'
                Text       = $text
                Network    = $parts[0]
                NetworkInt = $networkInt
                Prefix     = $prefix
            }
        }

        if ($text -match '^\d+\.\d+\.\d+\.\d+\s*-\s*\d+\.\d+\.\d+\.\d+$') {
            $rangeParts = $text -split '\s*-\s*'
            if ($rangeParts.Count -ne 2) { return $null }
            $startInt = ConvertTo-NetworkBaselineIpv4Int $rangeParts[0]
            $endInt = ConvertTo-NetworkBaselineIpv4Int $rangeParts[1]
            if ($null -eq $startInt -or $null -eq $endInt) { return $null }
            if ($endInt -lt $startInt) {
                $temp = $startInt
                $startInt = $endInt
                $endInt = $temp
            }

            return [pscustomobject]@{
                Type    = 'range'
                Text    = $text
                Start   = $rangeParts[0]
                End     = $rangeParts[1]
                StartInt = $startInt
                EndInt   = $endInt
            }
        }

        $ipInt = ConvertTo-NetworkBaselineIpv4Int $text
        if ($null -eq $ipInt) { return $null }

        return [pscustomobject]@{
            Type      = 'exact'
            Text      = $text
            Address   = $text
            AddressInt = $ipInt
        }
    }

    if ($Value.PSObject -and $Value.PSObject.Properties['Cidr'] -and $Value.Cidr) {
        return ConvertTo-NetworkBaselineSubnetSpec ([string]$Value.Cidr)
    }

    if ($Value.PSObject -and $Value.PSObject.Properties['Network'] -and $Value.PSObject.Properties['Prefix']) {
        $network = [string]$Value.Network
        $prefix = [int]$Value.Prefix
        if ([string]::IsNullOrWhiteSpace($network)) { return $null }
        return ConvertTo-NetworkBaselineSubnetSpec ("{0}/{1}" -f $network, $prefix)
    }

    $startProperty = $null
    foreach ($candidate in @('Start', 'StartAddress', 'RangeStart')) {
        if ($Value.PSObject.Properties[$candidate] -and $Value.$candidate) {
            $startProperty = $candidate
            break
        }
    }

    $endProperty = $null
    foreach ($candidate in @('End', 'EndAddress', 'RangeEnd')) {
        if ($Value.PSObject.Properties[$candidate] -and $Value.$candidate) {
            $endProperty = $candidate
            break
        }
    }

    if ($startProperty -and $endProperty) {
        $start = [string]$Value.$startProperty
        $end = [string]$Value.$endProperty
        if (-not [string]::IsNullOrWhiteSpace($start) -and -not [string]::IsNullOrWhiteSpace($end)) {
            return ConvertTo-NetworkBaselineSubnetSpec ("{0}-{1}" -f $start.Trim(), $end.Trim())
        }
    }

    if ($Value.PSObject -and $Value.PSObject.Properties['Address'] -and $Value.Address) {
        return ConvertTo-NetworkBaselineSubnetSpec ([string]$Value.Address)
    }

    return $null
}

function Test-NetworkBaselineIpv4Match {
    param(
        [string]$Address,
        $Subnets
    )

    $addressInt = ConvertTo-NetworkBaselineIpv4Int $Address
    if ($null -eq $addressInt) { return $false }

    foreach ($candidate in (ConvertTo-NetworkBaselineArray $Subnets)) {
        if (-not $candidate) { continue }
        $spec = if ($candidate.PSObject -and $candidate.PSObject.Properties['Type']) {
            $candidate
        } else {
            ConvertTo-NetworkBaselineSubnetSpec $candidate
        }

        if (-not $spec) { continue }

        switch ($spec.Type) {
            'cidr' {
                $prefix = [int]$spec.Prefix
                $networkInt = $spec.NetworkInt
                if ($null -eq $networkInt) { $networkInt = ConvertTo-NetworkBaselineIpv4Int $spec.Network }
                if ($null -eq $networkInt) { continue }

                if ($prefix -le 0) {
                    return $true
                } elseif ($prefix -ge 32) {
                    if ($addressInt -eq $networkInt) { return $true }
                } else {
                    $mask = ([uint32]0xFFFFFFFF -shl (32 - $prefix))
                    if (($addressInt -band $mask) -eq ($networkInt -band $mask)) { return $true }
                }
                continue
            }
            'range' {
                $startInt = $spec.StartInt
                if ($null -eq $startInt) { $startInt = ConvertTo-NetworkBaselineIpv4Int $spec.Start }
                $endInt = $spec.EndInt
                if ($null -eq $endInt) { $endInt = ConvertTo-NetworkBaselineIpv4Int $spec.End }
                if ($null -eq $startInt -or $null -eq $endInt) { continue }
                if ($startInt -le $addressInt -and $addressInt -le $endInt) { return $true }
                continue
            }
            'exact' {
                $expectedInt = $spec.AddressInt
                if ($null -eq $expectedInt) { $expectedInt = ConvertTo-NetworkBaselineIpv4Int $spec.Address }
                if ($null -eq $expectedInt) { continue }
                if ($expectedInt -eq $addressInt) { return $true }
                continue
            }
            default {
                $converted = ConvertTo-NetworkBaselineSubnetSpec $spec
                if ($converted -and (Test-NetworkBaselineIpv4Match -Address $Address -Subnets @($converted))) {
                    return $true
                }
            }
        }
    }

    return $false
}

function Test-NetworkBaselineHostMatch {
    param(
        [string]$Candidate,
        $Expected
    )

    if ([string]::IsNullOrWhiteSpace($Candidate)) { return $false }

    $normalizedCandidate = $Candidate.Trim().Split('%')[0]
    if (-not $normalizedCandidate) { return $false }
    $normalizedCandidate = $normalizedCandidate.ToLowerInvariant()

    foreach ($item in (ConvertTo-NetworkBaselineArray $Expected)) {
        if ($null -eq $item) { continue }
        $text = [string]$item
        if ([string]::IsNullOrWhiteSpace($text)) { continue }
        $normalizedExpected = $text.Trim().Split('%')[0].ToLowerInvariant()
        if ($normalizedExpected -eq $normalizedCandidate) { return $true }
    }

    return $false
}

function Get-NetworkBaselinePayload {
    param($Context)

    if (-not $Context -or -not $Context.Artifacts) { return $null }

    $candidates = @('network-baseline', 'corporate-network', 'dhcp-baseline', 'corporate-network-baseline')
    foreach ($candidate in $candidates) {
        foreach ($suffix in @('', '.json')) {
            $key = ($candidate + $suffix).ToLowerInvariant()
            if (-not $Context.Artifacts.ContainsKey($key)) { continue }

            $entries = $Context.Artifacts[$key]
            $list = @()
            if ($entries -is [System.Collections.IEnumerable] -and -not ($entries -is [string])) {
                foreach ($entry in $entries) { $list += $entry }
            } else {
                $list = @($entries)
            }

            foreach ($entry in $list) {
                if (-not $entry) { continue }
                if ($entry.PSObject.Properties['Data'] -and $entry.Data) {
                    $data = $entry.Data
                    if ($data.PSObject -and $data.PSObject.Properties['Error']) { continue }
                    if ($data.PSObject -and $data.PSObject.Properties['Payload'] -and $data.Payload) {
                        $payloadData = $data.Payload
                    } else {
                        $payloadData = $data
                    }

                    return [pscustomobject]@{
                        Data   = $payloadData
                        Source = if ($entry.PSObject.Properties['Path']) { [string]$entry.Path } else { $null }
                    }
                }
            }
        }
    }

    return $null
}

function Get-NetworkCorporateExpectations {
    param($Context)

    $baseline = Get-NetworkBaselinePayload -Context $Context
    if (-not $baseline -or -not $baseline.Data) { return $null }

    $node = $baseline.Data
    if ($node.PSObject -and $node.PSObject.Properties['Payload'] -and $node.Payload) {
        $node = $node.Payload
    }

    if ($node.PSObject -and $node.PSObject.Properties['CorporateNetworks'] -and $node.CorporateNetworks) {
        $node = $node.CorporateNetworks
    }

    $subnetSpecs = New-Object System.Collections.Generic.List[object]
    $serverList = New-Object System.Collections.Generic.List[string]
    $gatewayList = New-Object System.Collections.Generic.List[string]

    $nodesToProcess = @($node)
    if ($node.PSObject -and $node.PSObject.Properties['Dhcp'] -and $node.Dhcp) {
        $nodesToProcess += $node.Dhcp
    }

    foreach ($current in $nodesToProcess) {
        if (-not $current) { continue }

        foreach ($propertyName in @('CorporateSubnets','Subnets','Networks','DhcpScopes','Scopes','Ipv4Subnets','IPv4Subnets','Ranges')) {
            if (-not $current.PSObject.Properties[$propertyName]) { continue }
            foreach ($value in (ConvertTo-NetworkBaselineArray $current.$propertyName)) {
                $spec = ConvertTo-NetworkBaselineSubnetSpec $value
                if ($spec) { $subnetSpecs.Add($spec) | Out-Null }
            }
        }

        foreach ($propertyName in @('DhcpServers','Servers','CorporateDhcpServers','ServerAddresses')) {
            if (-not $current.PSObject.Properties[$propertyName]) { continue }
            foreach ($value in (ConvertTo-NetworkBaselineStringList $current.$propertyName)) {
                if (-not $serverList.Contains($value)) { $serverList.Add($value) | Out-Null }
            }
        }

        foreach ($propertyName in @('Gateways','DefaultGateways','CorporateGateways')) {
            if (-not $current.PSObject.Properties[$propertyName]) { continue }
            foreach ($value in (ConvertTo-NetworkBaselineStringList $current.$propertyName)) {
                if (-not $gatewayList.Contains($value)) { $gatewayList.Add($value) | Out-Null }
            }
        }
    }

    if ($subnetSpecs.Count -eq 0 -and $serverList.Count -eq 0 -and $gatewayList.Count -eq 0) { return $null }

    return [pscustomobject]@{
        Subnets     = $subnetSpecs.ToArray()
        DhcpServers = $serverList.ToArray()
        Gateways    = $gatewayList.ToArray()
        Source      = $baseline.Source
    }
}
