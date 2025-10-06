<#!
.SYNOPSIS
    Collects LLDP neighbor data from available utilities to map switch port connectivity.
.DESCRIPTION
    Invokes Windows PowerShell cmdlets (Get-NetAdapterLldpAgent) when available, along with cross-platform tools such as
    lldpctl and lldptool, to capture per-interface neighbor metadata. The collector normalizes the output into a unified
    structure and preserves raw command output for analyzers that need additional context.
#>
[CmdletBinding()]
param(
    [Parameter()]
    [string]$OutputDirectory = (Join-Path -Path (Split-Path -Parent $PSCommandPath) -ChildPath '..\\output')
)

. (Join-Path -Path $PSScriptRoot -ChildPath '..\\CollectorCommon.ps1')

function ConvertTo-LldpStringArray {
    param($Value)

    $results = New-Object System.Collections.Generic.List[string]

    $addValue = $null
    $addValue = {
        param($Input)

        if ($null -eq $Input) { return }

        if ($Input -is [string]) {
            $text = $Input.Trim()
            if ($text) { $results.Add($text) | Out-Null }
            return
        }

        if ($Input -is [ValueType]) {
            $results.Add($Input.ToString()) | Out-Null
            return
        }

        if ($Input -is [System.Collections.IEnumerable] -and -not ($Input -is [string])) {
            foreach ($item in $Input) { & $addValue $item }
            return
        }

        if ($Input.PSObject) {
            foreach ($name in @('Value','DisplayValue','Name','Address','Text')) {
                if ($Input.PSObject.Properties[$name]) {
                    & $addValue $Input.$name
                    return
                }
            }
        }

        $results.Add([string]$Input) | Out-Null
    }

    & $addValue $Value
    return $results.ToArray()
}

function Get-FirstPropertyValue {
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

function Get-LldpCmdletData {
    $command = Get-Command -Name 'Get-NetAdapterLldpAgent' -ErrorAction SilentlyContinue
    if (-not $command) { return $null }

    try {
        $records = Get-NetAdapterLldpAgent -ErrorAction Stop
    } catch {
        return [pscustomobject]@{
            Source = 'Get-NetAdapterLldpAgent'
            Error  = $_.Exception.Message
        }
    }

    $neighbors = New-Object System.Collections.Generic.List[object]
    $rawRecords = New-Object System.Collections.Generic.List[object]

    foreach ($record in $records) {
        if (-not $record) { continue }

        $raw = [ordered]@{}
        if ($record.PSObject) {
            foreach ($prop in $record.PSObject.Properties) {
                if ($prop -and $prop.Name) {
                    $raw[$prop.Name] = $prop.Value
                }
            }
        }
        $rawRecords.Add([pscustomobject]$raw) | Out-Null

        $neighbor = [ordered]@{
            Source                     = 'Get-NetAdapterLldpAgent'
            InterfaceAlias             = [string](Get-FirstPropertyValue -InputObject $record -PropertyNames @('InterfaceAlias','Name','InterfaceName','Interface'))
            InterfaceDescription       = [string](Get-FirstPropertyValue -InputObject $record -PropertyNames @('InterfaceDescription','Description'))
            LocalMacAddress            = [string](Get-FirstPropertyValue -InputObject $record -PropertyNames @('MacAddress','LocalMacAddress','InterfaceMacAddress'))
            NeighborChassisId          = [string](Get-FirstPropertyValue -InputObject $record -PropertyNames @('ChassisId','PeerChassisId'))
            NeighborChassisIdType      = [string](Get-FirstPropertyValue -InputObject $record -PropertyNames @('ChassisIdSubtype','PeerChassisIdType'))
            NeighborPortId             = [string](Get-FirstPropertyValue -InputObject $record -PropertyNames @('PortId','PeerPortId'))
            NeighborPortIdType         = [string](Get-FirstPropertyValue -InputObject $record -PropertyNames @('PortIdSubtype','PeerPortIdType'))
            NeighborPortDescription    = [string](Get-FirstPropertyValue -InputObject $record -PropertyNames @('PortDescription','PeerPortDescription'))
            NeighborSystemName         = [string](Get-FirstPropertyValue -InputObject $record -PropertyNames @('SystemName','PeerSystemName'))
            NeighborSystemDescription  = [string](Get-FirstPropertyValue -InputObject $record -PropertyNames @('SystemDescription','PeerSystemDescription'))
            NeighborManagementAddresses = ConvertTo-LldpStringArray (Get-FirstPropertyValue -InputObject $record -PropertyNames @('ManagementAddresses','PeerManagementAddress','PeerManagementAddresses'))
            NeighborCapabilities       = ConvertTo-LldpStringArray (Get-FirstPropertyValue -InputObject $record -PropertyNames @('Capability','Capabilities','SystemCapabilities','PeerCapability','PeerCapabilities'))
            Timestamp                  = [string](Get-FirstPropertyValue -InputObject $record -PropertyNames @('LastUpdate','LastSeen'))
        }

        $neighbors.Add([pscustomobject]$neighbor) | Out-Null
    }

    return [pscustomobject]@{
        Source     = 'Get-NetAdapterLldpAgent'
        Neighbors  = $neighbors.ToArray()
        RawRecords = $rawRecords.ToArray()
    }
}

function Parse-LldpctlKeyValue {
    param([string[]]$Lines)

    $interfaceMap = @{}

    foreach ($line in $Lines) {
        if (-not $line) { continue }
        $trimmed = $line.Trim()
        if (-not $trimmed) { continue }
        $parts = $trimmed.Split('=', 2)
        if ($parts.Count -lt 2) { continue }

        $key = $parts[0].Trim()
        $value = $parts[1].Trim()
        if (-not $key) { continue }

        $match = [regex]::Match($key, '^lldp\.([^\.]+)\.(.+)$')
        if (-not $match.Success) { continue }

        $iface = $match.Groups[1].Value
        $detailKey = $match.Groups[2].Value
        if (-not $interfaceMap.ContainsKey($iface)) {
            $interfaceMap[$iface] = [ordered]@{
                InterfaceAlias              = $iface
                Source                      = 'lldpctl'
                NeighborCapabilitiesRaw     = New-Object System.Collections.Generic.List[string]
                NeighborManagementAddresses = New-Object System.Collections.Generic.List[string]
                Vlans                       = @{}
                Raw                         = [ordered]@{}
            }
        }

        $entry = $interfaceMap[$iface]
        $entry.Raw[$detailKey] = $value

        switch -Regex ($detailKey) {
            '^chassis\.mac$'          { $entry['NeighborChassisId'] = $value }
            '^chassis\.id$'           { if (-not $entry.Contains('NeighborChassisId')) { $entry['NeighborChassisId'] = $value } }
            '^chassis\.name$'         { $entry['NeighborSystemName'] = $value }
            '^chassis\.descr$'        { $entry['NeighborSystemDescription'] = $value }
            '^chassis\.mgmt-ip$'      { if ($value) { $entry.NeighborManagementAddresses.Add($value) | Out-Null } }
            '^chassis\.mgmt\.'       { if ($value) { $entry.NeighborManagementAddresses.Add($value) | Out-Null } }
            '^chassis\.cap\.'        {
                if ($value) {
                    foreach ($cap in ($value -split ',')) {
                        $capTrim = $cap.Trim()
                        if ($capTrim) { $entry.NeighborCapabilitiesRaw.Add($capTrim) | Out-Null }
                    }
                }
            }
            '^port\.descr$'           { $entry['NeighborPortDescription'] = $value }
            '^port\.id$'              { $entry['NeighborPortId'] = $value }
            '^port\.id-subtype$'      { $entry['NeighborPortIdSubtype'] = $value }
            '^port\.ifname$'          { if (-not $entry.Contains('NeighborPortId')) { $entry['NeighborPortId'] = $value } }
            '^port\.ttl$'             { $entry['NeighborTtl'] = $value }
            '^local\.portid$'         { $entry['LocalPortId'] = $value }
            '^local\.chassisid$'      { $entry['LocalChassisId'] = $value }
            '^vlan\.([0-9]+)\.name$' {
                $vlanId = $Matches[1]
                $entry.Vlans[$vlanId] = $value
            }
        }
    }

    $neighbors = New-Object System.Collections.Generic.List[object]

    foreach ($iface in $interfaceMap.Keys) {
        $entry = $interfaceMap[$iface]
        $caps = ($entry.NeighborCapabilitiesRaw | Select-Object -Unique)
        $neighbor = [ordered]@{
            Source                     = 'lldpctl'
            InterfaceAlias             = $entry.InterfaceAlias
            LocalPortId                = $( if ($entry.Contains('LocalPortId')) { $entry['LocalPortId'] } else { $null } )
            LocalChassisId             = $( if ($entry.Contains('LocalChassisId')) { $entry['LocalChassisId'] } else { $null } )
            NeighborChassisId          = $( if ($entry.Contains('NeighborChassisId')) { $entry['NeighborChassisId'] } else { $null } )
            NeighborSystemName         = $( if ($entry.Contains('NeighborSystemName')) { $entry['NeighborSystemName'] } else { $null } )
            NeighborSystemDescription  = $( if ($entry.Contains('NeighborSystemDescription')) { $entry['NeighborSystemDescription'] } else { $null } )
            NeighborPortId             = $( if ($entry.Contains('NeighborPortId')) { $entry['NeighborPortId'] } else { $null } )
            NeighborPortIdSubtype      = $( if ($entry.Contains('NeighborPortIdSubtype')) { $entry['NeighborPortIdSubtype'] } else { $null } )
            NeighborPortDescription    = $( if ($entry.Contains('NeighborPortDescription')) { $entry['NeighborPortDescription'] } else { $null } )
            NeighborTtl                = $( if ($entry.Contains('NeighborTtl')) { $entry['NeighborTtl'] } else { $null } )
            NeighborCapabilities       = $caps
            NeighborManagementAddresses = ($entry.NeighborManagementAddresses | Select-Object -Unique)
            Vlans                      = $( if ($entry.Vlans.Keys.Count -gt 0) { $entry.Vlans } else { $null } )
            Raw                        = $entry.Raw
        }

        $neighbors.Add([pscustomobject]$neighbor) | Out-Null
    }

    return $neighbors.ToArray()
}

function Get-LldpctlData {
    $command = Get-Command -Name 'lldpctl' -ErrorAction SilentlyContinue
    if (-not $command) { return $null }

    $output = Invoke-CollectorNativeCommand -FilePath $command.Name -ArgumentList '-f','keyvalue' -SourceLabel 'lldpctl -f keyvalue'

    if ($output -is [pscustomobject] -and $output.PSObject.Properties['Error'] -and $output.Error) {
        return [pscustomobject]@{
            Source = 'lldpctl -f keyvalue'
            Error  = $output.Error
        }
    }

    $lines = ConvertTo-LldpStringArray $output
    $neighbors = Parse-LldpctlKeyValue -Lines $lines

    return [pscustomobject]@{
        Source    = 'lldpctl -f keyvalue'
        Lines     = $lines
        Neighbors = $neighbors
    }
}

function Invoke-VendorLldpUtilities {
    $results = New-Object System.Collections.Generic.List[object]
    $commands = @(
        @{ Name = 'lldptool'; Arguments = @('-n'); Label = 'lldptool -n' }
    )

    foreach ($command in $commands) {
        $info = Get-Command -Name $command.Name -ErrorAction SilentlyContinue
        if (-not $info) { continue }

        $output = Invoke-CollectorNativeCommand -FilePath $info.Name -ArgumentList $command.Arguments -SourceLabel $command.Label
        $record = [ordered]@{ Command = $command.Label }

        if ($output -is [pscustomobject] -and $output.PSObject.Properties['Error'] -and $output.Error) {
            $record['Error'] = $output.Error
        } else {
            $record['Lines'] = ConvertTo-LldpStringArray $output
        }

        $results.Add([pscustomobject]$record) | Out-Null
    }

    return $results.ToArray()
}

function Invoke-Main {
    $sources = [ordered]@{}
    $neighborList = New-Object System.Collections.Generic.List[object]

    $cmdletData = Get-LldpCmdletData
    if ($cmdletData) {
        $sources['Get-NetAdapterLldpAgent'] = $cmdletData
        if ($cmdletData.PSObject.Properties['Neighbors'] -and $cmdletData.Neighbors) {
            foreach ($neighbor in $cmdletData.Neighbors) {
                if ($neighbor) { $neighborList.Add($neighbor) | Out-Null }
            }
        }
    }

    $lldpctlData = Get-LldpctlData
    if ($lldpctlData) {
        $sources['lldpctl'] = $lldpctlData
        if ($lldpctlData.PSObject.Properties['Neighbors'] -and $lldpctlData.Neighbors) {
            foreach ($neighbor in $lldpctlData.Neighbors) {
                if ($neighbor) { $neighborList.Add($neighbor) | Out-Null }
            }
        }
    }

    $vendorData = Invoke-VendorLldpUtilities
    if ($vendorData -and $vendorData.Count -gt 0) {
        $sources['VendorUtilities'] = $vendorData
    }

    $payload = [ordered]@{
        schemaVersion = '1.0'
        generatedUtc  = (Get-Date).ToUniversalTime().ToString('o')
        neighbors     = $neighborList.ToArray()
    }

    if ($sources.Keys.Count -gt 0) {
        $payload['sources'] = $sources
    }

    $result = New-CollectorMetadata -Payload $payload
    $outputPath = Export-CollectorResult -OutputDirectory $OutputDirectory -FileName 'network-lldp.json' -Data $result -Depth 6
    Write-Output $outputPath
}

Invoke-Main
