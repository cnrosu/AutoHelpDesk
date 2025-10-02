<#!
.SYNOPSIS
    Collects LLDP neighbor information using native cmdlets and lldpctl when present.
#>
[CmdletBinding()]
param(
    [Parameter()]
    [string]$OutputDirectory = (Join-Path -Path (Split-Path -Parent $PSCommandPath) -ChildPath '..\\output')
)

. (Join-Path -Path $PSScriptRoot -ChildPath '..\\CollectorCommon.ps1')

function ConvertTo-LldpTrimmedString {
    param($Value)

    if ($null -eq $Value) { return $null }

    $text = $Value
    if (-not ($text -is [string])) {
        try {
            $text = [string]$Value
        } catch {
            $text = $null
        }
    }

    if ($null -eq $text) { return $null }

    $trimmed = $text.Trim()
    if (-not $trimmed) { return $null }

    return $trimmed
}

function ConvertTo-LldpStringArray {
    param($Value)

    $results = [System.Collections.Generic.List[string]]::new()
    if ($null -eq $Value) { return $results.ToArray() }

    if ($Value -is [string]) {
        $item = ConvertTo-LldpTrimmedString $Value
        if ($item) { $results.Add($item) | Out-Null }
        return $results.ToArray()
    }

    if ($Value -is [System.Collections.IDictionary]) {
        foreach ($key in $Value.Keys) {
            foreach ($entry in ConvertTo-LldpStringArray $Value[$key]) {
                if ($entry) { $results.Add($entry) | Out-Null }
            }
        }
        return ($results | Select-Object -Unique)
    }

    if ($Value -is [System.Collections.IEnumerable] -and -not ($Value -is [string])) {
        foreach ($item in $Value) {
            foreach ($entry in ConvertTo-LldpStringArray $item) {
                if ($entry) { $results.Add($entry) | Out-Null }
            }
        }
        return ($results | Select-Object -Unique)
    }

    $converted = ConvertTo-LldpTrimmedString $Value
    if ($converted) { $results.Add($converted) | Out-Null }

    return $results.ToArray()
}

function ConvertTo-LldpPrimitiveMap {
    param($Value)

    if ($null -eq $Value) { return $null }

    if ($Value -is [string] -or $Value -is [ValueType]) { return $Value }

    if ($Value -is [System.Collections.IDictionary]) {
        $map = [ordered]@{}
        foreach ($key in $Value.Keys) {
            $map[[string]$key] = ConvertTo-LldpPrimitiveMap $Value[$key]
        }
        return $map
    }

    if ($Value -is [System.Collections.IEnumerable] -and -not ($Value -is [string])) {
        $list = [System.Collections.Generic.List[object]]::new()
        foreach ($item in $Value) {
            $list.Add((ConvertTo-LldpPrimitiveMap $item)) | Out-Null
        }
        return $list.ToArray()
    }

    if ($Value.PSObject) {
        $map = [ordered]@{}
        foreach ($prop in $Value.PSObject.Properties) {
            $map[$prop.Name] = ConvertTo-LldpPrimitiveMap $prop.Value
        }
        return $map
    }

    try {
        return [string]$Value
    } catch {
        return ($Value | Out-String).Trim()
    }
}

function ConvertTo-LldpObjectArray {
    param($Value)

    if ($null -eq $Value) { return @() }

    if ($Value -is [System.Collections.IEnumerable] -and -not ($Value -is [string]) -and -not ($Value -is [hashtable]) -and -not ($Value -is [System.Collections.IDictionary])) {
        $list = [System.Collections.Generic.List[object]]::new()
        foreach ($item in $Value) {
            $list.Add($item) | Out-Null
        }
        return $list.ToArray()
    }

    return @($Value)
}

function Get-LldpPropertyValue {
    param(
        $Object,
        [string[]]$Names
    )

    if ($null -eq $Object) { return $null }

    foreach ($name in $Names) {
        if ($Object -is [System.Collections.IDictionary]) {
            if ($Object.Contains($name)) {
                $value = $Object[$name]
                $text = ConvertTo-LldpTrimmedString $value
                if ($text) { return $text }
            }
        } elseif ($Object.PSObject -and $Object.PSObject.Properties[$name]) {
            $value = $Object.$name
            $text = ConvertTo-LldpTrimmedString $value
            if ($text) { return $text }
        }
    }

    return $null
}

function Get-LldpPropertyValues {
    param(
        $Object,
        [string[]]$Names
    )

    if ($null -eq $Object) { return @() }

    foreach ($name in $Names) {
        if ($Object -is [System.Collections.IDictionary]) {
            if ($Object.Contains($name)) {
                return ConvertTo-LldpStringArray $Object[$name]
            }
        } elseif ($Object.PSObject -and $Object.PSObject.Properties[$name]) {
            return ConvertTo-LldpStringArray $Object.$name
        }
    }

    return @()
}

function ConvertTo-NetAdapterLldpNeighbor {
    param($Entry)

    if (-not $Entry) { return $null }

    $alias = Get-LldpPropertyValue $Entry @('InterfaceAlias','Name','InterfaceName')
    $description = Get-LldpPropertyValue $Entry @('InterfaceDescription','Description')
    $systemName = Get-LldpPropertyValue $Entry @('NeighborSystemName','SystemName')
    $systemDescription = Get-LldpPropertyValue $Entry @('NeighborSystemDescription','SystemDescription')
    $portId = Get-LldpPropertyValue $Entry @('NeighborPortId','PortId')
    $portDescription = Get-LldpPropertyValue $Entry @('NeighborPortDescription','PortDescription')
    $chassisId = Get-LldpPropertyValue $Entry @('NeighborChassisId','ChassisId')
    $management = Get-LldpPropertyValues $Entry @('NeighborManagementAddress','NeighborManagementAddresses','ManagementAddress','ManagementAddresses')
    $capabilities = Get-LldpPropertyValues $Entry @('NeighborSystemCapabilities','SystemCapabilities')
    $mac = Get-LldpPropertyValue $Entry @('MacAddress','PermanentAddress','SourceMacAddress')

    $switchPort = if ($portDescription) { $portDescription } elseif ($portId) { $portId } else { $null }

    if (-not ($alias -or $systemName -or $switchPort -or $portId)) { return $null }

    return [pscustomobject]@{
        Interface           = $alias
        InterfaceDescription= $description
        LocalMacAddress     = $mac
        Source              = 'netadapter-lldpagent'
        SourceLabel         = 'Get-NetAdapterLldpAgent'
        SwitchName          = $systemName
        SwitchDescription   = $systemDescription
        SwitchPort          = $switchPort
        PortId              = $portId
        PortDescription     = $portDescription
        ChassisId           = $chassisId
        ManagementAddresses = $management
        Capabilities        = $capabilities
    }
}

function Get-NetAdapterLldpAgentData {
    $result = [ordered]@{
        Entries   = @()
        Neighbors = @()
        Error     = $null
    }

    try {
        Get-Command -Name 'Get-NetAdapterLldpAgent' -ErrorAction Stop | Out-Null
    } catch {
        $result.Error = 'Get-NetAdapterLldpAgent cmdlet not available on this system.'
        return [pscustomobject]$result
    }

    try {
        $data = Get-NetAdapterLldpAgent -ErrorAction Stop
    } catch {
        $result.Error = $_.Exception.Message
        return [pscustomobject]$result
    }

    $entries = [System.Collections.Generic.List[object]]::new()
    $neighbors = [System.Collections.Generic.List[object]]::new()

    foreach ($item in ConvertTo-LldpObjectArray $data) {
        if (-not $item) { continue }
        $entries.Add((ConvertTo-LldpPrimitiveMap $item)) | Out-Null
        $neighbor = ConvertTo-NetAdapterLldpNeighbor $item
        if ($neighbor) { $neighbors.Add($neighbor) | Out-Null }
    }

    $result.Entries = $entries.ToArray()
    $result.Neighbors = $neighbors.ToArray()
    return [pscustomobject]$result
}

function ConvertTo-LldpctlNeighbor {
    param(
        $Interface,
        [string]$SourceKey,
        [string]$CommandLabel
    )

    if (-not $Interface) { return $null }

    $name = Get-LldpPropertyValue $Interface @('name','ifname','interface')
    $description = Get-LldpPropertyValue $Interface @('descr','description')
    $mac = Get-LldpPropertyValue $Interface @('mac','mac-address')

    $chassisEntries = ConvertTo-LldpObjectArray (if ($Interface.PSObject -and $Interface.PSObject.Properties['chassis']) { $Interface.chassis } elseif ($Interface -is [System.Collections.IDictionary] -and $Interface.Contains('chassis')) { $Interface['chassis'] } else { $null })
    $primaryChassis = if ($chassisEntries.Count -gt 0) { $chassisEntries[0] } else { $null }

    $switchName = Get-LldpPropertyValue $primaryChassis @('name')
    $switchDescription = Get-LldpPropertyValue $primaryChassis @('descr','description')

    $chassisIdValue = $null
    if ($primaryChassis) {
        if ($primaryChassis -is [System.Collections.IDictionary] -and $primaryChassis.Contains('id')) {
            $chassisIdValue = $primaryChassis['id']
        } elseif ($primaryChassis.PSObject -and $primaryChassis.PSObject.Properties['id']) {
            $chassisIdValue = $primaryChassis.id
        }
    }

    $chassisId = $null
    if ($chassisIdValue) {
        if ($chassisIdValue -is [System.Collections.IDictionary]) {
            $chassisId = Get-LldpPropertyValue $chassisIdValue @('value','local','mac')
        } elseif ($chassisIdValue.PSObject) {
            $chassisId = Get-LldpPropertyValue $chassisIdValue @('value','local','mac')
        } else {
            $chassisId = ConvertTo-LldpTrimmedString $chassisIdValue
        }
    }

    $managementAddresses = if ($primaryChassis) {
        $addresses = @()
        foreach ($field in @('mgmt-ip','mgmt-ipv6','mgmt','management-address','management-addresses')) {
            $addresses += Get-LldpPropertyValues $primaryChassis @($field)
        }
        if ($addresses) { $addresses | Select-Object -Unique } else { @() }
    } else {
        @()
    }

    $capabilities = @()
    if ($primaryChassis) {
        $caps = ConvertTo-LldpObjectArray (if ($primaryChassis -is [System.Collections.IDictionary] -and $primaryChassis.Contains('capability')) { $primaryChassis['capability'] } elseif ($primaryChassis.PSObject -and $primaryChassis.PSObject.Properties['capability']) { $primaryChassis.capability } else { $null })
        foreach ($cap in $caps) {
            if (-not $cap) { continue }
            $type = Get-LldpPropertyValue $cap @('type','name')
            $enabled = $true
            $enabledValue = Get-LldpPropertyValue $cap @('enabled')
            if ($enabledValue) {
                $enabled = $enabledValue -match '^(?i)(true|on|1|enabled|yes)$'
            }
            if ($type -and $enabled) { $capabilities += $type }
        }
        if ($capabilities) { $capabilities = $capabilities | Select-Object -Unique }
    }

    $ports = ConvertTo-LldpObjectArray (if ($Interface -is [System.Collections.IDictionary] -and $Interface.Contains('port')) { $Interface['port'] } elseif ($Interface.PSObject -and $Interface.PSObject.Properties['port']) { $Interface.port } else { $null })
    $primaryPort = if ($ports.Count -gt 0) { $ports[0] } else { $null }

    $portIdNode = $null
    if ($primaryPort) {
        if ($primaryPort -is [System.Collections.IDictionary] -and $primaryPort.Contains('id')) {
            $portIdNode = $primaryPort['id']
        } elseif ($primaryPort.PSObject -and $primaryPort.PSObject.Properties['id']) {
            $portIdNode = $primaryPort.id
        }
    }

    $portId = $null
    if ($portIdNode) {
        if ($portIdNode -is [System.Collections.IDictionary]) {
            $portId = Get-LldpPropertyValue $portIdNode @('value','local','ifname')
        } elseif ($portIdNode.PSObject) {
            $portId = Get-LldpPropertyValue $portIdNode @('value','local','ifname')
        } else {
            $portId = ConvertTo-LldpTrimmedString $portIdNode
        }
    }

    $portDescription = Get-LldpPropertyValue $primaryPort @('descr','description')
    $switchPort = if ($portDescription) { $portDescription } elseif ($portId) { $portId } else { $null }

    if (-not ($name -or $switchName -or $switchPort -or $portId)) { return $null }

    return [pscustomobject]@{
        Interface           = $name
        InterfaceDescription= $description
        LocalMacAddress     = $mac
        Source              = $SourceKey
        SourceLabel         = $CommandLabel
        SwitchName          = $switchName
        SwitchDescription   = $switchDescription
        SwitchPort          = $switchPort
        PortId              = $portId
        PortDescription     = $portDescription
        ChassisId           = $chassisId
        ManagementAddresses = $managementAddresses
        Capabilities        = $capabilities
    }
}

function ConvertFrom-LldpctlJsonObject {
    param(
        $Object,
        [string]$SourceKey,
        [string]$CommandLabel
    )

    $neighbors = [System.Collections.Generic.List[object]]::new()
    if (-not $Object) { return $neighbors.ToArray() }

    $root = if ($Object.PSObject -and $Object.PSObject.Properties['lldp']) { $Object.lldp } else { $Object }
    $interfaces = $root
    foreach ($candidate in @('interface','interfaces','ports')) {
        if ($root -and $root.PSObject -and $root.PSObject.Properties[$candidate]) {
            $interfaces = $root.$candidate
            break
        } elseif ($root -is [System.Collections.IDictionary] -and $root.Contains($candidate)) {
            $interfaces = $root[$candidate]
            break
        }
    }

    foreach ($iface in ConvertTo-LldpObjectArray $interfaces) {
        $neighbor = ConvertTo-LldpctlNeighbor -Interface $iface -SourceKey $SourceKey -CommandLabel $CommandLabel
        if ($neighbor) { $neighbors.Add($neighbor) | Out-Null }
    }

    return $neighbors.ToArray()
}

function Invoke-LldpctlAttempt {
    param(
        [string]$FilePath,
        [string[]]$Arguments,
        [string]$SourceKey,
        [string]$CommandLabel,
        [string]$Format
    )

    $output = Invoke-CollectorNativeCommand -FilePath $FilePath -ArgumentList $Arguments -SourceLabel $CommandLabel
    if ($output -is [pscustomobject] -and $output.PSObject.Properties['Error']) {
        return [pscustomobject]@{
            Success         = $false
            Output          = $null
            Error           = $output.Error
            ParseError      = $null
            ParsedNeighbors = @()
            Format          = $Format
            Command         = $CommandLabel
        }
    }

    $text = if ($null -eq $output) { '' } elseif ($output -is [string[]]) { $output -join "`n" } else { [string]$output }
    $parseError = $null
    $neighbors = @()

    if ($Format -eq 'json' -and $text) {
        try {
            $json = $text | ConvertFrom-Json -ErrorAction Stop
            $neighbors = ConvertFrom-LldpctlJsonObject -Object $json -SourceKey $SourceKey -CommandLabel $CommandLabel
        } catch {
            $parseError = $_.Exception.Message
        }
    }

    return [pscustomobject]@{
        Success         = $true
        Output          = $text
        Error           = $null
        ParseError      = $parseError
        ParsedNeighbors = $neighbors
        Format          = $Format
        Command         = $CommandLabel
    }
}

function Get-LldpctlData {
    $attemptDefinitions = @(
        @{ File = 'lldpctl'; Arguments = @('-f','json'); SourceKey = 'lldpctl'; Label = 'lldpctl -f json'; Format = 'json' },
        @{ File = 'lldpcli'; Arguments = @('show','neighbors','-f','json'); SourceKey = 'lldpcli'; Label = 'lldpcli show neighbors -f json'; Format = 'json' },
        @{ File = 'lldpctl'; Arguments = @(); SourceKey = 'lldpctl'; Label = 'lldpctl'; Format = 'text' },
        @{ File = 'lldpcli'; Arguments = @('show','neighbors'); SourceKey = 'lldpcli'; Label = 'lldpcli show neighbors'; Format = 'text' }
    )

    $attemptSummaries = [System.Collections.Generic.List[object]]::new()
    $neighbors = @()
    $errors = [System.Collections.Generic.List[string]]::new()

    foreach ($attempt in $attemptDefinitions) {
        $result = Invoke-LldpctlAttempt -FilePath $attempt.File -Arguments $attempt.Arguments -SourceKey $attempt.SourceKey -CommandLabel $attempt.Label -Format $attempt.Format

        $summary = [ordered]@{
            Command    = $attempt.Label
            Success    = $result.Success
            Format     = $attempt.Format
        }
        if ($result.Output) { $summary['Output'] = $result.Output }
        if ($result.Error) { $summary['Error'] = $result.Error }
        if ($result.ParseError) { $summary['ParseError'] = $result.ParseError }
        $attemptSummaries.Add([pscustomobject]$summary) | Out-Null

        if ($result.Success -and $result.ParsedNeighbors -and $result.ParsedNeighbors.Count -gt 0) {
            $neighbors = $result.ParsedNeighbors
            break
        }

        if (-not $result.Success -and $result.Error) {
            $errors.Add([string]$result.Error) | Out-Null
        } elseif ($result.Success -and $result.ParseError) {
            $errors.Add([string]$result.ParseError) | Out-Null
        }
    }

    $error = $null
    if ($neighbors.Count -eq 0 -and $errors.Count -gt 0) {
        $error = $errors[0]
    }

    return [pscustomobject]@{
        Attempts  = $attemptSummaries.ToArray()
        Neighbors = $neighbors
        Error     = $error
    }
}

function Invoke-Main {
    $netAdapterData = Get-NetAdapterLldpAgentData
    $lldpctlData = Get-LldpctlData

    $neighbors = [System.Collections.Generic.List[object]]::new()
    foreach ($neighbor in $netAdapterData.Neighbors) { if ($neighbor) { $neighbors.Add($neighbor) | Out-Null } }
    foreach ($neighbor in $lldpctlData.Neighbors) { if ($neighbor) { $neighbors.Add($neighbor) | Out-Null } }

    $sources = [ordered]@{}
    $sources['NetAdapterLldpAgent'] = [ordered]@{
        Entries       = $netAdapterData.Entries
        NeighborCount = ($netAdapterData.Neighbors | Measure-Object).Count
    }
    if ($netAdapterData.Error) { $sources['NetAdapterLldpAgent']['Error'] = $netAdapterData.Error }

    $sources['Lldpctl'] = [ordered]@{
        Attempts      = $lldpctlData.Attempts
        NeighborCount = ($lldpctlData.Neighbors | Measure-Object).Count
    }
    if ($lldpctlData.Error) { $sources['Lldpctl']['Error'] = $lldpctlData.Error }

    $payload = [ordered]@{
        Sources   = $sources
        Neighbors = $neighbors.ToArray()
    }

    $result = New-CollectorMetadata -Payload $payload
    $outputPath = Export-CollectorResult -OutputDirectory $OutputDirectory -FileName 'lldp.json' -Data $result -Depth 6
    Write-Output $outputPath
}

Invoke-Main
