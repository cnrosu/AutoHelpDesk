<#!
.SYNOPSIS
    Collects detailed Windows service state for core health analysis.
.DESCRIPTION
    Builds a normalized snapshot of Windows services with emphasis on the critical
    services referenced by AutoL1/Analyze-Diagnostics.ps1.  The snapshot includes
    both the complete service inventory and focused subsets for the crucial and
    legacy services evaluated by the analyzer.
#>
[CmdletBinding()]
param(
    [Parameter()]
    [string]$OutputDirectory = (Join-Path -Path (Split-Path -Parent $PSCommandPath) -ChildPath '..\output')
)

. (Join-Path -Path $PSScriptRoot -ChildPath '..\CollectorCommon.ps1')

$ServiceDefinitions = @(
    [pscustomobject]@{ Name = 'WSearch';            Display = 'Windows Search (WSearch)';                         Note = 'Outlook search depends on this.' },
    [pscustomobject]@{ Name = 'Dnscache';          Display = 'DNS Client (Dnscache)';                             Note = 'DNS resolution/cache for all apps.' },
    [pscustomobject]@{ Name = 'NlaSvc';            Display = 'Network Location Awareness (NlaSvc)';               Note = 'Network profile changes and detection.' },
    [pscustomobject]@{ Name = 'LanmanWorkstation'; Display = 'Workstation (LanmanWorkstation)';                   Note = 'SMB client for shares and printers.' },
    [pscustomobject]@{ Name = 'RpcSs';             Display = 'Remote Procedure Call (RPC) (RpcSs)';               Note = 'Core RPC runtime (do not disable).' },
    [pscustomobject]@{ Name = 'RpcEptMapper';      Display = 'RPC Endpoint Mapper (RpcEptMapper)';                Note = 'RPC endpoint directory.' },
    [pscustomobject]@{ Name = 'WinHttpAutoProxySvc'; Display = 'WinHTTP Auto Proxy (WinHttpAutoProxySvc)';        Note = 'WPAD/PAC resolution for system services.' },
    [pscustomobject]@{ Name = 'BITS';              Display = 'Background Intelligent Transfer Service (BITS)';    Note = 'Transfers for updates, antivirus, and Office.' },
    [pscustomobject]@{ Name = 'ClickToRunSvc';     Display = 'Office Click-to-Run (ClickToRunSvc)';               Note = 'Office servicing and repair.' }
)

$LegacyServiceNames = @('Dhcp','WlanSvc','LanmanServer','WinDefend')

function Normalize-ServiceStatus {
    param([string]$Status)

    if (-not $Status) { return 'unknown' }
    $trimmed = $Status.Trim()
    if (-not $trimmed) { return 'unknown' }

    $lower = $trimmed.ToLowerInvariant()
    switch ($lower) {
        'running' { return 'running' }
        'stopped' { return 'stopped' }
        'paused' { return 'other' }
        'pause pending' { return 'other' }
        'continue pending' { return 'other' }
        'start pending' { return 'other' }
        'stop pending' { return 'other' }
        default { return 'other' }
    }
}

function Normalize-ServiceStartType {
    param([string]$StartType)

    if (-not $StartType) { return 'unknown' }
    $trimmed = $StartType.Trim()
    if (-not $trimmed) { return 'unknown' }

    $lower = $trimmed.ToLowerInvariant()
    if ($lower -match 'automatic') {
        if ($lower -match 'delayed') { return 'automatic-delayed' }
        return 'automatic'
    }
    if ($lower -match 'manual') { return 'manual' }
    if ($lower -match 'disabled') { return 'disabled' }
    return 'other'
}

function Get-ServiceInventory {
    $inventory = Get-CollectorServiceInventory

    return [pscustomobject]@{
        Items  = if ($inventory.Items) { @($inventory.Items) } else { @() }
        Errors = if ($inventory.Errors) { @($inventory.Errors) } else { @() }
        Source = $inventory.Source
    }
}

function Get-ServiceRecord {
    param($Service)

    if (-not $Service) { return $null }

    $name = ''
    if ($Service.PSObject.Properties['Name']) { $name = [string]$Service.Name }
    elseif ($Service.PSObject.Properties['ServiceName']) { $name = [string]$Service.ServiceName }
    if (-not $name) { return $null }
    $name = $name.Trim()
    if (-not $name) { return $null }

    $displayName = ''
    if ($Service.PSObject.Properties['DisplayName']) { $displayName = [string]$Service.DisplayName }
    if ($displayName) { $displayName = ($displayName -replace "[\t\r\n]+", ' ').Trim() }

    $stateValue = ''
    if ($Service.PSObject.Properties['State']) { $stateValue = [string]$Service.State }
    elseif ($Service.PSObject.Properties['Status']) { $stateValue = [string]$Service.Status }
    elseif ($Service.PSObject.Properties['CurrentState']) { $stateValue = [string]$Service.CurrentState }
    if (-not $stateValue) { $stateValue = 'Unknown' }

    $startMode = ''
    if ($Service.PSObject.Properties['StartMode']) { $startMode = [string]$Service.StartMode }
    elseif ($Service.PSObject.Properties['StartType']) { $startMode = [string]$Service.StartType }

    $delayed = $false
    if ($Service.PSObject.Properties['DelayedAutoStart']) {
        try { $delayed = [bool]$Service.DelayedAutoStart } catch { $delayed = $false }
    }

    $startDisplay = 'Unknown'
    if ($startMode) {
        $modeLower = $startMode.Trim().ToLowerInvariant()
        switch ($modeLower) {
            { $_ -like 'auto*' } {
                if ($delayed) { $startDisplay = 'Automatic (Delayed Start)' }
                else { $startDisplay = 'Automatic' }
                break
            }
            'manual' {
                $startDisplay = 'Manual'
                break
            }
            'disabled' {
                $startDisplay = 'Disabled'
                break
            }
            default {
                $startDisplay = $startMode.Trim()
            }
        }
    }

    $rawLine = "{0}`t{1}`t{2}`t{3}" -f $name, $stateValue, $startDisplay, $displayName

    return [pscustomobject]@{
        Name                  = $name
        DisplayName           = $displayName
        Status                = $stateValue
        NormalizedStatus      = Normalize-ServiceStatus $stateValue
        StartType             = $startDisplay
        NormalizedStartType   = Normalize-ServiceStartType $startDisplay
        Raw                   = $rawLine
        StartModeRaw          = if ($startMode) { $startMode.Trim() } else { '' }
        DelayedAutoStart      = $delayed
    }
}

function Get-ServiceRecords {
    param([object[]]$Inventory)

    $records = [System.Collections.Generic.List[pscustomobject]]::new()
    foreach ($service in $Inventory) {
        $record = Get-ServiceRecord -Service $service
        if ($record) { $null = $records.Add($record) }
    }
    $recordsArray = $records.ToArray()
    return $recordsArray | Sort-Object -Property Name
}

function Get-RecordLookup {
    param([object[]]$Records)

    $map = @{}
    foreach ($record in $Records) {
        if (-not $record.Name) { continue }
        $map[$record.Name] = $record
    }
    return $map
}

function Get-CriticalServiceSnapshot {
    param(
        [hashtable]$Lookup,
        [object[]]$Definitions
    )

    $snapshot = [System.Collections.Generic.List[pscustomobject]]::new()
    foreach ($definition in $Definitions) {
        $name = $definition.Name
        $display = $definition.Display
        $note = $definition.Note
        $record = $null
        if ($name -and $Lookup.ContainsKey($name)) {
            $record = $Lookup[$name]
        }

        $null = $snapshot.Add([pscustomobject]@{
            Name                = $name
            Display             = $display
            Note                = $note
            Status              = if ($record) { $record.Status } else { 'Not Found' }
            NormalizedStatus    = if ($record) { $record.NormalizedStatus } else { 'missing' }
            StartType           = if ($record) { $record.StartType } else { 'Unknown' }
            NormalizedStartType = if ($record) { $record.NormalizedStartType } else { 'unknown' }
            Raw                 = if ($record) { $record.Raw } else { $null }
        })
    }
    return $snapshot.ToArray()
}

function Get-LegacyServiceSnapshot {
    param(
        [hashtable]$Lookup,
        [string[]]$Names
    )

    $snapshot = [System.Collections.Generic.List[pscustomobject]]::new()
    foreach ($name in $Names) {
        if (-not $name) { continue }
        $record = $null
        if ($Lookup.ContainsKey($name)) { $record = $Lookup[$name] }

        $null = $snapshot.Add([pscustomobject]@{
            Name             = $name
            Status           = if ($record) { $record.Status } else { 'Not Found' }
            NormalizedStatus = if ($record) { $record.NormalizedStatus } else { 'missing' }
            Raw              = if ($record) { $record.Raw } else { $null }
        })
    }
    return $snapshot.ToArray()
}

function Invoke-Main {
    $inventoryResult = Get-ServiceInventory
    $records = Get-ServiceRecords -Inventory $inventoryResult.Items
    $lookup = Get-RecordLookup -Records $records

    $payload = [ordered]@{
        Services             = $records
        CriticalServices     = Get-CriticalServiceSnapshot -Lookup $lookup -Definitions $ServiceDefinitions
        LegacyCoreServices   = Get-LegacyServiceSnapshot -Lookup $lookup -Names $LegacyServiceNames
    }

    if ($inventoryResult.Errors -and $inventoryResult.Errors.Count -gt 0) {
        $payload['CollectionErrors'] = $inventoryResult.Errors
    }

    $result = New-CollectorMetadata -Payload $payload
    $outputPath = Export-CollectorResult -OutputDirectory $OutputDirectory -FileName 'service-baseline.json' -Data $result -Depth 6
    Write-Output $outputPath
}

Invoke-Main
