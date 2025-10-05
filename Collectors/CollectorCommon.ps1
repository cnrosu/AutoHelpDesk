<#!
.SYNOPSIS
    Provides shared helper functions for collector scripts.
#>

if (-not (Get-Variable -Name 'CollectorCommonState' -Scope Global -ErrorAction SilentlyContinue)) {
    $Global:CollectorCommonState = [ordered]@{
        CimInstances     = @{}
        ServiceInventory = $null
    }
}

function Resolve-CollectorOutputDirectory {
    param(
        [Parameter(Mandatory)]
        [string]$RequestedPath
    )

    if (-not (Test-Path -Path $RequestedPath)) {
        $null = New-Item -Path $RequestedPath -ItemType Directory -Force
    }

    return (Resolve-Path -Path $RequestedPath).ProviderPath
}

function Test-CollectorResultHasError {
    param([object]$Value)

    if ($null -eq $Value) { return $false }

    try {
        $hasError = $Value.PSObject.Properties['Error'] -and $Value.PSObject.Properties['Source']
        if ($hasError) { return $true }
    } catch {
        return $false
    }

    return $false
}

function Get-CollectorOperatingSystem {
    param([switch]$ForceRefresh)

    $state = $Global:CollectorCommonState
    $key = 'Win32_OperatingSystem'

    if (-not $ForceRefresh -and $state.CimInstances.ContainsKey($key)) {
        return $state.CimInstances[$key]
    }

    try {
        $instance = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
        $state.CimInstances[$key] = $instance
        return $instance
    } catch {
        if ($state.CimInstances.ContainsKey($key)) {
            $null = $state.CimInstances.Remove($key)
        }

        return [PSCustomObject]@{
            Source = 'Win32_OperatingSystem'
            Error  = $_.Exception.Message
        }
    }
}

function Get-CollectorComputerSystem {
    param([switch]$ForceRefresh)

    $state = $Global:CollectorCommonState
    $key = 'Win32_ComputerSystem'

    if (-not $ForceRefresh -and $state.CimInstances.ContainsKey($key)) {
        return $state.CimInstances[$key]
    }

    try {
        $instance = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
        $state.CimInstances[$key] = $instance
        return $instance
    } catch {
        if ($state.CimInstances.ContainsKey($key)) {
            $null = $state.CimInstances.Remove($key)
        }

        return [PSCustomObject]@{
            Source = 'Win32_ComputerSystem'
            Error  = $_.Exception.Message
        }
    }
}

function Get-CollectorServiceInventory {
    param([switch]$ForceRefresh)

    $state = $Global:CollectorCommonState

    if (-not $ForceRefresh -and $state.ServiceInventory) {
        return $state.ServiceInventory
    }

    $inventory = [ordered]@{
        Items  = @()
        Errors = @()
        Source = $null
        Lookup = @{}
    }

    try {
        $items = Get-CimInstance -ClassName Win32_Service -ErrorAction Stop
        if ($items) {
            $inventory.Items = @($items)
            $inventory.Source = 'Win32_Service (CIM)'
        }
    } catch {
        $inventory.Errors += $_.Exception.Message
    }

    if (-not $inventory.Items -or $inventory.Items.Count -eq 0) {
        try {
            $items = Get-WmiObject -Class Win32_Service -ErrorAction Stop
            if ($items) {
                $inventory.Items = @($items)
                $inventory.Source = 'Win32_Service (WMI)'
            }
        } catch {
            $inventory.Errors += $_.Exception.Message
        }
    }

    if (-not $inventory.Items -or $inventory.Items.Count -eq 0) {
        try {
            $items = Get-Service -ErrorAction Stop
            if ($items) {
                $normalized = foreach ($service in $items) {
                    if (-not $service) { continue }

                    $status = if ($service.PSObject.Properties['Status']) { [string]$service.Status } else { $null }
                    $startType = if ($service.PSObject.Properties['StartType']) { [string]$service.StartType } else { $null }

                    [PSCustomObject]@{
                        Name        = [string]$service.Name
                        DisplayName = [string]$service.DisplayName
                        State       = $status
                        Status      = $status
                        StartMode   = $startType
                        StartType   = $startType
                        StartName   = $null
                        ServiceType = $null
                    }
                }

                $inventory.Items = @($normalized)
                $inventory.Source = 'Get-Service'
            }
        } catch {
            $inventory.Errors += $_.Exception.Message
        }
    }

    $lookup = @{}
    foreach ($item in $inventory.Items) {
        if (-not $item) { continue }
        $name = $null
        if ($item.PSObject.Properties['Name'] -and $item.Name) {
            $name = [string]$item.Name
        } elseif ($item.PSObject.Properties['ServiceName'] -and $item.ServiceName) {
            $name = [string]$item.ServiceName
        }

        if ($name) {
            $lookup[$name.ToLowerInvariant()] = $item
        }
    }

    $inventory.Lookup = $lookup
    $state.ServiceInventory = $inventory
    return $inventory
}

function Get-CollectorServiceByName {
    param(
        [Parameter(Mandatory)][string]$Name,
        [switch]$ForceRefresh
    )

    $inventory = Get-CollectorServiceInventory -ForceRefresh:$ForceRefresh
    $normalized = $Name.ToLowerInvariant()
    $service = $null

    if ($inventory.Lookup.ContainsKey($normalized)) {
        $service = $inventory.Lookup[$normalized]
    } else {
        $service = $inventory.Items | Where-Object {
            if (-not $_) { return $false }
            if ($_.PSObject.Properties['Name']) { return ([string]$_.Name).ToLowerInvariant() -eq $normalized }
            if ($_.PSObject.Properties['ServiceName']) { return ([string]$_.ServiceName).ToLowerInvariant() -eq $normalized }
            return $false
        } | Select-Object -First 1
    }

    return [PSCustomObject]@{
        Service = $service
        Errors  = $inventory.Errors
        Source  = $inventory.Source
    }
}

function Export-CollectorResult {
    param(
        [Parameter(Mandatory)]
        [string]$OutputDirectory,

        [Parameter(Mandatory)]
        [string]$FileName,

        [Parameter(Mandatory)]
        [object]$Data,

        [int]$Depth = 6
    )

    $resolved = Resolve-CollectorOutputDirectory -RequestedPath $OutputDirectory
    $path = Join-Path -Path $resolved -ChildPath $FileName
    $Data | ConvertTo-Json -Depth $Depth | Out-File -FilePath $path -Encoding UTF8
    return $path
}

function New-CollectorMetadata {
    param(
        [Parameter(Mandatory)]
        [object]$Payload
    )

    return [ordered]@{
        CollectedAt = (Get-Date).ToString('o')
        Payload     = $Payload
    }
}

function Invoke-CollectorNativeCommand {
    param(
        [Parameter(Mandatory)]
        [string]$FilePath,

        [string[]]$ArgumentList = @(),

        [string]$SourceLabel,

        [hashtable]$ErrorMetadata
    )

    try {
        return & $FilePath @ArgumentList 2>$null
    } catch {
        $metadata = [ordered]@{}

        if ($PSBoundParameters.ContainsKey('ErrorMetadata') -and $ErrorMetadata) {
            foreach ($key in $ErrorMetadata.Keys) {
                $metadata[$key] = $ErrorMetadata[$key]
            }
        } elseif ($PSBoundParameters.ContainsKey('SourceLabel') -and $SourceLabel) {
            $metadata['Source'] = $SourceLabel
        } else {
            $commandName = [System.IO.Path]::GetFileName($FilePath)
            if ($ArgumentList.Count -gt 0) {
                $commandName = "$commandName $($ArgumentList -join ' ')"
            }
            $metadata['Source'] = $commandName
        }

        $metadata['Error'] = $_.Exception.Message

        return [PSCustomObject]$metadata
    }
}
