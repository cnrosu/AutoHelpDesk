<#!
.SYNOPSIS
    Shared helper functions for DHCP analyzers.
#>

function Get-DhcpCollectorPayload {
    param(
        [Parameter(Mandatory)]
        [string]$InputFolder,

        [Parameter(Mandatory)]
        [string]$FileName
    )

    $path = Join-Path -Path $InputFolder -ChildPath $FileName
    if (-not (Test-Path -Path $path)) { return $null }

    try {
        $text = Get-Content -Path $path -Raw -ErrorAction Stop
        $json = $text | ConvertFrom-Json -ErrorAction Stop
        return $json.Payload
    } catch {
        return [pscustomobject]@{ Error = $_.Exception.Message; File = $path }
    }
}

function Write-DhcpDebug {
    param(
        [Parameter(Mandatory)]
        [string]$Message,

        [hashtable]$Data
    )

    $source = 'Network/DHCP'
    $arguments = @{ Source = $source; Message = $Message }
    if ($PSBoundParameters.ContainsKey('Data') -and $Data) {
        $arguments['Data'] = $Data
    }

    if (Get-Command -Name Write-HeuristicDebug -ErrorAction SilentlyContinue) {
        Write-HeuristicDebug @arguments
    } else {
        $text = "DBG [{0}] {1}" -f $source, $Message
        if ($arguments.ContainsKey('Data')) {
            $detailEntries = $Data.GetEnumerator() | Sort-Object Name
            $details = [System.Collections.Generic.List[string]]::new()
            foreach ($entry in $detailEntries) {
                $null = $details.Add(("{0}={1}" -f $entry.Key, $entry.Value))
            }

            if ($details.Count -gt 0) { $text = "{0} :: {1}" -f $text, ($details -join '; ') }
        }
        Write-Host $text
    }
}

function ConvertFrom-Iso8601 {
    param([string]$Text)

    if (-not $Text) { return $null }

    $trimmed = $Text.Trim()
    if (-not $trimmed) { return $null }

    $result = [datetime]::MinValue
    if ([datetime]::TryParse($trimmed, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AssumeLocal, [ref]$result)) {
        return $result
    }

    try {
        return [datetime]::Parse($trimmed)
    } catch {
        return $null
    }
}

function Ensure-Array {
    param($Value)

    if ($null -eq $Value) { return @() }
    if ($Value -is [System.Collections.IEnumerable] -and -not ($Value -is [string])) {
        $out = @()
        foreach ($item in $Value) { if ($null -ne $item) { $out += $item } }
        return $out
    }
    return @($Value)
}

function Get-AdapterIdentity {
    param($Adapter)

    if ($null -eq $Adapter) { return 'Unknown adapter' }

    $parts = @()
    if ($Adapter.Description) { $parts += [string]$Adapter.Description }
    elseif ($Adapter.Caption) { $parts += [string]$Adapter.Caption }

    $indexValue = $null
    if ($Adapter.PSObject.Properties['InterfaceIndex'] -and $null -ne $Adapter.InterfaceIndex) {
        $indexValue = $Adapter.InterfaceIndex
    } elseif ($Adapter.PSObject.Properties['Index'] -and $null -ne $Adapter.Index) {
        $indexValue = $Adapter.Index
    }
    if ($null -ne $indexValue) {
        $parts += "Index $indexValue"
    }

    if ($Adapter.MACAddress) { $parts += "MAC $($Adapter.MACAddress)" }

    if (-not $parts) { return 'Unknown adapter' }
    return ($parts -join ' | ')
}

function Get-AdapterIpv4Addresses {
    param($Adapter)

    $addresses = @()
    $raw = $null
    if ($Adapter.PSObject.Properties['IPAddress']) { $raw = $Adapter.IPAddress }
    if (-not $raw) { return @() }

    foreach ($value in (Ensure-Array $raw)) {
        if ($value -match '^\s*$') { continue }
        $candidate = $value.Trim()
        if ($candidate -match '^\d+\.\d+\.\d+\.\d+$') {
            $addresses += $candidate
        }
    }

    return $addresses
}

function Test-IsPrivateIPv4 {
    param([string]$Address)

    if (-not $Address) { return $false }

    if ($Address -match '^10\.') { return $true }
    if ($Address -match '^192\.168\.') { return $true }
    if ($Address -match '^172\.(1[6-9]|2[0-9]|3[0-1])\.'){ return $true }
    return $false
}

function Test-IsApipaIPv4 {
    param([string]$Address)

    if (-not $Address) { return $false }
    return $Address -match '^169\.254\.'
}

function Format-StringList {
    param($Values)

    $array = Ensure-Array $Values
    $clean = $array | Where-Object { $_ -and $_.Trim() }
    if (-not $clean) { return '' }

    $trimmedValues = [System.Collections.Generic.List[string]]::new()
    foreach ($value in $clean) {
        $null = $trimmedValues.Add($value.Trim())
    }

    return ($trimmedValues -join ', ')
}

function New-DhcpFinding {
    param(
        [string]$Check,
        [string]$Severity,
        [string]$Message,
        [hashtable]$Evidence
    )

    return [pscustomobject]@{
        Category    = 'Network'
        Subcategory = 'DHCP'
        Check       = $Check
        Severity    = $Severity
        Message     = $Message
        Evidence    = $Evidence
    }
}
