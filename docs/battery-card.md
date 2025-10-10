# AutoHelpDesk – Battery Card

## Purpose
Compute battery metrics without parsing HTML:
- Current mAh (live)
- Full-charge mAh
- Design mWh (via Windows PowerShell 5.1 WMI fallback)
- Degradation %

## Severity Ladder (editable)
- <10%   -> info
- 10-20% -> low
- 20-30% -> medium
- >=30%  -> high

## Implementation
```powershell
function Get-AHD-BatteryMetrics {
    [CmdletBinding()]
    param()

    $ns = 'root\wmi'

    # Try live values via CIM (PS7-friendly)
    $status = Get-CimInstance -Namespace $ns -ClassName BatteryStatus -ErrorAction SilentlyContinue | Select-Object -First 1
    $full   = Get-CimInstance -Namespace $ns -ClassName BatteryFullChargedCapacity -ErrorAction SilentlyContinue | Select-Object -First 1

    if (-not $status -or -not $full) {
        throw "Battery classes not available in $ns. Ensure device has ACPI battery and WMI provider."
    }

    $voltage_mV = [double]$status.Voltage
    $rem_mWh    = [double]$status.RemainingCapacity
    $full_mWh   = [double]$full.FullChargedCapacity

    $rem_mAh  = if ($voltage_mV) { [math]::Round(($rem_mWh  * 1000) / $voltage_mV) } else { $null }
    $full_mAh = if ($voltage_mV) { [math]::Round(($full_mWh * 1000) / $voltage_mV) } else { $null }

    # Try to get DesignedCapacity (mWh). BatteryStaticData often fails on PS7 CIM,
    # so we shell out to Windows PowerShell 5.1 which uses the WMI v1 provider.
    $design_mWh = $null
    try {
        $design_mWh = powershell.exe -NoProfile -Command "Get-WmiObject -Namespace root\wmi -Class BatteryStaticData | Select-Object -Expand DesignedCapacity | Select-Object -First 1"
        if ($design_mWh -is [string] -and [string]::IsNullOrWhiteSpace($design_mWh)) { $design_mWh = $null }
        if ($design_mWh -ne $null) { $design_mWh = [double]$design_mWh }
    } catch {
        # leave $design_mWh = $null
    }

    $degradationPct = $null
    if ($design_mWh -and $full_mWh) {
        $degradationPct = [math]::Round((1 - ($full_mWh / $design_mWh)) * 100, 2)
    }

    # Also include a few useful live flags
    $charging = $false
    if ($status.PSObject.Properties.Name -contains 'Charging') {
        $charging = [bool]$status.Charging
    }

    [pscustomobject]@{
        InstanceName          = $status.InstanceName
        Voltage_mV            = $voltage_mV
        Remaining_mWh         = $rem_mWh
        FullCharge_mWh        = $full_mWh
        Remaining_mAh         = $rem_mAh
        FullCharge_mAh        = $full_mAh
        Design_mWh            = $design_mWh
        Degradation_Percent   = $degradationPct
        Charging              = $charging
        PowerOnline           = [bool]$status.PowerOnline
        Timestamp_Sys100NS    = $status.Timestamp_Sys100NS
    }
}

function Invoke-BatteryHealthHeuristic {
    [CmdletBinding()]
    param(
        [double] $LowThresholdPercent      = 10,  # >=10% becomes 'low'
        [double] $MediumThresholdPercent   = 20,  # >=20% becomes 'medium'
        [double] $HighThresholdPercent     = 30   # >=30% becomes 'high'
    )

    $data = $null
    $err  = $null
    try { $data = Get-AHD-BatteryMetrics } catch { $err = $_ }

    if ($err) {
        # Return an informational issue if we can’t read metrics
        return ,@{
            Title       = 'Battery health'
            Heuristic   = 'System/BatteryHealth'
            Severity    = 'info'
            Summary     = 'Battery metrics unavailable, so unplugged runtime cannot be evaluated.'
            Evidence    = "Failed to query WMI battery classes. Error: $($err.Exception.Message)"
            Data        = $null
            Remediation = 'Ensure ACPI battery device and WMI provider are present. On PS7, design capacity may require Windows PowerShell 5.1 WMI.'
        }
    }

    # Determine severity from degradation
    $severity = 'info'
    $degr = $data.Degradation_Percent
    if ($degr -ne $null) {
        if     ($degr -ge $HighThresholdPercent)   { $severity = 'high' }
        elseif ($degr -ge $MediumThresholdPercent) { $severity = 'medium' }
        elseif ($degr -ge $LowThresholdPercent)    { $severity = 'low' }
        else                                       { $severity = 'info' }
    } else {
        # No design capacity => keep 'info'
        $severity = 'info'
    }

    # Compose a compact summary line with a plain-English impact first
    $impact = switch ($severity) {
        'high'   { 'Battery wear is high, so unplugged runtime will feel dramatically shorter.' }
        'medium' { 'Battery wear is moderate, so unplugged runtime will be noticeably shorter.' }
        'low'    { 'Battery shows slight wear, so runtime remains close to original capacity.' }
        default  { 'Battery health is good, so unplugged runtime should match expectations.' }
    }

    $summaryBits = @()
    if ($data.FullCharge_mAh) { $summaryBits += "Full≈$($data.FullCharge_mAh)mAh" }
    if ($data.Remaining_mAh)  { $summaryBits += "Now≈$($data.Remaining_mAh)mAh" }
    if ($data.Design_mWh)     { $summaryBits += "Design=$($data.Design_mWh)mWh" }
    if ($degr -ne $null)      { $summaryBits += "Degradation=$degr%" }
    if ($data.Charging)       { $summaryBits += 'Charging' }
    $summaryMetrics = ($summaryBits -join ' · ')
    $summary = if ($summaryMetrics) { "$impact $summaryMetrics" } else { $impact }

    # Return a single "issue/card" object that your Composer can render
    return ,@{
        Title       = 'Battery health'
        Heuristic   = 'System/BatteryHealth'
        Severity    = $severity
        Summary     = $summary
        Evidence    = @(
            "Voltage: $($data.Voltage_mV) mV",
            "Remaining: $($data.Remaining_mWh) mWh ($($data.Remaining_mAh) mAh est.)",
            "Full-charge: $($data.FullCharge_mWh) mWh ($($data.FullCharge_mAh) mAh est.)",
            if ($data.Design_mWh) { "Design: $($data.Design_mWh) mWh" },
            if ($degr -ne $null) { "Degradation: $degr %" }
        ) -ne $null -join "`n"
        Data        = $data
        Remediation = if ($degr -ge $HighThresholdPercent) {
            'Battery wear is high. Consider calibrating (full charge/discharge once) and plan for replacement if runtime is insufficient.'
        } elseif ($degr -ge $MediumThresholdPercent) {
            'Battery wear is moderate. Monitor runtime; calibration may help tighten the reported full-charge capacity.'
        } elseif ($degr -ge $LowThresholdPercent) {
            'Slight wear detected. No action needed; re-check in a few months.'
        } else {
            'Battery health is good. No action required.'
        }
    }
}
```

## Example Output
```
Title: Battery health

Summary: Battery wear is high, so unplugged runtime will feel dramatically shorter. Full≈2997mAh · Now≈2951mAh · Design=44000mWh · Degradation=31.9% · Charging

Severity: high (based on ≥30% threshold)

Evidence: voltage, remaining/full mWh & mAh, design mWh, degradation %

Data: full raw metrics object (handy for JSON export / debugging)
```
