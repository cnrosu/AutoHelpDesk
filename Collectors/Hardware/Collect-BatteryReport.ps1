<#!
.SYNOPSIS
    Captures battery health metrics from Windows battery WMI classes and normalizes them to JSON.
.DESCRIPTION
    Queries root\wmi battery classes to surface design capacity, current full-charge capacity,
    chemistry, and live discharge measurements without relying on powercfg.exe HTML reports.
#>
[CmdletBinding()]
param(
    [Parameter()]
    [string]$OutputDirectory = (Join-Path -Path $PSScriptRoot -ChildPath 'output'),

    [Parameter()]
    [int]$RateSamples = 6,

    [Parameter()]
    [int]$SampleIntervalSeconds = 5
)

. (Join-Path -Path $PSScriptRoot -ChildPath '..\CollectorCommon.ps1')

function Get-AHDBatteryRaw {
    [CmdletBinding()]
    param()

    $staticInstances = @()
    $fullInstances = @()
    $statusInstances = @()

    try {
        $staticInstances = @(Get-CimInstance -Namespace root\wmi -ClassName BatteryStaticData -ErrorAction SilentlyContinue)
    } catch {
        Write-Verbose "Failed to query BatteryStaticData: $($_.Exception.Message)"
    }

    try {
        $fullInstances = @(Get-CimInstance -Namespace root\wmi -ClassName BatteryFullChargedCapacity -ErrorAction SilentlyContinue)
    } catch {
        Write-Verbose "Failed to query BatteryFullChargedCapacity: $($_.Exception.Message)"
    }

    try {
        $statusInstances = @(Get-CimInstance -Namespace root\wmi -ClassName BatteryStatus -ErrorAction SilentlyContinue)
    } catch {
        Write-Verbose "Failed to query BatteryStatus: $($_.Exception.Message)"
    }

    if ($staticInstances.Count -eq 0 -and $fullInstances.Count -eq 0 -and $statusInstances.Count -eq 0) {
        throw 'No battery WMI data found in root\wmi. Are you on a desktop or is the battery disabled?'
    }

    $byInstance = @{}

    foreach ($static in $staticInstances) {
        if (-not $static) { continue }
        $instanceName = if ($static.PSObject.Properties['InstanceName']) { [string]$static.InstanceName } else { [guid]::NewGuid().ToString('N') }
        if (-not $byInstance.ContainsKey($instanceName)) {
            $byInstance[$instanceName] = [ordered]@{
                InstanceName = $instanceName
            }
        }

        $current = $byInstance[$instanceName]
        foreach ($prop in $static.PSObject.Properties) {
            $current["Static_$($prop.Name)"] = $prop.Value
        }

        if ($static.PSObject.Properties['DesignedCapacity']) { $current.Design_mWh = [double]$static.DesignedCapacity }
        if ($static.PSObject.Properties['DesignVoltage']) { $current.DesignVoltage_mV = [double]$static.DesignVoltage }
        if ($static.PSObject.Properties['Chemistry']) { $current.Chemistry = $static.Chemistry }
        if ($static.PSObject.Properties['ManufactureName']) { $current.Manufacturer = $static.ManufactureName }
        if ($static.PSObject.Properties['DeviceName']) { $current.DeviceName = $static.DeviceName }
        if ($static.PSObject.Properties['ModelNumber']) { $current.ModelNumber = $static.ModelNumber }
        if ($static.PSObject.Properties['SerialNumber']) { $current.SerialNumber = $static.SerialNumber }
        if ($static.PSObject.Properties['CycleCount']) { $current.CycleCount = [int]$static.CycleCount }
    }

    foreach ($full in $fullInstances) {
        if (-not $full) { continue }
        $instanceName = if ($full.PSObject.Properties['InstanceName']) { [string]$full.InstanceName } else { [guid]::NewGuid().ToString('N') }
        if (-not $byInstance.ContainsKey($instanceName)) {
            $byInstance[$instanceName] = [ordered]@{
                InstanceName = $instanceName
            }
        }

        $current = $byInstance[$instanceName]
        foreach ($prop in $full.PSObject.Properties) {
            $current["Full_$($prop.Name)"] = $prop.Value
        }

        if ($full.PSObject.Properties['FullChargedCapacity']) { $current.FullCharge_mWh = [double]$full.FullChargedCapacity }
    }

    foreach ($status in $statusInstances) {
        if (-not $status) { continue }
        $instanceName = if ($status.PSObject.Properties['InstanceName']) { [string]$status.InstanceName } else { [guid]::NewGuid().ToString('N') }
        if (-not $byInstance.ContainsKey($instanceName)) {
            $byInstance[$instanceName] = [ordered]@{
                InstanceName = $instanceName
            }
        }

        $current = $byInstance[$instanceName]
        foreach ($prop in $status.PSObject.Properties) {
            $current["Status_$($prop.Name)"] = $prop.Value
        }

        if ($status.PSObject.Properties['Rate']) { $current.Rate_mW = [double]$status.Rate }
        if ($status.PSObject.Properties['Voltage']) { $current.PresentVoltage_mV = [double]$status.Voltage }
        if ($status.PSObject.Properties['RemainingCapacity']) { $current.Remaining_mWh = [double]$status.RemainingCapacity }
        if ($status.PSObject.Properties['Chemistry'] -and -not $current.Chemistry) { $current.Chemistry = $status.Chemistry }
        if ($status.PSObject.Properties['ChargeDischargeRate']) { $current.Rate_mW = [double]$status.ChargeDischargeRate }
    }

    $results = New-Object System.Collections.Generic.List[pscustomobject]

    foreach ($key in $byInstance.Keys) {
        $entry = $byInstance[$key]
        $volt_mV = $null
        if ($entry.Contains('DesignVoltage_mV') -and $entry.DesignVoltage_mV -gt 0) {
            $volt_mV = [double]$entry.DesignVoltage_mV
        } elseif ($entry.Contains('PresentVoltage_mV') -and $entry.PresentVoltage_mV -gt 0) {
            $volt_mV = [double]$entry.PresentVoltage_mV
        }

        if ($volt_mV) {
            if ($entry.Contains('Design_mWh') -and $entry.Design_mWh) {
                $entry.Design_mAh = [math]::Round(($entry.Design_mWh * 1000.0) / $volt_mV, 1)
            }
            if ($entry.Contains('FullCharge_mWh') -and $entry.FullCharge_mWh) {
                $entry.FullCharge_mAh = [math]::Round(($entry.FullCharge_mWh * 1000.0) / $volt_mV, 1)
            }
            if ($entry.Contains('Remaining_mWh') -and $entry.Remaining_mWh) {
                $entry.Remaining_mAh = [math]::Round(($entry.Remaining_mWh * 1000.0) / $volt_mV, 1)
            }
            $entry.VoltageSource = "mV=$volt_mV"
        } else {
            $entry.VoltageSource = 'Unavailable'
        }

        if ($entry.Contains('Design_mWh') -and $entry.Design_mWh -and $entry.Contains('FullCharge_mWh') -and $entry.FullCharge_mWh) {
            $entry.Degradation_Pct = [math]::Round((1 - ($entry.FullCharge_mWh / $entry.Design_mWh)) * 100, 2)
        }

        $entry.Timestamp = Get-Date
        $results.Add([pscustomobject]$entry) | Out-Null
    }

    return $results
}

function Measure-AHDBatteryRate {
    [CmdletBinding()]
    param(
        [int]$Samples = 6,
        [int]$IntervalSeconds = 5,
        [string[]]$InstanceNames
    )

    $rates = New-Object System.Collections.Generic.List[pscustomobject]

    for ($i = 0; $i -lt $Samples; $i++) {
        try {
            $statusRows = @(Get-CimInstance -Namespace root\wmi -ClassName BatteryStatus -ErrorAction SilentlyContinue)
        } catch {
            Write-Verbose "Failed to sample BatteryStatus: $($_.Exception.Message)"
            $statusRows = @()
        }

        foreach ($row in $statusRows) {
            if (-not $row) { continue }
            if ($InstanceNames -and $InstanceNames.Count -gt 0) {
                if (-not $InstanceNames.Contains([string]$row.InstanceName)) { continue }
            }
            if ($null -eq $row.Rate) { continue }
            $rates.Add([pscustomobject]@{
                InstanceName = [string]$row.InstanceName
                Rate_mW      = [double]$row.Rate
                When         = Get-Date
            }) | Out-Null
        }

        if ($i -lt ($Samples - 1) -and $IntervalSeconds -gt 0) {
            Start-Sleep -Seconds $IntervalSeconds
        }
    }

    $grouped = $rates | Group-Object InstanceName
    $averages = New-Object System.Collections.Generic.List[pscustomobject]
    foreach ($group in $grouped) {
        if (-not $group) { continue }
        $avg = ($group.Group | Measure-Object Rate_mW -Average).Average
        $averages.Add([pscustomobject]@{
            InstanceName = $group.Name
            AvgRate_mW   = [math]::Round([math]::Abs([double]$avg), 0)
            Samples      = $group.Group.Count
        }) | Out-Null
    }

    return $averages
}

function Resolve-BatteryLabel {
    param(
        [pscustomobject]$Entry,
        [int]$Index
    )

    $candidates = @()
    if ($Entry.PSObject.Properties['DeviceName']) { $candidates += [string]$Entry.DeviceName }
    if ($Entry.PSObject.Properties['Static_DeviceName']) { $candidates += [string]$Entry.Static_DeviceName }
    if ($Entry.PSObject.Properties['Manufacturer']) { $candidates += [string]$Entry.Manufacturer }
    if ($Entry.PSObject.Properties['Static_ManufactureName']) { $candidates += [string]$Entry.Static_ManufactureName }
    if ($Entry.PSObject.Properties['ModelNumber']) { $candidates += [string]$Entry.ModelNumber }
    if ($Entry.PSObject.Properties['SerialNumber']) { $candidates += [string]$Entry.SerialNumber }
    if ($Entry.PSObject.Properties['InstanceName']) { $candidates += [string]$Entry.InstanceName }

    foreach ($candidate in $candidates) {
        if ($candidate -and $candidate.Trim()) { return $candidate.Trim() }
    }

    return "Battery $Index"
}

function Format-BatteryRuntime {
    param([double]$Minutes)

    if ($null -eq $Minutes) { return $null }
    if ($Minutes -le 0) { return '0m' }

    $timeSpan = [TimeSpan]::FromMinutes($Minutes)
    $parts = New-Object System.Collections.Generic.List[string]
    if ($timeSpan.Days -gt 0) { $parts.Add(("{0}d" -f $timeSpan.Days)) | Out-Null }
    if ($timeSpan.Hours -gt 0) { $parts.Add(("{0}h" -f $timeSpan.Hours)) | Out-Null }
    if ($timeSpan.Minutes -gt 0) { $parts.Add(("{0}m" -f $timeSpan.Minutes)) | Out-Null }
    if ($parts.Count -eq 0) { $parts.Add(("{0}m" -f [math]::Round($Minutes, 0))) | Out-Null }
    return $parts -join ' '
}

$resolvedOutput = Resolve-CollectorOutputDirectory -RequestedPath $OutputDirectory
$payload = [ordered]@{}
$errors = New-Object System.Collections.Generic.List[pscustomobject]

$batteryRows = @()
try {
    $batteryRows = @(Get-AHDBatteryRaw)
} catch {
    $errors.Add([pscustomobject]@{ Source = 'root\\wmi'; Error = $_.Exception.Message }) | Out-Null
}

$rateSummaries = @()
if ($batteryRows.Count -gt 0) {
    try {
        $instanceNames = @($batteryRows | ForEach-Object { [string]$_.InstanceName } | Where-Object { $_ })
        $rateSummaries = @(Measure-AHDBatteryRate -Samples $RateSamples -IntervalSeconds $SampleIntervalSeconds -InstanceNames $instanceNames)
    } catch {
        $errors.Add([pscustomobject]@{ Source = 'root\\wmi/BatteryStatus'; Error = $_.Exception.Message }) | Out-Null
    }
}

$rateMap = @{}
foreach ($rate in $rateSummaries) {
    if (-not $rate) { continue }
    $rateMap[[string]$rate.InstanceName] = $rate
}

$batteryList = New-Object System.Collections.Generic.List[object]
$lifeList = New-Object System.Collections.Generic.List[object]

$totalFull = 0.0
$totalDesign = 0.0
$totalRates = New-Object System.Collections.Generic.List[double]

$index = 0
foreach ($entry in $batteryRows) {
    if (-not $entry) { continue }
    $index++

    $label = Resolve-BatteryLabel -Entry $entry -Index $index

    $designWh = if ($entry.PSObject.Properties['Design_mWh']) { [double]$entry.Design_mWh } else { $null }
    $fullWh = if ($entry.PSObject.Properties['FullCharge_mWh']) { [double]$entry.FullCharge_mWh } else { $null }
    $designmAh = if ($entry.PSObject.Properties['Design_mAh']) { [double]$entry.Design_mAh } else { $null }
    $fullmAh = if ($entry.PSObject.Properties['FullCharge_mAh']) { [double]$entry.FullCharge_mAh } else { $null }
    $remainingWh = if ($entry.PSObject.Properties['Remaining_mWh']) { [double]$entry.Remaining_mWh } else { $null }
    $remainingmAh = if ($entry.PSObject.Properties['Remaining_mAh']) { [double]$entry.Remaining_mAh } else { $null }
    $degradation = if ($entry.PSObject.Properties['Degradation_Pct']) { [double]$entry.Degradation_Pct } else { $null }
    $cycle = $null
    if ($entry.PSObject.Properties['CycleCount']) { $cycle = [int]$entry.CycleCount }
    elseif ($entry.PSObject.Properties['Static_CycleCount']) { $cycle = [int]$entry.Static_CycleCount }

    $avgRate = $null
    $rateSamplesForInstance = $null
    if ($rateMap.ContainsKey([string]$entry.InstanceName)) {
        $avgRate = [double]$rateMap[[string]$entry.InstanceName].AvgRate_mW
        $rateSamplesForInstance = [int]$rateMap[[string]$entry.InstanceName].Samples
        if ($avgRate -gt 0) { $totalRates.Add($avgRate) | Out-Null }
    }

    $estFullMinutes = $null
    if ($avgRate -and $avgRate -gt 0 -and $fullWh -and $fullWh -gt 0) {
        $estFullMinutes = [math]::Round(($fullWh / $avgRate) * 60, 2)
    }

    $estDesignMinutes = $null
    if ($avgRate -and $avgRate -gt 0 -and $designWh -and $designWh -gt 0) {
        $estDesignMinutes = [math]::Round(($designWh / $avgRate) * 60, 2)
    }

    if ($fullWh -gt 0) { $totalFull += $fullWh }
    if ($designWh -gt 0) { $totalDesign += $designWh }

    $rawSnapshot = [ordered]@{
        InstanceName           = $entry.InstanceName
        Chemistry              = if ($entry.PSObject.Properties['Chemistry']) { $entry.Chemistry } else { $null }
        DesignCapacity_mWh     = $designWh
        FullChargeCapacity_mWh = $fullWh
        RemainingCapacity_mWh  = $remainingWh
        DesignCapacity_mAh     = $designmAh
        FullChargeCapacity_mAh = $fullmAh
        RemainingCapacity_mAh  = $remainingmAh
        DesignVoltage_mV       = if ($entry.PSObject.Properties['DesignVoltage_mV']) { $entry.DesignVoltage_mV } else { $null }
        PresentVoltage_mV      = if ($entry.PSObject.Properties['PresentVoltage_mV']) { $entry.PresentVoltage_mV } else { $null }
        AverageDischarge_mW    = $avgRate
        RateSamples            = $rateSamplesForInstance
        DegradationPercent     = $degradation
        VoltageSource          = if ($entry.PSObject.Properties['VoltageSource']) { $entry.VoltageSource } else { $null }
        Timestamp              = $entry.Timestamp
    }

    foreach ($prop in $entry.PSObject.Properties) {
        if ($prop.Name -like 'Static_*' -or $prop.Name -like 'Full_*' -or $prop.Name -like 'Status_*') {
            $rawSnapshot[$prop.Name] = $prop.Value
        }
    }

    $batteryList.Add([pscustomobject][ordered]@{
        Name                     = $label
        InstanceName             = $entry.InstanceName
        Manufacturer             = if ($entry.PSObject.Properties['Manufacturer']) { $entry.Manufacturer } elseif ($entry.PSObject.Properties['Static_ManufactureName']) { $entry.Static_ManufactureName } else { $null }
        SerialNumber             = if ($entry.PSObject.Properties['SerialNumber']) { $entry.SerialNumber } elseif ($entry.PSObject.Properties['Static_SerialNumber']) { $entry.Static_SerialNumber } else { $null }
        Chemistry                = if ($entry.PSObject.Properties['Chemistry']) { $entry.Chemistry } elseif ($entry.PSObject.Properties['Status_Chemistry']) { $entry.Status_Chemistry } else { $null }
        DesignCapacitymWh        = if ($designWh) { [int][math]::Round($designWh) } else { $null }
        FullChargeCapacitymWh    = if ($fullWh) { [int][math]::Round($fullWh) } else { $null }
        DesignCapacitymAh        = if ($designmAh) { [math]::Round($designmAh, 1) } else { $null }
        FullChargeCapacitymAh    = if ($fullmAh) { [math]::Round($fullmAh, 1) } else { $null }
        RemainingCapacitymWh     = if ($remainingWh) { [int][math]::Round($remainingWh) } else { $null }
        RemainingCapacitymAh     = if ($remainingmAh) { [math]::Round($remainingmAh, 1) } else { $null }
        DegradationPercent       = $degradation
        CycleCount               = if ($cycle -ge 0) { $cycle } else { $null }
        AverageDischargeMilliwatts = if ($avgRate) { [math]::Round($avgRate, 0) } else { $null }
        EstimatedRuntimeFullMinutes   = $estFullMinutes
        EstimatedRuntimeDesignMinutes = $estDesignMinutes
        RateSampleCount          = $rateSamplesForInstance
        Raw                      = [pscustomobject]$rawSnapshot
    }) | Out-Null

    $lifeList.Add([pscustomobject][ordered]@{
        Period                  = 'Live discharge measurement'
        InstanceName            = $entry.InstanceName
        AtFullChargeMinutes     = $estFullMinutes
        AtFullCharge            = if ($estFullMinutes -ne $null) { Format-BatteryRuntime -Minutes $estFullMinutes } else { $null }
        AtDesignCapacityMinutes = $estDesignMinutes
        AtDesignCapacity        = if ($estDesignMinutes -ne $null) { Format-BatteryRuntime -Minutes $estDesignMinutes } else { $null }
        AvgDischargeMilliwatts  = if ($avgRate) { [math]::Round($avgRate, 0) } else { $null }
        SampleCount             = $rateSamplesForInstance
    }) | Out-Null
}

if ($batteryList.Count -gt 0) {
    $payload['Batteries'] = $batteryList.ToArray()
}

if ($lifeList.Count -gt 0) {
    $payload['LifeEstimates'] = $lifeList.ToArray()
}

$aggregateRate = $null
if ($totalRates.Count -gt 0) {
    $aggregateRate = ($totalRates | Measure-Object -Average).Average
}

$aggregateFullMinutes = $null
if ($aggregateRate -and $aggregateRate -gt 0 -and $totalFull -gt 0) {
    $aggregateFullMinutes = [math]::Round(($totalFull / $aggregateRate) * 60, 2)
}

$aggregateDesignMinutes = $null
if ($aggregateRate -and $aggregateRate -gt 0 -and $totalDesign -gt 0) {
    $aggregateDesignMinutes = [math]::Round(($totalDesign / $aggregateRate) * 60, 2)
}

if ($batteryList.Count -gt 0) {
    $payload['AverageLife'] = [ordered]@{
        Period                  = 'Live discharge sampling'
        Samples                 = $RateSamples
        SampleIntervalSeconds   = $SampleIntervalSeconds
        AvgDischargeMilliwatts  = if ($aggregateRate) { [math]::Round($aggregateRate, 0) } else { $null }
        AtFullChargeMinutes     = $aggregateFullMinutes
        AtFullCharge            = if ($aggregateFullMinutes -ne $null) { Format-BatteryRuntime -Minutes $aggregateFullMinutes } else { $null }
        AtDesignCapacityMinutes = $aggregateDesignMinutes
        AtDesignCapacity        = if ($aggregateDesignMinutes -ne $null) { Format-BatteryRuntime -Minutes $aggregateDesignMinutes } else { $null }
    }
}

$payload['Metadata'] = [ordered]@{
    SourceNamespace        = 'root\\wmi'
    RateSamples            = $RateSamples
    SampleIntervalSeconds  = $SampleIntervalSeconds
    QueriedAt              = (Get-Date).ToString('o')
}

if ($errors.Count -gt 0) {
    $payload['Errors'] = $errors.ToArray()
}

$result = New-CollectorMetadata -Payload $payload
$exportPath = Export-CollectorResult -OutputDirectory $resolvedOutput -FileName 'battery.json' -Data $result

Write-Output $exportPath
