if (-not $script:HardwareBatteryRemediation) {
    # Structured remediation mapping:
    # - Markdown headings convert to titled text steps.
    # - Replacement guidance stays a text step before power policy commands.
    # - The policy script and validation snippet remain code steps with escaped literals.
    $script:HardwareBatteryRemediation = @'
[
  {
    "type": "text",
    "title": "Symptoms",
    "content": "Query errors; poor health titles."
  },
  {
    "type": "text",
    "title": "Fix (device)",
    "content": "Recommend battery replacement if FullChargeCapacity < 70% of DesignCapacity."
  },
  {
    "type": "text",
    "content": "Apply a balanced power policy to reduce wear and thermals on laptops."
  },
  {
    "type": "code",
    "lang": "powershell",
    "content": "$powercfg = Join-Path $env:WINDIR 'System32\\powercfg.exe'\n& $powercfg /setactive SCHEME_BALANCED\n& $powercfg /setdcvalueindex SCHEME_CURRENT SUB_PROCESSOR PROCTHROTTLEMIN 5\n& $powercfg /setdcvalueindex SCHEME_CURRENT SUB_PROCESSOR PROCTHROTTLEMAX 85\n& $powercfg /setacvalueindex SCHEME_CURRENT SUB_PROCESSOR PROCTHROTTLEMAX 85"
  },
  {
    "type": "text",
    "title": "Validate",
    "content": "Generate a battery report to confirm configuration changes."
  },
  {
    "type": "code",
    "lang": "powershell",
    "content": "$powercfg = Join-Path $env:WINDIR 'System32\\powercfg.exe'\n$output = Join-Path $env:TEMP 'battery.html'\n& $powercfg /batteryreport /output $output\nWrite-Host \"Battery report exported to $output\""
  }
]
'@
}

function Get-BatteryDesignCapacity {
    [CmdletBinding()]
    param(
        # If your OS is not English, "DESIGN CAPACITY" in batteryreport will be localized.
        # You can provide a custom regex that matches the localized label.
        [string]$BatteryReportDesignCapacityRegex = '(?im)DESIGN\s+CAPACITY\s*\.*\s*([\d,]+)\s*mWh'
    )

    function Get-PowerCfgPath {
        $sysnative = Join-Path $env:WINDIR 'sysnative\powercfg.exe'
        $system32  = Join-Path $env:WINDIR 'system32\powercfg.exe'
        if (Test-Path $sysnative) { return $sysnative }
        if (Test-Path $system32)  { return $system32 }
        return 'powercfg.exe'
    }

    $results = @()

    # --- Path 1: root\wmi BatteryStaticData (best: DesignedCapacity mWh, DesignVoltage mV)
    $static = $null
    try {
        $static = Get-CimInstance -Namespace root\wmi -ClassName BatteryStaticData -ErrorAction Stop
    } catch {
        # Try legacy WMI on PS5 if available (PS7 usually lacks Get-WmiObject)
        if (Get-Command Get-WmiObject -ErrorAction SilentlyContinue) {
            try { $static = Get-WmiObject -Namespace root\wmi -Class BatteryStaticData -ErrorAction Stop } catch {}
        }
    }

    if ($static) {
        $idx = 0
        foreach ($b in $static) {
            $idx++
            $mWh = $b.DesignedCapacity
            $mV  = $b.DesignVoltage
            [double]$mAh = $null
            if ($mWh -and $mV -and $mV -ne 0) { $mAh = [math]::Round($mWh / ($mV/1000.0), 0) }

            $results += [pscustomobject]@{
                Index                = $idx
                Source               = 'root\wmi:BatteryStaticData'
                DeviceName           = $b.DeviceName
                DesignedCapacity_mWh = $mWh
                DesignedCapacity_mAh = $mAh
                DesignVoltage_mV     = $mV
                Manufacturer         = $b.ManufacturerName
                SerialNumber         = $b.SerialNumber
                ManufactureDate      = $b.ManufactureDate
                Chemistry            = $b.Chemistry
                UniqueID             = $b.UniqueID
            }
        }
    }

    # --- Path 2: BatteryFullChargedCapacity (not design, but often present; helpful for sanity check)
    # Only add if Path 1 gave nothing.
    if (-not $results) {
        try {
            $full = Get-CimInstance -Namespace root\wmi -ClassName BatteryFullChargedCapacity -ErrorAction Stop
        } catch {
            if (Get-Command Get-WmiObject -ErrorAction SilentlyContinue) {
                try { $full = Get-WmiObject -Namespace root\wmi -Class BatteryFullChargedCapacity -ErrorAction Stop } catch {}
            }
        }
        if ($full) {
            $idx = 0
            foreach ($f in $full) {
                $idx++
                $results += [pscustomobject]@{
                    Index                = $idx
                    Source               = 'root\wmi:BatteryFullChargedCapacity'
                    DeviceName           = $null
                    DesignedCapacity_mWh = $null
                    DesignedCapacity_mAh = $null
                    DesignVoltage_mV     = $null
                    Manufacturer         = $null
                    SerialNumber         = $null
                    ManufactureDate      = $null
                    Chemistry            = $null
                    UniqueID             = $null
                    Note                 = "FullChargedCapacity (mWh) available: $($f.FullChargedCapacity). This is NOT design."
                }
            }
        }
    }

    # --- Path 3: powercfg /batteryreport (HTML parsing; English by default)
    if (-not $results) {
        try {
            $powercfg = Get-PowerCfgPath
            $tmp = Join-Path $env:TEMP ("batteryreport_{0:yyyyMMdd_HHmmss}.html" -f (Get-Date))
            & $powercfg /batteryreport /output "$tmp" | Out-Null
            if (Test-Path $tmp) {
                $html = Get-Content "$tmp" -Raw -ErrorAction Stop
                $m = [regex]::Matches($html, $BatteryReportDesignCapacityRegex)
                if ($m.Count -gt 0) {
                    $idx = 0
                    foreach ($mm in $m) {
                        $idx++
                        $num = ($mm.Groups[1].Value -replace '[^0-9]').Trim()
                        [int]$mWh = 0
                        [void][int]::TryParse($num, [ref]$mWh)
                        $results += [pscustomobject]@{
                            Index                = $idx
                            Source               = "powercfg:/batteryreport $tmp"
                            DeviceName           = $null
                            DesignedCapacity_mWh = $mWh
                            DesignedCapacity_mAh = $null
                            DesignVoltage_mV     = $null
                            Manufacturer         = $null
                            SerialNumber         = $null
                            ManufactureDate      = $null
                            Chemistry            = $null
                            UniqueID             = $null
                        }
                    }
                }
            }
        } catch {
            # ignore; we'll report below if nothing found
        }
    }

    if (-not $results) {
        Write-Warning "No battery design capacity information found. This can happen on desktops/VMs, unsupported ACPI battery drivers, or localized batteryreport labels."
    }

    $results
}

function Invoke-HardwareBatteryChecks {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $Context,

        [Parameter(Mandatory)]
        $CategoryResult
    )

    $issueCount = 0

    $formatBatteryRuntime = {
        param([double]$Minutes)

        if ($null -eq $Minutes) { return $null }

        $timeSpan = [System.TimeSpan]::FromMinutes($Minutes)
        $parts = New-Object System.Collections.Generic.List[string]

        if ($timeSpan.Days -gt 0) { $parts.Add(("{0}d" -f $timeSpan.Days)) | Out-Null }
        if ($timeSpan.Hours -gt 0) { $parts.Add(("{0}h" -f $timeSpan.Hours)) | Out-Null }
        if ($timeSpan.Minutes -gt 0) { $parts.Add(("{0}m" -f $timeSpan.Minutes)) | Out-Null }

        if ($parts.Count -eq 0) {
            $parts.Add(("{0}m" -f [math]::Round($Minutes, 0))) | Out-Null
        }

        return $parts -join ' '
    }

    $batteryArtifact = Get-AnalyzerArtifact -Context $Context -Name 'battery'
    Write-HeuristicDebug -Source 'Hardware/Battery' -Message 'Resolved battery artifact' -Data ([ordered]@{
        Found = [bool]$batteryArtifact
    })

    if (-not $batteryArtifact) {
        return $issueCount
    }

    $batteryPayload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $batteryArtifact)
    Write-HeuristicDebug -Source 'Hardware/Battery' -Message 'Resolved battery payload' -Data ([ordered]@{
        HasPayload = [bool]$batteryPayload
    })

    if (-not $batteryPayload) {
        return $issueCount
    }

    $batteryErrors = @()
    if ($batteryPayload.PSObject.Properties['Errors'] -and $batteryPayload.Errors) {
        $batteryErrors = @($batteryPayload.Errors | Where-Object { $_ })
    }

    $batteryEntries = @()
    if ($batteryPayload.PSObject.Properties['Batteries'] -and $batteryPayload.Batteries) {
        $batteryEntries = @($batteryPayload.Batteries | Where-Object { $_ })
    }

    $averageLife = $null
    if ($batteryPayload.PSObject.Properties['AverageLife']) {
        $averageLife = $batteryPayload.AverageLife
    }

    $lowWearThreshold    = 10.0
    $mediumWearThreshold = 20.0
    $highWearThreshold   = 30.0

    Write-HeuristicDebug -Source 'Hardware/Battery' -Message 'Parsed battery payload' -Data ([ordered]@{
        BatteryCount       = $batteryEntries.Count
        AverageLifeMinutes = if ($averageLife -and $averageLife.PSObject.Properties['AtFullChargeMinutes']) { $averageLife.AtFullChargeMinutes } else { $null }
        ErrorCount         = $batteryErrors.Count
    })

    $batteryEntryCount = $batteryEntries.Count
    $designCapacityFetchAttempted = $false
    $designCapacityResults = @()
    $designCapacityLookupByUniqueId = @{}
    $designCapacityLookupBySerial = @{}
    $designCapacityLookupByDevice = @{}
    $designCapacityLookupByIndex = @{}

    $resolveDesignCapacity = {
        param(
            [string[]]$UniqueIds = @(),
            [string[]]$SerialNumbers = @(),
            [string[]]$DeviceNames = @(),
            [int]$EntryIndex = -1
        )

        if (-not $designCapacityFetchAttempted) {
            $designCapacityFetchAttempted = $true
            try {
                $designCapacityResults = @(Get-BatteryDesignCapacity)
                Write-HeuristicDebug -Source 'Hardware/Battery' -Message 'Queried system design capacity fallback' -Data ([ordered]@{
                    ResultCount = $designCapacityResults.Count
                })
            } catch {
                Write-HeuristicDebug -Source 'Hardware/Battery' -Message 'Failed querying system design capacity fallback' -Data ([ordered]@{
                    Error = $_.Exception.Message
                })
                $designCapacityResults = @()
            }

            foreach ($designEntry in $designCapacityResults) {
                if (-not $designEntry) { continue }

                if ($designEntry.PSObject.Properties['UniqueID'] -and $designEntry.UniqueID) {
                    $uniqueKey = [string]$designEntry.UniqueID
                    if ($uniqueKey -and $uniqueKey.Trim() -and -not $designCapacityLookupByUniqueId.ContainsKey($uniqueKey.Trim())) {
                        $designCapacityLookupByUniqueId[$uniqueKey.Trim()] = $designEntry
                    }
                }

                if ($designEntry.PSObject.Properties['SerialNumber'] -and $designEntry.SerialNumber) {
                    $serialKey = [string]$designEntry.SerialNumber
                    if ($serialKey -and $serialKey.Trim() -and -not $designCapacityLookupBySerial.ContainsKey($serialKey.Trim())) {
                        $designCapacityLookupBySerial[$serialKey.Trim()] = $designEntry
                    }
                }

                if ($designEntry.PSObject.Properties['DeviceName'] -and $designEntry.DeviceName) {
                    $deviceKey = [string]$designEntry.DeviceName
                    if ($deviceKey -and $deviceKey.Trim() -and -not $designCapacityLookupByDevice.ContainsKey($deviceKey.Trim())) {
                        $designCapacityLookupByDevice[$deviceKey.Trim()] = $designEntry
                    }
                }

                if ($designEntry.PSObject.Properties['Index'] -and $designEntry.Index) {
                    $indexKey = [string]$designEntry.Index
                    if ($indexKey -and $indexKey.Trim() -and -not $designCapacityLookupByIndex.ContainsKey($indexKey.Trim())) {
                        $designCapacityLookupByIndex[$indexKey.Trim()] = $designEntry
                    }
                }
            }
        }

        foreach ($candidate in $UniqueIds) {
            if ([string]::IsNullOrWhiteSpace($candidate)) { continue }
            $lookupKey = $candidate.Trim()
            if ($designCapacityLookupByUniqueId.ContainsKey($lookupKey)) { return $designCapacityLookupByUniqueId[$lookupKey] }
        }

        foreach ($candidate in $SerialNumbers) {
            if ([string]::IsNullOrWhiteSpace($candidate)) { continue }
            $lookupKey = $candidate.Trim()
            if ($designCapacityLookupBySerial.ContainsKey($lookupKey)) { return $designCapacityLookupBySerial[$lookupKey] }
        }

        foreach ($candidate in $DeviceNames) {
            if ([string]::IsNullOrWhiteSpace($candidate)) { continue }
            $lookupKey = $candidate.Trim()
            if ($designCapacityLookupByDevice.ContainsKey($lookupKey)) { return $designCapacityLookupByDevice[$lookupKey] }
        }

        if ($EntryIndex -gt 0) {
            $indexKey = $EntryIndex.ToString().Trim()
            if ($designCapacityLookupByIndex.ContainsKey($indexKey)) { return $designCapacityLookupByIndex[$indexKey] }
        }

        if ($batteryEntryCount -eq 1 -and $designCapacityResults.Count -eq 1) {
            return $designCapacityResults[0]
        }

        return $null
    }

    if ($batteryErrors.Count -gt 0) {
        $firstError = $batteryErrors | Select-Object -First 1
        $errorText = if ($firstError -and $firstError.PSObject.Properties['Error'] -and $firstError.Error) { [string]$firstError.Error } else { 'Unknown error' }
        $source = if ($firstError -and $firstError.PSObject.Properties['Source'] -and $firstError.Source) { [string]$firstError.Source } else { 'root\wmi battery classes' }
        Add-CategoryIssue -CategoryResult $CategoryResult -Severity 'warning' -Title 'Battery health query reported an error, so health data may be incomplete.' -Evidence ("{0}: {1}" -f $source, $errorText) -Subcategory 'Battery' -Explanation 'Battery monitoring failed, so technicians cannot verify wear or runtime impacts.' -Remediation $script:HardwareBatteryRemediation
        $issueCount++
    }

    $batteryIndex = 0
    foreach ($battery in $batteryEntries) {
        if (-not $battery) { continue }
        $batteryIndex++

        $label = if ($battery.PSObject.Properties['Name'] -and $battery.Name) { [string]$battery.Name } else { 'Primary battery' }

        $design = $null
        if ($battery.PSObject.Properties['DesignCapacitymWh']) {
            $designValue = $battery.DesignCapacitymWh
            if ($designValue -ne $null -and $designValue -ne '') { $design = [double]$designValue }
        }

        $full = $null
        if ($battery.PSObject.Properties['FullChargeCapacitymWh']) {
            $fullValue = $battery.FullChargeCapacitymWh
            if ($fullValue -ne $null -and $fullValue -ne '') { $full = [double]$fullValue }
        }

        $remaining = $null
        if ($battery.PSObject.Properties['RemainingCapacitymWh']) {
            $remainingValue = $battery.RemainingCapacitymWh
            if ($remainingValue -ne $null -and $remainingValue -ne '') { $remaining = [double]$remainingValue }
        }

        $designmAh = $null
        if ($battery.PSObject.Properties['DesignCapacitymAh']) {
            $designmAhValue = $battery.DesignCapacitymAh
            if ($designmAhValue -ne $null -and $designmAhValue -ne '') { $designmAh = [double]$designmAhValue }
        }

        $fullmAh = $null
        if ($battery.PSObject.Properties['FullChargeCapacitymAh']) {
            $fullmAhValue = $battery.FullChargeCapacitymAh
            if ($fullmAhValue -ne $null -and $fullmAhValue -ne '') { $fullmAh = [double]$fullmAhValue }
        }

        $remainingmAh = $null
        if ($battery.PSObject.Properties['RemainingCapacitymAh']) {
            $remainingmAhValue = $battery.RemainingCapacitymAh
            if ($remainingmAhValue -ne $null -and $remainingmAhValue -ne '') { $remainingmAh = [double]$remainingmAhValue }
        }

        if ($design -eq $null -or $design -le 0) {
            $rawSnapshot = $null
            if ($battery.PSObject.Properties['RawSnapshot']) {
                $rawSnapshot = $battery.RawSnapshot
            }

            $fallbackCandidates = @()
            if ($battery.PSObject.Properties['UniqueId'] -and $battery.UniqueId) { $fallbackCandidates += [string]$battery.UniqueId }
            if ($battery.PSObject.Properties['SerialNumber'] -and $battery.SerialNumber) { $fallbackCandidates += [string]$battery.SerialNumber }
            if ($battery.PSObject.Properties['DeviceName'] -and $battery.DeviceName) { $fallbackCandidates += [string]$battery.DeviceName }
            $designEntry = & $resolveDesignCapacity -UniqueIds $fallbackCandidates -SerialNumbers @($battery.SerialNumber) -DeviceNames @($battery.DeviceName) -EntryIndex $batteryIndex

            if ($designEntry -and $designEntry.PSObject.Properties['DesignedCapacity_mWh'] -and $designEntry.DesignedCapacity_mWh) {
                $design = [double]$designEntry.DesignedCapacity_mWh
                Write-HeuristicDebug -Source 'Hardware/Battery' -Message 'Resolved missing design capacity from fallback' -Data ([ordered]@{
                    Label = $label
                    Source = $designEntry.Source
                    Value  = $design
                })
            } elseif ($rawSnapshot -and $rawSnapshot.PSObject.Properties['DesignedCapacitymWh']) {
                $snapshotValue = $rawSnapshot.DesignedCapacitymWh
                if ($snapshotValue -ne $null -and $snapshotValue -ne '') {
                    $design = [double]$snapshotValue
                    Write-HeuristicDebug -Source 'Hardware/Battery' -Message 'Resolved missing design capacity from snapshot' -Data ([ordered]@{
                        Label  = $label
                        Source = 'RawSnapshot.DesignedCapacitymWh'
                        Value  = $design
                    })
                }
            }
        }

        if ($design -eq $null -or $design -le 0 -or $full -eq $null -or $full -le 0) {
            $evidenceParts = @()
            if ($design -eq $null -or $design -le 0) {
                $evidenceParts += 'Design capacity not reported.'
            }
            if ($full -eq $null -or $full -le 0) {
                $evidenceParts += 'Full charge capacity not reported.'
            }

            $title = "Battery {0} is missing design/full capacity data, so health cannot be calculated." -f $label
            Add-CategoryIssue -CategoryResult $CategoryResult -Severity 'info' -Title $title -Evidence ($evidenceParts -join ' ') -Subcategory 'Battery' -Explanation 'Battery capacity signals are incomplete, so technicians cannot determine wear or plan replacements.' -Remediation $script:HardwareBatteryRemediation
            $issueCount++
            continue
        }

        $wearPercent = $null
        if ($design -gt 0 -and $full -ge 0) {
            $wearPercent = if ($design -eq 0) { $null } else { [math]::Round(((1 - ($full / $design)) * 100), 1) }
        }

        if ($wearPercent -ne $null) {
            $severity = if ($wearPercent -ge $highWearThreshold) {
                'high'
            } elseif ($wearPercent -ge $mediumWearThreshold) {
                'medium'
            } elseif ($wearPercent -ge $lowWearThreshold) {
                'info'
            } else {
                $null
            }

            if ($severity) {
                $title = "Battery {0} has degraded {1}%." -f $label, $wearPercent
                Add-CategoryIssue -CategoryResult $CategoryResult -Severity $severity -Title $title -Subcategory 'Battery' -Explanation 'Battery wear has reduced usable capacity, so unplugged runtime shortens for end users.' -Remediation $script:HardwareBatteryRemediation
                $issueCount++
            }
        }

        if ($remaining -ne $null -and $remaining -ge 0) {
            $percentRemaining = if ($full -gt 0) { [math]::Round((($remaining / $full) * 100), 1) } else { $null }
            if ($percentRemaining -ne $null) {
                Add-CategoryCheck -CategoryResult $CategoryResult -Name ("Battery {0} remaining capacity" -f $label) -Status ("{0}%" -f $percentRemaining) -Details "Remaining: $remaining mWh; Full: $full mWh; Design: $design mWh"
            }
        }

        if ($designmAh -ne $null -and $fullmAh -ne $null) {
            $percentRemainingmAh = if ($designmAh -gt 0) { [math]::Round((($fullmAh / $designmAh) * 100), 1) } else { $null }
            if ($percentRemainingmAh -ne $null) {
                Add-CategoryCheck -CategoryResult $CategoryResult -Name ("Battery {0} capacity" -f $label) -Status ("{0}% of design" -f $percentRemainingmAh) -Details "Full: $fullmAh mAh; Design: $designmAh mAh"
            }
        }
    }

    if ($averageLife) {
        $runtimeDisplay = $null
        if ($averageLife.PSObject.Properties['AtFullChargeMinutes'] -and $averageLife.AtFullChargeMinutes) {
            $runtimeDisplay = & $formatBatteryRuntime ([double]$averageLife.AtFullChargeMinutes)
        }
        if (-not $runtimeDisplay -and $averageLife.PSObject.Properties['AtFullCharge'] -and $averageLife.AtFullCharge) {
            $runtimeDisplay = [string]$averageLife.AtFullCharge
        }

        if ($runtimeDisplay) {
            $details = if ($averageLife.PSObject.Properties['Period'] -and $averageLife.Period) { "Period: $($averageLife.Period)" } else { '' }
            Add-CategoryCheck -CategoryResult $CategoryResult -Name 'Battery average runtime' -Status $runtimeDisplay -Details $details
        }
    }

    return $issueCount
}
