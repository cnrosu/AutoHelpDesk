<#!
.SYNOPSIS
    Captures battery health metrics from powercfg and normalizes them to JSON.
.DESCRIPTION
    Invokes `powercfg.exe /batteryreport` with XML output so analyzers can surface
    battery degradation and runtime estimates without parsing HTML.
#>
[CmdletBinding()]
param(
    [Parameter()]
    [string]$OutputDirectory = (Join-Path -Path $PSScriptRoot -ChildPath 'output')
)

. (Join-Path -Path $PSScriptRoot -ChildPath '..\CollectorCommon.ps1')

function Resolve-BatteryNumber {
    param([string]$Value)

    if (-not $Value) { return $null }

    $clean = ($Value -replace '[^0-9\.,-]', '')
    if (-not $clean) { return $null }

    # Remove thousands separators before parsing.
    $normalized = $clean -replace ',', ''

    $result = 0.0
    if ([double]::TryParse($normalized, [System.Globalization.NumberStyles]::AllowDecimalPoint -bor [System.Globalization.NumberStyles]::AllowLeadingSign, [System.Globalization.CultureInfo]::InvariantCulture, [ref]$result)) {
        return $result
    }

    return $null
}

function Resolve-BatteryCapacity {
    param([string]$Value)

    $number = Resolve-BatteryNumber -Value $Value
    if ($null -eq $number) { return $null }

    return [int][math]::Round($number)
}

function Resolve-BatteryTimespanMinutes {
    param([string]$Value)

    if (-not $Value) { return $null }

    $trimmed = $Value.Trim()
    if (-not $trimmed) { return $null }
    if ($trimmed -match '^(N/A|Unknown)$') { return $null }

    $timespan = [TimeSpan]::Zero
    if ([TimeSpan]::TryParse($trimmed, [ref]$timespan)) {
        return [math]::Round($timespan.TotalMinutes, 2)
    }

    return $null
}

function Resolve-BatteryLabel {
    param([hashtable]$Map)

    foreach ($candidate in @('BatteryName','Name','DeviceName','Manufacturer')) {
        if ($Map.ContainsKey($candidate) -and $Map[$candidate]) {
            return [string]$Map[$candidate]
        }
    }

    return 'Primary battery'
}

$resolvedOutput = Resolve-CollectorOutputDirectory -RequestedPath $OutputDirectory
$payload = [ordered]@{}
$errors = New-Object System.Collections.Generic.List[pscustomobject]

$tempFile = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath ("batteryreport_{0}.xml" -f ([guid]::NewGuid().ToString('N')))

try {
    $arguments = @('/batteryreport', '/output', $tempFile, '/format', 'XML')
    $commandOutput = & powercfg.exe @arguments 2>&1
    $exitCode = $LASTEXITCODE

    if ($exitCode -ne 0) {
        $message = if ($commandOutput) { ($commandOutput | Out-String).Trim() } else { "powercfg.exe exited with code $exitCode" }
        $errors.Add([pscustomobject]@{ Source = 'powercfg.exe /batteryreport'; Error = $message }) | Out-Null
    } elseif (-not (Test-Path -Path $tempFile)) {
        $errors.Add([pscustomobject]@{ Source = 'powercfg.exe /batteryreport'; Error = 'Expected XML report was not generated.' }) | Out-Null
    } else {
        try {
            [xml]$xml = Get-Content -Path $tempFile -Raw

            if ($xml -and $xml.DocumentElement) {
                $reportNode = $xml.DocumentElement

                $generated = $reportNode.SelectSingleNode('/*[local-name()="BatteryReport"]/*[local-name()="ReportMetadata"]/*[local-name()="GenerationTime"]')
                if (-not $generated) {
                    $generated = $reportNode.SelectSingleNode('/*[local-name()="BatteryReport"]/*[local-name()="ReportMetadata"]/*[local-name()="GeneratedTime"]')
                }

                if ($generated -and $generated.InnerText) {
                    $timestamp = $null
                    if ([DateTime]::TryParse($generated.InnerText.Trim(), [ref]$timestamp)) {
                        $payload['ReportGeneratedAt'] = $timestamp.ToString('o')
                    } else {
                        $payload['ReportGeneratedAt'] = $generated.InnerText.Trim()
                    }
                }

                $batteryNodes = $reportNode.SelectNodes('/*[local-name()="BatteryReport"]/*[local-name()="Batteries"]/*[local-name()="Battery"]')
                if ($batteryNodes -and $batteryNodes.Count -gt 0) {
                    $batteryList = New-Object System.Collections.Generic.List[object]

                    foreach ($node in $batteryNodes) {
                        if (-not $node) { continue }

                        $raw = [ordered]@{}
                        $map = @{}

                        foreach ($child in $node.ChildNodes) {
                            if (-not $child -or $child.NodeType -ne [System.Xml.XmlNodeType]::Element) { continue }
                            $name = [string]$child.LocalName
                            $value = $child.InnerText
                            if ($value) { $value = $value.Trim() }
                            $raw[$name] = $value
                            $map[$name] = $value
                        }

                        $label = Resolve-BatteryLabel -Map $map
                        $manufacturer = if ($map.ContainsKey('Manufacturer')) { [string]$map['Manufacturer'] } else { $null }
                        $serial = if ($map.ContainsKey('SerialNumber')) { [string]$map['SerialNumber'] } else { $null }
                        $chemistry = if ($map.ContainsKey('Chemistry')) { [string]$map['Chemistry'] } else { $null }

                        $designRaw = if ($map.ContainsKey('DesignCapacity')) { $map['DesignCapacity'] } else { $null }
                        if (-not $designRaw) {
                            foreach ($key in $map.Keys) {
                                if ($key -match 'design' -and $map[$key]) { $designRaw = $map[$key]; break }
                            }
                        }
                        $design = Resolve-BatteryCapacity -Value $designRaw

                        $fullRaw = if ($map.ContainsKey('FullChargeCapacity')) { $map['FullChargeCapacity'] } else { $null }
                        if (-not $fullRaw) {
                            foreach ($key in $map.Keys) {
                                if ($key -match 'full' -and $map[$key]) { $fullRaw = $map[$key]; break }
                            }
                        }
                        $full = Resolve-BatteryCapacity -Value $fullRaw

                        $cycleRaw = if ($map.ContainsKey('CycleCount')) { $map['CycleCount'] } else { $null }
                        if (-not $cycleRaw) {
                            foreach ($key in $map.Keys) {
                                if ($key -match 'cycle' -and $map[$key]) { $cycleRaw = $map[$key]; break }
                            }
                        }
                        $cycleNumber = Resolve-BatteryNumber -Value $cycleRaw
                        $cycle = if ($null -ne $cycleNumber) { [int][math]::Round($cycleNumber) } else { $null }

                        $batteryEntry = [ordered]@{
                            Name                   = $label
                            Manufacturer           = $manufacturer
                            SerialNumber           = $serial
                            Chemistry              = $chemistry
                            DesignCapacitymWh      = $design
                            FullChargeCapacitymWh  = $full
                            CycleCount             = $cycle
                            Raw                    = $raw
                        }

                        $batteryList.Add([pscustomobject]$batteryEntry) | Out-Null
                    }

                    if ($batteryList.Count -gt 0) {
                        $payload['Batteries'] = $batteryList.ToArray()
                    }
                }

                $lifeRows = $reportNode.SelectNodes('/*[local-name()="BatteryReport"]/*[local-name()="BatteryLifeEstimates"]//*[local-name()="Row"]')
                if ($lifeRows -and $lifeRows.Count -gt 0) {
                    $lifeList = New-Object System.Collections.Generic.List[object]

                    foreach ($row in $lifeRows) {
                        if (-not $row) { continue }

                        $rowData = [ordered]@{}
                        foreach ($child in $row.ChildNodes) {
                            if (-not $child -or $child.NodeType -ne [System.Xml.XmlNodeType]::Element) { continue }
                            $name = [string]$child.LocalName
                            $value = $child.InnerText
                            if ($value) { $value = $value.Trim() }
                            $rowData[$name] = $value
                        }

                        $period = if ($rowData.Contains('Period')) { [string]$rowData['Period'] } else { $null }
                        if (-not $period) {
                            foreach ($key in $rowData.Keys) {
                                if ($key -match 'period' -and $rowData[$key]) { $period = [string]$rowData[$key]; break }
                            }
                        }

                        $atFull = $null
                        foreach ($key in $rowData.Keys) {
                            if ($key -match 'fullcharge') { $atFull = $rowData[$key]; break }
                        }

                        $atDesign = $null
                        foreach ($key in $rowData.Keys) {
                            if ($key -match 'design') { $atDesign = $rowData[$key]; break }
                        }

                        $entry = [ordered]@{
                            Period                   = $period
                            AtFullCharge             = $atFull
                            AtFullChargeMinutes      = Resolve-BatteryTimespanMinutes -Value $atFull
                            AtDesignCapacity         = $atDesign
                            AtDesignCapacityMinutes  = Resolve-BatteryTimespanMinutes -Value $atDesign
                        }

                        $lifeList.Add([pscustomobject]$entry) | Out-Null
                    }

                    if ($lifeList.Count -gt 0) {
                        $payload['LifeEstimates'] = $lifeList.ToArray()

                        $primaryEstimate = $null
                        foreach ($item in $lifeList) {
                            if ($item.Period -and ($item.Period -match 'since' -and $item.Period -match 'os')) {
                                $primaryEstimate = $item
                                break
                            }
                        }
                        if (-not $primaryEstimate) {
                            $primaryEstimate = $lifeList | Select-Object -First 1
                        }

                        if ($primaryEstimate) {
                            $payload['AverageLife'] = [ordered]@{
                                Period                  = $primaryEstimate.Period
                                AtFullCharge            = $primaryEstimate.AtFullCharge
                                AtFullChargeMinutes     = $primaryEstimate.AtFullChargeMinutes
                                AtDesignCapacity        = $primaryEstimate.AtDesignCapacity
                                AtDesignCapacityMinutes = $primaryEstimate.AtDesignCapacityMinutes
                            }
                        }
                    }
                }
            }
        } catch {
            $errors.Add([pscustomobject]@{ Source = 'batteryreport.xml'; Error = $_.Exception.Message }) | Out-Null
        }
    }
} catch {
    $errors.Add([pscustomobject]@{ Source = 'powercfg.exe /batteryreport'; Error = $_.Exception.Message }) | Out-Null
} finally {
    if (Test-Path -Path $tempFile) {
        Remove-Item -Path $tempFile -Force -ErrorAction SilentlyContinue
    }
}

if ($errors.Count -gt 0) {
    $payload['Errors'] = $errors.ToArray()
}

$result = New-CollectorMetadata -Payload $payload
$exportPath = Export-CollectorResult -OutputDirectory $resolvedOutput -FileName 'battery.json' -Data $result

Write-Output $exportPath
