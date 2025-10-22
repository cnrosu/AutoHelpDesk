function Convert-HardwareVideoOutputTechnologyLabel {
    param($Value)

    if ($null -eq $Value) { return $null }

    $code = $null
    try { $code = [int64]$Value } catch { }
    if ($null -eq $code) { return [string]$Value }

    $labels = @{
        0             = 'Other/Unknown'
        1             = 'HD15 (VGA)'
        2             = 'S-Video'
        3             = 'Composite'
        4             = 'Component'
        5             = 'DVI'
        6             = 'HDMI'
        7             = 'LVDS'
        8             = 'D-JPN'
        9             = 'SDI'
        10            = 'DisplayPort'
        11            = 'DisplayPort (embedded)'
        12            = 'UDI'
        13            = 'UDI (embedded)'
        14            = 'SDTV Dongle'
        15            = 'Miracast/Wireless Display'
        2147483648    = 'Internal display'
        2147483649    = 'Display Serial Interface (DSI)'
        2147483650    = 'DisplayPort over USB-C'
    }

    if ($labels.ContainsKey($code)) {
        return "{0} (code {1})" -f $labels[$code], $code
    }

    if ($code -band 0x80000000) {
        return "Internal/embedded technology (code {0})" -f $code
    }

    return "Code {0}" -f $code
}

function Convert-HardwareEdidValue {
    param($Value)

    if ($null -eq $Value) { return $null }

    if ($Value -is [System.Array]) {
        $bytes = New-Object System.Collections.Generic.List[byte]
        foreach ($item in $Value) {
            if ($null -eq $item) { continue }
            try { $bytes.Add([byte]$item) | Out-Null } catch { }
        }

        if ($bytes.Count -eq 0) { return $null }

        $hex = [System.BitConverter]::ToString($bytes.ToArray()).Replace('-', '')
        $asciiChars = New-Object System.Collections.Generic.List[char]
        foreach ($byte in $bytes) {
            if ($byte -ge 32 -and $byte -le 126) {
                $asciiChars.Add([char]$byte) | Out-Null
            }
        }

        $ascii = $null
        if ($asciiChars.Count -gt 0) {
            $ascii = ($asciiChars.ToArray() -join '').Trim([char]0, ' ')
        }

        if (-not [string]::IsNullOrWhiteSpace($ascii)) {
            if (-not [string]::IsNullOrWhiteSpace($hex)) {
                return "{0} (0x{1})" -f $ascii, $hex
            }
            return $ascii
        }

        if (-not [string]::IsNullOrWhiteSpace($hex)) {
            return "0x{0}" -f $hex
        }

        return $null
    }

    return [string]$Value
}

function Invoke-HardwareDriverChecks {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $Context,

        [Parameter(Mandatory)]
        $CategoryResult
    )

    $issueCount = 0

    $msinfoDrivers = Get-MsinfoDriverEntries -Context $Context
    $msinfoDriverCount = if ($msinfoDrivers) { (@($msinfoDrivers | Where-Object { $_ })).Count } else { 0 }

    $driversArtifact = Get-AnalyzerArtifact -Context $Context -Name 'drivers'
    Write-HeuristicDebug -Source 'Hardware' -Message 'Resolved driver artifact' -Data ([ordered]@{
        Found          = [bool]$driversArtifact
        MsinfoDrivers  = $msinfoDriverCount
    })

    if (-not $driversArtifact -and $msinfoDriverCount -eq 0) {
        Add-CategoryIssue -CategoryResult $CategoryResult -Severity 'warning' -Title "Driver inventory artifact missing, so Device Manager issues can't be evaluated." -Subcategory 'Collection'
        $issueCount++
        return [pscustomobject]@{ Completed = $false; IssueCount = $issueCount }
    }

    $payload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $driversArtifact)
    Write-HeuristicDebug -Source 'Hardware' -Message 'Resolved driver payload' -Data ([ordered]@{
        HasPayload = [bool]$payload
    })

    if (-not $payload -and $msinfoDriverCount -eq 0) {
        Add-CategoryIssue -CategoryResult $CategoryResult -Severity 'warning' -Title "Driver inventory payload missing, so Device Manager issues can't be evaluated." -Subcategory 'Collection'
        $issueCount++
        return [pscustomobject]@{ Completed = $false; IssueCount = $issueCount }
    }

    if ($msinfoDriverCount -gt 0) {
        if (-not $payload) { $payload = [pscustomobject][ordered]@{} }
        elseif (-not ($payload -is [pscustomobject])) { $payload = [pscustomobject]$payload }

        if ($payload.PSObject.Properties['DriverQuery']) {
            $payload | Add-Member -NotePropertyName 'LegacyDriverQuery' -NotePropertyValue $payload.DriverQuery -Force
        }

        $payload | Add-Member -NotePropertyName 'DriverQuery' -NotePropertyValue $msinfoDrivers -Force
        $payload | Add-Member -NotePropertyName 'MsinfoDrivers' -NotePropertyValue $msinfoDrivers -Force
    }

    if ($payload.DriverQuery -and $payload.DriverQuery.PSObject.Properties['Error'] -and $payload.DriverQuery.Error) {
        $source = if ($payload.DriverQuery.PSObject.Properties['Source']) { [string]$payload.DriverQuery.Source } else { 'driverquery.exe' }
        $evidence = if ($payload.DriverQuery.Error) { [string]$payload.DriverQuery.Error } else { 'Unknown error' }
        Add-CategoryIssue -CategoryResult $CategoryResult -Severity 'warning' -Title "Driver inventory command failed, so Device Manager issues may be hidden." -Evidence ("{0}: {1}" -f $source, $evidence) -Subcategory 'Collection'
        $issueCount++
        return [pscustomobject]@{ Completed = $false; IssueCount = $issueCount }
    }

    if ($payload.PnpProblems -and $payload.PnpProblems.PSObject.Properties['Error'] -and $payload.PnpProblems.Error) {
        $source = if ($payload.PnpProblems.PSObject.Properties['Source']) { [string]$payload.PnpProblems.Source } else { 'pnputil.exe' }
        $evidence = if ($payload.PnpProblems.Error) { [string]$payload.PnpProblems.Error } else { 'Unknown error' }
        Add-CategoryIssue -CategoryResult $CategoryResult -Severity 'warning' -Title "Problem device inventory command failed, so Device Manager issues may be hidden." -Evidence ("{0}: {1}" -f $source, $evidence) -Subcategory 'Collection'
        $issueCount++
    }

    $inventory = Get-NormalizedDriverInventory -Payload $payload -VerboseLogging
    $entries = if ($inventory -and $inventory.Rows) { $inventory.Rows } else { @() }

    Write-HeuristicDebug -Source 'Hardware' -Message 'Resolved driver inventory' -Data ([ordered]@{
        RowCount = $entries.Count
        Source   = if ($inventory) { $inventory.Source } else { $null }
    })

    if ($entries.Count -eq 0) {
        Write-HeuristicDebug -Source 'Hardware' -Message 'Driver inventory parsing diagnostics' -Data ([ordered]@{
            AvailableProperties = if ($inventory -and $inventory.AvailableProperties -and $inventory.AvailableProperties.Count -gt 0) { $inventory.AvailableProperties -join ', ' } else { $null }
            TextPreview         = if ($inventory -and $inventory.TextPreview) { $inventory.TextPreview } else { $null }
        })
        $hasRawDriverData = $inventory -and ($inventory.HasDriverQueryData -or $inventory.HasTextPayload)
        $title = if ($hasRawDriverData) {
            "Driver inventory could not be parsed, so Device Manager issues may be hidden."
        } else {
            "Driver inventory empty, so Device Manager issues can't be evaluated."
        }
        Add-CategoryIssue -CategoryResult $CategoryResult -Severity 'info' -Title $title -Subcategory 'Collection'
        $issueCount++
        return [pscustomobject]@{ Completed = $false; IssueCount = $issueCount }
    }

    $hasBluetoothDeviceSnapshot = $false
    $bluetoothDevicesPayload = $null
    $bluetoothDeviceRecords = @()
    $bluetoothDeviceError = $null
    $bluetoothDeviceSource = $null
    if ($payload.PSObject.Properties['BluetoothDevices']) {
        $bluetoothDevicesPayload = $payload.BluetoothDevices
        if ($bluetoothDevicesPayload) {
            $hasBluetoothDeviceSnapshot = $true
            $bluetoothDeviceSource = if ($bluetoothDevicesPayload.PSObject.Properties['Source']) { [string]$bluetoothDevicesPayload.Source } else { 'Get-PnpDevice -Class Bluetooth' }
            if ($bluetoothDevicesPayload.PSObject.Properties['Error'] -and $bluetoothDevicesPayload.Error) {
                $bluetoothDeviceError = [string]$bluetoothDevicesPayload.Error
            } elseif ($bluetoothDevicesPayload.PSObject.Properties['Items'] -and $bluetoothDevicesPayload.Items) {
                $bluetoothDeviceRecords = @($bluetoothDevicesPayload.Items | Where-Object { $_ })
            }
        }
    }

    $hasBluetoothServiceSnapshot = $false
    $bluetoothServicePayload = $null
    $bluetoothServiceStatus = $null
    $bluetoothServiceExists = $null
    $bluetoothServiceError = $null
    $bluetoothServiceSource = 'Get-Service'
    if ($payload.PSObject.Properties['BluetoothService']) {
        $bluetoothServicePayload = $payload.BluetoothService
        if ($bluetoothServicePayload) {
            $hasBluetoothServiceSnapshot = $true
            if ($bluetoothServicePayload.PSObject.Properties['Source'] -and $bluetoothServicePayload.Source) {
                $bluetoothServiceSource = [string]$bluetoothServicePayload.Source
            }
            if ($bluetoothServicePayload.PSObject.Properties['Error'] -and $bluetoothServicePayload.Error) {
                $bluetoothServiceError = [string]$bluetoothServicePayload.Error
            }
            if ($bluetoothServicePayload.PSObject.Properties['Status'] -and $bluetoothServicePayload.Status) {
                $bluetoothServiceStatus = ([string]$bluetoothServicePayload.Status).Trim()
            }
            if ($bluetoothServicePayload.PSObject.Properties['Exists']) {
                try { $bluetoothServiceExists = [bool]$bluetoothServicePayload.Exists } catch { $bluetoothServiceExists = $null }
            }
        }
    }

    if (-not $hasBluetoothDeviceSnapshot -and -not $bluetoothDeviceError) {
        $bluetoothDeviceError = 'Bluetooth device snapshot missing from driver collector payload.'
        if (-not $bluetoothDeviceSource) { $bluetoothDeviceSource = 'Get-PnpDevice -Class Bluetooth' }
    }

    if (-not $hasBluetoothServiceSnapshot -and -not $bluetoothServiceError) {
        $bluetoothServiceError = 'Bluetooth service snapshot missing from driver collector payload.'
    }

    $failureEventMap = Get-DriverFailureEventMap -Context $Context
    Write-HeuristicDebug -Source 'Hardware' -Message 'Loaded driver failure event map' -Data ([ordered]@{
        HasEvents = ($failureEventMap -and ($failureEventMap.Count -gt 0))
        Keys      = if ($failureEventMap) { $failureEventMap.Count } else { 0 }
    })

    foreach ($entry in $entries) {
        if (-not $entry) { continue }

        $label = Get-DriverLabel -Entry $entry
        $statusRaw = Get-DriverPropertyValue -Entry $entry -Names @('Status')
        $statusNormalized = Normalize-DriverStatus -Value $statusRaw
        if ($statusNormalized -and $statusNormalized -ne 'ok' -and $statusNormalized -ne 'unknown') {
            $severity = switch ($statusNormalized) {
                'error'    { 'high' }
                'degraded' { 'medium' }
                default    { 'info' }
            }
            $title = if ($statusRaw) {
                "Driver status '{0}' reported for {1}, so the device may malfunction." -f $statusRaw, $label
            } else {
                "Driver status indicates an issue for {0}, so the device may malfunction." -f $label
            }
            Add-CategoryIssue -CategoryResult $CategoryResult -Severity $severity -Title $title -Evidence (Get-DriverEvidence -Entry $entry) -Subcategory 'Device Manager'
            $issueCount++
        }

        $stateRaw = Get-DriverPropertyValue -Entry $entry -Names @('State')
        $startModeRaw = Get-DriverPropertyValue -Entry $entry -Names @('Start Mode','StartMode')
        $stateNormalized = Normalize-DriverState -Value $stateRaw
        $startModeNormalized = Normalize-DriverStartMode -Value $startModeRaw
        $driverTypeRaw = Get-DriverPropertyValue -Entry $entry -Names @('Driver Type','Type','Service Type')
        $driverTypeNormalized = Normalize-DriverType -Value $driverTypeRaw

        $shouldFlagStartIssue = $false
        $failureEvents = @()

        if ($startModeNormalized -in @('boot','system','auto') -and $stateNormalized -ne 'running' -and $stateNormalized -ne 'pending') {
            if ($startModeNormalized -eq 'auto') {
                $shouldFlagStartIssue = $true
            } elseif ($startModeNormalized -in @('boot','system')) {
                if ($driverTypeNormalized -eq 'kernel') {
                    $candidates = Get-DriverNameCandidates -Entry $entry
                    $failureEvents = Find-DriverFailureEvents -Candidates $candidates -Map $failureEventMap
                    if ($failureEvents -and $failureEvents.Count -gt 0) {
                        $shouldFlagStartIssue = $true
                    } else {
                        Write-HeuristicDebug -Source 'Hardware' -Message 'Skipping stopped boot/system kernel driver without corroborating events' -Data ([ordered]@{
                            Driver     = $label
                            StartMode  = $startModeRaw
                            State      = $stateRaw
                            DriverType = $driverTypeRaw
                        })
                    }
                } else {
                    $shouldFlagStartIssue = $true
                }
            }
        }

        if ($shouldFlagStartIssue) {
            $severity = if ($startModeNormalized -in @('boot','system')) { 'high' } else { 'medium' }
            $errorControlRaw = Get-DriverPropertyValue -Entry $entry -Names @('Error Control','ErrorControl')
            $errorControlNormalized = Normalize-DriverErrorControl -Value $errorControlRaw
            if ($errorControlNormalized -eq 'critical') { $severity = 'critical' }

            $title = if ($stateRaw -and $startModeRaw) {
                "Driver {0} is {1} despite start mode {2}, so hardware may not initialize." -f $label, $stateRaw, $startModeRaw
            } elseif ($startModeRaw) {
                "Driver {0} is not running despite start mode {1}, so hardware may not initialize." -f $label, $startModeRaw
            } else {
                "Driver {0} is not running despite an automatic start mode, so hardware may not initialize." -f $label
            }

            $evidenceParts = New-Object System.Collections.Generic.List[string]
            $driverEvidence = Get-DriverEvidence -Entry $entry
            if ($driverEvidence) { $evidenceParts.Add($driverEvidence) | Out-Null }

            if ($failureEvents -and $failureEvents.Count -gt 0) {
                $eventEvidence = Format-DriverFailureEvidence -Events $failureEvents
                if ($eventEvidence) {
                    $evidenceParts.Add("Related events:`n$eventEvidence") | Out-Null
                }
            }

            $evidence = if ($evidenceParts.Count -gt 0) { $evidenceParts.ToArray() -join "`n`n" } else { $null }

            Add-CategoryIssue -CategoryResult $CategoryResult -Severity $severity -Title $title -Evidence $evidence -Subcategory 'Device Manager'
            $issueCount++
        }
    }

    $pnpText = ConvertTo-HardwareDriverText -Value $payload.PnpProblems
    Write-HeuristicDebug -Source 'Hardware' -Message 'Problem device text resolved' -Data ([ordered]@{
        HasText = [bool]$pnpText
        Length  = if ($pnpText) { $pnpText.Length } else { 0 }
    })

    $pnpEntries = @()
    if ($pnpText) {
        $pnpEntries = Parse-DriverQueryEntries -Text $pnpText
        Write-HeuristicDebug -Source 'Hardware' -Message 'Parsed problem device entries' -Data ([ordered]@{
            EntryCount = $pnpEntries.Count
        })

        foreach ($entry in $pnpEntries) {
            if (-not $entry) { continue }

            $code = Get-DriverPropertyValue -Entry $entry -Names @('Problem Code','ProblemCode','Problem')
            $normalized = Normalize-DriverProblemCode -Value $code
            if (-not $normalized -or $normalized -eq 'none') { continue }

            $label = Get-DriverLabel -Entry $entry
            $className = Get-DriverPropertyValue -Entry $entry -Names @('Class Name','ClassName','Class')
            $description = Get-DriverPropertyValue -Entry $entry -Names @('Device Description','Friendly Name','Name')
            $instanceId = Get-DriverPropertyValue -Entry $entry -Names @('Instance ID','InstanceId','Device Instance ID')
            $isBluetoothDevice = $false
            foreach ($candidate in @($className, $label, $description, $instanceId)) {
                if (-not $candidate) { continue }
                if (Test-BluetoothIndicator -Value $candidate) {
                    $isBluetoothDevice = $true
                    break
                }
            }
            if ($normalized -eq 'missing-driver') {
                if ($isBluetoothDevice) { continue }
                $title = "Device {0} is missing drivers (Code 28), so functionality may be limited." -f $label
                Add-CategoryIssue -CategoryResult $CategoryResult -Severity 'medium' -Title $title -Evidence (Get-PnpDeviceEvidence -Entry $entry) -Subcategory 'Device Manager'
                $issueCount++
                continue
            }

            if ($normalized -eq 'problem') {
                if ($isBluetoothDevice) { continue }
                $title = "Device Manager reports a problem for {0}." -f $label
                Add-CategoryIssue -CategoryResult $CategoryResult -Severity 'info' -Title $title -Evidence (Get-PnpDeviceEvidence -Entry $entry) -Subcategory 'Device Manager'
                $issueCount++
            }
        }
    }

    $billboardSnapshot = $null
    $billboardRecords = @()
    $billboardError = $null
    $billboardSource = "Get-PnpDevice -FriendlyName '*Billboard*'"
    if ($payload.PSObject.Properties['BillboardDevices']) {
        $billboardSnapshot = $payload.BillboardDevices
        if ($billboardSnapshot) {
            if ($billboardSnapshot.PSObject.Properties['Source'] -and $billboardSnapshot.Source) {
                $billboardSource = [string]$billboardSnapshot.Source
            }
            if ($billboardSnapshot.PSObject.Properties['Items'] -and $billboardSnapshot.Items) {
                $billboardRecords = @($billboardSnapshot.Items | Where-Object { $_ })
            }
            if ($billboardSnapshot.PSObject.Properties['Error'] -and $billboardSnapshot.Error) {
                $billboardError = [string]$billboardSnapshot.Error
            }
        }
    }

    $dockSnapshot = $null
    $dockRecords = @()
    $dockError = $null
    $dockSource = "Get-PnpDevice -Class 'System','USB','Net' (dock filter)"
    if ($payload.PSObject.Properties['DockDevices']) {
        $dockSnapshot = $payload.DockDevices
        if ($dockSnapshot) {
            if ($dockSnapshot.PSObject.Properties['Source'] -and $dockSnapshot.Source) {
                $dockSource = [string]$dockSnapshot.Source
            }
            if ($dockSnapshot.PSObject.Properties['Items'] -and $dockSnapshot.Items) {
                $dockRecords = @($dockSnapshot.Items | Where-Object { $_ })
            }
            if ($dockSnapshot.PSObject.Properties['Error'] -and $dockSnapshot.Error) {
                $dockError = [string]$dockSnapshot.Error
            }
        }
    }

    $transportSnapshot = $null
    $transportRecords = @()
    $transportError = $null
    $transportSource = 'Get-CimInstance -Namespace root\wmi -ClassName WmiMonitorConnectionParams'
    if ($payload.PSObject.Properties['DisplayTransports']) {
        $transportSnapshot = $payload.DisplayTransports
        if ($transportSnapshot) {
            if ($transportSnapshot.PSObject.Properties['Source'] -and $transportSnapshot.Source) {
                $transportSource = [string]$transportSnapshot.Source
            }
            if ($transportSnapshot.PSObject.Properties['Items'] -and $transportSnapshot.Items) {
                $transportRecords = @($transportSnapshot.Items | Where-Object { $_ })
            }
            if ($transportSnapshot.PSObject.Properties['Error'] -and $transportSnapshot.Error) {
                $transportError = [string]$transportSnapshot.Error
            }
        }
    }

    $monitorSnapshot = $null
    $monitorRecords = @()
    $monitorError = $null
    $monitorSource = 'Get-CimInstance -Namespace root\wmi -ClassName WmiMonitorID'
    if ($payload.PSObject.Properties['MonitorIdentities']) {
        $monitorSnapshot = $payload.MonitorIdentities
        if ($monitorSnapshot) {
            if ($monitorSnapshot.PSObject.Properties['Source'] -and $monitorSnapshot.Source) {
                $monitorSource = [string]$monitorSnapshot.Source
            }
            if ($monitorSnapshot.PSObject.Properties['Items'] -and $monitorSnapshot.Items) {
                $monitorRecords = @($monitorSnapshot.Items | Where-Object { $_ })
            }
            if ($monitorSnapshot.PSObject.Properties['Error'] -and $monitorSnapshot.Error) {
                $monitorError = [string]$monitorSnapshot.Error
            }
        }
    }

    if ($billboardRecords.Count -gt 0) {
        $evidenceLines = New-Object System.Collections.Generic.List[string]
        $evidenceLines.Add("Billboard device snapshot ($billboardSource):") | Out-Null
        foreach ($record in $billboardRecords) {
            if (-not $record) { continue }

            $name = if ($record.PSObject.Properties['FriendlyName'] -and $record.FriendlyName) { [string]$record.FriendlyName } elseif ($record.PSObject.Properties['Class'] -and $record.Class) { [string]$record.Class } else { 'Billboard device' }
            $line = "- $name"
            $detailParts = New-Object System.Collections.Generic.List[string]

            if ($record.PSObject.Properties['InstanceId'] -and $record.InstanceId) { $detailParts.Add("InstanceId=$([string]$record.InstanceId)") | Out-Null }
            if ($record.PSObject.Properties['Class'] -and $record.Class) { $detailParts.Add("Class=$([string]$record.Class)") | Out-Null }
            if ($record.PSObject.Properties['Manufacturer'] -and $record.Manufacturer) { $detailParts.Add("Manufacturer=$([string]$record.Manufacturer)") | Out-Null }
            if ($record.PSObject.Properties['Status'] -and $record.Status) { $detailParts.Add("Status=$([string]$record.Status)") | Out-Null }
            if ($record.PSObject.Properties['Present'] -and $record.Present -ne $null) { $detailParts.Add("Present=$([bool]$record.Present)") | Out-Null }
            if ($record.PSObject.Properties['ProblemCode'] -and $record.ProblemCode -ne $null -and $record.ProblemCode -ne '') { $detailParts.Add("ProblemCode=$([string]$record.ProblemCode)") | Out-Null }

            if ($detailParts.Count -gt 0) {
                $line += " — {0}" -f ($detailParts.ToArray() -join '; ')
            }

            $evidenceLines.Add($line) | Out-Null
        }

        if ($dockSnapshot) {
            if ($dockError) {
                $evidenceLines.Add("Dock detection failed ($dockSource): $dockError") | Out-Null
            } elseif ($dockRecords.Count -gt 0) {
                $evidenceLines.Add("Dock/thunderbolt/USB4 devices ($dockSource):") | Out-Null
                foreach ($dock in $dockRecords) {
                    if (-not $dock) { continue }

                    $dockName = if ($dock.PSObject.Properties['FriendlyName'] -and $dock.FriendlyName) { [string]$dock.FriendlyName } elseif ($dock.PSObject.Properties['Class'] -and $dock.Class) { [string]$dock.Class } else { 'Device' }
                    $dockLine = "- $dockName"
                    $dockDetails = New-Object System.Collections.Generic.List[string]
                    if ($dock.PSObject.Properties['InstanceId'] -and $dock.InstanceId) { $dockDetails.Add("InstanceId=$([string]$dock.InstanceId)") | Out-Null }
                    if ($dock.PSObject.Properties['Class'] -and $dock.Class) { $dockDetails.Add("Class=$([string]$dock.Class)") | Out-Null }
                    if ($dock.PSObject.Properties['Status'] -and $dock.Status) { $dockDetails.Add("Status=$([string]$dock.Status)") | Out-Null }
                    if ($dockDetails.Count -gt 0) { $dockLine += " — {0}" -f ($dockDetails.ToArray() -join '; ') }
                    $evidenceLines.Add($dockLine) | Out-Null
                }
            } else {
                $evidenceLines.Add("Dock/thunderbolt/USB4 devices ($dockSource): None detected") | Out-Null
            }
        }

        if ($transportSnapshot) {
            if ($transportError) {
                $evidenceLines.Add("Display transport query failed ($transportSource): $transportError") | Out-Null
            } elseif ($transportRecords.Count -gt 0) {
                $evidenceLines.Add("Active display transports ($transportSource):") | Out-Null
                foreach ($transport in $transportRecords) {
                    if (-not $transport) { continue }

                    $instanceName = if ($transport.PSObject.Properties['InstanceName'] -and $transport.InstanceName) { [string]$transport.InstanceName } else { 'Unknown connection' }
                    $techValue = $null
                    if ($transport.PSObject.Properties['VideoOutputTechnology']) { $techValue = $transport.VideoOutputTechnology }
                    $techLabel = Convert-HardwareVideoOutputTechnologyLabel -Value $techValue
                    if (-not $techLabel) { $techLabel = if ($null -ne $techValue) { "Code $techValue" } else { 'Unknown' } }
                    $evidenceLines.Add("- Instance: {0}; Technology: {1}" -f $instanceName, $techLabel) | Out-Null
                }
            } else {
                $evidenceLines.Add("Active display transports ($transportSource): None reported") | Out-Null
            }
        }

        if ($monitorSnapshot) {
            if ($monitorError) {
                $evidenceLines.Add("Monitor identity query failed ($monitorSource): $monitorError") | Out-Null
            } elseif ($monitorRecords.Count -gt 0) {
                $evidenceLines.Add("Monitor EDIDs ($monitorSource):") | Out-Null
                foreach ($monitor in $monitorRecords) {
                    if (-not $monitor) { continue }

                    $instanceName = if ($monitor.PSObject.Properties['InstanceName'] -and $monitor.InstanceName) { [string]$monitor.InstanceName } else { 'Monitor' }
                    $monitorDetails = New-Object System.Collections.Generic.List[string]

                    if ($monitor.PSObject.Properties['ManufacturerName']) {
                        $manufacturerValue = Convert-HardwareEdidValue -Value $monitor.ManufacturerName
                        if ($manufacturerValue) { $monitorDetails.Add("Manufacturer=$manufacturerValue") | Out-Null }
                    }
                    if ($monitor.PSObject.Properties['ProductCodeID']) {
                        $productValue = Convert-HardwareEdidValue -Value $monitor.ProductCodeID
                        if ($productValue) { $monitorDetails.Add("ProductCode=$productValue") | Out-Null }
                    }
                    if ($monitor.PSObject.Properties['SerialNumberID']) {
                        $serialValue = Convert-HardwareEdidValue -Value $monitor.SerialNumberID
                        if ($serialValue) { $monitorDetails.Add("Serial=$serialValue") | Out-Null }
                    }

                    $line = "- Instance: {0}" -f $instanceName
                    if ($monitorDetails.Count -gt 0) {
                        $line += " — {0}" -f ($monitorDetails.ToArray() -join '; ')
                    }

                    $evidenceLines.Add($line) | Out-Null
                }
            } else {
                $evidenceLines.Add("Monitor EDIDs ($monitorSource): None reported") | Out-Null
            }
        }

        $evidence = $null
        if ($evidenceLines.Count -gt 0) {
            $evidence = $evidenceLines.ToArray() -join "`n"
        }

        $title = 'USB Billboard device detected, so DisplayPort alternate mode may have failed.'
        $remediation = 'Check the USB-C cable or dock, reseat the connection, install any dock firmware or graphics driver updates, or connect the display directly to restore video output.'

        Add-CategoryIssue -CategoryResult $CategoryResult -Severity 'warning' -Title $title -Evidence $evidence -Subcategory 'Display' -Remediation $remediation
        $issueCount++
    } elseif ($billboardError) {
        $evidence = "{0}: {1}" -f $billboardSource, $billboardError
        $remediation = @'
**Symptoms:** Driver inventory missing or failed, problem devices, Bluetooth gaps, or USB-C billboard query failed.

**Fix**

```powershell
# Rebuild driver inventory & attempt inbox updates
pnputil /scan-devices

# Optional: try Windows Update driver
Get-PnpDevice | Where Status -ne 'OK' | ForEach-Object { pnputil /disable-device $_.InstanceId; pnputil /enable-device $_.InstanceId }

# Bluetooth service baseline
Set-Service bthserv -StartupType Automatic
Restart-Service bthserv
```

**Policy:** Prefer vendor-provided drivers via WUfB for Drivers or Intune Driver Updates (modern).
'@
        Add-CategoryIssue -CategoryResult $CategoryResult -Severity 'info' -Title 'Billboard device query failed, so USB-C display diagnostics are incomplete.' -Evidence $evidence -Subcategory 'Display' -Remediation $remediation
        $issueCount++
    }

    Write-HeuristicDebug -Source 'Hardware/Bluetooth' -Message 'Bluetooth snapshot summary' -Data ([ordered]@{
        DeviceSnapshotPresent  = $hasBluetoothDeviceSnapshot
        DeviceRecordCount      = $bluetoothDeviceRecords.Count
        DeviceErrorPresent     = [bool]$bluetoothDeviceError
        ServiceSnapshotPresent = $hasBluetoothServiceSnapshot
        ServiceStatus          = $bluetoothServiceStatus
        ServiceExists          = $bluetoothServiceExists
        ServiceErrorPresent    = [bool]$bluetoothServiceError
    })

    $bluetoothCanEvaluate = $true
    if ($bluetoothDeviceError) {
        $title = 'Bluetooth hardware query failed, so wireless accessory health could not be evaluated automatically.'
        $evidence = "{0}: {1}" -f $bluetoothDeviceSource, $bluetoothDeviceError
        Add-CategoryIssue -CategoryResult $CategoryResult -Severity 'info' -Title $title -Evidence $evidence -Subcategory 'Bluetooth'
        $issueCount++
        $bluetoothCanEvaluate = $false
    }

    if ($bluetoothServiceError) {
        $title = 'Bluetooth service snapshot missing, so technicians cannot confirm if wireless accessories will work.'
        $evidence = "{0}: {1}" -f $bluetoothServiceSource, $bluetoothServiceError
        Add-CategoryIssue -CategoryResult $CategoryResult -Severity 'info' -Title $title -Evidence $evidence -Subcategory 'Bluetooth'
        $issueCount++
        $bluetoothCanEvaluate = $false
    }

    if ($bluetoothCanEvaluate) {
        $bluetoothPnPRecords = @()
        if ($bluetoothDeviceRecords.Count -gt 0) {
            $bluetoothPnPRecords = @(
                $bluetoothDeviceRecords |
                    Where-Object {
                        if (-not $_) { return $false }
                        $classValue = $null
                        if ($_.PSObject.Properties['Class'] -and $null -ne $_.Class) {
                            $classValue = ([string]$_.Class).Trim()
                        }
                        return $classValue -and ($classValue -ieq 'Bluetooth')
                    }
            )
        }

        $usbBluetoothEntries = @()
        if ($bluetoothPnPRecords.Count -gt 0) {
            $usbBluetoothEntries = @($bluetoothPnPRecords | Where-Object { $_.InstanceId -and ($_.InstanceId -like 'USB\\VID*') })
        }

        $healthyDeviceNames = @()
        $radioDetails = @()
        $vendorOk = @()
        $vendorIssues = @()
        $enumeratorOk = @()
        $enumeratorIssues = @()
        $panDeviceNames = @()

        $vendorPattern = '(?i)(Intel|Qualcomm|Realtek|MediaTek|Broadcom|Adapter|Radio)'
        $enumeratorPattern = '(?i)Enumerator'
        $bluetoothKeywordPattern = '(?i)Bluetooth'

        foreach ($device in $bluetoothPnPRecords) {
            $statusNormalized = if ($device.Status) { ([string]$device.Status).Trim() } else { $null }
            $problemCodeValue = $null
            if ($device.PSObject.Properties['ProblemCode']) { $problemCodeValue = $device.ProblemCode }

            $problemActive = $false
            if ($null -ne $problemCodeValue) {
                try {
                    if ([int]$problemCodeValue -ne 0) { $problemActive = $true }
                } catch {
                    if ($problemCodeValue -ne '0') { $problemActive = $true }
                }
            }

            $isHealthyDevice = $statusNormalized -and ($statusNormalized -ieq 'OK') -and -not $problemActive

            $name = $device | Get-DeviceDisplayName
            if ($isHealthyDevice) { $healthyDeviceNames += $name }

            if ($name -match '(?i)personal area network') { $panDeviceNames += $name }

            if (-not ($name -match $bluetoothKeywordPattern)) { continue }

            $classification = $null
            if ($name -match $vendorPattern) {
                $classification = 'Vendor'
            } elseif ($name -match $enumeratorPattern) {
                $classification = 'Enumerator'
            } else {
                continue
            }

            $detail = [pscustomobject]@{
                Name           = $name
                Status         = if ($statusNormalized) { $statusNormalized } else { 'Unknown' }
                ProblemCode    = if ($null -ne $problemCodeValue) { [string]$problemCodeValue } else { $null }
                Classification = $classification
                Healthy        = $isHealthyDevice
                ProblemActive  = $problemActive
            }

            $radioDetails += $detail

            if ($classification -eq 'Vendor') {
                if ($detail.Healthy) { $vendorOk += $detail } else { $vendorIssues += $detail }
            } else {
                if ($detail.Healthy) { $enumeratorOk += $detail } else { $enumeratorIssues += $detail }
            }
        }

        $radioOkCount = ($vendorOk.Count + $enumeratorOk.Count)
        $radioIssueCount = ($vendorIssues.Count + $enumeratorIssues.Count)
        $hasRadio = ($vendorOk.Count -gt 0) -or (($vendorOk.Count -eq 0) -and ($enumeratorOk.Count -gt 0))

        $serviceRunning = $bluetoothServiceStatus -and ($bluetoothServiceStatus -ieq 'Running')
        $serviceKnown = (($bluetoothServiceStatus -ne $null) -and ($bluetoothServiceStatus -ne '')) -or ($bluetoothServiceExists -ne $null)

        $formatList = {
            param($values)
            $buffer = @()
            foreach ($value in @($values)) {
                if ($null -eq $value) { continue }
                $text = [string]$value
                if ([string]::IsNullOrWhiteSpace($text)) { continue }
                $trimmed = $text.Trim()
                if (-not $trimmed) { continue }
                if ($buffer -notcontains $trimmed) { $buffer += $trimmed }
            }
            if ($buffer.Count -eq 0) { return 'None' }
            return ($buffer -join '; ')
        }

        $radioFocus = @()
        if ($vendorOk.Count -gt 0) {
            $radioFocus = $vendorOk
        } elseif ($enumeratorOk.Count -gt 0) {
            $radioFocus = $enumeratorOk
        } elseif ($vendorIssues.Count -gt 0) {
            $radioFocus = $vendorIssues
        } elseif ($enumeratorIssues.Count -gt 0) {
            $radioFocus = $enumeratorIssues
        }

        $healthySummary = & $formatList $healthyDeviceNames
        $radioSummary = & $formatList ($radioFocus | ForEach-Object { $_.Name })
        $enumeratorSummary = & $formatList ((@($enumeratorOk) + @($enumeratorIssues)) | ForEach-Object { $_.Name })

        $serviceDisplay = if ($bluetoothServiceExists -eq $false) { 'Not Found' } elseif ($serviceKnown) { if ($bluetoothServiceStatus) { $bluetoothServiceStatus } else { 'Unknown' } } else { 'Unknown' }

        $panSummary = if ($panDeviceNames.Count -gt 0) { "Yes ($(& $formatList $panDeviceNames))" } else { 'No' }

        $evidenceLines = New-Object System.Collections.Generic.List[string]
        $evidenceLines.Add("PnP Bluetooth devices reporting OK: $healthySummary") | Out-Null
        $evidenceLines.Add("Likely radio or enumerator matches: $radioSummary") | Out-Null
        $evidenceLines.Add("Bluetooth enumerators detected: $enumeratorSummary") | Out-Null
        $evidenceLines.Add("Bluetooth PAN device present: $panSummary") | Out-Null
        $evidenceLines.Add("Bluetooth Support Service (bthserv) status: $serviceDisplay") | Out-Null
        $evidenceLines.Add("USB Bluetooth radios detected: $($usbBluetoothEntries.Count)") | Out-Null

        if ($radioDetails.Count -gt 0) {
            $evidenceLines.Add('Radio/enumerator status:') | Out-Null
            foreach ($detail in $radioDetails) {
                $role = if ($detail.Classification -eq 'Enumerator') { 'Enumerator' } else { 'Radio' }
                $statusText = if ($detail.Status) { $detail.Status } else { 'Unknown' }
                $line = "- $($detail.Name) ($role) — Status: $statusText"
                if ($detail.ProblemActive -and $detail.ProblemCode) { $line += "; ProblemCode: $($detail.ProblemCode)" }
                $evidenceLines.Add($line) | Out-Null
            }
        }

        $evidence = if ($evidenceLines.Count -gt 0) { $evidenceLines.ToArray() -join "`n" } else { $null }

        Write-HeuristicDebug -Source 'Hardware/Bluetooth' -Message 'Bluetooth detection metrics' -Data ([ordered]@{
            PnpRecordCount        = $bluetoothPnPRecords.Count
            HealthyPnpCount       = $healthyDeviceNames.Count
            VendorOkCount         = $vendorOk.Count
            VendorIssueCount      = $vendorIssues.Count
            EnumeratorOkCount     = $enumeratorOk.Count
            EnumeratorIssueCount  = $enumeratorIssues.Count
            RadioOkCount          = $radioOkCount
            UsbRadioCount         = $usbBluetoothEntries.Count
            ServiceStatus         = $bluetoothServiceStatus
        })

        if (-not $hasRadio) {
            Add-CategoryIssue -CategoryResult $CategoryResult -Severity 'warning' -Title 'Bluetooth adapter not detected, so wireless accessories cannot pair.' -Evidence $evidence -Subcategory 'Bluetooth' -Remediation 'Install or enable the Bluetooth radio, restart the Bluetooth Support Service, or [Open Troubleshoot settings](ms-settings:troubleshoot) to run the Bluetooth troubleshooter and let Windows repair the stack.'
            $issueCount++
        } elseif ($radioIssueCount -gt 0) {
            Add-CategoryIssue -CategoryResult $CategoryResult -Severity 'high' -Title 'Bluetooth adapter detected but reports errors, so wireless accessories cannot pair.' -Evidence $evidence -Subcategory 'Bluetooth' -Remediation 'Update or reinstall the Bluetooth drivers, restart the Bluetooth Support Service, or [Open Troubleshoot settings](ms-settings:troubleshoot) to run the Bluetooth troubleshooter and let Windows repair the stack.'
            $issueCount++
        } elseif (-not $serviceRunning) {
            Add-CategoryIssue -CategoryResult $CategoryResult -Severity 'high' -Title 'Bluetooth adapter detected but support service is not running, so wireless accessories cannot pair.' -Evidence $evidence -Subcategory 'Bluetooth' -Remediation 'Start the Bluetooth Support Service, confirm the adapter stays running, or [Open Troubleshoot settings](ms-settings:troubleshoot) to run the Bluetooth troubleshooter and let Windows repair the stack.'
            $issueCount++
        } else {
            Add-CategoryNormal -CategoryResult $CategoryResult -Title 'Bluetooth adapter detected and appears to be working normally.' -Subcategory 'Bluetooth'
        }
    }

    Write-HeuristicDebug -Source 'Hardware' -Message 'Device Manager analysis completed' -Data ([ordered]@{
        IssuesRaised = $issueCount
    })

    return [pscustomobject]@{
        Completed  = $true
        IssueCount = $issueCount
    }
}
