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
        Add-CategoryIssue -CategoryResult $CategoryResult -Severity 'info' -Title "Driver inventory artifact missing, so Device Manager issues can't be evaluated." -Subcategory 'Collection'
        $issueCount++
        return [pscustomobject]@{ Completed = $false; IssueCount = $issueCount }
    }

    $payload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $driversArtifact)
    Write-HeuristicDebug -Source 'Hardware' -Message 'Resolved driver payload' -Data ([ordered]@{
        HasPayload = [bool]$payload
    })

    if (-not $payload -and $msinfoDriverCount -eq 0) {
        Add-CategoryIssue -CategoryResult $CategoryResult -Severity 'info' -Title "Driver inventory payload missing, so Device Manager issues can't be evaluated." -Subcategory 'Collection'
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
        Add-CategoryIssue -CategoryResult $CategoryResult -Severity 'info' -Title "Driver inventory command failed, so Device Manager issues may be hidden." -Evidence ("{0}: {1}" -f $source, $evidence) -Subcategory 'Collection'
        $issueCount++
        return [pscustomobject]@{ Completed = $false; IssueCount = $issueCount }
    }

    if ($payload.PnpProblems -and $payload.PnpProblems.PSObject.Properties['Error'] -and $payload.PnpProblems.Error) {
        $source = if ($payload.PnpProblems.PSObject.Properties['Source']) { [string]$payload.PnpProblems.Source } else { 'pnputil.exe' }
        $evidence = if ($payload.PnpProblems.Error) { [string]$payload.PnpProblems.Error } else { 'Unknown error' }
        Add-CategoryIssue -CategoryResult $CategoryResult -Severity 'info' -Title "Problem device inventory command failed, so Device Manager issues may be hidden." -Evidence ("{0}: {1}" -f $source, $evidence) -Subcategory 'Collection'
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
        $radioCandidates = @()
        if ($bluetoothDeviceRecords.Count -gt 0) {
            $radioCandidates = @($bluetoothDeviceRecords | Where-Object { $_.InstanceId -and ($_.InstanceId -like 'USB\\VID*') })
        }

        $radiosOk = @()
        $radiosWithIssues = @()
        foreach ($radio in $radioCandidates) {
            $statusValue = if ($radio.Status) { [string]$radio.Status } else { 'Unknown' }
            if ($statusValue -eq 'OK') {
                $radiosOk += $radio
                continue
            }
            if ($statusValue -in @('Error','Degraded')) {
                $radiosWithIssues += $radio
            }
        }

        $serviceRunning = $bluetoothServiceStatus -eq 'Running'
        $serviceKnown = ($bluetoothServiceStatus -ne $null -and $bluetoothServiceStatus -ne '') -or ($bluetoothServiceExists -ne $null)

        $evidenceLines = New-Object System.Collections.Generic.List[string]
        $serviceDisplay = if ($bluetoothServiceExists -eq $false) { 'Not Found' } elseif ($serviceKnown) { if ($bluetoothServiceStatus) { $bluetoothServiceStatus } else { 'Unknown' } } else { 'Unknown' }
        $evidenceLines.Add("Bluetooth Support Service (bthserv) status: $serviceDisplay") | Out-Null
        $evidenceLines.Add("USB Bluetooth radios detected: $($radioCandidates.Count)") | Out-Null

        foreach ($radio in $radioCandidates) {
            $name = $radio | Get-DeviceDisplayName
            $statusText = if ($radio.Status) { [string]$radio.Status } else { 'Unknown' }
            $evidenceLines.Add("- $name — Status: $statusText") | Out-Null
        }

        $evidence = if ($evidenceLines.Count -gt 0) { $evidenceLines.ToArray() -join "`n" } else { $null }

        if ($radioCandidates.Count -eq 0) {
            Add-CategoryIssue -CategoryResult $CategoryResult -Severity 'warning' -Title 'Bluetooth adapter not detected, so wireless accessories cannot pair.' -Evidence $evidence -Subcategory 'Bluetooth' -Remediation 'Install or enable the Bluetooth radio, restart the Bluetooth Support Service, or [Run Bluetooth troubleshooter](ms-msdt:?id=BluetoothDiagnostic) to let Windows repair the stack.'
            $issueCount++
        } elseif ($radiosOk.Count -eq 0 -or $radiosWithIssues.Count -gt 0) {
            Add-CategoryIssue -CategoryResult $CategoryResult -Severity 'high' -Title 'Bluetooth adapter detected but reports errors, so wireless accessories cannot pair.' -Evidence $evidence -Subcategory 'Bluetooth' -Remediation 'Update or reinstall the Bluetooth drivers, restart the Bluetooth Support Service, or [Run Bluetooth troubleshooter](ms-msdt:?id=BluetoothDiagnostic) to let Windows repair the stack.'
            $issueCount++
        } elseif (-not $serviceRunning) {
            Add-CategoryIssue -CategoryResult $CategoryResult -Severity 'high' -Title 'Bluetooth adapter detected but support service is not running, so wireless accessories cannot pair.' -Evidence $evidence -Subcategory 'Bluetooth' -Remediation 'Start the Bluetooth Support Service, confirm the adapter stays running, or [Run Bluetooth troubleshooter](ms-msdt:?id=BluetoothDiagnostic) to let Windows repair the stack.'
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
