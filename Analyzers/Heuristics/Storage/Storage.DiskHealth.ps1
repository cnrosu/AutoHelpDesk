function Invoke-StorageDiskHealthEvaluation {
    param(
        [Parameter(Mandatory)]
        $CategoryResult,
        $Payload
    )

    $diskEntries = @()
    if ($Payload -and $Payload.PSObject.Properties['Disks']) {
        $diskEntries = ConvertTo-StorageArray $Payload.Disks | Where-Object {
            $_ -and -not ($_ -is [string]) -and $_.PSObject.Properties['HealthStatus']
        }
    }

    Write-HeuristicDebug -Source 'Storage' -Message 'Disk entries resolved' -Data ([ordered]@{
        DiskCount = $diskEntries.Count
    })

    if ($diskEntries.Count -gt 0) {
        $unhealthy = $diskEntries | Where-Object { $_.HealthStatus -and $_.HealthStatus -ne 'Healthy' }
        if ($unhealthy.Count -gt 0) {
            $evidenceLines = [System.Collections.Generic.List[string]]::new()
            $diskData = [System.Collections.Generic.List[object]]::new()

            foreach ($disk in $unhealthy) {
                $operationalStatus = $null
                if ($disk.PSObject.Properties['OperationalStatus']) {
                    if ($disk.OperationalStatus -is [System.Collections.IEnumerable] -and -not ($disk.OperationalStatus -is [string])) {
                        $operationalStatus = ($disk.OperationalStatus | Where-Object { $_ }) -join ', '
                    } else {
                        $operationalStatus = [string]$disk.OperationalStatus
                    }
                }

                $summaryLine = "Disk {0}: {1}" -f $disk.Number, $disk.HealthStatus
                if (-not [string]::IsNullOrWhiteSpace($operationalStatus)) {
                    $summaryLine = "$summaryLine ($operationalStatus)"
                }
                $null = $evidenceLines.Add($summaryLine)

                $diskInfo = [ordered]@{
                    Number             = if ($disk.PSObject.Properties['Number']) { [int]$disk.Number } else { $null }
                    Model              = if ($disk.PSObject.Properties['Model']) { [string]$disk.Model } else { $null }
                    Firmware           = if ($disk.PSObject.Properties['FirmwareVersion']) { [string]$disk.FirmwareVersion } elseif ($disk.PSObject.Properties['Firmware']) { [string]$disk.Firmware } else { $null }
                    MediaType          = if ($disk.PSObject.Properties['MediaType']) { [string]$disk.MediaType } else { $null }
                    PredictiveFailure  = if ($disk.PSObject.Properties['PredictiveFailure']) { [bool]$disk.PredictiveFailure } else { $false }
                    ReallocatedSectors = if ($disk.PSObject.Properties['ReallocatedSectorsCount']) { [int]$disk.ReallocatedSectorsCount } elseif ($disk.PSObject.Properties['ReallocatedSectors']) { [int]$disk.ReallocatedSectors } else { $null }
                    TemperatureC       = if ($disk.PSObject.Properties['TemperatureC']) { [double]$disk.TemperatureC } elseif ($disk.PSObject.Properties['Temperature']) { [double]$disk.Temperature } else { $null }
                    SerialNumber       = if ($disk.PSObject.Properties['SerialNumber']) { [string]$disk.SerialNumber } else { $null }
                    HealthStatus       = if ($disk.PSObject.Properties['HealthStatus']) { [string]$disk.HealthStatus } else { $null }
                    OperationalStatus  = $operationalStatus
                }

                $diskObject = [pscustomobject]$diskInfo
                $diskData.Add($diskObject) | Out-Null

                $modelText = if ($diskObject.PSObject.Properties['Model'] -and -not [string]::IsNullOrWhiteSpace($diskObject.Model)) { $diskObject.Model } else { 'Unknown' }
                $firmwareText = if ($diskObject.PSObject.Properties['Firmware'] -and -not [string]::IsNullOrWhiteSpace($diskObject.Firmware)) { $diskObject.Firmware } else { 'Unknown' }
                $mediaTypeText = if ($diskObject.PSObject.Properties['MediaType'] -and -not [string]::IsNullOrWhiteSpace($diskObject.MediaType)) { $diskObject.MediaType } else { 'Unknown' }
                $serialText = if ($diskObject.PSObject.Properties['SerialNumber'] -and -not [string]::IsNullOrWhiteSpace($diskObject.SerialNumber)) { $diskObject.SerialNumber } else { 'Unavailable' }

                $null = $evidenceLines.Add(("  Model: {0}" -f $modelText))
                $null = $evidenceLines.Add(("  Firmware: {0}" -f $firmwareText))
                $null = $evidenceLines.Add(("  Media Type: {0}" -f $mediaTypeText))
                $null = $evidenceLines.Add(("  Predictive Failure Reported: {0}" -f $diskObject.PredictiveFailure))

                if ($diskObject.PSObject.Properties['ReallocatedSectors'] -and $null -ne $diskObject.ReallocatedSectors) {
                    $null = $evidenceLines.Add(("  Reallocated Sectors: {0}" -f $diskObject.ReallocatedSectors))
                }

                if ($diskObject.PSObject.Properties['TemperatureC'] -and $null -ne $diskObject.TemperatureC) {
                    $null = $evidenceLines.Add(("  Temperature (C): {0}" -f $diskObject.TemperatureC))
                }

                $null = $evidenceLines.Add(("  Serial Number: {0}" -f $serialText))
                if ($diskObject.PSObject.Properties['OperationalStatus'] -and -not [string]::IsNullOrWhiteSpace($diskObject.OperationalStatus)) {
                    $null = $evidenceLines.Add(("  Operational Status: {0}" -f $diskObject.OperationalStatus))
                }
                if ($diskObject.PSObject.Properties['HealthStatus'] -and -not [string]::IsNullOrWhiteSpace($diskObject.HealthStatus)) {
                    $null = $evidenceLines.Add(("  Health Status: {0}" -f $diskObject.HealthStatus))
                }

                $null = $evidenceLines.Add('')
            }

            if ($diskData.Count -gt 0) {
                $null = $evidenceLines.Add('--- SMART dataset (JSON) ---')
                $diskJson = $diskData.ToArray() | ConvertTo-Json -Depth 6
                foreach ($line in $diskJson -split "`n") {
                    $null = $evidenceLines.Add($line)
                }
            }

            $explanation = 'SMART data for affected disks is included below so technicians can review the full diagnostic dataset.'

            Add-CategoryIssue -CategoryResult $CategoryResult -Severity 'high' -Title 'Disks reporting degraded health, indicating failing disks.' -Evidence $evidenceLines -Explanation $explanation -Subcategory 'Disk Health' -Remediation $script:StorageHealthAndSpaceRemediation -Area 'Storage/DiskHealth'
        } else {
            Add-CategoryNormal -CategoryResult $CategoryResult -Title 'Disk health reports healthy' -Subcategory 'Disk Health'
        }
    } elseif ($Payload -and $Payload.PSObject.Properties['Disks']) {
        $diskErrors = ConvertTo-StorageArray $Payload.Disks | Where-Object { $_ -and $_.PSObject.Properties['Error'] }
        if ($diskErrors.Count -gt 0) {
            $errorDetails = [System.Collections.Generic.List[string]]::new()
            foreach ($diskError in $diskErrors) {
                if ($diskError.Source) {
                    $null = $errorDetails.Add(("{0}: {1}" -f $diskError.Source, $diskError.Error))
                } else {
                    $null = $errorDetails.Add($diskError.Error)
                }
            }

            $evidenceLines = [System.Collections.Generic.List[string]]::new()
            if ($errorDetails.Count -gt 0) {
                $null = $evidenceLines.Add('SMART retrieval errors were reported while collecting disk health:')
                foreach ($errorDetail in $errorDetails) {
                    $null = $evidenceLines.Add(("  {0}" -f $errorDetail))
                }

                $null = $evidenceLines.Add('')
                $null = $evidenceLines.Add('--- SMART error dataset (JSON) ---')
                $errorJson = @{ Errors = $errorDetails.ToArray() } | ConvertTo-Json -Depth 3
                foreach ($line in $errorJson -split "`n") {
                    $null = $evidenceLines.Add($line)
                }
            }

            $explanation = 'Disk health data could not be retrieved; SMART collector errors are listed in the evidence.'

            Add-CategoryIssue -CategoryResult $CategoryResult -Severity 'warning' -Title 'Disk health unavailable, so failing disks may go unnoticed.' -Evidence $evidenceLines -Explanation $explanation -Subcategory 'Disk Health' -Remediation $script:StorageHealthAndSpaceRemediation -Area 'Storage/DiskHealth'
        }
    }
}
