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
            $details = [System.Collections.Generic.List[string]]::new()
            $diskData = [System.Collections.Generic.List[object]]::new()
            foreach ($disk in $unhealthy) {
                $null = $details.Add(("Disk {0}: {1} ({2})" -f $disk.Number, $disk.HealthStatus, $disk.OperationalStatus))
                $diskInfo = [ordered]@{
                    Model             = if ($disk.PSObject.Properties['Model']) { [string]$disk.Model } else { $null }
                    Firmware          = if ($disk.PSObject.Properties['FirmwareVersion']) { [string]$disk.FirmwareVersion } elseif ($disk.PSObject.Properties['Firmware']) { [string]$disk.Firmware } else { $null }
                    MediaType         = if ($disk.PSObject.Properties['MediaType']) { [string]$disk.MediaType } else { $null }
                    PredictiveFailure = if ($disk.PSObject.Properties['PredictiveFailure']) { [bool]$disk.PredictiveFailure } else { $false }
                    ReallocatedSectors = if ($disk.PSObject.Properties['ReallocatedSectorsCount']) { [int]$disk.ReallocatedSectorsCount } elseif ($disk.PSObject.Properties['ReallocatedSectors']) { [int]$disk.ReallocatedSectors } else { $null }
                    TemperatureC      = if ($disk.PSObject.Properties['TemperatureC']) { [double]$disk.TemperatureC } elseif ($disk.PSObject.Properties['Temperature']) { [double]$disk.Temperature } else { $null }
                    Number            = if ($disk.PSObject.Properties['Number']) { [int]$disk.Number } else { $null }
                    SerialNumber      = if ($disk.PSObject.Properties['SerialNumber']) { [string]$disk.SerialNumber } else { $null }
                }
                $diskData.Add([pscustomobject]$diskInfo) | Out-Null
            }

            $issueData = @{
                Area     = 'Storage/DiskHealth'
                Kind     = 'SmartHealth'
                Hostname = $env:COMPUTERNAME
                Disks    = $diskData.ToArray()
            }

            Add-CategoryIssue -CategoryResult $CategoryResult -Severity 'high' -Title 'Disks reporting degraded health, indicating failing disks.' -Evidence ($details -join "`n") -Subcategory 'Disk Health' -Data $issueData
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

            $issueData = @{
                Area     = 'Storage/DiskHealth'
                Kind     = 'SmartHealth'
                Hostname = $env:COMPUTERNAME
                Errors   = $errorDetails
            }
            Add-CategoryIssue -CategoryResult $CategoryResult -Severity 'info' -Title 'Disk health unavailable, so failing disks may go unnoticed.' -Evidence ($errorDetails -join "`n") -Subcategory 'Disk Health' -Data $issueData
        }
    }
}
