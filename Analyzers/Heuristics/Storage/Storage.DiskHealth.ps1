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
            foreach ($disk in $unhealthy) {
                $null = $details.Add(("Disk {0}: {1} ({2})" -f $disk.Number, $disk.HealthStatus, $disk.OperationalStatus))
            }

            Add-CategoryIssue -CategoryResult $CategoryResult -Severity 'high' -Title 'Disks reporting degraded health, indicating failing disks.' -Evidence ($details -join "`n") -Subcategory 'Disk Health'
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

            Add-CategoryIssue -CategoryResult $CategoryResult -Severity 'info' -Title 'Disk health unavailable, so failing disks may go unnoticed.' -Evidence ($errorDetails -join "`n") -Subcategory 'Disk Health'
        }
    }
}
