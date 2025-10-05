function Invoke-StorageWearEvaluation {
    param(
        [Parameter(Mandatory)]
        $CategoryResult,
        $Payload
    )

    if ($Payload -and $Payload.PSObject.Properties['WearCounters']) {
        $wearNode = $Payload.WearCounters
        Write-HeuristicDebug -Source 'Storage' -Message 'Processing wear counters'
        if ($wearNode -is [pscustomobject] -and $wearNode.PSObject.Properties['Error']) {
            $errorMessage = [string]$wearNode.Error
            if (-not [string]::IsNullOrWhiteSpace($errorMessage)) {
                Add-CategoryIssue -CategoryResult $CategoryResult -Severity 'info' -Title 'SMART wear data unavailable, so SSD end-of-life risks may be hidden.' -Evidence $errorMessage -Subcategory 'SMART Wear'
            } else {
                Add-CategoryIssue -CategoryResult $CategoryResult -Severity 'info' -Title 'SMART wear data unavailable, so SSD end-of-life risks may be hidden.' -Subcategory 'SMART Wear'
            }
        } else {
            $wearEntries = ConvertTo-StorageArray $wearNode
            $hasWearResult = $false
            $missingWearLabels = @()
            foreach ($entry in $wearEntries) {
                if (-not $entry) { continue }

                if ($entry.PSObject.Properties['Error'] -and -not [string]::IsNullOrWhiteSpace([string]$entry.Error)) {
                    $label = Get-StorageWearLabel -Entry $entry
                    Add-CategoryIssue -CategoryResult $CategoryResult -Severity 'info' -Title ("Unable to query SMART wear for {0}, so SSD end-of-life risks may be hidden." -f $label) -Evidence $entry.Error -Subcategory 'SMART Wear'
                    continue
                }

                $label = Get-StorageWearLabel -Entry $entry

                if (-not $entry.PSObject.Properties['Wear']) {
                    $missingWearLabels += $label
                    continue
                }

                $rawWear = $entry.Wear
                $wearValue = $null
                if ($rawWear -is [double] -or $rawWear -is [single] -or $rawWear -is [int]) {
                    $wearValue = [double]$rawWear
                } elseif ($rawWear) {
                    $parsedWear = 0.0
                    if ([double]::TryParse([string]$rawWear, [ref]$parsedWear)) {
                        $wearValue = [double]$parsedWear
                    }
                }

                if ($null -eq $wearValue) {
                    $missingWearLabels += $label
                    continue
                }

                if ($wearValue -lt 0) { $wearValue = 0 }
                $details = Format-StorageWearDetails -Entry $entry -Wear $wearValue
                $status = "{0}%" -f ([math]::Round($wearValue, 1))

                Add-CategoryCheck -CategoryResult $CategoryResult -Name ("SMART wear - {0}" -f $label) -Status $status -Details $details
                $hasWearResult = $true

                if ($wearValue -ge 95) {
                    Add-CategoryIssue -CategoryResult $CategoryResult -Severity 'high' -Title ("{0} nearing end of rated lifespan ({1}% wear)" -f $label, [math]::Round($wearValue, 1)) -Evidence $details -Subcategory 'SMART Wear'
                } elseif ($wearValue -ge 85) {
                    Add-CategoryIssue -CategoryResult $CategoryResult -Severity 'medium' -Title ("{0} wear approaching limits ({1}% used)" -f $label, [math]::Round($wearValue, 1)) -Evidence $details -Subcategory 'SMART Wear'
                } else {
                    Add-CategoryNormal -CategoryResult $CategoryResult -Title ("{0} wear at {1}% used" -f $label, [math]::Round($wearValue, 1)) -Subcategory 'SMART Wear'
                }
            }

            if (-not $hasWearResult -and $missingWearLabels.Count -gt 0) {
                $evidence = [string]::Join(", ", $missingWearLabels)
                if ([string]::IsNullOrWhiteSpace($evidence)) {
                    Add-CategoryIssue -CategoryResult $CategoryResult -Severity 'info' -Title 'SMART wear counters missing for detected drives, so SSD end-of-life risks may be hidden.' -Subcategory 'SMART Wear'
                } else {
                    Add-CategoryIssue -CategoryResult $CategoryResult -Severity 'info' -Title 'SMART wear counters missing for detected drives, so SSD end-of-life risks may be hidden.' -Evidence ("No wear percentage reported for: {0}" -f $evidence) -Subcategory 'SMART Wear'
                }
            }
        }
    } else {
        Add-CategoryIssue -CategoryResult $CategoryResult -Severity 'info' -Title 'SMART wear data not collected, so SSD end-of-life risks may be hidden.' -Subcategory 'SMART Wear'
    }
}
