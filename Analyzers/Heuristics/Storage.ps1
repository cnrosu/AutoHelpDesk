<#!
.SYNOPSIS
    Storage heuristics evaluating disk health and free space thresholds.
#>

. (Join-Path -Path (Split-Path $PSScriptRoot -Parent) -ChildPath 'AnalyzerCommon.ps1')

function ConvertTo-StorageArray {
    param($Value)

    if ($null -eq $Value) { return @() }
    if ($Value -is [string]) { return @($Value) }
    if ($Value -is [System.Collections.IEnumerable] -and -not ($Value -is [hashtable])) {
        $itemsList = New-Object System.Collections.Generic.List[object]
        foreach ($item in $Value) { $itemsList.Add($item) | Out-Null }
        return $itemsList.ToArray()
    }
    return @($Value)
}

function Get-StorageWearLabel {
    param(
        $Entry
    )

    if ($null -eq $Entry) { return 'Unknown disk' }

    if ($Entry.PSObject.Properties['FriendlyName'] -and -not [string]::IsNullOrWhiteSpace([string]$Entry.FriendlyName)) {
        return [string]$Entry.FriendlyName
    }
    if ($Entry.PSObject.Properties['SerialNumber'] -and -not [string]::IsNullOrWhiteSpace([string]$Entry.SerialNumber)) {
        return "Serial $($Entry.SerialNumber)"
    }
    if ($Entry.PSObject.Properties['DeviceId']) {
        return "Disk $($Entry.DeviceId)"
    }

    return 'Unknown disk'
}

function Format-StorageWearDetails {
    param(
        [Parameter(Mandatory)]
        $Entry,
        [double]$Wear
    )

    $parts = @()
    $parts += ("Wear used {0}%" -f ([math]::Round($Wear, 1)))

    $remaining = 100 - $Wear
    if ($remaining -ge 0) {
        $parts += ("~{0}% life remaining" -f ([math]::Round([math]::Max($remaining, 0), 1)))
    }

    if ($Entry.PSObject.Properties['MediaType'] -and -not [string]::IsNullOrWhiteSpace([string]$Entry.MediaType)) {
        $parts += ("Media type: {0}" -f $Entry.MediaType)
    }

    if ($Entry.PSObject.Properties['SerialNumber'] -and -not [string]::IsNullOrWhiteSpace([string]$Entry.SerialNumber)) {
        $parts += ("Serial {0}" -f $Entry.SerialNumber)
    }

    if ($Entry.PSObject.Properties['DeviceId']) {
        $parts += ("DeviceId {0}" -f $Entry.DeviceId)
    }

    if ($Entry.PSObject.Properties['TemperatureCelsius']) {
        $temperature = $Entry.TemperatureCelsius
        if ($temperature -is [double] -or $temperature -is [single] -or $temperature -is [int]) {
            $parts += ("Temperature {0}°C" -f ([math]::Round([double]$temperature, 1)))
        } elseif ($temperature) {
            $parts += ("Temperature {0}" -f $temperature)
        }
    }

    return ($parts -join '; ')
}

function Get-VolumeThreshold {
    param(
        [Parameter(Mandatory)]$Volume,
        [double]$SizeGB,
        $Config
    )

    $defaults = @{
        WarnPercent  = 0.20
        WarnAbsolute = 25
        CritPercent  = 0.10
        CritAbsolute = 10
    }

    if ($Config -and $Config.Defaults) {
        foreach ($prop in $Config.Defaults.PSObject.Properties) {
            if ($defaults.ContainsKey($prop.Name)) { $defaults[$prop.Name] = [double]$prop.Value }
        }
    }

    $driveLetter = if ($Volume.DriveLetter) { ([string]$Volume.DriveLetter).Trim(':') } else { '' }
    $label = if ($Volume.FileSystemLabel) { [string]$Volume.FileSystemLabel } else { '' }

    $profile = $defaults.Clone()
    if ($driveLetter -eq 'C') {
        $profile.Description = 'System volume thresholds'
    } elseif ($label -match '(?i)data|archive|backup') {
        $profile.WarnPercent  = [double]([math]::Max($profile.WarnPercent * 0.75, 0.12))
        $profile.WarnAbsolute = [double]([math]::Max($profile.WarnAbsolute * 0.6, 15))
        $profile.CritPercent  = [double]([math]::Max($profile.CritPercent * 0.8, 0.08))
        $profile.CritAbsolute = [double]([math]::Max($profile.CritAbsolute * 0.7, 8))
        $profile.Description  = 'Data/archive volume thresholds'
    } else {
        $profile.Description = 'Standard workstation thresholds'
    }

    if ($Config -and $Config.Volumes) {
        $volumeOverrides = ConvertTo-StorageArray $Config.Volumes
        $match = $volumeOverrides | Where-Object {
            ($_.DriveLetter -and ($_.DriveLetter.Trim(':') -ieq $driveLetter)) -or
            ($_.Label -and $label -and ($_.Label -ieq $label))
        } | Select-Object -First 1

        if ($match) {
            foreach ($prop in $match.PSObject.Properties) {
                if ($profile.ContainsKey($prop.Name)) {
                    $profile[$prop.Name] = [double]$prop.Value
                }
            }
            if ($match.PSObject.Properties['Description']) {
                $profile.Description = [string]$match.Description
            }
        }
    }

    $warnFloor = [math]::Max($SizeGB * $profile.WarnPercent, $profile.WarnAbsolute)
    $critFloor = [math]::Max($SizeGB * $profile.CritPercent, $profile.CritAbsolute)

    return [pscustomobject]@{
        WarnFloorGB = [math]::Round($warnFloor,2)
        CritFloorGB = [math]::Round($critFloor,2)
        WarnPercent = $profile.WarnPercent
        CritPercent = $profile.CritPercent
        Description = $profile.Description
    }
}

function Get-StoragePreview {
    param(
        [string]$Text,
        [int]$MaxLines = 12
    )

    if (-not $Text) { return $null }

    $lines = [regex]::Split($Text, '\r?\n')
    $preview = $lines | Where-Object { $_ -and $_.Trim() } | Select-Object -First $MaxLines
    if (-not $preview -or $preview.Count -eq 0) {
        $preview = $lines | Select-Object -First $MaxLines
    }

    if (-not $preview -or $preview.Count -eq 0) { return $null }

    return ($preview -join "`n").TrimEnd()
}

function Invoke-StorageHeuristics {
    param(
        [Parameter(Mandatory)]
        $Context
    )

    Write-HeuristicDebug -Source 'Storage' -Message 'Starting storage heuristics' -Data ([ordered]@{
        ArtifactCount = if ($Context -and $Context.Artifacts) { $Context.Artifacts.Count } else { 0 }
    })

    $result = New-CategoryResult -Name 'Storage'

    $storageArtifact = Get-AnalyzerArtifact -Context $Context -Name 'storage'
    $snapshotArtifact = Get-AnalyzerArtifact -Context $Context -Name 'storage-snapshot'
    Write-HeuristicDebug -Source 'Storage' -Message 'Resolved storage artifacts' -Data ([ordered]@{
        StorageFound  = [bool]$storageArtifact
        SnapshotFound = [bool]$snapshotArtifact
    })

    if ($storageArtifact) {
        $payload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $storageArtifact)
        Write-HeuristicDebug -Source 'Storage' -Message 'Evaluating storage payload' -Data ([ordered]@{
            HasPayload = [bool]$payload
        })
        $diskEntries = @()
        if ($payload -and $payload.PSObject.Properties['Disks']) {
            $diskEntries = ConvertTo-StorageArray $payload.Disks | Where-Object {
                $_ -and -not ($_ -is [string]) -and $_.PSObject.Properties['HealthStatus']
            }
        }
        Write-HeuristicDebug -Source 'Storage' -Message 'Disk entries resolved' -Data ([ordered]@{
            DiskCount = $diskEntries.Count
        })

        if ($diskEntries.Count -gt 0) {
            $unhealthy = $diskEntries | Where-Object { $_.HealthStatus -and $_.HealthStatus -ne 'Healthy' }
            if ($unhealthy.Count -gt 0) {
                $details = $unhealthy | ForEach-Object { "Disk $($_.Number): $($_.HealthStatus) ($($_.OperationalStatus))" }
                Add-CategoryIssue -CategoryResult $result -Severity 'high' -Title 'Disks reporting degraded health' -Evidence ($details -join "`n") -Subcategory 'Disk Health'
            } else {
                Add-CategoryNormal -CategoryResult $result -Title 'Disk health reports healthy' -Subcategory 'Disk Health'
            }
        } elseif ($payload -and $payload.PSObject.Properties['Disks']) {
            $diskErrors = ConvertTo-StorageArray $payload.Disks | Where-Object { $_ -and $_.PSObject.Properties['Error'] }
            if ($diskErrors.Count -gt 0) {
                $errorDetails = $diskErrors | ForEach-Object {
                    if ($_.Source) {
                        "{0}: {1}" -f $_.Source, $_.Error
                    } else {
                        $_.Error
                    }
                }
                Add-CategoryIssue -CategoryResult $result -Severity 'info' -Title 'Disk health unavailable' -Evidence ($errorDetails -join "`n") -Subcategory 'Disk Health'
            }
        }

        $thresholdConfig = $null
        $thresholdArtifact = Get-AnalyzerArtifact -Context $Context -Name 'storage-thresholds'
        Write-HeuristicDebug -Source 'Storage' -Message 'Resolved storage-thresholds artifact' -Data ([ordered]@{
            Found = [bool]$thresholdArtifact
        })
        if ($thresholdArtifact) {
            $thresholdPayload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $thresholdArtifact)
            if ($thresholdPayload) { $thresholdConfig = $thresholdPayload }
        }

        $volumeEntries = @()
        if ($payload -and $payload.PSObject.Properties['Volumes']) {
            $volumeEntries = ConvertTo-StorageArray $payload.Volumes | Where-Object {
                $_ -and -not ($_ -is [string]) -and $_.PSObject.Properties['Size'] -and $_.PSObject.Properties['SizeRemaining']
            }
        }
        Write-HeuristicDebug -Source 'Storage' -Message 'Volume entries resolved' -Data ([ordered]@{
            VolumeCount = $volumeEntries.Count
        })

        if ($volumeEntries.Count -gt 0) {
            foreach ($volume in $volumeEntries) {
                if (-not $volume.Size -or -not $volume.SizeRemaining) { continue }
                $size = [double]$volume.Size
                $free = [double]$volume.SizeRemaining
                if ($size -le 0) { continue }
                $sizeGb = [math]::Round($size / 1GB,2)
                $freeGb = [math]::Round($free / 1GB,2)
                $freePct = if ($size -gt 0) { ($free / $size) * 100 } else { 0 }
                $label = if ($volume.DriveLetter) { $volume.DriveLetter } elseif ($volume.FileSystemLabel) { $volume.FileSystemLabel } else { 'Unknown' }
                $threshold = Get-VolumeThreshold -Volume $volume -SizeGB $sizeGb -Config $thresholdConfig

                $details = "Free {0} GB of {1} GB ({2}% free); profile {3}" -f $freeGb, $sizeGb, ([math]::Round($freePct,1)), $threshold.Description
                Add-CategoryCheck -CategoryResult $result -Name ("Volume {0}" -f $label) -Status ([string][math]::Round($freePct,1)) -Details $details

                $critPercent = $threshold.CritPercent * 100
                $warnPercent = $threshold.WarnPercent * 100
                if ($freeGb -le $threshold.CritFloorGB -or $freePct -le $critPercent) {
                    $evidence = "Free {0} GB ({1}%); critical floor {2} GB or {3}%" -f $freeGb, [math]::Round($freePct,1), $threshold.CritFloorGB, [math]::Round($critPercent,1)
                    Add-CategoryIssue -CategoryResult $result -Severity 'high' -Title ("Volume {0} critically low on space" -f $label) -Evidence $evidence -Subcategory 'Free Space'
                } elseif ($freeGb -le $threshold.WarnFloorGB -or $freePct -le $warnPercent) {
                    $evidence = "Free {0} GB ({1}%); warning floor {2} GB or {3}%" -f $freeGb, [math]::Round($freePct,1), $threshold.WarnFloorGB, [math]::Round($warnPercent,1)
                    Add-CategoryIssue -CategoryResult $result -Severity 'medium' -Title ("Volume {0} approaching capacity" -f $label) -Evidence $evidence -Subcategory 'Free Space'
                } else {
                    Add-CategoryNormal -CategoryResult $result -Title ("Volume {0} has {1}% free" -f $label, [math]::Round($freePct,1)) -Subcategory 'Free Space'
                }
            }
        } elseif ($payload -and $payload.PSObject.Properties['Volumes']) {
            $volumeErrors = ConvertTo-StorageArray $payload.Volumes | Where-Object { $_ -and $_.PSObject.Properties['Error'] }
            if ($volumeErrors.Count -gt 0) {
                $errorDetails = $volumeErrors | ForEach-Object {
                    if ($_.Source) {
                        "{0}: {1}" -f $_.Source, $_.Error
                    } else {
                        $_.Error
                    }
                }
                Add-CategoryIssue -CategoryResult $result -Severity 'info' -Title 'Volume inventory unavailable' -Evidence ($errorDetails -join "`n") -Subcategory 'Free Space'
            }
        }

        if ($payload -and $payload.PSObject.Properties['WearCounters']) {
            $wearNode = $payload.WearCounters
            Write-HeuristicDebug -Source 'Storage' -Message 'Processing wear counters'
            if ($wearNode -is [pscustomobject] -and $wearNode.PSObject.Properties['Error']) {
                $errorMessage = [string]$wearNode.Error
                if (-not [string]::IsNullOrWhiteSpace($errorMessage)) {
                    Add-CategoryIssue -CategoryResult $result -Severity 'info' -Title 'SMART wear data unavailable' -Evidence $errorMessage -Subcategory 'SMART Wear'
                } else {
                    Add-CategoryIssue -CategoryResult $result -Severity 'info' -Title 'SMART wear data unavailable' -Subcategory 'SMART Wear'
                }
            } else {
                $wearEntries = ConvertTo-StorageArray $wearNode
                foreach ($entry in $wearEntries) {
                    if (-not $entry) { continue }

                    if ($entry.PSObject.Properties['Error'] -and -not [string]::IsNullOrWhiteSpace([string]$entry.Error)) {
                        $label = Get-StorageWearLabel -Entry $entry
                        Add-CategoryIssue -CategoryResult $result -Severity 'info' -Title ("Unable to query SMART wear for {0}" -f $label) -Evidence $entry.Error -Subcategory 'SMART Wear'
                        continue
                    }

                    if (-not $entry.PSObject.Properties['Wear']) { continue }

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

                    if ($null -eq $wearValue) { continue }

                    if ($wearValue -lt 0) { $wearValue = 0 }
                    $label = Get-StorageWearLabel -Entry $entry
                    $details = Format-StorageWearDetails -Entry $entry -Wear $wearValue
                    $status = "{0}%" -f ([math]::Round($wearValue, 1))

                    Add-CategoryCheck -CategoryResult $result -Name ("SMART wear - {0}" -f $label) -Status $status -Details $details

                    if ($wearValue -ge 95) {
                        Add-CategoryIssue -CategoryResult $result -Severity 'high' -Title ("{0} nearing end of rated lifespan ({1}% wear)" -f $label, [math]::Round($wearValue, 1)) -Evidence $details -Subcategory 'SMART Wear'
                    } elseif ($wearValue -ge 85) {
                        Add-CategoryIssue -CategoryResult $result -Severity 'medium' -Title ("{0} wear approaching limits ({1}% used)" -f $label, [math]::Round($wearValue, 1)) -Evidence $details -Subcategory 'SMART Wear'
                    } else {
                        Add-CategoryNormal -CategoryResult $result -Title ("{0} wear at {1}% used" -f $label, [math]::Round($wearValue, 1)) -Subcategory 'SMART Wear'
                    }
                }
            }
        }
    }

    if ($snapshotArtifact) {
        $snapshotPayload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $snapshotArtifact)
        Write-HeuristicDebug -Source 'Storage' -Message 'Evaluating storage snapshot payload' -Data ([ordered]@{
            HasPayload = [bool]$snapshotPayload
        })
        if ($snapshotPayload -and $snapshotPayload.PSObject.Properties['DiskDrives']) {
            $smartData = $snapshotPayload.DiskDrives
            if ($smartData -is [pscustomobject] -and $smartData.PSObject.Properties['Error']) {
                $errorDetail = $smartData.Error
                if (-not [string]::IsNullOrWhiteSpace($errorDetail)) {
                    Add-CategoryIssue -CategoryResult $result -Severity 'info' -Title 'SMART status unavailable' -Evidence $errorDetail -Subcategory 'SMART'
                }
            } else {
                $smartText = if ($smartData -is [string]) { $smartData } else { [string]$smartData }
                if (-not [string]::IsNullOrWhiteSpace($smartText)) {
                    $failurePattern = '(?i)\b(Pred\s*Fail|Fail(?:ed|ing)?|Bad|Caution)\b'
                    if ($smartText -match $failurePattern) {
                        $failureMatches = [regex]::Matches($smartText, $failurePattern)
                        $keywords = $failureMatches | ForEach-Object { $_.Value.Trim() } | Where-Object { $_ } | Sort-Object -Unique
                        $keywordSummary = if ($keywords) { $keywords -join ', ' } else { $null }
                        $evidenceLines = ([regex]::Split($smartText,'\r?\n') | Where-Object { $_ -match $failurePattern } | Select-Object -First 12)
                        if (-not $evidenceLines -or $evidenceLines.Count -eq 0) {
                            $evidenceLines = ([regex]::Split($smartText,'\r?\n') | Select-Object -First 12)
                        }
                        $evidenceText = ($evidenceLines -join "`n").TrimEnd()
                        $message = if ($keywordSummary) {
                            "SMART status reports failure indicators ({0})." -f $keywordSummary
                        } else {
                            'SMART status reports failure indicators.'
                        }
                        Add-CategoryIssue -CategoryResult $result -Severity 'critical' -Title $message -Evidence $evidenceText -Subcategory 'SMART'
                    } elseif ($smartText -notmatch '(?i)Unknown') {
                        $preview = Get-StoragePreview -Text $smartText
                        if ($preview) {
                            Add-CategoryNormal -CategoryResult $result -Title 'SMART status shows no failure indicators' -Evidence $preview -Subcategory 'SMART'
                        } else {
                            Add-CategoryNormal -CategoryResult $result -Title 'SMART status shows no failure indicators' -Subcategory 'SMART'
                        }
                    }
                }
            }
        }
    }

    if (-not $storageArtifact -and -not $snapshotArtifact) {
        Add-CategoryIssue -CategoryResult $result -Severity 'info' -Title 'Storage artifact missing' -Subcategory 'Collection'
    }

    return $result
}
