function Resolve-StorageThresholdConfig {
    param(
        [Parameter(Mandatory)]
        $Context
    )

    $thresholdArtifact = Get-AnalyzerArtifact -Context $Context -Name 'storage-thresholds'
    Write-HeuristicDebug -Source 'Storage' -Message 'Resolved storage-thresholds artifact' -Data ([ordered]@{
        Found = [bool]$thresholdArtifact
    })

    if (-not $thresholdArtifact) { return $null }

    $thresholdPayload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $thresholdArtifact)
    if ($thresholdPayload) { return $thresholdPayload }

    return $null
}

function Get-VolumeThreshold {
    param(
        [Parameter(Mandatory)]$Volume,
        [double]$SizeGB,
        $Config
    )

    $defaults = @{
        WarnPercent        = 0.20
        WarnAbsolute       = 50
        CritPercent        = 0.10
        CritAbsolute       = 25
        CriticalPercent    = 0.04
        CriticalAbsolute   = 10
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
        $profile.WarnPercent       = [double]([math]::Max($profile.WarnPercent * 0.75, 0.12))
        $profile.WarnAbsolute      = [double]([math]::Max($profile.WarnAbsolute * 0.6, 30))
        $profile.CritPercent       = [double]([math]::Max($profile.CritPercent * 0.8, 0.08))
        $profile.CritAbsolute      = [double]([math]::Max($profile.CritAbsolute * 0.7, 18))
        $profile.CriticalPercent   = [double]([math]::Max($profile.CriticalPercent * 0.7, 0.03))
        $profile.CriticalAbsolute  = [double]([math]::Max($profile.CriticalAbsolute * 0.6, 10))
        $profile.Description       = 'Data/archive volume thresholds'
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

    $warnFloor     = [math]::Max($SizeGB * $profile.WarnPercent, $profile.WarnAbsolute)
    $critFloor     = [math]::Max($SizeGB * $profile.CritPercent, $profile.CritAbsolute)
    $criticalFloor = [math]::Max($SizeGB * $profile.CriticalPercent, $profile.CriticalAbsolute)

    return [pscustomobject]@{
        WarnFloorGB      = [math]::Round($warnFloor,2)
        CritFloorGB      = [math]::Round($critFloor,2)
        CriticalFloorGB  = [math]::Round($criticalFloor,2)
        WarnPercent      = $profile.WarnPercent
        CritPercent      = $profile.CritPercent
        CriticalPercent  = $profile.CriticalPercent
        Description      = $profile.Description
    }
}

function Invoke-StorageVolumeEvaluation {
    param(
        [Parameter(Mandatory)]
        $CategoryResult,
        $Payload,
        $ThresholdConfig
    )

    $volumeEntries = @()
    if ($Payload -and $Payload.PSObject.Properties['Volumes']) {
        $volumeEntries = ConvertTo-StorageArray $Payload.Volumes | Where-Object {
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

            $hasDriveLetter = $volume.PSObject.Properties['DriveLetter'] -and -not [string]::IsNullOrWhiteSpace([string]$volume.DriveLetter)
            $rawLabel = if ($volume.FileSystemLabel) { [string]$volume.FileSystemLabel } else { '' }
            $label = if ($hasDriveLetter) { $volume.DriveLetter } elseif ($rawLabel) { $rawLabel } else { 'Unknown' }

            $driveLetterDisplay = $null
            if ($hasDriveLetter) {
                $driveLetterDisplay = ([string]$volume.DriveLetter).Trim()
                if ($driveLetterDisplay.EndsWith(':')) {
                    $driveLetterDisplay = $driveLetterDisplay.TrimEnd(':')
                }
            }

            $volumeLabel = if (-not [string]::IsNullOrWhiteSpace($rawLabel)) { $rawLabel.Trim() } else { $null }
            $volumeFriendlyName = $null
            if ($volume.PSObject.Properties['FriendlyName']) {
                $friendly = [string]$volume.FriendlyName
                if (-not [string]::IsNullOrWhiteSpace($friendly)) {
                    $volumeFriendlyName = $friendly.Trim()
                }
            }

            $volumeName = if ($volumeFriendlyName) {
                $volumeFriendlyName
            } elseif ($volumeLabel) {
                $volumeLabel
            } else {
                $null
            }

            $volumeDisplay = if ($driveLetterDisplay) {
                if ($volumeName -and ($volumeName -ine $driveLetterDisplay)) {
                    "{0} (`"{1}`")" -f $driveLetterDisplay, $volumeName
                } else {
                    $driveLetterDisplay
                }
            } elseif ($volumeName) {
                $volumeName
            } else {
                $label
            }

            $shouldSkip = $false
            $skipReason = $null
            if ($rawLabel -match '^(?i)system reserved$') {
                $shouldSkip = $true
                $skipReason = 'System Reserved volume'
            } elseif (-not $hasDriveLetter) {
                if ($rawLabel -match '(?i)recovery|reserved|diagnostic|tools|restore') {
                    $shouldSkip = $true
                    $skipReason = 'Hidden maintenance volume'
                } elseif ($sizeGb -lt 1) {
                    $shouldSkip = $true
                    $skipReason = 'Volume smaller than 1 GB'
                }
            }

            if ($shouldSkip) {
                Write-HeuristicDebug -Source 'Storage' -Message 'Skipping hidden volume for free space evaluation' -Data ([ordered]@{
                    Label = if ($rawLabel) { $rawLabel } else { $label }
                    SizeGb = $sizeGb
                    HasDriveLetter = $hasDriveLetter
                    Reason = if ($skipReason) { $skipReason } else { 'Not specified' }
                })
                continue
            }

            $threshold = Get-VolumeThreshold -Volume $volume -SizeGB $sizeGb -Config $ThresholdConfig

            $details = "Free {0} GB of {1} GB ({2}% free); profile {3}" -f $freeGb, $sizeGb, ([math]::Round($freePct,1)), $threshold.Description
            Add-CategoryCheck -CategoryResult $CategoryResult -Name ("Volume {0}" -f $volumeDisplay) -Status ([string][math]::Round($freePct,1)) -Details $details

            $critPercent = $threshold.CritPercent * 100
            $warnPercent = $threshold.WarnPercent * 100
            $criticalPercent = $threshold.CriticalPercent * 100
            if ($freeGb -le $threshold.CriticalFloorGB -or $freePct -le $criticalPercent) {
                $evidence = "Free {0} GB ({1}%); critical floor {2} GB or {3}%" -f $freeGb, [math]::Round($freePct,1), $threshold.CriticalFloorGB, [math]::Round($criticalPercent,1)
                Add-CategoryIssue -CategoryResult $CategoryResult -Severity 'critical' -Title ("Volume {0} nearly out of space ({1} GB remaining), causing imminent system or storage failures." -f $volumeDisplay, $freeGb) -Evidence $evidence -Subcategory 'Free Space'
            } elseif ($freeGb -le $threshold.CritFloorGB -or $freePct -le $critPercent) {
                $evidence = "Free {0} GB ({1}%); high-risk floor {2} GB or {3}%" -f $freeGb, [math]::Round($freePct,1), $threshold.CritFloorGB, [math]::Round($critPercent,1)
                Add-CategoryIssue -CategoryResult $CategoryResult -Severity 'high' -Title ("Volume {0} critically low on space ({1} GB remaining), risking system or storage failures." -f $volumeDisplay, $freeGb) -Evidence $evidence -Subcategory 'Free Space'
            } elseif ($freeGb -le $threshold.WarnFloorGB -or $freePct -le $warnPercent) {
                $evidence = "Free {0} GB ({1}%); warning floor {2} GB or {3}%" -f $freeGb, [math]::Round($freePct,1), $threshold.WarnFloorGB, [math]::Round($warnPercent,1)
                Add-CategoryIssue -CategoryResult $CategoryResult -Severity 'medium' -Title ("Volume {0} approaching capacity, risking system or storage failures." -f $volumeDisplay) -Evidence $evidence -Subcategory 'Free Space'
            } else {
                Add-CategoryNormal -CategoryResult $CategoryResult -Title ("Volume {0} has {1}% free" -f $volumeDisplay, [math]::Round($freePct,1)) -Subcategory 'Free Space'
            }
        }
    } elseif ($Payload -and $Payload.PSObject.Properties['Volumes']) {
        $volumeErrors = ConvertTo-StorageArray $Payload.Volumes | Where-Object { $_ -and $_.PSObject.Properties['Error'] }
        if ($volumeErrors.Count -gt 0) {
            $errorDetails = $volumeErrors | ForEach-Object {
                if ($_.Source) {
                    "{0}: {1}" -f $_.Source, $_.Error
                } else {
                    $_.Error
                }
            }
            Add-CategoryIssue -CategoryResult $CategoryResult -Severity 'info' -Title 'Volume inventory unavailable, so storage depletion risks may be hidden.' -Evidence ($errorDetails -join "`n") -Subcategory 'Free Space'
        }
    }
}
