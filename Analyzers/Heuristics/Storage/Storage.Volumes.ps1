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
        LowFloorGB      = 75
        MediumFloorGB   = 50
        HighFloorGB     = 25
        CriticalFloorGB = 10
    }

    if ($Config -and $Config.Defaults) {
        foreach ($prop in $Config.Defaults.PSObject.Properties) {
            $name = $prop.Name
            if ($defaults.ContainsKey($name)) {
                $defaults[$name] = [double]$prop.Value
                continue
            }

            switch ($name) {
                'WarnAbsolute'        { $defaults.LowFloorGB = [double]$prop.Value }
                'MediumAbsolute'      { $defaults.MediumFloorGB = [double]$prop.Value }
                'CritAbsolute'        { $defaults.HighFloorGB = [double]$prop.Value }
                'CriticalAbsolute'    { $defaults.CriticalFloorGB = [double]$prop.Value }
            }
        }
    }

    $driveLetter = if ($Volume.DriveLetter) { ([string]$Volume.DriveLetter).Trim(':') } else { '' }
    $label = if ($Volume.FileSystemLabel) { [string]$Volume.FileSystemLabel } else { '' }

    $profile = $defaults.Clone()
    if ($driveLetter -eq 'C') {
        $profile.Description = 'System volume thresholds'
    } elseif ($label -match '(?i)data|archive|backup') {
        $profile.Description = 'Data/archive volume thresholds'
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
                $name = $prop.Name
                if ($profile.ContainsKey($name)) {
                    $profile[$name] = [double]$prop.Value
                    continue
                }

                switch ($name) {
                    'WarnAbsolute'        { $profile.LowFloorGB = [double]$prop.Value }
                    'MediumAbsolute'      { $profile.MediumFloorGB = [double]$prop.Value }
                    'CritAbsolute'        { $profile.HighFloorGB = [double]$prop.Value }
                    'CriticalAbsolute'    { $profile.CriticalFloorGB = [double]$prop.Value }
                }
            }
            if ($match.PSObject.Properties['Description']) {
                $profile.Description = [string]$match.Description
            }
        }
    }

    return [pscustomobject]@{
        LowFloorGB       = [math]::Round($profile.LowFloorGB,2)
        MediumFloorGB    = [math]::Round($profile.MediumFloorGB,2)
        HighFloorGB      = [math]::Round($profile.HighFloorGB,2)
        CriticalFloorGB  = [math]::Round($profile.CriticalFloorGB,2)
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
                    Label = $( if ($rawLabel) { $rawLabel } else { $label } )
                    SizeGb = $sizeGb
                    HasDriveLetter = $hasDriveLetter
                    Reason = $( if ($skipReason) { $skipReason } else { 'Not specified' } )
                })
                continue
            }

            $threshold = Get-VolumeThreshold -Volume $volume -SizeGB $sizeGb -Config $ThresholdConfig

            $details = "Free {0} GB of {1} GB; profile {2}" -f $freeGb, $sizeGb, $threshold.Description
            Add-CategoryCheck -CategoryResult $CategoryResult -Name ("Volume {0}" -f $volumeDisplay) -Status ([string][math]::Round($freeGb,2)) -Details $details

            if ($freeGb -le $threshold.CriticalFloorGB) {
                $evidence = "Free {0} GB; critical floor {1} GB" -f $freeGb, $threshold.CriticalFloorGB
                Add-CategoryIssue -CategoryResult $CategoryResult -Severity 'critical' -Title ("Volume {0} nearly out of space ({1} GB remaining), causing imminent system or storage failures." -f $volumeDisplay, $freeGb) -Evidence $evidence -Subcategory 'Free Space'
            } elseif ($freeGb -le $threshold.HighFloorGB) {
                $evidence = "Free {0} GB; high-risk floor {1} GB" -f $freeGb, $threshold.HighFloorGB
                Add-CategoryIssue -CategoryResult $CategoryResult -Severity 'high' -Title ("Volume {0} critically low on space ({1} GB remaining), risking system or storage failures." -f $volumeDisplay, $freeGb) -Evidence $evidence -Subcategory 'Free Space'
            } elseif ($freeGb -le $threshold.MediumFloorGB) {
                $evidence = "Free {0} GB; medium floor {1} GB" -f $freeGb, $threshold.MediumFloorGB
                Add-CategoryIssue -CategoryResult $CategoryResult -Severity 'medium' -Title ("Volume {0} approaching capacity, risking system or storage failures." -f $volumeDisplay) -Evidence $evidence -Subcategory 'Free Space'
            } elseif ($freeGb -le $threshold.LowFloorGB) {
                $evidence = "Free {0} GB; low floor {1} GB" -f $freeGb, $threshold.LowFloorGB
                Add-CategoryIssue -CategoryResult $CategoryResult -Severity 'low' -Title ("Volume {0} trending low on space ({1} GB remaining), so plan cleanup before performance or storage issues." -f $volumeDisplay, $freeGb) -Evidence $evidence -Subcategory 'Free Space'
            } else {
                Add-CategoryNormal -CategoryResult $CategoryResult -Title ("Volume {0} has {1} GB free" -f $volumeDisplay, $freeGb) -Subcategory 'Free Space'
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
