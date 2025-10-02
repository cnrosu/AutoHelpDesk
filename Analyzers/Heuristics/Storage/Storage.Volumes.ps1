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

            $shouldSkip = $false
            if (-not $hasDriveLetter) {
                if ($rawLabel -match '(?i)recovery|reserved|diagnostic|tools|restore') {
                    $shouldSkip = $true
                } elseif ($sizeGb -lt 1) {
                    $shouldSkip = $true
                }
            }

            if ($shouldSkip) {
                Write-HeuristicDebug -Source 'Storage' -Message 'Skipping hidden volume for free space evaluation' -Data ([ordered]@{
                    Label = if ($rawLabel) { $rawLabel } else { $label }
                    SizeGb = $sizeGb
                    HasDriveLetter = $hasDriveLetter
                })
                continue
            }

            $threshold = Get-VolumeThreshold -Volume $volume -SizeGB $sizeGb -Config $ThresholdConfig

            $details = "Free {0} GB of {1} GB ({2}% free); profile {3}" -f $freeGb, $sizeGb, ([math]::Round($freePct,1)), $threshold.Description
            Add-CategoryCheck -CategoryResult $CategoryResult -Name ("Volume {0}" -f $label) -Status ([string][math]::Round($freePct,1)) -Details $details

            $critPercent = $threshold.CritPercent * 100
            $warnPercent = $threshold.WarnPercent * 100
            if ($freeGb -le $threshold.CritFloorGB -or $freePct -le $critPercent) {
                $evidence = "Free {0} GB ({1}%); critical floor {2} GB or {3}%" -f $freeGb, [math]::Round($freePct,1), $threshold.CritFloorGB, [math]::Round($critPercent,1)
                Add-CategoryIssue -CategoryResult $CategoryResult -Severity 'high' -Title ("Volume {0} critically low on space ({1} GB remaining), risking system or storage failures." -f $label, $freeGb) -Evidence $evidence -Subcategory 'Free Space'
            } elseif ($freeGb -le $threshold.WarnFloorGB -or $freePct -le $warnPercent) {
                $evidence = "Free {0} GB ({1}%); warning floor {2} GB or {3}%" -f $freeGb, [math]::Round($freePct,1), $threshold.WarnFloorGB, [math]::Round($warnPercent,1)
                Add-CategoryIssue -CategoryResult $CategoryResult -Severity 'medium' -Title ("Volume {0} approaching capacity, risking system or storage failures." -f $label) -Evidence $evidence -Subcategory 'Free Space'
            } else {
                Add-CategoryNormal -CategoryResult $CategoryResult -Title ("Volume {0} has {1}% free" -f $label, [math]::Round($freePct,1)) -Subcategory 'Free Space'
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
