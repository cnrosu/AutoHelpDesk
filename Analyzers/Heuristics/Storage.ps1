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
        $items = @()
        foreach ($item in $Value) { $items += $item }
        return $items
    }
    return @($Value)
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

function Invoke-StorageHeuristics {
    param(
        [Parameter(Mandatory)]
        $Context
    )

    $result = New-CategoryResult -Name 'Storage'

    $systemArtifact = Get-AnalyzerArtifact -Context $Context -Name 'system'
    $isWorkstationPerformanceTarget = $false
    if ($systemArtifact) {
        $systemPayload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $systemArtifact)
        if ($systemPayload -and $systemPayload.OperatingSystem -and -not $systemPayload.OperatingSystem.Error) {
            $caption = [string]$systemPayload.OperatingSystem.Caption
            if ($caption -and ($caption -notmatch '(?i)windows\s+server')) {
                $isWorkstationPerformanceTarget = $true
            }
        }
    }

    $storageArtifact = Get-AnalyzerArtifact -Context $Context -Name 'storage'
    if ($storageArtifact) {
        $payload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $storageArtifact)
        if ($payload -and $payload.Disks -and -not $payload.Disks.Error) {
            $diskEntries = $payload.Disks
            if ($diskEntries -isnot [System.Collections.IEnumerable] -or $diskEntries -is [string]) {
                $diskEntries = @($diskEntries)
            }

            $unhealthy = $diskEntries | Where-Object { $_.HealthStatus -and $_.HealthStatus -ne 'Healthy' }
            if ($unhealthy.Count -gt 0) {
                $details = $unhealthy | ForEach-Object { "Disk $($_.Number): $($_.HealthStatus) ($($_.OperationalStatus))" }
                Add-CategoryIssue -CategoryResult $result -Severity 'high' -Title 'Disks reporting degraded health' -Evidence ($details -join "`n") -Subcategory 'Disk Health'
            } else {
                Add-CategoryNormal -CategoryResult $result -Title 'Disk health reports healthy'
            }

            $systemDisks = New-Object System.Collections.Generic.List[object]
            foreach ($disk in $diskEntries) {
                $isBoot = $null
                if ($disk.PSObject.Properties['IsBoot']) { $isBoot = ConvertTo-NullableBool $disk.IsBoot }
                $isSystem = $null
                if ($disk.PSObject.Properties['IsSystem']) { $isSystem = ConvertTo-NullableBool $disk.IsSystem }
                $isReadOnly = $null
                if ($disk.PSObject.Properties['IsReadOnly']) { $isReadOnly = ConvertTo-NullableBool $disk.IsReadOnly }
                $writeCacheEnabled = $null
                if ($disk.PSObject.Properties['WriteCacheEnabled']) { $writeCacheEnabled = ConvertTo-NullableBool $disk.WriteCacheEnabled }

                if (($isBoot -eq $true) -or ($isSystem -eq $true)) {
                    $systemDisks.Add([pscustomobject]@{
                            Number            = if ($disk.PSObject.Properties['Number']) { $disk.Number } else { $null }
                            IsBoot            = $isBoot
                            IsSystem          = $isSystem
                            IsReadOnly        = $isReadOnly
                            WriteCacheEnabled = $writeCacheEnabled
                        }) | Out-Null
                }
            }

            if ($systemDisks.Count -gt 0) {
                foreach ($diskSummary in $systemDisks) {
                    $status = switch ($diskSummary.WriteCacheEnabled) {
                        $true { 'Enabled' }
                        $false { 'Disabled' }
                        default { 'Unknown' }
                    }

                    $formatFlag = {
                        param($value)
                        if ($value -eq $true) { return 'True' }
                        if ($value -eq $false) { return 'False' }
                        return 'Unknown'
                    }

                    $details = @(
                        "Boot=$(&$formatFlag $diskSummary.IsBoot)",
                        "System=$(&$formatFlag $diskSummary.IsSystem)",
                        "ReadOnly=$(&$formatFlag $diskSummary.IsReadOnly)"
                    ) -join '; '

                    $diskLabel = if ($null -ne $diskSummary.Number) { "Disk $($diskSummary.Number)" } else { 'Disk (unknown number)' }
                    Add-CategoryCheck -CategoryResult $result -Name ('{0} write cache' -f $diskLabel) -Status $status -Details $details
                }

                $disabledCaches = $systemDisks | Where-Object { $_.WriteCacheEnabled -eq $false }
                if ($disabledCaches.Count -gt 0) {
                    $severity = if ($isWorkstationPerformanceTarget) { 'high' } else { 'medium' }
                    $evidence = $disabledCaches | ForEach-Object {
                        $flagParts = @(
                            "Boot=$((if ($_.IsBoot -eq $true) { 'True' } elseif ($_.IsBoot -eq $false) { 'False' } else { 'Unknown' }))",
                            "System=$((if ($_.IsSystem -eq $true) { 'True' } elseif ($_.IsSystem -eq $false) { 'False' } else { 'Unknown' }))",
                            "ReadOnly=$((if ($_.IsReadOnly -eq $true) { 'True' } elseif ($_.IsReadOnly -eq $false) { 'False' } else { 'Unknown' }))",
                            "WriteCacheEnabled=False"
                        ) -join ', '
                        $label = if ($null -ne $_.Number) { "Disk $($_.Number)" } else { 'Disk (unknown number)' }
                        "$label ($flagParts)"
                    }
                    Add-CategoryIssue -CategoryResult $result -Severity $severity -Title 'Write cache disabled on system disk' -Evidence ($evidence -join "`n") -Subcategory 'Disk Configuration'
                } elseif (($systemDisks | Where-Object { $_.WriteCacheEnabled -eq $null }).Count -eq 0 -and ($systemDisks | Where-Object { $_.WriteCacheEnabled -eq $true }).Count -gt 0) {
                    Add-CategoryNormal -CategoryResult $result -Title 'Write cache enabled on system disks' -Subcategory 'Disk Configuration'
                }
            }
        }

        $thresholdConfig = $null
        $thresholdArtifact = Get-AnalyzerArtifact -Context $Context -Name 'storage-thresholds'
        if ($thresholdArtifact) {
            $thresholdPayload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $thresholdArtifact)
            if ($thresholdPayload) { $thresholdConfig = $thresholdPayload }
        }

        if ($payload -and $payload.Volumes -and -not $payload.Volumes.Error) {
            foreach ($volume in $payload.Volumes) {
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
                    Add-CategoryNormal -CategoryResult $result -Title ("Volume {0} has {1}% free" -f $label, [math]::Round($freePct,1))
                }
            }
        }
    } else {
        Add-CategoryIssue -CategoryResult $result -Severity 'info' -Title 'Storage artifact missing' -Subcategory 'Collection'
    }

    return $result
}
