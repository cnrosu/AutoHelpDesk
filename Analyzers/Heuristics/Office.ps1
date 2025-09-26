<#!
.SYNOPSIS
    Office security heuristics covering macro and Protected View policies along with cache sizing.
#>

. (Join-Path -Path (Split-Path $PSScriptRoot -Parent) -ChildPath 'AnalyzerCommon.ps1')

function Invoke-OfficeHeuristics {
    param(
        [Parameter(Mandatory)]
        $Context
    )

    $result = New-CategoryResult -Name 'Office'

    $policiesArtifact = Get-AnalyzerArtifact -Context $Context -Name 'office-policies'
    if ($policiesArtifact) {
        $payload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $policiesArtifact)
        if ($payload -and $payload.Policies) {
            $macroBlocked = $false
            foreach ($policy in $payload.Policies) {
                if ($policy.Values -and $policy.Values.PSObject.Properties['VBAWarnings']) {
                    $value = [int]$policy.Values.VBAWarnings
                    if ($value -ge 4) {
                        $macroBlocked = $true
                    } else {
                        Add-CategoryIssue -CategoryResult $result -Severity 'medium' -Title 'Office macros allowed' -Evidence ("VBAWarnings={0} at {1}" -f $value, $policy.Path) -Subcategory 'Macro Policies'
                    }
                }
                if ($policy.Values -and $policy.Values.PSObject.Properties['DisableTrustBarNotificationsFromUnsignedMacros']) {
                    $setting = [int]$policy.Values.DisableTrustBarNotificationsFromUnsignedMacros
                    if ($setting -eq 1) {
                        Add-CategoryIssue -CategoryResult $result -Severity 'low' -Title 'Trust Bar notifications disabled' -Evidence $policy.Path -Subcategory 'Macro Policies'
                    }
                }
                if ($policy.Values -and $policy.Values.PSObject.Properties['DisableProtectedViewForAttachments']) {
                    if ([int]$policy.Values.DisableProtectedViewForAttachments -eq 1) {
                        Add-CategoryIssue -CategoryResult $result -Severity 'medium' -Title 'Protected View disabled for attachments' -Evidence $policy.Path -Subcategory 'Protected View Policies'
                    }
                }
            }

            if ($macroBlocked) {
                Add-CategoryNormal -CategoryResult $result -Title 'Macro runtime blocked by policy'
            }
        } else {
            Add-CategoryIssue -CategoryResult $result -Severity 'medium' -Title 'Office MOTW macro blocking - no data. Confirm macro policies.' -Subcategory 'Macro Policies'
            Add-CategoryIssue -CategoryResult $result -Severity 'low' -Title 'Office macro notifications - no data. Collect policy details.' -Subcategory 'Macro Policies'
            Add-CategoryIssue -CategoryResult $result -Severity 'low' -Title 'Office Protected View - no data. Verify Protected View policies.' -Subcategory 'Protected View Policies'
        }
    }

    $cacheArtifact = Get-AnalyzerArtifact -Context $Context -Name 'outlook-caches'
    if ($cacheArtifact) {
        $payload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $cacheArtifact)
        if ($payload -and $payload.Caches -and -not $payload.Caches.Error) {
            $largeCaches = $payload.Caches | Where-Object { $_.Length -gt 25GB }
            if ($largeCaches.Count -gt 0) {
                $names = $largeCaches | Select-Object -ExpandProperty FullName -First 5
                Add-CategoryIssue -CategoryResult $result -Severity 'medium' -Title 'Large Outlook cache files detected' -Evidence ($names -join "`n") -Subcategory 'Outlook Cache'
            } elseif ($payload.Caches.Count -gt 0) {
                Add-CategoryNormal -CategoryResult $result -Title ('Outlook cache files present ({0})' -f $payload.Caches.Count)
            }
        }
    }

    $profileSignalsArtifact = Get-AnalyzerArtifact -Context $Context -Name 'outlook-profile-signals'
    if ($profileSignalsArtifact) {
        $payload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $profileSignalsArtifact)
        if ($payload) {
            $windowStart = $null
            if ($payload.PSObject.Properties['StartTime'] -and $payload.StartTime) {
                try {
                    $windowStart = [datetime]::Parse($payload.StartTime)
                } catch {
                    $windowStart = $null
                }
            }

            if (-not $windowStart) {
                $windowStart = (Get-Date).AddDays(-30)
            }

            $eventErrors = @()
            $events = @()
            if ($payload.PSObject.Properties['Events']) {
                $rawEvents = $payload.Events
                if ($rawEvents -is [System.Collections.IEnumerable] -and -not ($rawEvents -is [string])) {
                    $rawEvents = @($rawEvents)
                } else {
                    $rawEvents = @($rawEvents)
                }

                foreach ($entry in $rawEvents) {
                    if (-not $entry) { continue }
                    if ($entry.PSObject.Properties['Error'] -and $entry.Error) {
                        $eventErrors += $entry
                        continue
                    }
                    $events += $entry
                }
            }

            foreach ($errorEntry in $eventErrors) {
                Add-CategoryIssue -CategoryResult $result -Severity 'info' -Title 'Failed to query Outlook application events' -Evidence $errorEntry.Error -Subcategory 'Outlook OST Rebuilds'
            }

            $rebuildEvents = @()
            $eventPattern = '(?i)(creating new data file|rebuild|re-created|recreated|ost file|offline storage)' 
            foreach ($evt in $events) {
                if (-not $evt) { continue }
                $timeCreated = $null
                if ($evt.PSObject.Properties['TimeCreated']) {
                    try {
                        $timeCreated = [datetime]$evt.TimeCreated
                    } catch {
                        $timeCreated = $null
                    }
                }

                if ($timeCreated -and $timeCreated -lt $windowStart) { continue }

                $message = if ($evt.PSObject.Properties['Message']) { [string]$evt.Message } else { '' }
                if ($message -match $eventPattern) {
                    $rebuildEvents += [pscustomobject]@{
                        TimeCreated = $timeCreated
                        Id          = if ($evt.PSObject.Properties['Id']) { $evt.Id } else { $null }
                        Message     = $message
                    }
                }
            }

            $ostEntries = @()
            if ($payload.PSObject.Properties['OstFiles']) {
                $rawFiles = $payload.OstFiles
                if ($rawFiles -is [System.Collections.IEnumerable] -and -not ($rawFiles -is [string])) {
                    $rawFiles = @($rawFiles)
                } else {
                    $rawFiles = @($rawFiles)
                }

                foreach ($file in $rawFiles) {
                    if (-not $file -or -not ($file.PSObject.Properties['FullName'])) { continue }
                    $name = if ($file.PSObject.Properties['Name']) { [string]$file.Name } else { [System.IO.Path]::GetFileName($file.FullName) }
                    if ($name -notmatch '(?i)\.ost$') { continue }
                    $length = $null
                    if ($file.PSObject.Properties['Length']) {
                        try { $length = [double]$file.Length } catch { $length = $null }
                    }
                    $lastWrite = $null
                    if ($file.PSObject.Properties['LastWriteTime']) {
                        try { $lastWrite = [datetime]$file.LastWriteTime } catch { $lastWrite = $null }
                    }
                    $directory = [System.IO.Path]::GetDirectoryName([string]$file.FullName)
                    $baseName = [System.IO.Path]::GetFileNameWithoutExtension($name)
                    $normalized = ($baseName -replace '\s*\(\d+\)$','')
                    $normalized = ($normalized -replace '\s+\d+$','')
                    $normalized = ($normalized -replace '(?:\s|-|_)*(copy|backup|old|bak)$','')
                    $normalized = $normalized.Trim()
                    if (-not $normalized) { $normalized = $baseName }

                    $ostEntries += [pscustomobject]@{
                        Name           = $name
                        FullName       = [string]$file.FullName
                        Directory      = $directory
                        Length         = $length
                        LastWriteTime  = $lastWrite
                        NormalizedBase = $normalized
                    }
                }
            }

            $suffixPattern = '(?i)(\(\d+\)\.ost$| copy\.ost$| backup\.ost$| bak\.ost$|\.ost\d+$| _old\.ost$| _bak\.ost$|\.ost\.bak$| \d+\.ost$)'
            $duplicateEvidence = @()
            $sizeCollapseEvidence = @()

            if ($ostEntries.Count -gt 0) {
                $groups = $ostEntries | Group-Object -Property {
                    $dir = if ($_.Directory) { $_.Directory } else { '' }
                    $baseKey = if ($_.NormalizedBase) { $_.NormalizedBase.ToLowerInvariant() } else { '' }
                    '{0}|{1}' -f $dir, $baseKey
                }
                foreach ($group in $groups) {
                    if (-not $group -or -not $group.Group) { continue }
                    $members = $group.Group
                    if ($members.Count -lt 2) { continue }

                    $hasSuffix = $false
                    foreach ($member in $members) {
                        if ($member.Name -match $suffixPattern) {
                            $hasSuffix = $true
                            break
                        }
                    }

                    if ($hasSuffix) {
                        $duplicateEvidence += [pscustomobject]@{
                            Directory = $members[0].Directory
                            BaseName  = $members[0].NormalizedBase
                            Files     = ($members | Sort-Object LastWriteTime -Descending | Select-Object -First 5 Name, LastWriteTime, @{ Name = 'SizeMB'; Expression = { if ($_.Length -ne $null) { [math]::Round($_.Length / 1MB, 1) } else { $null } } })
                        }
                    }

                    $recentMembers = $members | Where-Object { $_.LastWriteTime }
                    if ($recentMembers.Count -lt 2) { continue }
                    $ordered = $recentMembers | Sort-Object LastWriteTime
                    $newest = $ordered[-1]
                    $previous = $ordered[-2]
                    if (-not $newest -or -not $previous) { continue }
                    if ($newest.LastWriteTime -lt $windowStart) { continue }
                    if ($previous.Length -le 0 -or $newest.Length -eq $null) { continue }
                    $sizeRatio = if ($previous.Length -gt 0) { $newest.Length / [double]$previous.Length } else { 1 }
                    if ($previous.Length -ge 1GB -and $sizeRatio -lt 0.5) {
                        $sizeCollapseEvidence += [pscustomobject]@{
                            Directory      = $newest.Directory
                            BaseName       = $newest.NormalizedBase
                            PreviousSizeMB = [math]::Round($previous.Length / 1MB, 1)
                            PreviousDate   = $previous.LastWriteTime
                            CurrentSizeMB  = if ($newest.Length -ne $null) { [math]::Round($newest.Length / 1MB, 1) } else { $null }
                            CurrentDate    = $newest.LastWriteTime
                        }
                    }
                }
            }

            $scanPstEvidence = @()
            if ($payload.PSObject.Properties['ScanPstLogs']) {
                $rawLogs = $payload.ScanPstLogs
                if ($rawLogs -is [System.Collections.IEnumerable] -and -not ($rawLogs -is [string])) {
                    $rawLogs = @($rawLogs)
                } else {
                    $rawLogs = @($rawLogs)
                }

                foreach ($log in $rawLogs) {
                    if (-not $log) { continue }
                    if ($log.PSObject.Properties['Error'] -and $log.Error) { continue }
                    $logTime = $null
                    if ($log.PSObject.Properties['LastWriteTime']) {
                        try { $logTime = [datetime]$log.LastWriteTime } catch { $logTime = $null }
                    }
                    if ($logTime -and $logTime -lt $windowStart) { continue }
                    $scanPstEvidence += [pscustomobject]@{
                        Name          = if ($log.PSObject.Properties['Name']) { [string]$log.Name } else { $null }
                        FullName      = if ($log.PSObject.Properties['FullName']) { [string]$log.FullName } else { $null }
                        LastWriteTime = $logTime
                    }
                }
            }

            $indicatorSummaries = @()
            $indicatorEvidence = [ordered]@{}
            $indicatorCount = 0

            if ($rebuildEvents.Count -gt 0) {
                $indicatorCount++
                $rebuildSuffix = if ($rebuildEvents.Count -eq 1) { '' } else { 's' }
                $indicatorSummaries += ('{0} Outlook rebuild event{1}' -f $rebuildEvents.Count, $rebuildSuffix)
                $indicatorEvidence['RebuildEvents'] = $rebuildEvents | Select-Object -First 10
            }

            if ($duplicateEvidence.Count -gt 0) {
                $indicatorCount++
                $duplicateSuffix = if ($duplicateEvidence.Count -eq 1) { '' } else { 's' }
                $indicatorSummaries += ('Duplicate OST caches in {0} location{1}' -f $duplicateEvidence.Count, $duplicateSuffix)
                $indicatorEvidence['DuplicateCaches'] = $duplicateEvidence
            }

            if ($sizeCollapseEvidence.Count -gt 0) {
                $indicatorCount++
                $indicatorSummaries += ('Recent OST size collapse detected ({0})' -f $sizeCollapseEvidence.Count)
                $indicatorEvidence['SizeCollapse'] = $sizeCollapseEvidence
            }

            if ($scanPstEvidence.Count -gt 0) {
                $indicatorCount++
                $indicatorSummaries += ('ScanPST runs ({0})' -f $scanPstEvidence.Count)
                $indicatorEvidence['ScanPstLogs'] = $scanPstEvidence
            }

            if ($indicatorSummaries.Count -gt 0) {
                $indicatorEvidence['Summary'] = $indicatorSummaries
            }

            $checkDetails = if ($indicatorSummaries.Count -gt 0) { $indicatorSummaries -join '; ' } else { 'No OST rebuild indicators detected.' }

            if ($indicatorCount -ge 2) {
                $severity = 'medium'
                if ($rebuildEvents.Count -ge 4 -or $indicatorCount -ge 3) {
                    $severity = 'high'
                }

                Add-CategoryIssue -CategoryResult $result -Severity $severity -Title 'Outlook profile rebuild indicators detected' -Evidence $indicatorEvidence -Subcategory 'Outlook OST Rebuilds' -CheckId 'Office/OSTRebuilds'
                Add-CategoryCheck -CategoryResult $result -Name 'Outlook OST rebuild signals' -Status 'Issue' -Details $checkDetails -CheckId 'Office/OSTRebuilds'
            } elseif ($indicatorCount -eq 1) {
                Add-CategoryIssue -CategoryResult $result -Severity 'low' -Title 'Single Outlook profile rebuild indicator detected' -Evidence $indicatorEvidence -Subcategory 'Outlook OST Rebuilds' -CheckId 'Office/OSTRebuilds'
                Add-CategoryCheck -CategoryResult $result -Name 'Outlook OST rebuild signals' -Status 'Issue' -Details $checkDetails -CheckId 'Office/OSTRebuilds'
            } else {
                Add-CategoryNormal -CategoryResult $result -Title 'No Outlook profile rebuild indicators detected' -Subcategory 'Outlook OST Rebuilds' -CheckId 'Office/OSTRebuilds'
                Add-CategoryCheck -CategoryResult $result -Name 'Outlook OST rebuild signals' -Status 'Good' -Details 'No rebuild indicators detected.' -CheckId 'Office/OSTRebuilds'
            }
        } else {
            Add-CategoryIssue -CategoryResult $result -Severity 'info' -Title 'Outlook profile rebuild signals - no payload' -Subcategory 'Outlook OST Rebuilds'
        }
    }

    $autodiscoverArtifact = Get-AnalyzerArtifact -Context $Context -Name 'autodiscover-dns'
    if ($autodiscoverArtifact) {
        $payload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $autodiscoverArtifact)
        if ($payload -and $payload.Results) {
            $results = if ($payload.Results -is [System.Collections.IEnumerable] -and -not ($payload.Results -is [string])) { @($payload.Results) } else { @($payload.Results) }
            foreach ($domainEntry in $results) {
                if (-not $domainEntry) { continue }
                $domain = $domainEntry.Domain
                $autoRecord = ($domainEntry.Lookups | Where-Object { $_.Label -eq 'Autodiscover' } | Select-Object -First 1)
                if (-not $autoRecord) { continue }

                $targetsRaw = if ($autoRecord.Targets -is [System.Collections.IEnumerable] -and -not ($autoRecord.Targets -is [string])) { @($autoRecord.Targets) } else { @($autoRecord.Targets) }
                $targetsClean = $targetsRaw | Where-Object { $_ }
                if ($autoRecord.Success -eq $true -and $targetsClean.Count -gt 0) {
                    $targets = $targetsClean
                    $targetText = $targets -join ', '
                    if ($targets -match 'autodiscover\.outlook\.com') {
                        Add-CategoryNormal -CategoryResult $result -Title ("Autodiscover CNAME healthy for {0}" -f $domain) -Evidence $targetText
                    } else {
                        Add-CategoryIssue -CategoryResult $result -Severity 'medium' -Title ("Autodiscover for {0} points to {1}" -f $domain, $targetText) -Evidence 'Expected autodiscover.outlook.com for Exchange Online onboarding.' -Subcategory 'Autodiscover DNS'
                    }
                } elseif ($autoRecord.Success -eq $false) {
                    $evidence = if ($autoRecord.Error) { $autoRecord.Error } else { "Lookup failed for autodiscover.$domain" }
                    Add-CategoryIssue -CategoryResult $result -Severity 'high' -Title ("Cannot locate Exchange Services for {0}" -f $domain) -Evidence $evidence -Subcategory 'Autodiscover DNS'
                }
            }
        }
    }

    return $result
}
