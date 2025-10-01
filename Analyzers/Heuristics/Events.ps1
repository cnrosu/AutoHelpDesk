<#!
.SYNOPSIS
    Event log heuristics summarizing recent error and warning volume.
#>

. (Join-Path -Path (Split-Path $PSScriptRoot -Parent) -ChildPath 'AnalyzerCommon.ps1')

function Invoke-EventsHeuristics {
    param(
        [Parameter(Mandatory)]
        $Context
    )

    Write-HeuristicDebug -Source 'Events' -Message 'Starting event log heuristics' -Data ([ordered]@{
        ArtifactCount = if ($Context -and $Context.Artifacts) { $Context.Artifacts.Count } else { 0 }
    })

    $result = New-CategoryResult -Name 'Events'

    $eventsArtifact = Get-AnalyzerArtifact -Context $Context -Name 'events'
    Write-HeuristicDebug -Source 'Events' -Message 'Resolved events artifact' -Data ([ordered]@{
        Found = [bool]$eventsArtifact
    })
    if ($eventsArtifact) {
        $payload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $eventsArtifact)
        Write-HeuristicDebug -Source 'Events' -Message 'Resolved events payload' -Data ([ordered]@{
            HasPayload = [bool]$payload
        })
        if ($payload) {
            foreach ($logName in @('System','Application','GroupPolicy')) {
                Write-HeuristicDebug -Source 'Events' -Message ('Inspecting {0} log entries' -f $logName)
                if (-not $payload.PSObject.Properties[$logName]) { continue }
                $entries = $payload.$logName
                if ($entries -and -not $entries.Error) {
                    $logSubcategory = ("{0} Event Log" -f $logName)
                    $errorCount = ($entries | Where-Object { $_.LevelDisplayName -eq 'Error' }).Count
                    $warnCount = ($entries | Where-Object { $_.LevelDisplayName -eq 'Warning' }).Count
                    Add-CategoryCheck -CategoryResult $result -Name ("{0} log errors" -f $logName) -Status ([string]$errorCount)
                    Add-CategoryCheck -CategoryResult $result -Name ("{0} log warnings" -f $logName) -Status ([string]$warnCount)
                    if ($logName -eq 'GroupPolicy') {
                        if ($errorCount -gt 0) {
                            Add-CategoryIssue -CategoryResult $result -Severity 'medium' -Title 'Group Policy Operational log errors detected, indicating noisy or unhealthy logs.' -Evidence ("Errors: {0}" -f $errorCount) -Subcategory $logSubcategory
                        }
                    } else {
                        if ($errorCount -gt 20) {
                            Add-CategoryIssue -CategoryResult $result -Severity 'medium' -Title ("{0} log shows many errors ({1} in recent sample), indicating noisy or unhealthy logs." -f $logName, $errorCount) -Evidence ("Errors recorded: {0}" -f $errorCount) -Subcategory $logSubcategory
                        }
                        if ($warnCount -gt 40) {
                            Add-CategoryIssue -CategoryResult $result -Severity 'low' -Title ("Many warnings in {0} log, indicating noisy or unhealthy logs." -f $logName) -Subcategory $logSubcategory
                        }
                    }
                } elseif ($entries.Error) {
                    $logSubcategory = ("{0} Event Log" -f $logName)
                    Add-CategoryIssue -CategoryResult $result -Severity 'high' -Title ("Unable to read {0} event log, so noisy or unhealthy logs may be hidden." -f $logName) -Evidence $entries.Error -Subcategory $logSubcategory
                }
            }

            $dcomProperty = $payload.PSObject.Properties['SystemDcom']
            Write-HeuristicDebug -Source 'Events' -Message 'Evaluating DCOM access denied payload presence' -Data ([ordered]@{
                HasSystemDcom = [bool]$dcomProperty
            })
            if ($dcomProperty) {
                $dcomPayload = $payload.SystemDcom
                $hasError = ($dcomPayload -and $dcomPayload.PSObject.Properties['Error'] -and -not [string]::IsNullOrWhiteSpace($dcomPayload.Error))
                $eventCount = if ($dcomPayload -and $dcomPayload.PSObject.Properties['EventCount']) { $dcomPayload.EventCount } elseif ($dcomPayload -and $dcomPayload.PSObject.Properties['Events']) { (@($dcomPayload.Events)).Count } else { 0 }
                Write-HeuristicDebug -Source 'Events/DCOM' -Message 'DCOM payload overview' -Data ([ordered]@{
                    HasError   = $hasError
                    EventCount = $eventCount
                })

                if ($hasError) {
                    Add-CategoryCheck -CategoryResult $result -Name 'DCOM 10016 events' -Status 'Unavailable' -Details $dcomPayload.Error -Subcategory 'DCOM'
                } elseif ($dcomPayload) {
                    $events = @()
                    if ($dcomPayload.PSObject.Properties['Events']) { $events = @($dcomPayload.Events) }
                    $guidPattern = '[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}'
                    $clsidRegex = [System.Text.RegularExpressions.Regex]::new("(?i)CLSID\s*\{\s*(?<guid>$guidPattern)\s*\}", [System.Text.RegularExpressions.RegexOptions]::Compiled)
                    $appidRegex = [System.Text.RegularExpressions.Regex]::new("(?i)APPID\s*\{\s*(?<guid>$guidPattern)\s*\}", [System.Text.RegularExpressions.RegexOptions]::Compiled)
                    $parsed = New-Object System.Collections.Generic.List[object]
                    $parseFailures = 0

                    foreach ($entry in $events) {
                        if (-not $entry) { continue }

                        $timestamp = $null
                        if ($entry.PSObject.Properties['TimeCreatedUtc'] -and $entry.TimeCreatedUtc) {
                            $timestamp = ConvertFrom-Iso8601 $entry.TimeCreatedUtc
                        } elseif ($entry.PSObject.Properties['TimeCreated'] -and $entry.TimeCreated) {
                            $timestamp = ConvertFrom-Iso8601 $entry.TimeCreated
                        }

                        if (-not $timestamp -and $entry.PSObject.Properties['TimeCreated'] -and ($entry.TimeCreated -is [datetime])) {
                            $timestamp = [datetime]$entry.TimeCreated
                        }

                        if (-not $timestamp) { $parseFailures++; continue }
                        if ($timestamp.Kind -ne [System.DateTimeKind]::Utc) {
                            $timestamp = $timestamp.ToUniversalTime()
                        }

                        $message = $null
                        if ($entry.PSObject.Properties['Message']) {
                            $message = [string]$entry.Message
                        }

                        if ([string]::IsNullOrWhiteSpace($message)) { $parseFailures++; continue }

                        $clsidMatch = $clsidRegex.Match($message)
                        $appidMatch = $appidRegex.Match($message)
                        if (-not ($clsidMatch.Success -and $appidMatch.Success)) { $parseFailures++; continue }

                        $clsidValue = $clsidMatch.Groups['guid'].Value.ToUpperInvariant()
                        $appidValue = $appidMatch.Groups['guid'].Value.ToUpperInvariant()
                        if ([string]::IsNullOrWhiteSpace($clsidValue) -or [string]::IsNullOrWhiteSpace($appidValue)) { $parseFailures++; continue }

                        $parsed.Add([pscustomobject]@{
                            TimestampUtc = $timestamp
                            Clsid        = $clsidValue
                            AppId        = $appidValue
                        }) | Out-Null
                    }

                    Write-HeuristicDebug -Source 'Events/DCOM' -Message 'Parsed DCOM 10016 entries' -Data ([ordered]@{
                        Parsed        = $parsed.Count
                        ParseFailures = $parseFailures
                    })

                    Add-CategoryCheck -CategoryResult $result -Name 'DCOM 10016 events (14d)' -Status ([string]$parsed.Count) -Details ("Parsed={0}; Skipped={1}" -f $parsed.Count, $parseFailures) -Subcategory 'DCOM'

                    if ($parsed.Count -gt 0) {
                        $bucketMap = @{}
                        foreach ($item in $parsed) {
                            $bucketStart = [datetime]::SpecifyKind($item.TimestampUtc.Date, [System.DateTimeKind]::Utc)
                            $key = '{0}|{1}|{2:o}' -f $item.Clsid, $item.AppId, $bucketStart
                            if (-not $bucketMap.ContainsKey($key)) {
                                $bucketMap[$key] = [ordered]@{
                                    Clsid      = $item.Clsid
                                    AppId      = $item.AppId
                                    BucketUtc  = $bucketStart
                                    Count      = 0
                                    LastUtc    = $item.TimestampUtc
                                }
                            }

                            $aggregate = $bucketMap[$key]
                            $aggregate.Count++
                            if ($item.TimestampUtc -gt $aggregate.LastUtc) { $aggregate.LastUtc = $item.TimestampUtc }
                        }

                        $threshold = 20
                        $noisyBuckets = @($bucketMap.Values | Where-Object { $_.Count -ge $threshold })
                        Write-HeuristicDebug -Source 'Events/DCOM' -Message 'Buckets meeting DCOM threshold' -Data ([ordered]@{
                            Threshold   = $threshold
                            BucketCount = $noisyBuckets.Count
                        })
                        if ($noisyBuckets.Count -gt 0) {
                            $evidenceLines = New-Object System.Collections.Generic.List[string]
                            $sortedBuckets = $noisyBuckets | Sort-Object -Property @{ Expression = 'Count'; Descending = $true }, @{ Expression = 'BucketUtc'; Descending = $false }
                            foreach ($bucket in $sortedBuckets) {
                                $clsidTail = if ($bucket.Clsid.Length -gt 8) { $bucket.Clsid.Substring($bucket.Clsid.Length - 8) } else { $bucket.Clsid }
                                $appIdTail = if ($bucket.AppId.Length -gt 8) { $bucket.AppId.Substring($bucket.AppId.Length - 8) } else { $bucket.AppId }
                                $lastUtcText = $bucket.LastUtc.ToUniversalTime().ToString('o')
                                $evidenceLines.Add(("clsidTail={0}; appIdTail={1}; count24h={2}; lastUtc={3}" -f $clsidTail, $appIdTail, $bucket.Count, $lastUtcText)) | Out-Null
                            }

                            Add-CategoryIssue -CategoryResult $result -Severity 'info' -Title 'Repeated DCOM 10016 events (noisy)' -Evidence ($evidenceLines -join "`n") -Subcategory 'DCOM'
                        }
                    }
                }
            }
        }
    } else {
        Add-CategoryIssue -CategoryResult $result -Severity 'high' -Title 'Event log artifact missing, so noisy or unhealthy logs may be hidden.' -Subcategory 'Collection'
    }

    return $result
}
