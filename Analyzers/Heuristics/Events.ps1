<#!
.SYNOPSIS
    Event log heuristics summarizing recent error and warning volume.
#>

. (Join-Path -Path (Split-Path $PSScriptRoot -Parent) -ChildPath 'AnalyzerCommon.ps1')

function Normalize-EventsString {
    param(
        [AllowNull()][object]$Value
    )

    if ($null -eq $Value) { return $null }

    $text = [string]$Value
    if ([string]::IsNullOrWhiteSpace($text)) { return $null }

    return $text.Trim()
}

function ConvertTo-EventsDateTimeUtc {
    param(
        [AllowNull()][object]$Value
    )

    if ($null -eq $Value) { return $null }

    if ($Value -is [datetime]) {
        $typed = [datetime]$Value
        if ($typed.Kind -eq [System.DateTimeKind]::Utc) { return $typed }
        return $typed.ToUniversalTime()
    }

    $text = [string]$Value
    if ([string]::IsNullOrWhiteSpace($text)) { return $null }

    try {
        $parsed = [datetime]::Parse($text, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::RoundtripKind)
    } catch {
        try {
            $parsed = [datetime]::Parse($text)
        } catch {
            return $null
        }
    }

    if ($parsed.Kind -eq [System.DateTimeKind]::Utc) { return $parsed }
    return $parsed.ToUniversalTime()
}

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

    $workgroupSuppression = $false
    $domainName = $null
    $isDomainJoined = $null
    $systemArtifact = Get-AnalyzerArtifact -Context $Context -Name 'system'
    if ($systemArtifact) {
        $systemPayload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $systemArtifact)
        if ($systemPayload -and $systemPayload.ComputerSystem -and -not $systemPayload.ComputerSystem.Error) {
            $computerSystem = $systemPayload.ComputerSystem
            if ($computerSystem.PSObject.Properties['Domain']) {
                $domainName = Normalize-EventsString -Value $computerSystem.Domain
            }
            if ($computerSystem.PSObject.Properties['PartOfDomain']) {
                $isDomainJoined = [bool]$computerSystem.PartOfDomain
            }

            if ($domainName -and $domainName.Equals('WORKGROUP', [System.StringComparison]::OrdinalIgnoreCase) -and $isDomainJoined -ne $true) {
                $workgroupSuppression = $true
            }
        }
    }

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

            if ($payload.PSObject.Properties['Security']) {
                $securityPayload = $payload.Security
                Write-HeuristicDebug -Source 'Events' -Message 'Processing security logon payload' -Data ([ordered]@{
                    HasSecurityData = [bool]$securityPayload
                })

                if ($securityPayload -and -not ($securityPayload.PSObject.Properties['Error'] -and $securityPayload.Error)) {
                    $logonEntries = $securityPayload.Logon4624
                    $nowUtc = (Get-Date).ToUniversalTime()
                    $windowStart = $nowUtc.AddHours(-24)

                    $ntlmCount24h = 0
                    $kerberosInWindow = $false
                    $lastEventTime = $null
                    $hostSamples = New-Object System.Collections.Generic.List[string]
                    $hostSet = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)

                    foreach ($entry in $logonEntries) {
                        if (-not $entry) { continue }

                        $timestamp = $null
                        if ($entry.PSObject.Properties['TimeCreatedUtc']) {
                            $timestamp = ConvertTo-EventsDateTimeUtc -Value $entry.TimeCreatedUtc
                        }
                        if (-not $timestamp -and $entry.PSObject.Properties['TimeCreated']) {
                            $timestamp = ConvertTo-EventsDateTimeUtc -Value $entry.TimeCreated
                        }

                        if ($timestamp) {
                            if (-not $lastEventTime -or $timestamp -gt $lastEventTime) {
                                $lastEventTime = $timestamp
                            }
                        }

                        $authPackage = $null
                        if ($entry.PSObject.Properties['AuthenticationPackageName']) {
                            $authPackage = Normalize-EventsString -Value $entry.AuthenticationPackageName
                        }

                        $logonType = $null
                        if ($entry.PSObject.Properties['LogonType']) {
                            $logonRaw = $entry.LogonType
                            if ($logonRaw -is [int]) {
                                $logonType = [int]$logonRaw
                            } elseif ($logonRaw -ne $null) {
                                $parsed = 0
                                if ([int]::TryParse([string]$logonRaw, [ref]$parsed)) {
                                    $logonType = $parsed
                                }
                            }
                        }

                        $workstationName = $null
                        if ($entry.PSObject.Properties['WorkstationName']) {
                            $workstationName = Normalize-EventsString -Value $entry.WorkstationName
                        }

                        $ipAddress = $null
                        if ($entry.PSObject.Properties['IpAddress']) {
                            $ipAddress = Normalize-EventsString -Value $entry.IpAddress
                        }

                        if ($timestamp -and $timestamp -ge $windowStart) {
                            if ($authPackage -and $authPackage.Equals('Kerberos', [System.StringComparison]::OrdinalIgnoreCase)) {
                                $kerberosInWindow = $true
                            }

                            if (($logonType -eq 3) -and $authPackage -and $authPackage.Equals('NTLM', [System.StringComparison]::OrdinalIgnoreCase)) {
                                $ntlmCount24h++

                                $hostCandidate = $workstationName
                                if (-not $hostCandidate -and $ipAddress) { $hostCandidate = $ipAddress }

                                if ($hostCandidate -and $hostSet.Add($hostCandidate)) {
                                    if ($hostSamples.Count -lt 5) {
                                        $hostSamples.Add($hostCandidate) | Out-Null
                                    }
                                }
                            }
                        }
                    }

                    Add-CategoryCheck -CategoryResult $result -Name 'NTLM network logons (24h)' -Status ([string]$ntlmCount24h) -Subcategory 'Authentication'
                    $kerberosStatus = if ($kerberosInWindow) { 'detected' } else { 'not detected' }
                    Add-CategoryCheck -CategoryResult $result -Name 'Kerberos authentication (24h)' -Status $kerberosStatus -Subcategory 'Authentication'

                    if ($ntlmCount24h -ge 10 -and $kerberosInWindow) {
                        if (-not $workgroupSuppression) {
                            $evidence = [ordered]@{
                                ntlmCount24h = $ntlmCount24h
                                sampleHosts  = $hostSamples.ToArray()
                                lastUtc      = if ($lastEventTime) { $lastEventTime.ToString('o') } else { $null }
                            }

                            $evidenceJson = ConvertTo-Json -InputObject $evidence -Compress -Depth 3
                            Add-CategoryIssue -CategoryResult $result -Severity 'medium' -Title 'NTLM network logons detected (Kerberos not used)' -Evidence $evidenceJson -Subcategory 'Authentication'
                        } else {
                            Write-HeuristicDebug -Source 'Events' -Message 'NTLM fallback heuristic suppressed for workgroup device' -Data ([ordered]@{
                                DomainName = $domainName
                                IsDomainJoined = $isDomainJoined
                            })
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
