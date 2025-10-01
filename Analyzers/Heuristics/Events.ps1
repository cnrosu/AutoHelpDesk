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

            if ($payload.PSObject.Properties['ServicingStack']) {
                $servicing = $payload.ServicingStack
                Write-HeuristicDebug -Source 'Events' -Message 'Evaluating servicing stack signals' -Data ([ordered]@{
                    HasNode = [bool]$servicing
                })

                if ($servicing) {
                    $count = 0
                    if ($servicing.PSObject.Properties['Servicing1016Count']) {
                        try { $count = [int]$servicing.Servicing1016Count } catch { $count = 0 }
                    }

                    $lastUtc = $null
                    if ($servicing.PSObject.Properties['LastUtc'] -and $servicing.LastUtc) {
                        $lastUtc = [string]$servicing.LastUtc
                    }

                    $tailLines = @()
                    if ($servicing.PSObject.Properties['CbsTailLines'] -and $servicing.CbsTailLines) {
                        $tailValue = $servicing.CbsTailLines
                        if ($tailValue -is [System.Collections.IEnumerable] -and -not ($tailValue -is [string])) {
                            foreach ($line in $tailValue) {
                                if ($null -ne $line) { $tailLines += [string]$line }
                            }
                        } else {
                            $tailLines = @([string]$tailValue)
                        }
                    }

                    $keywordRegex = [System.Text.RegularExpressions.Regex]::new('(?i)\b(cannot repair|corrupt)\b')
                    $matchingLines = New-Object System.Collections.Generic.List[string]
                    foreach ($line in $tailLines) {
                        if ([string]::IsNullOrWhiteSpace($line)) { continue }
                        if ($keywordRegex.IsMatch($line)) {
                            $matchingLines.Add($line) | Out-Null
                        }
                    }

                    $hasKeyword = ($matchingLines.Count -gt 0)
                    $snippetLines = @()
                    if ($hasKeyword) {
                        $snippetLines = $matchingLines | Select-Object -First 5
                    } elseif ($tailLines.Count -gt 0) {
                        $snippetLines = $tailLines | Select-Object -Last ([math]::Min(5, $tailLines.Count))
                    }

                    $snippetText = if ($snippetLines -and $snippetLines.Count -gt 0) { ($snippetLines -join [System.Environment]::NewLine) } else { $null }

                    $shouldFlag = ($count -gt 0) -or $hasKeyword
                    Write-HeuristicDebug -Source 'Events' -Message 'Servicing stack heuristic evaluation' -Data ([ordered]@{
                        EventCount   = $count
                        HasKeyword   = $hasKeyword
                        LastUtc      = $lastUtc
                        TailLineCount = $tailLines.Count
                    })

                    if ($shouldFlag) {
                        $evidence = [ordered]@{
                            servicing1016Count = $count
                            lastUtc            = if ($lastUtc) { $lastUtc } else { '(none)' }
                            cbsTailSnippet     = if ($snippetText) { $snippetText } else { '(no tail data)' }
                        }

                        Add-CategoryIssue -CategoryResult $result -Severity 'high' -Title 'Servicing stack reports corruption' -Evidence ([pscustomobject]$evidence) -Subcategory 'Servicing Stack / CBS'
                    }
                }
            }
        }
    } else {
        Add-CategoryIssue -CategoryResult $result -Severity 'high' -Title 'Event log artifact missing, so noisy or unhealthy logs may be hidden.' -Subcategory 'Collection'
    }

    return $result
}
