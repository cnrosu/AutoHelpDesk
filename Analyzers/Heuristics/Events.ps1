<#!
.SYNOPSIS
    Event log heuristics summarizing recent error and warning volume.
#>

. (Join-Path -Path (Split-Path $PSScriptRoot -Parent) -ChildPath 'AnalyzerCommon.ps1')

$eventsModuleRoot = Join-Path -Path $PSScriptRoot -ChildPath 'Events'
. (Join-Path -Path $eventsModuleRoot -ChildPath 'Common.ps1')
. (Join-Path -Path $eventsModuleRoot -ChildPath 'Dns.ps1')
. (Join-Path -Path $eventsModuleRoot -ChildPath 'Netlogon.ps1')
. (Join-Path -Path $eventsModuleRoot -ChildPath 'Authentication.ps1')
. (Join-Path -Path $eventsModuleRoot -ChildPath 'Vpn.ps1')

# Structured remediation steps derived from the legacy block:
# - The "Events (Log Health)" heading and symptoms sentence become a text step with a title.
# - Each action sentence maps to a text step that introduces the related PowerShell snippet.
# - The fenced code samples become code steps that keep the same commands and language.
$script:EventsLogHealthRemediation = @'
[
  {
    "type": "text",
    "title": "Events (Log Health)",
    "content": "Symptoms: Event logs unreadable; high error/warning rates; GP Operational errors."
  },
  {
    "type": "text",
    "title": "Restart Windows Event Log service",
    "content": "Ensure the Windows Event Log service is healthy."
  },
  {
    "type": "code",
    "lang": "powershell",
    "content": "Get-Service EventLog | Restart-Service"
  },
  {
    "type": "text",
    "title": "Increase log size",
    "content": "Clear only if stakeholders approve before resizing."
  },
  {
    "type": "code",
    "lang": "powershell",
    "content": "wevtutil sl System /ms:67108864\nwevtutil sl Application /ms:67108864"
  },
  {
    "type": "text",
    "title": "Validate log health",
    "content": "Confirm the System and Application logs respond without errors."
  },
  {
    "type": "code",
    "lang": "powershell",
    "content": "Get-WinEvent -ListLog * | Where-Object { $_.LogName -in 'System','Application' }"
  }
]
'@

function ConvertTo-LogView {
    param(
        $Node
    )

    $out = [pscustomobject]@{
        Events = @()
        Error  = $null
    }

    if ($null -eq $Node) {
        return $out
    }

    if ($Node -is [hashtable] -or $Node -is [psobject]) {
        if ($Node.PSObject.Properties['Events']) {
            $out.Events = @($Node.Events)
        } else {
            $out.Events = @($Node)
        }

        if ($Node.PSObject.Properties['Error']) {
            $out.Error = $Node.Error
        }

        return $out
    }

    if ($Node -is [System.Collections.IEnumerable] -and -not ($Node -is [string])) {
        $out.Events = @($Node)
        return $out
    }

    $out.Events = @($Node)
    return $out
}

function Invoke-EventsHeuristics {
    param(
        [Parameter(Mandatory)]
        $Context
    )

    Write-HeuristicDebug -Source 'Events' -Message 'Starting event log heuristics' -Data ([ordered]@{
        ArtifactCount = if ($Context -and $Context.Artifacts) { $Context.Artifacts.Count } else { 0 }
    })

    $deviceName = Get-EventsCurrentDeviceName -Context $Context

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

                $logView = ConvertTo-LogView $payload.$logName
                $entries = @($logView.Events | Where-Object { $_ -ne $null })
                $logError = $logView.Error

                $logSubcategory = ("{0} Event Log" -f $logName)

                $errorEvidence = $null
                if ($null -ne $logError) {
                    if ($logError -is [System.Collections.IEnumerable] -and -not ($logError -is [string])) {
                        $filteredErrors = @($logError | Where-Object { $_ })
                        if ($filteredErrors.Count -gt 0) {
                            $errorEvidence = $filteredErrors
                        }
                    } else {
                        $errorEvidence = $logError
                    }
                }

                if ($errorEvidence) {
                    Add-CategoryIssue -CategoryResult $result -Severity 'warning' -Title ("{0} Event Log: Unable to read {0} event log, so noisy or unhealthy logs may be hidden." -f $logName) -Evidence $errorEvidence -Subcategory $logSubcategory -Remediation $script:EventsLogHealthRemediation
                    continue
                }

                if ($entries) {
                    $errorCount = ($entries | Where-Object { $_.LevelDisplayName -eq 'Error' }).Count
                    $warnCount = ($entries | Where-Object { $_.LevelDisplayName -eq 'Warning' }).Count

                    Add-CategoryCheck -CategoryResult $result -Name ("{0} log errors" -f $logName) -Status ([string]$errorCount)
                    Add-CategoryCheck -CategoryResult $result -Name ("{0} log warnings" -f $logName) -Status ([string]$warnCount)

                    if ($logName -eq 'GroupPolicy') {
                        if ($errorCount -gt 0) {
                            Add-CategoryIssue -CategoryResult $result -Severity 'medium' -Title 'Group Policy Operational log errors detected, indicating noisy or unhealthy logs.' -Evidence ("Errors: {0}" -f $errorCount) -Subcategory $logSubcategory -Remediation $script:EventsLogHealthRemediation
                        }
                    } else {
                        if ($errorCount -gt 20) {
                            Add-CategoryIssue -CategoryResult $result -Severity 'medium' -Title ("{0} log shows many errors ({1} in recent sample), indicating noisy or unhealthy logs." -f $logName, $errorCount) -Evidence ("Errors recorded: {0}" -f $errorCount) -Subcategory $logSubcategory -Remediation $script:EventsLogHealthRemediation
                        }
                        if ($warnCount -gt 40) {
                            Add-CategoryIssue -CategoryResult $result -Severity 'low' -Title ("Many warnings in {0} log, indicating noisy or unhealthy logs." -f $logName) -Subcategory $logSubcategory -Remediation $script:EventsLogHealthRemediation
                        }
                    }
                }
            }

            if ($payload.PSObject.Properties['System']) {
                Invoke-EventsNetlogonTrustChecks -Result $result -SystemEntries $payload.System -Authentication $payload.Authentication
            }

            if ($payload.PSObject.Properties['Authentication']) {
                Invoke-EventsAuthenticationChecks -Result $result -Authentication $payload.Authentication -DeviceName $deviceName
            }
            $dnsClientData = $null
            if ($payload.PSObject.Properties['Networking']) {
                $networking = $payload.Networking
                if ($networking -and $networking.PSObject.Properties['DnsClient']) {
                    $dnsClientData = $networking.DnsClient
                }
            } elseif ($payload.PSObject.Properties['DnsClient']) {
                $dnsClientData = $payload.DnsClient
            }

            if ($dnsClientData) {
                Invoke-EventsDnsChecks -Result $result -DnsClient $dnsClientData -Context $Context
            }
        }
    } else {
        Add-CategoryIssue -CategoryResult $result -Severity 'warning' -Title 'Event log artifact missing, so noisy or unhealthy logs may be hidden.' -Subcategory 'Collection'
    }

    Invoke-EventsVpnAuthenticationChecks -Result $result -Context $Context

    return $result
}
