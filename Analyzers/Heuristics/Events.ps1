<#!
.SYNOPSIS
    Event log heuristics summarizing recent error and warning volume.
#>

. (Join-Path -Path (Split-Path $PSScriptRoot -Parent) -ChildPath 'AnalyzerCommon.ps1')

$servicesCommonPath = Join-Path -Path $PSScriptRoot -ChildPath 'Services/Services.Common.ps1'
if (-not (Get-Command ConvertTo-ServiceCollection -ErrorAction SilentlyContinue)) {
    if (Test-Path -LiteralPath $servicesCommonPath) {
        . $servicesCommonPath
    }
}

function ConvertTo-EventsCategoryArray {
    param($Value)

    if ($null -eq $Value) { return @() }
    if ($Value -is [System.Collections.IEnumerable] -and -not ($Value -is [string])) {
        return @($Value)
    }

    return @($Value)
}

function Get-EventsCategoryAllEntries {
    param($Payload)

    $entries = New-Object System.Collections.Generic.List[object]
    if (-not $Payload) { return $entries.ToArray() }

    foreach ($property in $Payload.PSObject.Properties) {
        if (-not $property) { continue }

        $value = $property.Value
        foreach ($item in (ConvertTo-EventsCategoryArray -Value $value)) {
            if (-not $item) { continue }
            if ($item.PSObject.Properties['Error']) { continue }
            $entries.Add($item) | Out-Null
        }
    }

    return $entries.ToArray()
}

function Get-EventsCategoryServiceLookup {
    param(
        [Parameter(Mandatory)]
        $Context
    )

    $candidates = @('service-baseline','services')
    foreach ($candidate in $candidates) {
        $artifact = Get-AnalyzerArtifact -Context $Context -Name $candidate
        if (-not $artifact) { continue }

        $payload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $artifact)
        if (-not $payload) { continue }

        $servicesValue = $null
        if ($payload.PSObject.Properties['Services']) { $servicesValue = $payload.Services }
        elseif ($payload.PSObject.Properties['Items']) { $servicesValue = $payload.Items }
        if (-not $servicesValue) { continue }

        $normalized = $null
        if (Get-Command ConvertTo-ServiceCollection -ErrorAction SilentlyContinue) {
            $normalized = ConvertTo-ServiceCollection -Value $servicesValue
        }

        if (-not $normalized) { continue }
        if (-not $normalized.PSObject.Properties['Services']) { continue }

        $lookup = @{}
        foreach ($service in (ConvertTo-EventsCategoryArray -Value $normalized.Services)) {
            if (-not $service) { continue }
            $name = $null
            if ($service.PSObject.Properties['Name']) { $name = [string]$service.Name }
            if (-not $name) { continue }

            $key = $name.ToLowerInvariant()
            $lookup[$key] = $service
        }

        if ($lookup.Count -gt 0) {
            return [pscustomobject]@{
                Lookup = $lookup
                Source = $candidate
            }
        }
    }

    return $null
}

function Get-EventsCategoryCorrelationMatches {
    param(
        [object[]]$Events,
        [string[]]$ProviderPatterns = @(),
        [string[]]$MessagePatterns = @(),
        [int[]]$EventIds = @()
    )

    $matches = New-Object System.Collections.Generic.List[object]
    if (-not $Events) { return $matches.ToArray() }

    foreach ($event in $Events) {
        if (-not $event) { continue }

        $provider = $null
        if ($event.PSObject.Properties['ProviderName']) { $provider = [string]$event.ProviderName }
        $message = $null
        if ($event.PSObject.Properties['Message']) { $message = [string]$event.Message }
        $level = $null
        if ($event.PSObject.Properties['LevelDisplayName']) { $level = [string]$event.LevelDisplayName }

        $idValue = $null
        if ($event.PSObject.Properties['Id']) {
            try { $idValue = [int]$event.Id } catch { $idValue = $event.Id }
        }

        $matched = $false

        foreach ($pattern in $ProviderPatterns) {
            if (-not $pattern) { continue }
            if ($provider -and ($provider -match $pattern)) { $matched = $true; break }
        }

        if (-not $matched) {
            foreach ($pattern in $MessagePatterns) {
                if (-not $pattern) { continue }
                if ($message -and ($message -match $pattern)) { $matched = $true; break }
            }
        }

        if (-not $matched -and $EventIds -and $EventIds.Count -gt 0) {
            if ($null -ne $idValue -and ($EventIds -contains $idValue)) { $matched = $true }
        }

        if (-not $matched) { continue }

        $levelNormalized = if ($level) { $level.Trim().ToLowerInvariant() } else { '' }
        if ($levelNormalized -and -not @('error','warning','critical') -contains $levelNormalized) {
            # Keep informational events when a match was found but level is unexpected.
        }

        $matches.Add($event) | Out-Null
    }

    return $matches.ToArray()
}

function Get-EventsCategoryEventSummaries {
    param(
        [object[]]$Events,
        [int]$Max = 3
    )

    $summaries = New-Object System.Collections.Generic.List[object]
    if (-not $Events) { return $summaries.ToArray() }

    foreach ($entry in ($Events | Select-Object -First $Max)) {
        if (-not $entry) { continue }

        $message = $null
        if ($entry.PSObject.Properties['Message']) { $message = [string]$entry.Message }
        if ($message) {
            $message = ($message -split "\r?\n" | Select-Object -First 1)
            if ($message.Length -gt 180) { $message = $message.Substring(0, 177) + '...' }
        }

        $summaries.Add([ordered]@{
            id       = if ($entry.PSObject.Properties['Id']) { $entry.Id } else { $null }
            provider = if ($entry.PSObject.Properties['ProviderName']) { $entry.ProviderName } else { $null }
            level    = if ($entry.PSObject.Properties['LevelDisplayName']) { $entry.LevelDisplayName } else { $null }
            message  = $message
        }) | Out-Null
    }

    return $summaries.ToArray()
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
    $payload = $null
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
        }
    } else {
        Add-CategoryIssue -CategoryResult $result -Severity 'high' -Title 'Event log artifact missing, so noisy or unhealthy logs may be hidden.' -Subcategory 'Collection'
    }

    $allEvents = Get-EventsCategoryAllEntries -Payload $payload

    $serviceLookupInfo = Get-EventsCategoryServiceLookup -Context $Context
    $wuMatches = Get-EventsCategoryCorrelationMatches -Events $allEvents -ProviderPatterns @('(?i)windows\s+update','(?i)windowsupdateclient','(?i)wuauserv','(?i)bits','(?i)intelligent\s+transfer') -MessagePatterns @('(?i)windows\s+update','(?i)wuauserv','(?i)bits','(?i)intelligent\s+transfer','(?i)service\s+(bits|wuauserv)\s+.*failed') -EventIds @(20,25,31,34,35,1001,1002,2004,3002,7000,7001,7022,7023,7024,7031,7032)
    $vpnMatches = Get-EventsCategoryCorrelationMatches -Events $allEvents -ProviderPatterns @('(?i)rasman','(?i)rasclient','(?i)ikeext','(?i)remoteaccess','(?i)vpn') -MessagePatterns @('(?i)vpn','(?i)rasman','(?i)ikeext','(?i)remote\s+access\s+connection','(?i)ikev2','(?i)l2tp','(?i)service\s+(rasman|ikeext)\s+.*failed') -EventIds @(20226,20227,20255,20271,7031,7032,7023,7024,7000,7001)
    Write-HeuristicDebug -Source 'Events' -Message 'Correlated event matches evaluated for service dependency heuristic' -Data ([ordered]@{
        ServiceLookup = if ($serviceLookupInfo) { $serviceLookupInfo.Source } else { '(none)' }
        WindowsUpdate = $wuMatches.Count
        VPN           = $vpnMatches.Count
    })

    if ($serviceLookupInfo) {
        $serviceLookup = $serviceLookupInfo.Lookup
        $hasWuFailures = ($wuMatches.Count -gt 0)
        $hasVpnSignals = ($vpnMatches.Count -gt 0)

        $requiredServices = @(
            [pscustomobject]@{ Name = 'RasMan';   Display = 'Remote Access Connection Manager (RasMan)'; Role = 'vpn'; Impact = 'VPN connections cannot establish tunnels.'; RecommendedStart = 'Manual (Trigger Start)' },
            [pscustomobject]@{ Name = 'IKEEXT';   Display = 'IKE and AuthIP IPsec Keying Modules (IKEEXT)'; Role = 'vpn'; Impact = 'VPN and IPsec negotiations will fail.'; RecommendedStart = 'Automatic' },
            [pscustomobject]@{ Name = 'BITS';     Display = 'Background Intelligent Transfer Service (BITS)'; Role = 'wu'; Impact = 'Windows Update, antivirus, and Store downloads will stall.'; RecommendedStart = 'Automatic (Delayed Start)' },
            [pscustomobject]@{ Name = 'wuauserv'; Display = 'Windows Update (wuauserv)'; Role = 'wu'; Impact = 'Windows Update scans and installs will fail.'; RecommendedStart = 'Manual (Trigger Start)' }
        )

        foreach ($serviceInfo in $requiredServices) {
            if (-not $serviceInfo) { continue }

            $key = $serviceInfo.Name.ToLowerInvariant()
            $record = if ($serviceLookup.ContainsKey($key)) { $serviceLookup[$key] } else { $null }

            $statusNormalized = 'unknown'
            if ($record -and $record.PSObject.Properties['StatusNormalized']) { $statusNormalized = [string]$record.StatusNormalized }
            elseif ($record -and $record.PSObject.Properties['NormalizedStatus']) { $statusNormalized = [string]$record.NormalizedStatus }

            $startNormalized = 'unknown'
            if ($record -and $record.PSObject.Properties['StartModeNormalized']) { $startNormalized = [string]$record.StartModeNormalized }
            elseif ($record -and $record.PSObject.Properties['NormalizedStartType']) { $startNormalized = [string]$record.NormalizedStartType }

            $stateDescriptor = 'unknown'
            $shouldFlag = $false
            $impactArea = [string]$serviceInfo.Role
            $hasCorrelatedIssue = if ($impactArea -eq 'vpn') { $hasVpnSignals } else { $hasWuFailures }

            if (-not $record) {
                $shouldFlag = $true
                $stateDescriptor = 'missing'
            } elseif ($startNormalized -eq 'disabled') {
                $shouldFlag = $true
                $stateDescriptor = 'disabled'
            } elseif ($statusNormalized -ne 'running' -and $hasCorrelatedIssue) {
                $shouldFlag = $true
                $stateDescriptor = 'stopped'
            }

            Write-HeuristicDebug -Source 'Events' -Message ('Evaluated service dependency {0}' -f $serviceInfo.Name) -Data ([ordered]@{
                Found            = [bool]$record
                StatusNormalized = $statusNormalized
                StartNormalized  = $startNormalized
                StateDescriptor  = $stateDescriptor
                ShouldFlag       = $shouldFlag
                ImpactArea       = $impactArea
                HasCorrelation   = $hasCorrelatedIssue
            })

            if (-not $shouldFlag) { continue }

            $severity = 'medium'
            if ($impactArea -eq 'vpn' -and $hasVpnSignals) { $severity = 'high' }
            elseif ($impactArea -eq 'wu' -and $hasWuFailures) { $severity = 'high' }

            $serviceNameForEvidence = if ($record -and $record.PSObject.Properties['DisplayName'] -and -not [string]::IsNullOrWhiteSpace([string]$record.DisplayName)) {
                [string]$record.DisplayName
            } else {
                [string]$serviceInfo.Display
            }

            $serviceEvidence = [ordered]@{
                name      = $serviceNameForEvidence
                startType = if ($record -and $record.PSObject.Properties['StartType']) { [string]$record.StartType } else { 'Unknown' }
                status    = if ($record -and $record.PSObject.Properties['Status']) { [string]$record.Status } else { if ($record) { 'Unknown' } else { 'Not Found' } }
            }

            if (-not $record) {
                $serviceEvidence.startType = 'Not Reported'
            }

            $evidence = [ordered]@{
                service     = $serviceEvidence
                remediation = "Set StartType to $($serviceInfo.RecommendedStart) and ensure the service is running."
            }

            $correlatedEvents = @()
            if ($impactArea -eq 'vpn') { $correlatedEvents = $vpnMatches }
            elseif ($impactArea -eq 'wu') { $correlatedEvents = $wuMatches }

            if ($correlatedEvents -and $correlatedEvents.Count -gt 0) {
                $evidence['correlatedIssue'] = [ordered]@{
                    type         = if ($impactArea -eq 'vpn') { 'vpn' } else { 'windows-update' }
                    sampleEvents = Get-EventsCategoryEventSummaries -Events $correlatedEvents -Max 3
                }
            }

            $stateText = switch ($stateDescriptor) {
                'disabled' { 'is disabled' }
                'stopped'  { 'is stopped' }
                'missing'  { 'is missing from inventory' }
                default    { 'is not healthy' }
            }

            $title = "Required service $serviceNameForEvidence $stateText — $($serviceInfo.Impact)"

            Add-CategoryIssue -CategoryResult $result -Severity $severity -Title $title -Evidence $evidence -Subcategory 'Service Dependencies'
        }
    }

    return $result
}
