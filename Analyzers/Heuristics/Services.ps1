<#!
.SYNOPSIS
    Service health heuristics reviewing stopped automatic services and query errors.
#>

. (Join-Path -Path (Split-Path $PSScriptRoot -Parent) -ChildPath 'AnalyzerCommon.ps1')

function Resolve-ServiceCrashServiceName {
    param(
        [string]$Message
    )

    if (-not $Message) { return $null }

    $match = [System.Text.RegularExpressions.Regex]::Match(
        $Message,
        'The (?<Service>.+?) service',
        [System.Text.RegularExpressions.RegexOptions]::IgnoreCase
    )

    if ($match.Success) {
        return $match.Groups['Service'].Value.Trim()
    }

    return $null
}

function Resolve-FaultingModuleFromMessage {
    param(
        [string]$Message
    )

    if (-not $Message) { return $null }

    $match = [System.Text.RegularExpressions.Regex]::Match(
        $Message,
        'Faulting module (?:name|path):\s*(?<Module>[^,\r\n]+)',
        [System.Text.RegularExpressions.RegexOptions]::IgnoreCase
    )

    if ($match.Success) {
        $module = $match.Groups['Module'].Value.Trim()
        if ($module -match '[\\/]') {
            try {
                return [System.IO.Path]::GetFileName($module)
            } catch {
                return $module
            }
        }

        return $module
    }

    $fallback = [System.Text.RegularExpressions.Regex]::Match(
        $Message,
        'Faulting application name:\s*(?<Module>[^,\r\n]+)',
        [System.Text.RegularExpressions.RegexOptions]::IgnoreCase
    )

    if ($fallback.Success) {
        return $fallback.Groups['Module'].Value.Trim()
    }

    return $null
}

function Resolve-DateTimeValue {
    param(
        $Value
    )

    if ($null -eq $Value) { return $null }
    if ($Value -is [datetime]) { return $Value }

    try {
        return [datetime]::Parse($Value.ToString())
    } catch {
        return $null
    }
}

function Invoke-ServicesHeuristics {
    param(
        [Parameter(Mandatory)]
        $Context
    )

    $result = New-CategoryResult -Name 'Services'

    $servicesArtifact = Get-AnalyzerArtifact -Context $Context -Name 'services'
    if ($servicesArtifact) {
        $payload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $servicesArtifact)
        if ($payload -and $payload.Services -and -not $payload.Services.Error) {
            $services = $payload.Services
            if ($services -is [System.Collections.IEnumerable] -and -not ($services -is [string])) {
                $services = @($services)
            } else {
                $services = @($services)
            }

            $lookup = @{}
            foreach ($service in $services) {
                if (-not $service) { continue }
                if ($service.PSObject.Properties['Name']) {
                    $lookup[[string]$service.Name] = $service
                }
            }

            if ($lookup.ContainsKey('BITS')) {
                $bits = $lookup['BITS']
                $status = if ($bits.PSObject.Properties['State']) { [string]$bits.State } elseif ($bits.PSObject.Properties['Status']) { [string]$bits.Status } else { 'Unknown' }
                $startMode = if ($bits.PSObject.Properties['StartMode']) { [string]$bits.StartMode } elseif ($bits.PSObject.Properties['StartType']) { [string]$bits.StartType } else { 'Unknown' }
                $statusNorm = if ($status) { $status.ToLowerInvariant() } else { '' }
                $startNorm = if ($startMode) { $startMode.ToLowerInvariant() } else { '' }

                if ($startNorm -like 'auto*' -and $statusNorm -notlike 'running') {
                    Add-CategoryIssue -CategoryResult $result -Severity 'high' -Title 'BITS stopped — background transfers for updates/AV/Office.' -Evidence ("Status: {0}; StartType: {1}" -f $status, $startMode) -Subcategory 'BITS Service'
                } elseif ($startNorm -eq 'manual' -and $statusNorm -notlike 'running') {
                    Add-CategoryIssue -CategoryResult $result -Severity 'medium' -Title 'BITS stopped (Manual start) — background transfers for updates/AV/Office.' -Evidence ("Status: {0}; StartType: {1}" -f $status, $startMode) -Subcategory 'BITS Service'
                } elseif ($startNorm -like 'disabled*') {
                    Add-CategoryIssue -CategoryResult $result -Severity 'high' -Title 'BITS disabled — background transfers for updates/AV/Office.' -Evidence ("Status: {0}; StartType: {1}" -f $status, $startMode) -Subcategory 'BITS Service'
                }
            }

            if ($lookup.ContainsKey('Spooler')) {
                $spooler = $lookup['Spooler']
                $status = if ($spooler.PSObject.Properties['State']) { [string]$spooler.State } elseif ($spooler.PSObject.Properties['Status']) { [string]$spooler.Status } else { 'Unknown' }
                $startMode = if ($spooler.PSObject.Properties['StartMode']) { [string]$spooler.StartMode } elseif ($spooler.PSObject.Properties['StartType']) { [string]$spooler.StartType } else { 'Unknown' }
                if ($status -notmatch '(?i)running') {
                    Add-CategoryIssue -CategoryResult $result -Severity 'high' -Title ("Print Spooler service not running (Status: {0}, StartType: {1})." -f $status, $startMode) -Evidence ("Status: {0}; StartType: {1}" -f $status, $startMode) -Subcategory 'Print Spooler Service'
                }
            }

            $stoppedAuto = $services | Where-Object {
                ($_.StartMode -eq 'Auto' -or $_.StartType -eq 'Automatic') -and ($_.State -ne 'Running' -and $_.Status -ne 'Running')
            }
            if ($stoppedAuto.Count -gt 0) {
                $summary = $stoppedAuto | Select-Object -First 5 | ForEach-Object { "{0} ({1})" -f $_.DisplayName, ($_.State ? $_.State : $_.Status) }
                Add-CategoryIssue -CategoryResult $result -Severity 'medium' -Title 'Automatic services not running' -Evidence ($summary -join "`n") -Subcategory 'Service Inventory'
            } else {
                Add-CategoryNormal -CategoryResult $result -Title 'Automatic services running'
            }

            $eventsArtifact = Get-AnalyzerArtifact -Context $Context -Name 'events'
            if ($eventsArtifact) {
                $eventsPayload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $eventsArtifact)
                if ($eventsPayload) {
                    $cutoff = (Get-Date).AddHours(-24)

                    $systemEvents = @()
                    if ($eventsPayload.PSObject.Properties['System']) {
                        $system = $eventsPayload.System
                        if ($system -and -not $system.Error) {
                            if ($system -is [System.Collections.IEnumerable] -and -not ($system -is [string])) {
                                $systemEvents = @($system)
                            } elseif ($system) {
                                $systemEvents = @($system)
                            }
                        }
                    }

                    $appCrashEvents = @()
                    if ($eventsPayload.PSObject.Properties['Application']) {
                        $application = $eventsPayload.Application
                        if ($application -and -not $application.Error) {
                            $applicationEntries = @()
                            if ($application -is [System.Collections.IEnumerable] -and -not ($application -is [string])) {
                                $applicationEntries = @($application)
                            } elseif ($application) {
                                $applicationEntries = @($application)
                            } else {
                                $applicationEntries = @()
                            }

                            foreach ($entry in $applicationEntries) {
                                if (-not $entry) { continue }
                                if ($entry.Id -ne 1000) { continue }
                                if ($entry.ProviderName -and $entry.ProviderName -notmatch '^(?i)Application Error$') { continue }

                                $time = Resolve-DateTimeValue $entry.TimeCreated
                                if ($time -and $time -lt $cutoff) { continue }

                                $message = if ($entry.PSObject.Properties['Message']) { [string]$entry.Message } else { $null }
                                $module = Resolve-FaultingModuleFromMessage -Message $message

                                $appCrashEvents += [pscustomobject]@{
                                    Time    = $time
                                    Message = $message
                                    Module  = if ($module) { $module } else { $null }
                                }
                            }
                        }
                    }

                    $serviceCrashMap = @{}
                    foreach ($entry in $systemEvents) {
                        if (-not $entry) { continue }
                        if ($entry.Id -ne 7031 -and $entry.Id -ne 7034) { continue }
                        if ($entry.ProviderName -and $entry.ProviderName -notmatch '^(?i)Service Control Manager$') { continue }

                        $time = Resolve-DateTimeValue $entry.TimeCreated
                        if ($time -and $time -lt $cutoff) { continue }

                        $message = if ($entry.PSObject.Properties['Message']) { [string]$entry.Message } else { $null }
                        $serviceName = Resolve-ServiceCrashServiceName -Message $message
                        if (-not $serviceName) { continue }

                        if (-not $serviceCrashMap.ContainsKey($serviceName)) {
                            $serviceCrashMap[$serviceName] = New-Object System.Collections.Generic.List[pscustomobject]
                        }

                        $serviceCrashMap[$serviceName].Add([pscustomobject]@{
                                Time    = $time
                                Message = $message
                            }) | Out-Null
                    }

                    if ($serviceCrashMap.Count -gt 0) {
                        foreach ($key in $serviceCrashMap.Keys) {
                            $eventsForService = $serviceCrashMap[$key]
                            if (-not $eventsForService -or $eventsForService.Count -le 0) { continue }

                            $recentEvents = $eventsForService | Where-Object { $_.Time } | Sort-Object -Property Time -Descending
                            if (-not $recentEvents) { continue }

                            $count = $eventsForService.Count
                            $latest = $recentEvents | Select-Object -First 1

                            $module = $null
                            if ($appCrashEvents.Count -gt 0 -and $latest.Time) {
                                $nearest = $appCrashEvents |
                                    Sort-Object -Property @{ Expression = { if ($_.Time -and $latest.Time) { [math]::Abs(($_.Time - $latest.Time).TotalMinutes) } else { [double]::PositiveInfinity } } } |
                                    Select-Object -First 1

                                if ($nearest -and $nearest.Module -and $nearest.Time -and $latest.Time) {
                                    $difference = [math]::Abs(($nearest.Time - $latest.Time).TotalMinutes)
                                    if ($difference -le 60) {
                                        $module = $nearest.Module
                                    }
                                }
                            }

                            if (-not $module) { $module = 'Unknown' }

                            $severity = if ($count -ge 2) { 'high' } else { 'medium' }
                            $title = if ($count -ge 2) {
                                "Service {0} crashed {1} times in last 24h" -f $key, $count
                            } else {
                                "Service {0} crashed in last 24h" -f $key
                            }

                            $evidence = "Service: {0}`nCrashes (24h): {1}`nLatest faulting module: {2}" -f $key, $count, $module

                            Add-CategoryIssue -CategoryResult $result -Severity $severity -Title $title -Evidence $evidence -Subcategory 'Service Crash Loops' -CheckId 'Services/CrashLoop'
                        }
                    } else {
                        Add-CategoryNormal -CategoryResult $result -Title 'No repeated service crashes.' -Subcategory 'Service Crash Loops'
                    }
                }
            }
        } elseif ($payload.Services.Error) {
            Add-CategoryIssue -CategoryResult $result -Severity 'high' -Title 'Unable to query services' -Evidence $payload.Services.Error -Subcategory 'Service Inventory'
        }
    } else {
        Add-CategoryIssue -CategoryResult $result -Severity 'high' -Title 'Services artifact missing' -Subcategory 'Collection'
    }

    return $result
}
