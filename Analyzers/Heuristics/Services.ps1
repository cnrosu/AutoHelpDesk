<#!
.SYNOPSIS
    Service health heuristics reviewing stopped automatic services and query errors.
#>

. (Join-Path -Path (Split-Path $PSScriptRoot -Parent) -ChildPath 'AnalyzerCommon.ps1')

$CoreAutostartServices = @('Dnscache','Netlogon','LanmanWorkstation','BITS','WSearch')

function Invoke-ServicesHeuristics {
    param(
        [Parameter(Mandatory)]
        $Context
    )

    $result = New-CategoryResult -Name 'Services'

    $servicesArtifact = Get-AnalyzerArtifact -Context $Context -Name 'services'
    $startPendingCheckAdded = $false
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

            $autostartSamples = @()
            if ($payload.PSObject.Properties['AutostartServiceSamples']) {
                $sampleValue = $payload.AutostartServiceSamples
                if ($sampleValue -is [System.Collections.IEnumerable] -and -not ($sampleValue -is [string])) {
                    $autostartSamples = @($sampleValue)
                } elseif ($sampleValue) {
                    $autostartSamples = @($sampleValue)
                }
            }

            $validSamples = $autostartSamples | Where-Object { $_ -and -not $_.Error }
            if ($validSamples.Count -ge 2) {
                $sortedSamples = $validSamples | Sort-Object -Property {
                    if ($_.PSObject.Properties['ElapsedSeconds']) {
                        try { [double]$_.ElapsedSeconds } catch { 0 }
                    } else { 0 }
                }

                $firstSample = $sortedSamples[0]
                $secondSample = $sortedSamples[1]

                $firstLookup = @{}
                if ($firstSample.Services -and ($firstSample.Services -is [System.Collections.IEnumerable]) -and -not ($firstSample.Services -is [string])) {
                    foreach ($svc in $firstSample.Services) {
                        if ($svc -and $svc.PSObject.Properties['Name']) {
                            $firstLookup[[string]$svc.Name] = $svc
                        }
                    }
                }

                $stuckServices = @()
                if ($secondSample.Services -and ($secondSample.Services -is [System.Collections.IEnumerable]) -and -not ($secondSample.Services -is [string])) {
                    foreach ($svc in $secondSample.Services) {
                        if (-not $svc -or -not $svc.PSObject.Properties['Name']) { continue }
                        $name = [string]$svc.Name
                        if (-not $firstLookup.ContainsKey($name)) { continue }
                        $initialStatus = ''
                        if ($firstLookup[$name].PSObject.Properties['Status']) { $initialStatus = [string]$firstLookup[$name].Status }
                        $initialStatusLower = if ($initialStatus) { $initialStatus.ToLowerInvariant() } else { '' }
                        if ($initialStatusLower -notin @('startpending','stoppending')) { continue }

                        $currentStatus = ''
                        if ($svc.PSObject.Properties['Status']) { $currentStatus = [string]$svc.Status }
                        $currentStatusLower = if ($currentStatus) { $currentStatus.ToLowerInvariant() } else { '' }
                        if ($currentStatusLower -notin @('startpending','stoppending')) { continue }

                        $startType = ''
                        if ($svc.PSObject.Properties['StartType']) { $startType = [string]$svc.StartType }

                        $elapsed = 0
                        if ($secondSample.PSObject.Properties['ElapsedSeconds']) {
                            try { $elapsed = [math]::Round([double]$secondSample.ElapsedSeconds, 2) } catch { $elapsed = 0 }
                        }

                        $stuckServices += [pscustomobject]@{
                            Name       = $name
                            Status     = $currentStatus
                            StartType  = $startType
                            ElapsedSec = $elapsed
                        }
                    }
                }

                if ($stuckServices.Count -gt 0) {
                    $coreLookup = @{}
                    foreach ($svcName in $CoreAutostartServices) {
                        if ($svcName) { $coreLookup[$svcName.ToLowerInvariant()] = $true }
                    }

                    $coreStuck = $stuckServices | Where-Object { $coreLookup.ContainsKey($_.Name.ToLowerInvariant()) }
                    $nonCoreStuck = $stuckServices | Where-Object { -not $coreLookup.ContainsKey($_.Name.ToLowerInvariant()) }

                    if ($coreStuck.Count -gt 0) {
                        $coreEvidence = $coreStuck | ForEach-Object { "{0} — {1}s — {2}" -f $_.Name, $_.ElapsedSec, $_.StartType }
                        Add-CategoryIssue -CategoryResult $result -Severity 'high' -Title 'Core autostart service(s) stuck pending start/stop' -Evidence ($coreEvidence -join "`n") -Subcategory 'Service Inventory'
                    }

                    if ($nonCoreStuck.Count -gt 0) {
                        $nonCoreEvidence = $nonCoreStuck | ForEach-Object { "{0} — {1}s — {2}" -f $_.Name, $_.ElapsedSec, $_.StartType }
                        Add-CategoryIssue -CategoryResult $result -Severity 'medium' -Title 'Autostart service(s) stuck pending start/stop' -Evidence ($nonCoreEvidence -join "`n") -Subcategory 'Service Inventory'
                    }

                    $checkDetails = $stuckServices | ForEach-Object { "{0} — {1}s — {2}" -f $_.Name, $_.ElapsedSec, $_.StartType }
                    Add-CategoryCheck -CategoryResult $result -Name 'Services/StartPending' -Status 'WARN' -Details ($checkDetails -join '; ')
                    $startPendingCheckAdded = $true
                }
            }

            if (-not $startPendingCheckAdded) {
                Add-CategoryCheck -CategoryResult $result -Name 'Services/StartPending' -Status 'GOOD' -Details 'No autostart service stuck.'
                $startPendingCheckAdded = $true
            }
        } elseif ($payload.Services.Error) {
            Add-CategoryIssue -CategoryResult $result -Severity 'high' -Title 'Unable to query services' -Evidence $payload.Services.Error -Subcategory 'Service Inventory'
        }
    } else {
        Add-CategoryIssue -CategoryResult $result -Severity 'high' -Title 'Services artifact missing' -Subcategory 'Collection'
    }

    if (-not $startPendingCheckAdded) {
        Add-CategoryCheck -CategoryResult $result -Name 'Services/StartPending' -Status 'UNKNOWN' -Details 'Autostart service sampling unavailable.'
    }

    return $result
}
