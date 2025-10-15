<#!
.SYNOPSIS
    Service health heuristics reviewing stopped automatic services and query errors.
#>

. (Join-Path -Path (Split-Path $PSScriptRoot -Parent) -ChildPath 'AnalyzerCommon.ps1')

$servicesModuleRoot = Join-Path -Path $PSScriptRoot -ChildPath 'Services'
if (Test-Path -LiteralPath $servicesModuleRoot) {
    $serviceScripts = Get-ChildItem -Path $servicesModuleRoot -Filter '*.ps1' -File | Sort-Object Name
    foreach ($script in $serviceScripts) {
        . $script.FullName
    }
    Write-HeuristicDebug -Source 'Services' -Message "Loaded services module scripts" -Data ([ordered]@{
        Root  = $servicesModuleRoot
        Count = $serviceScripts.Count
    })
}

function Get-ServicesArtifactEntries {
    param($Artifact)

    if (-not $Artifact) { return @() }
    if ($Artifact -is [System.Collections.IEnumerable] -and -not ($Artifact -is [string])) {
        return @($Artifact)
    }

    return @($Artifact)
}

function Get-ServicesArtifactPaths {
    param($Artifact)

    $entries = Get-ServicesArtifactEntries -Artifact $Artifact
    $paths = New-Object System.Collections.Generic.List[string]
    foreach ($entry in $entries) {
        if ($entry -and $entry.PSObject.Properties['Path']) {
            $null = $paths.Add([string]$entry.Path)
        }
    }

    return $paths
}

function Invoke-ServicesCheckWithLog {
    param(
        [Parameter(Mandatory)]$Result,
        [Parameter(Mandatory)][hashtable]$Tracker,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][scriptblock]$Action,
        [object[]]$Arguments = @(),
        [string]$SkipReason
    )

    if (-not $Tracker.ContainsKey($Name)) { $Tracker[$Name] = 0 }

    if ($PSBoundParameters.ContainsKey('SkipReason') -and -not [string]::IsNullOrWhiteSpace($SkipReason)) {
        $Tracker[$Name] = "skip: $SkipReason"
        Write-HeuristicDebug -Source 'Services' -Message ("Skipped {0}; reason: {1}" -f $Name, $SkipReason)
        return
    }

    $issuesBefore = if ($Result -and $Result.Issues) { $Result.Issues.Count } else { 0 }
    $normalsBefore = if ($Result -and $Result.Normals) { $Result.Normals.Count } else { 0 }

    & $Action @Arguments

    $issuesAfter = if ($Result -and $Result.Issues) { $Result.Issues.Count } else { 0 }
    $normalsAfter = if ($Result -and $Result.Normals) { $Result.Normals.Count } else { 0 }

    $issueDelta = $issuesAfter - $issuesBefore
    $normalDelta = $normalsAfter - $normalsBefore
    $findings = $issueDelta + $normalDelta

    $Tracker[$Name] = $findings
    Write-HeuristicDebug -Source 'Services' -Message ("Ran {0}; finding(s): {1}" -f $Name, $findings) -Data ([ordered]@{
        Issues  = $issueDelta
        Normals = $normalDelta
    })
}

function Invoke-ServicesHeuristics {
    param(
        [Parameter(Mandatory)]
        $Context
    )

    Write-HeuristicDebug -Source 'Services' -Message 'Invoke-ServicesHeuristics: START' -Data ([ordered]@{
        ArtifactCount = if ($Context -and $Context.Artifacts) { $Context.Artifacts.Count } else { 0 }
    })

    $result = New-CategoryResult -Name 'Services'

    $platform = Get-DevicePlatformInfo -Context $Context
    $isServer = ($platform.IsWindowsServer -eq $true)
    $isWorkstation = ($platform.IsWorkstation -eq $true)
    $proxyInfo = Get-SystemProxyInfo -Context $Context
    Write-HeuristicDebug -Source 'Services' -Message 'Platform and proxy information resolved' -Data ([ordered]@{
        IsServer      = $isServer
        IsWorkstation = $isWorkstation
        HasProxyInfo  = [bool]$proxyInfo
    })

    $artifactCandidates = @(
        [pscustomobject]@{ Key = 'service-baseline'; Preferred = $true;  Reason = 'baseline preferred' },
        [pscustomobject]@{ Key = 'services';         Preferred = $false; Reason = 'fallback after baseline failure' }
    )
    $selectedArtifact = $null
    $selectedCandidate = $null
    $selectedPayload = $null
    $selectedServicesNode = $null
    $selectedMetrics = $null
    $selectionReason = $null
    $candidateDiagnostics = New-Object System.Collections.Generic.List[pscustomobject]

    $msinfoServices = Get-MsinfoServicesPayload -Context $Context
    if ($msinfoServices -and $msinfoServices.PSObject.Properties['Services'] -and $msinfoServices.Services) {
        $servicesArray = if ($msinfoServices.Services -is [System.Collections.IEnumerable] -and -not ($msinfoServices.Services -is [string])) {
            @($msinfoServices.Services | Where-Object { $_ })
        } else {
            @($msinfoServices.Services)
        }

        if ($servicesArray.Count -gt 0) {
            $selectedPayload = $msinfoServices
            $selectedServicesNode = $servicesArray
            $selectionReason = 'msinfo32 services snapshot'
            $selectedCandidate = [pscustomobject]@{ Key = 'msinfo32'; Preferred = $true; Reason = 'msinfo32 services snapshot' }
            $selectedArtifact = [pscustomobject]@{
                Path = 'msinfo32.json'
                Data = [pscustomobject]@{ Payload = $msinfoServices }
            }
            if ($msinfoServices.CollectionErrors -and $msinfoServices.CollectionErrors.Count -gt 0) {
                foreach ($err in $msinfoServices.CollectionErrors) {
                    if ($err) {
                        $candidateDiagnostics.Add([pscustomobject]@{
                            Candidate = 'msinfo32'
                            Path      = 'msinfo32.json'
                            Status    = 'warning'
                            Message   = [string]$err
                        }) | Out-Null
                    }
                }
            }
        }
    }

    if (-not $selectedArtifact) {
        if ($msinfoServices -and (-not $msinfoServices.Services -or $msinfoServices.Services.Count -eq 0)) {
            $candidateDiagnostics.Add([pscustomobject]@{
                Candidate = 'msinfo32'
                Path      = 'msinfo32.json'
                Status    = 'empty'
                Message   = 'Services section empty in msinfo32 payload'
            }) | Out-Null
        } elseif (-not $msinfoServices) {
            $candidateDiagnostics.Add([pscustomobject]@{
                Candidate = 'msinfo32'
                Path      = 'msinfo32.json'
                Status    = 'missing'
                Message   = 'msinfo32 artifact missing'
            }) | Out-Null
        }

        foreach ($candidateInfo in $artifactCandidates) {
            $artifact = Get-AnalyzerArtifact -Context $Context -Name $candidateInfo.Key
            $entries = Get-ServicesArtifactEntries -Artifact $artifact

            if ($entries.Count -eq 0) {
                Write-HeuristicDebug -Source 'Services' -Message 'Services artifact candidate not found' -Data ([ordered]@{
                Candidate = $candidateInfo.Key
            })
            $candidateDiagnostics.Add([pscustomobject]@{
                Candidate = $candidateInfo.Key
                Path      = '(missing)'
                Status    = 'missing'
                Message   = 'Artifact not found'
            }) | Out-Null
            continue
        }

        foreach ($entry in $entries) {
            $entryPath = if ($entry -and $entry.PSObject.Properties['Path']) { [string]$entry.Path } else { '(unknown)' }
            Write-HeuristicDebug -Source 'Services' -Message 'Inspecting services candidate' -Data ([ordered]@{
                Candidate = $candidateInfo.Key
                Path      = $entryPath
            })

            if (-not ($entry.Data -and $entry.Data.PSObject.Properties['Payload'])) {
                $message = 'baseline present but missing Payload → try next candidate / flag artifact-shape issue'
                Write-HeuristicDebug -Source 'Services' -Message $message -Data ([ordered]@{
                    Candidate = $candidateInfo.Key
                    Path      = $entryPath
                })
                $candidateDiagnostics.Add([pscustomobject]@{
                    Candidate = $candidateInfo.Key
                    Path      = $entryPath
                    Status    = 'missing-payload'
                    Message   = $message
                }) | Out-Null
                continue
            }

            $payload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $entry)
            if (-not $payload) {
                $message = 'Resolved payload was null; continuing to next candidate'
                Write-HeuristicDebug -Source 'Services' -Message $message -Data ([ordered]@{
                    Candidate = $candidateInfo.Key
                    Path      = $entryPath
                })
                $candidateDiagnostics.Add([pscustomobject]@{
                    Candidate = $candidateInfo.Key
                    Path      = $entryPath
                    Status    = 'null-payload'
                    Message   = $message
                }) | Out-Null
                continue
            }

            if ($payload.PSObject.Properties['Error']) {
                $payloadError = [string]$payload.Error
                if (-not [string]::IsNullOrWhiteSpace($payloadError)) {
                    Write-HeuristicDebug -Source 'Services' -Message 'Payload reported non-blocking error' -Data ([ordered]@{
                        Candidate = $candidateInfo.Key
                        Path      = $entryPath
                        Error     = $payloadError
                    })
                }
            }

            if (-not $payload.PSObject.Properties['Services']) {
                $message = 'Payload.Services missing; continuing to next candidate'
                Write-HeuristicDebug -Source 'Services' -Message $message -Data ([ordered]@{
                    Candidate = $candidateInfo.Key
                    Path      = $entryPath
                })
                $candidateDiagnostics.Add([pscustomobject]@{
                    Candidate = $candidateInfo.Key
                    Path      = $entryPath
                    Status    = 'missing-services'
                    Message   = $message
                }) | Out-Null
                continue
            }

            $servicesNode = $payload.Services
            if ($servicesNode -and $servicesNode.PSObject.Properties['Error']) {
                $nodeError = [string]$servicesNode.Error
                if (-not [string]::IsNullOrWhiteSpace($nodeError)) {
                    Write-HeuristicDebug -Source 'Services' -Message 'Services candidate reported error; evaluating next option' -Data ([ordered]@{
                        Candidate = $candidateInfo.Key
                        Path      = $entryPath
                        Error     = $nodeError
                    })
                    $candidateDiagnostics.Add([pscustomobject]@{
                        Candidate = $candidateInfo.Key
                        Path      = $entryPath
                        Status    = 'error'
                        Message   = $nodeError
                    }) | Out-Null
                    continue
                }
            }

            $rawCount = 0
            if ($servicesNode -is [System.Collections.IEnumerable] -and -not ($servicesNode -is [string])) {
                $rawCount = (@($servicesNode)).Count
            } elseif ($servicesNode) {
                $rawCount = 1
            }

            $collection = ConvertTo-ServiceCollection -Value $servicesNode
            $services = $collection.Services
            $metrics = $collection.Metrics

            $typeLabel = if ($servicesNode -is [System.Collections.IEnumerable] -and -not ($servicesNode -is [string])) { 'Array' } elseif ($servicesNode) { $servicesNode.GetType().Name } else { '(null)' }
            Write-HeuristicDebug -Source 'Services' -Message ("Payload.Services type = {0}; count = {1}" -f $typeLabel, $services.Count) -Data ([ordered]@{
                Candidate        = $candidateInfo.Key
                RawCount         = $rawCount
                MissingName      = $metrics.MissingName
                MissingStatus    = $metrics.MissingStatus
                MissingStartType = $metrics.MissingStartType
            })

            if ($services.Count -eq 0) {
                $candidateDiagnostics.Add([pscustomobject]@{
                    Candidate = $candidateInfo.Key
                    Path      = $entryPath
                    Status    = 'empty'
                    Message   = 'Services array empty or unusable'
                }) | Out-Null
                continue
            }

            $selectedArtifact = $entry
            $selectedCandidate = $candidateInfo
            $selectedPayload = $payload
            $selectedServicesNode = $servicesNode
            $selectedMetrics = $metrics
            $selectionReason = if ($candidateInfo.Preferred) { $candidateInfo.Reason } else { $candidateInfo.Reason }
            break
        }

        if ($selectedArtifact) { break }
    }
    }

    Write-HeuristicDebug -Source 'Services' -Message 'Resolved services artifact' -Data ([ordered]@{
        Found      = [bool]$selectedArtifact
        Candidates = (($artifactCandidates | ForEach-Object { $_.Key }) -join ', ')
        Selected   = if ($selectedCandidate) { $selectedCandidate.Key } else { '(none)' }
    })

    if (-not $selectedArtifact) {
        $evidenceLines = New-Object System.Collections.Generic.List[string]
        foreach ($entry in $candidateDiagnostics) {
            $parts = [System.Collections.Generic.List[string]]::new()
            if ($entry.Path -and $entry.Path -ne '(missing)') { $parts.Add($entry.Path) }
            if ($entry.Message) { $parts.Add($entry.Message) }
            $detail = if ($parts.Count -gt 0) { ($parts.ToArray() -join ' | ') } else { $entry.Status }
            $evidenceLines.Add(("{0}: {1}" -f $entry.Candidate, $detail)) | Out-Null
        }

        $issueTitle = if ($candidateDiagnostics | Where-Object { $_.Status -eq 'missing' }) {
            'Services artifact missing, so outages in critical services may go unnoticed.'
        } else {
            'Unable to query services, so outages in critical services may go unnoticed.'
        }

        $evidenceText = if ($evidenceLines.Count -gt 0) { $evidenceLines -join "`n" } else { $null }
        Add-CategoryIssue -CategoryResult $result -Severity 'high' -Title $issueTitle -Evidence $evidenceText -Subcategory 'Service Inventory'
        Write-HeuristicDebug -Source 'Services' -Message 'Invoke-ServicesHeuristics: END' -Data ([ordered]@{
            Issues  = $result.Issues.Count
            Normals = $result.Normals.Count
        })
        return $result
    }

    $selectedPaths = Get-ServicesArtifactPaths -Artifact $selectedArtifact
    $primaryPath = if ($selectedPaths.Count -gt 0) { $selectedPaths[0] } else { '(unknown)' }
    Write-HeuristicDebug -Source 'Services' -Message ("Selected Services artifact: {0} (reason: {1})" -f $primaryPath, $selectionReason)

    $payload = $selectedPayload
    Write-HeuristicDebug -Source 'Services' -Message 'Resolved services payload' -Data ([ordered]@{
        HasPayload = [bool]$payload
    })
    if (-not $payload) {
        Write-HeuristicDebug -Source 'Services' -Message 'Invoke-ServicesHeuristics: END' -Data ([ordered]@{
            Issues  = $result.Issues.Count
            Normals = $result.Normals.Count
        })
        return $result
    }

    $collectionResult = ConvertTo-ServiceCollection -Value $selectedServicesNode
    $services = $collectionResult.Services
    $metrics = $collectionResult.Metrics
    Write-HeuristicDebug -Source 'Services' -Message ('Normalized services loaded: {0}' -f $services.Count) -Data ([ordered]@{
        MissingName      = $metrics.MissingName
        MissingStatus    = $metrics.MissingStatus
        MissingStartType = $metrics.MissingStartType
    })

    $preview = New-Object System.Collections.Generic.List[string]
    foreach ($service in ($services | Select-Object -First 5)) {
        $statusText = if ($service.PSObject.Properties['Status']) { [string]$service.Status } else { 'Unknown' }
        $startText = if ($service.PSObject.Properties['StartType']) { [string]$service.StartType } elseif ($service.PSObject.Properties['StartMode']) { [string]$service.StartMode } else { 'Unknown' }
        $preview.Add(("{0}={1}/{2}" -f $service.Name, $statusText, $startText)) | Out-Null
    }
    if ($preview.Count -gt 0) {
        Write-HeuristicDebug -Source 'Services' -Message ('Service preview (first 5): {0}' -f ($preview -join ' | '))
    }

    $lookup = New-ServiceLookup -Services $services

    $probeServices = @('BITS','wuauserv','Dnscache','Spooler','WinHttpAutoProxySvc')
    $probeDetails = New-Object System.Collections.Generic.List[string]
    foreach ($probe in $probeServices) {
        $state = Get-ServiceStateInfo -Lookup $lookup -Name $probe
        $probeDetails.Add(("{0} → Status={1}, StartType={2}, Normalized={3}/{4}" -f $probe, $state.Status, $state.StartMode, $state.StatusNormalized, $state.StartModeNormalized)) | Out-Null
    }
    Write-HeuristicDebug -Source 'Services' -Message ('Probe results: {0}' -f ($probeDetails -join ' | '))

    $checkTracker = [ordered]@{}
    Invoke-ServicesCheckWithLog -Result $result -Tracker $checkTracker -Name 'Search' -Action {
        param($res,$lookupParam,$workstation,$server)
        Invoke-ServiceCheckWindowsSearch -Result $res -Lookup $lookupParam -IsWorkstation $workstation -IsServer $server
    } -Arguments @($result,$lookup,$isWorkstation,$isServer)

    Invoke-ServicesCheckWithLog -Result $result -Tracker $checkTracker -Name 'DNS' -Action {
        param($res,$lookupParam)
        Invoke-ServiceCheckDnsClient -Result $res -Lookup $lookupParam
    } -Arguments @($result,$lookup)

    Invoke-ServicesCheckWithLog -Result $result -Tracker $checkTracker -Name 'NLA' -Action {
        param($res,$lookupParam,$workstation)
        Invoke-ServiceCheckNetworkLocation -Result $res -Lookup $lookupParam -IsWorkstation $workstation
    } -Arguments @($result,$lookup,$isWorkstation)

    Invoke-ServicesCheckWithLog -Result $result -Tracker $checkTracker -Name 'Workstation/SMB' -Action {
        param($res,$lookupParam)
        Invoke-ServiceCheckWorkstation -Result $res -Lookup $lookupParam
    } -Arguments @($result,$lookup)

    Invoke-ServicesCheckWithLog -Result $result -Tracker $checkTracker -Name 'Spooler' -Action {
        param($res,$lookupParam,$workstation)
        Invoke-ServiceCheckPrintSpooler -Result $res -Lookup $lookupParam -IsWorkstation $workstation
    } -Arguments @($result,$lookup,$isWorkstation)

    Invoke-ServicesCheckWithLog -Result $result -Tracker $checkTracker -Name 'RPC' -Action {
        param($res,$lookupParam)
        Invoke-ServiceCheckRpc -Result $res -Lookup $lookupParam
    } -Arguments @($result,$lookup)

    Invoke-ServicesCheckWithLog -Result $result -Tracker $checkTracker -Name 'WinHTTP' -Action {
        param($res,$lookupParam,$proxy)
        Invoke-ServiceCheckWinHttpAutoProxy -Result $res -Lookup $lookupParam -ProxyInfo $proxy
    } -Arguments @($result,$lookup,$proxyInfo)

    Invoke-ServicesCheckWithLog -Result $result -Tracker $checkTracker -Name 'BITS' -Action {
        param($res,$lookupParam,$workstation)
        Invoke-ServiceCheckBits -Result $res -Lookup $lookupParam -IsWorkstation $workstation
    } -Arguments @($result,$lookup,$isWorkstation)

    Invoke-ServicesCheckWithLog -Result $result -Tracker $checkTracker -Name 'Office C2R' -Action {
        param($res,$lookupParam,$workstation)
        Invoke-ServiceCheckOfficeClickToRun -Result $res -Lookup $lookupParam -IsWorkstation $workstation
    } -Arguments @($result,$lookup,$isWorkstation)

    Invoke-ServicesCheckWithLog -Result $result -Tracker $checkTracker -Name 'Auto-Start Sanity' -Action {
        param($res,$servicesParam)
        Invoke-ServiceCheckAutomaticInventory -Result $res -Services $servicesParam
    } -Arguments @($result,$services)

    $checkOrder = @('Search','DNS','NLA','Workstation/SMB','Spooler','RPC','WinHTTP','BITS','Office C2R','Auto-Start Sanity')
    $checkSummary = New-Object System.Collections.Generic.List[string]
    foreach ($check in $checkOrder) {
        if ($checkTracker.ContainsKey($check)) {
            $checkSummary.Add(("{0}={1}" -f $check, $checkTracker[$check])) | Out-Null
        } else {
            $checkSummary.Add(("{0}=0" -f $check)) | Out-Null
        }
    }
    Write-HeuristicDebug -Source 'Services' -Message ('Checks executed: {0}' -f ($checkSummary -join ', '))

    if ($payload.PSObject.Properties['CollectionErrors']) {
        $collectionErrors = @($payload.CollectionErrors | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) })
        if ($collectionErrors.Count -gt 0) {
            Write-HeuristicDebug -Source 'Services' -Message ('CollectionErrors found (non-blocking). Messages: {0}' -f ($collectionErrors -join ' | '))
            Add-CategoryIssue -CategoryResult $result -Severity 'warning' -Title 'Service inventory reported collection errors, so outages in critical services may go unnoticed.' -Evidence ($collectionErrors -join "`n") -Subcategory 'Service Inventory'
        }
    }

    Write-HeuristicDebug -Source 'Services' -Message ("Services: Issues={0}, Normals={1}" -f $result.Issues.Count, $result.Normals.Count)
    Write-HeuristicDebug -Source 'Services' -Message 'Invoke-ServicesHeuristics: END'

    return $result
}
