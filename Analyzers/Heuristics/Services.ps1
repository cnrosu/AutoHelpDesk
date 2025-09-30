<#!
.SYNOPSIS
    Service health heuristics reviewing stopped automatic services and query errors.
#>

. (Join-Path -Path (Split-Path $PSScriptRoot -Parent) -ChildPath 'AnalyzerCommon.ps1')

$servicesModuleRoot = Join-Path -Path $PSScriptRoot -ChildPath 'Services'
if (Test-Path -LiteralPath $servicesModuleRoot) {
    Get-ChildItem -Path $servicesModuleRoot -Filter '*.ps1' -File | Sort-Object Name | ForEach-Object {
        . $_.FullName
    }
}

function Invoke-ServicesHeuristics {
    param(
        [Parameter(Mandatory)]
        $Context
    )

    Write-HeuristicDebug -Source 'Services' -Message 'Starting services heuristics' -Data ([ordered]@{
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

    $artifactCandidates = @('service-baseline', 'services')
    $servicesArtifact = $null
    $servicesPayload = $null
    $servicesNode = $null
    $artifactSource = $null
    $artifactError = $null

    foreach ($candidate in $artifactCandidates) {
        $artifact = Get-AnalyzerArtifact -Context $Context -Name $candidate
        if (-not $artifact) { continue }

        $payload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $artifact)
        if (-not $payload) { continue }

        $candidateNode = $null
        if ($payload.PSObject.Properties['Services']) {
            $candidateNode = $payload.Services
        }

        if (-not $candidateNode) { continue }

        $candidateError = $null
        if ($candidateNode.PSObject.Properties['Error']) {
            $candidateError = [string]$candidateNode.Error
        }

        if (-not [string]::IsNullOrWhiteSpace($candidateError)) {
            if (-not $artifactError) {
                $artifactError = [pscustomobject]@{
                    Source  = $candidate
                    Message = $candidateError
                }
            }
            continue
        }

        $servicesArtifact = $artifact
        $servicesPayload = $payload
        $servicesNode = $candidateNode
        $artifactSource = $candidate
        break
    }

    Write-HeuristicDebug -Source 'Services' -Message 'Resolved services artifact' -Data ([ordered]@{
        Found     = [bool]$servicesArtifact
        Candidates = ($artifactCandidates -join ', ')
        Selected  = if ($artifactSource) { $artifactSource } else { '(none)' }
    })

    if (-not $servicesArtifact) {
        if ($artifactError -and $artifactError.Message) {
            $evidence = if ($artifactError.Source) {
                "{0}: {1}" -f $artifactError.Source, $artifactError.Message
            } else {
                $artifactError.Message
            }
            Add-CategoryIssue -CategoryResult $result -Severity 'high' -Title 'Unable to query services' -Evidence $evidence -Subcategory 'Service Inventory'
        } else {
            Add-CategoryIssue -CategoryResult $result -Severity 'high' -Title 'Services artifact missing' -Subcategory 'Collection'
        }
        return $result
    }

    $payload = $servicesPayload
    Write-HeuristicDebug -Source 'Services' -Message 'Resolved services payload' -Data ([ordered]@{
        HasPayload = [bool]$payload
    })
    if (-not $payload) {
        return $result
    }

    if ($servicesNode -and -not $servicesNode.Error) {
        $services = ConvertTo-ServiceCollection -Value $servicesNode
        Write-HeuristicDebug -Source 'Services' -Message 'Evaluating service inventory' -Data ([ordered]@{
            ServiceCount = $services.Count
        })
        $lookup = New-ServiceLookup -Services $services

        Invoke-ServiceCheckWindowsSearch      -Result $result -Lookup $lookup -IsWorkstation $isWorkstation -IsServer $isServer
        Invoke-ServiceCheckDnsClient          -Result $result -Lookup $lookup
        Invoke-ServiceCheckNetworkLocation    -Result $result -Lookup $lookup -IsWorkstation $isWorkstation
        Invoke-ServiceCheckWorkstation        -Result $result -Lookup $lookup
        Invoke-ServiceCheckPrintSpooler       -Result $result -Lookup $lookup -IsWorkstation $isWorkstation
        Invoke-ServiceCheckRpc                -Result $result -Lookup $lookup
        Invoke-ServiceCheckWinHttpAutoProxy   -Result $result -Lookup $lookup -ProxyInfo $proxyInfo
        Invoke-ServiceCheckBits               -Result $result -Lookup $lookup -IsWorkstation $isWorkstation
        Invoke-ServiceCheckOfficeClickToRun   -Result $result -Lookup $lookup -IsWorkstation $isWorkstation
        Invoke-ServiceCheckAutomaticInventory -Result $result -Services $services
        if ($payload.PSObject.Properties['CollectionErrors']) {
            $collectionErrors = @($payload.CollectionErrors | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) })
            if ($collectionErrors.Count -gt 0) {
                Add-CategoryIssue -CategoryResult $result -Severity 'info' -Title 'Service inventory reported collection errors' -Evidence ($collectionErrors -join "`n") -Subcategory 'Service Inventory'
            }
        }
    } elseif ($servicesNode -and $servicesNode.Error) {
        Add-CategoryIssue -CategoryResult $result -Severity 'high' -Title 'Unable to query services' -Evidence $servicesNode.Error -Subcategory 'Service Inventory'
    }

    return $result
}
