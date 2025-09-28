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

    $result = New-CategoryResult -Name 'Services'

    $platform = Get-DevicePlatformInfo -Context $Context
    $isServer = ($platform.IsWindowsServer -eq $true)
    $isWorkstation = ($platform.IsWorkstation -eq $true)
    $proxyInfo = Get-SystemProxyInfo -Context $Context

    $servicesArtifact = Get-AnalyzerArtifact -Context $Context -Name 'services'
    if (-not $servicesArtifact) {
        Add-CategoryIssue -CategoryResult $result -Severity 'high' -Title 'Services artifact missing' -Subcategory 'Collection'
        return $result
    }

    $payload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $servicesArtifact)
    if (-not $payload) {
        return $result
    }

    $servicesNode = $null
    if ($payload.PSObject.Properties['Services']) {
        $servicesNode = $payload.Services
    }

    if ($servicesNode -and -not $servicesNode.Error) {
        $services = ConvertTo-ServiceCollection -Value $servicesNode
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
    } elseif ($servicesNode -and $servicesNode.Error) {
        Add-CategoryIssue -CategoryResult $result -Severity 'high' -Title 'Unable to query services' -Evidence $servicesNode.Error -Subcategory 'Service Inventory'
    }

    return $result
}
