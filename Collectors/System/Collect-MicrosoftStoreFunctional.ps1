<#!
.SYNOPSIS
    Collects Microsoft Store operational signals for analyzer heuristics.
#>
[CmdletBinding()]
param(
    [Parameter()]
    [string]$OutputDirectory
)

$ErrorActionPreference = 'Stop'

function Get-ScriptRoot {
    if ($script:PSScriptRoot -and -not [string]::IsNullOrWhiteSpace($script:PSScriptRoot)) { return $script:PSScriptRoot }
    if ($MyInvocation.MyCommand.Path) { return (Split-Path -Parent $MyInvocation.MyCommand.Path) }
    return (Get-Location).Path
}

$__ScriptRoot = Get-ScriptRoot

if ([string]::IsNullOrWhiteSpace($__ScriptRoot)) { throw 'Script root unavailable.' }

$collectorCommonPath = Join-Path -Path $__ScriptRoot -ChildPath '..\CollectorCommon.ps1'
if (-not (Test-Path -LiteralPath $collectorCommonPath)) { throw 'Unable to resolve CollectorCommon.ps1 path.' }
. $collectorCommonPath

if (-not (Get-Command -Name Join-PathSafe -ErrorAction SilentlyContinue)) { throw 'Join-PathSafe helper is unavailable.' }

if (-not $PSBoundParameters.ContainsKey('OutputDirectory') -or [string]::IsNullOrWhiteSpace($OutputDirectory)) {
    $defaultOutput = Join-PathSafe $__ScriptRoot '..\output'
    if (-not $defaultOutput) {
        Write-Verbose 'Script root unavailable; defaulting output to current directory.'
        $locationPath = (Get-Location).Path
        $defaultOutput = Join-PathSafe $locationPath '..\output'
        if (-not $defaultOutput) { $defaultOutput = $locationPath }
    }
    $OutputDirectory = $defaultOutput
}

function Test-StoreInstallLocation {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$PackageFamilyName = 'Microsoft.WindowsStore'
    )

    $result = [ordered]@{
        storePackagePresent = $false
        installedLocationOk = $false
        appxManifestFound   = $false
        installLocation     = $null
        notes               = @()
    }

    $pkg = $null
    try {
        $pkg = Get-AppxPackage -AllUsers $PackageFamilyName -ErrorAction SilentlyContinue
    } catch {
        $result.notes += "Get-AppxPackage failed: $($_.Exception.Message)"
    }

    if (-not $pkg) {
        $result.notes += 'Store package missing or inaccessible.'
        return [pscustomobject]$result
    }

    $result.storePackagePresent = $true
    $installLocation = $pkg.InstallLocation
    $result.installLocation = $installLocation

    if ([string]::IsNullOrWhiteSpace($installLocation)) {
        $result.notes += 'InstallLocation string was empty.'
        return [pscustomobject]$result
    }

    if (-not (Test-Path -LiteralPath $installLocation)) {
        $result.notes += 'InstallLocation path did not exist.'
        return [pscustomobject]$result
    }

    $result.installedLocationOk = $true

    $manifestPath = Join-PathSafe $installLocation 'AppxManifest.xml'
    if (-not $manifestPath) {
        $result.notes += 'Unable to resolve AppxManifest.xml location.'
        return [pscustomobject]$result
    }

    if (Test-Path -LiteralPath $manifestPath) {
        try {
            $null = Get-Content -LiteralPath $manifestPath -TotalCount 1 -ErrorAction Stop
            $result.appxManifestFound = $true
        } catch {
            $result.notes += "Manifest unreadable: $($_.Exception.Message)"
        }
    } else {
        $result.notes += 'AppxManifest.xml missing at expected path.'
    }

    return [pscustomobject]$result
}

function Get-StorePackageState {
    $state = Test-StoreInstallLocation -PackageFamilyName 'Microsoft.WindowsStore'

    return [ordered]@{
        storePackagePresent = $state.storePackagePresent
        installedLocationOk = $state.installedLocationOk
        appxManifestFound   = $state.appxManifestFound
        installLocation     = $state.installLocation
        notes               = $state.notes
    }
}

function Get-ServiceSnapshot {
    param(
        [Parameter(Mandatory)]
        [string[]]$Names
    )

    $snapshot = New-Object System.Collections.Generic.List[object]
    foreach ($name in $Names) {
        $status = $null
        $startType = $null

        $serviceResult = Get-CollectorServiceByName -Name $name
        $service = $serviceResult.Service

        if ($service) {
            if ($service.PSObject.Properties['Status']) { $status = [string]$service.Status }
            elseif ($service.PSObject.Properties['State']) { $status = [string]$service.State }

            if ($service.PSObject.Properties['StartMode']) { $startType = [string]$service.StartMode }
            elseif ($service.PSObject.Properties['StartType']) { $startType = [string]$service.StartType }
        }

        if (-not $status) {
            try {
                $fallback = Get-Service -Name $name -ErrorAction Stop
                $status = [string]$fallback.Status
                if (-not $startType -and $fallback.PSObject.Properties['StartType']) {
                    $startType = [string]$fallback.StartType
                }
            } catch {
            }
        }

        $snapshot.Add([pscustomobject]@{
            name      = $name
            startType = $startType
            status    = $status
        }) | Out-Null
    }

    return $snapshot
}

function Get-WinHttpProxySummary {
    $summary = 'Unknown'
    $isDirect = $null

    try {
        $output = & netsh winhttp show proxy 2>$null
        if ($output) {
            $directMatch = $output -match 'Direct access \(no proxy server\)' -or $output -match 'Direct access'
            if ($directMatch) {
                $summary = 'Direct'
                $isDirect = $true
            } else {
                $summary = 'Non-Direct'
                $isDirect = $false
            }
        }
    } catch {
        $summary = 'Unknown'
        $isDirect = $null
    }

    return [pscustomobject]@{
        winhttp  = $summary
        isDirect = $isDirect
    }
}

function Test-StoreEndpointReachability {
    $hosts = 'storeedgefd.dsx.mp.microsoft.com','login.live.com','dl.delivery.mp.microsoft.com'
    $results = New-Object System.Collections.Generic.List[object]

    foreach ($endpoint in $hosts) {
        $dnsOk = $false
        $tcpOk = $false
        $rttMs = $null

        try {
            $null = Resolve-DnsName -Name $endpoint -ErrorAction Stop
            $dnsOk = $true
        } catch [System.Management.Automation.CommandNotFoundException] {
            $dnsOk = $null
        } catch {
            $dnsOk = $false
        }

        try {
            $test = Test-NetConnection -ComputerName $endpoint -Port 443 -InformationLevel Detailed -WarningAction SilentlyContinue -ErrorAction Stop
            if ($test) {
                if ($test.PSObject.Properties['TcpTestSucceeded']) {
                    $tcpOk = [bool]$test.TcpTestSucceeded
                }
                if ($test.PSObject.Properties['PingSucceeded'] -and $test.PingSucceeded -and $test.PSObject.Properties['PingReplyDetails']) {
                    $rttMs = [int]$test.PingReplyDetails.RoundtripTime
                } elseif ($test.PSObject.Properties['Latency']) {
                    $rttMs = [int]$test.Latency
                }
            }
        } catch [System.Management.Automation.CommandNotFoundException] {
            $tcpOk = $null
        } catch {
            $tcpOk = $false
        }

        $results.Add([pscustomobject]@{
            host     = $endpoint
            dnsOk    = $dnsOk
            tcp443Ok = $tcpOk
            rttMs    = $rttMs
        }) | Out-Null
    }

    return $results
}

function Invoke-Main {
    $packageState = Get-StorePackageState
    $services = Get-ServiceSnapshot -Names @('AppXSVC','ClipSVC','InstallService','DoSvc','wuauserv')
    $proxy = Get-WinHttpProxySummary
    $reachability = Test-StoreEndpointReachability

    $payload = [ordered]@{
        storePackagePresent = $packageState.storePackagePresent
        installedLocationOk = $packageState.installedLocationOk
        appxManifestFound   = $packageState.appxManifestFound
        installLocation     = $packageState.installLocation
        notes               = $packageState.notes
        services            = $services
        proxy               = $proxy
        reachability        = $reachability
    }

    $result = New-CollectorMetadata -Payload $payload
    $outputPath = Export-CollectorResult -OutputDirectory $OutputDirectory -FileName 'store-functional.json' -Data $result -Depth 6
    Write-Output $outputPath
}

Invoke-Main
