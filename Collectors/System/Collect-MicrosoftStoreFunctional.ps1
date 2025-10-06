<#!
.SYNOPSIS
    Collects Microsoft Store operational signals for analyzer heuristics.
#>
[CmdletBinding()]
param(
    [Parameter()]
    [string]$OutputDirectory = (Join-Path -Path (Split-Path -Parent $PSCommandPath) -ChildPath '..\\output')
)

. (Join-Path -Path $PSScriptRoot -ChildPath '..\\CollectorCommon.ps1')

function Get-StorePackageState {
    $package = $null
    try {
        $package = Get-AppxPackage -Name 'Microsoft.WindowsStore' -ErrorAction SilentlyContinue
    } catch {
        $package = $null
    }

    $present = [bool]$package
    $locationOk = $false
    if ($present -and $package.PSObject.Properties['InstalledLocation']) {
        $installedLocation = $package.InstalledLocation
        if ($installedLocation) {
            try {
                $locationOk = Test-Path -LiteralPath $installedLocation -ErrorAction Stop
            } catch {
                $locationOk = $false
            }
        }
    }

    $manifestFound = $false
    if ($present) {
        try {
            $storeRoot = 'C:\\Program Files\\WindowsApps'
            $storeFolders = Get-ChildItem -LiteralPath $storeRoot -ErrorAction Stop |
                Where-Object { $_.Name -like 'Microsoft.WindowsStore_*' }

            foreach ($folder in $storeFolders) {
                try {
                    $manifest = Get-ChildItem -LiteralPath $folder.FullName -Filter 'AppxManifest.xml' -ErrorAction Stop |
                        Select-Object -First 1
                    if ($manifest) {
                        $manifestFound = $true
                        break
                    }
                } catch [System.UnauthorizedAccessException] {
                    throw
                } catch {
                    # Ignore other per-folder errors and continue scanning.
                }
            }
        } catch [System.UnauthorizedAccessException] {
            $manifestFound = $null
        } catch {
            $manifestFound = $false
        }
    }

    return [ordered]@{
        storePackagePresent = $present
        installedLocationOk = $( if ($present) { [bool]$locationOk } else { $false } )
        appxManifestFound   = $( if ($present) { $manifestFound } else { $false } )
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
        services            = $services
        proxy               = $proxy
        reachability        = $reachability
    }

    $result = New-CollectorMetadata -Payload $payload
    $outputPath = Export-CollectorResult -OutputDirectory $OutputDirectory -FileName 'store-functional.json' -Data $result -Depth 6
    Write-Output $outputPath
}

Invoke-Main
