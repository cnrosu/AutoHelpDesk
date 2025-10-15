<#!
.SYNOPSIS
    Network VPN analyzer that converts collected VPN baselines into AutoHelpDesk findings.
#>

function ConvertTo-VpnArray {
    param($Value)

    if ($null -eq $Value) { return @() }
    if ($Value -is [string]) { return @($Value) }
    if ($Value -is [System.Collections.IEnumerable] -and -not ($Value -is [hashtable])) {
        $items = @()
        foreach ($item in $Value) { $items += $item }
        return $items
    }
    return @($Value)
}

function Get-VpnServiceStateSummary {
    param($Services)

    $summary = [ordered]@{}
    foreach ($name in @('RasMan','IKEEXT')) {
        $entry = $null
        if ($Services -and $Services.PSObject.Properties[$name]) {
            $entry = $Services.$name
        }

        if ($entry -and -not $entry.Error) {
            $status = if ($entry.PSObject.Properties['Status']) { [string]$entry.Status } else { $null }
            $start  = if ($entry.PSObject.Properties['StartType']) { [string]$entry.StartType } else { $null }
            if ($status -and $start) {
                $summary[$name] = ('{0} ({1})' -f $status, $start)
            } elseif ($status) {
                $summary[$name] = $status
            } elseif ($start) {
                $summary[$name] = $start
            }
        } elseif ($entry -and $entry.Error) {
            $summary[$name] = 'error'
        } else {
            $summary[$name] = $null
        }
    }

    return $summary
}

function Select-VpnCertificateForConnection {
    param(
        $Connection,
        $Certificates
    )

    if (-not $Certificates) { return $null }

    $thumbprint = $null
    if ($Connection -and $Connection.auth -and $Connection.auth.PSObject.Properties['certificateThumbprint']) {
        $thumbprint = $Connection.auth.certificateThumbprint
    }

    $matches = @()
    if ($thumbprint) {
        $matches = $Certificates | Where-Object { $_.thumbprint -and $_.thumbprint -ieq $thumbprint }
    }

    if (-not $matches -or $matches.Count -eq 0) {
        $matches = $Certificates | Where-Object { $_.intendedForClientAuth -eq $true }
    }

    if (-not $matches -or $matches.Count -eq 0) {
        $matches = $Certificates | Where-Object { $_.isExpired -eq $false }
    }

    return $matches | Select-Object -First 1
}

function New-VpnEvidence {
    param(
        $Connection,
        $Network,
        $Certificates,
        $Services,
        [hashtable]$Additional
    )

    $serviceSummary = Get-VpnServiceStateSummary -Services $Services
    $defaultViaVpn = $null
    $corpRoutesCount = $null
    $splitTunneling = $null
    $vpnType = $null
    $serverAddress = $null

    if ($Connection) {
        if ($Connection.PSObject.Properties['splitTunneling']) { $splitTunneling = $Connection.splitTunneling }
        if ($Connection.PSObject.Properties['routes'] -and $Connection.routes) {
            if ($Connection.routes.PSObject.Properties['defaultViaVpn']) { $defaultViaVpn = $Connection.routes.defaultViaVpn }
            if ($Connection.routes.PSObject.Properties['classlessRoutes']) {
                $corpRoutesCount = @(ConvertTo-VpnArray -Value $Connection.routes.classlessRoutes | Where-Object { $_ }).Count
            }
        }
        if ($Connection.PSObject.Properties['type']) { $vpnType = $Connection.type }
        if ($Connection.PSObject.Properties['serverAddress']) { $serverAddress = $Connection.serverAddress }
    }

    $effectiveDns = @()
    if ($Network -and $Network.PSObject.Properties['effectiveDnsServers'] -and $Network.effectiveDnsServers) {
        $effectiveDns = (ConvertTo-VpnArray -Value $Network.effectiveDnsServers) | Where-Object { $_ }
    }

    $certSummary = $null
    if ($Connection -and $Connection.auth -and $Connection.auth.usesCertificate -eq $true) {
        $cert = Select-VpnCertificateForConnection -Connection $Connection -Certificates $Certificates
        if ($cert) {
            $suffix = $null
            if ($cert.thumbprint -and $cert.thumbprint.Length -ge 8) {
                $suffix = $cert.thumbprint.Substring($cert.thumbprint.Length - 8)
            }
            $certSummary = [ordered]@{
                thumbprintLast8 = $suffix
                notAfterUtc     = if ($cert.PSObject.Properties['notAfterUtc']) { $cert.notAfterUtc } else { $null }
                isExpired       = if ($cert.PSObject.Properties['isExpired']) { $cert.isExpired } else { $null }
            }
        } else {
            $certSummary = [ordered]@{ status = 'not-found' }
        }
    }

    $lastStatusSummary = $null
    if ($Connection -and $Connection.PSObject.Properties['lastStatus'] -and $Connection.lastStatus) {
        $status = $Connection.lastStatus
        $lastStatusSummary = [ordered]@{
            connected         = if ($status.PSObject.Properties['connected']) { $status.connected } else { $null }
            connectedSinceUtc = if ($status.PSObject.Properties['connectedSinceUtc']) { $status.connectedSinceUtc } else { $null }
            bytesIn           = if ($status.PSObject.Properties['bytesIn']) { $status.bytesIn } else { $null }
            bytesOut          = if ($status.PSObject.Properties['bytesOut']) { $status.bytesOut } else { $null }
            lastError         = if ($status.PSObject.Properties['lastError']) { $status.lastError } else { $null }
        }
    }

    $evidence = [ordered]@{
        vpnName             = if ($Connection) { $Connection.name } else { $null }
        vpnType             = $vpnType
        serverAddress       = $serverAddress
        splitTunneling      = $splitTunneling
        defaultViaVpn       = $defaultViaVpn
        corpRoutesCount     = $corpRoutesCount
        effectiveDnsServers = ($effectiveDns | Select-Object -First 3)
        certSummary         = $certSummary
        serviceStates       = $serviceSummary
        lastStatus          = $lastStatusSummary
    }

    if ($Additional) {
        foreach ($key in $Additional.Keys) {
            $evidence[$key] = $Additional[$key]
        }
    }

    return $evidence
}

function Test-VpnPublicAddress {
    param([string]$Address)

    if (-not $Address) { return $false }
    $addr = $Address.Trim()
    if (-not $addr) { return $false }

    if ($addr -match '^(8\.8\.8\.8|8\.8\.4\.4|1\.1\.1\.1|1\.0\.0\.1|9\.9\.9\.9|149\.112\.112\.112)') { return $true }
    if ($addr -match '^(208\.67\.)') { return $true }
    if ($addr -match '^(4\.2\.2\.)') { return $true }
    return $false
}

function Add-VpnIssue {
    param(
        $CategoryResult,
        [string]$Severity,
        [string]$Title,
        $Connection,
        $Network,
        $Certificates,
        $Services,
        [string]$Subcategory,
        [string]$Remediation,
        [string]$RemediationScript,
        [hashtable]$ExtraEvidence
    )

    $evidence = New-VpnEvidence -Connection $Connection -Network $Network -Certificates $Certificates -Services $Services -Additional $ExtraEvidence
    $issueArguments = @{
        CategoryResult = $CategoryResult
        Severity       = $Severity
        Title          = $Title
        Evidence       = $evidence
        Subcategory    = $Subcategory
    }

    if ($Remediation) { $issueArguments['Remediation'] = $Remediation }
    if ($RemediationScript) { $issueArguments['RemediationScript'] = $RemediationScript }

    Add-CategoryIssue @issueArguments
}

function Add-VpnHealthyFinding {
    param(
        $CategoryResult,
        $Connection,
        $Network,
        $Certificates,
        $Services
    )

    $evidence = New-VpnEvidence -Connection $Connection -Network $Network -Certificates $Certificates -Services $Services -Additional @{}
    Add-CategoryNormal -CategoryResult $CategoryResult -Title ("VPN '{0}' healthy" -f $Connection.name) -Evidence $evidence -Subcategory 'Profiles'
}

function Invoke-NetworkVpnAnalysis {
    param(
        [Parameter(Mandatory)]
        $Context
    )

    $category = New-CategoryResult -Name 'Network/VPN'

    $artifact = Get-AnalyzerArtifact -Context $Context -Name 'vpn-baseline'
    if (-not $artifact) {
        Add-CategoryIssue -CategoryResult $category -Severity 'warning' -Title 'VPN baseline artifact missing; VPN health unknown.' -Subcategory 'Collection'
        return $category
    }

    $payload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $artifact)
    if (-not $payload) {
        Add-CategoryIssue -CategoryResult $category -Severity 'warning' -Title 'VPN baseline payload unavailable or corrupted.' -Subcategory 'Collection'
        return $category
    }

    $services = if ($payload.PSObject.Properties['services']) { $payload.services } else { $null }
    $network = if ($payload.PSObject.Properties['network']) { $payload.network } else { $null }
    $certificates = if ($payload.PSObject.Properties['certificates']) { ConvertTo-VpnArray -Value $payload.certificates } else { @() }
    $connections = if ($payload.PSObject.Properties['connections']) { ConvertTo-VpnArray -Value $payload.connections } else { @() }

    if ($connections.Count -eq 0) {
        $summary = Get-VpnServiceStateSummary -Services $services
        $extra = [ordered]@{ detectedProfiles = 0; serviceStates = $summary }
        Add-CategoryIssue -CategoryResult $category -Severity 'warning' -Title 'No VPN profiles detected; remote access will fail on managed devices.' -Evidence $extra -Subcategory 'Profiles'
        return $category
    }

    $eventArtifact = Get-AnalyzerArtifact -Context $Context -Name 'vpn-events'
    $eventPayload = $null
    $eventList = @()
    if ($eventArtifact) {
        $eventPayload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $eventArtifact)
        if ($eventPayload -and $eventPayload.PSObject.Properties['events']) {
            $eventList = ConvertTo-VpnArray -Value $eventPayload.events
        }
    }

    $defaultRouteConnections = @()
    $routeMap = @{}

    foreach ($connection in $connections) {
        if (-not $connection) { continue }

        $type = if ($connection.PSObject.Properties['type']) { [string]$connection.type } else { 'Unknown' }
        if ($type) { $type = $type.Trim() }

        if ($type -eq 'PPTP') {
            Add-VpnIssue -CategoryResult $category -Severity 'critical' -Title ("PPTP profile '{0}' detected — deprecated and insecure." -f $connection.name) -Connection $connection -Network $network -Certificates $certificates -Services $services -Subcategory 'Profiles' -Remediation 'Replace PPTP with IKEv2 or SSTP and remove the legacy profile.' -ExtraEvidence @{}
        } elseif ($type -eq 'L2TP') {
            $usesCertificate = $false
            if ($connection.auth -and $connection.auth.PSObject.Properties['usesCertificate']) {
                $usesCertificate = [bool]$connection.auth.usesCertificate
            }
            if (-not $usesCertificate) {
                Add-VpnIssue -CategoryResult $category -Severity 'high' -Title ("L2TP profile '{0}' lacks certificate/IPsec enforcement." -f $connection.name) -Connection $connection -Network $network -Certificates $certificates -Services $services -Subcategory 'Profiles' -Remediation 'Require certificate-based IPsec (EAP-TLS) or migrate to IKEv2/SSTP.' -ExtraEvidence @{}
            }
        } elseif ($type -eq 'Automatic') {
            Add-VpnIssue -CategoryResult $category -Severity 'warning' -Title ("VPN '{0}' uses Automatic tunnel selection, leading to inconsistent protocols." -f $connection.name) -Connection $connection -Network $network -Certificates $certificates -Services $services -Subcategory 'Profiles' -Remediation 'Pin the tunnel type to IKEv2 or SSTP to align with policy.' -ExtraEvidence @{}
        }

        if ($connection.PSObject.Properties['routes'] -and $connection.routes) {
            if ($connection.routes.PSObject.Properties['defaultViaVpn'] -and $connection.routes.defaultViaVpn -eq $true) {
                $defaultRouteConnections += $connection
            }

            if ($connection.routes.PSObject.Properties['classlessRoutes']) {
                foreach ($route in (ConvertTo-VpnArray -Value $connection.routes.classlessRoutes)) {
                    if (-not $route) { continue }
                    $normalized = $route.ToLowerInvariant()
                    if ($routeMap.ContainsKey($normalized)) {
                        $routeMap[$normalized] = $routeMap[$normalized] + ,$connection.name
                    } else {
                        $routeMap[$normalized] = @($connection.name)
                    }
                }
            }
        }

        $split = $connection.splitTunneling
        if ($split -eq $true) {
            Add-VpnIssue -CategoryResult $category -Severity 'high' -Title ("Split tunneling enabled on '{0}' (policy violation)." -f $connection.name) -Connection $connection -Network $network -Certificates $certificates -Services $services -Subcategory 'Policies' -Remediation 'Disable split tunneling so all corporate traffic routes through the VPN.' -ExtraEvidence @{}
        }

        $authMethod = $null
        if ($connection.auth -and $connection.auth.PSObject.Properties['method']) {
            $authMethod = [string]$connection.auth.method
        }
        $usesCert = $false
        if ($connection.auth -and $connection.auth.PSObject.Properties['usesCertificate']) {
            $usesCert = $connection.auth.usesCertificate
        }

        if ($authMethod -eq 'MSCHAPv2' -and -not $usesCert) {
            Add-VpnIssue -CategoryResult $category -Severity 'high' -Title ("Weak MS-CHAPv2 authentication on '{0}'." -f $connection.name) -Connection $connection -Network $network -Certificates $certificates -Services $services -Subcategory 'Authentication' -Remediation 'Switch to EAP-TLS or certificate-based authentication to prevent credential attacks.' -ExtraEvidence @{}
        }

        if ($connection.auth -and $connection.auth.PSObject.Properties['usesCertificate'] -and $connection.auth.usesCertificate -eq $true) {
            $cert = Select-VpnCertificateForConnection -Connection $connection -Certificates $certificates
            if (-not $cert) {
                Add-VpnIssue -CategoryResult $category -Severity 'critical' -Title ("Certificate required for '{0}' but none found." -f $connection.name) -Connection $connection -Network $network -Certificates $certificates -Services $services -Subcategory 'Authentication' -Remediation 'Install a valid client authentication certificate for this VPN profile.' -ExtraEvidence @{}
            } elseif ($cert.PSObject.Properties['isExpired'] -and $cert.isExpired -eq $true) {
                Add-VpnIssue -CategoryResult $category -Severity 'critical' -Title ("VPN certificate expired for '{0}'." -f $connection.name) -Connection $connection -Network $network -Certificates $certificates -Services $services -Subcategory 'Authentication' -Remediation 'Renew and deploy a fresh client authentication certificate.' -ExtraEvidence @{}
            }
        }

        $lastStatus = if ($connection.PSObject.Properties['lastStatus']) { $connection.lastStatus } else { $null }
        if ($lastStatus -and $lastStatus.connected -eq $true) {
            $defaultViaVpn = $null
            $routes = $connection.routes
            if ($routes -and $routes.PSObject.Properties['defaultViaVpn']) { $defaultViaVpn = $routes.defaultViaVpn }
            $corpCount = 0
            if ($routes -and $routes.PSObject.Properties['classlessRoutes']) {
                $corpCount = @(ConvertTo-VpnArray -Value $routes.classlessRoutes | Where-Object { $_ }).Count
            }
            $interfaceDown = $false
            if ($network -and $network.interfaces) {
                $interfaces = ConvertTo-VpnArray -Value $network.interfaces
                $wan = $interfaces | Where-Object { $_.name -match 'WAN Miniport' -or $_.name -match $connection.name }
                if ($wan) {
                    foreach ($if in $wan) {
                        if ($if.status -and $if.status -notin @('Up','UpMediaSense')) { $interfaceDown = $true }
                    }
                }
            }
            if (($defaultViaVpn -ne $true) -and ($corpCount -eq 0)) {
                Add-VpnIssue -CategoryResult $category -Severity 'critical' -Title ("VPN '{0}' connected but no corporate routes applied." -f $connection.name) -Connection $connection -Network $network -Certificates $certificates -Services $services -Subcategory 'Routing' -Remediation 'Update the profile to push a default route or corporate prefixes when connected.' -ExtraEvidence @{}
            } elseif ($interfaceDown) {
                Add-VpnIssue -CategoryResult $category -Severity 'critical' -Title ("VPN '{0}' connected but adapter reports down." -f $connection.name) -Connection $connection -Network $network -Certificates $certificates -Services $services -Subcategory 'Routing' -Remediation 'Investigate WAN Miniport health and driver state; rebuild the VPN adapter if needed.' -ExtraEvidence @{}
            }
        } else {
            $everConnected = $false
            if ($lastStatus -and $lastStatus.connectedSinceUtc) { $everConnected = $true }
            $bytesIn = if ($lastStatus) { $lastStatus.bytesIn } else { $null }
            $bytesOut = if ($lastStatus) { $lastStatus.bytesOut } else { $null }
            if (-not $everConnected -and ((-not $bytesIn) -or $bytesIn -eq 0) -and ((-not $bytesOut) -or $bytesOut -eq 0)) {
                Add-VpnIssue -CategoryResult $category -Severity 'medium' -Title ("VPN '{0}' configured but never successfully connected." -f $connection.name) -Connection $connection -Network $network -Certificates $certificates -Services $services -Subcategory 'Usage' -Remediation 'Verify credentials, certificates, and server reachability for this profile.' -ExtraEvidence @{}
            }
        }

        if ($lastStatus -and $lastStatus.connected -eq $true) {
            $dnsServers = @()
            if ($network -and $network.PSObject.Properties['effectiveDnsServers']) {
                $dnsServers = ConvertTo-VpnArray -Value $network.effectiveDnsServers
            }
            $publicDns = $dnsServers | Where-Object { Test-VpnPublicAddress -Address $_ }
            if ($publicDns.Count -gt 0) {
                Add-VpnIssue -CategoryResult $category -Severity 'medium' -Title ("Public DNS detected while '{0}' is connected." -f $connection.name) -Connection $connection -Network $network -Certificates $certificates -Services $services -Subcategory 'DNS' -Remediation 'Ensure VPN policies enforce internal DNS servers when connected.' -ExtraEvidence @{}
            }
        }

        $suffixes = if ($connection.PSObject.Properties['dnsSuffixes']) { ConvertTo-VpnArray -Value $connection.dnsSuffixes } else { @() }
        if ($suffixes.Count -eq 0) {
            Add-VpnIssue -CategoryResult $category -Severity 'medium' -Title ("VPN '{0}' missing corporate DNS suffix configuration." -f $connection.name) -Connection $connection -Network $network -Certificates $certificates -Services $services -Subcategory 'DNS' -Remediation 'Add corporate DNS suffixes (e.g., corp.local) to the VPN profile.' -ExtraEvidence @{}
        }

        if ($lastStatus -and $lastStatus.connected -eq $true) {
            $healthy = $false
            $typeOk = $type -in @('IKEv2','SSTP')
            $splitOk = ($connection.splitTunneling -eq $false -or $null -eq $connection.splitTunneling)
            $defaultOk = $connection.routes -and $connection.routes.defaultViaVpn -eq $true
            $dnsOk = $true
            if ($network -and $network.PSObject.Properties['effectiveDnsServers']) {
                $dnsOk = -not (ConvertTo-VpnArray -Value $network.effectiveDnsServers | Where-Object { Test-VpnPublicAddress -Address $_ })
            }
            $certHealthy = $true
            if ($connection.auth -and $connection.auth.PSObject.Properties['usesCertificate'] -and $connection.auth.usesCertificate -eq $true) {
                $cert = Select-VpnCertificateForConnection -Connection $connection -Certificates $certificates
                if (-not $cert -or ($cert.PSObject.Properties['isExpired'] -and $cert.isExpired -eq $true)) {
                    $certHealthy = $false
                } elseif ($cert.PSObject.Properties['notAfterUtc']) {
                    try {
                        $expiry = [datetime]::Parse($cert.notAfterUtc)
                        if ($expiry -lt (Get-Date).AddDays(30)) { $certHealthy = $false }
                    } catch {
                    }
                }
            }

            if ($typeOk -and $splitOk -and $defaultOk -and $dnsOk -and $certHealthy) {
                Add-VpnHealthyFinding -CategoryResult $category -Connection $connection -Network $network -Certificates $certificates -Services $services
            }
        }
    }

    if ($defaultRouteConnections.Count -gt 1) {
        $names = $defaultRouteConnections | ForEach-Object { $_.name }
        Add-VpnIssue -CategoryResult $category -Severity 'warning' -Title ('Multiple VPN profiles push default routes: {0}.' -f ($names -join ', ')) -Connection $null -Network $network -Certificates $certificates -Services $services -Subcategory 'Routing' -Remediation 'Review overlapping VPN defaults to prevent route conflicts.' -ExtraEvidence @{}
    }

    $conflicts = @()
    foreach ($routeKey in $routeMap.Keys) {
        $owners = $routeMap[$routeKey]
        if ($owners.Count -gt 1) {
            $conflicts += [ordered]@{ route = $routeKey; profiles = ($owners | Select-Object -Unique) }
        }
    }
    if ($conflicts.Count -gt 0) {
        $evidence = [ordered]@{
            overlappingRoutes = $conflicts | Select-Object -First 5
        }
        Add-CategoryIssue -CategoryResult $category -Severity 'warning' -Title 'VPN profiles share overlapping routes.' -Evidence $evidence -Subcategory 'Routing'
    }

    if ($connections.Count -gt 0 -and $services) {
        foreach ($name in @('RasMan','IKEEXT')) {
            $entry = if ($services.PSObject.Properties[$name]) { $services.$name } else { $null }
            if (-not $entry) {
                Add-CategoryIssue -CategoryResult $category -Severity 'high' -Title ("{0} service missing; VPN stack broken." -f $name) -Connection $null -Network $network -Certificates $certificates -Services $services -Subcategory 'Services' -Remediation 'Reinstall or repair the Windows VPN components.' -ExtraEvidence @{}
                continue
            }
            $status = if ($entry.PSObject.Properties['Status']) { [string]$entry.Status } else { $null }
            $start = if ($entry.PSObject.Properties['StartType']) { [string]$entry.StartType } else { $null }
            if ($status -and $status -ne 'Running') {
                Add-VpnIssue -CategoryResult $category -Severity 'high' -Title ("{0} service not running; VPN connections will fail." -f $name) -Connection $null -Network $network -Certificates $certificates -Services $services -Subcategory 'Services' -Remediation 'Start the service and configure Automatic start mode.' -ExtraEvidence @{}
            } elseif ($start -and $start -match 'Disabled') {
                Add-VpnIssue -CategoryResult $category -Severity 'high' -Title ("{0} service disabled; VPN stack unavailable." -f $name) -Connection $null -Network $network -Certificates $certificates -Services $services -Subcategory 'Services' -Remediation 'Set the service to Manual or Automatic and restart the device.' -ExtraEvidence @{}
            }
        }
    }

    if ($eventList.Count -gt 0) {
        $failureIds = @('20227','20255','20226','20271','13801','13806','32775')
        $failures = $eventList | Where-Object {
            ($_.level -and $_.level -match 'Error') -or ($_.eventId -and $failureIds -contains ([string]$_.eventId))
        }
        if ($failures.Count -gt 3) {
            $sample = $failures | Select-Object -First 3
            $evidence = [ordered]@{
                recentFailures = $sample
                totalFailures  = $failures.Count
            }
            Add-CategoryIssue -CategoryResult $category -Severity 'high' -Title 'Frequent VPN failures detected in RasClient/IKEEXT logs.' -Evidence $evidence -Subcategory 'Events'
        }
    }

    return $category
}
