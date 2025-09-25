<#!
.SYNOPSIS
    Network diagnostics heuristics covering connectivity, DNS, proxy, and Outlook health.
#>

. (Join-Path -Path (Split-Path $PSScriptRoot -Parent) -ChildPath 'AnalyzerCommon.ps1')

function Test-NetworkPrivateIpv4 {
    param([string]$Address)

    if (-not $Address) { return $false }
    if ($Address -match '^10\.') { return $true }
    if ($Address -match '^192\.168\.') { return $true }
    if ($Address -match '^172\.(1[6-9]|2[0-9]|3[0-1])\.'){ return $true }
    return $false
}

function Test-NetworkLoopback {
    param([string]$Address)

    if (-not $Address) { return $false }
    return ($Address -match '^127\.')
}

function ConvertTo-NetworkArray {
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

function Invoke-NetworkHeuristics {
    param(
        [Parameter(Mandatory)]
        $Context
    )

    $result = New-CategoryResult -Name 'Network'

    $computerSystem = $null
    $systemArtifact = Get-AnalyzerArtifact -Context $Context -Name 'system'
    if ($systemArtifact) {
        $systemPayload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $systemArtifact)
        if ($systemPayload -and $systemPayload.ComputerSystem -and -not $systemPayload.ComputerSystem.Error) {
            $computerSystem = $systemPayload.ComputerSystem
        }
    }

    $networkArtifact = Get-AnalyzerArtifact -Context $Context -Name 'network'
    if ($networkArtifact) {
        $payload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $networkArtifact)
        if ($payload -and $payload.IpConfig) {
            $ipText = if ($payload.IpConfig -is [string[]]) { $payload.IpConfig -join "`n" } else { [string]$payload.IpConfig }
            if ($ipText -match 'IPv4 Address') {
                Add-CategoryNormal -CategoryResult $result -Title 'IPv4 addressing detected'
            } else {
                Add-CategoryIssue -CategoryResult $result -Severity 'high' -Title 'No IPv4 configuration found' -Evidence 'ipconfig /all output did not include IPv4 details.'
            }
        }

        if ($payload -and $payload.Route) {
            $routeText = if ($payload.Route -is [string[]]) { $payload.Route -join "`n" } else { [string]$payload.Route }
            if ($routeText -notmatch '0\.0\.0\.0') {
                Add-CategoryIssue -CategoryResult $result -Severity 'medium' -Title 'Routing table missing default route' -Evidence 'route print output did not include 0.0.0.0/0.'
            }
        }
    } else {
        Add-CategoryIssue -CategoryResult $result -Severity 'info' -Title 'Network base diagnostics not collected'
    }

    $dnsArtifact = Get-AnalyzerArtifact -Context $Context -Name 'dns'
    if ($dnsArtifact) {
        $payload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $dnsArtifact)
        if ($payload -and $payload.Resolution) {
            $failures = $payload.Resolution | Where-Object { $_.Success -eq $false }
            if ($failures.Count -gt 0) {
                $names = $failures | Select-Object -ExpandProperty Name
                Add-CategoryIssue -CategoryResult $result -Severity 'high' -Title ('DNS lookup failures: {0}' -f ($names -join ', '))
            } else {
                Add-CategoryNormal -CategoryResult $result -Title 'DNS lookups succeeded'
            }
        }

        if ($payload -and $payload.Latency) {
            $latency = $payload.Latency
            if ($latency.PSObject.Properties['PingSucceeded']) {
                if (-not $latency.PingSucceeded) {
                    Add-CategoryIssue -CategoryResult $result -Severity 'high' -Title ('Ping to {0} failed' -f $latency.RemoteAddress)
                } else {
                    Add-CategoryNormal -CategoryResult $result -Title ('Ping to {0} succeeded' -f $latency.RemoteAddress)
                }
            } elseif ($latency -is [string] -and $latency -match 'Request timed out') {
                Add-CategoryIssue -CategoryResult $result -Severity 'medium' -Title 'Latency test reported timeouts'
            }
        }

        if ($payload -and $payload.Autodiscover) {
            $autoErrors = $payload.Autodiscover | Where-Object { $_.Error }
            if ($autoErrors.Count -gt 0) {
                $details = $autoErrors | Select-Object -ExpandProperty Error -First 3
                Add-CategoryIssue -CategoryResult $result -Severity 'low' -Title 'Autodiscover DNS queries failed' -Evidence ($details -join "`n")
            }
        }

        if ($payload -and $payload.ClientServers) {
            $entries = ConvertTo-NetworkArray $payload.ClientServers
            $publicServers = New-Object System.Collections.Generic.List[string]
            $loopbackOnly = $true
            $missingInterfaces = @()

            foreach ($entry in $entries) {
                if ($entry -and $entry.Error) {
                    Add-CategoryIssue -CategoryResult $result -Severity 'info' -Title 'Unable to enumerate DNS servers' -Evidence $entry.Error
                    continue
                }

                $alias = if ($entry.InterfaceAlias) { [string]$entry.InterfaceAlias } else { 'Interface' }
                $addresses = ConvertTo-NetworkArray $entry.ServerAddresses | Where-Object { $_ }
                if (-not $addresses -or $addresses.Count -eq 0) {
                    $missingInterfaces += $alias
                    continue
                }

                $loopbackForInterface = $true
                foreach ($address in $addresses) {
                    if (-not (Test-NetworkLoopback $address)) { $loopbackForInterface = $false }
                    if (-not (Test-NetworkPrivateIpv4 $address) -and -not (Test-NetworkLoopback $address)) {
                        $publicServers.Add($address) | Out-Null
                    }
                }

                if (-not $loopbackForInterface) { $loopbackOnly = $false }
                Add-CategoryCheck -CategoryResult $result -Name ("DNS servers ({0})" -f $alias) -Status (($addresses | Select-Object -First 3) -join ', ')
            }

            if ($missingInterfaces.Count -gt 0) {
                Add-CategoryIssue -CategoryResult $result -Severity 'high' -Title ('Adapters missing DNS servers: {0}' -f ($missingInterfaces -join ', '))
            }

            if ($publicServers.Count -gt 0) {
                $severity = if ($computerSystem -and $computerSystem.PartOfDomain -eq $true) { 'high' } else { 'medium' }
                $unique = ($publicServers | Select-Object -Unique)
                Add-CategoryIssue -CategoryResult $result -Severity $severity -Title ('Public DNS servers detected: {0}' -f ($unique -join ', ')) -Evidence 'Prioritize internal DNS for domain services.'
            } elseif (-not $loopbackOnly) {
                Add-CategoryNormal -CategoryResult $result -Title 'Private DNS servers detected'
            }
        }

        if ($payload -and $payload.ClientPolicies) {
            $policies = ConvertTo-NetworkArray $payload.ClientPolicies
            foreach ($policy in $policies) {
                if ($policy -and $policy.Error) {
                    Add-CategoryIssue -CategoryResult $result -Severity 'info' -Title 'DNS client policy query failed' -Evidence $policy.Error
                    continue
                }

                $alias = if ($policy.InterfaceAlias) { [string]$policy.InterfaceAlias } else { 'Interface' }
                $suffix = $policy.ConnectionSpecificSuffix
                if ($suffix) {
                    Add-CategoryCheck -CategoryResult $result -Name ("DNS suffix ({0})" -f $alias) -Status $suffix
                }

                if ($policy.PSObject.Properties['RegisterThisConnectionsAddress']) {
                    $register = $policy.RegisterThisConnectionsAddress
                    if ($register -eq $false -and $computerSystem -and $computerSystem.PartOfDomain -eq $true) {
                        Add-CategoryIssue -CategoryResult $result -Severity 'medium' -Title ("DNS registration disabled on {0}" -f $alias) -Evidence 'RegisterThisConnectionsAddress = False'
                    }
                }
            }
        }
    }

    $outlookArtifact = Get-AnalyzerArtifact -Context $Context -Name 'outlook-connectivity'
    if ($outlookArtifact) {
        $payload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $outlookArtifact)
        if ($payload -and $payload.Connectivity) {
            $conn = $payload.Connectivity
            if ($conn.PSObject.Properties['TcpTestSucceeded']) {
                if (-not $conn.TcpTestSucceeded) {
                    Add-CategoryIssue -CategoryResult $result -Severity 'high' -Title 'Outlook HTTPS connectivity failed' -Evidence ('TcpTestSucceeded reported False for {0}' -f $conn.RemoteAddress)
                } else {
                    Add-CategoryNormal -CategoryResult $result -Title 'Outlook HTTPS connectivity succeeded'
                }
            } elseif ($conn.Error) {
                Add-CategoryIssue -CategoryResult $result -Severity 'medium' -Title 'Unable to test Outlook connectivity' -Evidence $conn.Error
            }
        }

        if ($payload -and $payload.OstFiles) {
            $largeOst = $payload.OstFiles | Where-Object { $_.Length -gt 25GB }
            if ($largeOst.Count -gt 0) {
                $names = $largeOst | Select-Object -ExpandProperty Name
                Add-CategoryIssue -CategoryResult $result -Severity 'medium' -Title ('Large OST files detected: {0}' -f ($names -join ', '))
            } elseif ($payload.OstFiles.Count -gt 0) {
                Add-CategoryNormal -CategoryResult $result -Title ('OST files present ({0})' -f $payload.OstFiles.Count)
            }
        }
    }

    $autodiscoverArtifact = Get-AnalyzerArtifact -Context $Context -Name 'autodiscover-dns'
    if ($autodiscoverArtifact) {
        $payload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $autodiscoverArtifact)
        if ($payload -and $payload.Results) {
            foreach ($domainEntry in (ConvertTo-NetworkArray $payload.Results)) {
                if (-not $domainEntry) { continue }
                $domain = $domainEntry.Domain
                $lookups = ConvertTo-NetworkArray $domainEntry.Lookups
                $autoRecord = $lookups | Where-Object { $_.Label -eq 'Autodiscover' } | Select-Object -First 1
                if (-not $autoRecord) { continue }

                $targetsRaw = ConvertTo-NetworkArray $autoRecord.Targets
                if ($autoRecord.Success -eq $true -and $targetsRaw.Count -gt 0) {
                    $targets = ($targetsRaw | Where-Object { $_ })
                    $targetText = $targets -join ', '
                    if ($targets -match 'autodiscover\.outlook\.com') {
                        Add-CategoryNormal -CategoryResult $result -Title ("Autodiscover healthy for {0}" -f $domain) -Evidence $targetText
                    } else {
                        $severity = if ($computerSystem -and $computerSystem.PartOfDomain -eq $true) { 'medium' } else { 'low' }
                        Add-CategoryIssue -CategoryResult $result -Severity $severity -Title ("Autodiscover for {0} targets {1}" -f $domain, $targetText) -Evidence 'Expected autodiscover.outlook.com for Exchange Online onboarding.'
                    }
                } elseif ($autoRecord.Success -eq $false) {
                    $severity = if ($computerSystem -and $computerSystem.PartOfDomain -eq $true) { 'high' } else { 'medium' }
                    $evidence = if ($autoRecord.Error) { $autoRecord.Error } else { "Lookup failed for autodiscover.$domain" }
                    Add-CategoryIssue -CategoryResult $result -Severity $severity -Title ("Autodiscover lookup failed for {0}" -f $domain) -Evidence $evidence
                }

                foreach ($additional in ($lookups | Where-Object { $_.Label -ne 'Autodiscover' })) {
                    if (-not $additional) { continue }
                    if ($additional.Success -eq $false -and $additional.Error) {
                        Add-CategoryIssue -CategoryResult $result -Severity 'low' -Title ("{0} record missing for {1}" -f $additional.Label, $domain) -Evidence $additional.Error
                    }
                }
            }
        }
    }

    $adapterArtifact = Get-AnalyzerArtifact -Context $Context -Name 'network-adapters'
    if ($adapterArtifact) {
        $payload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $adapterArtifact)
        if ($payload -and $payload.Adapters -and -not $payload.Adapters.Error) {
            $upAdapters = $payload.Adapters | Where-Object { $_.Status -eq 'Up' }
            if ($upAdapters.Count -gt 0) {
                Add-CategoryNormal -CategoryResult $result -Title ('Active adapters: {0}' -f ($upAdapters | Select-Object -ExpandProperty Name -join ', '))
            } else {
                Add-CategoryIssue -CategoryResult $result -Severity 'high' -Title 'No active network adapters reported'
            }
        }
    }

    $proxyArtifact = Get-AnalyzerArtifact -Context $Context -Name 'proxy'
    if ($proxyArtifact) {
        $payload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $proxyArtifact)
        if ($payload -and $payload.Internet) {
            $internet = $payload.Internet
            if ($internet.ProxyEnable -eq 1 -and $internet.ProxyServer) {
                Add-CategoryIssue -CategoryResult $result -Severity 'low' -Title ('User proxy enabled: {0}' -f $internet.ProxyServer)
            } elseif ($internet.ProxyEnable -eq 0) {
                Add-CategoryNormal -CategoryResult $result -Title 'User proxy disabled'
            }
        }

        if ($payload -and $payload.WinHttp) {
            $winHttpText = if ($payload.WinHttp -is [string[]]) { $payload.WinHttp -join "`n" } else { [string]$payload.WinHttp }
            if ($winHttpText -match 'Direct access') {
                Add-CategoryNormal -CategoryResult $result -Title 'WinHTTP proxy: Direct access'
            } elseif ($winHttpText) {
                Add-CategoryIssue -CategoryResult $result -Severity 'info' -Title 'WinHTTP proxy configured' -Evidence $winHttpText
            }
        }
    }

    return $result
}
