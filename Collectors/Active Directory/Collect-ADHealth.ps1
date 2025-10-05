<#!
.SYNOPSIS
    Collects detailed Active Directory health information, including discovery, reachability, time, Kerberos, and GPO data.
.PARAMETER OutputDirectory
    Specifies the folder where the AD health JSON artifact will be written.
#>
[CmdletBinding()]
param(
    [Parameter()]
    [string]$OutputDirectory = (Join-Path -Path (Split-Path -Parent $PSCommandPath) -ChildPath '..\output')
)

. (Join-Path -Path $PSScriptRoot -ChildPath '..\CollectorCommon.ps1')

$script:candidateMap = @{}

function Invoke-CommandCapture {
    param(
        [Parameter(Mandatory)]
        [string]$FilePath,

        [Parameter()]
        [string[]]$ArgumentList = @()
    )

    $result = [ordered]@{
        FilePath  = $FilePath
        Arguments = $ArgumentList
        Output    = @()
        ExitCode  = $null
        Error     = $null
        Succeeded = $false
    }

    try {
        $output = & $FilePath @ArgumentList 2>&1
        if ($output) {
            $result.Output = @($output)
        }
        if ($null -ne $LASTEXITCODE) {
            $result.ExitCode = $LASTEXITCODE
            if ($LASTEXITCODE -eq 0) {
                $result.Succeeded = $true
            }
        } else {
            $result.ExitCode = 0
            $result.Succeeded = $true
        }
    } catch {
        $result.Error = $_.Exception.Message
        $result.Succeeded = $false
    }

    return $result
}

function Add-Candidate {
    param(
        [Parameter(Mandatory)]
        [string]$Hostname,

        [Parameter(Mandatory)]
        [string]$Source,

        [string]$Address
    )

    $cleanHost = ($Hostname -replace '^\\\\', '').Trim()
    if ($cleanHost.EndsWith('.')) { $cleanHost = $cleanHost.TrimEnd('.') }
    if (-not $cleanHost) { return }

    $key = $cleanHost.ToLowerInvariant()
    if (-not $script:candidateMap.ContainsKey($key)) {
        $script:candidateMap[$key] = [ordered]@{
            Hostname  = $cleanHost
            Addresses = New-Object System.Collections.Generic.List[string]
            Sources   = New-Object System.Collections.Generic.List[string]
        }
    }

    $entry = $script:candidateMap[$key]
    if ($Source -and -not $entry.Sources.Contains($Source)) {
        $entry.Sources.Add($Source) | Out-Null
    }
    if ($Address) {
        $trimmedAddress = $Address.Trim()
        if ($trimmedAddress -and -not $entry.Addresses.Contains($trimmedAddress)) {
            $entry.Addresses.Add($trimmedAddress) | Out-Null
        }
    }
}

function Resolve-Candidates {
    return $script:candidateMap.Keys | Sort-Object | ForEach-Object {
        $entry = $script:candidateMap[$_]
        [ordered]@{
            Hostname  = $entry.Hostname
            Addresses = @($entry.Addresses)
            Sources   = @($entry.Sources)
        }
    }
}

function Test-TcpPort {
    param(
        [Parameter(Mandatory)]
        [string]$Target,

        [Parameter(Mandatory)]
        [int]$Port,

        [int]$TimeoutMs = 2000
    )

    $result = [ordered]@{
        Success       = $false
        RemoteAddress = $null
        LatencyMs     = $null
        Error         = $null
    }

    $client = $null
    $waitHandle = $null
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        $client = New-Object System.Net.Sockets.TcpClient
        $asyncResult = $client.BeginConnect($Target, $Port, $null, $null)
        $waitHandle = $asyncResult.AsyncWaitHandle

        if (-not $waitHandle.WaitOne($TimeoutMs, $false)) {
            throw "Connection attempt timed out after $TimeoutMs ms."
        }

        $client.EndConnect($asyncResult)
        $stopwatch.Stop()
        $result.Success = $true
        $result.LatencyMs = [Math]::Round($stopwatch.Elapsed.TotalMilliseconds, 2)

        $remoteEndpoint = $client.Client.RemoteEndPoint
        if ($remoteEndpoint -and $remoteEndpoint.Address) {
            $result.RemoteAddress = $remoteEndpoint.Address.ToString()
        }
    } catch {
        if ($stopwatch.IsRunning) { $stopwatch.Stop() }
        $result.Error = $_.Exception.Message
        $result.Success = $false
    } finally {
        if ($waitHandle) { $waitHandle.Close() }
        if ($client) { $client.Close() }
    }

    return $result
}

function Get-DomainStatus {
    $result = [ordered]@{
        ComputerName = $env:COMPUTERNAME
        DomainJoined = $null
        Domain       = $null
        Forest       = $null
        DomainRole   = $null
        Workgroup    = $null
        Error        = $null
    }

    $cs = Get-CollectorComputerSystem
    if (Test-CollectorResultHasError -Value $cs) {
        $result.Error = $cs.Error
        return $result
    }

    if ($cs) {
        $result.DomainJoined = $cs.PartOfDomain
        $result.Domain = $cs.Domain
        if ($cs.PSObject.Properties['DomainRole']) {
            $result.DomainRole = $cs.DomainRole
        }
        if (-not $cs.PartOfDomain -and $cs.PSObject.Properties['Workgroup']) {
            $result.Workgroup = $cs.Workgroup
        }
    }

    return $result
}

function Get-DomainDiscovery {
    param(
        [string]$Domain,
        [string]$Forest
    )

    $discovery = [ordered]@{
        DsGetDc    = $null
        DcList     = $null
        SrvLookups = [ordered]@{}
        Candidates = @()
        Forest     = $Forest
    }

    if (-not $Domain) { return $discovery }

    $dsgetdc = Invoke-CommandCapture -FilePath 'nltest.exe' -ArgumentList "/dsgetdc:$Domain"
    $discovery.DsGetDc = $dsgetdc

    if ($dsgetdc.Output) {
        $currentHost = $null
        foreach ($line in $dsgetdc.Output) {
            if ($line -match 'Forest:\s*(?<forest>[^\s]+)') {
                if (-not $Forest) { $Forest = $matches['forest'] }
            }
            if ($line -match 'Domain Name:\s*(?<domain>[^\s]+)' -and -not $Domain) {
                $Domain = $matches['domain']
            }
            if ($line -match 'DC:\s*\\\\(?<dc>[^\s]+)') {
                $currentHost = $matches['dc']
                Add-Candidate -Hostname $currentHost -Source 'nltest-dsgetdc'
            }
            if ($line -match 'Address:\s*(?<addr>[\d\.:]+)') {
                if ($currentHost) {
                    Add-Candidate -Hostname $currentHost -Source 'nltest-dsgetdc' -Address $matches['addr']
                }
            }
        }
    }

    $dclist = Invoke-CommandCapture -FilePath 'nltest.exe' -ArgumentList "/dclist:$Domain"
    $discovery.DcList = $dclist
    if ($dclist.Output) {
        foreach ($line in $dclist.Output) {
            if ($line -match 'DC:\s*\\\\(?<dc>[^\s]+)') {
                Add-Candidate -Hostname $matches['dc'] -Source 'nltest-dclist'
            }
        }
    }

    if (-not $Forest) { $Forest = $Domain }

    $srvTargets = @{
        'ldap-forest'  = "_ldap._tcp.dc._msdcs.$Forest"
        'kerberos-domain' = "_kerberos._tcp.$Domain"
    }

    foreach ($key in $srvTargets.Keys) {
        $name = $srvTargets[$key]
        $lookup = [ordered]@{
            Query     = $name
            Records   = [System.Collections.Generic.List[pscustomobject]]::new()
            Error     = $null
            Succeeded = $false
        }
        try {
            $records = Resolve-DnsName -Type SRV -Name $name -ErrorAction Stop
            foreach ($record in $records) {
                if ($record.PSObject.Properties['NameTarget']) {
                    $target = $record.NameTarget
                } else {
                    $target = $record.NameHost
                }
                $target = if ($target) { $target.Trim() } else { $null }
                if ($target) {
                    if ($target.EndsWith('.')) { $target = $target.TrimEnd('.') }
                    Add-Candidate -Hostname $target -Source $key
                }
                $address = $null
                if ($record.PSObject.Properties['IPAddress']) { $address = $record.IPAddress }
                elseif ($record.PSObject.Properties['IP4Address']) { $address = $record.IP4Address }
                if ($address) {
                    Add-Candidate -Hostname $target -Source $key -Address $address
                } elseif ($target) {
                    try {
                        $aRecord = Resolve-DnsName -Name $target -ErrorAction Stop | Select-Object -First 5
                        foreach ($addrRecord in $aRecord) {
                            if ($addrRecord.PSObject.Properties['IPAddress']) {
                                Add-Candidate -Hostname $target -Source "$key-a" -Address $addrRecord.IPAddress
                            } elseif ($addrRecord.PSObject.Properties['IP4Address']) {
                                Add-Candidate -Hostname $target -Source "$key-a" -Address $addrRecord.IP4Address
                            }
                        }
                    } catch {
                        # ignore resolution errors here
                    }
                }
                $lookup.Records.Add([pscustomobject]@{
                    Target    = $target
                    Port      = $record.Port
                    Priority  = $record.Priority
                    Weight    = $record.Weight
                    TimeToLive = $record.TTL
                })
            }
            $lookup.Succeeded = $true
        } catch {
            $lookup.Error = $_.Exception.Message
            $lookup.Succeeded = $false
        }
        if ($lookup.Records -is [System.Collections.Generic.List[object]]) {
            $lookup.Records = $lookup.Records.ToArray()
        }
        $discovery.SrvLookups[$key] = $lookup
    }

    if (-not $Forest) { $Forest = $Domain }
    $discovery.Forest = $Forest
    $discovery.Candidates = Resolve-Candidates
    return $discovery
}

function Test-DomainControllerReachability {
    param(
        [array]$Candidates
    )

    $tests = [System.Collections.Generic.List[pscustomobject]]::new()
    if (-not $Candidates) { return $tests }

    $ports = @(88, 389, 445, 135)
    foreach ($candidate in $Candidates) {
        $host = $candidate.Hostname
        foreach ($port in $ports) {
            $testResult = [ordered]@{
                Target        = $host
                Port          = $port
                Success       = $null
                RemoteAddress = $null
                LatencyMs     = $null
                Error         = $null
            }
            try {
                $probe = Test-TcpPort -Target $host -Port $port -TimeoutMs 2000
                $testResult.Success = $probe.Success
                $testResult.RemoteAddress = $probe.RemoteAddress
                $testResult.LatencyMs = $probe.LatencyMs
                $testResult.Error = $probe.Error
            } catch {
                $testResult.Success = $false
                $testResult.Error = $_.Exception.Message
            }
            if (-not $testResult.RemoteAddress -and $candidate.Addresses -and $candidate.Addresses.Count -gt 0) {
                $testResult.RemoteAddress = $candidate.Addresses[0]
            }
            $tests.Add([pscustomobject]$testResult)
        }
    }

    return $tests.ToArray()
}

function Test-DomainShares {
    param(
        [array]$Candidates
    )

    $tests = [System.Collections.Generic.List[pscustomobject]]::new()
    if (-not $Candidates) { return $tests }

    foreach ($candidate in $Candidates) {
        $host = $candidate.Hostname
        foreach ($share in @('SYSVOL', 'NETLOGON')) {
            $test = [ordered]@{
                Target = $host
                Share  = $share
                Path   = "\\$host\$share"
                Success = $false
                Error   = $null
                Items   = @()
            }
            try {
                $path = "\\$host\$share"
                if (Test-Path -Path $path) {
                    $test.Success = $true
                    try {
                        $items = (Get-ChildItem -Path $path -ErrorAction Stop | Select-Object -First 5).Name
                        if ($items) {
                            $test.Items = @($items)
                        }
                    } catch {
                        $test.Error = $_.Exception.Message
                    }
                } else {
                    $test.Success = $false
                }
            } catch {
                $test.Success = $false
                $test.Error = $_.Exception.Message
            }
            $tests.Add([pscustomobject]$test)
        }
    }

    return $tests.ToArray()
}

function Get-TimeServiceStatus {
    $status = Invoke-CommandCapture -FilePath 'w32tm.exe' -ArgumentList '/query','/status'
    $peers = Invoke-CommandCapture -FilePath 'w32tm.exe' -ArgumentList '/query','/peers'
    $config = Invoke-CommandCapture -FilePath 'w32tm.exe' -ArgumentList '/query','/configuration'

    $parsed = [ordered]@{
        Source        = $null
        Stratum       = $null
        OffsetSeconds = $null
        LastSync      = $null
        Synchronized  = $null
        ClientType    = $null
        ClientNtpServer = $null
        PeerEntries   = @()
    }

    if ($status.Output) {
        foreach ($line in $status.Output) {
            if (-not $parsed.Source -and $line -match 'Source:\s*(?<value>.+)$') {
                $parsed.Source = $matches['value'].Trim()
            }
            if (-not $parsed.Stratum -and $line -match 'Stratum:\s*(?<value>\d+)') {
                $parsed.Stratum = [int]$matches['value']
            }
            if (-not $parsed.LastSync -and $line -match 'Last Successful Sync Time:\s*(?<value>.+)$') {
                $parsed.LastSync = $matches['value'].Trim()
            }
            if ($line -match '(?:Phase Offset|Clock Skew|Offset):\s*(?<value>[-+]?\d+(?:\.\d+)?)s') {
                $parsed.OffsetSeconds = [double]$matches['value']
            }
            if ($line -match 'Clock State:\s*(?<state>.+)$') {
                $state = $matches['state'].Trim()
                if ($state -match 'Not\s+synchroniz') {
                    $parsed.Synchronized = $false
                } elseif ($state) {
                    $parsed.Synchronized = $true
                }
            }
        }
    }

    if ($null -eq $parsed.Synchronized) {
        if ($status.Succeeded) {
            $parsed.Synchronized = $true
        } elseif ($status.Error -or ($status.Output -and ($status.Output -join ' ') -match 'not\s+synchroniz')) {
            $parsed.Synchronized = $false
        }
    }

    if ($config.Output) {
        $currentProvider = $null
        foreach ($line in $config.Output) {
            $trimmed = $line.Trim()
            if ($trimmed -match '^(?<provider>[A-Za-z0-9]+)\s*\(') {
                $currentProvider = $matches['provider']
                continue
            }
            if ($currentProvider -ne 'NtpClient') { continue }
            if (-not $parsed.ClientType -and $trimmed -match '^Type:\s*(?<value>\S+)') {
                $parsed.ClientType = $matches['value']
                continue
            }
            if ($trimmed -match '^NtpServer:\s*(?<value>.+)$') {
                $parsed.ClientNtpServer = $matches['value'].Trim()
                continue
            }
        }
    }

    if ($peers.Output) {
        $peerList = New-Object System.Collections.Generic.List[string]
        foreach ($line in $peers.Output) {
            if ($line -match '^Peer:\s*(?<value>.+)$') {
                $peerValue = $matches['value'].Trim()
                if ($peerValue) {
                    $null = $peerList.Add($peerValue)
                }
            }
        }
        $parsed.PeerEntries = $peerList.ToArray()
    }

    return [ordered]@{
        Status = $status
        Peers  = $peers
        Configuration = $config
        Parsed = $parsed
    }
}

function Get-KerberosInfo {
    $klist = Invoke-CommandCapture -FilePath 'klist.exe'

    $parsed = [ordered]@{
        HasTgt   = $false
        TgtRealm = $null
    }

    if ($klist.Output) {
        foreach ($line in $klist.Output) {
            if ($line -match 'krbtgt/(?<realm>[^\s]+)') {
                $parsed.HasTgt = $true
                $parsed.TgtRealm = $matches['realm']
                break
            }
        }
    }

    $startTime = (Get-Date).AddHours(-72)
    $kerberosEvents = [System.Collections.Generic.List[pscustomobject]]::new()
    try {
        $events = Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = @(4768, 4771, 4776); StartTime = $startTime } -ErrorAction Stop | Select-Object -First 200 -Property TimeCreated, Id, LevelDisplayName, Message
        if ($events) {
            foreach ($event in $events) {
                $kerberosEvents.Add([pscustomobject]@{
                    TimeCreated = $event.TimeCreated
                    Id          = $event.Id
                    Level       = $event.LevelDisplayName
                    Message     = $event.Message
                })
            }
        }
    } catch {
        $kerberosEvents = [System.Collections.Generic.List[pscustomobject]]::new()
        $kerberosEvents.Add([pscustomobject]@{ Error = $_.Exception.Message })
    }

    return [ordered]@{
        Klist  = $klist
        Parsed = $parsed
        Events = $kerberosEvents.ToArray()
    }
}

function Get-SecureChannelInfo {
    param(
        [string]$Domain
    )

    $secureChannel = [ordered]@{
        TestComputerSecureChannel = $null
        NltestScQuery             = $null
    }

    try {
        $result = Test-ComputerSecureChannel -Verbose:$false
        $secureChannel.TestComputerSecureChannel = [ordered]@{
            Succeeded = $true
            IsSecure  = [bool]$result
        }
    } catch {
        $secureChannel.TestComputerSecureChannel = [ordered]@{
            Succeeded = $false
            IsSecure  = $false
            Error     = $_.Exception.Message
        }
    }

    if ($Domain) {
        $secureChannel.NltestScQuery = Invoke-CommandCapture -FilePath 'nltest.exe' -ArgumentList "/sc_query:$Domain"
    }

    return $secureChannel
}

function Get-GpoInfo {
    $gpo = [ordered]@{
        GpResult = $null
        Events   = [System.Collections.Generic.List[pscustomobject]]::new()
    }

    $gpo.GpResult = Invoke-CommandCapture -FilePath 'gpresult.exe' -ArgumentList '/r','/scope','computer'

    $startTime = (Get-Date).AddHours(-72)
    try {
        $events = Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-GroupPolicy/Operational'; Id = @(1058, 1030); StartTime = $startTime } -ErrorAction Stop | Select-Object -First 200 -Property TimeCreated, Id, LevelDisplayName, Message
        foreach ($event in $events) {
            $gpo.Events.Add([pscustomobject]@{
                TimeCreated = $event.TimeCreated
                Id          = $event.Id
                Level       = $event.LevelDisplayName
                Message     = $event.Message
            })
        }
    } catch {
        $gpo.Events = @([ordered]@{ Error = $_.Exception.Message })
    }

    if ($gpo.Events -is [System.Collections.Generic.List[object]]) {
        $gpo.Events = $gpo.Events.ToArray()
    }

    return $gpo
}

function Get-OptionalContext {
    $context = [ordered]@{
        Site   = $null
        Trusts = $null
    }

    try {
        $context.Site = Invoke-CommandCapture -FilePath 'nltest.exe' -ArgumentList '/dsgetsite'
    } catch {
        $context.Site = [ordered]@{ Error = $_.Exception.Message }
    }

    try {
        $context.Trusts = Invoke-CommandCapture -FilePath 'nltest.exe' -ArgumentList '/domain_trusts'
    } catch {
        $context.Trusts = [ordered]@{ Error = $_.Exception.Message }
    }

    return $context
}

function Invoke-Main {
    $domainStatus = Get-DomainStatus
    $payload = [ordered]@{
        DomainStatus = $domainStatus
        Discovery    = $null
        Reachability = [ordered]@{ Tests = @() }
        Sysvol       = [ordered]@{ Tests = @() }
        Time         = $null
        Kerberos     = $null
        Secure       = $null
        Gpo          = $null
        Context      = $null
        Skipped      = $false
        SkipReason   = $null
    }

    if (-not $domainStatus.DomainJoined) {
        $payload.Skipped = $true
        $payload.SkipReason = 'Device not domain joined'
    } else {
        $discovery = Get-DomainDiscovery -Domain $domainStatus.Domain -Forest $domainStatus.Forest
        $payload.Discovery = $discovery
        if ($discovery.Forest) {
            $payload.DomainStatus.Forest = $discovery.Forest
        } elseif (-not $domainStatus.Forest -and $discovery -and $discovery.SrvLookups.Contains('ldap-forest')) {
            $forestLookup = $discovery.SrvLookups['ldap-forest']
            if ($forestLookup -and $forestLookup.Query) {
                $payload.DomainStatus.Forest = $forestLookup.Query -replace '^_ldap._tcp.dc._msdcs.', ''
            }
        }

        $reachability = Test-DomainControllerReachability -Candidates $discovery.Candidates
        $payload.Reachability = [ordered]@{ Tests = $reachability }

        $sysvol = Test-DomainShares -Candidates $discovery.Candidates
        $payload.Sysvol = [ordered]@{ Tests = $sysvol }

        $payload.Time = Get-TimeServiceStatus
        $payload.Kerberos = Get-KerberosInfo
        $payload.Secure = Get-SecureChannelInfo -Domain $payload.DomainStatus.Domain
        $payload.Gpo = Get-GpoInfo
        $payload.Context = Get-OptionalContext
    }

    $result = New-CollectorMetadata -Payload $payload
    $outputPath = Export-CollectorResult -OutputDirectory $OutputDirectory -FileName 'ad-health.json' -Data $result -Depth 6
    Write-Output $outputPath
}

Invoke-Main
