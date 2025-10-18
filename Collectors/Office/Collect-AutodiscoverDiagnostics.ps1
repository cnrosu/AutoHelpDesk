<#!
.SYNOPSIS
    Collects per-domain Autodiscover DNS posture for Exchange Online onboarding parity with AutoL1 heuristics.
.DESCRIPTION
    Enumerates candidate primary SMTP/AD domains from environment and identity telemetry, then resolves
    Autodiscover-related records for each domain to power granular scoring in the analyzer stack.
#>
[CmdletBinding()]
param(
    [Parameter()]
    [string]$OutputDirectory = (Join-Path -Path (Split-Path -Parent $PSCommandPath) -ChildPath '..\output')
)

. (Join-Path -Path $PSScriptRoot -ChildPath '..\CollectorCommon.ps1')

$PSModuleAutoloadingPreference = 'None'
$dnsClientImported = $false
$dnsClientError = $null
try {
    Import-Module DnsClient -ErrorAction Stop
    $dnsClientImported = $true
} catch {
    $dnsClientError = $_.Exception.Message
}

$resolveDnsNameAvailable = $false
if (Get-Command -Name 'Resolve-DnsName' -ErrorAction SilentlyContinue) {
    $resolveDnsNameAvailable = $true
} elseif (-not $dnsClientError) {
    $dnsClientError = 'Resolve-DnsName command unavailable.'
}

$nslookupCommand = Get-Command -Name 'nslookup.exe' -ErrorAction SilentlyContinue
$nslookupAvailable = [bool]$nslookupCommand

$dnsResolveOptions = [pscustomobject]@{
    ResolveDnsNameAvailable = $resolveDnsNameAvailable
    UseNslookupFallback     = (-not $resolveDnsNameAvailable -and $nslookupAvailable)
    NslookupPath            = if ($nslookupCommand) { $nslookupCommand.Source } else { $null }
    ResolveFailureMessage   = if ($dnsClientError) { $dnsClientError } elseif (-not $resolveDnsNameAvailable) { 'Resolve-DnsName unavailable.' } else { $null }
    ModuleImported          = $dnsClientImported
}

function Get-CollectorStringValues {
    param([object]$Value)

    if ($null -eq $Value) { return @() }

    if ($Value -is [System.Collections.IEnumerable] -and -not ($Value -is [string])) {
        $items = New-Object System.Collections.Generic.List[string]
        foreach ($element in $Value) {
            if ($null -eq $element) { continue }
            if ($element -is [string]) {
                if ($element) { $items.Add($element) | Out-Null }
                continue
            }

            try {
                $items.Add([string]$element) | Out-Null
            } catch {
            }
        }

        return @($items | Where-Object { $_ })
    }

    try {
        $text = [string]$Value
        if ($text) { return @($text) }
    } catch {
    }

    return @()
}

function Get-IdentityEmailAddresses {
    $addresses = New-Object System.Collections.Generic.HashSet[string]([System.StringComparer]::OrdinalIgnoreCase)

    foreach ($candidate in @($env:USERPRINCIPALNAME)) {
        if ([string]::IsNullOrWhiteSpace($candidate)) { continue }
        $trimmed = $candidate.Trim()
        if (-not $trimmed) { continue }
        if ($trimmed -match '@') {
            $addresses.Add($trimmed) | Out-Null
        }
    }

    try {
        $identityRoot = 'HKCU:\Software\Microsoft\Office\16.0\Common\Identity'
        if (Test-Path -Path $identityRoot) {
            $rootProperties = Get-ItemProperty -Path $identityRoot -ErrorAction Stop
            foreach ($prop in $rootProperties.PSObject.Properties) {
                foreach ($value in (Get-CollectorStringValues -Value $prop.Value)) {
                    if ([string]::IsNullOrWhiteSpace($value)) { continue }
                    $normalized = $value.Trim()
                    if (-not $normalized) { continue }
                    if ($normalized -match '^(?i)(smtp:)?[^@\s]+@[^@\s]+$') {
                        $addresses.Add(($normalized -replace '^(?i)smtp:', '')) | Out-Null
                    }
                }
            }

            $identitiesPath = Join-Path -Path $identityRoot -ChildPath 'Identities'
            if (Test-Path -Path $identitiesPath) {
                $identityKeys = Get-ChildItem -Path $identitiesPath -ErrorAction Stop
                foreach ($key in $identityKeys) {
                    try {
                        $props = Get-ItemProperty -Path $key.PSPath -ErrorAction Stop
                        foreach ($prop in $props.PSObject.Properties) {
                            foreach ($value in (Get-CollectorStringValues -Value $prop.Value)) {
                                if ([string]::IsNullOrWhiteSpace($value)) { continue }
                                $normalized = $value.Trim()
                                if (-not $normalized) { continue }
                                if ($normalized -match '^(?i)(smtp:)?[^@\s]+@[^@\s]+$') {
                                    $addresses.Add(($normalized -replace '^(?i)smtp:', '')) | Out-Null
                                }
                            }
                        }
                    } catch {
                    }
                }
            }
        }
    } catch {
    }

    return @($addresses | Where-Object { $_ })
}

function Test-AutodiscoverDomainName {
    param([string]$Domain)

    if ([string]::IsNullOrWhiteSpace($Domain)) { return $false }

    $candidate = $Domain.Trim()
    if (-not $candidate) { return $false }

    if ($candidate.EndsWith('.')) {
        $candidate = $candidate.TrimEnd('.')
        if (-not $candidate) { return $false }
    }

    if ($candidate.Length -gt 253) { return $false }

    $pattern = '^(?i)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$'
    return ($candidate -match $pattern)
}

function Get-CandidateDomains {
    param([string[]]$EmailAddresses)

    $domains = New-Object System.Collections.Generic.HashSet[string]([System.StringComparer]::OrdinalIgnoreCase)
    $addresses = if ($EmailAddresses) { $EmailAddresses } else { Get-IdentityEmailAddresses }

    foreach ($address in $addresses) {
        if (-not $address) { continue }
        $parts = $address.Split('@')
        if ($parts.Count -lt 2) { continue }
        $domain = $parts[-1].Trim()
        if (-not $domain) { continue }
        if ($domain -notmatch '\.') { continue }
        if (-not (Test-AutodiscoverDomainName -Domain $domain)) { continue }
        if ($domain.EndsWith('.')) { $domain = $domain.TrimEnd('.') }
        if (-not $domain) { continue }
        $domains.Add($domain) | Out-Null
    }

    return @($domains | Where-Object { $_ })
}

$domainLookupScript = {
    param(
        [Parameter(Mandatory)][string]$Domain,
        [Parameter()][psobject]$Options
    )

    $PSModuleAutoloadingPreference = 'None'

    function New-LookupEntry {
        param(
            [Parameter(Mandatory)][string]$Label,
            [Parameter(Mandatory)][string]$Query,
            [Parameter(Mandatory)][string]$Type
        )

        return [pscustomobject][ordered]@{
            Label     = $Label
            Query     = $Query
            Type      = $Type
            Success   = $false
            Targets   = @()
            Addresses = @()
            Records   = @()
            Strings   = @()
            Error     = $null
            Source    = $null
        }
    }

    function Set-LookupOutcome {
        param(
            [Parameter(Mandatory)][pscustomobject]$Entry,
            [Parameter(Mandatory)][string]$Type,
            [Parameter()][object[]]$Data,
            [string]$ErrorMessage
        )

        $typeUpper = $Type.ToUpperInvariant()
        $recordsCount = 0

        switch ($typeUpper) {
            'CNAME' {
                $targets = @()
                foreach ($item in ($Data | Where-Object { $_ })) {
                    if ($item -is [string]) {
                        $targets += $item
                    } elseif ($item) {
                        $targets += [string]$item
                    }
                }
                $Entry.Targets = @($targets | Where-Object { $_ })
                $recordsCount = $Entry.Targets.Count
            }
            'A' {
                $addresses = @()
                foreach ($item in ($Data | Where-Object { $_ })) {
                    $addresses += [string]$item
                }
                $Entry.Addresses = @($addresses | Where-Object { $_ })
                $recordsCount = $Entry.Addresses.Count
            }
            'AAAA' {
                $addresses = @()
                foreach ($item in ($Data | Where-Object { $_ })) {
                    $addresses += [string]$item
                }
                $Entry.Addresses = @($addresses | Where-Object { $_ })
                $recordsCount = $Entry.Addresses.Count
            }
            'SRV' {
                $records = @()
                foreach ($item in ($Data | Where-Object { $_ })) {
                    if ($item -is [psobject]) {
                        $records += [pscustomobject]@{
                            Priority = $item.Priority
                            Weight   = $item.Weight
                            Port     = $item.Port
                            Target   = $item.Target
                        }
                    } else {
                        $records += $item
                    }
                }
                $Entry.Records = @($records | Where-Object { $_ })
                $Entry.Targets = @($Entry.Records | ForEach-Object { $_.Target } | Where-Object { $_ })
                $recordsCount = $Entry.Records.Count
            }
            'MX' {
                $records = @()
                foreach ($item in ($Data | Where-Object { $_ })) {
                    if ($item -is [psobject]) {
                        $records += [pscustomobject]@{
                            Preference = $item.Preference
                            Target     = $item.Target
                        }
                    } else {
                        $records += $item
                    }
                }
                $Entry.Records = @($records | Where-Object { $_ })
                $Entry.Targets = @($Entry.Records | ForEach-Object { $_.Target } | Where-Object { $_ })
                $recordsCount = $Entry.Records.Count
            }
            default {
                $Entry.Records = @($Data | Where-Object { $_ })
                $recordsCount = $Entry.Records.Count
            }
        }

        if ($recordsCount -gt 0) {
            $Entry.Success = $true
            $Entry.Error = $null
            return
        }

        $Entry.Success = $false
        if ([string]::IsNullOrWhiteSpace($ErrorMessage)) {
            $Entry.Error = "No $typeUpper records"
        } else {
            $Entry.Error = $ErrorMessage
        }
    }

    function Invoke-ResolveDnsRecord {
        param(
            [Parameter(Mandatory)][pscustomobject]$RecordDefinition,
            [Parameter(Mandatory)][pscustomobject]$Entry
        )

        $typeUpper = $RecordDefinition.Type.ToUpperInvariant()
        try {
            $response = Resolve-DnsName -Type $RecordDefinition.Type -Name $RecordDefinition.Name -DnsOnly -ErrorAction Stop
            $Entry.Source = 'Resolve-DnsName'
            $items = if ($null -eq $response) { @() } else { @($response) }
            switch ($typeUpper) {
                'CNAME' {
                    $targets = foreach ($item in $items) { $item.NameHost }
                    Set-LookupOutcome -Entry $Entry -Type $RecordDefinition.Type -Data $targets -ErrorMessage $null
                }
                'A' {
                    $addresses = foreach ($item in $items) { $item.IPAddress }
                    Set-LookupOutcome -Entry $Entry -Type $RecordDefinition.Type -Data $addresses -ErrorMessage $null
                }
                'AAAA' {
                    $addresses = foreach ($item in $items) { $item.IPAddress }
                    Set-LookupOutcome -Entry $Entry -Type $RecordDefinition.Type -Data $addresses -ErrorMessage $null
                }
                'SRV' {
                    $records = foreach ($item in $items) {
                        [pscustomobject]@{
                            Priority = $item.Priority
                            Weight   = $item.Weight
                            Port     = $item.Port
                            Target   = $item.NameTarget
                        }
                    }
                    Set-LookupOutcome -Entry $Entry -Type $RecordDefinition.Type -Data $records -ErrorMessage $null
                }
                'MX' {
                    $records = foreach ($item in $items) {
                        [pscustomobject]@{
                            Preference = $item.Preference
                            Target     = $item.NameExchange
                        }
                    }
                    Set-LookupOutcome -Entry $Entry -Type $RecordDefinition.Type -Data $records -ErrorMessage $null
                }
                default {
                    Set-LookupOutcome -Entry $Entry -Type $RecordDefinition.Type -Data $items -ErrorMessage $null
                }
            }
        } catch {
            $Entry.Error = $_.Exception.Message
        }

        return $Entry
    }

    function Invoke-NslookupRecord {
        param(
            [Parameter(Mandatory)][pscustomobject]$RecordDefinition,
            [Parameter(Mandatory)][pscustomobject]$Entry,
            [Parameter()][psobject]$Options
        )

        if (-not $Options -or [string]::IsNullOrWhiteSpace($Options.NslookupPath)) {
            if (-not $Entry.Error) {
                $Entry.Error = 'nslookup.exe unavailable.'
            }
            return $Entry
        }

        $typeUpper = $RecordDefinition.Type.ToUpperInvariant()
        $output = @()
        try {
            $arguments = @("-type=$($RecordDefinition.Type)", $RecordDefinition.Name)
            $raw = & $Options.NslookupPath @arguments 2>&1
            foreach ($line in $raw) {
                if ($null -ne $line) {
                    $output += [string]$line
                }
            }
        } catch {
            $Entry.Error = $_.Exception.Message
            return $Entry
        }

        $trimmed = @()
        foreach ($line in $output) {
            if ($null -ne $line) {
                $trimmed += $line.Trim()
            }
        }

        if ($trimmed | Where-Object { $_ -match '(?i)non-existent domain' -or $_ -match '(?i)can''t find' }) {
            $Entry.Error = 'DNS name does not exist.'
            Set-LookupOutcome -Entry $Entry -Type $RecordDefinition.Type -Data @() -ErrorMessage $Entry.Error
            return $Entry
        }

        switch ($typeUpper) {
            'CNAME' {
                $targets = @()
                foreach ($line in $trimmed) {
                    if ($line -match '(?i)canonical name =\s*(.+)$') {
                        $target = $matches[1].Trim()
                        if ($target.EndsWith('.')) { $target = $target.TrimEnd('.') }
                        if ($target) { $targets += $target }
                    }
                }
                Set-LookupOutcome -Entry $Entry -Type $RecordDefinition.Type -Data $targets -ErrorMessage $Entry.Error
            }
            'A' {
                $data = @()
                $answerStarted = $false
                foreach ($line in $output) {
                    $trim = $line.Trim()
                    if (-not $answerStarted -and $trim -match '(?i)^Name:\s*(.+)$') {
                        $nameValue = $matches[1].Trim()
                        if ($nameValue.EndsWith('.')) { $nameValue = $nameValue.TrimEnd('.') }
                        if ($nameValue.ToLowerInvariant() -eq $RecordDefinition.Name.ToLowerInvariant()) {
                            $answerStarted = $true
                        }
                        continue
                    }

                    if (-not $answerStarted) { continue }

                    if ($trim -match '(?i)^Addresses?:\s*(.+)$') {
                        $values = $matches[1].Split(' ', [System.StringSplitOptions]::RemoveEmptyEntries)
                        foreach ($value in $values) {
                            if ($value) { $data += $value }
                        }
                    } elseif ($trim -match '(?i)^Address:\s*(.+)$') {
                        $value = $matches[1].Trim()
                        if ($value) { $data += $value }
                    }
                }
                Set-LookupOutcome -Entry $Entry -Type $RecordDefinition.Type -Data $data -ErrorMessage $Entry.Error
            }
            'AAAA' {
                $data = @()
                $answerStarted = $false
                foreach ($line in $output) {
                    $trim = $line.Trim()
                    if (-not $answerStarted -and $trim -match '(?i)^Name:\s*(.+)$') {
                        $nameValue = $matches[1].Trim()
                        if ($nameValue.EndsWith('.')) { $nameValue = $nameValue.TrimEnd('.') }
                        if ($nameValue.ToLowerInvariant() -eq $RecordDefinition.Name.ToLowerInvariant()) {
                            $answerStarted = $true
                        }
                        continue
                    }

                    if (-not $answerStarted) { continue }

                    if ($trim -match '(?i)^Addresses?:\s*(.+)$') {
                        $values = $matches[1].Split(' ', [System.StringSplitOptions]::RemoveEmptyEntries)
                        foreach ($value in $values) {
                            if ($value) { $data += $value }
                        }
                    } elseif ($trim -match '(?i)^Address:\s*(.+)$') {
                        $value = $matches[1].Trim()
                        if ($value) { $data += $value }
                    }
                }
                Set-LookupOutcome -Entry $Entry -Type $RecordDefinition.Type -Data $data -ErrorMessage $Entry.Error
            }
            'SRV' {
                $records = [System.Collections.Generic.List[object]]::new()
                $current = $null
                foreach ($line in $trimmed) {
                    if ($line -match '(?i)SRV service location') {
                        if ($current) { $records.Add($current) | Out-Null }
                        $current = [pscustomobject]@{ Priority = $null; Weight = $null; Port = $null; Target = $null }
                        continue
                    }

                    if (-not $current) { continue }

                    if ($line -match '(?i)^priority\s*=\s*(\d+)') {
                        $current.Priority = [int]$matches[1]
                        continue
                    }
                    if ($line -match '(?i)^weight\s*=\s*(\d+)') {
                        $current.Weight = [int]$matches[1]
                        continue
                    }
                    if ($line -match '(?i)^port\s*=\s*(\d+)') {
                        $current.Port = [int]$matches[1]
                        continue
                    }
                    if ($line -match '(?i)svr hostname =\s*(.+)$') {
                        $target = $matches[1].Trim()
                        if ($target.EndsWith('.')) { $target = $target.TrimEnd('.') }
                        $current.Target = $target
                        continue
                    }
                }

                if ($current) { $records.Add($current) | Out-Null }
                Set-LookupOutcome -Entry $Entry -Type $RecordDefinition.Type -Data $records.ToArray() -ErrorMessage $Entry.Error
            }
            'MX' {
                $records = [System.Collections.Generic.List[object]]::new()
                $pendingPreference = $null
                foreach ($line in $trimmed) {
                    if ($line -match '(?i)^preference\s*=\s*(\d+),\s*mail exchanger\s*=\s*(.+)$') {
                        $target = $matches[2].Trim()
                        if ($target.EndsWith('.')) { $target = $target.TrimEnd('.') }
                        $records.Add([pscustomobject]@{
                            Preference = [int]$matches[1]
                            Target     = $target
                        }) | Out-Null
                        $pendingPreference = $null
                        continue
                    }

                    if ($line -match '(?i)^preference\s*=\s*(\d+)$') {
                        $pendingPreference = [int]$matches[1]
                        continue
                    }

                    if ($line -match '(?i)mail exchanger\s*=\s*(.+)$') {
                        $target = $matches[1].Trim()
                        if ($target.EndsWith('.')) { $target = $target.TrimEnd('.') }
                        $pref = if ($null -ne $pendingPreference) { $pendingPreference } else { 0 }
                        $records.Add([pscustomobject]@{
                            Preference = $pref
                            Target     = $target
                        }) | Out-Null
                        $pendingPreference = $null
                    }
                }

                Set-LookupOutcome -Entry $Entry -Type $RecordDefinition.Type -Data $records.ToArray() -ErrorMessage $Entry.Error
            }
            default {
                Set-LookupOutcome -Entry $Entry -Type $RecordDefinition.Type -Data @() -ErrorMessage $Entry.Error
            }
        }

        if ($Entry.Success) {
            $Entry.Source = 'nslookup'
            $Entry.Error = $null
        }

        return $Entry
    }

    function Invoke-AutodiscoverHttpProbe {
        param(
            [Parameter(Mandatory)][string]$Domain,
            [Parameter()][int]$TimeoutSeconds = 10
        )

        $url = "https://autodiscover.$Domain/autodiscover/autodiscover.xml"
        $result = [pscustomobject][ordered]@{
            Url        = $url
            Method     = 'HEAD'
            StatusCode = $null
            Success    = $false
            Error      = $null
            Location   = $null
        }

        $handler = $null
        $client = $null
        $request = $null
        $response = $null

        try {
            $handler = [System.Net.Http.HttpClientHandler]::new()
            $handler.AllowAutoRedirect = $false
            $client = [System.Net.Http.HttpClient]::new($handler)
            $client.Timeout = [System.TimeSpan]::FromSeconds($TimeoutSeconds)
            $request = [System.Net.Http.HttpRequestMessage]::new([System.Net.Http.HttpMethod]::Head, $url)
            $response = $client.SendAsync($request).GetAwaiter().GetResult()
            $statusCode = [int]$response.StatusCode
            $result.StatusCode = $statusCode
            if ($response.Headers.Location) {
                try {
                    $result.Location = $response.Headers.Location.OriginalString
                } catch {
                    $result.Location = $response.Headers.Location.ToString()
                }
            }

            if (($statusCode -ge 200 -and $statusCode -lt 400) -or $statusCode -eq 401) {
                $result.Success = $true
            } else {
                $result.Error = "HTTP status $statusCode"
            }
        } catch {
            $result.Error = $_.Exception.Message
        } finally {
            if ($response) { $response.Dispose() }
            if ($request) { $request.Dispose() }
            if ($client) { $client.Dispose() }
            if ($handler) { $handler.Dispose() }
        }

        return $result
    }

    $resolveCommand = Get-Command -Name 'Resolve-DnsName' -ErrorAction SilentlyContinue
    $resolveAvailable = [bool]$resolveCommand
    if (-not $resolveAvailable -and $Options -and $Options.ModuleImported) {
        try {
            Import-Module DnsClient -ErrorAction Stop
            $resolveCommand = Get-Command -Name 'Resolve-DnsName' -ErrorAction SilentlyContinue
            $resolveAvailable = [bool]$resolveCommand
        } catch {
            if ($Options -and -not $Options.ResolveFailureMessage) {
                $Options | Add-Member -NotePropertyName 'ResolveFailureMessage' -NotePropertyValue $_.Exception.Message -Force
            }
        }
    }

    $records = @(
        @{ Label = 'Autodiscover';     Name = "autodiscover.$Domain";        Type = 'CNAME' },
        @{ Label = 'AutodiscoverA';    Name = "autodiscover.$Domain";        Type = 'A' },
        @{ Label = 'AutodiscoverAAAA'; Name = "autodiscover.$Domain";        Type = 'AAAA' },
        @{ Label = 'AutodiscoverSrv';  Name = "_autodiscover._tcp.$Domain";  Type = 'SRV' },
        @{ Label = 'Mx';               Name = $Domain;                        Type = 'MX' }
    )

    $results = [System.Collections.Generic.List[object]]::new()
    foreach ($record in $records) {
        $entry = New-LookupEntry -Label $record.Label -Query $record.Name -Type $record.Type
        if ($resolveAvailable) {
            $entry = Invoke-ResolveDnsRecord -RecordDefinition ([pscustomobject]$record) -Entry $entry
        } else {
            $entry.Error = if ($Options.ResolveFailureMessage) { $Options.ResolveFailureMessage } else { 'Resolve-DnsName unavailable.' }
        }

        if (-not $resolveAvailable -and $Options.UseNslookupFallback) {
            $entry = Invoke-NslookupRecord -RecordDefinition ([pscustomobject]$record) -Entry $entry -Options $Options
        }

        if (-not $entry.Success -and -not $entry.Error) {
            Set-LookupOutcome -Entry $entry -Type $record.Type -Data @() -ErrorMessage $entry.Error
        }

        $results.Add($entry) | Out-Null
    }

    $httpProbe = Invoke-AutodiscoverHttpProbe -Domain $Domain

    return [pscustomobject]@{
        Domain    = $Domain
        Lookups   = $results.ToArray()
        HttpProbe = $httpProbe
    }
}

$domainLookupWrapper = {
    param(
        [Parameter(Mandatory)][scriptblock]$Worker,
        [Parameter(Mandatory)][string]$Domain,
        [Parameter()][psobject]$Options
    )

    & $Worker $Domain $Options
}

function Invoke-Main {
    $emailAddresses = Get-IdentityEmailAddresses
    $domains = Get-CandidateDomains -EmailAddresses $emailAddresses
    $results = [System.Collections.Generic.List[object]]::new()

    if ($domains.Count -gt 0) {
        $maxThreads = [Math]::Max(1, [Math]::Min($domains.Count, [Environment]::ProcessorCount))
        $pool = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspacePool(1, $maxThreads)
        $pool.ApartmentState = 'MTA'
        $pool.Open()

        $workItems = [System.Collections.Generic.List[object]]::new()
        foreach ($domain in $domains) {
            $ps = [System.Management.Automation.PowerShell]::Create()
            $ps.RunspacePool = $pool
            $null = $ps.AddScript($domainLookupWrapper).AddArgument($domainLookupScript).AddArgument($domain).AddArgument($dnsResolveOptions)
            $async = $ps.BeginInvoke()
            $workItems.Add([pscustomobject]@{
                Domain     = $domain
                PowerShell = $ps
                Async      = $async
            }) | Out-Null
        }

        $domainTimeoutSeconds = 60
        $domainTimeout = [TimeSpan]::FromSeconds($domainTimeoutSeconds)

        foreach ($work in $workItems) {
            $endInvokeCompleted = $false
            $timeoutTriggered = $false
            try {
                $waitHandle = $work.Async.AsyncWaitHandle
                $completed = $true
                if ($waitHandle) {
                    $completed = $waitHandle.WaitOne($domainTimeout)
                }

                if (-not $completed) {
                    $timeoutTriggered = $true
                    try { $work.PowerShell.Stop() } catch { }
                    throw [System.TimeoutException]::new(("Autodiscover DNS lookups for {0} exceeded the allotted {1} seconds." -f $work.Domain, $domainTimeoutSeconds))
                }

                $result = $work.PowerShell.EndInvoke($work.Async)
                $endInvokeCompleted = $true
                if ($result) {
                    foreach ($item in $result) {
                        if ($item) { $results.Add($item) | Out-Null }
                    }
                }
            } catch {
                $message = $null
                if ($_.Exception -and $_.Exception.Message) {
                    $message = [string]$_.Exception.Message
                } else {
                    $message = [string]$_
                }

                if ($timeoutTriggered -and -not $message) {
                    $message = "Autodiscover DNS lookups for $($work.Domain) exceeded the allotted $domainTimeoutSeconds seconds."
                }

                $results.Add([pscustomobject]@{
                    Domain    = $work.Domain
                    Lookups   = @()
                    HttpProbe = [pscustomobject]@{
                        Url        = "https://autodiscover.$($work.Domain)/autodiscover/autodiscover.xml"
                        Method     = 'HEAD'
                        StatusCode = $null
                        Success    = $false
                        Error      = $message
                        Location   = $null
                    }
                    Error     = $message
                }) | Out-Null
            } finally {
                if (-not $endInvokeCompleted) {
                    try { $null = $work.PowerShell.EndInvoke($work.Async) } catch { }
                }

                if ($work.Async.AsyncWaitHandle) {
                    try { $work.Async.AsyncWaitHandle.Dispose() } catch { }
                }

                try { $work.PowerShell.Dispose() } catch { }
            }
        }

        $pool.Close()
        $pool.Dispose()
    }

    $payload = [ordered]@{
        CollectedAtUtc = (Get-Date).ToUniversalTime().ToString('o')
        Domains        = $domains
        Addresses      = $emailAddresses
        Results        = $results.ToArray()
        Resolver       = [ordered]@{
            ResolveDnsNameAvailable = [bool]$dnsResolveOptions.ResolveDnsNameAvailable
            DnsClientImported       = [bool]$dnsResolveOptions.ModuleImported
            UseNslookupFallback     = [bool]$dnsResolveOptions.UseNslookupFallback
            ResolveFailureMessage   = $dnsResolveOptions.ResolveFailureMessage
        }
    }

    $metadata = New-CollectorMetadata -Payload $payload
    $outputPath = Export-CollectorResult -OutputDirectory $OutputDirectory -FileName 'autodiscover-dns.json' -Data $metadata -Depth 6
    Write-Output $outputPath
}

Invoke-Main
