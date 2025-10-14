<#!
.SYNOPSIS
    Collects DNS diagnostic data including resolution tests and connectivity checks.
#>
[CmdletBinding()]
param(
    [Parameter()]
    [string]$OutputDirectory = (Join-Path -Path (Split-Path -Parent $PSCommandPath) -ChildPath '..\\output')
)

. (Join-Path -Path $PSScriptRoot -ChildPath '..\\CollectorCommon.ps1')

function Invoke-Parallel {
    param(
        [Parameter(Mandatory)]
        [ScriptBlock]$ScriptBlock,

        [Parameter(Mandatory)]
        [object[]]$InputObjects,

        [int]$ThrottleLimit = [Math]::Min([Environment]::ProcessorCount, [Math]::Max(1, $InputObjects.Count))
    )

    if ($InputObjects.Count -eq 0) {
        return @()
    }

    if ($InputObjects.Count -le 1 -or $ThrottleLimit -le 1) {
        $sequentialResults = [System.Collections.Generic.List[object]]::new()
        foreach ($inputObject in $InputObjects) {
            $result = & $ScriptBlock $inputObject
            if ($null -ne $result) {
                if ($result -is [System.Collections.IEnumerable] -and -not ($result -is [string])) {
                    foreach ($item in $result) {
                        $null = $sequentialResults.Add($item)
                    }
                } else {
                    $null = $sequentialResults.Add($result)
                }
            }
        }

        return $sequentialResults.ToArray()
    }

    $runspacePool = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspacePool(1, $ThrottleLimit)
    $runspacePool.ApartmentState = 'MTA'
    $runspacePool.Open()

    $jobs = foreach ($inputObject in $InputObjects) {
        $psInstance = [System.Management.Automation.PowerShell]::Create()
        $psInstance.RunspacePool = $runspacePool
        $null = $psInstance.AddScript($ScriptBlock.ToString(), $true).AddArgument($inputObject)
        [PSCustomObject]@{
            PowerShell = $psInstance
            Handle     = $psInstance.BeginInvoke()
        }
    }

    $outputs = [System.Collections.Generic.List[object]]::new()

    foreach ($job in $jobs) {
        try {
            $result = $job.PowerShell.EndInvoke($job.Handle)
            if ($null -ne $result) {
                if ($result -is [System.Collections.IEnumerable] -and -not ($result -is [string])) {
                    foreach ($item in $result) {
                        $null = $outputs.Add($item)
                    }
                } else {
                    $null = $outputs.Add($result)
                }
            }
        } finally {
            $job.PowerShell.Dispose()
        }
    }

    $runspacePool.Close()
    $runspacePool.Dispose()

    return $outputs.ToArray()
}

function Test-DnsResolution {
    param(
        [string[]]$Names = @('www.microsoft.com','outlook.office365.com','autodiscover.outlook.com')
    )

    if (-not $Names -or $Names.Count -eq 0) {
        return @()
    }

    $queries = Invoke-Parallel -InputObjects $Names -ScriptBlock {
        param($Name)

        try {
            $records = Resolve-DnsName -Name $Name -ErrorAction Stop
            return [PSCustomObject]@{
                Name    = $Name
                Success = $true
                Records = $records | Select-Object Name, Type, IPAddress
            }
        } catch {
            return [PSCustomObject]@{
                Name    = $Name
                Success = $false
                Error   = $_.Exception.Message
            }
        }
    }

    return foreach ($name in $Names) {
        $queries | Where-Object { $_.Name -eq $name } | Select-Object -First 1
    }
}

function Trace-NetworkPath {
    param(
        [string]$Target = 'outlook.office365.com',
        [int]$MaxHops = 20,
        [int]$TimeoutMilliseconds = 750
    )

    $effectiveMaxHops = if ($MaxHops -gt 0) { $MaxHops } else { 20 }
    $effectiveTimeout = if ($TimeoutMilliseconds -gt 0) { $TimeoutMilliseconds } else { 750 }
    $arguments = @('-d', '-h', $effectiveMaxHops, '-w', $effectiveTimeout, $Target)

    return Invoke-CollectorNativeCommand -FilePath 'tracert.exe' -ArgumentList $arguments -ErrorMetadata @{ Target = $Target }
}

function Test-Latency {
    param([string]$Target = '8.8.8.8')

    $attempts = 3
    $summary = [ordered]@{
        Target            = $Target
        Attempts          = $attempts
        SuccessCount      = 0
        FailureCount      = 0
        Status            = 'Unknown'
        AverageLatencyMs  = $null
        MinimumLatencyMs  = $null
        MaximumLatencyMs  = $null
        AttemptsDetail    = @()
    }

    $testConnectionCmd = Get-Command -Name 'Test-Connection' -ErrorAction SilentlyContinue

    if ($null -ne $testConnectionCmd) {
        $attemptDetails = [System.Collections.Generic.List[pscustomobject]]::new()
        for ($i = 1; $i -le $attempts; $i++) {
            try {
                $reply = Test-Connection -ComputerName $Target -Count 1 -ErrorAction Stop
                $latency = $reply | Select-Object -First 1 -ExpandProperty ResponseTime
                $null = $attemptDetails.Add([PSCustomObject]@{
                    Attempt   = $i
                    Success   = $true
                    LatencyMs = $latency
                })
            } catch {
                $null = $attemptDetails.Add([PSCustomObject]@{
                    Attempt = $i
                    Success = $false
                    Error   = $_.Exception.Message
                })
            }
        }

        $attemptDetailsArray = $attemptDetails.ToArray()
        $summary.AttemptsDetail = $attemptDetailsArray
        $summary.SuccessCount = ($attemptDetailsArray | Where-Object { $_.Success }).Count
        $summary.FailureCount = $attempts - $summary.SuccessCount

        if ($summary.SuccessCount -gt 0) {
            $latencies = $attemptDetailsArray | Where-Object { $_.Success } | Select-Object -ExpandProperty LatencyMs
            $measure = $latencies | Measure-Object -Average -Minimum -Maximum
            $summary.AverageLatencyMs = [Math]::Round($measure.Average, 2)
            $summary.MinimumLatencyMs = $measure.Minimum
            $summary.MaximumLatencyMs = $measure.Maximum
        }

        $summary.Status = if ($summary.SuccessCount -eq $attempts) {
            'Success'
        } elseif ($summary.SuccessCount -gt 0) {
            'Partial'
        } else {
            'Failed'
        }

        return [PSCustomObject]$summary
    }

    $pingOutput = Invoke-CollectorNativeCommand -FilePath 'ping.exe' -ArgumentList @('-n', $attempts, $Target) -ErrorMetadata @{ Target = $Target }

    if ($pingOutput -isnot [System.Array]) {
        return $pingOutput
    }

    $summary.AttemptsDetail = $pingOutput

    $packetLine = $pingOutput | Where-Object { $_ -match 'Packets: Sent = (\d+), Received = (\d+), Lost = (\d+)' } | Select-Object -Last 1
    if ($packetLine) {
        $packetMatch = [regex]::Match($packetLine, 'Packets: Sent = (\d+), Received = (\d+), Lost = (\d+)')
        if ($packetMatch.Success) {
            $summary.Attempts = [int]$packetMatch.Groups[1].Value
            $summary.SuccessCount = [int]$packetMatch.Groups[2].Value
            $summary.FailureCount = [int]$packetMatch.Groups[3].Value
        }
    } else {
        $summary.SuccessCount = 0
        $summary.FailureCount = $attempts
    }

    $latencyLine = $pingOutput | Where-Object { $_ -match 'Minimum = (\d+)ms, Maximum = (\d+)ms, Average = (\d+)ms' } | Select-Object -Last 1
    if ($latencyLine) {
        $latencyMatch = [regex]::Match($latencyLine, 'Minimum = (\d+)ms, Maximum = (\d+)ms, Average = (\d+)ms')
        if ($latencyMatch.Success) {
            $summary.MinimumLatencyMs = [int]$latencyMatch.Groups[1].Value
            $summary.MaximumLatencyMs = [int]$latencyMatch.Groups[2].Value
            $summary.AverageLatencyMs = [int]$latencyMatch.Groups[3].Value
        }
    }

    $summary.Status = if ($summary.SuccessCount -eq $summary.Attempts) {
        'Success'
    } elseif ($summary.SuccessCount -gt 0) {
        'Partial'
    } else {
        'Failed'
    }

    return [PSCustomObject]$summary
}

function Resolve-AutodiscoverRecords {
    param(
        [string[]]$Domains = @('autodiscover', 'enterpriseenrollment', 'enterpriseregistration')
    )

    if (-not $Domains -or $Domains.Count -eq 0) {
        return @()
    }

    $queries = Invoke-Parallel -InputObjects $Domains -ScriptBlock {
        param($Domain)

        $query = "$Domain.outlook.com"
        try {
            $records = Resolve-DnsName -Type CNAME -Name $query -ErrorAction Stop
            return [PSCustomObject]@{
                Query   = $query
                Records = $records | Select-Object Name, Type, NameHost
            }
        } catch {
            return [PSCustomObject]@{
                Query = $query
                Error = $_.Exception.Message
            }
        }
    }

    return foreach ($domain in $Domains) {
        $queries | Where-Object { $_.Query -eq "$domain.outlook.com" } | Select-Object -First 1
    }
}

function Get-DnsClientServerInventory {
    try {
        return Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction Stop | Select-Object InterfaceAlias, InterfaceIndex, ServerAddresses
    } catch {
        return [PSCustomObject]@{
            Source = 'Get-DnsClientServerAddress'
            Error  = $_.Exception.Message
        }
    }
}

function Get-DnsClientPolicies {
    try {
        return Get-DnsClient -ErrorAction Stop | Select-Object InterfaceAlias, InterfaceIndex, ConnectionSpecificSuffix, UseSuffixWhenRegistering, RegisterThisConnectionsAddress
    } catch {
        return [PSCustomObject]@{
            Source = 'Get-DnsClient'
            Error  = $_.Exception.Message
        }
    }
}

function Invoke-Main {
    $payload = [ordered]@{
        Resolution      = Test-DnsResolution
        Traceroute      = Trace-NetworkPath
        Latency         = Test-Latency
        Autodiscover    = Resolve-AutodiscoverRecords
        ClientServers   = Get-DnsClientServerInventory
        ClientPolicies  = Get-DnsClientPolicies
    }

    $result = New-CollectorMetadata -Payload $payload
    $outputPath = Export-CollectorResult -OutputDirectory $OutputDirectory -FileName 'dns.json' -Data $result -Depth 6
    Write-Output $outputPath
}

Invoke-Main
