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

function Test-DnsResolution {
    param(
        [string[]]$Names = @('www.microsoft.com','outlook.office365.com','autodiscover.outlook.com')
    )

    $results = @()
    foreach ($name in $Names) {
        try {
            $records = Resolve-DnsName -Name $name -ErrorAction Stop
            $results += [PSCustomObject]@{
                Name    = $name
                Success = $true
                Records = $records | Select-Object Name, Type, IPAddress
            }
        } catch {
            $results += [PSCustomObject]@{
                Name    = $name
                Success = $false
                Error   = $_.Exception.Message
            }
        }
    }
    return $results
}

function Trace-NetworkPath {
    param([string]$Target = 'outlook.office365.com')
    return Invoke-CollectorNativeCommand -FilePath 'tracert.exe' -ArgumentList $Target -ErrorMetadata @{ Target = $Target }
}

function Test-Latency {
    param([string]$Target = '8.8.8.8')

    $attempts = 4
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
        $attemptDetails = @()
        for ($i = 1; $i -le $attempts; $i++) {
            try {
                $reply = Test-Connection -ComputerName $Target -Count 1 -ErrorAction Stop
                $latency = $reply | Select-Object -First 1 -ExpandProperty ResponseTime
                $attemptDetails += [PSCustomObject]@{
                    Attempt   = $i
                    Success   = $true
                    LatencyMs = $latency
                }
            } catch {
                $attemptDetails += [PSCustomObject]@{
                    Attempt = $i
                    Success = $false
                    Error   = $_.Exception.Message
                }
            }
        }

        $summary.AttemptsDetail = $attemptDetails
        $summary.SuccessCount = ($attemptDetails | Where-Object { $_.Success }).Count
        $summary.FailureCount = $attempts - $summary.SuccessCount

        if ($summary.SuccessCount -gt 0) {
            $latencies = $attemptDetails | Where-Object { $_.Success } | Select-Object -ExpandProperty LatencyMs
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

    $results = @()
    foreach ($domain in $Domains) {
        try {
            $records = Resolve-DnsName -Type CNAME -Name "$domain.outlook.com" -ErrorAction Stop
            $results += [PSCustomObject]@{
                Query   = "$domain.outlook.com"
                Records = $records | Select-Object Name, Type, NameHost
            }
        } catch {
            $results += [PSCustomObject]@{
                Query = "$domain.outlook.com"
                Error = $_.Exception.Message
            }
        }
    }

    return $results
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
