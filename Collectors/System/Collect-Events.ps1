<#!
.SYNOPSIS
    Collects recent Application and System event log entries.
#>
[CmdletBinding()]
param(
    [Parameter()]
    [string]$OutputDirectory = (Join-Path -Path (Split-Path -Parent $PSCommandPath) -ChildPath '..\\output')
)

. (Join-Path -Path $PSScriptRoot -ChildPath '..\\CollectorCommon.ps1')

$script:FilePathRegex = [System.Text.RegularExpressions.Regex]::new('(?i)\b([A-Z]:\\[^\s"'']+)', [System.Text.RegularExpressions.RegexOptions]::Compiled)

function Get-RecentEvents {
    param(
        [Parameter(Mandatory)]
        [string]$LogName,

        [int]$MaxEvents = 100
    )

    try {
        return Get-WinEvent -LogName $LogName -MaxEvents $MaxEvents -ErrorAction Stop | Select-Object TimeCreated, Id, LevelDisplayName, ProviderName, Message
    } catch {
        return [PSCustomObject]@{
            LogName = $LogName
            Error   = $_.Exception.Message
        }
    }
}

function Redact-ServicingPath {
    param([string]$Text)

    if ([string]::IsNullOrWhiteSpace($Text)) { return $Text }

    return $script:FilePathRegex.Replace($Text, '<path>')
}

function Get-CbsTailSnippet {
    param(
        [int]$TailLines = 200
    )

    $logPath = 'C:\\Windows\\Logs\\CBS\\CBS.log'
    if (-not (Test-Path -LiteralPath $logPath)) {
        return [pscustomobject]@{
            Lines = @()
            Error = "CBS log missing at $logPath"
        }
    }

    try {
        $rawLines = Get-Content -LiteralPath $logPath -Tail $TailLines -ErrorAction Stop
    } catch {
        return [pscustomobject]@{
            Lines = @()
            Error = $_.Exception.Message
        }
    }

    $redacted = @()
    foreach ($line in $rawLines) {
        if ($null -eq $line) {
            $redacted += ''
        } else {
            $redacted += (Redact-ServicingPath -Text ([string]$line))
        }
    }

    return [pscustomobject]@{ Lines = $redacted }
}

function Get-ServicingStackSummary {
    param(
        [int]$WindowDays = 14,
        [int]$TailLines = 200
    )

    $logName = 'Microsoft-Windows-Servicing/Operations'
    $eventId = 1016
    $startTime = (Get-Date).AddDays(-1 * [math]::Abs($WindowDays))
    $events = @()
    $eventError = $null

    try {
        $events = Get-WinEvent -FilterHashtable @{ LogName = $logName; Id = $eventId; StartTime = $startTime } -ErrorAction Stop
    } catch {
        $eventError = $_.Exception.Message
        $events = @()
    }

    $count = if ($events) { $events.Count } else { 0 }
    $lastUtc = $null
    if ($events -and $events.Count -gt 0) {
        $latest = $events | Sort-Object TimeCreated -Descending | Select-Object -First 1
        if ($latest -and $latest.TimeCreated) {
            $lastUtc = $latest.TimeCreated.ToUniversalTime().ToString('o')
        }
    }

    $tailInfo = Get-CbsTailSnippet -TailLines $TailLines

    $summary = [ordered]@{
        EventLogName        = $logName
        EventId             = $eventId
        WindowDays          = $WindowDays
        Servicing1016Count  = $count
        LastUtc             = $lastUtc
        CbsTailLines        = $tailInfo.Lines
    }

    if ($eventError) { $summary['EventError'] = $eventError }
    if ($tailInfo.PSObject.Properties['Error']) { $summary['CbsTailError'] = $tailInfo.Error }

    return [pscustomobject]$summary
}

function Invoke-Main {
    $payload = [ordered]@{
        System         = Get-RecentEvents -LogName 'System'
        Application    = Get-RecentEvents -LogName 'Application'
        GroupPolicy    = Get-RecentEvents -LogName 'Microsoft-Windows-GroupPolicy/Operational' -MaxEvents 200
        ServicingStack = Get-ServicingStackSummary -WindowDays 14 -TailLines 200
    }

    $result = New-CollectorMetadata -Payload $payload
    $outputPath = Export-CollectorResult -OutputDirectory $OutputDirectory -FileName 'events.json' -Data $result -Depth 6
    Write-Output $outputPath
}

Invoke-Main
