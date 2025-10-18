<#!
.SYNOPSIS
    Collects Intune push wake prerequisites including dmwappushservice, PushLaunch task state, and push error logs.
#>
[CmdletBinding()]
param(
    [Parameter()]
    [string]$OutputDirectory = (Join-Path -Path (Split-Path -Parent $PSCommandPath) -ChildPath '..\output'),

    [Parameter()]
    [int]$RecencyWindowDays = 7
)

. (Join-Path -Path $PSScriptRoot -ChildPath '..\CollectorCommon.ps1')

function ConvertTo-IntuneUtcString {
    param([AllowNull()][object]$Value)

    if ($null -eq $Value) { return $null }

    $dateValue = $null

    if ($Value -is [datetime]) {
        $dateValue = [datetime]$Value
    } elseif ($Value -is [string]) {
        $text = ([string]$Value).Trim()
        if (-not $text) { return $null }
        if ($text -match '^(?i)(n/a|not available|never)$') { return $null }

        try {
            $dateValue = [datetime]::Parse($text)
        } catch {
            try {
                $dateValue = [datetime]::Parse($text, [System.Globalization.CultureInfo]::InvariantCulture)
            } catch {
                return $null
            }
        }
    } else {
        try {
            $dateValue = [datetime]::Parse([string]$Value)
        } catch {
            return $null
        }
    }

    if (-not $dateValue) { return $null }
    if ($dateValue -eq [datetime]::MinValue -or $dateValue -eq [datetime]::MaxValue) { return $null }

    if ($dateValue.Kind -eq [System.DateTimeKind]::Unspecified) {
        $dateValue = [datetime]::SpecifyKind($dateValue, [System.DateTimeKind]::Local)
    }

    $utc = $dateValue.ToUniversalTime()
    return $utc.ToString('yyyy-MM-ddTHH:mm:ssZ')
}

function Get-IntunePushServiceSnapshot {
    $record = [ordered]@{
        Name      = 'dmwappushservice'
        Exists    = $false
        StartType = $null
        State     = $null
    }

    $serviceResult = Get-CollectorServiceByName -Name 'dmwappushservice'
    $service = $serviceResult.Service

    if (-not $service) {
        if ($serviceResult.Errors -and $serviceResult.Errors.Count -gt 0) {
            $record['Error'] = ($serviceResult.Errors -join '; ')
        }
        return [pscustomobject]$record
    }

    $record.Exists = $true

    $startType = $null
    if ($service.PSObject.Properties['StartMode'] -and $service.StartMode) {
        $startType = [string]$service.StartMode
    } elseif ($service.PSObject.Properties['StartType'] -and $service.StartType) {
        $startType = [string]$service.StartType
    }

    $delayed = $false
    if ($service.PSObject.Properties['DelayedAutoStart']) {
        try { $delayed = [bool]$service.DelayedAutoStart } catch { $delayed = $false }
    }

    if ($startType) {
        $normalized = $startType.Trim().ToLowerInvariant()
        if ($normalized -like 'auto*') {
            if ($delayed -or $normalized -like '*delay*') { $record.StartType = 'AutomaticDelayedStart' }
            else { $record.StartType = 'Automatic' }
        } elseif ($normalized -like 'manual*') {
            $record.StartType = 'Manual'
        } elseif ($normalized -like 'disabled*') {
            $record.StartType = 'Disabled'
        } else {
            $record.StartType = $startType.Trim()
        }
    }

    $state = $null
    if ($service.PSObject.Properties['State'] -and $service.State) {
        $state = [string]$service.State
    } elseif ($service.PSObject.Properties['Status'] -and $service.Status) {
        $state = [string]$service.Status
    }

    if ($state) {
        $record.State = $state.Trim()
    }

    return [pscustomobject]$record
}

function Get-IntunePushLaunchTaskSnapshot {
    $taskPath = '\\Microsoft\\Windows\\PushToInstall\\'
    $taskName = 'PushLaunch'
    $taskFullPath = '{0}{1}' -f $taskPath, $taskName

    $snapshot = [ordered]@{
        Path            = $taskFullPath
        Exists          = $false
        Enabled         = $null
        LastResult      = $null
        LastRunTimeUtc  = $null
        State           = $null
    }

    $getTaskAvailable = Get-Command -Name 'Get-ScheduledTask' -ErrorAction SilentlyContinue
    $getTaskInfoAvailable = Get-Command -Name 'Get-ScheduledTaskInfo' -ErrorAction SilentlyContinue

    if ($getTaskAvailable -and $getTaskInfoAvailable) {
        try {
            $task = Get-ScheduledTask -TaskPath $taskPath -TaskName $taskName -ErrorAction Stop
            if ($task) {
                $snapshot.Exists = $true
                if ($task.PSObject.Properties['Settings'] -and $task.Settings -and $task.Settings.PSObject.Properties['Enabled']) {
                    try { $snapshot.Enabled = [bool]$task.Settings.Enabled } catch { $snapshot.Enabled = $null }
                }
                if ($task.PSObject.Properties['State'] -and $task.State) {
                    $snapshot.State = [string]$task.State
                }
            }
        } catch {
            $message = $_.Exception.Message
            if ($message -notmatch 'Cannot find the task' -and $message -notmatch 'cannot find the file') {
                $snapshot['Error'] = $message
            }
        }

        if ($snapshot.Exists) {
            try {
                $info = Get-ScheduledTaskInfo -TaskPath $taskPath -TaskName $taskName -ErrorAction Stop
                if ($info) {
                    if ($info.PSObject.Properties['LastTaskResult']) {
                        try { $snapshot.LastResult = [int]$info.LastTaskResult } catch { $snapshot.LastResult = $info.LastTaskResult }
                    }
                    if ($info.PSObject.Properties['LastRunTime']) {
                        $snapshot.LastRunTimeUtc = ConvertTo-IntuneUtcString -Value $info.LastRunTime
                    }
                    if (-not $snapshot.State -and $info.PSObject.Properties['State']) {
                        $snapshot.State = [string]$info.State
                    }
                }
            } catch {
                $message = $_.Exception.Message
                if ($snapshot.Contains('Error')) { $snapshot['Error'] = $snapshot['Error'] + '; ' + $message }
                else { $snapshot['Error'] = $message }
            }
        }

        if ($snapshot.Exists -or $snapshot.Contains('Error')) {
            return [pscustomobject]$snapshot
        }
    }

    $arguments = @('/Query', '/TN', $taskFullPath, '/V', '/FO', 'LIST')
    try {
        $output = & schtasks.exe @arguments 2>&1
        $exitCode = $LASTEXITCODE
    } catch {
        $snapshot['Error'] = $_.Exception.Message
        return [pscustomobject]$snapshot
    }

    if ($exitCode -ne 0) {
        $text = ($output | Where-Object { $_ }) -join ' '
        if ($text -notmatch 'ERROR:\s*The system cannot find the file') {
            if ($text) { $snapshot['Error'] = $text.Trim() }
        }
        return [pscustomobject]$snapshot
    }

    $lines = @($output | Where-Object { $_ })
    if ($lines.Count -eq 0) {
        return [pscustomobject]$snapshot
    }

    $map = @{}
    foreach ($line in $lines) {
        $separatorIndex = $line.IndexOf(':')
        if ($separatorIndex -lt 0) { continue }
        $key = $line.Substring(0, $separatorIndex).Trim()
        $value = $line.Substring($separatorIndex + 1).Trim()
        if (-not $key) { continue }
        if ($map.ContainsKey($key)) {
            if ($value) { $map[$key] = $map[$key] + ' | ' + $value }
        } else {
            $map[$key] = $value
        }
    }

    $snapshot.Exists = $true

    if ($map.ContainsKey('Scheduled Task State')) {
        $stateValue = $map['Scheduled Task State']
        if ($stateValue) {
            $snapshot.State = $stateValue
            $lower = $stateValue.ToLowerInvariant()
            if ($lower -match 'disabled') { $snapshot.Enabled = $false }
            elseif ($lower -match 'ready' -or $lower -match 'running') { $snapshot.Enabled = $true }
        }
    }

    if ($map.ContainsKey('Task To Run') -and -not $snapshot.State) {
        $snapshot.State = 'Unknown'
    }

    if ($map.ContainsKey('Last Result')) {
        $lastResultText = $map['Last Result']
        if ($lastResultText) {
            $trimmed = $lastResultText.Trim()
            if ($trimmed -match '^(?:0x)?0$') { $snapshot.LastResult = 0 }
            else {
                $numeric = $null
                if ([int]::TryParse($trimmed, [ref]$numeric)) { $snapshot.LastResult = $numeric }
                else { $snapshot.LastResult = $trimmed }
            }
        }
    }

    if ($map.ContainsKey('Last Run Time')) {
        $snapshot.LastRunTimeUtc = ConvertTo-IntuneUtcString -Value $map['Last Run Time']
    }

    if ($null -eq $snapshot.Enabled -and $map.ContainsKey('Task Enabled')) {
        $enabledValue = $map['Task Enabled']
        if ($enabledValue) {
            $snapshot.Enabled = $enabledValue.ToLowerInvariant().Contains('yes')
        }
    }

    return [pscustomobject]$snapshot
}

function Get-IntunePushLogSummary {
    param(
        [Parameter(Mandatory)]
        [string]$LogName,

        [datetime]$StartTime
    )

    try {
        $filter = @{ LogName = $LogName; Level = 2 }
        if ($StartTime) { $filter['StartTime'] = $StartTime }

        $events = @(Get-WinEvent -FilterHashtable $filter -MaxEvents 200 -ErrorAction Stop)
        if ($events.Count -eq 0) {
            return [pscustomobject]@{
                RecentErrors = 0
                LastErrorUtc = $null
            }
        }

        $recent = $events | Sort-Object -Property TimeCreated -Descending
        $latest = $recent | Select-Object -First 1

        $lastError = $null
        if ($latest -and $latest.TimeCreated) {
            $lastError = ConvertTo-IntuneUtcString -Value $latest.TimeCreated
        }

        return [pscustomobject]@{
            RecentErrors = $events.Count
            LastErrorUtc = $lastError
        }
    } catch {
        return $null
    }
}

function Invoke-Main {
    $collectedAtUtc = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    $windowDays = if ($RecencyWindowDays -gt 0) { [int]$RecencyWindowDays } else { 7 }
    $windowStart = (Get-Date).ToUniversalTime().AddDays(-1 * $windowDays)

    $serviceSnapshot = Get-IntunePushServiceSnapshot
    $taskSnapshot = Get-IntunePushLaunchTaskSnapshot

    $dmedp = Get-IntunePushLogSummary -LogName 'Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Admin' -StartTime $windowStart
    $push = Get-IntunePushLogSummary -LogName 'Microsoft-Windows-PushNotifications-Platform/Operational' -StartTime $windowStart

    $logs = $null
    if ($dmedp -or $push) {
        $logs = [ordered]@{
            DMEDP = $dmedp
            Push  = $push
        }
    }

    $payload = [ordered]@{
        CollectedAtUtc    = $collectedAtUtc
        RecencyWindowDays = $windowDays
        Service           = $serviceSnapshot
        Task              = $taskSnapshot
        Logs              = $logs
    }

    $outputPath = Export-CollectorResult -OutputDirectory $OutputDirectory -FileName 'intune-push.json' -Data $payload -Depth 6
    Write-Output $outputPath
}

Invoke-Main
