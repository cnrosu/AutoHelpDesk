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

function Normalize-EventString {
    param(
        [AllowNull()][object]$Value
    )

    if ($null -eq $Value) { return $null }

    $text = [string]$Value
    if ([string]::IsNullOrWhiteSpace($text)) { return $null }

    return $text.Trim()
}

function Get-EventDataValue {
    param(
        [AllowNull()][object]$EventData,

        [Parameter(Mandatory)]
        [string]$Name
    )

    if (-not $EventData) { return $null }

    foreach ($entry in @($EventData)) {
        if (-not $entry) { continue }
        if (-not ($entry.PSObject.Properties['Name']) -or $entry.Name -ne $Name) { continue }

        if ($entry.PSObject.Properties['#text']) { return $entry.'#text' }
        if ($entry.PSObject.Properties['InnerText']) { return $entry.InnerText }
        if ($entry.PSObject.Properties['Value']) { return $entry.Value }

        return $null
    }

    return $null
}

function Get-SecurityLogonEvents {
    param(
        [int]$MaxDays = 14,

        [int]$MaxEvents = 5000
    )

    $startTime = (Get-Date).AddDays(-[math]::Abs($MaxDays))

    try {
        $events = Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4624; StartTime = $startTime } -MaxEvents $MaxEvents -ErrorAction Stop
    } catch {
        return [PSCustomObject]@{
            Error = $_.Exception.Message
        }
    }

    $records = New-Object System.Collections.Generic.List[object]

    foreach ($event in $events) {
        if (-not $event) { continue }

        $timeUtc = $null
        if ($event.PSObject.Properties['TimeCreated'] -and $event.TimeCreated) {
            $timeUtc = $event.TimeCreated.ToUniversalTime()
        }

        $xml = $null
        try {
            $xml = [xml]$event.ToXml()
        } catch {
            continue
        }

        if (-not $xml -or -not $xml.Event -or -not $xml.Event.EventData) { continue }
        $dataNodes = $xml.Event.EventData.Data

        $logonTypeRaw = Get-EventDataValue -EventData $dataNodes -Name 'LogonType'
        $authPackageRaw = Get-EventDataValue -EventData $dataNodes -Name 'AuthenticationPackageName'
        $workstationRaw = Get-EventDataValue -EventData $dataNodes -Name 'WorkstationName'
        $ipAddressRaw = Get-EventDataValue -EventData $dataNodes -Name 'IpAddress'
        $targetUserRaw = Get-EventDataValue -EventData $dataNodes -Name 'TargetUserName'
        $targetDomainRaw = Get-EventDataValue -EventData $dataNodes -Name 'TargetDomainName'

        $logonTypeValue = $null
        if ($null -ne $logonTypeRaw) {
            $parsed = 0
            if ([int]::TryParse([string]$logonTypeRaw, [ref]$parsed)) {
                $logonTypeValue = $parsed
            }
        }

        $record = [ordered]@{
            TimeCreatedUtc            = if ($timeUtc) { $timeUtc.ToString('o') } else { $null }
            LogonType                 = $logonTypeValue
            AuthenticationPackageName = Normalize-EventString -Value $authPackageRaw
            WorkstationName           = Normalize-EventString -Value $workstationRaw
            IpAddress                 = Normalize-EventString -Value $ipAddressRaw
            TargetUserName            = Normalize-EventString -Value $targetUserRaw
            TargetDomainName          = Normalize-EventString -Value $targetDomainRaw
        }

        $records.Add([PSCustomObject]$record) | Out-Null
    }

    return [PSCustomObject]@{
        Logon4624 = $records.ToArray()
        StartTimeUtc = $startTime.ToUniversalTime().ToString('o')
        MaxEventsLimitReached = ($events.Count -ge $MaxEvents)
    }
}

function Invoke-Main {
    $payload = [ordered]@{
        System      = Get-RecentEvents -LogName 'System'
        Application = Get-RecentEvents -LogName 'Application'
        GroupPolicy = Get-RecentEvents -LogName 'Microsoft-Windows-GroupPolicy/Operational' -MaxEvents 200
        Security    = Get-SecurityLogonEvents -MaxDays 14 -MaxEvents 5000
    }

    $result = New-CollectorMetadata -Payload $payload
    $outputPath = Export-CollectorResult -OutputDirectory $OutputDirectory -FileName 'events.json' -Data $result -Depth 6
    Write-Output $outputPath
}

Invoke-Main
