<#!
.SYNOPSIS
    Collects network adapter configuration, IP assignments, and operational state.
#>
[CmdletBinding()]
param(
    [Parameter()]
    [string]$OutputDirectory = (Join-Path -Path (Split-Path -Parent $PSCommandPath) -ChildPath '..\\output')
)

. (Join-Path -Path $PSScriptRoot -ChildPath '..\\CollectorCommon.ps1')

function Get-AdapterConfigurations {
    try {
        return Get-NetAdapter -ErrorAction Stop | Select-Object Name, InterfaceDescription, Status, LinkSpeed, MediaConnectionState, MacAddress, DriverInformation
    } catch {
        return [PSCustomObject]@{
            Source = 'Get-NetAdapter'
            Error  = $_.Exception.Message
        }
    }
}

function Get-NetIPAssignments {
    try {
        return Get-NetIPConfiguration -ErrorAction Stop | Select-Object InterfaceAlias, InterfaceDescription, IPv4Address, IPv6Address, DNSServer, IPv4DefaultGateway
    } catch {
        return [PSCustomObject]@{
            Source = 'Get-NetIPConfiguration'
            Error  = $_.Exception.Message
        }
    }
}

function Get-NetworkAdapterState {
    try {
        return Get-NetAdapterAdvancedProperty -ErrorAction Stop | Select-Object Name, DisplayName, DisplayValue
    } catch {
        return [PSCustomObject]@{
            Source = 'Get-NetAdapterAdvancedProperty'
            Error  = $_.Exception.Message
        }
    }
}

function ConvertTo-LinkEventRecord {
    param(
        [Parameter(Mandatory)]
        $Event,

        [Parameter(Mandatory)]
        [string]$Source
    )

    $timeValue = $null
    if ($Event.PSObject.Properties['TimeCreated']) {
        $timeValue = $Event.TimeCreated
        if ($timeValue -is [datetime]) {
            $timeValue = $timeValue.ToString('o')
        }
    }

    [PSCustomObject]@{
        TimeCreated = $timeValue
        Id          = if ($Event.PSObject.Properties['Id']) { $Event.Id } else { $null }
        Level       = if ($Event.PSObject.Properties['LevelDisplayName']) { $Event.LevelDisplayName } else { $null }
        Provider    = if ($Event.PSObject.Properties['ProviderName']) { $Event.ProviderName } else { $null }
        Message     = if ($Event.PSObject.Properties['Message']) { $Event.Message } else { $null }
        Source      = $Source
    }
}

function Get-LinkEventsFromLog {
    param(
        [Parameter(Mandatory)]
        [string]$LogName,

        [int[]]$Ids,

        [datetime]$StartTime = (Get-Date).AddHours(-72)
    )

    $filter = @{ LogName = $LogName }
    if ($Ids -and $Ids.Count -gt 0) {
        $filter['Id'] = $Ids
    }
    if ($StartTime) {
        $filter['StartTime'] = $StartTime
    }

    try {
        $events = Get-WinEvent -FilterHashtable $filter -MaxEvents 400 -ErrorAction Stop | Select-Object TimeCreated, Id, LevelDisplayName, ProviderName, Message
        if (-not $events) { return @() }

        $list = New-Object System.Collections.Generic.List[object]
        foreach ($event in $events) {
            $list.Add((ConvertTo-LinkEventRecord -Event $event -Source $LogName)) | Out-Null
        }

        return $list.ToArray()
    } catch {
        return [PSCustomObject]@{
            Source = "Get-WinEvent $LogName"
            Error  = $_.Exception.Message
        }
    }
}

function Get-NetworkLinkEvents {
    param([int]$LookbackHours = 72)

    $windowStart = (Get-Date).AddHours(-[math]::Abs($LookbackHours))

    $systemIds = @(27, 32, 4201, 10400, 10401, 10402, 8021, 8026)
    $systemEvents = Get-LinkEventsFromLog -LogName 'System' -Ids $systemIds -StartTime $windowStart

    $msftLog = 'Microsoft-Windows-MsftNetAdapter/Admin'
    $msftEvents = Get-LinkEventsFromLog -LogName $msftLog -StartTime $windowStart

    [ordered]@{
        CollectedAt   = (Get-Date).ToString('o')
        LookbackHours = [math]::Abs($LookbackHours)
        System        = $systemEvents
        MsftNetAdapter = $msftEvents
    }
}

function Invoke-Main {
    $payload = [ordered]@{
        Adapters   = Get-AdapterConfigurations
        IPConfig   = Get-NetIPAssignments
        Properties = Get-NetworkAdapterState
        LinkEvents = Get-NetworkLinkEvents
    }

    $result = New-CollectorMetadata -Payload $payload
    $outputPath = Export-CollectorResult -OutputDirectory $OutputDirectory -FileName 'network-adapters.json' -Data $result -Depth 6
    Write-Output $outputPath
}

Invoke-Main
