<#!
.SYNOPSIS
    Collects USB and device installation failure events plus SetupAPI diagnostics.
#>
[CmdletBinding()]
param(
    [Parameter()]
    [string]$OutputDirectory = (Join-Path -Path (Split-Path -Parent $PSCommandPath) -ChildPath '..\output')
)

. (Join-Path -Path $PSScriptRoot -ChildPath '..\CollectorCommon.ps1')

function ConvertTo-EventRecord {
    param(
        [Parameter(Mandatory)]
        $Event
    )

    $properties = @()
    if ($Event -and $Event.PSObject.Properties['Properties'] -and $Event.Properties) {
        $propValues = foreach ($prop in $Event.Properties) {
            if ($null -eq $prop) { continue }
            if ($prop.PSObject.Properties['Value']) {
                if ($null -ne $prop.Value) {
                    $prop.Value.ToString()
                } else {
                    $null
                }
            } else {
                $prop.ToString()
            }
        }

        $properties = @($propValues)
    }

    return [pscustomobject]@{
        Id           = $Event.Id
        ProviderName = $Event.ProviderName
        Level        = $Event.LevelDisplayName
        TimeCreated  = if ($Event.TimeCreated) { $Event.TimeCreated.ToString('o') } else { $null }
        Message      = $Event.Message
        Properties   = $properties
    }
}

function Get-DeviceInstallEvents {
    param(
        [Parameter(Mandatory)]
        [string]$LogName,

        [int[]]$EventIds = @(),

        [string]$ProviderName,

        [datetime]$StartTime,

        [int]$MaxEvents = 500
    )

    $filter = @{ LogName = $LogName }
    if ($EventIds -and $EventIds.Count -gt 0) { $filter['Id'] = $EventIds }
    if ($PSBoundParameters.ContainsKey('ProviderName') -and -not [string]::IsNullOrWhiteSpace($ProviderName)) {
        $filter['ProviderName'] = $ProviderName
    }
    if ($PSBoundParameters.ContainsKey('StartTime') -and $StartTime) {
        $filter['StartTime'] = $StartTime
    }

    try {
        $events = Get-WinEvent -FilterHashtable $filter -MaxEvents $MaxEvents -ErrorAction Stop
    } catch {
        return @([pscustomobject]@{
            Source = "Get-WinEvent $LogName"
            Error  = $_.Exception.Message
        })
    }

    $records = [System.Collections.Generic.List[pscustomobject]]::new()
    foreach ($event in $events) {
        $records.Add((ConvertTo-EventRecord -Event $event)) | Out-Null
    }

    return $records.ToArray()
}

function Get-SetupApiLogTail {
    param(
        [string]$Path = 'C:\\Windows\\INF\\setupapi.dev.log',
        [int]$Tail = 100
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        return [pscustomobject]@{
            Source = $Path
            Error  = 'File not found'
        }
    }

    try {
        return Get-Content -LiteralPath $Path -Tail $Tail -ErrorAction Stop
    } catch {
        return [pscustomobject]@{
            Source = $Path
            Error  = $_.Exception.Message
        }
    }
}

function Invoke-Main {
    $windowDays = 7
    $startTime = (Get-Date).AddDays(-1 * $windowDays)

    $payload = [ordered]@{
        CapturedAtUtc     = (Get-Date).ToUniversalTime().ToString('o')
        WindowDays        = $windowDays
        StartTimeUtc      = $startTime.ToUniversalTime().ToString('o')
        UserPnpEvents     = Get-DeviceInstallEvents -LogName 'Microsoft-Windows-UserPnp/DeviceInstall' -EventIds (20001..20007) -StartTime $startTime
        KernelPnPEvents   = Get-DeviceInstallEvents -LogName 'System' -EventIds @(219) -ProviderName 'Microsoft-Windows-Kernel-PnP' -StartTime $startTime
        SetupApiDevLogTail = Get-SetupApiLogTail
    }

    $result = New-CollectorMetadata -Payload $payload
    $outputPath = Export-CollectorResult -OutputDirectory $OutputDirectory -FileName 'deviceinstall-events.json' -Data $result -Depth 6
    Write-Output $outputPath
}

Invoke-Main
