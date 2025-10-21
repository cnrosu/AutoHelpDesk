<#!
.SYNOPSIS
    Collects device uptime details.
#>
[CmdletBinding()]
param(
    [Parameter()]
    [string]$OutputDirectory = (Join-Path -Path (Split-Path -Parent $PSCommandPath) -ChildPath '..\\output')
)

. (Join-Path -Path $PSScriptRoot -ChildPath '..\\CollectorCommon.ps1')

function ConvertTo-UptimeUtcDateTime {
    param($Value)

    if (-not $Value) { return $null }

    try {
        if ($Value -is [DateTimeOffset]) {
            return $Value.UtcDateTime
        }

        $dateTime = $null
        if ($Value -is [DateTime]) {
            $dateTime = $Value
        } elseif ($Value -is [string]) {
            $text = $Value.Trim()
            if (-not $text) { return $null }

            $styles = [System.Globalization.DateTimeStyles]::AssumeUniversal -bor [System.Globalization.DateTimeStyles]::AdjustToUniversal
            try {
                $parsedOffset = [DateTimeOffset]::Parse($text, [System.Globalization.CultureInfo]::InvariantCulture, $styles)
                return $parsedOffset.UtcDateTime
            } catch {
                $dateTime = [DateTime]::Parse($text, [System.Globalization.CultureInfo]::InvariantCulture)
            }
        } else {
            return $null
        }

        if (-not $dateTime) { return $null }

        if ($dateTime.Kind -eq [DateTimeKind]::Utc) { return $dateTime }
        if ($dateTime.Kind -eq [DateTimeKind]::Unspecified) {
            $dateTime = [DateTime]::SpecifyKind($dateTime, [DateTimeKind]::Local)
        }

        return $dateTime.ToUniversalTime()
    } catch {
        return $null
    }
}

function Test-UptimeRestartEvent {
    param($Event)

    if (-not $Event) { return $false }
    if ($Event.Id -ne 1074) { return $true }

    $isRestart = $false

    try {
        $description = $Event.FormatDescription()
        if ($description -and ($description -match '(?i)restart')) {
            $isRestart = $true
        }
    } catch {
        $isRestart = $false
    }

    if (-not $isRestart -and $Event.PSObject.Properties['Properties']) {
        foreach ($property in $Event.Properties) {
            if (-not $property) { continue }
            $value = $property.Value
            if (-not $value) { continue }

            $text = [string]$value
            if ($text -match '(?i)restart') { $isRestart = $true; break }
        }
    }

    return $isRestart
}

function Get-UptimeEffectiveSinceUtc {
    param(
        [DateTime]$LastBootUtc
    )

    $eventIds = @(12, 41, 6008, 1074)
    $maxEventTime = $null

    try {
        $filter = @{ LogName = 'System'; Id = $eventIds }
        $windowStart = $null
        if ($LastBootUtc) {
            $windowStart = $LastBootUtc.AddDays(-30)
        }

        if (-not $windowStart) {
            $windowStart = (Get-Date).AddDays(-60)
        }

        $filter['StartTime'] = $windowStart

        $events = Get-WinEvent -FilterHashtable $filter -MaxEvents 200 -ErrorAction Stop
        foreach ($event in $events) {
            if (-not $event) { continue }
            if (-not (Test-UptimeRestartEvent -Event $event)) { continue }

            $timeCreated = $event.TimeCreated
            if (-not $timeCreated) { continue }

            try {
                $utcTime = if ($timeCreated.Kind -eq [DateTimeKind]::Utc) { $timeCreated } else { $timeCreated.ToUniversalTime() }
                if (-not $maxEventTime -or $utcTime -gt $maxEventTime) { $maxEventTime = $utcTime }
            } catch {
                continue
            }
        }
    } catch {
        $maxEventTime = $null
    }

    if ($LastBootUtc -and $maxEventTime -and $maxEventTime -lt $LastBootUtc) {
        return $LastBootUtc
    }

    return $maxEventTime
}

function Get-UptimeBooleanFromRegistry {
    param(
        [Parameter(Mandatory)]
        [string]$Path,
        [Parameter(Mandatory)]
        [string]$Name
    )

    try {
        $value = Get-ItemPropertyValue -Path $Path -Name $Name -ErrorAction Stop
        if ($null -eq $value) { return $null }

        if ($value -is [bool]) { return $value }
        if ($value -is [int] -or $value -is [long]) { return ([int64]$value -ne 0) }

        $text = [string]$value
        if ([string]::IsNullOrWhiteSpace($text)) { return $null }

        if ($text -match '^(?i)(true|yes|enabled|on)$') { return $true }
        if ($text -match '^(?i)(false|no|disabled|off)$') { return $false }

        try {
            $numeric = [int64]$text
            return ($numeric -ne 0)
        } catch {
            return $null
        }
    } catch {
        return $null
    }
}

function Get-Uptime {
    $os = Get-CollectorOperatingSystem

    if (Test-CollectorResultHasError -Value $os) {
        return $os
    }

    if (-not $os) { return $null }

    $lastBootRaw = $null
    if ($os.PSObject.Properties['LastBootUpTime']) { $lastBootRaw = $os.LastBootUpTime }

    $lastBootUtc = ConvertTo-UptimeUtcDateTime -Value $lastBootRaw
    $lastBootIso = if ($lastBootUtc) { $lastBootUtc.ToString('o') } else { $null }

    $nowUtc = (Get-Date).ToUniversalTime()

    $kernelUptimeSeconds = $null
    if ($lastBootUtc) {
        try {
            $span = $nowUtc - $lastBootUtc
            if ($span.TotalSeconds -ge 0) {
                $kernelUptimeSeconds = [int64][math]::Floor($span.TotalSeconds)
            }
        } catch {
            $kernelUptimeSeconds = $null
        }
    }

    $effectiveSinceUtc = Get-UptimeEffectiveSinceUtc -LastBootUtc $lastBootUtc
    if (-not $effectiveSinceUtc) { $effectiveSinceUtc = $lastBootUtc }
    if ($lastBootUtc -and $effectiveSinceUtc -and $effectiveSinceUtc -lt $lastBootUtc) {
        $effectiveSinceUtc = $lastBootUtc
    }
    $effectiveSinceIso = if ($effectiveSinceUtc) { $effectiveSinceUtc.ToString('o') } else { $null }

    $effectiveUptimeSeconds = $null
    if ($effectiveSinceUtc) {
        try {
            $effectiveSpan = $nowUtc - $effectiveSinceUtc
            if ($effectiveSpan.TotalSeconds -ge 0) {
                $effectiveUptimeSeconds = [int64][math]::Floor($effectiveSpan.TotalSeconds)
            }
        } catch {
            $effectiveUptimeSeconds = $null
        }
    }

    $fastStartupConfigured = Get-UptimeBooleanFromRegistry -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power' -Name 'HiberbootEnabled'
    $hibernateEnabled = Get-UptimeBooleanFromRegistry -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Power' -Name 'HibernateEnabled'

    $hiberfilePresent = $null
    try {
        $systemDrive = if ($env:SystemDrive) { $env:SystemDrive } else { 'C:' }
        $hiberfilePath = Join-Path -Path $systemDrive -ChildPath 'hiberfil.sys'
        $hiberfilePresent = Test-Path -LiteralPath $hiberfilePath -PathType Leaf
    } catch {
        $hiberfilePresent = $null
    }

    $fastStartupEffective = $false
    if ($fastStartupConfigured -eq $true) {
        if (($hibernateEnabled -eq $true) -or ($hiberfilePresent -eq $true)) {
            $fastStartupEffective = $true
        }
    }

    return [ordered]@{
        LastBootUpTime        = $lastBootIso
        KernelUptimeSeconds   = $kernelUptimeSeconds
        EffectiveSince        = $effectiveSinceIso
        EffectiveUptimeSeconds = $effectiveUptimeSeconds
        FastStartupConfigured = if ($null -ne $fastStartupConfigured) { [bool]$fastStartupConfigured } else { $null }
        HibernateEnabled      = if ($null -ne $hibernateEnabled) { [bool]$hibernateEnabled } else { $null }
        HiberfilePresent      = if ($null -ne $hiberfilePresent) { [bool]$hiberfilePresent } else { $null }
        FastStartupEffective  = [bool]$fastStartupEffective
    }
}

function Invoke-Main {
    $payload = [ordered]@{
        Uptime = Get-Uptime
    }

    $result = New-CollectorMetadata -Payload $payload
    $outputPath = Export-CollectorResult -OutputDirectory $OutputDirectory -FileName 'uptime.json' -Data $result -Depth 4
    Write-Output $outputPath
}

Invoke-Main
