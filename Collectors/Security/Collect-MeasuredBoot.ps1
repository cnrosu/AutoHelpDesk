<#!
.SYNOPSIS
    Collects measured boot, Secure Boot, TPM, and Device Health Attestation signals.
#>
[CmdletBinding()]
param(
    [Parameter()]
    [string]$OutputDirectory = (Join-Path -Path (Split-Path -Parent $PSCommandPath) -ChildPath '..\output')
)

. (Join-Path -Path $PSScriptRoot -ChildPath '..\CollectorCommon.ps1')

function ConvertTo-YesNoBoolean {
    param([string]$Value)

    if ([string]::IsNullOrWhiteSpace($Value)) { return $null }

    switch -Regex ($Value.Trim()) {
        '^(?i)yes|true$' { return $true }
        '^(?i)no|false$' { return $false }
        default          { return $null }
    }
}

function Get-DsRegFieldValue {
    param(
        [string[]]$Lines,
        [string]$Field
    )

    if (-not $Lines -or -not $Field) { return $null }

    $pattern = '^(?i)\s*' + [regex]::Escape($Field) + '\s*:\s*(.+)$'
    foreach ($line in $Lines) {
        if (-not $line) { continue }
        if ($line -match $pattern) {
            $value = $matches[1]
            if ($null -eq $value) { return $null }
            return $value.Trim()
        }
    }

    return $null
}

function Test-DsRegValueIsSet {
    param([string]$Value)

    if ([string]::IsNullOrWhiteSpace($Value)) { return $false }

    $trimmed = $Value.Trim()
    if (-not $trimmed) { return $false }

    if ($trimmed -match '^(?i)\(not\s*set\)|\(null\)|none|not\s+configured|n/?a$') { return $false }

    return $true
}

function Get-DsRegOutputText {
    try {
        $raw = dsregcmd.exe /status 2>$null
        if ($null -eq $raw) { return $null }
        if ($raw -is [string[]]) { return ($raw -join [Environment]::NewLine) }
        return [string]$raw
    } catch {
        return $null
    }
}

function Get-JoinSignals {
    $result = [ordered]@{
        AADJ        = $null
        HAADJ       = $null
        ADJoined    = $null
        MDMEnrolled = $null
    }

    $dsRegText = Get-DsRegOutputText
    if ($dsRegText) {
        $lines = [regex]::Split($dsRegText, '\r?\n')
        $aadJoined = ConvertTo-YesNoBoolean (Get-DsRegFieldValue -Lines $lines -Field 'AzureAdJoined')
        $domainJoined = ConvertTo-YesNoBoolean (Get-DsRegFieldValue -Lines $lines -Field 'DomainJoined')
        $hybridJoined = ConvertTo-YesNoBoolean (Get-DsRegFieldValue -Lines $lines -Field 'HybridAzureADJoined')

        if ($null -eq $hybridJoined) {
            if ($aadJoined -eq $true -and $domainJoined -eq $true) {
                $hybridJoined = $true
            } elseif ($aadJoined -eq $false -or $domainJoined -eq $false) {
                $hybridJoined = $false
            }
        }

        $result.AADJ = $aadJoined
        $result.ADJoined = $domainJoined
        $result.HAADJ = $hybridJoined

        $mdmIndicators = @('MdmUrl', 'MdmEnrollmentUrl', 'MdmComplianceUrl', 'MdmTermsOfUseUrl', 'MdmCrmUrl', 'MdmId')
        foreach ($indicator in $mdmIndicators) {
            $value = Get-DsRegFieldValue -Lines $lines -Field $indicator
            if (Test-DsRegValueIsSet -Value $value) {
                $result.MDMEnrolled = $true
                break
            }
        }

        if ($null -eq $result.MDMEnrolled) {
            $result.MDMEnrolled = $false
        }
    } else {
        $cs = Get-CollectorComputerSystem
        if (-not (Test-CollectorResultHasError -Value $cs) -and $cs -and $cs.PSObject.Properties['PartOfDomain']) {
            $result.ADJoined = [bool]$cs.PartOfDomain
        }
    }

    return [pscustomobject]$result
}

function Get-UefiState {
    $registryPath = 'HKLM:\SYSTEM\CurrentControlSet\Control'
    try {
        $value = Get-ItemPropertyValue -Path $registryPath -Name 'PEFirmwareType' -ErrorAction Stop
        if ($null -ne $value) {
            $numeric = [int]$value
            if ($numeric -eq 2) { return $true }
            if ($numeric -eq 1) { return $false }
        }
    } catch {
    }

    return $null
}

function Get-SecureBootState {
    $enabled = $null
    $cmd = Get-Command -Name 'Confirm-SecureBootUEFI' -ErrorAction SilentlyContinue
    if ($cmd) {
        try {
            $enabled = [bool](Confirm-SecureBootUEFI -ErrorAction Stop)
        } catch {
        }
    }

    if ($null -eq $enabled) {
        $registryPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State'
        try {
            $value = Get-ItemPropertyValue -Path $registryPath -Name 'UEFISecureBootEnabled' -ErrorAction Stop
            if ($null -ne $value) {
                $enabled = ([int]$value -eq 1)
            }
        } catch {
        }
    }

    return $enabled
}

function Select-TpmSpecVersion {
    param([string]$Value)

    if ([string]::IsNullOrWhiteSpace($Value)) { return $null }

    $matches = [regex]::Matches($Value, '\d+(?:\.\d+)?')
    if ($matches.Count -eq 0) { return $Value.Trim() }

    $maxVersion = $null
    foreach ($match in $matches) {
        if (-not $match.Success) { continue }
        $numberText = $match.Value
        if (-not $numberText) { continue }

        $parsed = 0.0
        if ([double]::TryParse($numberText, [System.Globalization.NumberStyles]::Float, [System.Globalization.CultureInfo]::InvariantCulture, [ref]$parsed)) {
            if ($null -eq $maxVersion -or $parsed -gt $maxVersion) {
                $maxVersion = $parsed
            }
        }
    }

    if ($null -eq $maxVersion) {
        return $Value.Trim()
    }

    return $maxVersion.ToString('0.0', [System.Globalization.CultureInfo]::InvariantCulture)
}

function Get-TpmSignals {
    $result = [ordered]@{
        Present = $null
        Ready   = $null
        Spec    = $null
    }

    $cmd = Get-Command -Name 'Get-Tpm' -ErrorAction SilentlyContinue
    if (-not $cmd) { return [pscustomobject]$result }

    try {
        $tpm = Get-Tpm -ErrorAction Stop
    } catch {
        return [pscustomobject]$result
    }

    if (-not $tpm) { return [pscustomobject]$result }

    if ($tpm.PSObject.Properties['TpmPresent']) { $result.Present = [bool]$tpm.TpmPresent }
    if ($tpm.PSObject.Properties['TpmReady']) { $result.Ready = [bool]$tpm.TpmReady }
    if ($tpm.PSObject.Properties['SpecVersion']) {
        $normalized = Select-TpmSpecVersion -Value ([string]$tpm.SpecVersion)
        if ($normalized) {
            $result.Spec = $normalized
        }
    }

    return [pscustomobject]$result
}

function Test-EventLogAvailable {
    param([string]$LogName)

    if ([string]::IsNullOrWhiteSpace($LogName)) { return $false }

    try {
        $null = Get-WinEvent -ListLog $LogName -ErrorAction Stop
        return $true
    } catch {
        return $false
    }
}

function Get-DhaSignals {
    $dhaLogName = 'Microsoft-Windows-DeviceHealthAttestation/Operational'
    $tpmLogName = 'Microsoft-Windows-TPM-WMI/Operational'

    $logPresent = Test-EventLogAvailable -LogName $dhaLogName
    $tpmLogPresent = Test-EventLogAvailable -LogName $tpmLogName

    $lastSuccess = $null
    $lastError = $null
    $recentErrors = 0

    if ($logPresent) {
        $lookbackStart = (Get-Date).AddDays(-30)
        $recentWindow = (Get-Date).ToUniversalTime().AddDays(-7)
        $events = @()
        try {
            $events = Get-WinEvent -FilterHashtable @{ LogName = $dhaLogName; StartTime = $lookbackStart } -ErrorAction Stop
        } catch {
            $events = @()
        }

        foreach ($event in $events) {
            if (-not $event) { continue }

            $time = $event.TimeCreated
            if (-not $time) { continue }
            $timeUtc = $time.ToUniversalTime()

            $message = $null
            try {
                if ($event.Message) { $message = [string]$event.Message }
            } catch {
                $message = $null
            }

            $levelText = $null
            if ($event.PSObject.Properties['LevelDisplayName']) {
                $levelText = [string]$event.LevelDisplayName
            }

            $isError = $false
            if ($levelText -and $levelText -match '(?i)error|warning') { $isError = $true }
            if ($message -and $message -match '(?i)\b(error|fail|denied|timeout|unsuccessful)\b') { $isError = $true }

            $isSuccess = $false
            $successIds = @(307, 3000, 3001, 3002, 3003, 3004, 3010)
            if ($successIds -contains $event.Id) { $isSuccess = $true }
            if (-not $isSuccess -and $message -and $message -match '(?i)success|succeeded|healthy|compliant') {
                $isSuccess = $true
            }

            if ($isSuccess) {
                if ($null -eq $lastSuccess -or $timeUtc -gt $lastSuccess) {
                    $lastSuccess = $timeUtc
                }
            }

            if ($isError) {
                if ($null -eq $lastError -or $timeUtc -gt $lastError) {
                    $lastError = $timeUtc
                }

                if ($timeUtc -ge $recentWindow) {
                    $recentErrors += 1
                }
            }
        }
    }

    return [pscustomobject]@{
        LogChannels = [pscustomobject]@{
            DHAOperationalPresent    = $logPresent
            TPMWMIOperationalPresent = $tpmLogPresent
        }
        LastSuccessUtc = if ($lastSuccess) { $lastSuccess.ToString('o') } else { $null }
        LastErrorUtc   = if ($lastError) { $lastError.ToString('o') } else { $null }
        RecentErrors   = $recentErrors
    }
}

function Invoke-Main {
    $payload = [ordered]@{
        CollectedAtUtc = (Get-Date).ToUniversalTime().ToString('o')
        Join           = Get-JoinSignals
        Platform       = [pscustomobject]@{
            UEFI       = Get-UefiState
            SecureBoot = Get-SecureBootState
            TPM        = Get-TpmSignals
        }
        DHA            = Get-DhaSignals
    }

    $result = New-CollectorMetadata -Payload ([pscustomobject]$payload)
    $outputPath = Export-CollectorResult -OutputDirectory $OutputDirectory -FileName 'measured-boot.json' -Data $result -Depth 6
    Write-Output $outputPath
}

Invoke-Main
