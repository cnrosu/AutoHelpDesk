<#!
.SYNOPSIS
    Collects signals indicating whether a reboot is pending on the device.
#>
[CmdletBinding()]
param(
    [Parameter()]
    [string]$OutputDirectory = (Join-Path -Path (Split-Path -Parent $PSCommandPath) -ChildPath '..\output')
)

. (Join-Path -Path $PSScriptRoot -ChildPath '..\CollectorCommon.ps1')

function Test-RegistryPathSafe {
    param(
        [Parameter(Mandatory)]
        [string]$Path,
        [Parameter(Mandatory)]
        [System.Collections.Generic.List[string]]$Errors
    )

    try {
        return Test-Path -LiteralPath $Path -ErrorAction Stop
    } catch {
        $Errors.Add(('Test-Path {0}: {1}' -f $Path, $_.Exception.Message)) | Out-Null
        return $false
    }
}

function Get-RegistryValueStringSafe {
    param(
        [Parameter(Mandatory)]
        [string]$Path,
        [Parameter(Mandatory)]
        [string]$ValueName,
        [Parameter(Mandatory)]
        [System.Collections.Generic.List[string]]$Errors
    )

    try {
        if (-not (Test-Path -LiteralPath $Path)) { return $null }
        $value = Get-ItemProperty -LiteralPath $Path -Name $ValueName -ErrorAction Stop | Select-Object -ExpandProperty $ValueName -ErrorAction Stop
        if ($null -eq $value) { return $null }
        return [string]$value
    } catch {
        $Errors.Add(('Get-ItemProperty {0}!{1}: {2}' -f $Path, $ValueName, $_.Exception.Message)) | Out-Null
        return $null
    }
}

function Get-PendingRenameStatus {
    param(
        [Parameter(Mandatory)]
        [System.Collections.Generic.List[string]]$Errors
    )

    $activeName = Get-RegistryValueStringSafe -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName' -ValueName 'ComputerName' -Errors $Errors
    $pendingName = Get-RegistryValueStringSafe -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName' -ValueName 'ComputerName' -Errors $Errors

    $tcpipCurrent = Get-RegistryValueStringSafe -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' -ValueName 'Hostname' -Errors $Errors
    $tcpipPending = Get-RegistryValueStringSafe -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' -ValueName 'NV Hostname' -Errors $Errors

    $mismatch = $false
    if ($activeName -and $pendingName -and ($activeName -ne $pendingName)) {
        $mismatch = $true
    }

    $tcpMismatch = $false
    if ($tcpipCurrent -and $tcpipPending -and ($tcpipCurrent -ne $tcpipPending)) {
        $tcpMismatch = $true
    }

    return [pscustomobject]@{
        ActiveName        = $activeName
        PendingName       = $pendingName
        TcpipHostname     = $tcpipCurrent
        TcpipPendingName  = $tcpipPending
        NameMismatch      = $mismatch
        TcpipMismatch     = $tcpMismatch
    }
}

function Get-PendingFileRenameEntries {
    param(
        [Parameter(Mandatory)]
        [System.Collections.Generic.List[string]]$Errors
    )

    $sessionManagerPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager'
    $valueName = 'PendingFileRenameOperations'
    $entries = @()

    try {
        if (Test-Path -LiteralPath $sessionManagerPath) {
            $value = Get-ItemProperty -LiteralPath $sessionManagerPath -Name $valueName -ErrorAction Stop | Select-Object -ExpandProperty $valueName -ErrorAction Stop
            if ($null -ne $value) {
                if ($value -is [string]) {
                    $entries = @($value)
                } elseif ($value -is [System.Collections.IEnumerable] -and -not ($value -is [string])) {
                    $entries = @($value | ForEach-Object { [string]$_ })
                } else {
                    $entries = @([string]$value)
                }
            }
        }
    } catch {
        $Errors.Add(('Get-ItemProperty {0}!{1}: {2}' -f $sessionManagerPath, $valueName, $_.Exception.Message)) | Out-Null
    }

    $normalized = [System.Collections.Generic.List[string]]::new()
    foreach ($entry in $entries) {
        if ([string]::IsNullOrWhiteSpace($entry)) { continue }
        $trimmed = $entry.Trim()
        if (-not $trimmed) { continue }

        $sanitized = $trimmed
        $sanitized = [System.Text.RegularExpressions.Regex]::Replace($sanitized, '^(\*+\d*)', '')
        if ($sanitized.StartsWith('\\??\')) {
            $sanitized = $sanitized.Substring(4)
        }
        if (-not $sanitized) { $sanitized = $trimmed }

        $normalized.Add($sanitized) | Out-Null
    }

    return $normalized
}

function Get-BoolSignal {
    param(
        [Parameter(Mandatory)][string]$Path,
        [System.Collections.Generic.List[string]]$Errors
    )

    $exists = Test-RegistryPathSafe -Path $Path -Errors $Errors
    return [bool]$exists
}

function Invoke-Main {
    $errors = [System.Collections.Generic.List[string]]::new()

    $signals = [ordered]@{
        'CBS.RebootPending'   = Get-BoolSignal -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending' -Errors $errors
        'CBS.SessionsPending' = Get-BoolSignal -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\SessionsPending' -Errors $errors
        'WU.RebootRequired'   = Get-BoolSignal -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired' -Errors $errors
        'MSI.InProgress'      = Get-BoolSignal -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\InProgress' -Errors $errors
        'PFRO.HasEntries'     = $false
        'RenamePending'       = $false
    }

    $pfroEntries = Get-PendingFileRenameEntries -Errors $errors
    $pfroTotal = $pfroEntries.Count
    if ($pfroTotal -gt 0) {
        $signals['PFRO.HasEntries'] = $true
    }

    $renameState = Get-PendingRenameStatus -Errors $errors
    if ($renameState -and ($renameState.NameMismatch -or $renameState.TcpipMismatch)) {
        $signals['RenamePending'] = $true
    }

    $payload = [ordered]@{
        CollectedAtUtc = (Get-Date).ToUniversalTime().ToString('o')
        Signals        = [pscustomobject]$signals
        'PFRO.Sample'  = @($pfroEntries | Select-Object -First 5)
        Counts         = [pscustomobject]@{
            'PFRO.Total' = $pfroTotal
        }
        RenameDetails  = $renameState
    }

    if ($errors.Count -gt 0) {
        $payload['Errors'] = @($errors | Select-Object -First 10)
    }

    $outputPath = Export-CollectorResult -OutputDirectory $OutputDirectory -FileName 'pendingreboot.json' -Data $payload -Depth 6
    Write-Output $outputPath
}

Invoke-Main
