<#!
.SYNOPSIS
    Analyzes Kernel DMA protection collector output and classifies policy health.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$InputFolder
)

$repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
Import-Module (Join-Path -Path $repoRoot -ChildPath 'Modules/Common.psm1') -Force

function New-KernelDmaFinding {
    param(
        [string]$Check,
        [string]$Severity,
        [string]$Message,
        [object]$Evidence = $null
    )

    return [pscustomobject]@{
        Area     = 'System/Kernel DMA'
        Check    = $Check
        Severity = $Severity
        Message  = $Message
        Evidence = $Evidence
    }
}

function Get-KernelDmaPayload {
    param([string]$InputFolder)

    $file = Get-ChildItem -Path $InputFolder -Filter 'kerneldma.json' -File -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $file) { return $null }

    try {
        $data = Get-Content -Path $file.FullName -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
    } catch {
        return [pscustomobject]@{
            Error = "Failed to parse $($file.FullName): $($_.Exception.Message)"
            File  = $file.FullName
        }
    }

    return [pscustomobject]@{
        File    = $file.FullName
        Payload = $data.Payload
    }
}

$payloadResult = Get-KernelDmaPayload -InputFolder $InputFolder
if (-not $payloadResult) { return @() }
if ($payloadResult.PSObject.Properties['Error']) {
    return @(New-KernelDmaFinding -Check 'Kernel DMA protection' -Severity 'warning' -Message $payloadResult.Error -Evidence ([ordered]@{ File = $payloadResult.File }))
}

$payload = $payloadResult.Payload
if (-not $payload) {
    return @(New-KernelDmaFinding -Check 'Kernel DMA protection' -Severity 'warning' -Message 'Kernel DMA payload missing from collector output.' -Evidence ([ordered]@{ File = $payloadResult.File }))
}

$deviceGuard = $payload.DeviceGuard
$registry    = $payload.Registry
$msInfo      = $payload.MsInfo

$findings = @()

if ($deviceGuard) {
    $dgEvidence = [ordered]@{
        Status  = $deviceGuard.Status
        Message = $deviceGuard.Message
    }
    $dgEntry = $null
    if ($deviceGuard.Entries) {
        $dgEntry = $deviceGuard.Entries | Select-Object -First 1
    }
    if ($dgEntry) {
        if ($dgEntry.PSObject.Properties['VirtualizationBasedSecurityStatus']) {
            $dgEvidence.VirtualizationBasedSecurityStatus = $dgEntry.VirtualizationBasedSecurityStatus
        }
        if ($dgEntry.PSObject.Properties['SecurityServicesRunning']) {
            $dgEvidence.SecurityServicesRunning = ($dgEntry.SecurityServicesRunning -join ',')
        }
        if ($dgEntry.PSObject.Properties['AvailableSecurityProperties']) {
            $dgEvidence.AvailableSecurityProperties = ($dgEntry.AvailableSecurityProperties -join ',')
        }
        if ($dgEntry.PSObject.Properties['RequiredSecurityProperties']) {
            $dgEvidence.RequiredSecurityProperties = ($dgEntry.RequiredSecurityProperties -join ',')
        }
    }

    switch ($deviceGuard.Status) {
        'Error' {
            $findings += New-KernelDmaFinding -Check 'Device Guard state' -Severity 'warning' -Message "Unable to query Win32_DeviceGuard: $($deviceGuard.Message)" -Evidence $dgEvidence
        }
        'Info' {
            $message = if ($deviceGuard.Message) { $deviceGuard.Message } else { 'Device Guard data not available.' }
            $findings += New-KernelDmaFinding -Check 'Device Guard state' -Severity 'info' -Message $message -Evidence $dgEvidence
        }
        default {
            $findings += New-KernelDmaFinding -Check 'Device Guard state' -Severity 'good' -Message 'Device Guard information collected successfully.' -Evidence $dgEvidence
        }
    }
}

$allowValue = $null
if ($registry -and $registry.Values -and $registry.Values.PSObject.Properties['AllowDmaUnderLock']) {
    $allowValue = $registry.Values.AllowDmaUnderLock
}
$allowInt = ConvertTo-NullableInt $allowValue

$registryEvidence = [ordered]@{
    Path   = if ($registry) { $registry.Path } else { $null }
    Status = if ($registry) { $registry.Status } else { 'Missing' }
    AllowDmaUnderLock = $allowValue
}
if ($registry -and $registry.Values) {
    foreach ($property in $registry.Values.PSObject.Properties) {
        if ($property.Name -eq 'AllowDmaUnderLock') { continue }
        $registryEvidence[$property.Name] = $property.Value
    }
}

if ($registry) {
    switch ($registry.Status) {
        'Error' {
            $findings += New-KernelDmaFinding -Check 'Kernel DMA registry policy' -Severity 'warning' -Message "Unable to read KernelDMAProtection policy: $($registry.Message)" -Evidence $registryEvidence
        }
        'Info' {
            $message = if ($registry.Message) { $registry.Message } else { 'Kernel DMA registry policy not present.' }
            $findings += New-KernelDmaFinding -Check 'Kernel DMA registry policy' -Severity 'info' -Message $message -Evidence $registryEvidence
        }
        default {
            if ($allowInt -eq 0) {
                $findings += New-KernelDmaFinding -Check 'Kernel DMA registry policy' -Severity 'good' -Message 'AllowDmaUnderLock = 0 (DMA blocked while locked).' -Evidence $registryEvidence
            } elseif ($allowInt -eq 1) {
                $findings += New-KernelDmaFinding -Check 'Kernel DMA registry policy' -Severity 'high' -Message 'AllowDmaUnderLock = 1 (DMA allowed when locked).' -Evidence $registryEvidence
            } else {
                $findings += New-KernelDmaFinding -Check 'Kernel DMA registry policy' -Severity 'info' -Message 'Kernel DMA registry policy captured but AllowDmaUnderLock value not present.' -Evidence $registryEvidence
            }
        }
    }
} else {
    $findings += New-KernelDmaFinding -Check 'Kernel DMA registry policy' -Severity 'warning' -Message 'Kernel DMA registry policy missing from collector payload.' -Evidence $registryEvidence
}

if ($msInfo -and $msInfo.Status -and $msInfo.Status -ne 'Skipped') {
    $msInfoEvidence = [ordered]@{
        Status = $msInfo.Status
        Message = $msInfo.Message
        Lines   = if ($msInfo.Lines) { ($msInfo.Lines | Select-Object -First 10) } else { @() }
    }
    $severity = if ($msInfo.Status -eq 'Success') { 'info' } elseif ($msInfo.Status -eq 'Timeout') { 'warning' } else { 'info' }
    $findings += New-KernelDmaFinding -Check 'msinfo32 fallback' -Severity $severity -Message "msinfo32 fallback status: $($msInfo.Status)" -Evidence $msInfoEvidence
}

return $findings
