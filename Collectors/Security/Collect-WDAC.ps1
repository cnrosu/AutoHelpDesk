<#!
.SYNOPSIS
    Collects Windows Defender Application Control (WDAC) configuration data.
#>
[CmdletBinding()]
param(
    [Parameter()]
    [string]$OutputDirectory = (Join-Path -Path (Split-Path -Parent $PSCommandPath) -ChildPath '..\\output')
)

. (Join-Path -Path $PSScriptRoot -ChildPath '..\\CollectorCommon.ps1')

function Get-DeviceGuardPolicy {
    try {
        $dg = Get-CimInstance -Namespace 'root/Microsoft/Windows/DeviceGuard' -ClassName Win32_DeviceGuard -ErrorAction Stop
        return $dg | Select-Object SecurityServicesRunning, SecurityServicesConfigured, RequiredSecurityProperties, AvailableSecurityProperties, Version
    } catch {
        return [PSCustomObject]@{
            Source = 'Win32_DeviceGuard'
            Error  = $_.Exception.Message
        }
    }
}

function Get-WdacRegistrySnapshot {
    $paths = @(
        'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Policy',
        'HKLM:\SYSTEM\CurrentControlSet\Control\CI'
    )

    $result = [System.Collections.Generic.List[pscustomobject]]::new()
    foreach ($path in $paths) {
        try {
            $values = Get-ItemProperty -Path $path -ErrorAction Stop | Select-Object * -ExcludeProperty PS*, CIM*, PSEdition
            $result.Add([PSCustomObject]@{
                Path   = $path
                Values = $values
            })
        } catch {
            $result.Add([PSCustomObject]@{
                Path  = $path
                Error = $_.Exception.Message
            })
        }
    }

    return $result.ToArray()
}

function Get-SmartAppControlState {
    $path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\SmartAppControl'
    try {
        if (-not (Test-Path -Path $path)) {
            return $null
        }

        $values = Get-ItemProperty -Path $path -ErrorAction Stop | Select-Object * -ExcludeProperty PS*, CIM*, PSEdition
        return [ordered]@{
            Path   = $path
            Values = $values
        }
    } catch {
        return [ordered]@{
            Path  = $path
            Error = $_.Exception.Message
        }
    }
}

function Get-AppTrustPosture {
    [CmdletBinding()]
    param()

    $result = [ordered]@{
        OSVersion   = [string][Environment]::OSVersion.Version
        IsWin11     = $false
        SAC         = $null
        WDAC        = [ordered]@{
            FilesPresent = $false
            CiStatus     = $null
            UmciStatus   = $null
            CipCount     = 0
            SipolicyP7b  = $false
            CipSamples   = @()
        }
        Decision    = $null
        Reason      = $null
        Remediation = $null
    }

    $ver = [Version]$result.OSVersion
    $result.IsWin11 = ($ver -ge [Version]'10.0.22621.0')

    $sacVal = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Policy' -Name VerifiedAndReputablePolicyState -ErrorAction SilentlyContinue).VerifiedAndReputablePolicyState
    if ($null -eq $sacVal) { $sacVal = -1 }
    $result.SAC = [int]$sacVal

    $sip = Test-Path 'C:\Windows\System32\CodeIntegrity\SIPolicy.p7b'
    $cip = @(Get-ChildItem 'C:\Windows\System32\CodeIntegrity\CiPolicies\Active\' -ErrorAction SilentlyContinue | Where-Object { $_.Extension -ieq '.cip' })
    $result.WDAC.SipolicyP7b = $sip
    $result.WDAC.CipCount    = $cip.Count
    $result.WDAC.CipSamples  = $cip | Select-Object -First 3 -ExpandProperty Name
    $result.WDAC.FilesPresent = $sip -or ($cip.Count -gt 0)

    try {
        $dg = Get-CimInstance -Namespace root\Microsoft\Windows\DeviceGuard -Class Win32_DeviceGuard -ErrorAction Stop
        $result.WDAC.CiStatus   = [int]$dg.CodeIntegrityPolicyEnforcementStatus
        $result.WDAC.UmciStatus = [int]$dg.UserModeCodeIntegrityPolicyEnforcementStatus
    } catch {
        $result.WDAC.CiStatus   = -1
        $result.WDAC.UmciStatus = -1
    }

    if (-not $result.IsWin11) {
        $result.Decision = 'NA'
        $result.Reason   = 'Windows 10 or earlier; SAC not applicable.'
        return [pscustomobject]$result
    }

    $hasWDAC = $result.WDAC.FilesPresent
    $ci = $result.WDAC.CiStatus
    $um = $result.WDAC.UmciStatus

    $SAC_On  = ($result.SAC -eq 2)
    $SAC_Eval = ($result.SAC -eq 1)
    $SAC_Off = ($result.SAC -eq 0)

    if ($hasWDAC -and (($ci -eq 1) -or ($um -eq 1))) {
        $result.Decision = 'SUPPRESS'
        $result.Reason   = 'WDAC present and Enforced (kernel and/or UMCI); SAC superseded.'
        return [pscustomobject]$result
    }

    if ($hasWDAC -and ($ci -eq 2) -and ($um -in 0, 2)) {
        $result.Decision = 'INFO'
        $result.Reason   = 'WDAC present in Audit; UMCI Off/Audit.'
        $result.Remediation = @(
            @{ type = 'text'; title = 'What’s happening'; content = 'An App Control for Business (WDAC) policy is present in Audit mode (kernel). UMCI is Off. SAC is suppressed because WDAC governs app trust posture.' },
            @{ type = 'text'; title = 'Promote to enforce (admins)'; content = 'Update the WDAC policy to Enforced (and enable UMCI if required). Redeploy and reboot, then verify status.' },
            @{ type = 'code'; lang = 'powershell'; content = 'Get-CimInstance -Namespace root\Microsoft\Windows\DeviceGuard -Class Win32_DeviceGuard | Select CodeIntegrityPolicyEnforcementStatus, UserModeCodeIntegrityPolicyEnforcementStatus' },
            @{ type = 'note'; content = 'Values: 0=Off, 1=Enforce, 2=Audit.' }
        ) | ConvertTo-Json -Depth 6
        return [pscustomobject]$result
    }

    if (-not $hasWDAC) {
        if ($SAC_On) {
            $result.Decision = 'OK'
            $result.Reason   = 'SAC On; no WDAC present.'
            return [pscustomobject]$result
        }
        if ($SAC_Eval) {
            $result.Decision = 'INFO'
            $result.Reason   = 'SAC in Evaluation; Windows may auto-enable.'
            $result.Remediation = @(
                @{ type = 'note'; content = 'SAC Evaluation observes app installs and may turn On automatically if it won’t cause issues.' }
            ) | ConvertTo-Json -Depth 6
            return [pscustomobject]$result
        }
        if ($SAC_Off) {
            $result.Decision = 'MEDIUM'
            $result.Reason   = 'SAC Off on Windows 11 and no WDAC present.'
            $result.Remediation = @(
                @{ type = 'text'; title = 'Turn on SAC'; content = 'Windows Security → App & browser control → Smart App Control → On. If SAC was previously turned Off or device was upgraded, a Reset/clean install may be required.' },
                @{ type = 'code'; lang = 'powershell'; content = 'Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\CI\Policy -Name VerifiedAndReputablePolicyState | Select VerifiedAndReputablePolicyState' },
                @{ type = 'note'; content = 'In managed environments, consider deploying App Control for Business (WDAC) instead of SAC.' }
            ) | ConvertTo-Json -Depth 6
            return [pscustomobject]$result
        }
    }

    $result.Decision = 'INFO'
    $result.Reason   = 'Indeterminate posture (check SAC state and WDAC artifacts).'
    return [pscustomobject]$result
}

function Invoke-Main {
    $payload = [ordered]@{
        DeviceGuard       = Get-DeviceGuardPolicy
        Registry          = Get-WdacRegistrySnapshot
        SmartAppControl   = Get-SmartAppControlState
        AppTrustPosture   = Get-AppTrustPosture
    }

    $result = New-CollectorMetadata -Payload $payload
    $outputPath = Export-CollectorResult -OutputDirectory $OutputDirectory -FileName 'wdac.json' -Data $result -Depth 6
    Write-Output $outputPath
}

Invoke-Main
