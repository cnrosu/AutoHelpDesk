function Get-KernelDmaProtection {
<#!
.SYNOPSIS
    Returns Kernel DMA Protection status with multiple fallbacks and raw evidence.

.DESCRIPTION
    Gold-standard PS 5.1 routine to determine Kernel DMA Protection:
     1) Try msinfo32.exe /report (headless) with +systemsummary and parse:
          - "Kernel DMA Protection" -> On/Off/Not supported/…
          - (bonus) "Device Encryption Support", "Virtualization-based security", "DMA Remapping", "Secure Boot State"
     2) If msinfo is unavailable or inconclusive, collect registry evidence:
          - HKLM:\SOFTWARE\Policies\Microsoft\Windows\Kernel DMA Protection\DeviceEnumerationPolicy (GPO)
          - HKLM:\SYSTEM\CurrentControlSet\Control\DmaSecurity\AllowDmaUnderLock (platform/OS toggle)
     3) Gate by OS version (feature introduced on modern Windows 10; older OS => Not supported)

    Returns a [pscustomobject] with Status, Source, MsInfo details (if any), Registry evidence, OS build, and Notes.

.NOTES
    - No admin required.
    - Runs headless; no msinfo UI pops.
    - Designed for Windows PowerShell 5.1; works on PowerShell 7+ too.
#>

    function Invoke-HeadlessMsInfo {
        param(
            [int]$TimeoutSeconds = 30
        )

        $system32 = Join-Path -Path $env:WINDIR -ChildPath 'System32'
        $msinfo = Join-Path -Path $system32 -ChildPath 'msinfo32.exe'
        if (-not (Test-Path -LiteralPath $msinfo)) {
            return [pscustomobject]@{
                Succeeded = $false
                Path      = $null
                Error     = 'msinfo32.exe not found'
            }
        }

        $tempPath = [IO.Path]::ChangeExtension([IO.Path]::GetTempFileName(), '.txt')
        $nfoPath = [IO.Path]::ChangeExtension($tempPath, '.nfo')

        $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
        $startInfo.FileName = $msinfo
        $startInfo.Arguments = "/nfo `"$nfoPath`" /report `"$tempPath`" /categories +systemsummary"
        $startInfo.UseShellExecute = $false

        $process = [System.Diagnostics.Process]::Start($startInfo)
        if (-not $process) {
            return [pscustomobject]@{
                Succeeded = $false
                Path      = $null
                Error     = 'Failed to start msinfo32.exe'
            }
        }

        if (-not $process.WaitForExit($TimeoutSeconds * 1000)) {
            try { $process.Kill() | Out-Null } catch { }
            return [pscustomobject]@{
                Succeeded = $false
                Path      = $tempPath
                Error     = "msinfo32 timed out after $TimeoutSeconds s"
            }
        }

        if (-not (Test-Path -LiteralPath $tempPath)) {
            return [pscustomobject]@{
                Succeeded = $false
                Path      = $tempPath
                Error     = 'msinfo32 did not produce a report'
            }
        }

        $text = Get-Content -LiteralPath $tempPath -Raw -ErrorAction SilentlyContinue
        [pscustomobject]@{
            Succeeded = [bool]$text
            Path      = $tempPath
            Text      = $text
            Error     = $(if ($text) { $null } else { 'Empty report' })
        }
    }

    function Parse-MsInfoScalar {
        param(
            [string]$Text,
            [string[]]$CandidateKeys
        )

        if ([string]::IsNullOrWhiteSpace($Text)) {
            return $null
        }

        $options = [System.Text.RegularExpressions.RegexOptions]::IgnoreCase -bor [System.Text.RegularExpressions.RegexOptions]::Multiline
        foreach ($key in $CandidateKeys) {
            if ([string]::IsNullOrWhiteSpace($key)) { continue }
            $pattern = "^(?:\s*)$([regex]::Escape($key))\s*:\s*(.+?)\s*$"
            $match = [regex]::Match($Text, $pattern, $options)
            if ($match.Success) {
                return $match.Groups[1].Value.Trim()
            }
        }

        return $null
    }

    function Get-RegistryValue {
        param(
            [string]$Path,
            [string]$Name
        )

        if ([string]::IsNullOrWhiteSpace($Path) -or [string]::IsNullOrWhiteSpace($Name)) {
            return $null
        }

        try {
            if (Get-Item -LiteralPath $Path -ErrorAction Stop) {
                return Get-ItemPropertyValue -LiteralPath $Path -Name $Name -ErrorAction Stop
            }
        } catch {
            return $null
        }

        return $null
    }

    $osInstance = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue
    $osVersion = $osInstance.Version
    $buildNumber = $null
    if ($osInstance -and $osInstance.PSObject.Properties['BuildNumber']) {
        [void][int]::TryParse($osInstance.BuildNumber, [ref]$buildNumber)
    }

    $likelySupported = $false
    if ($null -ne $buildNumber) {
        $likelySupported = ($buildNumber -ge 17134)
    }

    $msInfoResult = Invoke-HeadlessMsInfo -TimeoutSeconds 35
    $msInfoDetails = $null
    $kernelDmaValue = $null
    $dmaRemapping = $null
    $virtualization = $null
    $deviceEncryption = $null
    $secureBoot = $null

    if ($msInfoResult.Succeeded -and $msInfoResult.Text) {
        $text = $msInfoResult.Text
        $kernelDmaValue = Parse-MsInfoScalar -Text $text -CandidateKeys @('Kernel DMA Protection')
        $dmaRemapping = Parse-MsInfoScalar -Text $text -CandidateKeys @('DMA Remapping')
        $virtualization = Parse-MsInfoScalar -Text $text -CandidateKeys @('Virtualization-based security','Virtualization Based Security')
        $deviceEncryption = Parse-MsInfoScalar -Text $text -CandidateKeys @('Device Encryption Support')
        $secureBoot = Parse-MsInfoScalar -Text $text -CandidateKeys @('Secure Boot State','Secure Boot')

        $msInfoDetails = [pscustomobject]@{
            KernelDmaProtection = $kernelDmaValue
            DmaRemapping        = $dmaRemapping
            Virtualization      = $virtualization
            DeviceEncryption    = $deviceEncryption
            SecureBoot          = $secureBoot
            ReportPath          = $msInfoResult.Path
            Error               = $msInfoResult.Error
        }
    }

    $policyPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Kernel DMA Protection'
    $platformPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\DmaSecurity'

    $policyValue = Get-RegistryValue -Path $policyPath -Name 'DeviceEnumerationPolicy'
    $allowUnderLock = Get-RegistryValue -Path $platformPath -Name 'AllowDmaUnderLock'

    $registryEvidence = [pscustomobject]@{
        PolicyPath              = $policyPath
        DeviceEnumerationPolicy = $policyValue
        PlatformPath            = $platformPath
        AllowDmaUnderLock       = $allowUnderLock
    }

    $status = 'Unknown'
    $source = 'None'
    $notes = [System.Collections.Generic.List[string]]::new()

    if ($kernelDmaValue) {
        $source = 'MsInfo32'
        switch -Regex ($kernelDmaValue) {
            '^(\s*)on(\s*)$'         { $status = 'On'; break }
            '^(\s*)off(\s*)$'        { $status = 'Off'; break }
            'not\s*support'          { $status = 'NotSupported'; break }
            default                   { $status = 'Unknown' }
        }
    } else {
        $source = 'RegistryInference'
        if (-not $likelySupported) {
            $status = 'NotSupported'
            if ($null -ne $buildNumber) {
                $notes.Add("OS build $buildNumber predates broad Kernel DMA Protection availability (Windows 10 1803+).") | Out-Null
            } else {
                $notes.Add('OS build predates broad Kernel DMA Protection availability (Windows 10 1803+).') | Out-Null
            }
        } elseif ($null -ne $policyValue -or $null -ne $allowUnderLock) {
            $status = 'Inconclusive'
            $notes.Add('Policy or platform toggles present. Kernel DMA Protection state requires msinfo32 for confirmation.') | Out-Null
        } else {
            $status = 'Unknown'
            $notes.Add('No msinfo32 result and no registry evidence found.') | Out-Null
        }
    }

    if ($secureBoot) {
        $notes.Add("Secure Boot: $secureBoot") | Out-Null
    }
    if ($dmaRemapping) {
        $notes.Add("DMA Remapping: $dmaRemapping") | Out-Null
    }
    if ($virtualization) {
        $notes.Add("VBS: $virtualization") | Out-Null
    }
    if ($deviceEncryption) {
        $notes.Add("Device Encryption: $deviceEncryption") | Out-Null
    }

    $notesArray = @()
    if ($notes.Count -gt 0) {
        $notesArray = $notes.ToArray()
    }

    [pscustomobject]@{
        KernelDmaProtection = $status
        Source              = $source
        MsInfo              = $msInfoDetails
        Registry            = $registryEvidence
        OS                  = [pscustomobject]@{ Version = $osVersion; Build = $buildNumber }
        Notes               = $notesArray
    }
}

Export-ModuleMember -Function Get-KernelDmaProtection
