<#!
.SYNOPSIS
    Helper functions for gathering Kernel DMA protection state using fast data sources.
.DESCRIPTION
    Provides reusable functions to query Device Guard (Win32_DeviceGuard),
    registry policy, and an optional msinfo32 fallback with a timeout.
#>

function ConvertTo-PlainValue {
    param(
        [object]$Value
    )

    if ($null -eq $Value) { return $null }

    if ($Value -is [string]) {
        $text = $Value.Trim()
        return ($text -replace '\s+', ' ')
    }

    if ($Value -is [System.Collections.IEnumerable] -and -not ($Value -is [string])) {
        $list = @()
        foreach ($item in $Value) {
            if ($null -eq $item) { continue }
            $list += [string]$item
        }
        return $list
    }

    return $Value
}

function Get-KernelDmaDeviceGuardState {
    try {
        $instances = Get-CimInstance -Namespace 'root/Microsoft/Windows/DeviceGuard' -ClassName Win32_DeviceGuard -ErrorAction Stop
    } catch {
        return [pscustomobject]@{
            Status  = 'Error'
            Message = $_.Exception.Message
            Entries = @()
            HasData = $false
        }
    }

    if (-not $instances) {
        return [pscustomobject]@{
            Status  = 'Info'
            Message = 'Not supported / no data'
            Entries = @()
            HasData = $false
        }
    }

    $converted = @()
    $hasData = $false
    foreach ($instance in $instances) {
        $entry = [ordered]@{}
        foreach ($property in $instance.PSObject.Properties) {
            if ($property.Name -like 'Cim*' -or $property.Name -like 'PS*') { continue }
            $plain = ConvertTo-PlainValue $property.Value
            if ($plain -is [System.Collections.IEnumerable] -and -not ($plain -is [string])) {
                $plain = @($plain)
            }
            $entry[$property.Name] = $plain
            if ($null -ne $plain) {
                if ($plain -is [System.Collections.IEnumerable] -and -not ($plain -is [string])) {
                    if ($plain.Count -gt 0) { $hasData = $true }
                } else {
                    $hasData = $true
                }
            }
        }
        $converted += [pscustomobject]$entry
    }

    if (-not $hasData) {
        return [pscustomobject]@{
            Status  = 'Info'
            Message = 'Not supported / no data'
            Entries = @()
            HasData = $false
        }
    }

    return [pscustomobject]@{
        Status  = 'Success'
        Message = $null
        Entries = $converted
        HasData = $true
    }
}

function Get-KernelDmaRegistryPolicy {
    $path = 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\KernelDMAProtection'
    if (-not (Test-Path -Path $path)) {
        return [pscustomobject]@{
            Status  = 'Info'
            Message = 'Registry key not found'
            Path    = $path
            Values  = @{}
            HasData = $false
        }
    }

    try {
        $values = Get-ItemProperty -Path $path -ErrorAction Stop
    } catch {
        return [pscustomobject]@{
            Status  = 'Error'
            Message = $_.Exception.Message
            Path    = $path
            Values  = @{}
            HasData = $false
        }
    }

    $result = [ordered]@{}
    foreach ($property in $values.PSObject.Properties) {
        if ($property.Name -like 'PS*' -or $property.Name -like 'Cim*') { continue }
        $result[$property.Name] = ConvertTo-PlainValue $property.Value
    }

    $hasData = ($result.Count -gt 0)

    return [pscustomobject]@{
        Status  = 'Success'
        Message = $null
        Path    = $path
        Values  = [pscustomobject]$result
        HasData = $hasData
    }
}

function Get-KernelDmaMsInfoFallback {
    param(
        [int]$TimeoutSeconds = 4
    )

    $tempPath = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath (([System.Guid]::NewGuid().ToString()) + '.txt')
    $arguments = @('/report', $tempPath, '/categories', 'Hardware Resources\\DMA')

    try {
        $process = Start-Process -FilePath 'msinfo32.exe' -ArgumentList $arguments -PassThru -WindowStyle Hidden -ErrorAction Stop
    } catch {
        return [pscustomobject]@{
            Status  = 'Error'
            Message = $_.Exception.Message
            Lines   = @()
        }
    }

    $timeoutMilliseconds = [math]::Max(1000, $TimeoutSeconds * 1000)
    $completed = $false
    try {
        $completed = $process.WaitForExit($timeoutMilliseconds)
    } catch {
        Write-Verbose -Message ("WaitForExit on msinfo32.exe failed: {0}" -f $_.Exception.Message)
        $completed = $false
    }

    if (-not $completed) {
        try { $process.Kill() | Out-Null } catch { Write-Verbose -Message ("Failed to terminate msinfo32.exe after timeout: {0}" -f $_.Exception.Message) }
        return [pscustomobject]@{
            Status  = 'Timeout'
            Message = "msinfo32.exe exceeded ${TimeoutSeconds}s timeout"
            Lines   = @()
        }
    }

    if (-not (Test-Path -Path $tempPath)) {
        return [pscustomobject]@{
            Status  = 'Error'
            Message = "msinfo32.exe did not produce output"
            Lines   = @()
        }
    }

    try {
        $content = Get-Content -Path $tempPath -ErrorAction Stop
    } catch {
        Write-Verbose -Message ("Failed to read msinfo32.exe output from '{0}': {1}" -f $tempPath, $_.Exception.Message)
        $content = @()
    }

    Remove-Item -Path $tempPath -ErrorAction SilentlyContinue

    return [pscustomobject]@{
        Status  = 'Success'
        Message = $null
        Lines   = @($content)
    }
}

function Get-KernelDmaStatusData {
    param(
        [int]$MsInfoTimeoutSeconds = 4
    )

    $deviceGuard = Get-KernelDmaDeviceGuardState
    $registry    = Get-KernelDmaRegistryPolicy

    $fastPathAvailable = $deviceGuard.HasData -or $registry.HasData -or ($deviceGuard.Status -eq 'Info' -and $deviceGuard.Message)

    $msInfo = $null
    if (-not $fastPathAvailable) {
        $msInfo = Get-KernelDmaMsInfoFallback -TimeoutSeconds $MsInfoTimeoutSeconds
    } else {
        $msInfo = [pscustomobject]@{
            Status  = 'Skipped'
            Message = 'Fast path data collected'
            Lines   = @()
        }
    }

    return [pscustomobject]@{
        DeviceGuard = $deviceGuard
        Registry    = $registry
        MsInfo      = $msInfo
    }
}
