<#!
.SYNOPSIS
    Collects signals indicating whether a reboot is pending on the device.
#>
[CmdletBinding()]
param(
    [Parameter()]
    [string]$OutputDirectory = (Join-Path -Path (Split-Path -Parent $PSCommandPath) -ChildPath '..\\output')
)

. (Join-Path -Path $PSScriptRoot -ChildPath '..\\CollectorCommon.ps1')

function Test-RegistryPath {
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )

    try {
        return Test-Path -LiteralPath $Path -ErrorAction Stop
    } catch {
        return $false
    }
}

function Get-RegistryValueStrings {
    param(
        [Parameter(Mandatory)]
        [string]$Path,
        [Parameter(Mandatory)]
        [string]$ValueName
    )

    try {
        if (-not (Test-Path -LiteralPath $Path)) { return @() }
        $value = Get-ItemProperty -LiteralPath $Path -Name $ValueName -ErrorAction Stop | Select-Object -ExpandProperty $ValueName -ErrorAction Stop
        if ($null -eq $value) { return @() }
        if ($value -is [string]) { return @($value) }
        if ($value -is [System.Collections.IEnumerable]) {
            return ($value | ForEach-Object { [string]$_ })
        }
        return @([string]$value)
    } catch {
        return @([pscustomobject]@{ Error = $_.Exception.Message })
    }
}

function Get-RegistryValueAsString {
    param(
        [Parameter(Mandatory)]
        [string]$Path,
        [Parameter(Mandatory)]
        [string]$ValueName
    )

    try {
        if (-not (Test-Path -LiteralPath $Path)) { return $null }
        $value = Get-ItemProperty -LiteralPath $Path -Name $ValueName -ErrorAction Stop | Select-Object -ExpandProperty $ValueName -ErrorAction Stop
        if ($null -eq $value) { return $null }
        return [string]$value
    } catch {
        return $null
    }
}

function Get-PendingRenameStatus {
    $activeName = Get-RegistryValueAsString -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\ComputerName\\ActiveComputerName' -ValueName 'ComputerName'
    $pendingName = Get-RegistryValueAsString -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\ComputerName\\ComputerName' -ValueName 'ComputerName'

    $tcpipCurrent = Get-RegistryValueAsString -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters' -ValueName 'Hostname'
    $tcpipPending = Get-RegistryValueAsString -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters' -ValueName 'NV Hostname'

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

function Get-PendingFileOperations {
    $sessionManagerPath = 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Session Manager'
    $primary = Get-RegistryValueStrings -Path $sessionManagerPath -ValueName 'PendingFileRenameOperations'

    return [pscustomobject]@{
        PendingFileRenameOperations = $primary
    }
}

function Get-PendingRebootIndicators {
    $registryPaths = @(
        [pscustomobject]@{ Name = 'WindowsUpdateRebootRequired'; Path = 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate\\Auto Update\\RebootRequired' },
        [pscustomobject]@{ Name = 'ComponentBasedServicingRebootPending'; Path = 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Component Based Servicing\\RebootPending' },
        [pscustomobject]@{ Name = 'ComponentBasedServicingRebootInProgress'; Path = 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Component Based Servicing\\RebootInProgress' },
        [pscustomobject]@{ Name = 'ComponentBasedServicingPackagesPending'; Path = 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Component Based Servicing\\PackagesPending' },
        [pscustomobject]@{ Name = 'ComponentBasedServicingSessionsPending'; Path = 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Component Based Servicing\\SessionsPending' },
        [pscustomobject]@{ Name = 'UpdateExeVolatile'; Path = 'HKLM:\\SOFTWARE\\Microsoft\\Updates\\UpdateExeVolatile' },
        [pscustomobject]@{ Name = 'ServerManagerCurrentRebootAttempts'; Path = 'HKLM:\\SOFTWARE\\Microsoft\\ServerManager\\CurrentRebootAttempts' }
    )

    $results = [System.Collections.Generic.List[pscustomobject]]::new()
    foreach ($entry in $registryPaths) {
        $exists = Test-RegistryPath -Path $entry.Path
        $results.Add([pscustomobject]@{
            Name    = $entry.Name
            Path    = $entry.Path
            Present = $exists
        })
    }

    return $results.ToArray()
}

function Invoke-Main {
    $payload = [ordered]@{
        Indicators          = Get-PendingRebootIndicators
        PendingFileRenames  = Get-PendingFileOperations
        ComputerRenameState = Get-PendingRenameStatus
    }

    $result = New-CollectorMetadata -Payload $payload
    $outputPath = Export-CollectorResult -OutputDirectory $OutputDirectory -FileName 'pendingreboot.json' -Data $result -Depth 6
    Write-Output $outputPath
}

Invoke-Main
