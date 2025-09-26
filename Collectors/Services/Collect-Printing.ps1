<#!
.SYNOPSIS
    Collects comprehensive print subsystem data for AutoHelpDesk heuristics.
.DESCRIPTION
    Captures spooler service state, printer inventory, driver/package details,
    Point-and-Print policy posture, recent PrintService event activity, and
    network reachability tests for printer hosts.
#>
[CmdletBinding()]
param(
    [Parameter()]
    [string]$OutputDirectory = (Join-Path -Path (Split-Path -Parent $PSCommandPath) -ChildPath '..\\output')
)

. (Join-Path -Path $PSScriptRoot -ChildPath '..\\CollectorCommon.ps1')

function Get-SpoolerState {
    $info = [ordered]@{
        Name             = 'Spooler'
        DisplayName      = $null
        Status           = $null
        StartMode        = $null
        StartType        = $null
        StartAccount     = $null
        AcceptPause      = $null
        AcceptStop       = $null
        Error            = $null
    }

    try {
        $service = Get-CimInstance -ClassName Win32_Service -Filter "Name='Spooler'" -ErrorAction Stop
    } catch {
        try {
            $service = Get-WmiObject -Class Win32_Service -Filter "Name='Spooler'" -ErrorAction Stop
        } catch {
            try {
                $service = Get-Service -Name Spooler -ErrorAction Stop
            } catch {
                $info.Error = $_.Exception.Message
                return $info
            }
        }
    }

    if (-not $service) { return $info }

    $info.DisplayName  = [string]$service.DisplayName
    $info.Status       = if ($service.PSObject.Properties['State']) { [string]$service.State } elseif ($service.PSObject.Properties['Status']) { [string]$service.Status } else { [string]$service.Status } 
    $info.StartMode    = if ($service.PSObject.Properties['StartMode']) { [string]$service.StartMode } elseif ($service.PSObject.Properties['StartType']) { [string]$service.StartType } else { $null }
    $info.StartType    = if ($service.PSObject.Properties['StartType']) { [string]$service.StartType } elseif ($service.PSObject.Properties['StartMode']) { [string]$service.StartMode } else { $null }
    if ($service.PSObject.Properties['StartName']) { $info.StartAccount = [string]$service.StartName }
    if ($service.PSObject.Properties['AcceptPause']) { $info.AcceptPause = [bool]$service.AcceptPause }
    if ($service.PSObject.Properties['AcceptStop']) { $info.AcceptStop = [bool]$service.AcceptStop }

    return $info
}

function ConvertTo-OrderedDictionary {
    param([object]$InputObject)

    if (-not $InputObject) { return $null }
    $dict = [ordered]@{}
    foreach ($prop in $InputObject.PSObject.Properties) {
        if ($prop.Name -match '^PS[A-Z]') { continue }
        $dict[$prop.Name] = $prop.Value
    }
    return $dict
}

function Get-PrinterDictionaries {
    $result = [ordered]@{
        Printers       = @()
        DefaultPrinter = $null
        Errors         = @()
    }

    $printersRaw = @()
    try {
        $printersRaw = Get-Printer -ErrorAction Stop
    } catch {
        $result.Errors += "Get-Printer failed: $($_.Exception.Message)"
        try {
            $printersRaw = Get-CimInstance -ClassName Win32_Printer -ErrorAction Stop
        } catch {
            $result.Errors += "Win32_Printer fallback failed: $($_.Exception.Message)"
            $printersRaw = @()
        }
    }

    $portsByName = @{}
    try {
        foreach ($port in (Get-PrinterPort -ErrorAction Stop)) {
            if ($null -ne $port) {
                $portsByName[[string]$port.Name] = $port
            }
        }
    } catch {
        $result.Errors += "Get-PrinterPort failed: $($_.Exception.Message)"
    }

    $driversByName = @{}
    try {
        foreach ($driver in (Get-PrinterDriver -ErrorAction Stop)) {
            if ($null -ne $driver) {
                $driversByName[[string]$driver.Name] = $driver
            }
        }
    } catch {
        $result.Errors += "Get-PrinterDriver failed: $($_.Exception.Message)"
    }

    $now = Get-Date
    $printerDictionaries = @()
    foreach ($printer in $printersRaw) {
        if (-not $printer) { continue }

        $printerName = [string]$printer.Name
        if (-not $printerName) { continue }

        $portName = if ($printer.PSObject.Properties['PortName']) { [string]$printer.PortName } else { '' }
        $driverName = if ($printer.PSObject.Properties['DriverName']) { [string]$printer.DriverName } else { '' }
        $computerName = if ($printer.PSObject.Properties['ComputerName']) { [string]$printer.ComputerName } else { '' }
        $workOffline = $null
        if ($printer.PSObject.Properties['WorkOffline']) {
            try { $workOffline = [bool]$printer.WorkOffline } catch { $workOffline = $null }
        }
        $defaultPrinter = $false
        if ($printer.PSObject.Properties['Default']) {
            try { $defaultPrinter = [bool]$printer.Default } catch { $defaultPrinter = $false }
        }
        if ($defaultPrinter) { $result.DefaultPrinter = $printerName }

        $portObject = $null
        if ($portName -and $portsByName.ContainsKey($portName)) {
            $portObject = $portsByName[$portName]
        }

        $driverObject = $null
        if ($driverName -and $driversByName.ContainsKey($driverName)) {
            $driverObject = $driversByName[$driverName]
        }

        $configuration = $null
        try {
            $configRaw = $null
            if ($printer.PSObject.Properties['ComputerName'] -and $printer.ComputerName) {
                $configRaw = Get-PrintConfiguration -PrinterName $printerName -ComputerName $printer.ComputerName -ErrorAction Stop
            } else {
                $configRaw = Get-PrintConfiguration -PrinterName $printerName -ErrorAction Stop
            }
            if ($configRaw) { $configuration = ConvertTo-OrderedDictionary $configRaw }
        } catch {
            $result.Errors += "Get-PrintConfiguration ($printerName) failed: $($_.Exception.Message)"
        }

        $jobs = @()
        try {
            $jobsRaw = $null
            if ($printer.PSObject.Properties['ComputerName'] -and $printer.ComputerName) {
                $jobsRaw = Get-PrintJob -PrinterName $printerName -ComputerName $printer.ComputerName -ErrorAction Stop
            } else {
                $jobsRaw = Get-PrintJob -PrinterName $printerName -ErrorAction Stop
            }
            foreach ($job in $jobsRaw) {
                if (-not $job) { continue }
                $submitted = $null
                if ($job.PSObject.Properties['SubmittedTime'] -and $job.SubmittedTime) {
                    try { $submitted = [datetime]$job.SubmittedTime } catch { $submitted = $null }
                }
                $ageMinutes = $null
                if ($submitted) {
                    $ageMinutes = [math]::Round(($now - $submitted).TotalMinutes,2)
                }
                $jobs += [ordered]@{
                    Id            = $job.Id
                    DocumentName  = [string]$job.DocumentName
                    JobStatus     = [string]$job.JobStatus
                    JobSize       = $job.JobSize
                    PagesPrinted  = $job.PagesPrinted
                    TotalPages    = $job.TotalPages
                    SubmittedBy   = if ($job.PSObject.Properties['UserName']) { [string]$job.UserName } else { $null }
                    SubmittedTime = if ($submitted) { $submitted.ToString('o') } else { $null }
                    AgeMinutes    = $ageMinutes
                }
            }
        } catch {
            $result.Errors += "Get-PrintJob ($printerName) failed: $($_.Exception.Message)"
        }

        $portDict = $null
        if ($portObject) {
            $portDict = [ordered]@{}
            foreach ($prop in $portObject.PSObject.Properties) {
                if ($prop.Name -match '^PS[A-Z]') { continue }
                $portDict[$prop.Name] = $prop.Value
            }
        }

        $driverDict = $null
        if ($driverObject) {
            $driverDict = [ordered]@{}
            foreach ($prop in $driverObject.PSObject.Properties) {
                if ($prop.Name -match '^PS[A-Z]') { continue }
                $driverDict[$prop.Name] = $prop.Value
            }
        }

        $connectionInfo = Get-PrinterConnectionInfo -Printer $printer -Port $portObject

        $printerDict = [ordered]@{
            Name           = $printerName
            ShareName      = if ($printer.PSObject.Properties['ShareName']) { [string]$printer.ShareName } else { $null }
            ComputerName   = $computerName
            Comment        = if ($printer.PSObject.Properties['Comment']) { [string]$printer.Comment } else { $null }
            Location       = if ($printer.PSObject.Properties['Location']) { [string]$printer.Location } else { $null }
            QueueStatus    = if ($printer.PSObject.Properties['QueueStatus']) { [string]$printer.QueueStatus } else { $null }
            PrinterStatus  = if ($printer.PSObject.Properties['PrinterStatus']) { [string]$printer.PrinterStatus } else { $null }
            WorkOffline    = $workOffline
            Default        = $defaultPrinter
            PortName       = $portName
            DriverName     = $driverName
            Port           = $portDict
            Driver         = $driverDict
            Configuration  = $configuration
            Jobs           = $jobs
            Connection     = $connectionInfo
        }

        $printerDictionaries += $printerDict
    }

    $result.Printers = $printerDictionaries
    return $result
}

function Normalize-HostName {
    param([string]$Value)
    if (-not $Value) { return $null }
    $trimmed = $Value.Trim()
    if (-not $trimmed) { return $null }
    $trimmed = $trimmed -replace '^\\\\',''
    $trimmed = $trimmed -replace '\\.*$',''
    return $trimmed
}

function Get-PrinterConnectionInfo {
    param(
        [Parameter(Mandatory)]$Printer,
        $Port
    )

    $info = [ordered]@{
        Kind        = 'Unknown'
        PortMonitor = $null
        Hosts       = @()
    }

    $hosts = New-Object System.Collections.Generic.List[string]
    $portMonitor = $null
    if ($Port -and $Port.PSObject.Properties['PortMonitor']) {
        $portMonitor = [string]$Port.PortMonitor
    }
    $info.PortMonitor = $portMonitor

    $portName = if ($Printer.PSObject.Properties['PortName']) { [string]$Printer.PortName } else { '' }
    $computerName = if ($Printer.PSObject.Properties['ComputerName']) { [string]$Printer.ComputerName } else { '' }

    if ($computerName) {
        $normalized = Normalize-HostName $computerName
        if ($normalized) { $hosts.Add($normalized) }
    }

    if ($Port -and $Port.PSObject.Properties['PrinterHostAddress']) {
        $hostAddress = [string]$Port.PrinterHostAddress
        $normalizedAddress = Normalize-HostName $hostAddress
        if ($normalizedAddress) { $hosts.Add($normalizedAddress) }
    }

    $candidates = New-Object System.Collections.Generic.List[string]
    if ($portName) { $candidates.Add($portName) | Out-Null }
    if ($Port -and $Port.PSObject.Properties['Name']) {
        $candidates.Add([string]$Port.Name) | Out-Null
    }

    foreach ($candidate in $candidates) {
        if (-not $candidate) { continue }
        if ($candidate -like '\\\\*') {
            $normalizedCandidate = Normalize-HostName $candidate
            if ($normalizedCandidate) { $hosts.Add($normalizedCandidate) }
        } elseif ($candidate -match '^[0-9]{1,3}(\.[0-9]{1,3}){3}$') {
            $hosts.Add($candidate)
        }
    }

    $kind = 'Unknown'
    if ($portMonitor -match '(?i)wsd') {
        $kind = 'WSD'
    } elseif ($portMonitor -match '(?i)standard tcp' -or $portMonitor -match '(?i)tcpmon') {
        $kind = 'DirectIp'
    } elseif ($portMonitor -match '(?i)local port') {
        if ($hosts.Count -gt 0) { $kind = 'ServerQueue' }
    }

    if ($kind -eq 'Unknown' -and $computerName) { $kind = 'ServerQueue' }
    if ($kind -eq 'Unknown' -and $hosts.Count -gt 0) { $kind = 'DirectIp' }

    $info.Kind = $kind
    $info.Hosts = ($hosts | Select-Object -Unique)
    return $info
}

function Get-RegistryKeyValues {
    param([string]$Path)

    $values = [ordered]@{}
    try {
        $item = Get-ItemProperty -Path $Path -ErrorAction Stop
        foreach ($prop in $item.PSObject.Properties) {
            if ($prop.Name -match '^PS[A-Z]') { continue }
            $values[$prop.Name] = $prop.Value
        }
    } catch {
        $values['Error'] = $_.Exception.Message
    }
    return $values
}

function Get-PrintPolicies {
    $policyRoot = 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Printers'
    $pointAndPrintPath = Join-Path $policyRoot 'PointAndPrint'
    $driverInstallPath = 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\DriverInstall'

    return [ordered]@{
        PrintersRoot    = Get-RegistryKeyValues -Path $policyRoot
        PointAndPrint   = Get-RegistryKeyValues -Path $pointAndPrintPath
        DriverInstall   = Get-RegistryKeyValues -Path (Join-Path $driverInstallPath 'Restrictions')
    }
}

function Convert-Event {
    param($Event)
    if (-not $Event) { return $null }
    return [ordered]@{
        Id          = $Event.Id
        Level       = $Event.LevelDisplayName
        Provider    = $Event.ProviderName
        TimeCreated = if ($Event.TimeCreated) { $Event.TimeCreated.ToString('o') } else { $null }
        Message     = ($Event.Message -replace '\s+', ' ').Trim()
    }
}

function Collect-PrintEvents {
    $startTime = (Get-Date).AddDays(-7)
    $adminEvents = @()
    $operationalEvents = @()
    $errors = @()

    try {
        $adminEvents = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PrintService/Admin'; StartTime=$startTime} -ErrorAction Stop
    } catch {
        $errors += "Admin log query failed: $($_.Exception.Message)"
        $adminEvents = @()
    }

    try {
        $operationalEvents = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PrintService/Operational'; StartTime=$startTime} -ErrorAction Stop
    } catch {
        $errors += "Operational log query failed: $($_.Exception.Message)"
        $operationalEvents = @()
    }

    $driverCrashIds = @(808,215,372,6161,842,843)
    $driverCrashCounts = @{}
    foreach ($evt in $adminEvents) {
        if ($evt -and $driverCrashIds -contains $evt.Id) {
            $driverCrashCounts[$evt.Id] = ($driverCrashCounts[$evt.Id] + 1)
        }
    }

    $adminConverted = $adminEvents | Sort-Object TimeCreated -Descending | Select-Object -First 100 | ForEach-Object { Convert-Event $_ }
    $operationalConverted = $operationalEvents | Sort-Object TimeCreated -Descending | Select-Object -First 100 | ForEach-Object { Convert-Event $_ }

    return [ordered]@{
        Admin = [ordered]@{
            TotalCount       = $adminEvents.Count
            ErrorCount       = ($adminEvents | Where-Object { $_.LevelDisplayName -eq 'Error' }).Count
            WarningCount     = ($adminEvents | Where-Object { $_.LevelDisplayName -eq 'Warning' }).Count
            DriverCrashCount = $driverCrashCounts
            Events           = $adminConverted
        }
        Operational = [ordered]@{
            TotalCount   = $operationalEvents.Count
            ErrorCount   = ($operationalEvents | Where-Object { $_.LevelDisplayName -eq 'Error' }).Count
            WarningCount = ($operationalEvents | Where-Object { $_.LevelDisplayName -eq 'Warning' }).Count
            Events       = $operationalConverted
        }
        Errors = $errors
    }
}

function Invoke-PortTest {
    param(
        [string]$Host,
        [string]$Kind,
        [hashtable]$Definition
    )

    $testResult = [ordered]@{
        Name           = $Definition.Name
        Port           = if ($Definition.ContainsKey('Port')) { $Definition.Port } else { $null }
        Type           = if ($Definition.ContainsKey('Type')) { $Definition.Type } else { 'Tcp' }
        Success        = $null
        RemoteAddress  = $null
        PingSucceeded  = $null
        RoundTripTime  = $null
        Error          = $null
    }

    try {
        if ($Definition.ContainsKey('Common') -and $Definition.Common -eq 'SMB') {
            $result = Test-NetConnection -ComputerName $Host -CommonTCPPort SMB -WarningAction SilentlyContinue
        } elseif ($Definition.ContainsKey('Port')) {
            $result = Test-NetConnection -ComputerName $Host -Port $Definition.Port -WarningAction SilentlyContinue
        } else {
            $result = Test-NetConnection -ComputerName $Host -WarningAction SilentlyContinue
        }

        if ($result) {
            if ($result.PSObject.Properties['TcpTestSucceeded']) {
                $testResult.Success = [bool]$result.TcpTestSucceeded
            }
            if ($result.PSObject.Properties['RemoteAddress']) {
                $testResult.RemoteAddress = [string]$result.RemoteAddress
            }
            if ($result.PSObject.Properties['PingSucceeded']) {
                $testResult.PingSucceeded = [bool]$result.PingSucceeded
            }
            if ($result.PSObject.Properties['PingReplyDetails'] -and $result.PingReplyDetails) {
                try { $testResult.RoundTripTime = $result.PingReplyDetails.RoundtripTime } catch {}
            }
        }
    } catch {
        $testResult.Error = $_.Exception.Message
        if (-not $testResult.Success) { $testResult.Success = $false }
    }

    return $testResult
}

function Get-NetworkTestsForPrinters {
    param([array]$Printers)

    $hostMap = @{}
    foreach ($printer in $Printers) {
        if (-not $printer) { continue }
        $connection = $printer.Connection
        if (-not $connection) { continue }
        $kind = if ($connection.Kind) { [string]$connection.Kind } else { 'Unknown' }
        foreach ($host in $connection.Hosts) {
            if (-not $host) { continue }
            $key = "$kind|$host"
            if (-not $hostMap.ContainsKey($key)) {
                $hostMap[$key] = [ordered]@{
                    Host     = $host
                    Kind     = $kind
                    Printers = New-Object System.Collections.Generic.List[string]
                }
            }
            $hostMap[$key].Printers.Add([string]$printer.Name)
        }
    }

    $results = [System.Collections.Generic.List[object]]::new()
    foreach ($entry in $hostMap.Values) {
        $definitions = [System.Collections.Generic.List[hashtable]]::new()
        switch ($entry.Kind) {
            'ServerQueue' {
                $null = $definitions.Add(@{ Name='SMB'; Type='Common'; Common='SMB' })
                $null = $definitions.Add(@{ Name='TCP135'; Port=135; Type='Tcp' })
                $null = $definitions.Add(@{ Name='TCP445'; Port=445; Type='Tcp' })
            }
            'DirectIp' {
                $null = $definitions.Add(@{ Name='TCP9100'; Port=9100; Type='Tcp' })
                $null = $definitions.Add(@{ Name='TCP631'; Port=631; Type='Tcp' })
            }
            default {
                $null = $definitions.Add(@{ Name='TCP9100'; Port=9100; Type='Tcp' })
                $null = $definitions.Add(@{ Name='TCP631'; Port=631; Type='Tcp' })
            }
        }

        $tests = [System.Collections.Generic.List[object]]::new()
        foreach ($definition in $definitions) {
            $null = $tests.Add(Invoke-PortTest -Host $entry.Host -Kind $entry.Kind -Definition $definition)
        }

        $null = $results.Add([ordered]@{
            Host     = $entry.Host
            Kind     = $entry.Kind
            Printers = $entry.Printers.ToArray()
            Tests    = $tests
        })
    }

    return $results
}

function Invoke-Main {
    $spooler = Get-SpoolerState
    $printerData = Get-PrinterDictionaries
    $policies = Get-PrintPolicies
    $events = Collect-PrintEvents
    $networkTests = Get-NetworkTestsForPrinters -Printers $printerData.Printers

    $payload = [ordered]@{
        Spooler        = $spooler
        Printers       = $printerData.Printers
        DefaultPrinter = $printerData.DefaultPrinter
        Policies       = $policies
        Events         = $events
        NetworkTests   = $networkTests
        Errors         = $printerData.Errors
    }

    $metadata = New-CollectorMetadata -Payload $payload
    $outputPath = Export-CollectorResult -OutputDirectory $OutputDirectory -FileName 'printing.json' -Data $metadata -Depth 6
    Write-Output $outputPath
}

Invoke-Main
