function Get-HardwareSystemInfoValue {
    param(
        [string[]]$Lines,
        [string]$Label
    )

    if (-not $Lines -or -not $Label) { return $null }

    $pattern = '^(?i)\s*{0}\s*:\s*(?<value>.+)$' -f [regex]::Escape($Label)
    foreach ($line in $Lines) {
        if ([string]::IsNullOrWhiteSpace($line)) { continue }
        $match = [regex]::Match($line, $pattern)
        if ($match.Success) {
            $value = $match.Groups['value'].Value.Trim()
            if ($value) { return $value }
        }
    }

    return $null
}

function Test-HardwareDictionaryKey {
    param(
        $Dictionary,
        [string]$Key
    )

    if ($null -eq $Dictionary -or [string]::IsNullOrWhiteSpace($Key)) { return $false }

    if ($Dictionary -is [hashtable]) {
        return $Dictionary.ContainsKey($Key)
    }

    if ($Dictionary -is [System.Collections.Specialized.OrderedDictionary]) {
        return $Dictionary.Contains($Key)
    }

    $psObject = $Dictionary.PSObject
    if ($psObject -and $psObject.Methods['ContainsKey']) {
        try { return [bool]$Dictionary.ContainsKey($Key) } catch { }
    }

    if ($psObject -and $psObject.Methods['Contains']) {
        try { return [bool]$Dictionary.Contains($Key) } catch { }
    }

    if ($psObject -and $psObject.Properties[$Key]) { return $true }

    return $false
}

function Get-BatteryDesignCapacity {
    [CmdletBinding()]
    param(
        # If your OS is not English, "DESIGN CAPACITY" in batteryreport will be localized.
        # You can provide a custom regex that matches the localized label.
        [string]$BatteryReportDesignCapacityRegex = '(?im)DESIGN\s+CAPACITY\s*\.*\s*([\d,]+)\s*mWh'
    )

    function Get-PowerCfgPath {
        $sysnative = Join-Path $env:WINDIR 'sysnative\powercfg.exe'
        $system32  = Join-Path $env:WINDIR 'system32\powercfg.exe'
        if (Test-Path $sysnative) { return $sysnative }
        if (Test-Path $system32)  { return $system32 }
        return 'powercfg.exe'
    }

    $results = @()

    # --- Path 1: root\wmi BatteryStaticData (best: DesignedCapacity mWh, DesignVoltage mV)
    $static = $null
    try {
        $static = Get-CimInstance -Namespace root\wmi -ClassName BatteryStaticData -ErrorAction Stop
    } catch {
        # Try legacy WMI on PS5 if available (PS7 usually lacks Get-WmiObject)
        if (Get-Command Get-WmiObject -ErrorAction SilentlyContinue) {
            try { $static = Get-WmiObject -Namespace root\wmi -Class BatteryStaticData -ErrorAction Stop } catch {}
        }
    }

    if ($static) {
        $idx = 0
        foreach ($b in $static) {
            $idx++
            $mWh = $b.DesignedCapacity
            $mV  = $b.DesignVoltage
            [double]$mAh = $null
            if ($mWh -and $mV -and $mV -ne 0) { $mAh = [math]::Round($mWh / ($mV/1000.0), 0) }

            $results += [pscustomobject]@{
                Index                = $idx
                Source               = 'root\wmi:BatteryStaticData'
                DeviceName           = $b.DeviceName
                DesignedCapacity_mWh = $mWh
                DesignedCapacity_mAh = $mAh
                DesignVoltage_mV     = $mV
                Manufacturer         = $b.ManufacturerName
                SerialNumber         = $b.SerialNumber
                ManufactureDate      = $b.ManufactureDate
                Chemistry            = $b.Chemistry
                UniqueID             = $b.UniqueID
            }
        }
    }

    # --- Path 2: BatteryFullChargedCapacity (not design, but often present; helpful for sanity check)
    # Only add if Path 1 gave nothing.
    if (-not $results) {
        try {
            $full = Get-CimInstance -Namespace root\wmi -ClassName BatteryFullChargedCapacity -ErrorAction Stop
        } catch {
            if (Get-Command Get-WmiObject -ErrorAction SilentlyContinue) {
                try { $full = Get-WmiObject -Namespace root\wmi -Class BatteryFullChargedCapacity -ErrorAction Stop } catch {}
            }
        }
        if ($full) {
            $idx = 0
            foreach ($f in $full) {
                $idx++
                $results += [pscustomobject]@{
                    Index                = $idx
                    Source               = 'root\wmi:BatteryFullChargedCapacity'
                    DeviceName           = $null
                    DesignedCapacity_mWh = $null
                    DesignedCapacity_mAh = $null
                    DesignVoltage_mV     = $null
                    Manufacturer         = $null
                    SerialNumber         = $null
                    ManufactureDate      = $null
                    Chemistry            = $null
                    UniqueID             = $null
                    Note                 = "FullChargedCapacity (mWh) available: $($f.FullChargedCapacity). This is NOT design."
                }
            }
        }
    }

    # --- Path 3: powercfg /batteryreport (HTML parsing; English by default)
    if (-not $results) {
        try {
            $powercfg = Get-PowerCfgPath
            $tmp = Join-Path $env:TEMP ("batteryreport_{0:yyyyMMdd_HHmmss}.html" -f (Get-Date))
            & $powercfg /batteryreport /output "$tmp" | Out-Null
            if (Test-Path $tmp) {
                $html = Get-Content "$tmp" -Raw -ErrorAction Stop
                $m = [regex]::Matches($html, $BatteryReportDesignCapacityRegex)
                if ($m.Count -gt 0) {
                    $idx = 0
                    foreach ($mm in $m) {
                        $idx++
                        $num = ($mm.Groups[1].Value -replace '[^0-9]').Trim()
                        [int]$mWh = 0
                        [void][int]::TryParse($num, [ref]$mWh)
                        $results += [pscustomobject]@{
                            Index                = $idx
                            Source               = "powercfg:/batteryreport $tmp"
                            DeviceName           = $null
                            DesignedCapacity_mWh = $mWh
                            DesignedCapacity_mAh = $null
                            DesignVoltage_mV     = $null
                            Manufacturer         = $null
                            SerialNumber         = $null
                            ManufactureDate      = $null
                            Chemistry            = $null
                            UniqueID             = $null
                        }
                    }
                }
            }
        } catch {
            # ignore; we'll report below if nothing found
        }
    }

    if (-not $results) {
        Write-Warning "No battery design capacity information found. This can happen on desktops/VMs, unsupported ACPI battery drivers, or localized batteryreport labels."
    }

    $results
}

function Get-HardwareInventorySummary {
    param(
        [Parameter(Mandatory)]
        $Context
    )

    $systemArtifact   = Get-AnalyzerArtifact -Context $Context -Name 'system'
    $firmwareArtifact = Get-AnalyzerArtifact -Context $Context -Name 'firmware'
    $tpmArtifact      = Get-AnalyzerArtifact -Context $Context -Name 'tpm'

    $systemPayload = $null
    if ($systemArtifact) {
        $systemPayload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $systemArtifact)
    }

    $firmwarePayload = $null
    if ($firmwareArtifact) {
        $firmwarePayload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $firmwareArtifact)
    }

    $tpmPayload = $null
    if ($tpmArtifact) {
        $tpmPayload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $tpmArtifact)
    }

    if (-not $systemPayload -and -not $firmwarePayload -and -not $tpmPayload) {
        return $null
    }

    $systemInfoLines = @()
    if ($systemPayload -and $systemPayload.SystemInfoText) {
        $systemInfo = $systemPayload.SystemInfoText
        if ($systemInfo -is [System.Collections.IEnumerable] -and -not ($systemInfo -is [string])) {
            $systemInfo = ($systemInfo | ForEach-Object { [string]$_ }) -join "`n"
        }
        $systemInfoText = [string]$systemInfo
        if ($systemInfoText) {
            $systemInfoLines = $systemInfoText -split "\r?\n"
        }
    }

    $cpuEntries = New-Object System.Collections.Generic.List[pscustomobject]
    $cpuSummaryParts = New-Object System.Collections.Generic.List[string]
    $cpuAvailable = $false
    if ($systemPayload -and $systemPayload.Processors) {
        $processors = @($systemPayload.Processors | Where-Object { $_ })
        foreach ($processor in $processors) {
            $entry = [ordered]@{}
            if ($processor.PSObject.Properties['Name'] -and $processor.Name) {
                $entry['Name'] = [string]$processor.Name
            }
            if ($processor.PSObject.Properties['Manufacturer'] -and $processor.Manufacturer) {
                $entry['Manufacturer'] = [string]$processor.Manufacturer
            }
            if ($processor.PSObject.Properties['NumberOfCores'] -and $processor.NumberOfCores -ne $null -and $processor.NumberOfCores -ne '') {
                $entry['Cores'] = [int]$processor.NumberOfCores
            }
            if ($processor.PSObject.Properties['NumberOfLogicalProcessors'] -and $processor.NumberOfLogicalProcessors -ne $null -and $processor.NumberOfLogicalProcessors -ne '') {
                $entry['LogicalProcessors'] = [int]$processor.NumberOfLogicalProcessors
            }
            if ($processor.PSObject.Properties['MaxClockSpeed'] -and $processor.MaxClockSpeed -ne $null -and $processor.MaxClockSpeed -ne '') {
                $entry['MaxClockMHz'] = [int]$processor.MaxClockSpeed
            }
            if ($processor.PSObject.Properties['SocketDesignation'] -and $processor.SocketDesignation) {
                $entry['Socket'] = [string]$processor.SocketDesignation
            }

            if ($entry.Count -gt 0) {
                $cpuEntries.Add([pscustomobject]$entry) | Out-Null
            }
        }

        if ($cpuEntries.Count -gt 0) {
            $cpuAvailable = $true
            $grouped = $cpuEntries | Group-Object -Property Name
            foreach ($group in $grouped) {
                $label = if ($group.Name) { $group.Name } else { 'Processor' }
                if ($group.Count -gt 1) {
                    $cpuSummaryParts.Add(("{0} ×{1}" -f $label, $group.Count)) | Out-Null
                } else {
                    $cpuSummaryParts.Add($label) | Out-Null
                }
            }
        }
    }

    $cpuSummary = if ($cpuSummaryParts.Count -gt 0) { $cpuSummaryParts.ToArray() -join '; ' } else { $null }
    $cpuInfo = [ordered]@{
        Available  = $cpuAvailable
        Summary    = $cpuSummary
        Processors = $cpuEntries.ToArray()
    }

    $computerSystem = $null
    if ($systemPayload -and $systemPayload.ComputerSystem -and -not ($systemPayload.ComputerSystem.Error)) {
        $computerSystem = $systemPayload.ComputerSystem
    }

    $memoryBytes = $null
    if ($computerSystem -and $computerSystem.PSObject.Properties['TotalPhysicalMemory'] -and $computerSystem.TotalPhysicalMemory -ne $null -and $computerSystem.TotalPhysicalMemory -ne '') {
        try {
            $memoryBytes = [uint64]$computerSystem.TotalPhysicalMemory
        } catch {
            $memoryBytes = $null
        }
    }

    $memoryInfo = [ordered]@{
        Available = ($memoryBytes -ne $null)
    }
    if ($memoryBytes -ne $null) {
        $totalGb = [math]::Round(($memoryBytes / 1GB), 2)
        $memoryInfo['TotalBytes'] = $memoryBytes
        $memoryInfo['TotalGB'] = $totalGb
        $memoryInfo['Summary'] = ("{0:N2} GB" -f $totalGb)
    }

    $modelInfo = [ordered]@{
        Available = $false
    }
    if ($computerSystem) {
        $manufacturer = if ($computerSystem.PSObject.Properties['Manufacturer']) { [string]$computerSystem.Manufacturer } else { $null }
        $model = if ($computerSystem.PSObject.Properties['Model']) { [string]$computerSystem.Model } else { $null }
        $domain = if ($computerSystem.PSObject.Properties['Domain']) { [string]$computerSystem.Domain } else { $null }
        $partOfDomain = $null
        if ($computerSystem.PSObject.Properties['PartOfDomain']) {
            try { $partOfDomain = [bool]$computerSystem.PartOfDomain } catch { $partOfDomain = $null }
        }
        $domainRole = $null
        if ($computerSystem.PSObject.Properties['DomainRole']) {
            try { $domainRole = [int]$computerSystem.DomainRole } catch { $domainRole = $null }
        }
        $logicalProcessors = $null
        if ($computerSystem.PSObject.Properties['NumberOfLogicalProcessors'] -and $computerSystem.NumberOfLogicalProcessors -ne $null -and $computerSystem.NumberOfLogicalProcessors -ne '') {
            try { $logicalProcessors = [int]$computerSystem.NumberOfLogicalProcessors } catch { $logicalProcessors = $null }
        }
        $physicalProcessors = $null
        if ($computerSystem.PSObject.Properties['NumberOfProcessors'] -and $computerSystem.NumberOfProcessors -ne $null -and $computerSystem.NumberOfProcessors -ne '') {
            try { $physicalProcessors = [int]$computerSystem.NumberOfProcessors } catch { $physicalProcessors = $null }
        }

        if ($manufacturer) { $modelInfo['Manufacturer'] = $manufacturer }
        if ($model) { $modelInfo['Model'] = $model }
        if ($domain) { $modelInfo['Domain'] = $domain }
        if ($partOfDomain -ne $null) { $modelInfo['PartOfDomain'] = $partOfDomain }
        if ($domainRole -ne $null) { $modelInfo['DomainRole'] = $domainRole }
        if ($logicalProcessors -ne $null) { $modelInfo['LogicalProcessors'] = $logicalProcessors }
        if ($physicalProcessors -ne $null) { $modelInfo['PhysicalProcessors'] = $physicalProcessors }

        $sku = Get-HardwareSystemInfoValue -Lines $systemInfoLines -Label 'System SKU Number'
        if ($sku) { $modelInfo['Sku'] = $sku }
        $systemType = Get-HardwareSystemInfoValue -Lines $systemInfoLines -Label 'System Type'
        if ($systemType) { $modelInfo['SystemType'] = $systemType }

        if ($manufacturer -or $model) {
            $modelInfo['Available'] = $true
            $modelInfo['Summary'] = if ($manufacturer -and $model) { "{0} {1}" -f $manufacturer, $model } elseif ($manufacturer) { $manufacturer } else { $model }
        }
    }

    $tpmInfo = [ordered]@{
        Available = $false
    }
    if ($tpmPayload -and $tpmPayload.Tpm) {
        $tpm = $tpmPayload.Tpm
        if ($tpm.PSObject.Properties['Error'] -and $tpm.Error) {
            $tpmInfo['Error'] = [string]$tpm.Error
        }
        if ($tpm.PSObject.Properties['GetTpm'] -and $tpm.GetTpm) {
            $getTpm = $tpm.GetTpm
            if ($getTpm.PSObject.Properties['TpmPresent']) { $tpmInfo['Present'] = [bool]$getTpm.TpmPresent }
            if ($getTpm.PSObject.Properties['TpmReady']) { $tpmInfo['Ready'] = [bool]$getTpm.TpmReady }
            if ($getTpm.PSObject.Properties['TpmEnabled']) { $tpmInfo['Enabled'] = [bool]$getTpm.TpmEnabled }
            if ($getTpm.PSObject.Properties['TpmActivated']) { $tpmInfo['Activated'] = [bool]$getTpm.TpmActivated }
            if ($getTpm.PSObject.Properties['SpecVersion'] -and $getTpm.SpecVersion) { $tpmInfo['SpecVersion'] = [string]$getTpm.SpecVersion }
            if ($getTpm.PSObject.Properties['ManagedAuthLevel'] -and $getTpm.ManagedAuthLevel) { $tpmInfo['ManagedAuthLevel'] = [string]$getTpm.ManagedAuthLevel }
            if ($getTpm.PSObject.Properties['ManufacturerId'] -and $getTpm.ManufacturerId) { $tpmInfo['ManufacturerId'] = [string]$getTpm.ManufacturerId }
            if ($getTpm.PSObject.Properties['ManufacturerVersion'] -and $getTpm.ManufacturerVersion) { $tpmInfo['ManufacturerVersion'] = [string]$getTpm.ManufacturerVersion }
            if ($getTpm.PSObject.Properties['LockoutHealTime'] -and $getTpm.LockoutHealTime -ne $null -and $getTpm.LockoutHealTime -ne '') {
                $lockoutHealRaw = $getTpm.LockoutHealTime
                $lockoutHealSeconds = $null
                $lockoutHealDisplay = $null

                if ($lockoutHealRaw -is [TimeSpan]) {
                    $lockoutHealSeconds = [int][math]::Round($lockoutHealRaw.TotalSeconds)
                } elseif ($lockoutHealRaw -is [ValueType]) {
                    try {
                        $lockoutHealSeconds = [int][math]::Round([double]$lockoutHealRaw)
                    } catch {
                        $lockoutHealSeconds = $null
                    }
                }

                if ($lockoutHealSeconds -eq $null) {
                    $lockoutHealDisplay = [string]$lockoutHealRaw
                    if ($lockoutHealDisplay) {
                        $parsedInt = 0
                        if ([int]::TryParse($lockoutHealDisplay, [ref]$parsedInt)) {
                            $lockoutHealSeconds = $parsedInt
                        } else {
                            $parsedDouble = 0.0
                            if ([double]::TryParse($lockoutHealDisplay, [ref]$parsedDouble)) {
                                $lockoutHealSeconds = [int][math]::Round($parsedDouble)
                            } elseif ($lockoutHealDisplay -match '^\s*(?<value>\d+(?:\.\d+)?)\s*(?<unit>seconds?|minutes?|hours?)\s*$') {
                                $valueGroup = $null
                                if ($matches -and $matches.ContainsKey('value')) {
                                    $valueGroup = [string]$matches['value']
                                }

                                $unitGroup = $null
                                if ($matches -and $matches.ContainsKey('unit')) {
                                    $unitGroup = [string]$matches['unit']
                                }

                                if ($valueGroup -and $unitGroup) {
                                    $value = [double]$valueGroup
                                    $unit = $unitGroup.ToLowerInvariant()
                                    switch ($unit) {
                                        { $_ -eq 'second' -or $_ -eq 'seconds' } { $lockoutHealSeconds = [int][math]::Round($value) }
                                        { $_ -eq 'minute' -or $_ -eq 'minutes' } { $lockoutHealSeconds = [int][math]::Round($value * 60) }
                                        { $_ -eq 'hour'   -or $_ -eq 'hours' }   { $lockoutHealSeconds = [int][math]::Round($value * 3600) }
                                    }
                                }
                            }
                        }
                    }
                }

                if ($lockoutHealSeconds -ne $null) {
                    $tpmInfo['LockoutHealTimeSeconds'] = $lockoutHealSeconds
                    $tpmInfo['LockoutHealTime'] = $lockoutHealSeconds
                }

                if (-not $lockoutHealDisplay -and $lockoutHealRaw -ne $null) {
                    $lockoutHealDisplay = [string]$lockoutHealRaw
                }

                if ($lockoutHealDisplay) {
                    $tpmInfo['LockoutHealTimeDisplay'] = $lockoutHealDisplay
                    if ($lockoutHealSeconds -eq $null) {
                        $tpmInfo['LockoutHealTime'] = $lockoutHealDisplay
                    }
                }
            }
            if ($getTpm.PSObject.Properties['LockoutCount'] -and $getTpm.LockoutCount -ne $null -and $getTpm.LockoutCount -ne '') {
                $tpmInfo['LockoutCount'] = [int]$getTpm.LockoutCount
            }
            if ($getTpm.PSObject.Properties['LockedOut']) { $tpmInfo['LockedOut'] = [bool]$getTpm.LockedOut }
        }

        if ($tpm.PSObject.Properties['Win32_Tpm'] -and $tpm.Win32_Tpm) {
            $win32 = $tpm.Win32_Tpm
            if (-not (Test-HardwareDictionaryKey -Dictionary $tpmInfo -Key 'SpecVersion') -and $win32.PSObject.Properties['SpecVersion'] -and $win32.SpecVersion) {
                $tpmInfo['SpecVersion'] = [string]$win32.SpecVersion
            }
            if (-not (Test-HardwareDictionaryKey -Dictionary $tpmInfo -Key 'ManufacturerId') -and $win32.PSObject.Properties['ManufacturerId'] -and $win32.ManufacturerId) {
                $tpmInfo['ManufacturerId'] = [string]$win32.ManufacturerId
            }
            if (-not (Test-HardwareDictionaryKey -Dictionary $tpmInfo -Key 'ManufacturerVersion') -and $win32.PSObject.Properties['ManufacturerVersion'] -and $win32.ManufacturerVersion) {
                $tpmInfo['ManufacturerVersion'] = [string]$win32.ManufacturerVersion
            }
        }

        $tpmAvailable = (
            (Test-HardwareDictionaryKey -Dictionary $tpmInfo -Key 'Present') -or
            (Test-HardwareDictionaryKey -Dictionary $tpmInfo -Key 'Ready') -or
            (Test-HardwareDictionaryKey -Dictionary $tpmInfo -Key 'Enabled') -or
            (Test-HardwareDictionaryKey -Dictionary $tpmInfo -Key 'Activated') -or
            (Test-HardwareDictionaryKey -Dictionary $tpmInfo -Key 'SpecVersion')
        )
        if ($tpmAvailable) { $tpmInfo['Available'] = $true }

        if (Test-HardwareDictionaryKey -Dictionary $tpmInfo -Key 'Present') {
            if ($tpmInfo['Present'] -eq $true) {
                $statusParts = @('Present')
                if ((Test-HardwareDictionaryKey -Dictionary $tpmInfo -Key 'SpecVersion') -and $tpmInfo['SpecVersion']) {
                    $statusParts += ("Spec {0}" -f $tpmInfo['SpecVersion'])
                }
                if (Test-HardwareDictionaryKey -Dictionary $tpmInfo -Key 'Ready') { $statusParts += $(if ($tpmInfo['Ready']) { 'Ready' } else { 'Not Ready' }) }
                if (Test-HardwareDictionaryKey -Dictionary $tpmInfo -Key 'Enabled') { $statusParts += $(if ($tpmInfo['Enabled']) { 'Enabled' } else { 'Disabled' }) }
                if (Test-HardwareDictionaryKey -Dictionary $tpmInfo -Key 'Activated') { $statusParts += $(if ($tpmInfo['Activated']) { 'Activated' } else { 'Deactivated' }) }
                $tpmInfo['Summary'] = ($statusParts -join ', ')
            } elseif ($tpmInfo['Present'] -eq $false) {
                $tpmInfo['Summary'] = 'No TPM detected'
            }
        } elseif (Test-HardwareDictionaryKey -Dictionary $tpmInfo -Key 'Error') {
            $tpmInfo['Summary'] = 'TPM query reported an error'
        }
    }

    $firmware = $null
    if ($firmwarePayload -and $firmwarePayload.Firmware) {
        $firmware = $firmwarePayload.Firmware
    }

    $secureBootInfo = [ordered]@{
        Available = $false
    }
    if ($firmware -and $firmware.PSObject.Properties['SecureBoot'] -and $firmware.SecureBoot) {
        $secureBoot = $firmware.SecureBoot
        $sources = New-Object System.Collections.Generic.List[string]
        if ($secureBoot.PSObject.Properties['ConfirmSecureBootUEFI']) {
            $value = $secureBoot.ConfirmSecureBootUEFI
            if ($value -ne $null -and $value -ne '') {
                $boolValue = $null
                try { $boolValue = [bool]$value } catch { $boolValue = $null }
                if ($boolValue -ne $null) {
                    $secureBootInfo['ConfirmSecureBootUEFI'] = $boolValue
                    $sources.Add("Confirm-SecureBootUEFI: {0}" -f $boolValue) | Out-Null
                }
            }
        }
        if ($secureBoot.PSObject.Properties['MS_SecureBootEnabled']) {
            $value = $secureBoot.MS_SecureBootEnabled
            if ($value -ne $null -and $value -ne '') {
                $boolValue = $null
                try { $boolValue = [bool]$value } catch { $boolValue = $null }
                if ($boolValue -ne $null) {
                    $secureBootInfo['MS_SecureBootEnabled'] = $boolValue
                    $sources.Add("MS_SecureBootEnabled: {0}" -f $boolValue) | Out-Null
                }
            }
        }
        if ($secureBoot.PSObject.Properties['RegistryEnabled']) {
            $value = $secureBoot.RegistryEnabled
            if ($value -ne $null -and $value -ne '') {
                $boolValue = $null
                try { $boolValue = [bool]$value } catch { $boolValue = $null }
                if ($boolValue -ne $null) {
                    $secureBootInfo['RegistryEnabled'] = $boolValue
                    $sources.Add("RegistryEnabled: {0}" -f $boolValue) | Out-Null
                }
            }
        }
        if ($secureBoot.PSObject.Properties['Error'] -and $secureBoot.Error) {
            $secureBootInfo['Error'] = [string]$secureBoot.Error
        }

        if ($sources.Count -gt 0 -or (Test-HardwareDictionaryKey -Dictionary $secureBootInfo -Key 'Error')) {
            $secureBootInfo['Available'] = $true
        }

        $enabledStates = @()
        if (Test-HardwareDictionaryKey -Dictionary $secureBootInfo -Key 'ConfirmSecureBootUEFI') { $enabledStates += $secureBootInfo['ConfirmSecureBootUEFI'] }
        if (Test-HardwareDictionaryKey -Dictionary $secureBootInfo -Key 'MS_SecureBootEnabled') { $enabledStates += $secureBootInfo['MS_SecureBootEnabled'] }
        if (Test-HardwareDictionaryKey -Dictionary $secureBootInfo -Key 'RegistryEnabled') { $enabledStates += $secureBootInfo['RegistryEnabled'] }

        if ($enabledStates.Count -gt 0) {
            if ($enabledStates -contains $false) {
                $secureBootInfo['Summary'] = 'Secure Boot appears disabled'
            } elseif ($enabledStates -contains $true) {
                $secureBootInfo['Summary'] = 'Secure Boot appears enabled'
            }
        } elseif (Test-HardwareDictionaryKey -Dictionary $secureBootInfo -Key 'Error') {
            $secureBootInfo['Summary'] = 'Secure Boot status unavailable (error reported)'
        }

        if ($sources.Count -gt 0) {
            $secureBootInfo['Signals'] = $sources.ToArray()
        }
    }

    $biosInfo = [ordered]@{
        Available = $false
    }
    $biosVersion = Get-HardwareSystemInfoValue -Lines $systemInfoLines -Label 'BIOS Version'
    if ($biosVersion) { $biosInfo['Version'] = $biosVersion }
    $biosReleaseDate = Get-HardwareSystemInfoValue -Lines $systemInfoLines -Label 'BIOS Release Date'
    if ($biosReleaseDate) { $biosInfo['ReleaseDate'] = $biosReleaseDate }
    $biosMode = Get-HardwareSystemInfoValue -Lines $systemInfoLines -Label 'BIOS Mode'
    if ($biosMode) { $biosInfo['Mode'] = $biosMode }
    $baseboardManufacturer = Get-HardwareSystemInfoValue -Lines $systemInfoLines -Label 'BaseBoard Manufacturer'
    if ($baseboardManufacturer) { $biosInfo['BaseBoardManufacturer'] = $baseboardManufacturer }
    $baseboardProduct = Get-HardwareSystemInfoValue -Lines $systemInfoLines -Label 'BaseBoard Product'
    if ($baseboardProduct) { $biosInfo['BaseBoardProduct'] = $baseboardProduct }

    if ($firmware) {
        $firmwareDetails = [ordered]@{}
        if ($firmware.PSObject.Properties['UefiDetected']) { $firmwareDetails['UefiDetected'] = $firmware.UefiDetected }
        if ($firmware.PSObject.Properties['PEFirmwareType'] -and $firmware.PEFirmwareType -ne $null -and $firmware.PEFirmwareType -ne '') {
            $firmwareDetails['PEFirmwareType'] = [int]$firmware.PEFirmwareType
        }
        if ($firmware.PSObject.Properties['EspDetected']) { $firmwareDetails['EspDetected'] = $firmware.EspDetected }
        if ($firmware.PSObject.Properties['EspPartitions'] -and $firmware.EspPartitions) {
            $firmwareDetails['EspPartitions'] = @($firmware.EspPartitions | Where-Object { $_ })
        }
        if ($firmware.PSObject.Properties['UefiSources'] -and $firmware.UefiSources) {
            $firmwareDetails['UefiSources'] = @($firmware.UefiSources | Where-Object { $_ })
        }
        if ($firmware.PSObject.Properties['Error'] -and $firmware.Error) {
            $firmwareDetails['Error'] = [string]$firmware.Error
        }
        if ($firmwareDetails.Count -gt 0) {
            $biosInfo['Firmware'] = [pscustomobject]$firmwareDetails
        }
    }

    if ((Test-HardwareDictionaryKey -Dictionary $biosInfo -Key 'Version') -or (Test-HardwareDictionaryKey -Dictionary $biosInfo -Key 'Mode') -or (Test-HardwareDictionaryKey -Dictionary $biosInfo -Key 'Firmware')) {
        $biosInfo['Available'] = $true
        $summaryParts = New-Object System.Collections.Generic.List[string]
        if (Test-HardwareDictionaryKey -Dictionary $biosInfo -Key 'Version') { $summaryParts.Add("Version: {0}" -f $biosInfo['Version']) | Out-Null }
        if (Test-HardwareDictionaryKey -Dictionary $biosInfo -Key 'Mode') { $summaryParts.Add("Mode: {0}" -f $biosInfo['Mode']) | Out-Null }
        if ($summaryParts.Count -gt 0) {
            $biosInfo['Summary'] = $summaryParts.ToArray() -join '; '
        }
    }

    $missingSignals = New-Object System.Collections.Generic.List[string]
    if (-not $cpuInfo['Available']) { $missingSignals.Add('CPU') | Out-Null }
    if (-not $memoryInfo['Available']) { $missingSignals.Add('RAM') | Out-Null }
    if (-not $modelInfo['Available']) { $missingSignals.Add('Model') | Out-Null }
    $tpmAvailable = ($tpmInfo['Available'] -eq $true)
    if (-not $tpmAvailable -and -not (Test-HardwareDictionaryKey -Dictionary $tpmInfo -Key 'Error')) { $missingSignals.Add('TPM') | Out-Null }
    if (-not $secureBootInfo['Available'] -and -not (Test-HardwareDictionaryKey -Dictionary $secureBootInfo -Key 'Error')) { $missingSignals.Add('Secure Boot') | Out-Null }
    if (-not $biosInfo['Available'] -and -not (Test-HardwareDictionaryKey -Dictionary $biosInfo -Key 'Firmware')) { $missingSignals.Add('Firmware') | Out-Null }

    $evidenceLines = New-Object System.Collections.Generic.List[string]
    if (Test-HardwareDictionaryKey -Dictionary $modelInfo -Key 'Summary') {
        $evidenceLines.Add("Model: {0}" -f $modelInfo['Summary']) | Out-Null
    } elseif (-not $modelInfo['Available']) {
        $evidenceLines.Add('Model information unavailable.') | Out-Null
    }

    if ($cpuSummary) {
        $evidenceLines.Add("CPU: {0}" -f $cpuSummary) | Out-Null
    } elseif (-not $cpuInfo['Available']) {
        $evidenceLines.Add('CPU information unavailable.') | Out-Null
    }

    if (Test-HardwareDictionaryKey -Dictionary $memoryInfo -Key 'Summary') {
        $evidenceLines.Add("Memory: {0}" -f $memoryInfo['Summary']) | Out-Null
    } elseif (-not $memoryInfo['Available']) {
        $evidenceLines.Add('Memory information unavailable.') | Out-Null
    }

    if (Test-HardwareDictionaryKey -Dictionary $tpmInfo -Key 'Summary') {
        $evidenceLines.Add("TPM: {0}" -f $tpmInfo['Summary']) | Out-Null
    } elseif (Test-HardwareDictionaryKey -Dictionary $tpmInfo -Key 'Error') {
        $evidenceLines.Add("TPM query error: {0}" -f $tpmInfo['Error']) | Out-Null
    }

    if (Test-HardwareDictionaryKey -Dictionary $secureBootInfo -Key 'Summary') {
        $evidenceLines.Add($secureBootInfo['Summary']) | Out-Null
    } elseif (Test-HardwareDictionaryKey -Dictionary $secureBootInfo -Key 'Error') {
        $evidenceLines.Add("Secure Boot query error: {0}" -f $secureBootInfo['Error']) | Out-Null
    }

    if (Test-HardwareDictionaryKey -Dictionary $biosInfo -Key 'Summary') {
        $evidenceLines.Add("BIOS: {0}" -f $biosInfo['Summary']) | Out-Null
    }

    $evidence = if ($evidenceLines.Count -gt 0) { $evidenceLines.ToArray() -join "`n" } else { $null }

    $title = if ($missingSignals.Count -eq 0) {
        'Hardware inventory captured for readiness checks.'
    } else {
        "Hardware inventory incomplete ({0})" -f ($missingSignals.ToArray() -join ', ')
    }

    $hasAnyData = (
        $cpuInfo['Available'] -or
        $memoryInfo['Available'] -or
        $modelInfo['Available'] -or
        $tpmInfo['Available'] -or
        $secureBootInfo['Available'] -or
        $biosInfo['Available'] -or
        (Test-HardwareDictionaryKey -Dictionary $tpmInfo -Key 'Error') -or
        (Test-HardwareDictionaryKey -Dictionary $secureBootInfo -Key 'Error')
    )

    if (-not $hasAnyData) {
        return $null
    }

    return [pscustomobject]@{
        Title      = $title
        Severity   = 'info'
        Evidence   = $evidence
        CPU        = [pscustomobject]$cpuInfo
        Memory     = [pscustomobject]$memoryInfo
        TPM        = [pscustomobject]$tpmInfo
        SecureBoot = [pscustomobject]$secureBootInfo
        Model      = [pscustomobject]$modelInfo
        Bios       = [pscustomobject]$biosInfo
    }
}

function Invoke-HardwareHeuristics {
    param(
        [Parameter(Mandatory)]
        $Context
    )

    Write-HeuristicDebug -Source 'Hardware' -Message 'Starting hardware heuristics' -Data ([ordered]@{
        ArtifactCount = if ($Context -and $Context.Artifacts) { $Context.Artifacts.Count } else { 0 }
    })

    $result = New-CategoryResult -Name 'Hardware'
    $issueCount = 0

    $inventorySummary = Get-HardwareInventorySummary -Context $Context
    if ($inventorySummary) {
        $cpuInfo = $inventorySummary.CPU
        $memoryInfo = $inventorySummary.Memory
        $tpmInfo = $inventorySummary.TPM
        $secureBootInfo = $inventorySummary.SecureBoot
        $modelInfo = $inventorySummary.Model
        $biosInfo = $inventorySummary.Bios
        $title = if ($inventorySummary.Title) { [string]$inventorySummary.Title } else { 'Hardware inventory summary' }
        $severity = if ($inventorySummary.Severity) { [string]$inventorySummary.Severity } else { 'info' }
        $evidence = $inventorySummary.Evidence

        Add-CategoryIssue -CategoryResult $result -Severity $severity `
            -Title $title `
            -Evidence $evidence `
            -Subcategory 'Hardware' `
            -Data @{
                Area       = 'Hardware'
                Kind       = 'Inventory'
                CPU        = $cpuInfo
                Memory     = $memoryInfo
                TPM        = $tpmInfo
                SecureBoot = $secureBootInfo
                Model      = $modelInfo
                Bios       = $biosInfo
            }
    }

    $formatBatteryRuntime = {
        param([double]$Minutes)

        if ($null -eq $Minutes) { return $null }

        $timeSpan = [System.TimeSpan]::FromMinutes($Minutes)
        $parts = New-Object System.Collections.Generic.List[string]

        if ($timeSpan.Days -gt 0) { $parts.Add(("{0}d" -f $timeSpan.Days)) | Out-Null }
        if ($timeSpan.Hours -gt 0) { $parts.Add(("{0}h" -f $timeSpan.Hours)) | Out-Null }
        if ($timeSpan.Minutes -gt 0) { $parts.Add(("{0}m" -f $timeSpan.Minutes)) | Out-Null }

        if ($parts.Count -eq 0) {
            $parts.Add(("{0}m" -f [math]::Round($Minutes, 0))) | Out-Null
        }

        return $parts -join ' '
    }

    $batteryArtifact = Get-AnalyzerArtifact -Context $Context -Name 'battery'
    Write-HeuristicDebug -Source 'Hardware/Battery' -Message 'Resolved battery artifact' -Data ([ordered]@{
        Found = [bool]$batteryArtifact
    })

    if ($batteryArtifact) {
        $batteryPayload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $batteryArtifact)
        Write-HeuristicDebug -Source 'Hardware/Battery' -Message 'Resolved battery payload' -Data ([ordered]@{
            HasPayload = [bool]$batteryPayload
        })

        if ($batteryPayload) {
            $batteryErrors = @()
            if ($batteryPayload.PSObject.Properties['Errors'] -and $batteryPayload.Errors) {
                $batteryErrors = @($batteryPayload.Errors | Where-Object { $_ })
            }

            $batteryEntries = @()
            if ($batteryPayload.PSObject.Properties['Batteries'] -and $batteryPayload.Batteries) {
                $batteryEntries = @($batteryPayload.Batteries | Where-Object { $_ })
            }

            $averageLife = $null
            if ($batteryPayload.PSObject.Properties['AverageLife']) {
                $averageLife = $batteryPayload.AverageLife
            }

            $lowWearThreshold    = 10.0
            $mediumWearThreshold = 20.0
            $highWearThreshold   = 30.0

            Write-HeuristicDebug -Source 'Hardware/Battery' -Message 'Parsed battery payload' -Data ([ordered]@{
                BatteryCount       = $batteryEntries.Count
                AverageLifeMinutes = if ($averageLife -and $averageLife.PSObject.Properties['AtFullChargeMinutes']) { $averageLife.AtFullChargeMinutes } else { $null }
                ErrorCount         = $batteryErrors.Count
            })

            $batteryEntryCount = $batteryEntries.Count
            $designCapacityFetchAttempted = $false
            $designCapacityResults = @()
            $designCapacityLookupByUniqueId = @{}
            $designCapacityLookupBySerial = @{}
            $designCapacityLookupByDevice = @{}
            $designCapacityLookupByIndex = @{}

            $resolveDesignCapacity = {
                param(
                    [string[]]$UniqueIds = @(),
                    [string[]]$SerialNumbers = @(),
                    [string[]]$DeviceNames = @(),
                    [int]$EntryIndex = -1
                )

                if (-not $designCapacityFetchAttempted) {
                    $designCapacityFetchAttempted = $true
                    try {
                        $designCapacityResults = @(Get-BatteryDesignCapacity)
                        Write-HeuristicDebug -Source 'Hardware/Battery' -Message 'Queried system design capacity fallback' -Data ([ordered]@{
                            ResultCount = $designCapacityResults.Count
                        })
                    } catch {
                        Write-HeuristicDebug -Source 'Hardware/Battery' -Message 'Failed querying system design capacity fallback' -Data ([ordered]@{
                            Error = $_.Exception.Message
                        })
                        $designCapacityResults = @()
                    }

                    foreach ($designEntry in $designCapacityResults) {
                        if (-not $designEntry) { continue }

                        if ($designEntry.PSObject.Properties['UniqueID'] -and $designEntry.UniqueID) {
                            $uniqueKey = [string]$designEntry.UniqueID
                            if ($uniqueKey -and $uniqueKey.Trim() -and -not $designCapacityLookupByUniqueId.ContainsKey($uniqueKey.Trim())) {
                                $designCapacityLookupByUniqueId[$uniqueKey.Trim()] = $designEntry
                            }
                        }

                        if ($designEntry.PSObject.Properties['SerialNumber'] -and $designEntry.SerialNumber) {
                            $serialKey = [string]$designEntry.SerialNumber
                            if ($serialKey -and $serialKey.Trim() -and -not $designCapacityLookupBySerial.ContainsKey($serialKey.Trim())) {
                                $designCapacityLookupBySerial[$serialKey.Trim()] = $designEntry
                            }
                        }

                        if ($designEntry.PSObject.Properties['DeviceName'] -and $designEntry.DeviceName) {
                            $deviceKey = [string]$designEntry.DeviceName
                            if ($deviceKey -and $deviceKey.Trim() -and -not $designCapacityLookupByDevice.ContainsKey($deviceKey.Trim())) {
                                $designCapacityLookupByDevice[$deviceKey.Trim()] = $designEntry
                            }
                        }

                        if ($designEntry.PSObject.Properties['Index'] -and $designEntry.Index) {
                            $indexKey = [string]$designEntry.Index
                            if ($indexKey -and $indexKey.Trim() -and -not $designCapacityLookupByIndex.ContainsKey($indexKey.Trim())) {
                                $designCapacityLookupByIndex[$indexKey.Trim()] = $designEntry
                            }
                        }
                    }
                }

                foreach ($candidate in $UniqueIds) {
                    if ([string]::IsNullOrWhiteSpace($candidate)) { continue }
                    $lookupKey = $candidate.Trim()
                    if ($designCapacityLookupByUniqueId.ContainsKey($lookupKey)) { return $designCapacityLookupByUniqueId[$lookupKey] }
                }

                foreach ($candidate in $SerialNumbers) {
                    if ([string]::IsNullOrWhiteSpace($candidate)) { continue }
                    $lookupKey = $candidate.Trim()
                    if ($designCapacityLookupBySerial.ContainsKey($lookupKey)) { return $designCapacityLookupBySerial[$lookupKey] }
                }

                foreach ($candidate in $DeviceNames) {
                    if ([string]::IsNullOrWhiteSpace($candidate)) { continue }
                    $lookupKey = $candidate.Trim()
                    if ($designCapacityLookupByDevice.ContainsKey($lookupKey)) { return $designCapacityLookupByDevice[$lookupKey] }
                }

                if ($EntryIndex -gt 0) {
                    $indexKey = $EntryIndex.ToString().Trim()
                    if ($designCapacityLookupByIndex.ContainsKey($indexKey)) { return $designCapacityLookupByIndex[$indexKey] }
                }

                if ($batteryEntryCount -eq 1 -and $designCapacityResults.Count -eq 1) {
                    return $designCapacityResults[0]
                }

                return $null
            }

            if ($batteryErrors.Count -gt 0) {
                $firstError = $batteryErrors | Select-Object -First 1
                $errorText = if ($firstError -and $firstError.PSObject.Properties['Error'] -and $firstError.Error) { [string]$firstError.Error } else { 'Unknown error' }
                $source = if ($firstError -and $firstError.PSObject.Properties['Source'] -and $firstError.Source) { [string]$firstError.Source } else { 'root\wmi battery classes' }
                Add-CategoryIssue -CategoryResult $result -Severity 'info' -Title 'Battery health query reported an error, so health data may be incomplete.' -Evidence ("{0}: {1}" -f $source, $errorText) -Subcategory 'Battery'
                $issueCount++
            }

            $batteryIndex = 0
            foreach ($battery in $batteryEntries) {
                if (-not $battery) { continue }
                $batteryIndex++

                $label = if ($battery.PSObject.Properties['Name'] -and $battery.Name) { [string]$battery.Name } else { 'Primary battery' }

                $design = $null
                if ($battery.PSObject.Properties['DesignCapacitymWh']) {
                    $designValue = $battery.DesignCapacitymWh
                    if ($designValue -ne $null -and $designValue -ne '') { $design = [double]$designValue }
                }

                $full = $null
                if ($battery.PSObject.Properties['FullChargeCapacitymWh']) {
                    $fullValue = $battery.FullChargeCapacitymWh
                    if ($fullValue -ne $null -and $fullValue -ne '') { $full = [double]$fullValue }
                }

                $remaining = $null
                if ($battery.PSObject.Properties['RemainingCapacitymWh']) {
                    $remainingValue = $battery.RemainingCapacitymWh
                    if ($remainingValue -ne $null -and $remainingValue -ne '') { $remaining = [double]$remainingValue }
                }

                $designmAh = $null
                if ($battery.PSObject.Properties['DesignCapacitymAh']) {
                    $designmAhValue = $battery.DesignCapacitymAh
                    if ($designmAhValue -ne $null -and $designmAhValue -ne '') { $designmAh = [double]$designmAhValue }
                }

                $fullmAh = $null
                if ($battery.PSObject.Properties['FullChargeCapacitymAh']) {
                    $fullmAhValue = $battery.FullChargeCapacitymAh
                    if ($fullmAhValue -ne $null -and $fullmAhValue -ne '') { $fullmAh = [double]$fullmAhValue }
                }

                $remainingmAh = $null
                if ($battery.PSObject.Properties['RemainingCapacitymAh']) {
                    $remainingmAhValue = $battery.RemainingCapacitymAh
                    if ($remainingmAhValue -ne $null -and $remainingmAhValue -ne '') { $remainingmAh = [double]$remainingmAhValue }
                }

                if ($design -eq $null -or $design -le 0) {
                    $rawSnapshot = $null
                    if ($battery.PSObject.Properties['Raw'] -and $battery.Raw) { $rawSnapshot = $battery.Raw }

                    $uniqueCandidates = New-Object System.Collections.Generic.List[string]
                    $serialCandidates = New-Object System.Collections.Generic.List[string]
                    $deviceCandidates = New-Object System.Collections.Generic.List[string]

                    if ($battery.PSObject.Properties['InstanceName'] -and $battery.InstanceName) { $uniqueCandidates.Add([string]$battery.InstanceName) | Out-Null }
                    if ($battery.PSObject.Properties['SerialNumber'] -and $battery.SerialNumber) { $serialCandidates.Add([string]$battery.SerialNumber) | Out-Null }
                    if ($battery.PSObject.Properties['Name'] -and $battery.Name) { $deviceCandidates.Add([string]$battery.Name) | Out-Null }

                    if ($rawSnapshot) {
                        foreach ($propName in @('Static_UniqueID', 'UniqueID', 'Status_UniqueID')) {
                            if ($rawSnapshot.PSObject.Properties[$propName] -and $rawSnapshot.$propName) { $uniqueCandidates.Add([string]$rawSnapshot.$propName) | Out-Null }
                        }

                        foreach ($propName in @('Static_SerialNumber', 'SerialNumber', 'Status_SerialNumber')) {
                            if ($rawSnapshot.PSObject.Properties[$propName] -and $rawSnapshot.$propName) { $serialCandidates.Add([string]$rawSnapshot.$propName) | Out-Null }
                        }

                        foreach ($propName in @('Static_DeviceName', 'DeviceName', 'Full_DeviceName', 'Status_DeviceName')) {
                            if ($rawSnapshot.PSObject.Properties[$propName] -and $rawSnapshot.$propName) { $deviceCandidates.Add([string]$rawSnapshot.$propName) | Out-Null }
                        }
                    }

                    $resolvedDesignEntry = & $resolveDesignCapacity -UniqueIds ($uniqueCandidates.ToArray()) -SerialNumbers ($serialCandidates.ToArray()) -DeviceNames ($deviceCandidates.ToArray()) -EntryIndex $batteryIndex
                    if ($resolvedDesignEntry -and $resolvedDesignEntry.PSObject.Properties['DesignedCapacity_mWh'] -and $resolvedDesignEntry.DesignedCapacity_mWh) {
                        $design = [double]$resolvedDesignEntry.DesignedCapacity_mWh
                        if (($designmAh -eq $null -or $designmAh -le 0) -and $resolvedDesignEntry.PSObject.Properties['DesignedCapacity_mAh'] -and $resolvedDesignEntry.DesignedCapacity_mAh) {
                            $designmAh = [double]$resolvedDesignEntry.DesignedCapacity_mAh
                        }

                        Write-HeuristicDebug -Source 'Hardware/Battery' -Message 'Filled design capacity from Get-BatteryDesignCapacity' -Data ([ordered]@{
                            BatteryLabel         = $label
                            DesignedCapacity_mWh = $design
                            FallbackSource       = if ($resolvedDesignEntry.PSObject.Properties['Source'] -and $resolvedDesignEntry.Source) { [string]$resolvedDesignEntry.Source } else { 'Unknown' }
                        })
                    }
                }

                $cycleCount = $null
                if ($battery.PSObject.Properties['CycleCount']) {
                    $cycleValue = $battery.CycleCount
                    if ($cycleValue -ne $null -and $cycleValue -ne '') { $cycleCount = [int]$cycleValue }
                }

                $wearPct = $null
                if ($battery.PSObject.Properties['DegradationPercent'] -and $battery.DegradationPercent -ne $null -and $battery.DegradationPercent -ne '') {
                    $wearPct = [double]$battery.DegradationPercent
                } elseif ($design -and $design -gt 0 -and $full -ne $null -and $full -ge 0) {
                    $wearPct = [math]::Round((1 - ($full / $design)) * 100, 2)
                }

                if ($wearPct -ne $null) {
                    if ($wearPct -lt 0) { $wearPct = 0 }
                    if ($wearPct -gt 100) { $wearPct = 100 }
                }

                $charging = $null
                if ($battery.PSObject.Properties['Status_Charging']) {
                    $charging = [bool]$battery.Status_Charging
                }

                $powerOnline = $null
                if ($battery.PSObject.Properties['Status_PowerOnline']) {
                    $powerOnline = [bool]$battery.Status_PowerOnline
                }

                $impactSummaryParts = New-Object System.Collections.Generic.List[string]
                if ($fullmAh -ne $null) { $impactSummaryParts.Add(("Full≈{0:N0}mAh" -f $fullmAh)) | Out-Null }
                if ($remainingmAh -ne $null) { $impactSummaryParts.Add(("Now≈{0:N0}mAh" -f $remainingmAh)) | Out-Null }
                if ($design -ne $null) { $impactSummaryParts.Add(("Design={0:N0}mWh" -f $design)) | Out-Null }
                if ($wearPct -ne $null) { $impactSummaryParts.Add(("Degradation={0:N1}%" -f $wearPct)) | Out-Null }
                if ($charging -ne $null -and $charging) { $impactSummaryParts.Add('Charging') | Out-Null }

                $evidenceLines = New-Object System.Collections.Generic.List[string]
                if ($impactSummaryParts.Count -gt 0) {
                    $evidenceLines.Add("Snapshot: {0}" -f ($impactSummaryParts.ToArray() -join ' · ')) | Out-Null
                }
                if ($design -ne $null) {
                    $designSuffix = if ($designmAh -ne $null) { " (~{0:N0} mAh)" -f $designmAh } else { '' }
                    $evidenceLines.Add(("Design capacity: {0:N0} mWh{1}" -f $design, $designSuffix)) | Out-Null
                }
                if ($full -ne $null) {
                    $fullSuffix = if ($fullmAh -ne $null) { " (~{0:N0} mAh)" -f $fullmAh } else { '' }
                    $evidenceLines.Add(("Full-charge capacity: {0:N0} mWh{1}" -f $full, $fullSuffix)) | Out-Null
                }
                if ($remaining -ne $null) {
                    $remainingSuffix = if ($remainingmAh -ne $null) { " (~{0:N0} mAh)" -f $remainingmAh } else { '' }
                    $evidenceLines.Add(("Remaining capacity: {0:N0} mWh{1}" -f $remaining, $remainingSuffix)) | Out-Null
                }
                if ($wearPct -ne $null) {
                    $evidenceLines.Add(("Estimated wear: {0:N1}%" -f $wearPct)) | Out-Null
                }
                if ($cycleCount -ne $null) {
                    $evidenceLines.Add(("Reported cycle count: {0}" -f $cycleCount)) | Out-Null
                }
                if ($battery.PSObject.Properties['AverageDischargeMilliwatts'] -and $battery.AverageDischargeMilliwatts) {
                    $evidenceLines.Add(("Average discharge rate: {0:N0} mW" -f $battery.AverageDischargeMilliwatts)) | Out-Null
                }
                if ($charging -ne $null) {
                    $evidenceLines.Add(("Charging: {0}" -f ([string]$charging))) | Out-Null
                }
                if ($powerOnline -ne $null) {
                    $evidenceLines.Add(("Power source online: {0}" -f ([string]$powerOnline))) | Out-Null
                }

                if ($averageLife) {
                    $lifeDisplay = $null
                    if ($averageLife.PSObject.Properties['AtFullChargeMinutes'] -and $averageLife.AtFullChargeMinutes -ne $null) {
                        $lifeDisplay = & $formatBatteryRuntime ([double]$averageLife.AtFullChargeMinutes)
                    }
                    if (-not $lifeDisplay -and $averageLife.PSObject.Properties['AtFullCharge'] -and $averageLife.AtFullCharge) {
                        $lifeDisplay = [string]$averageLife.AtFullCharge
                    }
                    if ($lifeDisplay) {
                        $evidenceLines.Add(("Average runtime (full charge): {0}" -f $lifeDisplay)) | Out-Null
                    }
                }

                $evidence = if ($evidenceLines.Count -gt 0) { $evidenceLines.ToArray() -join "`n" } else { $null }

                $remediation = $null
                $title = $null
                $severity = 'info'

                if ($wearPct -eq $null) {
                    if ($design -or $full) {
                        $title = "Battery '{0}' reported incomplete capacity data, so unplugged runtime cannot be estimated." -f $label
                        $remediation = 'Ensure the battery exposes design and full-charge capacity through WMI, or rerun diagnostics after a full charge/discharge cycle.'
                        Add-CategoryIssue -CategoryResult $result -Severity 'info' -Title $title -Evidence $evidence -Subcategory 'Battery' -Remediation $remediation
                        $issueCount++
                    }
                } else {
                    if     ($wearPct -ge $highWearThreshold)   { $severity = 'high' }
                    elseif ($wearPct -ge $mediumWearThreshold) { $severity = 'medium' }
                    elseif ($wearPct -ge $lowWearThreshold)    { $severity = 'low' }
                    else                                       { $severity = 'info' }

                    switch ($severity) {
                        'high' {
                            $title = "Battery '{0}' has lost about {1:N1}% of its original capacity, so unplugged runtime will feel dramatically shorter." -f $label, $wearPct
                            $remediation = 'Battery wear is high. Consider calibrating with a full charge/discharge and plan for replacement if runtime is insufficient.'
                        }
                        'medium' {
                            $title = "Battery '{0}' has lost about {1:N1}% of its original capacity, so unplugged runtime will be noticeably shorter." -f $label, $wearPct
                            $remediation = 'Battery wear is moderate. Monitor runtime; calibration may help tighten the reported full-charge capacity.'
                        }
                        'low' {
                            $title = "Battery '{0}' shows about {1:N1}% wear, so unplugged runtime will be slightly shorter than new." -f $label, $wearPct
                            $remediation = 'Slight wear detected. No action is required beyond periodic rechecks.'
                        }
                        default {
                            $title = "Battery '{0}' is in good health, so unplugged runtime should match expectations." -f $label
                            $remediation = 'Battery health is good. No action required.'
                        }
                    }

                    Add-CategoryIssue -CategoryResult $result -Severity $severity -Title $title -Evidence $evidence -Subcategory 'Battery' -Remediation $remediation
                    $issueCount++
                }

                if ($design -ne $null -and $full -ne $null) {
                    $detailsParts = New-Object System.Collections.Generic.List[string]
                    if ($cycleCount -ne $null) { $detailsParts.Add(("Cycle count: {0}" -f $cycleCount)) | Out-Null }
                    if ($battery.PSObject.Properties['Chemistry'] -and $battery.Chemistry) { $detailsParts.Add(("Chemistry: {0}" -f $battery.Chemistry)) | Out-Null }
                    if ($battery.PSObject.Properties['Manufacturer'] -and $battery.Manufacturer) { $detailsParts.Add(("Manufacturer: {0}" -f $battery.Manufacturer)) | Out-Null }

                    $wearDisplay = if ($wearPct -ne $null) { " | Wear: {0:N1}%" -f $wearPct } else { '' }
                    $details = if ($detailsParts.Count -gt 0) { $detailsParts.ToArray() -join '; ' } else { '' }
                    $fullStatusSuffix = if ($fullmAh -ne $null) { " (~{0:N0} mAh)" -f $fullmAh } else { '' }
                    $designStatusSuffix = if ($designmAh -ne $null) { " (~{0:N0} mAh)" -f $designmAh } else { '' }
                    $status = "Full: {0:N0} mWh{1} | Design: {2:N0} mWh{3}{4}" -f $full, $fullStatusSuffix, $design, $designStatusSuffix, $wearDisplay
                    Add-CategoryCheck -CategoryResult $result -Name ("Battery {0} capacity" -f $label) -Status $status -Details $details
                }

                if ($averageLife) {
                    $runtimeDisplay = $null
                    if ($averageLife.PSObject.Properties['AtFullChargeMinutes'] -and $averageLife.AtFullChargeMinutes -ne $null) {
                        $runtimeDisplay = & $formatBatteryRuntime ([double]$averageLife.AtFullChargeMinutes)
                    }
                    if (-not $runtimeDisplay -and $averageLife.PSObject.Properties['AtFullCharge'] -and $averageLife.AtFullCharge) {
                        $runtimeDisplay = [string]$averageLife.AtFullCharge
                    }

                    if ($runtimeDisplay) {
                        $details = if ($averageLife.PSObject.Properties['Period'] -and $averageLife.Period) { "Period: $($averageLife.Period)" } else { '' }
                        Add-CategoryCheck -CategoryResult $result -Name ("Battery {0} average runtime" -f $label) -Status $runtimeDisplay -Details $details
                    }
                }
            }
        }
    }

    $driversArtifact = Get-AnalyzerArtifact -Context $Context -Name 'drivers'
    Write-HeuristicDebug -Source 'Hardware' -Message 'Resolved driver artifact' -Data ([ordered]@{
        Found = [bool]$driversArtifact
    })

    if (-not $driversArtifact) {
        Add-CategoryIssue -CategoryResult $result -Severity 'info' -Title "Driver inventory artifact missing, so Device Manager issues can't be evaluated." -Subcategory 'Collection'
        return $result
    }

    $payload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $driversArtifact)
    Write-HeuristicDebug -Source 'Hardware' -Message 'Resolved driver payload' -Data ([ordered]@{
        HasPayload = [bool]$payload
    })

    if (-not $payload) {
        Add-CategoryIssue -CategoryResult $result -Severity 'info' -Title "Driver inventory payload missing, so Device Manager issues can't be evaluated." -Subcategory 'Collection'
        return $result
    }

    if ($payload.DriverQuery -and $payload.DriverQuery.PSObject.Properties['Error'] -and $payload.DriverQuery.Error) {
        $source = if ($payload.DriverQuery.PSObject.Properties['Source']) { [string]$payload.DriverQuery.Source } else { 'driverquery.exe' }
        $evidence = if ($payload.DriverQuery.Error) { [string]$payload.DriverQuery.Error } else { 'Unknown error' }
        Add-CategoryIssue -CategoryResult $result -Severity 'info' -Title "Driver inventory command failed, so Device Manager issues may be hidden." -Evidence ("{0}: {1}" -f $source, $evidence) -Subcategory 'Collection'
        return $result
    }

    if ($payload.PnpProblems -and $payload.PnpProblems.PSObject.Properties['Error'] -and $payload.PnpProblems.Error) {
        $source = if ($payload.PnpProblems.PSObject.Properties['Source']) { [string]$payload.PnpProblems.Source } else { 'pnputil.exe' }
        $evidence = if ($payload.PnpProblems.Error) { [string]$payload.PnpProblems.Error } else { 'Unknown error' }
        Add-CategoryIssue -CategoryResult $result -Severity 'info' -Title "Problem device inventory command failed, so Device Manager issues may be hidden." -Evidence ("{0}: {1}" -f $source, $evidence) -Subcategory 'Collection'
    }

    $inventory = Get-NormalizedDriverInventory -Payload $payload -VerboseLogging
    $entries = if ($inventory -and $inventory.Rows) { $inventory.Rows } else { @() }

    Write-HeuristicDebug -Source 'Hardware' -Message 'Resolved driver inventory' -Data ([ordered]@{
        RowCount = $entries.Count
        Source   = if ($inventory) { $inventory.Source } else { $null }
    })

    if ($entries.Count -eq 0) {
        Write-HeuristicDebug -Source 'Hardware' -Message 'Driver inventory parsing diagnostics' -Data ([ordered]@{
            AvailableProperties = if ($inventory -and $inventory.AvailableProperties -and $inventory.AvailableProperties.Count -gt 0) { $inventory.AvailableProperties -join ', ' } else { $null }
            TextPreview         = if ($inventory -and $inventory.TextPreview) { $inventory.TextPreview } else { $null }
        })
        $hasRawDriverData = $inventory -and ($inventory.HasDriverQueryData -or $inventory.HasTextPayload)
        $title = if ($hasRawDriverData) {
            "Driver inventory could not be parsed, so Device Manager issues may be hidden."
        } else {
            "Driver inventory empty, so Device Manager issues can't be evaluated."
        }
        Add-CategoryIssue -CategoryResult $result -Severity 'info' -Title $title -Subcategory 'Collection'
        return $result
    }

    $hasBluetoothDeviceSnapshot = $false
    $bluetoothDevicesPayload = $null
    $bluetoothDeviceRecords = @()
    $bluetoothDeviceError = $null
    $bluetoothDeviceSource = $null
    if ($payload.PSObject.Properties['BluetoothDevices']) {
        $bluetoothDevicesPayload = $payload.BluetoothDevices
        if ($bluetoothDevicesPayload) {
            $hasBluetoothDeviceSnapshot = $true
            $bluetoothDeviceSource = if ($bluetoothDevicesPayload.PSObject.Properties['Source']) { [string]$bluetoothDevicesPayload.Source } else { 'Get-PnpDevice -Class Bluetooth' }
            if ($bluetoothDevicesPayload.PSObject.Properties['Error'] -and $bluetoothDevicesPayload.Error) {
                $bluetoothDeviceError = [string]$bluetoothDevicesPayload.Error
            } elseif ($bluetoothDevicesPayload.PSObject.Properties['Items'] -and $bluetoothDevicesPayload.Items) {
                $bluetoothDeviceRecords = @($bluetoothDevicesPayload.Items | Where-Object { $_ })
            }
        }
    }

    $hasBluetoothServiceSnapshot = $false
    $bluetoothServicePayload = $null
    $bluetoothServiceStatus = $null
    $bluetoothServiceExists = $null
    $bluetoothServiceError = $null
    $bluetoothServiceSource = 'Get-Service'
    if ($payload.PSObject.Properties['BluetoothService']) {
        $bluetoothServicePayload = $payload.BluetoothService
        if ($bluetoothServicePayload) {
            $hasBluetoothServiceSnapshot = $true
            if ($bluetoothServicePayload.PSObject.Properties['Source'] -and $bluetoothServicePayload.Source) {
                $bluetoothServiceSource = [string]$bluetoothServicePayload.Source
            }
            if ($bluetoothServicePayload.PSObject.Properties['Error'] -and $bluetoothServicePayload.Error) {
                $bluetoothServiceError = [string]$bluetoothServicePayload.Error
            }
            if ($bluetoothServicePayload.PSObject.Properties['Status'] -and $bluetoothServicePayload.Status) {
                $bluetoothServiceStatus = ([string]$bluetoothServicePayload.Status).Trim()
            }
            if ($bluetoothServicePayload.PSObject.Properties['Exists']) {
                try { $bluetoothServiceExists = [bool]$bluetoothServicePayload.Exists } catch { $bluetoothServiceExists = $null }
            }
        }
    }

    if (-not $hasBluetoothDeviceSnapshot -and -not $bluetoothDeviceError) {
        $bluetoothDeviceError = 'Bluetooth device snapshot missing from driver collector payload.'
        if (-not $bluetoothDeviceSource) { $bluetoothDeviceSource = 'Get-PnpDevice -Class Bluetooth' }
    }

    if (-not $hasBluetoothServiceSnapshot -and -not $bluetoothServiceError) {
        $bluetoothServiceError = 'Bluetooth service snapshot missing from driver collector payload.'
    }

    $failureEventMap = Get-DriverFailureEventMap -Context $Context
    Write-HeuristicDebug -Source 'Hardware' -Message 'Loaded driver failure event map' -Data ([ordered]@{
        HasEvents = ($failureEventMap -and ($failureEventMap.Count -gt 0))
        Keys      = if ($failureEventMap) { $failureEventMap.Count } else { 0 }
    })

    foreach ($entry in $entries) {
        if (-not $entry) { continue }

        $label = Get-DriverLabel -Entry $entry
        $statusRaw = Get-DriverPropertyValue -Entry $entry -Names @('Status')
        $statusNormalized = Normalize-DriverStatus -Value $statusRaw
        if ($statusNormalized -and $statusNormalized -ne 'ok' -and $statusNormalized -ne 'unknown') {
            $severity = switch ($statusNormalized) {
                'error'    { 'high' }
                'degraded' { 'medium' }
                default    { 'info' }
            }
            $title = if ($statusRaw) {
                "Driver status '{0}' reported for {1}, so the device may malfunction." -f $statusRaw, $label
            } else {
                "Driver status indicates an issue for {0}, so the device may malfunction." -f $label
            }
            Add-CategoryIssue -CategoryResult $result -Severity $severity -Title $title -Evidence (Get-DriverEvidence -Entry $entry) -Subcategory 'Device Manager'
            $issueCount++
        }

        $stateRaw = Get-DriverPropertyValue -Entry $entry -Names @('State')
        $startModeRaw = Get-DriverPropertyValue -Entry $entry -Names @('Start Mode','StartMode')
        $stateNormalized = Normalize-DriverState -Value $stateRaw
        $startModeNormalized = Normalize-DriverStartMode -Value $startModeRaw
        $driverTypeRaw = Get-DriverPropertyValue -Entry $entry -Names @('Driver Type','Type','Service Type')
        $driverTypeNormalized = Normalize-DriverType -Value $driverTypeRaw

        $shouldFlagStartIssue = $false
        $failureEvents = @()

        if ($startModeNormalized -in @('boot','system','auto') -and $stateNormalized -ne 'running' -and $stateNormalized -ne 'pending') {
            if ($startModeNormalized -eq 'auto') {
                $shouldFlagStartIssue = $true
            } elseif ($startModeNormalized -in @('boot','system')) {
                if ($driverTypeNormalized -eq 'kernel') {
                    $candidates = Get-DriverNameCandidates -Entry $entry
                    $failureEvents = Find-DriverFailureEvents -Candidates $candidates -Map $failureEventMap
                    if ($failureEvents -and $failureEvents.Count -gt 0) {
                        $shouldFlagStartIssue = $true
                    } else {
                        Write-HeuristicDebug -Source 'Hardware' -Message 'Skipping stopped boot/system kernel driver without corroborating events' -Data ([ordered]@{
                            Driver     = $label
                            StartMode  = $startModeRaw
                            State      = $stateRaw
                            DriverType = $driverTypeRaw
                        })
                    }
                } else {
                    $shouldFlagStartIssue = $true
                }
            }
        }

        if ($shouldFlagStartIssue) {
            $severity = if ($startModeNormalized -in @('boot','system')) { 'high' } else { 'medium' }
            $errorControlRaw = Get-DriverPropertyValue -Entry $entry -Names @('Error Control','ErrorControl')
            $errorControlNormalized = Normalize-DriverErrorControl -Value $errorControlRaw
            if ($errorControlNormalized -eq 'critical') { $severity = 'critical' }

            $title = if ($stateRaw -and $startModeRaw) {
                "Driver {0} is {1} despite start mode {2}, so hardware may not initialize." -f $label, $stateRaw, $startModeRaw
            } elseif ($startModeRaw) {
                "Driver {0} is not running despite start mode {1}, so hardware may not initialize." -f $label, $startModeRaw
            } else {
                "Driver {0} is not running despite an automatic start mode, so hardware may not initialize." -f $label
            }

            $evidenceParts = New-Object System.Collections.Generic.List[string]
            $driverEvidence = Get-DriverEvidence -Entry $entry
            if ($driverEvidence) { $evidenceParts.Add($driverEvidence) | Out-Null }

            if ($failureEvents -and $failureEvents.Count -gt 0) {
                $eventEvidence = Format-DriverFailureEvidence -Events $failureEvents
                if ($eventEvidence) {
                    $evidenceParts.Add("Related events:`n$eventEvidence") | Out-Null
                }
            }

            $evidence = if ($evidenceParts.Count -gt 0) { $evidenceParts.ToArray() -join "`n`n" } else { $null }

            Add-CategoryIssue -CategoryResult $result -Severity $severity -Title $title -Evidence $evidence -Subcategory 'Device Manager'
            $issueCount++
        }
    }

    $pnpText = ConvertTo-HardwareDriverText -Value $payload.PnpProblems
    Write-HeuristicDebug -Source 'Hardware' -Message 'Problem device text resolved' -Data ([ordered]@{
        HasText = [bool]$pnpText
        Length  = if ($pnpText) { $pnpText.Length } else { 0 }
    })

    $pnpEntries = @()
    if ($pnpText) {
        $pnpEntries = Parse-DriverQueryEntries -Text $pnpText
        Write-HeuristicDebug -Source 'Hardware' -Message 'Parsed problem device entries' -Data ([ordered]@{
            EntryCount = $pnpEntries.Count
        })

        foreach ($entry in $pnpEntries) {
            if (-not $entry) { continue }

            $label = Get-PnpDeviceLabel -Entry $entry
            $statusRaw = Get-DriverPropertyValue -Entry $entry -Names @('Status','Problem Status')
            $problemRaw = Get-DriverPropertyValue -Entry $entry -Names @('Problem','Problem Code','ProblemStatus')
            $normalized = Normalize-PnpProblem -Values @($statusRaw, $problemRaw)

            $className = Get-DriverPropertyValue -Entry $entry -Names @('Class Name','ClassName','Class')
            $description = Get-DriverPropertyValue -Entry $entry -Names @('Device Description','Friendly Name','Name')
            $instanceId = Get-DriverPropertyValue -Entry $entry -Names @('Instance ID','InstanceId','Device Instance ID')
            $isBluetoothDevice = $false
            foreach ($candidate in @($className, $label, $description, $instanceId)) {
                if (-not $candidate) { continue }
                if (Test-BluetoothIndicator -Value $candidate) {
                    $isBluetoothDevice = $true
                    break
                }
            }
            if ($normalized -eq 'missing-driver') {
                if ($isBluetoothDevice) { continue }
                $title = "Device {0} is missing drivers (Code 28), so functionality may be limited." -f $label
                Add-CategoryIssue -CategoryResult $result -Severity 'medium' -Title $title -Evidence (Get-PnpDeviceEvidence -Entry $entry) -Subcategory 'Device Manager'
                $issueCount++
                continue
            }

            if ($normalized -eq 'problem') {
                if ($isBluetoothDevice) { continue }
                $title = "Device Manager reports a problem for {0}." -f $label
                Add-CategoryIssue -CategoryResult $result -Severity 'info' -Title $title -Evidence (Get-PnpDeviceEvidence -Entry $entry) -Subcategory 'Device Manager'
                $issueCount++
            }
        }
    }

    Write-HeuristicDebug -Source 'Hardware/Bluetooth' -Message 'Bluetooth snapshot summary' -Data ([ordered]@{
        DeviceSnapshotPresent  = $hasBluetoothDeviceSnapshot
        DeviceRecordCount      = $bluetoothDeviceRecords.Count
        DeviceErrorPresent     = [bool]$bluetoothDeviceError
        ServiceSnapshotPresent = $hasBluetoothServiceSnapshot
        ServiceStatus          = $bluetoothServiceStatus
        ServiceExists          = $bluetoothServiceExists
        ServiceErrorPresent    = [bool]$bluetoothServiceError
    })

    $bluetoothCanEvaluate = $true
    if ($bluetoothDeviceError) {
        $title = 'Bluetooth hardware query failed, so wireless accessory health could not be evaluated automatically.'
        $evidence = "{0}: {1}" -f $bluetoothDeviceSource, $bluetoothDeviceError
        Add-CategoryIssue -CategoryResult $result -Severity 'info' -Title $title -Evidence $evidence -Subcategory 'Bluetooth'
        $issueCount++
        $bluetoothCanEvaluate = $false
    }

    if ($bluetoothServiceError) {
        $title = 'Bluetooth service snapshot missing, so technicians cannot confirm if wireless accessories will work.'
        $evidence = "{0}: {1}" -f $bluetoothServiceSource, $bluetoothServiceError
        Add-CategoryIssue -CategoryResult $result -Severity 'info' -Title $title -Evidence $evidence -Subcategory 'Bluetooth'
        $issueCount++
        $bluetoothCanEvaluate = $false
    }

    if ($bluetoothCanEvaluate) {
        $radioCandidates = @()
        if ($bluetoothDeviceRecords.Count -gt 0) {
            $radioCandidates = @($bluetoothDeviceRecords | Where-Object { $_.InstanceId -and ($_.InstanceId -like 'USB\VID*') })
        }

        $radiosOk = @()
        $radiosWithIssues = @()
        foreach ($radio in $radioCandidates) {
            $statusValue = if ($radio.Status) { [string]$radio.Status } else { 'Unknown' }
            if ($statusValue -eq 'OK') {
                $radiosOk += $radio
                continue
            }
            if ($statusValue -in @('Error','Degraded')) {
                $radiosWithIssues += $radio
            }
        }

        $serviceRunning = $bluetoothServiceStatus -eq 'Running'
        $serviceKnown = ($bluetoothServiceStatus -ne $null -and $bluetoothServiceStatus -ne '') -or ($bluetoothServiceExists -ne $null)

        $evidenceLines = New-Object System.Collections.Generic.List[string]
        $serviceDisplay = if ($bluetoothServiceExists -eq $false) { 'Not Found' } elseif ($serviceKnown) { if ($bluetoothServiceStatus) { $bluetoothServiceStatus } else { 'Unknown' } } else { 'Unknown' }
        $evidenceLines.Add("Bluetooth Support Service (bthserv) status: $serviceDisplay") | Out-Null
        $evidenceLines.Add("USB Bluetooth radios detected: $($radioCandidates.Count)") | Out-Null

        foreach ($radio in $radioCandidates) {
            $name = if ($radio.FriendlyName) { [string]$radio.FriendlyName } elseif ($radio.InstanceId) { [string]$radio.InstanceId } else { 'Unknown device' }
            $statusText = if ($radio.Status) { [string]$radio.Status } else { 'Unknown' }
            $evidenceLines.Add("- $name — Status: $statusText") | Out-Null
        }

        $evidence = if ($evidenceLines.Count -gt 0) { $evidenceLines.ToArray() -join "`n" } else { $null }

        if ($radioCandidates.Count -eq 0) {
            Add-CategoryIssue -CategoryResult $result -Severity 'warning' -Title 'Bluetooth adapter not detected, so wireless accessories cannot pair.' -Evidence $evidence -Subcategory 'Bluetooth'
            $issueCount++
        } elseif ($radiosOk.Count -eq 0 -or $radiosWithIssues.Count -gt 0) {
            Add-CategoryIssue -CategoryResult $result -Severity 'high' -Title 'Bluetooth adapter detected but reports errors, so wireless accessories cannot pair.' -Evidence $evidence -Subcategory 'Bluetooth'
            $issueCount++
        } elseif (-not $serviceRunning) {
            Add-CategoryIssue -CategoryResult $result -Severity 'high' -Title 'Bluetooth adapter detected but support service is not running, so wireless accessories cannot pair.' -Evidence $evidence -Subcategory 'Bluetooth'
            $issueCount++
        } else {
            Add-CategoryNormal -CategoryResult $result -Title 'Bluetooth adapter detected and appears to be working normally.' -Subcategory 'Bluetooth'
        }
    }

    Write-HeuristicDebug -Source 'Hardware' -Message 'Device Manager analysis completed' -Data ([ordered]@{
        IssuesRaised = $issueCount
    })

    if ($issueCount -eq 0) {
        Add-CategoryNormal -CategoryResult $result -Title 'Device Manager reports all drivers healthy.' -Subcategory 'Device Manager'
    }

    return $result
}
