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
