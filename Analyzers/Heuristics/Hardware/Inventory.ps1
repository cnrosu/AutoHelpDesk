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

    $msinfoIdentity = Get-MsinfoSystemIdentity -Context $Context
    $msinfoSummary = $null
    if ($msinfoIdentity -and $msinfoIdentity.PSObject.Properties['Summary']) {
        $msinfoSummary = $msinfoIdentity.Summary
    } else {
        $msinfoSummary = Get-MsinfoSystemSummarySection -Context $Context
    }

    $processorRows = Get-MsinfoProcessors -Context $Context

    $firmwareArtifact = Get-AnalyzerArtifact -Context $Context -Name 'firmware'
    $tpmArtifact      = Get-AnalyzerArtifact -Context $Context -Name 'tpm'

    $firmwarePayload = $null
    if ($firmwareArtifact) {
        $firmwarePayload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $firmwareArtifact)
    }

    $tpmPayload = $null
    if ($tpmArtifact) {
        $tpmPayload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $tpmArtifact)
    }

    $hasMsinfo = $false
    if ($msinfoIdentity) { $hasMsinfo = $true }
    elseif ($msinfoSummary) { $hasMsinfo = $true }
    elseif ($processorRows) { $hasMsinfo = $true }

    if (-not $hasMsinfo -and -not $firmwarePayload -and -not $tpmPayload) {
        return $null
    }

    $title = 'Hardware inventory summary'
    $evidence = $null

    $cpuEntries = New-Object System.Collections.Generic.List[pscustomobject]
    $cpuSummaryParts = New-Object System.Collections.Generic.List[string]
    $cpuAvailable = $false

    $parseNumber = {
        param($text)
        if (-not $text) { return $null }
        $match = [regex]::Match([string]$text, '\d+')
        if ($match.Success) {
            try { return [int]$match.Value } catch { return $null }
        }
        return $null
    }

    if ($processorRows) {
        foreach ($row in $processorRows) {
            if (-not $row) { continue }

            $entry = [ordered]@{}
            $name = Get-MsinfoRowValue -Row $row -Names @('Name', 'ProcessorName', 'Processor')
            if ($name) { $entry['Name'] = $name }
            $manufacturer = Get-MsinfoRowValue -Row $row -Names @('Manufacturer')
            if ($manufacturer) { $entry['Manufacturer'] = $manufacturer }
            $coresValue = Get-MsinfoRowValue -Row $row -Names @('NumberOfCores', 'Number Of Cores')
            $cores = & $parseNumber $coresValue
            if ($cores -ne $null) { $entry['Cores'] = $cores }
            $logicalValue = Get-MsinfoRowValue -Row $row -Names @('NumberOfLogicalProcessors', 'Number Of Logical Processors')
            $logical = & $parseNumber $logicalValue
            if ($logical -ne $null) { $entry['LogicalProcessors'] = $logical }
            $clockValue = Get-MsinfoRowValue -Row $row -Names @('MaxClockSpeed', 'Maximum Clock Speed', 'CurrentClockSpeed')
            $clock = & $parseNumber $clockValue
            if ($clock -ne $null) { $entry['MaxClockMHz'] = $clock }
            $socket = Get-MsinfoRowValue -Row $row -Names @('SocketDesignation', 'Socket Designation', 'Socket')
            if ($socket) { $entry['Socket'] = $socket }

            if ($entry.Count -gt 0) {
                $cpuEntries.Add([pscustomobject]$entry) | Out-Null
            }
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

    $cpuSummary = $null
    if ($cpuSummaryParts.Count -gt 0) {
        $cpuSummary = $cpuSummaryParts.ToArray() -join '; '
    } elseif ($msinfoSummary) {
        $processorSummary = Get-MsinfoSystemSummaryValue -Summary $msinfoSummary -Names @('Processor')
        if ($processorSummary) {
            $cpuSummary = $processorSummary
            $cpuAvailable = $true
        }
    }

    $cpuInfo = [ordered]@{
        Available  = $cpuAvailable
        Summary    = $cpuSummary
        Processors = $cpuEntries.ToArray()
    }

    $memoryBytes = $null
    if ($msinfoIdentity -and $msinfoIdentity.TotalPhysicalMemoryBytes -ne $null) {
        $memoryBytes = $msinfoIdentity.TotalPhysicalMemoryBytes
    } elseif ($msinfoIdentity -and $msinfoIdentity.InstalledPhysicalMemoryBytes -ne $null) {
        $memoryBytes = $msinfoIdentity.InstalledPhysicalMemoryBytes
    }

    $memoryInfo = [ordered]@{ Available = ($memoryBytes -ne $null) }
    if ($memoryBytes -ne $null) {
        $totalGb = [math]::Round(($memoryBytes / 1GB), 2)
        $memoryInfo['TotalBytes'] = $memoryBytes
        $memoryInfo['TotalGB'] = $totalGb
        $memoryInfo['Summary'] = ("{0:N2} GB" -f $totalGb)
    } elseif ($msinfoIdentity -and $msinfoIdentity.InstalledPhysicalMemory) {
        $memoryInfo['Summary'] = $msinfoIdentity.InstalledPhysicalMemory
        $memoryInfo['Available'] = $true
    }

    $modelInfo = [ordered]@{ Available = $false }
    if ($msinfoIdentity) {
        if ($msinfoIdentity.Manufacturer) { $modelInfo['Manufacturer'] = $msinfoIdentity.Manufacturer }
        if ($msinfoIdentity.Model) { $modelInfo['Model'] = $msinfoIdentity.Model }
        if ($msinfoIdentity.Domain) { $modelInfo['Domain'] = $msinfoIdentity.Domain }
        if ($msinfoIdentity.PartOfDomain -ne $null) { $modelInfo['PartOfDomain'] = [bool]$msinfoIdentity.PartOfDomain }
        if ($msinfoIdentity.DomainRole -ne $null) { $modelInfo['DomainRole'] = $msinfoIdentity.DomainRole }
        if ($msinfoIdentity.SystemSku) { $modelInfo['Sku'] = $msinfoIdentity.SystemSku }
    }

    if ($msinfoSummary) {
        $systemType = Get-MsinfoSystemSummaryValue -Summary $msinfoSummary -Names @('System Type')
        if ($systemType) { $modelInfo['SystemType'] = $systemType }
    }

    if ($cpuEntries.Count -gt 0) {
        $logicalTotal = 0
        $logicalFound = $false
        foreach ($entry in $cpuEntries) {
            if ($entry.PSObject.Properties['LogicalProcessors'] -and $entry.LogicalProcessors -ne $null) {
                $logicalTotal += [int]$entry.LogicalProcessors
                $logicalFound = $true
            }
        }
        if ($logicalFound) { $modelInfo['LogicalProcessors'] = $logicalTotal }
        $modelInfo['PhysicalProcessors'] = $cpuEntries.Count
    }

    if ($modelInfo.PSObject.Properties['Manufacturer'] -and $modelInfo.PSObject.Properties['Model']) {
        $modelInfo['Summary'] = "{0} {1}" -f $modelInfo.Manufacturer, $modelInfo.Model
    } elseif ($modelInfo.PSObject.Properties['Manufacturer']) {
        $modelInfo['Summary'] = $modelInfo.Manufacturer
    } elseif ($modelInfo.PSObject.Properties['Model']) {
        $modelInfo['Summary'] = $modelInfo.Model
    }

    if ($modelInfo.Summary -or $modelInfo.Manufacturer -or $modelInfo.Model -or $modelInfo.Domain -or $modelInfo.SystemType) {
        $modelInfo['Available'] = $true
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
        if ($secureBoot.PSObject.Properties['BCDValue']) {
            $value = $secureBoot.BCDValue
            if ($value -ne $null -and $value -ne '') {
                $secureBootInfo['BCDValue'] = [string]$value
                $sources.Add("BCD Secure Boot: {0}" -f $value) | Out-Null
            }
        }

        if ($sources.Count -gt 0) {
            $secureBootInfo['Available'] = $true
            $secureBootInfo['Summary'] = ($sources.ToArray() -join '; ')
        }
    }

    $biosInfo = [ordered]@{
        Available = $false
    }
    if ($firmware -and $firmware.PSObject.Properties['Bios']) {
        $bios = $firmware.Bios
        if ($bios) {
            foreach ($prop in @('Manufacturer','Name','Version','SMBIOSBIOSVersion','ReleaseDate','BuildNumber')) {
                if ($bios.PSObject.Properties[$prop] -and $bios.$prop) {
                    $biosInfo[$prop] = [string]$bios.$prop
                }
            }

            $summaryParts = @()
            foreach ($prop in @('Manufacturer','Name','Version','SMBIOSBIOSVersion')) {
                if ($biosInfo[$prop]) {
                    $summaryParts += $biosInfo[$prop]
                }
            }

            if ($summaryParts.Count -gt 0) {
                $biosInfo['Summary'] = ($summaryParts -join ' ')
                $biosInfo['Available'] = $true
            }
        }
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
