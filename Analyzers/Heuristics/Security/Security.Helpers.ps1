function ConvertTo-List {
    param($Value)

    if ($null -eq $Value) { return @() }
    if ($Value -is [string]) { return @($Value) }
    if ($Value -is [System.Collections.IEnumerable] -and -not ($Value -is [string])) {
        $items = [System.Collections.Generic.List[object]]::new()
        foreach ($item in $Value) { $items.Add($item) }
        return $items.ToArray()
    }
    return @($Value)
}

function ConvertTo-IntArray {
    param($Value)

    $list = [System.Collections.Generic.List[int]]::new()
    foreach ($item in (ConvertTo-List $Value)) {
        if ($null -eq $item) { continue }
        $text = $item.ToString()
        $parsed = 0
        if ([int]::TryParse($text, [ref]$parsed)) {
            $list.Add($parsed)
        }
    }
    return $list.ToArray()
}

function Get-ObjectPropertyString {
    param(
        $Object,
        [string]$PropertyName,
        [string]$NullPlaceholder = 'null'
    )

    if (-not $Object) { return $NullPlaceholder }
    if (-not $PropertyName) { return $NullPlaceholder }

    $property = $Object.PSObject.Properties[$PropertyName]
    if (-not $property) { return $NullPlaceholder }

    $value = $property.Value
    if ($null -eq $value) { return $NullPlaceholder }

    if ($value -is [bool]) {
        if ($value) { return 'True' }
        return 'False'
    }
    return [string]$value
}

function Format-BitLockerVolume {
    param($Volume)

    $parts = [System.Collections.Generic.List[string]]::new()
    if ($Volume.MountPoint) { $parts.Add(("Mount: {0}" -f $Volume.MountPoint)) }
    if ($Volume.VolumeType) { $parts.Add(("Type: {0}" -f $Volume.VolumeType)) }
    if ($Volume.ProtectionStatus -ne $null) { $parts.Add(("Protection: {0}" -f $Volume.ProtectionStatus)) }
    if ($Volume.EncryptionMethod) { $parts.Add(("Method: {0}" -f $Volume.EncryptionMethod)) }
    if ($Volume.LockStatus) { $parts.Add(("Lock: {0}" -f $Volume.LockStatus)) }
    if ($Volume.AutoUnlockEnabled -ne $null) { $parts.Add(("AutoUnlock: {0}" -f $Volume.AutoUnlockEnabled)) }
    return ($parts.ToArray() -join '; ')
}

function Get-RegistryValueFromEntries {
    param(
        $Entries,
        [string]$PathPattern,
        [string]$Name
    )

    if (-not $Entries) { return $null }

    foreach ($entry in (ConvertTo-List $Entries)) {
        if (-not $entry) { continue }
        if (-not $Name) { continue }
        if ($entry.PSObject.Properties['Error'] -and $entry.Error) { continue }
        if ($PathPattern -and -not ($entry.Path -and $entry.Path -match $PathPattern)) { continue }

        $values = $null
        if ($entry.PSObject.Properties['Values']) {
            $values = $entry.Values
        }

        if (-not $values) { continue }

        if ($values -is [System.Collections.IDictionary]) {
            foreach ($key in $values.Keys) {
                if ($null -eq $key) { continue }
                if ([string]$key -ieq $Name) {
                    return $values[$key]
                }
            }
        }

        $property = $values.PSObject.Properties[$Name]
        if ($property) { return $property.Value }

        foreach ($candidate in $values.PSObject.Properties) {
            if (-not $candidate) { continue }
            if ($candidate.Name -ieq $Name) {
                return $candidate.Value
            }
        }

        $valueItems = @()
        if ($values -is [System.Collections.IEnumerable] -and -not ($values -is [string]) -and -not ($values -is [pscustomobject])) {
            $valueItems = ConvertTo-List $values
        }

        foreach ($item in $valueItems) {
            if (-not $item) { continue }
            if ($item -is [System.Collections.DictionaryEntry]) {
                if ([string]$item.Key -ieq $Name) { return $item.Value }
                continue
            }

            if ($item.PSObject.Properties['Name'] -and $item.PSObject.Properties['Value']) {
                if ($item.Name -ieq $Name) { return $item.Value }
            }
        }
    }

    return $null
}

function ConvertTo-NullablePolicyInt {
    param($Value)

    if ($Value -is [int]) { return [int]$Value }
    if ($null -eq $Value) { return $null }

    $text = [string]$Value
    if ([string]::IsNullOrWhiteSpace($text)) { return $null }

    $trimmed = $text.Trim()
    if ($trimmed -match '^(?i)0x[0-9a-f]+$') {
        try {
            return [Convert]::ToInt32($trimmed.Substring(2), 16)
        } catch {
            return $null
        }
    }

    $parsed = 0
    if ([int]::TryParse($trimmed, [ref]$parsed)) {
        return $parsed
    }

    return $null
}

function Get-AutorunPolicyValue {
    param(
        $Entries,
        [string[]]$PreferredPaths,
        [string]$Name
    )

    if (-not $Entries) { return $null }

    foreach ($path in $PreferredPaths) {
        foreach ($entry in (ConvertTo-List $Entries)) {
            if (-not $entry) { continue }
            if ($entry.Path -ne $path) { continue }
            if ($entry.Error) { continue }
            if ($entry.PSObject.Properties['Exists'] -and -not $entry.Exists) { continue }
            if (-not $entry.Values) { continue }

            $property = $entry.Values.PSObject.Properties[$Name]
            if (-not $property) { continue }

            $converted = ConvertTo-NullablePolicyInt $property.Value
            return [pscustomobject]@{
                Path     = $entry.Path
                Value    = $converted
                RawValue = $property.Value
            }
        }
    }

    foreach ($entry in (ConvertTo-List $Entries)) {
        if (-not $entry) { continue }
        if ($entry.Error) { continue }
        if ($entry.PSObject.Properties['Exists'] -and -not $entry.Exists) { continue }
        if (-not $entry.Values) { continue }

        $property = $entry.Values.PSObject.Properties[$Name]
        if (-not $property) { continue }

        $converted = ConvertTo-NullablePolicyInt $property.Value
        return [pscustomobject]@{
            Path     = $entry.Path
            Value    = $converted
            RawValue = $property.Value
        }
    }

    return $null
}
