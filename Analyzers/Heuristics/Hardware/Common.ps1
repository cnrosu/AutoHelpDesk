function ConvertTo-HardwareDriverText {
    param(
        $Value
    )

    if ($null -eq $Value) { return $null }

    if ($Value -is [pscustomobject]) {
        if ($Value.PSObject.Properties['Error'] -and $Value.Error) {
            return $null
        }
        if ($Value.PSObject.Properties['Value'] -and $Value.Value) {
            return [string]$Value.Value
        }
    }

    if ($Value -is [System.Collections.IEnumerable] -and -not ($Value -is [string])) {
        $builder = [System.Text.StringBuilder]::new()
        foreach ($item in $Value) {
            if ($null -eq $item) { continue }
            $text = [string]$item
            if ($builder.Length -gt 0) { $null = $builder.AppendLine() }
            $null = $builder.Append($text)
        }
        return $builder.ToString()
    }

    return [string]$Value
}

function Add-UniqueDriverNameVariant {
    param(
        [System.Collections.Generic.List[string]]$List,
        [hashtable]$Lookup,
        [string]$Name
    )

    if (-not $List -or -not $Lookup) { return }
    if ([string]::IsNullOrWhiteSpace($Name)) { return }

    $trimmed = $Name.Trim(' `t`r`n.:;''"'.ToCharArray())
    if (-not $trimmed) { return }

    $candidates = [System.Collections.Generic.List[string]]::new()
    $candidates.Add($trimmed) | Out-Null

    $withoutSuffix = [regex]::Replace($trimmed, '\\b(service|driver)\\b$', '', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase).Trim(' `t`r`n.:;''"'.ToCharArray())
    if ($withoutSuffix -and ($withoutSuffix -ne $trimmed)) {
        $candidates.Add($withoutSuffix) | Out-Null
    }

    foreach ($candidate in @($trimmed, $withoutSuffix)) {
        if (-not $candidate) { continue }
        $dotIndex = $candidate.IndexOf('.')
        if ($dotIndex -gt 0) {
            $prefix = $candidate.Substring(0, $dotIndex)
            if ($prefix -and ($prefix -ne $candidate)) {
                $candidates.Add($prefix) | Out-Null
            }
        }
    }

    foreach ($candidate in $candidates) {
        if (-not $candidate) { continue }
        $lower = $candidate.ToLowerInvariant()
        if (-not $Lookup.ContainsKey($lower)) {
            $Lookup[$lower] = $true
            $List.Add($candidate) | Out-Null
        }
    }
}

function Parse-DriverQueryEntries {
    param(
        [string]$Text
    )

    $entries = New-Object System.Collections.Generic.List[pscustomobject]
    if ([string]::IsNullOrWhiteSpace($Text)) { return $entries.ToArray() }

    $lines = $Text -split '\r?\n'
    $current = [ordered]@{}

    foreach ($line in $lines) {
        if ($null -eq $line) { continue }
        $trimmed = $line.TrimEnd()
        if (-not $trimmed) {
            if ($current.Count -gt 0) {
                $entries.Add([pscustomobject]$current) | Out-Null
                $current = [ordered]@{}
            }
            continue
        }

        $match = [regex]::Match($trimmed, '^(?<key>[^:]+?):\\s*(?<value>.*)$')
        if ($match.Success) {
            $key = $match.Groups['key'].Value.Trim()
            $value = $match.Groups['value'].Value
            if ($null -ne $value) { $value = $value.Trim() }

            if (-not $current.Contains($key)) {
                $current[$key] = $value
            } else {
                $existing = $current[$key]
                if ($existing -is [System.Collections.IEnumerable] -and -not ($existing -is [string])) {
                    $items = New-Object System.Collections.Generic.List[object]
                    foreach ($item in $existing) { $items.Add($item) | Out-Null }
                    $items.Add($value) | Out-Null
                    $current[$key] = $items.ToArray()
                } else {
                    $current[$key] = @($existing, $value)
                }
            }
            continue
        }

        if ($current.Count -gt 0) {
            $keysArray = @($current.Keys)
            if ($keysArray.Count -gt 0) {
                $lastKey = $keysArray[$keysArray.Count - 1]
                $existingValue = $current[$lastKey]
                $addition = $trimmed.Trim()
                if ($existingValue -is [System.Collections.IEnumerable] -and -not ($existingValue -is [string])) {
                    $lastIndex = $existingValue.Count - 1
                    if ($lastIndex -ge 0) {
                        $existingValue[$lastIndex] = ("{0} {1}" -f $existingValue[$lastIndex], $addition).Trim()
                    }
                } else {
                    $current[$lastKey] = ("{0} {1}" -f $existingValue, $addition).Trim()
                }
            }
        }
    }

    if ($current.Count -gt 0) {
        $entries.Add([pscustomobject]$current) | Out-Null
    }

    return $entries.ToArray()
}

function Get-DriverPropertyValue {
    param(
        [Parameter(Mandatory)]$Entry,
        [Parameter(Mandatory)][string[]]$Names
    )

    foreach ($name in $Names) {
        $prop = $Entry.PSObject.Properties[$name]
        if (-not $prop) { continue }
        $raw = $prop.Value
        if ($null -eq $raw) { continue }

        if ($raw -is [System.Collections.IEnumerable] -and -not ($raw -is [string])) {
            $values = New-Object System.Collections.Generic.List[string]
            foreach ($item in $raw) {
                if ($null -eq $item) { continue }
                $text = [string]$item
                if (-not [string]::IsNullOrWhiteSpace($text)) {
                    $values.Add($text.Trim()) | Out-Null
                }
            }
            if ($values.Count -gt 0) {
                return ($values.ToArray() -join '; ')
            }
        } else {
            $text = [string]$raw
            if (-not [string]::IsNullOrWhiteSpace($text)) {
                return $text.Trim()
            }
        }
    }

    return $null
}

function Get-DriverLabel {
    param($Entry)

    $label = Get-DriverPropertyValue -Entry $Entry -Names @('Display Name','Module Name','Driver Name','Name')
    if ($label) { return $label }
    return 'Unknown driver'
}

function Get-DriverNameCandidates {
    param($Entry)

    $list = [System.Collections.Generic.List[string]]::new()
    $lookup = @{}

    foreach ($name in @('Display Name','Module Name','Driver Name','Name','Service Name')) {
        $value = Get-DriverPropertyValue -Entry $Entry -Names @($name)
        if ($value) {
            Add-UniqueDriverNameVariant -List $list -Lookup $lookup -Name $value
        }
    }

    return $list.ToArray()
}

function Get-DriverEvidence {
    param($Entry)

    $lines = New-Object System.Collections.Generic.List[string]
    foreach ($name in @('Display Name','Module Name','Driver Type','Start Mode','State','Status','Error Control','Path','Image Path','Link Date')) {
        $value = Get-DriverPropertyValue -Entry $Entry -Names @($name)
        if ($value) {
            $lines.Add(("{0}: {1}" -f $name, $value)) | Out-Null
        }
    }

    if ($lines.Count -eq 0) { return $null }
    return ($lines.ToArray() -join "`n")
}

function Get-PnpDeviceLabel {
    param($Entry)

    $label = Get-DriverPropertyValue -Entry $Entry -Names @('Device Description','Friendly Name','Name','Instance ID','InstanceID')
    if ($label) { return $label }
    return 'Unknown device'
}

function Get-PnpDeviceEvidence {
    param($Entry)

    $lines = New-Object System.Collections.Generic.List[string]
    foreach ($name in @('Device Description','Instance ID','Class Name','Manufacturer Name','Status','Problem','Problem Status')) {
        $value = Get-DriverPropertyValue -Entry $Entry -Names @($name)
        if ($value) {
            $lines.Add(("{0}: {1}" -f $name, $value)) | Out-Null
        }
    }

    if ($lines.Count -eq 0) { return $null }
    return ($lines.ToArray() -join "`n")
}
