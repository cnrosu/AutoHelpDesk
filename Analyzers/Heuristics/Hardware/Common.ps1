function ConvertTo-HardwareDriverText {
    param(
        $Value
    )

    if ($null -eq $Value) { return $null }

    if ($Value -is [pscustomobject]) {
        if ($Value.PSObject.Properties['Error'] -and $Value.Error) {
            return $null
        }
        if ($Value.PSObject.Properties['Value']) {
            $inner = $Value.Value
            if ($null -eq $inner) { return $null }
            if ([object]::ReferenceEquals($inner, $Value)) { return $null }
            return ConvertTo-HardwareDriverText -Value $inner
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

function Get-NormalizedDriverInventory {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $Payload,

        [switch]$VerboseLogging
    )

    $rows = @()
    $source = $null
    $driverQueryPropertyPresent = $false
    $driverQueryPropertyHasItems = $false
    $textPayloadUsed = $false
    $textPayloadPresent = $false

    if ($Payload -and $Payload.PSObject.Properties['DriverQuery']) {
        $driverQueryPropertyPresent = $true
        $candidate = $Payload.DriverQuery
        if ($candidate -is [System.Collections.IEnumerable] -and -not ($candidate -is [string])) {
            $rows = @($candidate)
            if ($rows.Count -gt 0) {
                $source = 'Payload.DriverQuery (objects)'
                $driverQueryPropertyHasItems = $true
            }
        } elseif ($candidate) {
            $driverQueryPropertyHasItems = $true
        }
    }

    if (-not $rows -or $rows.Count -eq 0) {
        $candidateProps = @('DriverQueryText','DriverQueryCsv','DriverQueryVerboseCsv','Text')
        foreach ($prop in $candidateProps) {
            if (-not ($Payload.PSObject.Properties[$prop])) { continue }

            $text = [string]$Payload.$prop
            if ([string]::IsNullOrWhiteSpace($text)) { continue }

            $textPayloadPresent = $true

            if ($text -match '\\r\\n') {
                $text = [System.Text.RegularExpressions.Regex]::Unescape($text)
            }

            try {
                $rows = @($text | ConvertFrom-Csv)
                if ($rows.Count -gt 0) {
                    $source = "Payload.$prop (csv text)"
                    $textPayloadUsed = $true
                    break
                }
            } catch {
                if ($VerboseLogging) {
                    Write-Warning ("[Hardware/Drivers] ConvertFrom-Csv failed from {0}: {1}" -f $prop, $_.Exception.Message)
                }
            }
        }
    }

    if (-not $rows -or $rows.Count -eq 0) {
        $available = @()
        foreach ($member in ($Payload | Get-Member -MemberType NoteProperty)) {
            if ($member -and $member.Name) {
                $available += $member.Name
            }
        }

        $textPreview = $null
        foreach ($prop in @('DriverQueryText','DriverQueryCsv','DriverQueryVerboseCsv','Text')) {
            if ($Payload.PSObject.Properties[$prop]) {
                $candidateText = [string]$Payload.$prop
                if (-not [string]::IsNullOrEmpty($candidateText)) {
                    $textPreview = $candidateText.Substring(0, [Math]::Min(100, $candidateText.Length))
                    break
                }
            }
        }

        $warning = "[Hardware/Drivers] Parsed 0 entries. Available payload props: {0}; Source={1}; TextPreview='{2}'" -f (
            ($available -join ', '),
            $(if ($source) { $source } else { 'None' }),
            $(if ($textPreview) { $textPreview } else { '' })
        )

        if ($VerboseLogging) {
            Write-Warning $warning
        }

        return [pscustomobject]@{
            Rows                    = @()
            Source                  = $source
            AvailableProperties     = $available
            TextPreview             = $textPreview
            HasDriverQueryProperty  = $driverQueryPropertyPresent
            HasDriverQueryData      = $driverQueryPropertyHasItems
            UsedTextPayload         = $textPayloadUsed
            HasTextPayload          = $textPayloadPresent
        }
    }

    $normalized = New-Object System.Collections.Generic.List[pscustomobject]

    foreach ($row in $rows) {
        if (-not $row) { continue }

        $ordered = [ordered]@{}
        foreach ($prop in $row.PSObject.Properties) {
            $ordered[$prop.Name] = $prop.Value

            $trimmed = $prop.Name -replace '\s',''
            if ($trimmed -and $trimmed -ne $prop.Name -and -not $ordered.Contains($trimmed)) {
                $ordered[$trimmed] = $prop.Value
            }
        }

        $obj = [pscustomobject]$ordered

        foreach ($name in @('ModuleName','DisplayName','StartMode','State','Path','DriverType','LinkDate','Version','Provider')) {
            $existing = $obj.PSObject.Properties[$name]
            if ($existing) {
                $obj | Add-Member -NotePropertyName $name -NotePropertyValue $existing.Value -Force
            } else {
                $obj | Add-Member -NotePropertyName $name -NotePropertyValue $null -Force
            }
        }

        $normalized.Add($obj) | Out-Null
    }

    return [pscustomobject]@{
        Rows                    = $normalized.ToArray()
        Source                  = $source
        AvailableProperties     = @()
        TextPreview             = $null
        HasDriverQueryProperty  = $driverQueryPropertyPresent
        HasDriverQueryData      = $driverQueryPropertyHasItems -or ($normalized.Count -gt 0)
        UsedTextPayload         = $textPayloadUsed
        HasTextPayload          = $textPayloadPresent
    }
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
        if (-not $prop -and $name -match '\s') {
            $alternate = $name -replace '\s',''
            if ($alternate -and $alternate -ne $name) {
                $prop = $Entry.PSObject.Properties[$alternate]
            }
        }
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

function Test-BluetoothIndicator {
    param([string]$Value)

    if ([string]::IsNullOrWhiteSpace($Value)) { return $false }

    $normalized = $Value.Trim()
    if (-not $normalized) { return $false }

    if ($normalized -match '(?i)bluetooth') { return $true }

    $pattern = '(?i)(^|[^a-z0-9])(bth|ibt|qcbt|btath)[a-z0-9_-]*'
    if ($normalized -match $pattern) { return $true }

    return $false
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
