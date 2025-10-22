$script:MsinfoCacheAvailabilityChecked = $false
$script:MsinfoCacheAvailable = $false

<#!
.SYNOPSIS
    Shared helper functions for analyzer modules.
#>

function New-AnalyzerContext {
    param(
        [Parameter(Mandatory)]
        [string]$InputFolder
    )

    if (-not (Test-Path -LiteralPath $InputFolder)) {
        throw "Input folder '$InputFolder' not found."
    }

    $resolved = (Resolve-Path -LiteralPath $InputFolder).ProviderPath
    $artifactMap = @{}

    $files = Get-ChildItem -Path $resolved -File -Recurse -ErrorAction SilentlyContinue

    if (-not $script:MsinfoCacheAvailabilityChecked) {
        $script:MsinfoCacheAvailabilityChecked = $true
        $requiredCommands = @('Test-AhdCacheItem', 'Get-AhdCacheValue', 'Set-AhdCacheValue')
        $script:MsinfoCacheAvailable = $true
        foreach ($commandName in $requiredCommands) {
            if (-not (Get-Command -Name $commandName -ErrorAction SilentlyContinue)) {
                $script:MsinfoCacheAvailable = $false
                break
            }
        }
    }

    $cacheAvailable = $script:MsinfoCacheAvailable

    foreach ($file in $files) {
        $data = $null
        $cacheKey = $null
        $cacheHit = $false
        $shouldCache = $false

        if ($file.Extension -ieq '.json') {
            if ($cacheAvailable -and ($file.Name -ieq 'msinfo32.json' -or $file.Name -ieq 'msinfo.json')) {
                $lastWriteToken = '{0:x16}' -f $file.LastWriteTimeUtc.ToFileTimeUtc()
                $lengthToken = '{0:x16}' -f $file.Length
                $pathToken = $file.FullName.ToLowerInvariant()
                $cacheKey = "msinfo::${pathToken}::${lastWriteToken}::${lengthToken}"

                if (Test-AhdCacheItem -Key $cacheKey) {
                    $data = Get-AhdCacheValue -Key $cacheKey
                    $cacheHit = $true
                } else {
                    $shouldCache = $true
                }
            }

            if (-not $cacheHit) {
                $content = Get-Content -Path $file.FullName -Raw -ErrorAction SilentlyContinue
                if ($content) {
                    try {
                        $data = $content | ConvertFrom-Json -ErrorAction Stop
                    } catch {
                        $data = [pscustomobject]@{ Error = $_.Exception.Message }
                    }
                }

                if ($shouldCache -and $cacheKey) {
                    try {
                        Set-AhdCacheValue -Key $cacheKey -Value $data
                    } catch {
                        # Ignore cache persistence failures and continue with parsed data.
                    }
                }
            }
        }

        $entry = [pscustomobject]@{
            Path = $file.FullName
            Data = $data
        }

        if ($file.Name -ieq 'msinfo32.json' -or $file.Name -ieq 'msinfo.json') {
            Write-HeuristicDebug -Source 'Context' -Message 'Tracking msinfo artifact' -Data ([ordered]@{
                Path        = $entry.Path
                CacheKey    = if ($cacheKey) { $cacheKey } else { '(none)' }
                CacheHit    = $cacheHit
                ShouldCache = $shouldCache
                HasData     = [bool]$entry.Data
            })
        }

        $key = $file.Name.ToLowerInvariant()
        if ($artifactMap.ContainsKey($key)) {
            $artifactMap[$key] = @($artifactMap[$key]) + ,$entry
        } else {
            $artifactMap[$key] = @($entry)
        }
    }

    $jsonFiles = @($files | Where-Object { $_.Extension -ieq '.json' })
    if ($jsonFiles.Count -gt 0) {
        $artifactCount = $jsonFiles.Count
        $suffix = if ($artifactCount -eq 1) { '' } else { 's' }
        Write-HeuristicDebug -Source 'Context' -Message ("Discovered {0} artifact{1}." -f $artifactCount, $suffix)
    } else {
        Write-HeuristicDebug -Source 'Context' -Message 'Discovered artifacts (0): (none)'
    }

    $msinfoKeys = @($artifactMap.Keys | Where-Object { $_ -match 'msinfo' })
    if ($msinfoKeys.Count -gt 0) {
        Write-HeuristicDebug -Source 'Context' -Message 'Context msinfo artifact keys' -Data ([ordered]@{
            Count = $msinfoKeys.Count
            Keys  = ($msinfoKeys -join ', ')
        })
    } else {
        Write-HeuristicDebug -Source 'Context' -Message 'Context msinfo artifact keys: (none)'
    }

    return [pscustomobject]@{
        InputFolder = $resolved
        Artifacts   = $artifactMap
    }
}

function Write-HeuristicDebug {
    param(
        [Parameter(Mandatory)]
        [string]$Source,

        [Parameter(Mandatory)]
        [string]$Message,

        [hashtable]$Data
    )

    $formatted = "[{0}] {1}" -f $Source, $Message

    if ($PSBoundParameters.ContainsKey('Data') -and $Data) {
        $detailEntries = $Data.GetEnumerator() | Sort-Object Name
        $details = [System.Collections.Generic.List[string]]::new()
        foreach ($entry in $detailEntries) {
            if ($entry -is [System.Collections.DictionaryEntry]) {
                $null = $details.Add(("{0}={1}" -f $entry.Key, $entry.Value))
            } else {
                $null = $details.Add(("{0}={1}" -f $entry.Name, $entry.Value))
            }
        }

        if ($details) {
            $formatted = "{0} :: {1}" -f $formatted, ($details -join '; ')
        }
    }

    Write-Host $formatted
}

function Get-HeuristicSourceMetadata {
    param(
        [string[]]$SkipCommands = @(
            'Get-HeuristicSourceMetadata',
            'New-CategoryResult',
            'Add-CategoryIssue',
            'Add-CategoryNormal',
            'Add-CategoryCheck'
        )
    )

    try {
        $stack = Get-PSCallStack
    } catch {
        return $null
    }

    if (-not $stack) { return $null }

    foreach ($frame in $stack) {
        if (-not $frame) { continue }

        $command = if ($frame.PSObject.Properties['Command']) { [string]$frame.Command } else { $null }
        if ($command -and $SkipCommands -contains $command) { continue }

        $script = if ($frame.PSObject.Properties['ScriptName']) { [string]$frame.ScriptName } else { $null }
        if (-not $script) { continue }

        $resolvedScript = $script
        try {
            if (Test-Path -LiteralPath $script) {
                $resolvedScript = (Resolve-Path -LiteralPath $script -ErrorAction Stop).ProviderPath
            }
        } catch {
        }

        if ($resolvedScript -and $resolvedScript.EndsWith('AnalyzerCommon.ps1', [System.StringComparison]::OrdinalIgnoreCase)) {
            continue
        }

        $functionName = if ($frame.PSObject.Properties['FunctionName'] -and $frame.FunctionName) {
            [string]$frame.FunctionName
        } elseif ($command) {
            $command
        } else {
            $null
        }

        $lineNumber = $null
        if ($frame.PSObject.Properties['ScriptLineNumber'] -and $frame.ScriptLineNumber -gt 0) {
            $lineNumber = [int]$frame.ScriptLineNumber
        }

        return [pscustomobject]@{
            Script   = $resolvedScript
            Function = $functionName
            Command  = $command
            Line     = $lineNumber
        }
    }

    return $null
}

function Get-AnalyzerArtifact {
    param(
        [Parameter(Mandatory)]
        $Context,

        [Parameter(Mandatory)]
        [string]$Name
    )

    if (-not $Context -or -not $Context.Artifacts) { return $null }

    $key = $Name.ToLowerInvariant()
    $lookupKeys = [System.Collections.Generic.List[string]]::new()
    $lookupKeys.Add($key) | Out-Null
    if ($key -notmatch '\.') {
        $builder = [System.Text.StringBuilder]::new($key)
        $null = $builder.Append('.json')
        $lookupKeys.Add($builder.ToString()) | Out-Null
    }

    $entries = $null
    foreach ($candidate in $lookupKeys) {
        if ($Context.Artifacts.ContainsKey($candidate)) {
            $entries = $Context.Artifacts[$candidate]
            break
        }
    }

    if (-not $entries) { return $null }

    if ($entries.Count -gt 1) { return $entries }
    return $entries[0]
}

function New-CategoryResult {
    param(
        [Parameter(Mandatory)]
        [string]$Name
    )

    $source = Get-HeuristicSourceMetadata

    return [pscustomobject]@{
        Name    = $Name
        Issues  = New-Object System.Collections.Generic.List[pscustomobject]
        Normals = New-Object System.Collections.Generic.List[pscustomobject]
        Checks  = New-Object System.Collections.Generic.List[pscustomobject]
        Source  = $source
    }
}

function Add-CategoryIssue {
    param(
        [Parameter(Mandatory)]
        $CategoryResult,

        [Parameter(Mandatory)]
        [string]$Title,

        [ValidateSet('critical','high','medium','low','warning','info')]
        [string]$Severity,

        [string]$Category,

        [string]$Subcategory,

        [string]$Area,

        [object]$Evidence,

        [object]$Data,

        [string]$CheckId,

        [string]$Remediation,

        [string]$RemediationScript,

        [string]$Explanation
    )

    if (-not $CategoryResult) { throw 'CategoryResult is required.' }

    if (-not $Category -and $CategoryResult.PSObject.Properties['Name']) {
        $Category = [string]$CategoryResult.Name
    }

    if (-not $Area -and $Category) { $Area = $Category }

    $dataSpecified = $PSBoundParameters.ContainsKey('Data')
    if ($dataSpecified -and (Get-Command ConvertTo-AnalyzerDataDictionary -ErrorAction SilentlyContinue)) {
        if ($null -ne $Data) {
            $Data = ConvertTo-AnalyzerDataDictionary -InputObject $Data
        } else {
            $Data = $null
        }
    }

    if (-not $Severity) { $Severity = 'info' }

    $source = Get-HeuristicSourceMetadata

    if ($PSBoundParameters.ContainsKey('Evidence')) {
        if ($Evidence -is [System.Collections.IEnumerable] -and -not ($Evidence -is [string])) {
            $sanitizedEvidence = @($Evidence | Where-Object { $_ })
            if ($sanitizedEvidence.Count -gt 0) {
                $Evidence = $sanitizedEvidence
            } else {
                $Evidence = $null
            }
        }
    }

    $payloadMeta = [ordered]@{}
    if (-not [string]::IsNullOrWhiteSpace($CheckId)) { $payloadMeta['check_id'] = $CheckId }
    if (-not [string]::IsNullOrWhiteSpace($Area)) { $payloadMeta['area'] = $Area }
    if (-not [string]::IsNullOrWhiteSpace($Category)) { $payloadMeta['category'] = $Category }
    if (-not [string]::IsNullOrWhiteSpace($Subcategory)) { $payloadMeta['subcategory'] = $Subcategory }

    $payload = @{
        schemaVersion = '1.1'
        flags = @{ hasEvidence = [bool]$Evidence; hasData = [bool]$Data }
        data  = $Data
        meta  = $payloadMeta
    }

    $entry = [ordered]@{
        Severity    = $Severity
        Title       = $Title
        Evidence    = $Evidence
        Subcategory = $Subcategory
    }

    if ($Area) { $entry['Area'] = $Area }

    if ($dataSpecified -or $null -ne $Data) {
        $entry['Data'] = $Data
    }

    if ($payload) {
        $entry['Payload'] = $payload
        $entry['Meta'] = $payload.meta
    }

    if (-not [string]::IsNullOrWhiteSpace($CheckId)) { $entry['CheckId'] = $CheckId }

    if ($PSBoundParameters.ContainsKey('Explanation') -and -not [string]::IsNullOrWhiteSpace($Explanation)) {
        $entry['Explanation'] = $Explanation.Trim()
    }

    if ($PSBoundParameters.ContainsKey('Remediation') -and -not [string]::IsNullOrWhiteSpace($Remediation)) {
        $entry['Remediation'] = $Remediation.Trim()
    }

    if ($PSBoundParameters.ContainsKey('RemediationScript') -and -not [string]::IsNullOrWhiteSpace($RemediationScript)) {
        $entry['RemediationScript'] = $RemediationScript
    }

    if ($source) { $entry['Source'] = $source }

    $CategoryResult.Issues.Add([pscustomobject]$entry) | Out-Null
}

function Add-CategoryNormal {
    param(
        [Parameter(Mandatory)]
        $CategoryResult,

        [Parameter(Mandatory)]
        [string]$Title,

        [object]$Evidence = $null,

        [string]$Subcategory = $null,

        [string]$CheckId = $null
    )

    $source = Get-HeuristicSourceMetadata

    $entry = [ordered]@{
        Title    = $Title
        Evidence = $Evidence
    }

    if ($PSBoundParameters.ContainsKey('Subcategory') -and $Subcategory) {
        $entry['Subcategory'] = $Subcategory
    }

    if ($PSBoundParameters.ContainsKey('CheckId') -and -not [string]::IsNullOrWhiteSpace($CheckId)) {
        $entry['CheckId'] = $CheckId
    }

    if ($source) { $entry['Source'] = $source }

    $CategoryResult.Normals.Add([pscustomobject]$entry) | Out-Null
}

function Add-CategoryCheck {
    param(
        [Parameter(Mandatory)]
        $CategoryResult,

        [Parameter(Mandatory)]
        [string]$Name,

        [Parameter(Mandatory)]
        [string]$Status,

        [string]$Details = ''
    )

    $source = Get-HeuristicSourceMetadata

    $entry = [ordered]@{
        Name    = $Name
        Status  = $Status
        Details = $Details
    }

    if ($source) { $entry['Source'] = $source }

    $CategoryResult.Checks.Add([pscustomobject]$entry) | Out-Null
}

function Merge-AnalyzerResults {
    param(
        [Parameter(Mandatory)]
        [System.Collections.Generic.IEnumerable[object]]$Categories
    )

    $issues = New-Object System.Collections.Generic.List[pscustomobject]
    $normals = New-Object System.Collections.Generic.List[pscustomobject]
    $checks = New-Object System.Collections.Generic.List[pscustomobject]

    foreach ($category in $Categories) {
        if (-not $category) { continue }
        foreach ($item in $category.Issues) { $issues.Add($item) | Out-Null }
        foreach ($item in $category.Normals) { $normals.Add($item) | Out-Null }
        foreach ($item in $category.Checks) { $checks.Add($item) | Out-Null }
    }

    return [pscustomobject]@{
        Issues  = $issues
        Normals = $normals
        Checks  = $checks
    }
}

function Get-ArtifactPayload {
    param(
        [Parameter(Mandatory)]
        $Artifact
    )

    if (-not $Artifact) { return $null }

    if ($Artifact -is [System.Collections.IEnumerable] -and -not ($Artifact -is [string])) {
        $payloads = [System.Collections.Generic.List[object]]::new()
        foreach ($item in $Artifact) {
            $null = $payloads.Add($item.Data.Payload)
        }

        return $payloads
    }

    if ($Artifact.Data -and $Artifact.Data.PSObject.Properties['Payload']) {
        return $Artifact.Data.Payload
    }

    return $null
}

function Resolve-SinglePayload {
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        $Payload
    )

    if ($null -eq $Payload) { return $null }

    if ($Payload -is [System.Collections.IEnumerable] -and -not ($Payload -is [string])) {
        return ($Payload | Select-Object -First 1)
    }

    return $Payload
}

function ConvertTo-MsinfoSectionKey {
    param([string]$Name)

    if ([string]::IsNullOrWhiteSpace($Name)) { return $null }

    $normalized = $Name.Trim().ToLowerInvariant()
    if (-not $normalized) { return $null }

    $normalized = [System.Text.RegularExpressions.Regex]::Replace(
        $normalized,
        '[^a-z0-9]+',
        '-',
        [System.Text.RegularExpressions.RegexOptions]::Compiled
    )

    $normalized = $normalized.Trim('-')
    if (-not $normalized) { return $null }

    return $normalized
}

function Get-MsinfoArtifactPayload {
    param(
        [Parameter(Mandatory)]
        $Context
    )

    if (-not $Context) { return $null }

    $artifact = Get-AnalyzerArtifact -Context $Context -Name 'msinfo32'
    if (-not $artifact) {
        $artifact = Get-AnalyzerArtifact -Context $Context -Name 'msinfo'
    }

    if (-not $artifact) { return $null }

    return Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $artifact)
}

function Get-MsinfoSectionTable {
    param(
        [Parameter(Mandatory)]
        $Payload,

        [Parameter(Mandatory)]
        [string[]]$Names
    )

    if (-not $Payload) { return $null }
    if (-not $Payload.PSObject.Properties['Sections']) { return $null }

    $sections = $Payload.Sections
    if (-not $sections) { return $null }

    if ($sections -and -not ($sections -is [System.Collections.IDictionary])) {
        $supportsContainsKey = $false
        try {
            if ($sections.PSObject -and $sections.PSObject.Methods['ContainsKey']) { $supportsContainsKey = $true }
        } catch {
            $supportsContainsKey = $false
        }

        if (-not $supportsContainsKey) {
            $convertedSections = New-Object System.Collections.Specialized.OrderedDictionary
            foreach ($prop in $sections.PSObject.Properties) {
                if (-not $prop -or -not $prop.Name) { continue }
                $convertedSections[$prop.Name] = $prop.Value
            }
            $sections = $convertedSections
        }
    }

    $index = $null
    if ($Payload.PSObject.Properties['Index']) { $index = $Payload.Index }
    if ($index -and -not ($index -is [System.Collections.IDictionary])) {
        $supportsContainsKey = $false
        try {
            if ($index.PSObject -and $index.PSObject.Methods['ContainsKey']) { $supportsContainsKey = $true }
        } catch {
            $supportsContainsKey = $false
        }

        if (-not $supportsContainsKey) {
            $convertedIndex = New-Object System.Collections.Specialized.OrderedDictionary
            foreach ($prop in $index.PSObject.Properties) {
                if (-not $prop -or -not $prop.Name) { continue }
                $convertedIndex[$prop.Name] = $prop.Value
            }
            $index = $convertedIndex
        }
    }

    $candidateKeys = New-Object System.Collections.Generic.List[string]
    foreach ($name in $Names) {
        if ([string]::IsNullOrWhiteSpace($name)) { continue }

        $candidateKeys.Add($name) | Out-Null

        $normalized = ConvertTo-MsinfoSectionKey -Name $name
        if ($normalized) { $candidateKeys.Add($normalized) | Out-Null }
    }

    $visited = New-Object System.Collections.Generic.HashSet[string]([System.StringComparer]::OrdinalIgnoreCase)

    foreach ($candidate in $candidateKeys) {
        if ([string]::IsNullOrWhiteSpace($candidate)) { continue }
        if (-not $visited.Add($candidate)) { continue }

        if ($sections.ContainsKey($candidate)) {
            $table = $sections[$candidate]
            if ($table) { return $table }
        }

        $normalized = ConvertTo-MsinfoSectionKey -Name $candidate
        if ($normalized -and $sections.ContainsKey($normalized)) {
            $table = $sections[$normalized]
            if ($table) { return $table }
        }

        if ($index -and $normalized -and $index.ContainsKey($normalized)) {
            $targets = @($index[$normalized])
            foreach ($target in $targets) {
                if (-not $target) { continue }
                if ($sections.ContainsKey($target)) {
                    $table = $sections[$target]
                    if ($table) { return $table }
                }
            }
        }

        if ($index -and $index.ContainsKey($candidate)) {
            $targets = @($index[$candidate])
            foreach ($target in $targets) {
                if (-not $target) { continue }
                if ($sections.ContainsKey($target)) {
                    $table = $sections[$target]
                    if ($table) { return $table }
                }
            }
        }

        foreach ($sectionName in $sections.Keys) {
            if (-not $sectionName) { continue }

            $sectionKey = ConvertTo-MsinfoSectionKey -Name $sectionName
            if ($sectionKey -and ($sectionKey -eq $candidate -or $sectionKey -eq $normalized)) {
                $table = $sections[$sectionName]
                if ($table) { return $table }
            }
        }
    }

    return $null
}

function Get-MsinfoRowValue {
    param(
        [Parameter(Mandatory)]
        $Row,

        [Parameter(Mandatory)]
        [string[]]$Names
    )

    if (-not $Row) { return $null }

    foreach ($name in $Names) {
        if ([string]::IsNullOrWhiteSpace($name)) { continue }

        $property = $Row.PSObject.Properties[$name]
        if ($property -and $null -ne $property.Value -and $property.Value -ne '') {
            $value = [string]$property.Value
            if (-not [string]::IsNullOrWhiteSpace($value)) { return $value.Trim() }
        }

        $trimmedName = ($name -replace '[^A-Za-z0-9]', '')
        if ($trimmedName -and $Row.PSObject.Properties[$trimmedName]) {
            $candidateValue = $Row.$trimmedName
            if ($null -ne $candidateValue -and $candidateValue -ne '') {
                $value = [string]$candidateValue
                if (-not [string]::IsNullOrWhiteSpace($value)) { return $value.Trim() }
            }
        }

        foreach ($prop in $Row.PSObject.Properties) {
            if (-not $prop -or -not $prop.Name) { continue }
            if ($prop.Name.Equals($name, [System.StringComparison]::OrdinalIgnoreCase)) {
                $candidate = $prop.Value
                if ($null -ne $candidate -and $candidate -ne '') {
                    $value = [string]$candidate
                    if (-not [string]::IsNullOrWhiteSpace($value)) { return $value.Trim() }
                }
            }
        }
    }

    return $null
}

function ConvertTo-MsinfoRowObject {
    param(
        [Parameter(Mandatory)]
        $Row
    )

    if (-not $Row) { return $null }

    if ($Row -is [pscustomobject] -or $Row -is [hashtable] -or $Row -is [System.Collections.IDictionary]) {
        $ordered = [ordered]@{}

        if ($Row -is [System.Collections.IDictionary]) {
            foreach ($key in $Row.Keys) {
                if ([string]::IsNullOrWhiteSpace($key)) { continue }
                $value = $Row[$key]
                if ($value -is [string]) { $value = $value.Trim() }
                $ordered[$key] = $value
            }
        } else {
            foreach ($prop in $Row.PSObject.Properties) {
                if (-not $prop -or -not $prop.Name) { continue }
                $name = [string]$prop.Name
                if (-not $name) { continue }
                $value = $prop.Value
                if ($value -is [string]) { $value = $value.Trim() }
                $ordered[$name] = $value
            }
        }

        return [pscustomobject]$ordered
    }

    return [pscustomobject]@{ Value = $Row }
}

function Get-MsinfoSectionRows {
    param(
        [Parameter(Mandatory)]
        $Context,

        [Parameter(Mandatory)]
        [string[]]$Names
    )

    $msinfoPayload = Get-MsinfoArtifactPayload -Context $Context
    if (-not $msinfoPayload) { return $null }

    $table = Get-MsinfoSectionTable -Payload $msinfoPayload -Names $Names
    if (-not $table -or -not $table.Rows -or $table.RowCount -eq 0) { return $null }

    $rows = New-Object System.Collections.Generic.List[pscustomobject]
    foreach ($row in $table.Rows) {
        if (-not $row) { continue }
        $converted = ConvertTo-MsinfoRowObject -Row $row
        if ($converted) { $rows.Add($converted) | Out-Null }
    }

    if ($rows.Count -eq 0) { return $null }

    return [pscustomobject]@{
        Source      = 'msinfo32'
        SectionName = $table.Name
        Rows        = $rows.ToArray()
        RowCount    = $rows.Count
    }
}

function Get-MsinfoSystemSummarySection {
    param(
        [Parameter(Mandatory)]
        $Context
    )

    $section = Get-MsinfoSectionRows -Context $Context -Names @('system summary')
    if (-not $section) { return $null }

    $ordered = New-Object System.Collections.Specialized.OrderedDictionary
    $lookup = New-Object 'System.Collections.Generic.Dictionary[string,object]' ([System.StringComparer]::OrdinalIgnoreCase)
    $rowLookup = New-Object 'System.Collections.Generic.Dictionary[string,object]' ([System.StringComparer]::OrdinalIgnoreCase)

    foreach ($row in $section.Rows) {
        if (-not $row) { continue }
        $key = Get-MsinfoRowValue -Row $row -Names @('Item', 'Name')
        if (-not $key) { continue }
        $value = Get-MsinfoRowValue -Row $row -Names @('Value')
        if (-not $ordered.Contains($key)) { $ordered.Add($key, $value) }
        $lookup[$key] = $value
        $rowLookup[$key] = $row
    }

    $section | Add-Member -NotePropertyName 'Values' -NotePropertyValue $ordered -Force
    $section | Add-Member -NotePropertyName 'Lookup' -NotePropertyValue $lookup -Force
    $section | Add-Member -NotePropertyName 'RowsByKey' -NotePropertyValue $rowLookup -Force

    return $section
}

function Get-MsinfoSystemSummaryValue {
    param(
        [Parameter(Mandatory)]
        $Summary,

        [Parameter(Mandatory)]
        [string[]]$Names
    )

    if (-not $Summary) { return $null }
    $lookup = $Summary.Lookup
    if (-not $lookup) { return $null }

    foreach ($name in $Names) {
        if ([string]::IsNullOrWhiteSpace($name)) { continue }
        if ($lookup.ContainsKey($name)) {
            $value = $lookup[$name]
            if ($value -is [string]) { return $value.Trim() }
            return $value
        }
    }

    return $null
}

function ConvertTo-MsinfoByteCount {
    param([string]$Value)

    if ([string]::IsNullOrWhiteSpace($Value)) { return $null }

    $text = $Value.Trim()
    if (-not $text) { return $null }

    $number = $null
    $unit = $null

    $pattern = '^(?<number>[0-9,\.]+)\s*(?<unit>[A-Za-z]+)' 
    $match = [regex]::Match($text, $pattern)
    if ($match.Success) {
        $numberText = $match.Groups['number'].Value.Replace(',', '')
        if (-not [string]::IsNullOrWhiteSpace($numberText)) {
            try {
                $number = [double]::Parse($numberText, [System.Globalization.CultureInfo]::InvariantCulture)
            } catch {
                $number = $null
            }
        }
        $unit = $match.Groups['unit'].Value.ToLowerInvariant()
    } elseif ($text -match '^(?<digits>\d+)$') {
        $digits = $matches['digits']
        if ($digits) {
            try { return [uint64]$digits } catch { return $null }
        }
    }

    if ($null -eq $number -or -not $unit) { return $null }

    $multiplier = switch -regex ($unit) {
        '^(b|byte|bytes)$'       { 1 }
        '^(kb|kilobyte|kilobytes)$' { 1KB }
        '^(mb|megabyte|megabytes)$' { 1MB }
        '^(gb|gigabyte|gigabytes)$' { 1GB }
        '^(tb|terabyte|terabytes)$' { 1TB }
        default { $null }
    }

    if ($null -eq $multiplier) { return $null }

    try {
        return [uint64]([math]::Round($number * $multiplier))
    } catch {
        return $null
    }
}

function ConvertTo-MsinfoDomainRoleInfo {
    param([string]$Label)

    if ([string]::IsNullOrWhiteSpace($Label)) {
        return [pscustomobject]@{ Role = $null; PartOfDomain = $null }
    }

    $normalized = $Label.ToLowerInvariant()
    switch ($normalized) {
        { $_ -match 'stand-?alone workstation' } { return [pscustomobject]@{ Role = 0; PartOfDomain = $false } }
        { $_ -match 'member workstation' }       { return [pscustomobject]@{ Role = 1; PartOfDomain = $true } }
        { $_ -match 'stand-?alone server' }      { return [pscustomobject]@{ Role = 2; PartOfDomain = $false } }
        { $_ -match 'member server' }            { return [pscustomobject]@{ Role = 3; PartOfDomain = $true } }
        { $_ -match 'backup domain controller' } { return [pscustomobject]@{ Role = 4; PartOfDomain = $true } }
        { $_ -match 'primary domain controller' }{ return [pscustomobject]@{ Role = 5; PartOfDomain = $true } }
    }

    return [pscustomobject]@{ Role = $null; PartOfDomain = $null }
}

function Get-MsinfoDomainContext {
    param(
        [Parameter(Mandatory)]
        $Context,

        $Summary
    )

    $summaryToUse = $Summary
    if (-not $summaryToUse) {
        $summaryToUse = Get-MsinfoSystemSummarySection -Context $Context
    }

    if (-not $summaryToUse) { return $null }

    $domain = Get-MsinfoSystemSummaryValue -Summary $summaryToUse -Names @('Domain')
    $workgroup = Get-MsinfoSystemSummaryValue -Summary $summaryToUse -Names @('Workgroup')
    $domainRoleLabel = Get-MsinfoSystemSummaryValue -Summary $summaryToUse -Names @('Domain Role')
    $roleInfo = ConvertTo-MsinfoDomainRoleInfo -Label $domainRoleLabel

    $partOfDomain = $roleInfo.PartOfDomain
    if ($partOfDomain -eq $null -and $domain) {
        $domainTrim = $domain.Trim()
        if ($domainTrim) {
            if ($domainTrim.Equals('workgroup', [System.StringComparison]::OrdinalIgnoreCase)) {
                $partOfDomain = $false
            } elseif ($domainTrim.Equals('local', [System.StringComparison]::OrdinalIgnoreCase)) {
                $partOfDomain = $false
            } elseif ($domainTrim -match '(?i)workgroup') {
                $partOfDomain = $false
            } else {
                $partOfDomain = $true
            }
        }
    }

    return [pscustomobject]@{
        Domain          = if ($domain) { $domain } else { $null }
        Workgroup       = if ($workgroup) { $workgroup } else { $null }
        DomainRole      = $roleInfo.Role
        DomainRoleLabel = $domainRoleLabel
        PartOfDomain    = $partOfDomain
    }
}

function Get-MsinfoSecuritySummary {
    param(
        [Parameter(Mandatory)]
        $Context
    )

    $summary = Get-MsinfoSystemSummarySection -Context $Context
    if (-not $summary) { return $null }

    $valueFor = {
        param([string[]]$Names)
        return Get-MsinfoSystemSummaryValue -Summary $summary -Names $Names
    }

    $result = [ordered]@{
        Source                               = 'msinfo32'
        SectionName                          = $summary.SectionName
        SecureBootState                      = & $valueFor @('Secure Boot State')
        KernelDmaProtection                  = & $valueFor @('Kernel DMA Protection')
        VirtualizationBasedSecurity          = & $valueFor @('Virtualization-based security', 'Virtualization-based Security')
        VirtualizationBasedSecurityServices  = & $valueFor @('Virtualization-based Security Services Running', 'Virtualization-based security Services Running')
        VirtualizationBasedSecurityConfigured = & $valueFor @('Virtualization-based Security Services Configured')
        VirtualizationBasedSecurityRequired  = & $valueFor @('Virtualization-based Security Required Security Properties')
        VirtualizationBasedSecurityAvailable = & $valueFor @('Virtualization-based Security Available Security Properties')
        DeviceGuardSecurityServicesRunning   = & $valueFor @('Device Guard Security Services Running')
        DeviceGuardSecurityServicesConfigured = & $valueFor @('Device Guard Security Services Configured')
        DeviceGuardRequiredSecurityProperties = & $valueFor @('Device Guard Required Security Properties')
        DeviceGuardAvailableSecurityProperties = & $valueFor @('Device Guard Available Security Properties')
        DeviceGuardCodeIntegrityPolicy       = & $valueFor @('Device Guard Code Integrity Policy')
        DeviceGuardUserModeCodeIntegrityPolicy = & $valueFor @('Device Guard User Mode Code Integrity Policy')
        WindowsDefenderApplicationControlPolicy = & $valueFor @('Windows Defender Application Control policy', 'Windows Defender Application Control Policy')
        WindowsDefenderApplicationControlUserModePolicy = & $valueFor @('Windows Defender Application Control user mode policy', 'Windows Defender Application Control User Mode Policy')
    }

    return [pscustomobject]$result
}

function Get-MsinfoStorageDisksSection {
    param(
        [Parameter(Mandatory)]
        $Context
    )

    return Get-MsinfoSectionRows -Context $Context -Names @('components\storage\disks', 'storage\disks', 'disks')
}

function Get-MsinfoStorageDrivesSection {
    param(
        [Parameter(Mandatory)]
        $Context
    )

    return Get-MsinfoSectionRows -Context $Context -Names @('components\storage\drives', 'storage\drives', 'drives')
}

function Get-MsinfoNetworkAdapterSection {
    param(
        [Parameter(Mandatory)]
        $Context
    )

    return Get-MsinfoSectionRows -Context $Context -Names @('components\network\adapter', 'network\adapter', 'adapter')
}

function Get-MsinfoPrinterSection {
    param(
        [Parameter(Mandatory)]
        $Context
    )

    return Get-MsinfoSectionRows -Context $Context -Names @('components\printer', 'printer', 'printers')
}

function Get-MsinfoProcessors {
    param(
        [Parameter(Mandatory)]
        $Context
    )

    $section = Get-MsinfoSectionRows -Context $Context -Names @('components\processor', 'processor', 'processors')
    if (-not $section) { return $null }

    return $section.Rows
}

function ConvertTo-MsinfoVersionInfo {
    param([string]$Value)

    if ([string]::IsNullOrWhiteSpace($Value)) {
        return [pscustomobject]@{ Version = $null; Build = $null }
    }

    $text = $Value.Trim()
    $version = $null
    $build = $null

    $versionMatch = [regex]::Match($text, '^(?<version>\d+(?:\.\d+){1,3})')
    if ($versionMatch.Success) { $version = $versionMatch.Groups['version'].Value }

    $buildMatch = [regex]::Match($text, '(?i)build\s*(?<build>\d+)')
    if ($buildMatch.Success) { $build = $buildMatch.Groups['build'].Value }

    if (-not $build) {
        $secondaryMatch = [regex]::Match($text, '(?<build>\d{4,})$')
        if ($secondaryMatch.Success) { $build = $secondaryMatch.Groups['build'].Value }
    }

    return [pscustomobject]@{ Version = $version; Build = $build }
}

function Get-MsinfoSystemIdentity {
    param(
        [Parameter(Mandatory)]
        $Context
    )

    $summary = Get-MsinfoSystemSummarySection -Context $Context
    if (-not $summary) { return $null }

    $domainContext = Get-MsinfoDomainContext -Context $Context -Summary $summary

    $deviceName = Get-MsinfoSystemSummaryValue -Summary $summary -Names @('System Name', 'Host Name', 'Computer Name')
    $osName = Get-MsinfoSystemSummaryValue -Summary $summary -Names @('OS Name', 'Operating System')
    $versionValue = Get-MsinfoSystemSummaryValue -Summary $summary -Names @('Version', 'OS Version')
    $displayVersion = Get-MsinfoSystemSummaryValue -Summary $summary -Names @('Display Version')
    $architecture = Get-MsinfoSystemSummaryValue -Summary $summary -Names @('System Type', 'OS Architecture')
    $manufacturer = Get-MsinfoSystemSummaryValue -Summary $summary -Names @('System Manufacturer', 'Manufacturer')
    $model = Get-MsinfoSystemSummaryValue -Summary $summary -Names @('System Model', 'Model')
    $systemSku = Get-MsinfoSystemSummaryValue -Summary $summary -Names @('System SKU Number', 'System SKU')
    $biosVersion = Get-MsinfoSystemSummaryValue -Summary $summary -Names @('BIOS Version/Date', 'BIOS Version')
    $biosMode = Get-MsinfoSystemSummaryValue -Summary $summary -Names @('BIOS Mode')
    $installDate = Get-MsinfoSystemSummaryValue -Summary $summary -Names @('Original Install Date', 'Install Date')
    $totalPhysicalMemory = Get-MsinfoSystemSummaryValue -Summary $summary -Names @('Total Physical Memory', 'TotalPhysicalMemory')
    $installedPhysicalMemory = Get-MsinfoSystemSummaryValue -Summary $summary -Names @('Installed Physical Memory (RAM)', 'InstalledPhysicalMemory')

    $versionInfo = ConvertTo-MsinfoVersionInfo -Value $versionValue

    $totalPhysicalBytes = ConvertTo-MsinfoByteCount -Value $totalPhysicalMemory
    $installedPhysicalBytes = ConvertTo-MsinfoByteCount -Value $installedPhysicalMemory

    return [pscustomobject]@{
        Source                    = 'msinfo32'
        Summary                   = $summary
        DeviceName                = $deviceName
        OSName                    = $osName
        OSVersionRaw              = $versionValue
        OSVersion                 = $versionInfo.Version
        OSBuild                   = $versionInfo.Build
        DisplayVersion            = $displayVersion
        OSArchitecture            = $architecture
        Manufacturer              = $manufacturer
        Model                     = $model
        SystemSku                 = $systemSku
        BiosVersion               = $biosVersion
        BiosMode                  = $biosMode
        InstallDate               = $installDate
        TotalPhysicalMemory       = $totalPhysicalMemory
        TotalPhysicalMemoryBytes  = $totalPhysicalBytes
        InstalledPhysicalMemory   = $installedPhysicalMemory
        InstalledPhysicalMemoryBytes = $installedPhysicalBytes
        Domain                    = if ($domainContext) { $domainContext.Domain } else { $null }
        Workgroup                 = if ($domainContext) { $domainContext.Workgroup } else { $null }
        DomainRole                = if ($domainContext) { $domainContext.DomainRole } else { $null }
        DomainRoleLabel           = if ($domainContext) { $domainContext.DomainRoleLabel } else { $null }
        PartOfDomain              = if ($domainContext) { $domainContext.PartOfDomain } else { $null }
    }
}

function Get-MsinfoServicesPayload {
    param(
        [Parameter(Mandatory)]
        $Context
    )

    $msinfoPayload = Get-MsinfoArtifactPayload -Context $Context
    if (-not $msinfoPayload) { return $null }

    $table = Get-MsinfoSectionTable -Payload $msinfoPayload -Names @('software environment\services', 'services')
    if (-not $table -or -not $table.Rows -or $table.RowCount -eq 0) { return $null }

    $services = New-Object System.Collections.Generic.List[pscustomobject]
    $errors = New-Object System.Collections.Generic.List[string]

    foreach ($row in $table.Rows) {
        if (-not $row) { continue }

        $name = Get-MsinfoRowValue -Row $row -Names @('ServiceName', 'Service Name', 'Name')
        if (-not $name) {
            $errors.Add('Service entry missing Service Name.') | Out-Null
            continue
        }

        $displayName = Get-MsinfoRowValue -Row $row -Names @('DisplayName', 'Display Name', 'Name')
        $status = Get-MsinfoRowValue -Row $row -Names @('Status', 'State')
        $state = Get-MsinfoRowValue -Row $row -Names @('State', 'Status')
        $startMode = Get-MsinfoRowValue -Row $row -Names @('StartMode', 'StartupType', 'Startup Type', 'Start Type')
        $logOnAs = Get-MsinfoRowValue -Row $row -Names @('LogOnAs', 'Log On As', 'User', 'StartName')
        $serviceType = Get-MsinfoRowValue -Row $row -Names @('ServiceType', 'Service Type', 'Type')
        $path = Get-MsinfoRowValue -Row $row -Names @('Path', 'BinaryPath', 'ImagePath')

        $entry = [ordered]@{
            Name        = $name
            DisplayName = if ($displayName) { $displayName } else { $name }
            Status      = if ($status) { $status } else { $null }
            State       = if ($state) { $state } else { $status }
            StartMode   = if ($startMode) { $startMode } else { $null }
            StartType   = if ($startMode) { $startMode } else { $null }
            StartName   = if ($logOnAs) { $logOnAs } else { $null }
            ServiceType = if ($serviceType) { $serviceType } else { $null }
            Path        = if ($path) { $path } else { $null }
        }

        $services.Add([pscustomobject]$entry) | Out-Null
    }

    if ($services.Count -eq 0) { return $null }

    return [pscustomobject]@{
        Source           = 'msinfo32'
        SectionName      = $table.Name
        Services         = $services.ToArray()
        CollectionErrors = if ($errors.Count -gt 0) { $errors.ToArray() } else { @() }
    }
}

function Get-MsinfoStartupPayload {
    param(
        [Parameter(Mandatory)]
        $Context
    )

    $msinfoPayload = Get-MsinfoArtifactPayload -Context $Context
    if (-not $msinfoPayload) { return $null }

    $table = Get-MsinfoSectionTable -Payload $msinfoPayload -Names @('software environment\startup programs', 'startup programs')
    if (-not $table -or -not $table.Rows -or $table.RowCount -eq 0) { return $null }

    $startupItems = New-Object System.Collections.Generic.List[pscustomobject]

    foreach ($row in $table.Rows) {
        if (-not $row) { continue }

        $name = Get-MsinfoRowValue -Row $row -Names @('Item', 'Name')
        $command = Get-MsinfoRowValue -Row $row -Names @('Command')
        $location = Get-MsinfoRowValue -Row $row -Names @('Location', 'Path')
        $user = Get-MsinfoRowValue -Row $row -Names @('User')
        $description = Get-MsinfoRowValue -Row $row -Names @('Description')
        $disabled = Get-MsinfoRowValue -Row $row -Names @('Disabled')

        $entry = [ordered]@{
            Name        = $name
            Command     = $command
            Location    = $location
            User        = $user
            Description = $description
            Disabled    = $disabled
        }

        $startupItems.Add([pscustomobject]$entry) | Out-Null
    }

    if ($startupItems.Count -eq 0) { return $null }

    return [pscustomobject]@{
        Source          = 'msinfo32'
        SectionName     = $table.Name
        StartupCommands = $startupItems.ToArray()
    }
}

function Get-MsinfoDriverEntries {
    param(
        [Parameter(Mandatory)]
        $Context
    )

    $msinfoPayload = Get-MsinfoArtifactPayload -Context $Context
    if (-not $msinfoPayload) { return $null }

    $table = Get-MsinfoSectionTable -Payload $msinfoPayload -Names @('software environment\system drivers', 'system drivers')
    if (-not $table -or -not $table.Rows -or $table.RowCount -eq 0) { return $null }

    $entries = New-Object System.Collections.Generic.List[pscustomobject]

    foreach ($row in $table.Rows) {
        if (-not $row) { continue }

        $moduleName = Get-MsinfoRowValue -Row $row -Names @('Name', 'ModuleName', 'Module Name')
        $displayName = Get-MsinfoRowValue -Row $row -Names @('DisplayName', 'Display Name', 'Description')
        $type = Get-MsinfoRowValue -Row $row -Names @('Type', 'DriverType', 'Driver Type')
        $startMode = Get-MsinfoRowValue -Row $row -Names @('StartMode', 'Start Mode', 'StartupType', 'Startup Type')
        $state = Get-MsinfoRowValue -Row $row -Names @('State')
        $status = Get-MsinfoRowValue -Row $row -Names @('Status')
        $errorControl = Get-MsinfoRowValue -Row $row -Names @('ErrorControl', 'Error Control')
        $path = Get-MsinfoRowValue -Row $row -Names @('Path', 'ImagePath', 'BinaryPath')
        $startName = Get-MsinfoRowValue -Row $row -Names @('StartedBy', 'Started By')

        $entry = [ordered]@{
            ModuleName   = $moduleName
            DisplayName  = $displayName
            DriverType   = $type
            StartMode    = $startMode
            State        = $state
            Status       = $status
            ErrorControl = $errorControl
            Path         = $path
            StartName    = $startName
        }

        $entries.Add([pscustomobject]$entry) | Out-Null
    }

    if ($entries.Count -eq 0) { return $null }

    return $entries.ToArray()
}
