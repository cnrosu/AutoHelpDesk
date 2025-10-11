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
    foreach ($file in $files) {
        $data = $null
        if ($file.Extension -ieq '.json') {
            $content = Get-Content -Path $file.FullName -Raw -ErrorAction SilentlyContinue
            if ($content) {
                try {
                    $data = $content | ConvertFrom-Json -ErrorAction Stop
                } catch {
                    $data = [pscustomobject]@{ Error = $_.Exception.Message }
                }
            }
        }

        $entry = [pscustomobject]@{
            Path = $file.FullName
            Data = $data
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
        $paths = $jsonFiles | ForEach-Object { $_.FullName }
        Write-HeuristicDebug -Source 'Context' -Message ("Discovered artifacts ({0}): {1}" -f $paths.Count, ($paths -join ', '))
    } else {
        Write-HeuristicDebug -Source 'Context' -Message 'Discovered artifacts (0): (none)'
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

    $formatted = "DBG [{0}] {1}" -f $Source, $Message

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

function ConvertTo-AnalyzerDataDictionary {
    param(
        [AllowNull()]
        $Value
    )

    if ($null -eq $Value) {
        return $null
    }

    if ($Value -is [System.Collections.IDictionary]) {
        $ordered = [ordered]@{}
        foreach ($key in $Value.Keys) {
            $ordered[$key] = $Value[$key]
        }

        return $ordered
    }

    if ($Value -is [psobject]) {
        $ordered = [ordered]@{}
        foreach ($property in $Value.PSObject.Properties) {
            $ordered[$property.Name] = $property.Value
        }

        return $ordered
    }

    return [ordered]@{ Value = $Value }
}

function Add-CategoryIssue {
    param(
        [Parameter(Mandatory)]
        $CategoryResult,

        [Parameter(Mandatory)]
        [string]$Severity,

        [Parameter(Mandatory)]
        [string]$Title,

        [object]$Evidence = $null,

        [string]$Subcategory = $null,

        [string]$CheckId = $null,

        [string]$Remediation = $null,

        [string]$RemediationScript = $null,

        [object]$Data = $null
    )

    $source = Get-HeuristicSourceMetadata

    $evidenceSupplied = $PSBoundParameters.ContainsKey('Evidence')
    $normalizedEvidence = $Evidence
    if ($evidenceSupplied -and $null -ne $normalizedEvidence) {
        if ($normalizedEvidence -is [System.Collections.IEnumerable] -and -not ($normalizedEvidence -is [string])) {
            $sanitizedEvidence = @($normalizedEvidence | Where-Object { $_ })
            if ($sanitizedEvidence.Count -gt 0) {
                $normalizedEvidence = $sanitizedEvidence
            } else {
                $normalizedEvidence = $null
            }
        }
    }

    $entry = [ordered]@{
        Severity    = $Severity
        Title       = $Title
        Evidence    = $normalizedEvidence
        Subcategory = $Subcategory
    }

    $checkIdValue = $null
    if ($PSBoundParameters.ContainsKey('CheckId') -and -not [string]::IsNullOrWhiteSpace($CheckId)) {
        $checkIdValue = $CheckId
        $entry['CheckId'] = $checkIdValue
    }

    $remediationValue = $null
    if ($PSBoundParameters.ContainsKey('Remediation') -and -not [string]::IsNullOrWhiteSpace($Remediation)) {
        $remediationValue = $Remediation.Trim()
        $entry['Remediation'] = $remediationValue
    }

    $remediationScriptValue = $null
    if ($PSBoundParameters.ContainsKey('RemediationScript') -and -not [string]::IsNullOrWhiteSpace($RemediationScript)) {
        $remediationScriptValue = $RemediationScript
        $entry['RemediationScript'] = $remediationScriptValue
    }

    $issueData = [ordered]@{
        SchemaVersion = 1
        Title         = $Title
        Severity      = $Severity
    }

    $categoryProvided = $false
    if ($CategoryResult -and $CategoryResult.PSObject.Properties['Name']) {
        $categoryName = [string]$CategoryResult.Name
        if (-not [string]::IsNullOrWhiteSpace($categoryName)) {
            $issueData['Category'] = $categoryName
            $categoryProvided = $true
        }
    }

    $subcategoryProvided = $false
    if (-not [string]::IsNullOrWhiteSpace($Subcategory)) {
        $issueData['Subcategory'] = $Subcategory
        $subcategoryProvided = $true
    }

    if ($checkIdValue) {
        $issueData['CheckId'] = $checkIdValue
    }
    $issueData['HasCheckId'] = [bool]$checkIdValue
    $issueData['HasSubcategory'] = $subcategoryProvided
    $issueData['HasCategory'] = $categoryProvided

    $hasEvidence = $false
    $evidencePreview = $null
    $issueData['EvidenceIsCollection'] = $false
    $issueData['EvidenceCount'] = 0
    if ($evidenceSupplied -and $null -ne $normalizedEvidence) {
        if ($normalizedEvidence -is [string]) {
            $trimmedEvidence = $normalizedEvidence.Trim()
            if (-not [string]::IsNullOrWhiteSpace($trimmedEvidence)) {
                $hasEvidence = $true
                $previewLength = [Math]::Min($trimmedEvidence.Length, 200)
                $evidencePreview = $trimmedEvidence.Substring(0, $previewLength)
                if ($trimmedEvidence.Length -gt $previewLength) {
                    $evidencePreview = '{0}…' -f $evidencePreview
                }
            }
        } elseif ($normalizedEvidence -is [System.Collections.IEnumerable] -and -not ($normalizedEvidence -is [string])) {
            $collection = @($normalizedEvidence | Where-Object { $_ })
            if ($collection.Count -gt 0) {
                $hasEvidence = $true
                $issueData['EvidenceIsCollection'] = $true
                $issueData['EvidenceCount'] = $collection.Count
                $previewItems = $collection | Select-Object -First 3
                $previewStrings = @()
                foreach ($item in $previewItems) {
                    if ($item -is [System.Collections.DictionaryEntry]) {
                        $previewStrings += ('{0}={1}' -f $item.Key, $item.Value)
                        continue
                    }

                    if ($null -ne $item -and $item.PSObject -and $item.PSObject.Properties.Count -gt 0) {
                        $innerPairs = @()
                        foreach ($prop in $item.PSObject.Properties) {
                            if ($innerPairs.Count -ge 3) { break }
                            $innerPairs += ('{0}={1}' -f $prop.Name, $prop.Value)
                        }

                        if ($innerPairs.Count -gt 0) {
                            $previewStrings += ('[{0}]' -f ($innerPairs -join '; '))
                            continue
                        }
                    }

                    if ($null -ne $item) {
                        $previewStrings += [string]$item
                    }
                }

                $previewStrings = $previewStrings | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
                if ($previewStrings.Count -gt 0) {
                    $evidencePreview = $previewStrings -join '; '
                }
            }
        } else {
            $hasEvidence = $true
            $evidencePreview = [string]$normalizedEvidence
        }
    }

    $issueData['HasEvidence'] = $hasEvidence
    $issueData['EvidenceProvided'] = $evidenceSupplied
    if ($hasEvidence -and -not [string]::IsNullOrWhiteSpace($evidencePreview)) {
        $issueData['EvidencePreview'] = $evidencePreview
    }

    if ($hasEvidence) {
        $evidenceType = if ($normalizedEvidence -is [string]) {
            'string'
        } elseif ($normalizedEvidence -is [System.Collections.IEnumerable] -and -not ($normalizedEvidence -is [string])) {
            'collection'
        } elseif ($normalizedEvidence) {
            $normalizedEvidence.GetType().Name
        } else {
            $null
        }

        if ($evidenceType) {
            $issueData['EvidenceType'] = $evidenceType
        }
    }

    $issueData['HasRemediation'] = [bool]$remediationValue
    $issueData['HasRemediationScript'] = [bool]$remediationScriptValue
    $issueData['HasSource'] = [bool]$source

    if ($PSBoundParameters.ContainsKey('Data')) {
        $customData = ConvertTo-AnalyzerDataDictionary -Value $Data
        if ($customData) {
            foreach ($key in $customData.Keys) {
                $issueData[$key] = $customData[$key]
            }
        }
    }

    if ($issueData.Count -gt 0) {
        $entry['Data'] = $issueData
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
