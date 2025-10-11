. (Join-Path $PSScriptRoot '_troubleshooting/Catalog.Runtime.psm1')

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

function Add-CategoryIssue {
    [CmdletBinding(DefaultParameterSetName='ByCardId')]
    param(
        [Parameter(Mandatory, ParameterSetName='ByCardId')]
        [Parameter(Mandatory, ParameterSetName='ByFields')]
        $CategoryResult,

        [Parameter(Mandatory, ParameterSetName='ByCardId')]
        [Parameter(ParameterSetName='ByFields')]
        [string]$CardId,

        [Parameter(ParameterSetName='ByFields')]
        [string]$Category,

        [Parameter(ParameterSetName='ByFields')]
        [string]$Subcategory,

        [Parameter(ParameterSetName='ByCardId')]
        [Parameter(Mandatory, ParameterSetName='ByFields')]
        [string]$Title,

        [Parameter()][ValidateSet('critical','high','medium','low','warning','info')]
        [string]$Severity,

        [Parameter()][string]$Area,

        [Parameter()][object]$Evidence,

        [Parameter()][object]$Data,

        [Parameter()][string]$CheckId,

        [Parameter()][string]$Remediation,

        [Parameter()][string]$RemediationScript
    )

    if (-not $CategoryResult) { throw 'CategoryResult is required.' }

    if (-not (Get-Variable -Name CATALOG_INDEX -Scope Script -ErrorAction SilentlyContinue)) {
        Initialize-Catalog -PreferMerged -WriteArtifacts:$false | Out-Null
        # Optional: Start-CatalogWatcher | Out-Null  # dev-only hot reload
    }

    $TitleTpl = $null
    $CatalogCard = $null

    if ($PSCmdlet.ParameterSetName -eq 'ByCardId') {
        $CatalogCard = Get-CatalogCardById -CardId $CardId
        if (-not $CatalogCard) { throw "Unknown card_id '$CardId'." }

        $Category    = $CatalogCard.category
        $Subcategory = $CatalogCard.subcategory
        if (-not $Area) { $Area = if ($CatalogCard.area) { $CatalogCard.area } else { $CatalogCard.category } }
        $TitleTpl    = $CatalogCard.title
        if (-not $Severity) { $Severity = $CatalogCard.severity }
        if (-not $CheckId -and $CatalogCard.meta -and $CatalogCard.meta.check_id) { $CheckId = $CatalogCard.meta.check_id }
    } else {
        if (-not $Category -and $CategoryResult.PSObject.Properties['Name']) {
            $Category = [string]$CategoryResult.Name
        }

        if (-not $Area -and $Category) { $Area = $Category }

        $maybe = $script:CATALOG.cards | Where-Object {
            $_.title -eq $Title -and $_.category -eq $Category -and $_.subcategory -eq $Subcategory
        } | Select-Object -First 1
        if ($maybe) { Write-Warning "Card exists in catalog; prefer -CardId '$($maybe.card_id)' with -Data." }
    }

    if (-not $Area -and $Category) { $Area = $Category }

    if (Get-Command ConvertTo-AnalyzerDataDictionary -ErrorAction SilentlyContinue) {
        $Data = if ($Data) { ConvertTo-AnalyzerDataDictionary -InputObject $Data } else { $null }
    }

    if ($TitleTpl -and -not $Title) { $Title = $TitleTpl }

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

    $payload = @{
        schemaVersion = '1.1'
        flags = @{ hasEvidence = [bool]$Evidence; hasData = [bool]$Data }
        data  = $Data
        meta  = @{ card_id = if ($CatalogCard) { $CatalogCard.card_id } else { $CardId }; template = @{ title = $TitleTpl } }
    }

    if ($CatalogCard -and $CatalogCard.explanation) {
        $payload.meta['explanation'] = $CatalogCard.explanation
    }

    $entry = [ordered]@{
        Severity    = $Severity
        Title       = $Title
        Evidence    = $Evidence
        Subcategory = $Subcategory
    }

    if ($Area) { $entry['Area'] = $Area }

    if ($PSBoundParameters.ContainsKey('Data') -or $null -ne $Data) {
        $entry['Data'] = $Data
    }

    if ($payload) {
        $entry['Payload'] = $payload
        $entry['Meta'] = $payload.meta
    }

    if (-not [string]::IsNullOrWhiteSpace($CheckId)) { $entry['CheckId'] = $CheckId }

    if ($CatalogCard -and $CatalogCard.explanation) {
        $entry['Explanation'] = $CatalogCard.explanation
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
