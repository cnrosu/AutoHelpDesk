<#!
.SYNOPSIS
    Shared helper functions for analyzer modules.
#>

function Get-HeuristicSourceContext {
    $stack = Get-PSCallStack
    if (-not $stack) { return $null }

    foreach ($frame in $stack) {
        if (-not $frame) { continue }

        $scriptName = $null
        if ($frame.PSObject.Properties['ScriptName']) { $scriptName = $frame.ScriptName }
        if (-not $scriptName) { continue }

        if ($scriptName -like '*AnalyzerCommon.ps1') { continue }

        $functionName = $null
        if ($frame.PSObject.Properties['FunctionName']) { $functionName = $frame.FunctionName }
        elseif ($frame.PSObject.Properties['Command']) { $functionName = $frame.Command }

        if ($functionName -and ($functionName -like 'Add-Category*' -or $functionName -eq 'New-CategoryResult')) {
            continue
        }

        $line = $null
        if ($frame.PSObject.Properties['ScriptLineNumber']) { $line = $frame.ScriptLineNumber }

        return [ordered]@{
            Script   = $scriptName
            Function = $functionName
            Line     = $line
        }
    }

    return $null
}

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

function Get-AnalyzerArtifact {
    param(
        [Parameter(Mandatory)]
        $Context,

        [Parameter(Mandatory)]
        [string]$Name
    )

    if (-not $Context -or -not $Context.Artifacts) { return $null }

    $key = $Name.ToLowerInvariant()
    $lookupKeys = @($key)
    if ($key -notmatch '\.') {
        $lookupKeys += ($key + '.json')
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

    $category = [pscustomobject]@{
        Name    = $Name
        Issues  = New-Object System.Collections.Generic.List[pscustomobject]
        Normals = New-Object System.Collections.Generic.List[pscustomobject]
        Checks  = New-Object System.Collections.Generic.List[pscustomobject]
    }

    $source = Get-HeuristicSourceContext
    if ($source) {
        if ($source.Script) {
            $category | Add-Member -NotePropertyName 'SourceScript' -NotePropertyValue $source.Script -Force
        }
        if ($source.Function) {
            $category | Add-Member -NotePropertyName 'SourceFunction' -NotePropertyValue $source.Function -Force
        }
        if ($null -ne $source.Line) {
            $category | Add-Member -NotePropertyName 'SourceLine' -NotePropertyValue $source.Line -Force
        }
    }

    return $category
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

        [string]$CheckId = $null
    )

    $entry = [ordered]@{
        Severity    = $Severity
        Title       = $Title
        Evidence    = $Evidence
        Subcategory = $Subcategory
    }

    if ($PSBoundParameters.ContainsKey('CheckId') -and -not [string]::IsNullOrWhiteSpace($CheckId)) {
        $entry['CheckId'] = $CheckId
    }

    $source = Get-HeuristicSourceContext
    if ($source) {
        if ($source.Script -and -not $entry.Contains('SourceScript')) { $entry['SourceScript'] = $source.Script }
        if ($source.Function -and -not $entry.Contains('SourceFunction')) { $entry['SourceFunction'] = $source.Function }
        if ($null -ne $source.Line -and -not $entry.Contains('SourceLine')) { $entry['SourceLine'] = $source.Line }

        if ($CategoryResult -and $CategoryResult.PSObject -and -not $CategoryResult.PSObject.Properties['SourceScript']) {
            if ($source.Script) { $CategoryResult | Add-Member -NotePropertyName 'SourceScript' -NotePropertyValue $source.Script -Force }
        }
        if ($CategoryResult -and $CategoryResult.PSObject -and -not $CategoryResult.PSObject.Properties['SourceFunction']) {
            if ($source.Function) { $CategoryResult | Add-Member -NotePropertyName 'SourceFunction' -NotePropertyValue $source.Function -Force }
        }
        if ($CategoryResult -and $CategoryResult.PSObject -and -not $CategoryResult.PSObject.Properties['SourceLine']) {
            if ($null -ne $source.Line) { $CategoryResult | Add-Member -NotePropertyName 'SourceLine' -NotePropertyValue $source.Line -Force }
        }
    }

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

    $source = Get-HeuristicSourceContext
    if ($source) {
        if ($source.Script -and -not $entry.Contains('SourceScript')) { $entry['SourceScript'] = $source.Script }
        if ($source.Function -and -not $entry.Contains('SourceFunction')) { $entry['SourceFunction'] = $source.Function }
        if ($null -ne $source.Line -and -not $entry.Contains('SourceLine')) { $entry['SourceLine'] = $source.Line }

        if ($CategoryResult -and $CategoryResult.PSObject -and -not $CategoryResult.PSObject.Properties['SourceScript']) {
            if ($source.Script) { $CategoryResult | Add-Member -NotePropertyName 'SourceScript' -NotePropertyValue $source.Script -Force }
        }
        if ($CategoryResult -and $CategoryResult.PSObject -and -not $CategoryResult.PSObject.Properties['SourceFunction']) {
            if ($source.Function) { $CategoryResult | Add-Member -NotePropertyName 'SourceFunction' -NotePropertyValue $source.Function -Force }
        }
        if ($CategoryResult -and $CategoryResult.PSObject -and -not $CategoryResult.PSObject.Properties['SourceLine']) {
            if ($null -ne $source.Line) { $CategoryResult | Add-Member -NotePropertyName 'SourceLine' -NotePropertyValue $source.Line -Force }
        }
    }

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

    $entry = [ordered]@{
        Name    = $Name
        Status  = $Status
        Details = $Details
    }

    $source = Get-HeuristicSourceContext
    if ($source) {
        if ($source.Script -and -not $entry.Contains('SourceScript')) { $entry['SourceScript'] = $source.Script }
        if ($source.Function -and -not $entry.Contains('SourceFunction')) { $entry['SourceFunction'] = $source.Function }
        if ($null -ne $source.Line -and -not $entry.Contains('SourceLine')) { $entry['SourceLine'] = $source.Line }

        if ($CategoryResult -and $CategoryResult.PSObject -and -not $CategoryResult.PSObject.Properties['SourceScript']) {
            if ($source.Script) { $CategoryResult | Add-Member -NotePropertyName 'SourceScript' -NotePropertyValue $source.Script -Force }
        }
        if ($CategoryResult -and $CategoryResult.PSObject -and -not $CategoryResult.PSObject.Properties['SourceFunction']) {
            if ($source.Function) { $CategoryResult | Add-Member -NotePropertyName 'SourceFunction' -NotePropertyValue $source.Function -Force }
        }
        if ($CategoryResult -and $CategoryResult.PSObject -and -not $CategoryResult.PSObject.Properties['SourceLine']) {
            if ($null -ne $source.Line) { $CategoryResult | Add-Member -NotePropertyName 'SourceLine' -NotePropertyValue $source.Line -Force }
        }
    }

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
