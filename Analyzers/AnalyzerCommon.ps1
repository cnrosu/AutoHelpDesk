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
        $details = $Data.GetEnumerator() | Sort-Object Name | ForEach-Object {
            "{0}={1}" -f $_.Name, $_.Value
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

    Write-HeuristicDebug -Source 'AnalyzerCommon' -Message 'Resolving analyzer artifact' -Data ([ordered]@{
        RequestedName = $Name
        LookupKeys    = ($lookupKeys -join ', ')
    })

    $entries = $null
    foreach ($candidate in $lookupKeys) {
        if ($Context.Artifacts.ContainsKey($candidate)) {
            Write-HeuristicDebug -Source 'AnalyzerCommon' -Message 'Matched analyzer artifact key' -Data ([ordered]@{
                RequestedName = $Name
                MatchedKey    = $candidate
                MatchCount    = $Context.Artifacts[$candidate].Count
            })

            $entries = $Context.Artifacts[$candidate]
            break
        }
    }

    if (-not $entries) {
        Write-HeuristicDebug -Source 'AnalyzerCommon' -Message 'No analyzer artifact match found' -Data ([ordered]@{
            RequestedName = $Name
            LookupKeys    = ($lookupKeys -join ', ')
        })
        return $null
    }

    if ($entries.Count -gt 1) { return $entries }
    return $entries[0]
}

function New-CategoryResult {
    param(
        [Parameter(Mandatory)]
        [string]$Name
    )

    return [pscustomobject]@{
        Name    = $Name
        Issues  = New-Object System.Collections.Generic.List[pscustomobject]
        Normals = New-Object System.Collections.Generic.List[pscustomobject]
        Checks  = New-Object System.Collections.Generic.List[pscustomobject]
    }
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

    $CategoryResult.Checks.Add([pscustomobject]@{
            Name    = $Name
            Status  = $Status
            Details = $Details
        }) | Out-Null
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
        return $Artifact | ForEach-Object { $_.Data.Payload }
    }

    if ($Artifact.Data -and $Artifact.Data.PSObject.Properties['Payload']) {
        return $Artifact.Data.Payload
    }

    return $null
}

function Resolve-SinglePayload {
    param(
        [Parameter(Mandatory)]
        $Payload
    )

    if ($null -eq $Payload) { return $null }

    if ($Payload -is [System.Collections.IEnumerable] -and -not ($Payload -is [string])) {
        return ($Payload | Select-Object -First 1)
    }

    return $Payload
}
