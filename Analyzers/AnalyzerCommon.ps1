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

    Get-ChildItem -Path $resolved -Recurse -Filter '*.json' -File -ErrorAction SilentlyContinue | ForEach-Object {
        $content = Get-Content -Path $_.FullName -Raw -ErrorAction SilentlyContinue
        $data = $null
        if ($content) {
            try {
                $data = $content | ConvertFrom-Json -ErrorAction Stop
            } catch {
                $data = [pscustomobject]@{ Error = $_.Exception.Message }
            }
        }

        $key = $_.BaseName.ToLowerInvariant()
        if ($artifactMap.ContainsKey($key)) {
            $artifactMap[$key] = @($artifactMap[$key]) + ,([pscustomobject]@{
                    Path = $_.FullName
                    Data = $data
                })
        } else {
            $artifactMap[$key] = @([pscustomobject]@{
                    Path = $_.FullName
                    Data = $data
                })
        }
    }

    return [pscustomobject]@{
        InputFolder = $resolved
        Artifacts   = $artifactMap
    }
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
    if (-not $Context.Artifacts.ContainsKey($key)) { return $null }

    $entries = $Context.Artifacts[$key]
    if (-not $entries) { return $null }

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

        [string]$Subcategory = $null
    )

    $CategoryResult.Issues.Add([pscustomobject]@{
            Severity = $Severity
            Title    = $Title
            Evidence = $Evidence
            Subcategory = $Subcategory
        }) | Out-Null
}

function Add-CategoryNormal {
    param(
        [Parameter(Mandatory)]
        $CategoryResult,

        [Parameter(Mandatory)]
        [string]$Title,

        [object]$Evidence = $null,

        [string]$Subcategory = $null
    )

    $entry = [ordered]@{
        Title    = $Title
        Evidence = $Evidence
    }

    if ($PSBoundParameters.ContainsKey('Subcategory') -and $Subcategory) {
        $entry['Subcategory'] = $Subcategory
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
