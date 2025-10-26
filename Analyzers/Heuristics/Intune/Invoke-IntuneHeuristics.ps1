<#!
.SYNOPSIS
    Entry point that evaluates all Intune heuristics and returns the combined category result.
#>

function Get-IntuneEnrollmentStateFromDsreg {
    param([string]$Text)

    if (-not $Text) { return 'Unknown' }

    $values = New-Object System.Collections.Generic.List[string]
    foreach ($line in [regex]::Split($Text, '\r?\n')) {
        if (-not $line) { continue }

        if ($line -match '^(?i)\s*Mdm[a-zA-Z]*\s*:\s*(?<value>.+)$') {
            $values.Add($matches['value'].Trim()) | Out-Null
        }
    }

    if ($values.Count -eq 0) { return 'Unknown' }

    $meaningfulFound = $false
    foreach ($value in $values) {
        if (-not $value) { continue }

        $trimmed = $value.Trim()
        if (-not $trimmed) { continue }

        if ($trimmed -match '^(?i)\(null\)|\(not\s+set\)|none|not\s+configured|n/?a|0x0$') { continue }
        if ($trimmed -match '^(?i)\{?0{8}-0{4}-0{4}-0{4}-0{12}\}?$') { continue }

        $meaningfulFound = $true

        $lower = $trimmed.ToLowerInvariant()
        if ($lower -match 'intune' -or $lower -match 'manage\.microsoft\.com' -or $lower -match 'mdm\.microsoft\.com' -or $lower -match 'd4ebce55-015a-49b5-a083-c84d1797ae8c') {
            return 'Intune'
        }
    }

    if (-not $meaningfulFound) { return 'None' }
    return 'Other'
}

function Test-IntuneArtifactEvidence {
    param($Context)

    if (-not $Context -or -not $Context.Artifacts) { return $false }

    foreach ($key in $Context.Artifacts.Keys) {
        if (-not $key) { continue }

        if ($key -match 'intune') {
            return $true
        }
    }

    return $false
}

function Invoke-IntuneHeuristics {
    param(
        [Parameter(Mandatory)]
        $Context
    )

    Write-HeuristicDebug -Source 'Intune' -Message 'Starting Intune heuristics evaluation' -Data ([ordered]@{
        HasArtifacts = [bool]($Context -and $Context.Artifacts)
    })

    $dsregText = Get-IntuneDsregText -Context $Context
    $enrollmentState = Get-IntuneEnrollmentStateFromDsreg -Text $dsregText

    $shouldRun = $false
    $detectionSource = 'none'

    switch ($enrollmentState) {
        'Intune' {
            $shouldRun = $true
            $detectionSource = 'dsreg'
        }
        'Other' {
            $shouldRun = $false
            $detectionSource = 'dsreg'
        }
        'None' {
            $shouldRun = $false
            $detectionSource = 'dsreg'
        }
        default {
            if (Test-IntuneArtifactEvidence -Context $Context) {
                $shouldRun = $true
                $detectionSource = 'artifacts'
            } else {
                $shouldRun = $false
                $detectionSource = if ($dsregText) { 'dsreg' } else { 'none' }
            }
        }
    }

    Write-HeuristicDebug -Source 'Intune' -Message 'Intune management detection result' -Data ([ordered]@{
        EnrollmentState = $enrollmentState
        DetectionSource = $detectionSource
        ShouldRun       = $shouldRun
    })

    if (-not $shouldRun) {
        return $null
    }

    $result = New-CategoryResult -Name 'Intune'
    Invoke-IntuneHeuristic-EnrollmentConnectivityHealth -Context $Context -Result $result
    Invoke-IntuneHeuristic-Win32EspAppHealth -Context $Context -Result $result
    Invoke-IntuneHeuristic-PushNotificationQuickSync -Context $Context -Result $result
    return $result
}
