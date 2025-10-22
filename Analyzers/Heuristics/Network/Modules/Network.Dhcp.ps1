$script:DhcpAnalyzerFailureExplanation = 'The DHCP diagnostics failed to run, so AutoHelpDesk cannot confirm lease or server health.'
# Structured remediation mapping:
# - Initial instruction becomes a text step describing the restart and renewal.
# - Commands remain a code step.
# - Follow-up driver guidance is a concluding text step.
$script:DhcpAnalyzerFailureRemediation = @'
[
  {
    "type": "text",
    "content": "Restart the DHCP Client service and renew the lease to restore analyzer telemetry; update network adapter drivers if failures persist."
  },
  {
    "type": "code",
    "lang": "powershell",
    "content": "Restart-Service Dhcp\nipconfig /renew"
  },
  {
    "type": "text",
    "content": "Install the latest network adapter drivers from the vendor if the service keeps failing."
  }
]
'@

function Get-DhcpAnalyzerDisplayName {
    param(
        $Analyzer
    )

    if (-not $Analyzer) { return 'DHCP check' }

    $scriptInfo = if ($Analyzer.PSObject.Properties['Script']) { $Analyzer.Script } else { $null }
    $scriptName = $null

    if ($scriptInfo) {
        if ($scriptInfo.PSObject -and $scriptInfo.PSObject.Properties['Name']) {
            $scriptName = [string]$scriptInfo.Name
        } else {
            try {
                $scriptName = [System.IO.Path]::GetFileName($scriptInfo)
            } catch {
                $scriptName = [string]$scriptInfo
            }
        }
    }

    if (-not $scriptName) { return 'DHCP check' }

    $baseName = [System.IO.Path]::GetFileNameWithoutExtension($scriptName)
    if ($baseName.StartsWith('Analyze-')) {
        $baseName = $baseName.Substring(8)
    }

    if (-not $baseName) { return 'DHCP check' }

    $kebab = ConvertTo-KebabCase $baseName
    if (-not $kebab) { $kebab = $baseName }

    $rawParts = $kebab -split '-'
    $parts = New-Object System.Collections.Generic.List[string]
    foreach ($part in $rawParts) {
        if (-not $part) { continue }

        $upper = $part.ToUpperInvariant()
        switch ($upper) {
            'DHCP' { $parts.Add('DHCP') | Out-Null; continue }
            'APIPA' { $parts.Add('APIPA') | Out-Null; continue }
        }

        $text = $part.Substring(0,1).ToUpperInvariant()
        if ($part.Length -gt 1) {
            $text += $part.Substring(1).ToLowerInvariant()
        }
        $parts.Add($text) | Out-Null
    }

    if ($parts.Count -eq 0) { return 'DHCP check' }
    return ($parts -join ' ')
}

function Invoke-DhcpAnalyzers {
    param(
        [Parameter(Mandatory)]
        $Context,

        [Parameter(Mandatory)]
        $CategoryResult,

        [string]$InputFolder
    )

    Write-HeuristicDebug -Source 'Network' -Message 'Entering Invoke-DhcpAnalyzers' -Data ([ordered]@{
        InputFolder = $InputFolder
    })

    if (-not $InputFolder) {
        Write-Host 'DHCP analyzers skipped: no InputFolder provided.'
        return
    }
    if (-not (Test-Path -LiteralPath $InputFolder)) {
        Write-Host ("DHCP analyzers skipped: folder '{0}' not found." -f $InputFolder)
        return
    }

    $analyzerRoot = Join-Path -Path $PSScriptRoot -ChildPath 'DHCP'
    if (-not (Test-Path -LiteralPath $analyzerRoot)) {
        Write-Host ("DHCP analyzers skipped: analyzer root '{0}' not found." -f $analyzerRoot)
        return
    }

    $scriptFiles = Get-ChildItem -Path $analyzerRoot -Filter 'Analyze-Dhcp*.ps1' -File -ErrorAction SilentlyContinue | Sort-Object Name
    if (-not $scriptFiles -or $scriptFiles.Count -eq 0) {
        Write-Host ("DHCP analyzers missing scripts: searched '{0}' for pattern 'Analyze-Dhcp*.ps1'." -f $analyzerRoot)
        return
    }

    Write-HeuristicDebug -Source 'Network' -Message 'Resolved DHCP analyzer scripts' -Data ([ordered]@{
        AnalyzerRoot = $analyzerRoot
        ScriptCount  = $scriptFiles.Count
    })

    $baseArtifactPath = Join-Path -Path $InputFolder -ChildPath 'dhcp-base.json'
    $resolvedBaseArtifact = $null
    $hasBaseArtifact = $false
    if (Test-Path -LiteralPath $baseArtifactPath) {
        $resolvedBaseArtifact = (Resolve-Path -LiteralPath $baseArtifactPath).ProviderPath
        $hasBaseArtifact = $true
    }

    $eligibleAnalyzers = [System.Collections.Generic.List[object]]::new()
    foreach ($script in $scriptFiles) {
        $baseName = [System.IO.Path]::GetFileNameWithoutExtension($script.Name)
        if (-not $baseName.StartsWith('Analyze-')) { continue }
        $suffix = $baseName.Substring(8)
        if (-not $suffix) { continue }

        if ($hasBaseArtifact) {
            $eligibleAnalyzers.Add([pscustomobject]@{
                Script       = $script
                ArtifactBase = 'dhcp-base'
                ArtifactPath = $resolvedBaseArtifact
                Source       = 'dhcp-base.json'
            }) | Out-Null
            continue
        }

        $artifactBase = ConvertTo-KebabCase $suffix
        if (-not $artifactBase) { continue }

        $artifactPath = Join-Path -Path $InputFolder -ChildPath ($artifactBase + '.json')
        if (Test-Path -LiteralPath $artifactPath) {
            $eligibleAnalyzers.Add([pscustomobject]@{
                Script       = $script
                ArtifactBase = $artifactBase
                ArtifactPath = (Resolve-Path -LiteralPath $artifactPath).ProviderPath
                Source       = 'legacy'
            }) | Out-Null
        } else {
            Write-Host (
                "DHCP analyzer '{0}' skipped: artifact '{1}.json' not found in '{2}'." -f
                $script.Name,
                $artifactBase,
                $InputFolder
            )
        }
    }

    if ($eligibleAnalyzers.Count -eq 0) {
        if ($hasBaseArtifact) {
            Write-Host ("DHCP analyzers skipped: dhcp-base.json resolved to '{0}' but no analyzers were eligible." -f $resolvedBaseArtifact)
        } else {
            Write-Host ("DHCP analyzers skipped: no eligible artifacts discovered in '{0}'." -f $InputFolder)
        }
        return
    }

    if ($hasBaseArtifact) {
        Write-HeuristicDebug -Source 'Network' -Message 'Eligible DHCP analyzers' -Data ([ordered]@{
            EligibleCount    = $eligibleAnalyzers.Count
            ArtifactStrategy = 'dhcp-base.json'
            ArtifactPath     = $resolvedBaseArtifact
        })
    } else {
        Write-HeuristicDebug -Source 'Network' -Message 'Eligible DHCP analyzers' -Data ([ordered]@{
            EligibleCount = $eligibleAnalyzers.Count
            Artifacts     = ($eligibleAnalyzers | ForEach-Object { $_.ArtifactBase })
        })
    }

    $findings = New-Object System.Collections.Generic.List[object]

    foreach ($analyzer in $eligibleAnalyzers) {
        try {
            $result = & $analyzer.Script.FullName -InputFolder $InputFolder -CategoryResult $CategoryResult -Context $Context
        } catch {
            Add-CategoryIssue -CategoryResult $CategoryResult -Severity 'warning' -Title ("DHCP analyzer failed: {0}" -f $analyzer.Script.Name) -Evidence $_.Exception.Message -Subcategory 'DHCP' -Explanation $script:DhcpAnalyzerFailureExplanation -Remediation $script:DhcpAnalyzerFailureRemediation
            continue
        }

        if ($null -eq $result) { continue }

        if ($result -is [System.Collections.IEnumerable] -and -not ($result -is [string])) {
            foreach ($item in $result) {
                if ($null -ne $item) { $findings.Add($item) | Out-Null }
            }
        } else {
            $findings.Add($result) | Out-Null
        }
    }

    if ($findings.Count -gt 0) {
        foreach ($finding in $findings) {
            if (-not $finding) { continue }

            $severity = if ($finding.PSObject.Properties['Severity'] -and $finding.Severity) { [string]$finding.Severity } else { 'info' }
            $title = if ($finding.PSObject.Properties['Message'] -and $finding.Message) {
                    [string]$finding.Message
                } elseif ($finding.PSObject.Properties['Check'] -and $finding.Check) {
                    [string]$finding.Check
                } else {
                    'DHCP finding'
                }
            $evidence = if ($finding.PSObject.Properties['Evidence']) { $finding.Evidence } else { $null }
            $subcategory = if ($finding.PSObject.Properties['Subcategory'] -and $finding.Subcategory) { [string]$finding.Subcategory } else { 'DHCP' }

            if ($severity -in @('good', 'ok', 'normal')) {
                Add-CategoryNormal -CategoryResult $CategoryResult -Title $title -Evidence $evidence -Subcategory $subcategory
            } else {
                Add-CategoryIssue -CategoryResult $CategoryResult -Severity $severity -Title $title -Evidence $evidence -Subcategory $subcategory
            }
        }
    } else {
        foreach ($analyzer in $eligibleAnalyzers) {
            $checkName = Get-DhcpAnalyzerDisplayName -Analyzer $analyzer
            $evidence = [ordered]@{
                Check    = $checkName
                Artifact = "$($analyzer.ArtifactBase).json"
                Folder   = $InputFolder
            }

            if ($analyzer.Script -and $analyzer.Script.PSObject -and $analyzer.Script.PSObject.Properties['FullName']) {
                $evidence['Script'] = $analyzer.Script.FullName
            }

            Add-CategoryNormal -CategoryResult $CategoryResult -Title ("{0} check healthy" -f $checkName) -Evidence $evidence -Subcategory 'DHCP'
        }
    }
}
