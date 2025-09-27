[CmdletBinding()]
param(
  [Parameter(Mandatory)]
  [string]$InputFolder
)

$ErrorActionPreference = 'Stop'

if (-not (Test-Path -Path $InputFolder -PathType Container)) {
  throw "Input folder '$InputFolder' does not exist or is not a directory."
}

# Discover candidate text files (txt/log/csv/tsv) beneath the input folder.
# NOTE: -Include only works when the -Path has a wildcard, so we gather all
# files first and then filter them in PowerShell to ensure we don't miss the
# Autoruns export.
$textExtensions = '.txt', '.log', '.csv', '.tsv'
$allTextFiles = Get-ChildItem -Path $InputFolder -Recurse -File -ErrorAction SilentlyContinue |
  Where-Object { $textExtensions -contains $_.Extension.ToLowerInvariant() }

# Helper: find an Autoruns file by name hints or content inspection.
function Find-AutorunsFile {
  param(
    [System.IO.FileInfo[]]$Files
  )

  $nameHints = @('autoruns','autorunsc','startupprograms','startupitems')
  $contentNeedles = @(
    'Entry,Description,Publisher',
    'Entry Location'
  )

  # Try matching by filename first.
  foreach ($file in $Files) {
    $lowerName = $file.Name.ToLowerInvariant()
    foreach ($hint in $nameHints) {
      if ($lowerName -like "*${hint}*") {
        return $file
      }
    }
  }

  # Fall back to content sniffing (first ~80 lines) if no filename match.
  foreach ($file in $Files) {
    $snippet = Get-Content -Path $file.FullName -TotalCount 80 -ErrorAction SilentlyContinue | Out-String
    foreach ($needle in $contentNeedles) {
      if ($snippet -match [regex]::Escape($needle)) {
        return $file
      }
    }
  }

  return $null
}

$autorunsFile = Find-AutorunsFile -Files $allTextFiles

if (-not $autorunsFile) {
  Write-Output "autoruns\tMissing\tFile not discovered in collection output."
  return
}

Write-Output ("autoruns\tFound\t{0}" -f $autorunsFile.FullName)

# Try to parse the file as CSV to count non-Microsoft entries.
$rawText = Get-Content -Path $autorunsFile.FullName -Raw -ErrorAction SilentlyContinue

if (-not $rawText) {
  Write-Output "autoruns\tWarning\tAutoruns file exists but is empty."
  return
}

if ($rawText -notmatch 'Entry,Description,Publisher') {
  $lines = $rawText -split "`r?`n"
  if ($lines.Count -gt 0) {
    $maxIndex = [Math]::Min($lines.Count - 1, 10)
    $preview = $lines[0..$maxIndex] -join ' | '
  } else {
    $preview = ''
  }
  Write-Output ("autoruns\tWarning\tAutoruns output detected but format not recognized. Preview: {0}" -f $preview)
  return
}

try {
  $csv = $rawText | ConvertFrom-Csv
} catch {
  Write-Output ("autoruns\tWarning\tFailed to parse CSV: {0}" -f $_.Exception.Message)
  return
}

if (-not $csv) {
  Write-Output "autoruns\tWarning\tAutoruns CSV parsed but contained no rows."
  return
}

$nonMicrosoft = $csv | Where-Object {
  $_.Publisher -and ($_.Publisher -notmatch 'microsoft')
}

$totalCount = $csv.Count
$nonMicrosoftCount = if ($nonMicrosoft) { $nonMicrosoft.Count } else { 0 }

Write-Output (
  "autoruns\tParsed\tTotal Entries: {0}; Non-Microsoft Entries: {1}" -f $totalCount, $nonMicrosoftCount
)
