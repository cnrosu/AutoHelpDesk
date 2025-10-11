<# 
  Split-CoLocatedShards.ps1
  Splits the monolithic troubleshooting catalog (YAML or JSON) into per-analyzer JSON shards:
    <AnalyzerPath>.ps1.cards.json
  Also writes an index: dist/troubleshooting/index.json

  Usage examples:
    pwsh tools/Split-CoLocatedShards.ps1 -Source Analyzers/_troubleshooting/all.cards.yaml
    pwsh tools/Split-CoLocatedShards.ps1 -Source Analyzers/_troubleshooting/all.cards.json
#>

param(
  [Parameter(Mandatory=$true)][string]$Source,
  [string]$OutIndexDir = "dist/troubleshooting",
  [switch]$FailOnDuplicateIds
)

$ErrorActionPreference = 'Stop'

if (!(Test-Path $Source)) { throw "Source not found: $Source" }

# ------------ Load document (YAML or JSON) ------------
$ext = [IO.Path]::GetExtension($Source).ToLowerInvariant()
$doc = $null

switch ($ext) {
  '.json' {
    $raw = Get-Content -Path $Source -Raw -Encoding UTF8
    $doc = $raw | ConvertFrom-Json -Depth 100
  }
  default {
    # Treat as YAML. Uses your PureYaml module.
    $pureYaml = Join-Path -Path (Split-Path $PSScriptRoot -Parent) -ChildPath "Analyzers/_troubleshooting/PureYaml.psm1"
    if (!(Test-Path $pureYaml)) {
      # also check relative to repo root if invoked there
      $alt = "Analyzers/_troubleshooting/PureYaml.psm1"
      if (Test-Path $alt) { $pureYaml = $alt }
    }
    if (!(Test-Path $pureYaml)) { throw "PureYaml.psm1 not found at $pureYaml" }
    Import-Module -Name $pureYaml -Force

    $raw = Get-Content -Path $Source -Raw -Encoding UTF8
    $doc = ConvertFrom-Yaml -Yaml $raw
  }
}

if (-not $doc)             { throw "Parsed document is null." }
if (-not $doc.cards)       { throw "Parsed document missing 'cards' array." }

$cards = @($doc.cards)
Write-Host "Loaded $($cards.Count) card(s) from $Source"

# ------------ Helpers ------------
function Slugify([string]$s) {
  if ([string]::IsNullOrWhiteSpace($s)) { return $null }
  $t = $s.ToLowerInvariant()
  $t = ($t -replace '[^a-z0-9]+','-').Trim('-')
  if ([string]::IsNullOrWhiteSpace($t)) { return $null }
  return $t
}

function Stable-IdFromParts([string]$prefix, [string]$a, [string]$b) {
  $concat = "$a|$b"
  $hash = [System.Security.Cryptography.SHA1]::Create()
  $bytes = [Text.Encoding]::UTF8.GetBytes($concat)
  $digest = $hash.ComputeHash($bytes)
  $hex = -join ($digest | ForEach-Object { $_.ToString("x2") })
  return ("{0}/{1}" -f $prefix, $hex.Substring(0,12))
}

function Derive-CardId([pscustomobject]$c) {
  if ($c.card_id) { return $c.card_id }
  if ($c.PSObject.Properties.Match('meta').Count -gt 0 -and $c.meta -and $c.meta.PSObject.Properties.Match('check_id').Count -gt 0) {
    return $c.meta.check_id
  }
  $slug = Slugify ($c.title)
  if ($c.area -and $slug) { return "$($c.area)/$slug" }
  if ($c.category -and $slug) { return "$($c.category)/$slug" }

  $anPath = if ($c.paths) { $c.paths.analyzer_file } else { $null }
  if ($anPath -or $c.title) {
    $prefix = $c.area; if (-not $prefix) { $prefix = $c.category }; if (-not $prefix) { $prefix = 'Generated' }
    return (Stable-IdFromParts $prefix ($anPath ?? '') ($c.title ?? ''))
  }
  return $null
}

# ------------ Normalize, validate, group ------------
$cardsByAnalyzer = @{}
$fixedIds = 0; $skippedNoId = 0; $skippedNoAnalyzer = 0
$seenIds = @{}

foreach($c in $cards) {

  # Ensure card_id
  $cid = Derive-CardId $c
  if (-not $cid) {
    Write-Warning "Skipping card without usable id. Title='$($c.title)' Area='$($c.area)'"
    $skippedNoId++; continue
  }
  if (-not ($c.PSObject.Properties.Match('card_id').Count)) {
    $c | Add-Member -NotePropertyName 'card_id' -NotePropertyValue $cid
    $fixedIds++
  } elseif (-not $c.card_id) {
    $c.card_id = $cid
    $fixedIds++
  }

  # Duplicate ID detection (per shard compile we still allow, but can fail if requested)
  if ($seenIds.ContainsKey($c.card_id)) {
    $seenIds[$c.card_id]++
    if ($FailOnDuplicateIds) {
      throw "Duplicate card_id detected: '$($c.card_id)'"
    }
  } else {
    $seenIds[$c.card_id] = 1
  }

  # Analyzer path
  $analyzer = $null
  if ($c.PSObject.Properties.Match('paths').Count -and $c.paths -and $c.paths.PSObject.Properties.Match('analyzer_file').Count) {
    $analyzer = $c.paths.analyzer_file
  }
  if (-not $analyzer) {
    Write-Warning "Card '$($c.card_id)' has no paths.analyzer_file — skipping (cannot place shard)."
    $skippedNoAnalyzer++; continue
  }

  if (-not $cardsByAnalyzer.ContainsKey($analyzer)) { $cardsByAnalyzer[$analyzer] = New-Object System.Collections.ArrayList }
  [void]$cardsByAnalyzer[$analyzer].Add($c)
}

# ------------ Write JSON shards ------------
[int]$written = 0
foreach($kv in $cardsByAnalyzer.GetEnumerator()){
  $relAnalyzer = $kv.Key
  $cardsForAnalyzer = $kv.Value

  $dir   = Split-Path $relAnalyzer -Parent
  $file  = Split-Path $relAnalyzer -Leaf
  $shard = Join-Path $dir ($file + ".cards.json")

  if (!(Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }

  $docOut = [pscustomobject]@{ cards = $cardsForAnalyzer }
  $json   = $docOut | ConvertTo-Json -Depth 100
  Set-Content -Path $shard -Value $json -Encoding UTF8
  Write-Host "Wrote $shard"
  $written++
}

# ------------ Write index ------------
if (!(Test-Path $OutIndexDir)) { New-Item -ItemType Directory -Force -Path $OutIndexDir | Out-Null }
$all = @()
foreach($kv in $cardsByAnalyzer.GetEnumerator()){ $all += $kv.Value }
$all = $all | Sort-Object category, area, card_id

$indexJsonPath = Join-Path $OutIndexDir "index.json"
$all | ConvertTo-Json -Depth 100 | Set-Content -Path $indexJsonPath -Encoding UTF8

# Optionally also write the consolidated full JSON (nice to have)
$allDocPath = Join-Path $OutIndexDir "all.cards.json"
([pscustomobject]@{ cards = $all }) | ConvertTo-Json -Depth 100 | Set-Content -Path $allDocPath -Encoding UTF8

Write-Host "Done. Wrote $written shard(s), $indexJsonPath, and $allDocPath"
Write-Host "Fixed missing ids: $fixedIds     Skipped (no id): $skippedNoId     Skipped (no analyzer): $skippedNoAnalyzer"
