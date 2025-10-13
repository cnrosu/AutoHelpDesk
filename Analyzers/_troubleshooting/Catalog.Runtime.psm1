Set-StrictMode -Version Latest

# region: state --------------------------------------------------------------
$script:CATALOG = $null
$script:CATALOG_INDEX = @{}
$script:CATALOG_WATCHER = $null
$script:CATALOG_LAST_HASH = $null

# region: helpers ------------------------------------------------------------
function ConvertTo-Sha1Hex {
  param(
    [Parameter(Mandatory)]
    [AllowEmptyString()]
    [string]$Text
  )

  if ([string]::IsNullOrEmpty($Text)) {
    $stack = @()
    try { $stack = Get-PSCallStack | Select-Object -First 5 } catch { $stack = @() }
    $stackTrace = if ($stack -and $stack.Count -gt 0) {
      ($stack | ForEach-Object {
          $scriptName = if ($_.ScriptName) { $_.ScriptName } else { '(no script)' }
          $functionName = if ($_.FunctionName) { $_.FunctionName } else { '(no function)' }
          $lineNumber = if ($_.ScriptLineNumber -and $_.ScriptLineNumber -gt 0) { $_.ScriptLineNumber } else { '?' }
          "${functionName} @ ${scriptName}:${lineNumber}"
        }) -join ' | '
    } else {
      '(call stack unavailable)'
    }

    Write-Host "[Catalog] ConvertTo-Sha1Hex received empty Text input. Stack: $stackTrace"
  }

  $sha = [System.Security.Cryptography.SHA1]::Create()
  $bytes = [Text.Encoding]::UTF8.GetBytes($Text)
  ($sha.ComputeHash($bytes) | ForEach-Object { $_.ToString('x2') }) -join ''
}

function Get-RepoRoot {
  # repo root is parent of Analyzers/
  $here = $PSScriptRoot
  # <repo>/Analyzers/_troubleshooting
  Split-Path (Split-Path $here -Parent) -Parent
}

function Read-Json {
  param([Parameter(Mandatory)] [string]$Path)
  if (!(Test-Path -LiteralPath $Path)) { throw "File not found: $Path" }
  Get-Content -LiteralPath $Path -Raw -Encoding UTF8 | ConvertFrom-Json -Depth 100
}

# region: compilation --------------------------------------------------------
function Find-CardShards {
  param([string]$SearchRoot = (Get-RepoRoot))
  Get-ChildItem -Path $SearchRoot -Recurse -Filter '*.ps1.cards.json' -File | Sort-Object FullName
}

function Compile-CatalogFromShards {
  <#
    Returns:
      [pscustomobject]@{ cards = <sorted array>; duplicates = <array of {card_id, files[]}> }
  #>
  param(
    [string]$SearchRoot = (Get-RepoRoot),
    [switch]$FailOnDuplicateIds
  )
  $shards = Find-CardShards -SearchRoot $SearchRoot
  $cards = New-Object System.Collections.ArrayList
  $byIdFiles = @{}

  foreach ($f in $shards) {
    try {
      $doc = Read-Json -Path $f.FullName
    } catch {
      throw "Failed to parse shard: $($f.FullName) -> $($_.Exception.Message)"
    }
    if (-not $doc -or -not $doc.cards) {
      Write-Warning "Shard has no 'cards' array: $($f.FullName)"
      continue
    }
    foreach ($c in @($doc.cards)) {
      if (-not $c.card_id) {
        Write-Warning "Skipping card without 'card_id' in $($f.FullName)"
        continue
      }
      if (-not $byIdFiles.ContainsKey($c.card_id)) {
        $byIdFiles[$c.card_id] = New-Object System.Collections.ArrayList
      }
      [void]$byIdFiles[$c.card_id].Add($f.FullName)
      [void]$cards.Add($c)
    }
  }

  # dupes
  $dupes = @()
  foreach ($k in $byIdFiles.Keys) {
    $paths = $byIdFiles[$k]
    if ($paths.Count -gt 1) {
      $dupes += [pscustomobject]@{
        card_id = $k
        files   = ($paths | Sort-Object -Unique)
      }
    }
  }
  if ($FailOnDuplicateIds -and $dupes.Count -gt 0) {
    $msg = "Duplicate card_id(s) found:`n" + ($dupes | ForEach-Object { "  $($_.card_id)`n    - " + ($_.files -join "`n    - ") }) -join "`n"
    throw $msg
  }

  $sorted = $cards | Sort-Object category, area, card_id
  [pscustomobject]@{ cards = $sorted; duplicates = $dupes }
}

function Write-CatalogArtifacts {
  param(
    [Parameter(Mandatory)][pscustomobject]$Catalog,
    [string]$OutIndexDir = (Join-Path (Get-RepoRoot) 'dist/troubleshooting'),
    [string]$OutAllCards = (Join-Path (Get-RepoRoot) 'Analyzers/_troubleshooting/all.cards.json')
  )
  if (!(Test-Path $OutIndexDir)) { New-Item -ItemType Directory -Force -Path $OutIndexDir | Out-Null }
  $flat = $Catalog.cards
  $flat | ConvertTo-Json -Depth 100 | Set-Content -Path (Join-Path $OutIndexDir 'index.json') -Encoding UTF8
  ([pscustomobject]@{ cards = $flat }) | ConvertTo-Json -Depth 100 | Set-Content -Path $OutAllCards -Encoding UTF8
}

# region: runtime API --------------------------------------------------------
function Initialize-Catalog {
  param(
    [switch]$PreferMerged,         # try prebuilt all.cards.json first (if present)
    [switch]$WriteArtifacts,       # also write merged files on startup
    [switch]$FailOnDuplicateIds
  )
  # Try merged file
  if ($PreferMerged) {
    $merged = Join-Path $PSScriptRoot 'all.cards.json'
    if (Test-Path $merged) {
      try {
        $doc = Read-Json -Path $merged
        if ($doc -and $doc.cards) {
          $script:CATALOG = $doc
        }
      } catch {
        Write-Warning "Failed to load prebuilt catalog: $($_.Exception.Message)"
      }
    }
  }
  # Fallback: compile from shards
  if (-not $script:CATALOG) {
    $compiled = Compile-CatalogFromShards -FailOnDuplicateIds:$FailOnDuplicateIds
    $script:CATALOG = [pscustomobject]@{ cards = $compiled.cards }
    if ($compiled.duplicates.Count -gt 0) {
      Write-Warning ("Duplicate card_ids detected: {0}" -f (($compiled.duplicates.card_id | Sort-Object -Unique) -join ', '))
    }
    if ($WriteArtifacts) {
      Write-CatalogArtifacts -Catalog $compiled
    }
  }
  # Build index
  $script:CATALOG_INDEX = @{}
  foreach ($c in @($script:CATALOG.cards)) { $script:CATALOG_INDEX[$c.card_id] = $c }
  # Remember content hash for change detection
  $hashInput = ($script:CATALOG.cards | ConvertTo-Json -Depth 100)
  $script:CATALOG_LAST_HASH = ConvertTo-Sha1Hex -Text $hashInput
  Write-Host ("Catalog loaded: {0} cards." -f $script:CATALOG_INDEX.Count)
}

function Get-CatalogCardById {
  param([Parameter(Mandatory)][string]$CardId)
  if (-not $script:CATALOG_INDEX) { Initialize-Catalog -PreferMerged }
  return $script:CATALOG_INDEX[$CardId]
}

function Start-CatalogWatcher {
  <#
    Optional hot-reload.
    Re-compiles when any *.ps1.cards.json changes and updates in-memory catalog.
  #>
  param([string]$SearchRoot = (Get-RepoRoot))
  if ($script:CATALOG_WATCHER) { return }
  $fsw = New-Object System.IO.FileSystemWatcher
  $fsw.Path = (Resolve-Path $SearchRoot)
  $fsw.Filter = '*.ps1.cards.json'
  $fsw.IncludeSubdirectories = $true
  $fsw.EnableRaisingEvents = $true

  $action = {
    try {
      $compiled = Compile-CatalogFromShards
      $flat = $compiled.cards
      $hash = ConvertTo-Sha1Hex -Text ($flat | ConvertTo-Json -Depth 100)
      if ($hash -ne $script:CATALOG_LAST_HASH) {
        $script:CATALOG = [pscustomobject]@{ cards = $flat }
        $script:CATALOG_INDEX = @{}
        foreach ($c in @($flat)) { $script:CATALOG_INDEX[$c.card_id] = $c }
        $script:CATALOG_LAST_HASH = $hash
        Write-Host "[Catalog] Reloaded: $($flat.Count) cards."
      }
    } catch {
      Write-Warning "[Catalog] Reload failed: $($_.Exception.Message)"
    }
  }

  Register-ObjectEvent $fsw Changed -Action $action | Out-Null
  Register-ObjectEvent $fsw Created -Action $action | Out-Null
  Register-ObjectEvent $fsw Deleted -Action $action | Out-Null
  Register-ObjectEvent $fsw Renamed -Action $action | Out-Null

  $script:CATALOG_WATCHER = $fsw
  Write-Host "[Catalog] Watcher started: $($fsw.Path)"
}

Export-ModuleMember -Function Initialize-Catalog, Get-CatalogCardById, Start-CatalogWatcher, Compile-CatalogFromShards, Write-CatalogArtifacts
