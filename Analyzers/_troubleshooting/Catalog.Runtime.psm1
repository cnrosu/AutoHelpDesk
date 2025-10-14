Set-StrictMode -Version Latest

# region: state --------------------------------------------------------------
$script:CATALOG = $null
$script:CATALOG_INDEX = @{}

# region: helpers ------------------------------------------------------------
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

function Initialize-Catalog {
  param(
    [string]$CatalogPath = (Join-Path (Get-RepoRoot) 'dist/troubleshooting/index.json'),
    [switch]$Force
  )

  if (-not $Force -and $script:CATALOG_INDEX -and $script:CATALOG_INDEX.Count -gt 0) { return }

  if (-not (Test-Path -LiteralPath $CatalogPath)) {
    throw "Troubleshooting catalog not found at '$CatalogPath'. Ensure the build artifacts are present."
  }

  try {
    $doc = Read-Json -Path $CatalogPath
  } catch {
    throw "Failed to load troubleshooting catalog from '$CatalogPath': $($_.Exception.Message)"
  }

  $cards = @()
  if ($doc -is [System.Collections.IEnumerable] -and -not ($doc -is [string])) {
    $cards = @($doc)
  } elseif ($doc -and $doc.PSObject.Properties['cards']) {
    $cards = @($doc.cards)
  }

  $script:CATALOG = [pscustomobject]@{ cards = $cards }
  $script:CATALOG_INDEX = @{}

  $duplicates = [System.Collections.Generic.List[string]]::new()

  foreach ($card in $cards) {
    if (-not $card) { continue }

    $hasIdProperty = $card.PSObject.Properties['card_id']
    if (-not $hasIdProperty -or [string]::IsNullOrWhiteSpace($card.card_id)) {
      Write-Warning "Skipping troubleshooting card missing card_id."
      continue
    }

    $id = [string]$card.card_id
    if ($script:CATALOG_INDEX.ContainsKey($id)) {
      if (-not $duplicates.Contains($id)) { $null = $duplicates.Add($id) }
      continue
    }

    $script:CATALOG_INDEX[$id] = $card
  }

  if ($duplicates.Count -gt 0) {
    $unique = $duplicates | Sort-Object -Unique
    Write-Warning ("Duplicate card_id(s) detected in troubleshooting catalog: {0}" -f ($unique -join ', '))
  }
}

function Get-CatalogCardById {
  param(
    [Parameter(Mandatory)][string]$CardId,
    [string]$CatalogPath
  )

  if (-not $script:CATALOG_INDEX -or $script:CATALOG_INDEX.Count -eq 0) {
    if ($PSBoundParameters.ContainsKey('CatalogPath') -and $CatalogPath) {
      Initialize-Catalog -CatalogPath $CatalogPath
    } else {
      Initialize-Catalog
    }
  }

  return $script:CATALOG_INDEX[$CardId]
}

Export-ModuleMember -Function Initialize-Catalog, Get-CatalogCardById
