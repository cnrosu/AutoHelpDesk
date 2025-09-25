<#
  Shared helpers for Active Directory analysis.
#>

function Normalize-AdDomain {
  param([string]$Name)

  if (-not $Name) { return $null }
  $value = $Name.Trim()
  if (-not $value) { return $null }
  return $value.TrimEnd('.').ToLowerInvariant()
}

function Normalize-AdHost {
  param([string]$Name)

  if (-not $Name) { return $null }
  $value = $Name.Trim()
  if (-not $value) { return $null }
  $value = $value.Trim('\\')
  if ($value -like '*\\*') {
    $segments = $value -split '\\'
    if ($segments.Count -gt 0) { $value = $segments[-1] }
  }
  return $value.Trim().TrimEnd('.').ToLowerInvariant()
}
