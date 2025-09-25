# Common.psm1
# Shared helpers, severity mapping, and object constructors used by all analyzer modules.
# Exported: New-IssueCard, New-GoodCard, New-Check, Read-Text, Get-AllTextFiles, Normalize-Severity

$script:SeverityOrder = @('critical','high','medium','low','info','good')

function Normalize-Severity {
  param([Parameter(Mandatory)][string]$Severity)
  $s = $Severity.ToLowerInvariant()
  if ($script:SeverityOrder -contains $s) { return $s } else { return 'info' }
}

function New-IssueCard {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][ValidateSet('System','Hardware','Network','Security','Services','Office','ActiveDirectory','Printing')][string]$Area,
    [Parameter(Mandatory)][string]$Message,
    [string]$Evidence = '',
    [Parameter(Mandatory)][string]$Severity
  )
  $sev = Normalize-Severity $Severity
  $css = if ($sev -eq 'good') { 'good' } else { $sev }
  $badge = if ($sev -eq 'good') { 'GOOD' } else { $sev.ToUpper() }
  [pscustomobject]@{
    Severity  = $sev
    Area      = $Area
    Message   = $Message
    Evidence  = $Evidence
    CssClass  = $css
    BadgeText = $badge
  }
}

function New-GoodCard {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][ValidateSet('System','Hardware','Network','Security','Services','Office','ActiveDirectory','Printing')][string]$Area,
    [Parameter(Mandatory)][string]$Message,
    [string]$Evidence = ''
  )
  New-IssueCard -Area $Area -Message $Message -Evidence $Evidence -Severity good
}

function New-Check {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$Area,
    [Parameter(Mandatory)][string]$Name,
    [Parameter(Mandatory)][ValidateSet('pass','fail','warn','info')][string]$Status,
    [double]$Weight = 1.0,
    [string]$Evidence = ''
  )
  [pscustomobject]@{
    Area     = $Area
    Name     = $Name
    Status   = $Status
    Weight   = $Weight
    Evidence = $Evidence
  }
}

function Read-Text {
  param([Parameter(Mandatory)][string]$Path)
  if (Test-Path $Path) { return (Get-Content -Path $Path -Raw -ErrorAction SilentlyContinue) } else { return '' }
}

function Get-AllTextFiles {
  param([Parameter(Mandatory)][string]$Root)
  Get-ChildItem -Path $Root -Recurse -File -Include *.txt,*.log,*.csv,*.tsv -ErrorAction SilentlyContinue
}

Export-ModuleMember -Function Normalize-Severity, New-IssueCard, New-GoodCard, New-Check, Read-Text, Get-AllTextFiles
