param([string]$ReportRoot)

function Try-GetItemProperty($path) {
  try { Get-ItemProperty -Path $path -ErrorAction Stop } catch { $null }
}

if (-not $ReportRoot) {
  throw "ReportRoot parameter is required."
}

# Ensure collectors directory exists
$collectorDir = Join-Path $ReportRoot 'collectors'
if (-not (Test-Path $collectorDir)) {
  New-Item -Path $collectorDir -ItemType Directory -Force | Out-Null
}

# 1) LAPS footprints
$winLapsPol   = Try-GetItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LAPS'
$winLapsState = Try-GetItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\LAPS\State'
$admPwdPolicy = Try-GetItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft Services\AdmPwd'

# 2) Local admins + metadata
$localAdmins = @(Get-LocalGroupMember -Group 'Administrators' -ErrorAction SilentlyContinue)
$localUsers  = @(Get-LocalUser -ErrorAction SilentlyContinue)

$users = @()
foreach ($m in $localAdmins) {
  if ($m.ObjectClass -ne 'User' -or $m.PrincipalSource -notin @('Local','MicrosoftAccount')) { continue }

  $memberSid = $null
  if ($m.PSObject.Properties['SID'] -and $m.SID) {
    try { $memberSid = $m.SID.Value } catch { $memberSid = [string]$m.SID }
  }

  $u = $null
  if ($memberSid) {
    $u = $localUsers |
      Where-Object { $_.PSObject.Properties['SID'] -and $_.SID -and $_.SID.Value -eq $memberSid } |
      Select-Object -First 1
  }

  if (-not $u) {
    $nameCandidate = $m.Name
    if ($nameCandidate -match '^[^\\]+\\(.+)$') { $nameCandidate = $matches[1] }
    $u = $localUsers | Where-Object { $_.Name -eq $nameCandidate } | Select-Object -First 1
  }

  if (-not $u) { continue }

  $sid = $u.SID.Value
  $users += [pscustomobject]@{
    Name                 = $u.Name
    Sid                  = $sid
    Enabled              = [bool]$u.Enabled
    PasswordNeverExpires = [bool]$u.PasswordNeverExpires
    LastPasswordSet      = if ($u.LastPasswordSet) { $u.LastPasswordSet.ToUniversalTime().ToString('o') } else { $null }
    IsBuiltInAdmin       = ($sid -match '-500$')   # RID 500
    PrincipalSource      = $m.PrincipalSource
  }
}

# 3) Emit JSON
$checks = @(
  [pscustomobject]@{
    Id='LAPS.Policy'; Status='OK'; Data=@{
      WindowsLapsPolicy   = $winLapsPol
      WindowsLapsState    = $winLapsState
      LegacyAdmPwdPolicy  = $admPwdPolicy
    }
    Notes = if ($winLapsPol -or $winLapsState -or $admPwdPolicy) { 'LAPS footprints present' } else { 'No LAPS footprints' }
  },
  [pscustomobject]@{
    Id='LocalAdmins.List'; Status='OK'; Data=@{ Users = $users }
    Notes = "Count=$($users.Count)"
  }
)

$doc = [pscustomobject]@{
  SchemaVersion = 1
  Host          = $env:COMPUTERNAME
  CollectedAt   = (Get-Date).ToUniversalTime().ToString('o')
  CheckGroup    = 'LAPSLocalAdmin'
  Checks        = $checks
}

$path = Join-Path $collectorDir 'laps_localadmin.json'
$doc  | ConvertTo-Json -Depth 8 | Set-Content -Path $path -Encoding UTF8
Write-Output "Wrote $path"
