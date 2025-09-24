<#
.SYNOPSIS
  Sets PDC Emulator to sync with external NTP servers and restarts time service.
#>
[CmdletBinding()]
param(
  [string[]]$NtpServers = @('time.google.com,0x9','au.pool.ntp.org,0x9')
)
$ErrorActionPreference='Stop'

# Ensure this is the PDC
$domain = Get-ADDomain
$pdc = $domain.PDCEmulator
if ($env:COMPUTERNAME -ne $pdc){
  Write-Warning "This server is not the PDC Emulator ($pdc). Run on the PDC."
  return
}
$peers = ($NtpServers -join ' ')
w32tm /config /manualpeerlist:$peers /syncfromflags:manual /reliable:yes /update | Out-Null
Stop-Service w32time
Start-Service w32time
w32tm /resync /force
Write-Host "PDC configured to use: $peers"
