<#
.SYNOPSIS
  Sets the domain PDC Emulator to sync with external NTP servers and restarts the time service.
.DESCRIPTION
  Confirms the script is running on the PDC Emulator, updates the manual peer list to the provided NTP servers, marks the
  clock as reliable, restarts the Windows Time service, and forces a resynchronization.
.PARAMETER NtpServers
  Specifies the NTP servers to configure. Each entry should include optional flags (for example, ",0x9"). Defaults to a
  pair of publicly available time sources.
.EXAMPLE
  PS C:\> .\Set-PDC-TimeSource.ps1 -NtpServers 'time.nist.gov,0x8','pool.ntp.org,0x8'

  Configures the local PDC Emulator to sync with the provided time servers and restarts the Windows Time service.
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
