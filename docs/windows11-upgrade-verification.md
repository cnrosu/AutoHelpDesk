# Windows 11 upgrade verification commands
Technicians can run these PowerShell commands on an affected device to confirm whether raw telemetry matches the upgrade readiness analyzer. Each section explains how to gather the evidence AutoHelpDesk expects and how to interpret the output. Run the commands in an elevated PowerShell session when possible. The current release is Windows 11 24H2, so confirm devices meet its stricter CPU rules when documenting readiness.

## Check CPU support
Use the first command to capture the model strings exactly as Windows reports them. Dot-source the analyzer script so you can reuse the same normalization logic and lookup table that AutoHelpDesk uses. Microsoft updates the supported processor catalog over time, so reload it before testing against Windows 11 22H2, 23H2, or 24H2. Windows 11 24H2 also enforces POPCNT and SSE4.2 instructions on some older CPU families, so note the requirement if a model falls out of compliance. Then test whether the CPU appears in the supported catalog.
```powershell
Get-CimInstance -ClassName Win32_Processor | Select-Object -ExpandProperty Name
. "C:\\ProgramData\\AutoHelpDesk\\Analyzers\\Heuristics\\System\\Windows11Upgrade.ps1"
Initialize-Windows11CpuCatalog
$cpuName = (Get-CimInstance -ClassName Win32_Processor | Select-Object -First 1 -ExpandProperty Name)
$normalized = Normalize-Windows11CpuName -Name $cpuName
$catalog = $script:Windows11CpuCatalogLookup
$normalized
$catalog.ContainsKey($normalized)
```
A `True` result confirms the CPU model is considered supported after normalization.

## Confirm firmware mode and Secure Boot
Check the firmware mode reported by `systeminfo`, then validate Secure Boot directly through firmware. A `BIOS Mode` of `UEFI` or a `True` value from `Confirm-SecureBootUEFI` should satisfy the analyzer after the latest fixes.
```powershell
systeminfo | Select-String -SimpleMatch "BIOS Mode"
Confirm-SecureBootUEFI
```
If `Confirm-SecureBootUEFI` throws an error, capture the full message because the analyzer now surfaces that text whenever it cannot confirm UEFI support.

## Validate TPM 2.0
`Get-Tpm` returns the presence, readiness, and version fields AutoHelpDesk checks. Ensure `TpmPresent`, `TpmReady`, `TpmEnabled`, and `TpmActivated` all read `True`, and confirm the `SpecVersion` string contains `2.0`.
```powershell
Get-Tpm
```
Collect the output for escalation if any property is `False` or missing.

## Confirm Windows edition
Verifying the OS edition eliminates false upgrade-path failures once a device already runs Windows 11. The following command shows the caption and build version recorded in diagnostics.
```powershell
Get-CimInstance -ClassName Win32_OperatingSystem | Select-Object Caption, Version
```
Record the caption value in your ticket notes and note whether the build is 22H2, 23H2, or 24H2 to document that the device is already on Windows 11.

## Evidence checklist
Use this checklist to confirm the ticket captures every data point the analyzer expects.
- Capture the CPU model string and normalized lookup result.
- Save the catalog membership test output.
- Document firmware mode and Secure Boot status.
- Collect the complete `Get-Tpm` output with version details.
- Record build: 22H2/23H2/24H2.
