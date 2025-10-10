## Summary
AutoHelpDesk flags BitLocker volumes that lack recovery password protectors and measured boot payloads that omit PCR binding data, because both gaps prevent reliable recovery and attestation. This guide explains the signals the analyzers consume and how technicians can reproduce the checks on an endpoint. Following these steps validates whether the alerts reflect real configuration gaps or collector issues.

## Signals to Collect
- `Get-BitLockerVolume -MountPoint 'C:' | Select-Object -ExpandProperty KeyProtector | Select-Object KeyProtectorId, KeyProtectorType, AutoUnlockEnabled` → Enumerate protectors and confirm a recovery password exists.
- `manage-bde -protectors -get C:` → Capture the CLI view that surfaces **Numerical Password** entries.
- `Get-BitLockerVolume -MountPoint 'C:' | Select-Object -ExpandProperty KeyProtector | Where-Object { $_.KeyProtectorType -match 'TPM' } | Select-Object KeyProtectorType, PcrBinding, PcrHashAlgorithm` → Inspect PCR binding data for measured boot.
- `Get-Content (Join-Path $folder 'Security/measured-boot.json')` → Review the collector artifact to confirm PCR data was captured.

## Detection Rule
- Emit **high severity** when no BitLocker volume exposes a recovery password or numerical password protector.
- Emit an **informational** card when the measured boot artifact lacks PCR binding data for all TPM protectors.
- Document evidence with the raw protector list or measured boot payload whenever the collector fails or returns empty sets.

## Heuristic Mapping
- `Security.BitLocker`
- `Security.MeasuredBoot`

## Remediation
1. Add a BitLocker recovery password protector to each protected volume (`Add-BitLockerKeyProtector -MountPoint 'C:' -RecoveryPasswordProtector`).
2. Escrow the recovery password in the approved directory service or key vault and confirm rotation policies match corporate standards.
3. Reconfigure TPM-based protectors to bind the expected PCR set (e.g., `Set-BitLockerVolume -MountPoint 'C:' -TPMProtector`) if measured boot data is absent.
4. Re-run the AutoHelpDesk collectors to verify the recovery protector and PCR bindings now appear in the payloads.

## References
- `docs/bitlocker-verification.md`

# Verifying BitLocker Recovery and Measured Boot Evidence

This guide shows how the AutoHelpDesk security analyzers decide when to flag
BitLocker recovery and measured boot issues, and how you can manually confirm
those findings on a Windows endpoint.

## Why the "no recovery password" issue appears

The BitLocker heuristic reviews every volume returned by `Get-BitLockerVolume`.
The card *"No BitLocker recovery password protector detected"* is raised when
no volume exposes a key protector that contains either a **Recovery Password**
or a **Numerical Password** entry. These labels cover the two strings emitted by
PowerShell (`RecoveryPassword`) and the `manage-bde` CLI (`Numerical Password`).
If neither string is present, the analyzer assumes a recovery key is missing and
warns that the device could be permanently locked if recovery is required.

### Manual verification

Run the following commands from an elevated PowerShell session to review the
protectors for the system drive (replace `C:` if your OS volume uses a different
letter):

```powershell
# Enumerate all protectors for the OS volume
Get-BitLockerVolume -MountPoint 'C:' | Select-Object -ExpandProperty KeyProtector |
    Select-Object KeyProtectorId, KeyProtectorType, AutoUnlockEnabled

# Show the raw output the analyzer receives
Get-BitLockerVolume -MountPoint 'C:' | Format-List *

# Alternative view that matches "Numerical Password" strings
manage-bde -protectors -get C:
```

Confirm that at least one protector reports either a `KeyProtectorType` of
`RecoveryPassword`, a friendly name that includes **Numerical Password**, or a
`RecoveryPasswordId` value. If any of those indicators are present, the analyzer
records the recovery password as available.

## Why the measured boot info card appears

The measured boot collector queries PCR binding data for each BitLocker
protector. The informational card *"BitLocker PCR binding data unavailable, so
boot integrity attestation cannot be confirmed."* is raised when none of the
protectors return a `PcrBinding` list. This typically happens on systems where
TPM-based protectors are not bound to PCRs or when firmware/OS versions omit the
binding details.

### Manual verification

Use these commands to check what the collector gathered. Replace `$folder` with
the root folder that contains your collected JSON (for example, the path output
by `Device-Report.ps1`, where the `Security\measured-boot.json` file lives):

```powershell
# Dump protector PCR bindings (if available)
Get-BitLockerVolume -MountPoint 'C:' | Select-Object -ExpandProperty KeyProtector |
    Where-Object { $_.KeyProtectorType -match 'TPM' } |
    Select-Object KeyProtectorType, PcrBinding, PcrHashAlgorithm

# Review the measured boot collector output directly (JSON file)
$folder = "C:\\Users\\Me\\Desktop\\DiagReports\\20240915_132233"
Get-Content (Join-Path $folder 'Security/measured-boot.json')
```

If `PcrBinding` is empty for all TPM protectors, AutoHelpDesk cannot confirm the
set of PCRs that guard the boot chain, so the informational card remains. If the
bindings are populated, the analyzer will surface a normal card confirming the
captured PCR data.
