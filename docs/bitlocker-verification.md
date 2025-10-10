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
