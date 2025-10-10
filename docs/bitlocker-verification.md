## Summary
AutoHelpDesk verifies that the operating system drive is fully encrypted with BitLocker, protected by a TPM-based key protector, and not repeatedly entering recovery mode. This guide explains the telemetry the analyzers rely on and how technicians can reproduce each check to validate whether alerts represent real risk or collection errors.

## Signals to Collect
- `Get-BitLockerVolume | Select-Object MountPoint, ProtectionStatus, VolumeStatus, KeyProtector` → Capture encryption state, protector status, and available key protectors for every volume.
- `Confirm-SecureBootUEFI` → Verify Secure Boot is enabled when the platform supports UEFI validation.
- `Get-CimInstance -ClassName Win32_Tpm -Namespace root\cimv2\Security\MicrosoftTpm` → Inspect TPM ownership and provisioning information.
- `Get-WinEvent -LogName 'Microsoft-Windows-BitLocker/BitLocker Management' -MaxEvents 200` → Review recent BitLocker recovery and unlock activity for loop detection.

## Detection Rule
- **OSDriveUnprotected (Critical):** Flag when the operating system volume reports `VolumeStatus -ne 'FullyEncrypted'` **or** `ProtectionStatus -ne 'On'`.
- **NoTPMProtector (High):** Flag when the operating system volume lacks any TPM-based key protector entry.
- **RecoveryLoop (Medium):** Flag when three or more BitLocker recovery or unlock events occur within the past 24 hours. Use `RecoveryEvents24hThreshold = 3` as the evaluation threshold.

## Heuristic Mapping
- `Security/BitLocker/OSDriveUnprotected`
- `Security/BitLocker/NoTPMProtector`
- `Security/BitLocker/RecoveryLoop`

## Remediation
1. Enable BitLocker on the operating system drive with TPM protection (add a PIN if required by policy) and confirm Secure Boot plus PCR bindings are active.
2. Ensure TPM ownership is established, key protectors are escrowed to the approved directory service or vault, and policies enforce recovery key backup.
3. Investigate repeated recovery prompts, address underlying hardware or firmware issues, then clear recovery counters by successfully booting without prompts.

## References
- `docs/bitlocker-verification.md`

# Verifying BitLocker OS Drive Protection and Recovery Stability

This section outlines how the AutoHelpDesk analyzers decide when to surface
BitLocker issues around OS drive encryption, TPM usage, and recovery loops, and
how you can confirm those findings on an affected Windows endpoint.

## Investigating "OS drive unprotected" alerts

The OS drive alert triggers whenever `Get-BitLockerVolume` reports that the
system volume is not fully encrypted or the protection status is anything other
than `On`. Without active protection, end users can boot without BitLocker or
may lose data if the drive is lost or stolen.

### Manual verification

Run the following commands from an elevated PowerShell session (replace `C:`
with the correct OS volume if different):

```powershell
# Capture overall BitLocker status for each volume
Get-BitLockerVolume | Select-Object MountPoint, VolumeStatus, ProtectionStatus, EncryptionMethod

# Review Secure Boot state on supported hardware
Confirm-SecureBootUEFI

# Inspect TPM provisioning information
Get-CimInstance -ClassName Win32_Tpm -Namespace root\cimv2\Security\MicrosoftTpm | Format-List *
```

If the OS drive reports `FullyEncrypted` and `ProtectionStatus` shows `On`, the
alert should clear after the next data collection. Any other state indicates the
drive needs remediation.

## Investigating "No TPM protector" alerts

This alert fires when the OS drive lacks a TPM-based key protector. Without a
TPM protector (and optional PIN), attackers could bypass pre-boot checks, or the
device might rely on weaker password-only protectors.

### Manual verification

```powershell
# Enumerate all protectors and locate TPM entries
Get-BitLockerVolume -MountPoint 'C:' | Select-Object -ExpandProperty KeyProtector |
    Select-Object KeyProtectorType, AutoUnlockEnabled, KeyProtectorId
```

Look for protectors with `KeyProtectorType` values such as `Tpm` or `TpmPin`.
If none exist, add a TPM-based protector and ensure it is escrowed before
closing the ticket.

## Investigating "Recovery loop" alerts

AutoHelpDesk counts BitLocker recovery-related events in the
`Microsoft-Windows-BitLocker/BitLocker Management` log. When three or more
events occur in a 24-hour window, the analyzer warns that the device may be
stuck in a recovery loop that leaves users locked out or repeatedly prompted for
the recovery key.

### Manual verification

```powershell
$events = Get-WinEvent -LogName 'Microsoft-Windows-BitLocker/BitLocker Management' -MaxEvents 200 |
    Where-Object { $_.TimeCreated -gt (Get-Date).AddHours(-24) -and $_.Id -in 24620, 24660, 24588 }

$events | Format-Table TimeCreated, Id, LevelDisplayName, Message
"Total recovery/unlock events (24h): $($events.Count)"
```

If the event count meets or exceeds `RecoveryEvents24hThreshold = 3`, collect
the boot history, review firmware updates, and check for hardware changes that
may cause repeated recovery prompts.
