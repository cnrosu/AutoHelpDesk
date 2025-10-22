---
title: LAPS and Password Rotation Guidance for Entra Joined Devices
ms.date: 2025-05-15
description: Best practices for using LAPS or compensating password-rotation controls on Entra joined Windows devices managed with Intune.
---
## Summary
Entra joined endpoints still maintain local administrator accounts, so static credentials remain a lateral-movement risk without automated rotation. This doc explains why Windows LAPS (or equivalent tooling) must remain in scope for cloud-managed devices and how to justify compensating controls when LAPS cannot be deployed. Applying the guidance keeps AutoHelpDesk heuristics satisfied and reduces credential-reuse exposure.

## Signals to Collect
- `Get-LocalUser -Name "Administrator"` (or targeted admin account) → Confirm the local admin account exists when policy requires rotation coverage.
- `Get-WinEvent -LogName "Microsoft-Windows-LAPS/Operational" -MaxEvents 200` → Parse rotation timestamps and password read operations for audit analysis.
- `Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Policies\LAPS'` → Read policy values (e.g., `PasswordAgeDays`, complexity settings) to confirm rotation interval and enforcement.

## Detection Rule
- **RotationStale (High):** Flag when the time since the last successful password rotation exceeds **RotationDaysThreshold = 30** days.
- **PasswordReadSpike (High):** Flag when password read events exceed **ReadSpike24h = 5** within a 24-hour window or **ReadSpike72h = 10** within a 72-hour window.
- **PolicyMissing (Medium):** Flag when required LAPS policy registry values (e.g., `PasswordAgeDays`, backup directory) are absent on devices expected to enforce rotation.

## Heuristic Mapping
- `Security/LAPS/RotationStale`
- `Security/LAPS/PasswordReadSpike`
- `Security/LAPS/PolicyMissing`

## Remediation
1. Enforce the Windows LAPS rotation policy so every managed local admin account rotates automatically on a ≤30-day cadence.
2. Limit password read permissions to least-privileged roles and investigate any abnormal read spikes in the LAPS operational log.
3. Trigger an immediate password rotation for accounts with stale secrets and verify the updated timestamp in the collector output.
4. Review the LAPS audit trail and registry policy values to confirm policy presence; document compensating controls if enforcement is not possible.

## References
- `docs/azuread-laps-best-practices.md`

# LAPS and Password Rotation Guidance for Entra Joined Devices

Joining devices to Entra ID and managing them with Intune do not automatically provide per-device password rotation for local administrator accounts.
Organizations that rely on static or manually managed local admin credentials should still deploy Windows LAPS (or equivalent controls) to prevent password reuse risks flagged by credential management analyzers.

## Why LAPS Still Matters on Entra Joined Devices

- **Local administrators still exist.** Entra ID device administrators, break-glass local accounts, and users manually added to the local *Administrators* group all receive local admin rights even on cloud-only devices.
- **Static passwords remain exploitable.** Without a rotation mechanism, any local account with admin rights can be harvested and reused across machines, enabling lateral movement.
- **Analyzer expectations.** AutoHelpDesk raises a high-severity issue when it cannot see LAPS/PLAP footprints because static credentials remain an unmanaged risk.

## Recommended Controls for the Scenario Described

1. **Deploy Windows LAPS where possible.** Configure Windows LAPS policy via Intune to rotate the built-in Administrator (or a custom local admin) password on a defined cadence and escrow secrets in Microsoft Entra ID.
2. **Scope local admin membership tightly.** Keep day-to-day users out of the *Administrators* group. Instead, require just-in-time elevation (e.g., Endpoint Privilege Management or local admin password on demand).
3. **Rotate any standing local admin credentials.** If business requirements demand a permanent local admin (for break-glass or support), store its password in a managed vault and rotate it at least every 30 days—more frequently if feasible.
4. **Enable auditing and alerting.** Monitor Entra ID sign-ins for Device Administrator assignments and track local group changes to detect drift that would reintroduce unmanaged admins.
5. **Document compensating controls when LAPS cannot be deployed.** If you rely solely on Windows Hello for Business, Conditional Access, or Privileged Identity Management, record how those controls prevent password reuse and include justification for audit purposes.

### Data sources collected

- **Windows LAPS policy keys:** `HKLM\SOFTWARE\Policies\Microsoft\Windows\LAPS` and `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\LAPS\State` expose whether password backup is enabled, where secrets are escrowed, and rotation cadence values.
- **Legacy AdmPwd/LAPS policy keys:** `HKLM\SOFTWARE\Policies\Microsoft Services\AdmPwd` reveals whether the legacy Group Policy-based solution is deployed.
- **Local Administrators group inventory:** The collector enumerates membership plus per-account metadata such as whether a local user is enabled, has `PasswordNeverExpires`, and the timestamp of `LastPasswordSet`.

These artifacts are bundled into the `laps_localadmin` analyzer payload that the `Security.CredentialPolicies` heuristic consumes.

### Interpretation logic

- The heuristic marks **LAPS/PLAP as deployed** when any collected policy shows an enabled flag (`*Enabled = 1`) or a populated backup directory (Entra ID, Active Directory, or custom key escrow) indicating passwords are being rotated and escrowed.
- When no policy keys are present or all enabled flags are unset, the heuristic raises a **high-severity** issue titled **"LAPS/PLAP not detected, allowing unmanaged or reused local admin passwords."** The evidence section mirrors the raw registry values to help confirm whether policies are missing or simply misconfigured.
- Separate security heuristics review the administrator inventory. If a standing local admin exists without rotation controls or its `LastPasswordSet` is stale, those checks emit additional medium/high findings to highlight the persistent account risk.

### Issue card mapping

| Issue card title | Triggering data | Impact statement | Remediation guidance |
| --- | --- | --- | --- |
| **LAPS/PLAP not detected, allowing unmanaged or reused local admin passwords.** | No Windows LAPS or legacy AdmPwd policy shows an enabled flag or backup target. | Attackers who capture a static local admin password can reuse it across devices to gain full control. | Deploy Windows LAPS via Intune or re-enable the legacy AdmPwd policy so administrator passwords rotate and are escrowed in Microsoft Entra ID or Active Directory. |
| **Local admin risk: No rotation/escrow control. Standing local admin detected; no LAPS/PAM and password appears persistent.** | Local Administrators inventory finds an enabled local account with `PasswordNeverExpires` or a stale `LastPasswordSet`, and no rotation tooling is detected. | A local admin account that never changes its password gives attackers a long-lived backdoor on every device where it exists. | Remove the standing account if possible, or pair it with Windows LAPS/privileged access management that rotates the password on a defined schedule. |
| **Local admin risk: No rotation/escrow control. Standing local admin detected; no LAPS/PAM but password not stale.** | Local admin exists and lacks rotation tooling, though `LastPasswordSet` is recent. | Even a recently changed local admin password can be harvested and reused until it rotates automatically. | Keep the account only if required, and enforce automatic rotation using LAPS or a privileged access platform. |
| **Local admin present: LAPS/PAM in place. Rotation/escrow control detected (Windows LAPS/AdmPwd or PAM/JIT).** | A local admin is present but LAPS or another rotation control is detected. | When rotation controls run correctly, a standing admin account has far less chance of being reused by attackers. | Monitor LAPS health and ensure escrow destinations remain reachable so password rotations continue without failure. |


## Answering the Original Questions

- **Does LAPS/PLAP apply?** Yes. LAPS (or equivalent automated rotation) is still recommended even on Entra joined, Intune-managed devices whenever any local admin credential could persist.
- **What should be done?** Implement Windows LAPS policy through Intune, minimize permanent admin membership, and ensure any remaining local admin passwords are rotated and escrowed.
- **Is Windows Hello enough?** No. Biometric sign-in secures user authentication but does not rotate or escrow local admin passwords; it should be layered with LAPS or just-in-time admin solutions.

## Summary for Technicians

Missing LAPS/PLAP on Entra joined endpoints leaves standing local admin credentials unrotated, which attackers can reuse across devices; deploy Windows LAPS or document equally strong rotation controls to close this gap.
