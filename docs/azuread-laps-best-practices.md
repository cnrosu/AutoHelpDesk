---
title: LAPS and Password Rotation Guidance for Azure AD Joined Devices
ms.date: 2025-05-15
description: Best practices for using LAPS or compensating password-rotation controls on Azure AD joined Windows devices managed with Intune.
---
# LAPS and Password Rotation Guidance for Azure AD Joined Devices

Azure AD join and Intune management do not automatically provide per-device password rotation for local administrator accounts.
Organizations that rely on static or manually managed local admin credentials should still deploy Windows LAPS (or equivalent controls) to prevent password reuse risks flagged by credential management analyzers.

## Why LAPS Still Matters on Azure AD Joined Devices

- **Local administrators still exist.** Azure AD device administrators, break-glass local accounts, and users manually added to the local *Administrators* group all receive local admin rights even on cloud-only devices.
- **Static passwords remain exploitable.** Without a rotation mechanism, any local account with admin rights can be harvested and reused across machines, enabling lateral movement.
- **Analyzer expectations.** AutoHelpDesk raises a high-severity issue when it cannot see LAPS/PLAP footprints because static credentials remain an unmanaged risk.

## Recommended Controls for the Scenario Described

1. **Deploy Windows LAPS where possible.** Configure Windows LAPS policy via Intune to rotate the built-in Administrator (or a custom local admin) password on a defined cadence and escrow secrets in Azure AD or Microsoft Entra ID.
2. **Scope local admin membership tightly.** Keep day-to-day users out of the *Administrators* group. Instead, require just-in-time elevation (e.g., Endpoint Privilege Management or local admin password on demand).
3. **Rotate any standing local admin credentials.** If business requirements demand a permanent local admin (for break-glass or support), store its password in a managed vault and rotate it at least every 30 days—more frequently if feasible.
4. **Enable auditing and alerting.** Monitor Azure AD sign-ins for Device Administrator assignments and track local group changes to detect drift that would reintroduce unmanaged admins.
5. **Document compensating controls when LAPS cannot be deployed.** If you rely solely on Windows Hello for Business, Conditional Access, or Privileged Identity Management, record how those controls prevent password reuse and include justification for audit purposes.

## How AutoHelpDesk Evaluates LAPS Coverage

### Data sources collected

- **Windows LAPS policy keys:** `HKLM\SOFTWARE\Policies\Microsoft\Windows\LAPS` and `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\LAPS\State` expose whether password backup is enabled, where secrets are escrowed, and rotation cadence values.
- **Legacy AdmPwd/LAPS policy keys:** `HKLM\SOFTWARE\Policies\Microsoft Services\AdmPwd` reveals whether the legacy Group Policy-based solution is deployed.
- **Local Administrators group inventory:** The collector enumerates membership plus per-account metadata such as whether a local user is enabled, has `PasswordNeverExpires`, and the timestamp of `LastPasswordSet`.

These artifacts are bundled into the `laps_localadmin` analyzer payload that the `Security.CredentialPolicies` heuristic consumes.

### Interpretation logic

- The heuristic marks **LAPS/PLAP as deployed** when any collected policy shows an enabled flag (`*Enabled = 1`) or a populated backup directory (Azure AD, Active Directory, or custom key escrow) indicating passwords are being rotated and escrowed.
- When no policy keys are present or all enabled flags are unset, the heuristic raises a **high-severity** issue titled **"LAPS/PLAP not detected, allowing unmanaged or reused local admin passwords."** The evidence section mirrors the raw registry values to help confirm whether policies are missing or simply misconfigured.
- Separate security heuristics review the administrator inventory. If a standing local admin exists without rotation controls or its `LastPasswordSet` is stale, those checks emit additional medium/high findings to highlight the persistent account risk.

### Issue card mapping

| Issue card title | Triggering data | Impact statement | Remediation guidance |
| --- | --- | --- | --- |
| **LAPS/PLAP not detected, allowing unmanaged or reused local admin passwords.** | No Windows LAPS or legacy AdmPwd policy shows an enabled flag or backup target. | Attackers who capture a static local admin password can reuse it across devices to gain full control. | Deploy Windows LAPS via Intune or re-enable the legacy AdmPwd policy so administrator passwords rotate and are escrowed in Azure AD/Entra or Active Directory. |
| **Local admin risk: No rotation/escrow control. Standing local admin detected; no LAPS/PAM and password appears persistent.** | Local Administrators inventory finds an enabled local account with `PasswordNeverExpires` or a stale `LastPasswordSet`, and no rotation tooling is detected. | A local admin account that never changes its password gives attackers a long-lived backdoor on every device where it exists. | Remove the standing account if possible, or pair it with Windows LAPS/privileged access management that rotates the password on a defined schedule. |
| **Local admin risk: No rotation/escrow control. Standing local admin detected; no LAPS/PAM but password not stale.** | Local admin exists and lacks rotation tooling, though `LastPasswordSet` is recent. | Even a recently changed local admin password can be harvested and reused until it rotates automatically. | Keep the account only if required, and enforce automatic rotation using LAPS or a privileged access platform. |
| **Local admin present: LAPS/PAM in place. Rotation/escrow control detected (Windows LAPS/AdmPwd or PAM/JIT).** | A local admin is present but LAPS or another rotation control is detected. | When rotation controls run correctly, a standing admin account has far less chance of being reused by attackers. | Monitor LAPS health and ensure escrow destinations remain reachable so password rotations continue without failure. |

## Answering the Original Questions

- **Does LAPS/PLAP apply?** Yes. LAPS (or equivalent automated rotation) is still recommended even on Azure AD joined, Intune-managed devices whenever any local admin credential could persist.
- **What should be done?** Implement Windows LAPS policy through Intune, minimize permanent admin membership, and ensure any remaining local admin passwords are rotated and escrowed.
- **Is Windows Hello enough?** No. Biometric sign-in secures user authentication but does not rotate or escrow local admin passwords; it should be layered with LAPS or just-in-time admin solutions.

## Summary for Technicians

Missing LAPS/PLAP on Azure AD joined endpoints leaves standing local admin credentials unrotated, which attackers can reuse across devices; deploy Windows LAPS or document equally strong rotation controls to close this gap.
