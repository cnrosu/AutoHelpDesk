---
title: LAPS and Password Rotation Guidance for Azure AD Joined Devices
ms.date: 2025-05-15
description: Best practices for using LAPS or compensating password-rotation controls on Azure AD joined Windows devices managed with Intune.
---
## Summary
Azure AD joined endpoints still maintain local administrator accounts, so static credentials remain a lateral-movement risk without automated rotation. This doc explains why Windows LAPS (or equivalent tooling) must remain in scope for cloud-managed devices and how to justify compensating controls when LAPS cannot be deployed. Applying the guidance keeps AutoHelpDesk heuristics satisfied and reduces credential-reuse exposure.

## Signals to Collect
- `Get-LapsAADPassword -DeviceName <DeviceName>` → Confirm Azure AD secret escrow and rotation timestamps.
- `Get-LocalGroupMember -Group Administrators | Select-Object Name, ObjectClass, PrincipalSource` → Inventory local administrators that require rotation.
- `Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Policies\LAPS' | Select-Object BackupDirectory, PasswordAgeDays` → Validate LAPS policy enforcement on the device.

## Detection Rule
- Raise **high severity** when no LAPS/PLAP artifact is found in collector payloads, indicating unmanaged local admin passwords.
- Record a **normal** card when the collector confirms an Intune or Group Policy LAPS configuration with escrow enabled.
- Attach evidence describing missing payloads or stale password timestamps whenever rotation cannot be confirmed.

## Heuristic Mapping
- `Security.CredentialPolicies`

## Remediation
1. Configure Windows LAPS via Intune or Group Policy to rotate the built-in Administrator (or a custom local admin) credential and escrow secrets in Azure AD.
2. Audit the *Administrators* group and remove users or break-glass accounts that do not require standing access.
3. Document compensating controls (e.g., just-in-time elevation, privileged access management) when LAPS deployment is blocked.
4. Re-run AutoHelpDesk collectors to confirm the LAPS artifact now includes rotation metadata.

## References
- `docs/azuread-laps-best-practices.md`

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

## Answering the Original Questions

- **Does LAPS/PLAP apply?** Yes. LAPS (or equivalent automated rotation) is still recommended even on Azure AD joined, Intune-managed devices whenever any local admin credential could persist.
- **What should be done?** Implement Windows LAPS policy through Intune, minimize permanent admin membership, and ensure any remaining local admin passwords are rotated and escrowed.
- **Is Windows Hello enough?** No. Biometric sign-in secures user authentication but does not rotate or escrow local admin passwords; it should be layered with LAPS or just-in-time admin solutions.

## Summary for Technicians

Missing LAPS/PLAP on Azure AD joined endpoints leaves standing local admin credentials unrotated, which attackers can reuse across devices; deploy Windows LAPS or document equally strong rotation controls to close this gap.
