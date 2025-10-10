---
title: LAPS and Password Rotation Guidance for Azure AD Joined Devices
ms.date: 2025-05-15
description: Best practices for using LAPS or compensating password-rotation controls on Azure AD joined Windows devices managed with Intune.
---
## Summary
Azure AD joined endpoints still maintain local administrator accounts, so static credentials remain a lateral-movement risk without automated rotation. This doc explains why Windows LAPS (or equivalent tooling) must remain in scope for cloud-managed devices and how to justify compensating controls when LAPS cannot be deployed. Applying the guidance keeps AutoHelpDesk heuristics satisfied and reduces credential-reuse exposure.

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
