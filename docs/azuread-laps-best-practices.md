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

## Answering the Original Questions

- **Does LAPS/PLAP apply?** Yes. LAPS (or equivalent automated rotation) is still recommended even on Azure AD joined, Intune-managed devices whenever any local admin credential could persist.
- **What should be done?** Implement Windows LAPS policy through Intune, minimize permanent admin membership, and ensure any remaining local admin passwords are rotated and escrowed.
- **Is Windows Hello enough?** No. Biometric sign-in secures user authentication but does not rotate or escrow local admin passwords; it should be layered with LAPS or just-in-time admin solutions.

## Summary for Technicians

Missing LAPS/PLAP on Azure AD joined endpoints leaves standing local admin credentials unrotated, which attackers can reuse across devices; deploy Windows LAPS or document equally strong rotation controls to close this gap.
