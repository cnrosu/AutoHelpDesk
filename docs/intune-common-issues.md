---
title: Top Intune Troubleshooting Issues
ms.date: 05/19/2025
description: Common Microsoft Intune issues that surface in frontline support engagements and how to approach troubleshooting them.
---
# Top Microsoft Intune Troubleshooting Issues

Microsoft Intune incidents tend to cluster around a core set of enrollment, policy delivery, and compliance problems. The sections below outline the ten issues frontline support teams encounter most often, the typical symptoms, and quick guidance on how to triage each scenario.

## 1. Device cannot connect to Intune service
- **Symptoms**: Company Portal or Settings app shows "Cannot connect" or repeatedly prompts to sign in; device status in admin center is "Not evaluated".
- **Likely causes**: Expired Azure AD token, conditional access blocking device registration, device clock skew.
- **Triage tips**: Verify Azure AD sign-in logs for conditional access failures, sync device time, clear Company Portal cache, and re-run `dsregcmd /status` to confirm device is Azure AD joined.

## 2. Enrollment hangs during Autopilot or Company Portal flow
- **Symptoms**: Autopilot deployment stops at the enrollment status page (ESP) or Company Portal never finishes onboarding.
- **Likely causes**: Required apps stuck installing, Win32 app detection rule mismatch, Enrollment Status Page timing out.
- **Triage tips**: Review Intune Management Extension (IME) logs in `C:\ProgramData\Microsoft\IntuneManagementExtension\Logs`, confirm required apps succeed manually, and use Autopilot deployment report for error codes.

## 3. Device enrolled in Autopilot but missing from Intune
- **Symptoms**: Hardware hash imported and shows assigned profile, but device never appears in Intune device list.
- **Likely causes**: Device registered with different tenant, hash uploaded without tenant assignment, sync delays beyond 15 minutes.
- **Triage tips**: Confirm hardware hash matches device serial, verify enrollment token on device, and use `Get-AutopilotDevice` (Graph API or PowerShell) to check assignment state.

## 4. Configuration profiles not applying
- **Symptoms**: Policy shows "Pending" or "Not applicable" in admin center; settings remain unchanged on device.
- **Likely causes**: Scope tags limiting assignment, incorrect targeting (user vs. device), or platform mismatch.
- **Triage tips**: Validate assignment groups, review `DeviceManagement-Enterprise-Diagnostics-Provider` event log, and force sync from Company Portal or `Settings > Accounts > Access work or school`.

## 5. Compliance policies stuck in "Not evaluated"
- **Symptoms**: Device compliance state remains "Not evaluated" or "Unknown"; conditional access blocks access.
- **Likely causes**: Device last check-in beyond 7 days, compliance policy targeting conflict, IME service stopped.
- **Triage tips**: Confirm device check-in time, restart Intune Management Extension service, and review `DeviceComplianceOrg` event log channel for error 5008/5009 entries.

## 6. App installations failing or stuck
- **Symptoms**: Managed apps in Company Portal report installation failed (0x87D1041C, 0x87D13B9F) or remain in "Install pending".
- **Likely causes**: Content download blocked by firewall/proxy, detection rule mismatch, required dependency missing.
- **Triage tips**: Check `IntuneManagementExtension.log` and `AgentExecutor.log`, manually download installer using same network path, and validate detection logic on a healthy device.

## 7. Windows Update for Business policies not taking effect
- **Symptoms**: Update deferrals ignored, devices install updates outside maintenance window, WUfB reports "Not applicable".
- **Likely causes**: Conflicting Group Policy, co-management workloads pointing Windows Update to Configuration Manager, device using WSUS.
- **Triage tips**: Run `gpresult /h` to confirm no legacy policies override, check co-management slider in Configuration Manager, and review `WindowsUpdate.log` for policy source.

## 8. Compliance conflicts between policies
- **Symptoms**: Admin center shows "Conflict" status on compliance policy; device marked non-compliant despite meeting requirements.
- **Likely causes**: Multiple compliance policies targeting same setting with different thresholds, user/device scope overlap.
- **Triage tips**: Consolidate requirements into fewer policies, ensure mutually exclusive targeting groups, and re-evaluate compliance after forcing sync.

## 9. Conditional Access blocking Intune enrollment
- **Symptoms**: Enrollment wizard displays "Your sign-in was blocked" or CA policy violation; device never registers.
- **Likely causes**: CA policy requires compliant device for registration, unsupported platform blocked by design.
- **Triage tips**: Review Azure AD sign-in logs for policy evaluation results, temporarily exclude enrollment users to allow registration, and adjust CA policy to permit initial device registration.

## 10. Reporting delays and stale device status
- **Symptoms**: Device inventory shows outdated compliance or configuration data; last check-in older than expected.
- **Likely causes**: Devices powered off, MDM agent service stopped, network restrictions preventing check-in.
- **Triage tips**: Confirm device connectivity, restart `Microsoft Intune Management Extension` and `Microsoft Edge Update Service (Intune)` services, and initiate manual sync via Company Portal.

> [!TIP]
> For each scenario, Microsoft publishes detailed log locations in the [Intune troubleshooting documentation](https://learn.microsoft.com/mem/intune/fundamentals/troubleshoot) that can help you correlate error codes with remediation steps.

