# OneDrive sync health

## Overview
The OneDrive cloud analyzer helps technicians confirm whether Microsoft 365 file sync is available on a device. It pairs the `cloud-onedrive.json` payload with account and policy context so report consumers understand how local state maps to expected cloud behavior. The guidance below reflects the current OneDrive sync client (24.x) baseline that assumes Known Folder Move (KFM)—now branded as Known Folder Backup—and Files On-Demand (FOD) are enabled together so end-user files stay protected without exhausting disk space.

## Collector signals
Run [`Collectors/Cloud/Collect-OneDrive.ps1`](../Collectors/Cloud/Collect-OneDrive.ps1) in the signed-in user context so HKCU registry data, account folders, and live processes are readable. The collector records installation source, version, auto-start triggers, running state, signed-in accounts, and Known Folder Move (KFM) policies so downstream rules can pinpoint missing prerequisites. Current builds surface `OneDrive.exe /status` output, the `UserSettingTenantId` registry value, and the `KfmConsentOptIn` policy flag so technicians can confirm the 24.x client is enforcing the tenant that owns KFM and Files On-Demand. When OneDrive is absent or the module cannot be loaded, the payload captures error text instead of silently failing.

## Client and policy expectations
OneDrive 24.x treats KFM and FOD as table stakes, so the analyzer expects redirected Desktop/Documents/Pictures libraries and placeholders for files not cached locally. When `OneDrive.exe /status` reports healthy sync for the tenant listed in `UserSettingTenantId`, technicians can rely on Files On-Demand to hydrate only the data in use. If `KfmConsentOptIn` is missing or disabled, the analyzer highlights the gap because users will see legacy folders left unmanaged, leading to data loss risk if the device fails.

## Business account health and enforcement
Business sign-in relies on ADAL or MSAL tokens, so the analyzer checks that the work account appears under the `Business` section of `OneDrive.exe /status` output. A missing or expired work token means SharePoint and Teams document libraries stop syncing, which prevents collaborative edits from reaching Microsoft 365. Office cloud policy can enforce KFM, and the analyzer notes when policies from the tenant identified by `UserSettingTenantId` apply so admins know if central controls override local preferences.

## Analyzer outcomes
`Invoke-CloudHeuristics` calls `Invoke-OneDriveHeuristic` to emit impact-focused cards in the **Cloud \ OneDrive** section of the HTML report. The analyzer raises warnings when collection gaps make sync posture unknown, medium issues when the client is missing or stopped, low issues when auto-start is disabled, and informational notices when policy blocks personal sync. It records normal findings when OneDrive is installed, running, and protecting desktop folders via Known Folder Move (KFM) so technicians can trust that files reach Microsoft 365 storage.

## Troubleshooting gaps
If the analyzer reports unknown OneDrive health, confirm the collector was run after the user signed in and that antivirus or application control policies allow the module to load. Re-run the collector, then feed the refreshed output back into the analyzer to verify the updated sync state.

## Checklist
- Confirm Known Folder Move (KFM, now branded as Known Folder Backup) is enabled so Desktop, Documents, and Pictures redirect to OneDrive without manual intervention.
- Verify Files On-Demand is active so the client keeps placeholders for cloud-only content and conserves disk space.
- Make sure the OneDrive client is signed in with the user’s business account and `OneDrive.exe /status` reports the tenant expected in `UserSettingTenantId`.
- Check that KFM policy enforcement matches tenant requirements, including any Office cloud policy that manages `KfmConsentOptIn` for this device.
