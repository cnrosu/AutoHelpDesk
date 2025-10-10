## Summary
AutoHelpDesk’s Microsoft Store heuristic reviews package presence, licensing services, network reachability, and diagnostic output to determine whether the storefront is functional. This checklist gives technicians a consistent order of operations to gather evidence and remediate issues without unnecessary reinstalls. Applying the steps also satisfies analyzer requirements for Store troubleshooting artifacts.

## Signals to Collect
- `Get-AppxPackage -AllUsers Microsoft.WindowsStore | Select-Object Name, Version, Status` → Confirm the Store package is installed and healthy.
- `Get-Service -Name ClipSVC, wlidsvc, DoSvc, bits, wuauserv | Select-Object Name, Status, StartType` → Validate dependent services.
- `Test-NetConnection -ComputerName storeedgefd.dsx.mp.microsoft.com -Port 443` → Check CDN connectivity.
- `& "$Env:SystemRoot\System32\StoreDiag.exe" /report "$Env:USERPROFILE\Desktop\StoreDiagReport"` → Generate the Microsoft Store diagnostic report for evidence.

## Detection Rule
- Mark the Store as **not applicable** when the package and AppXSVC service are absent on the SKU.
- Raise **high severity** when the package is missing, the manifest path is inaccessible, or multiple core services fail health checks.
- Raise **medium severity** when connectivity tests fail for Store endpoints or the WinHTTP proxy blocks access.
- Emit a **normal** card when all functional checks succeed, attaching the summarized evidence list.

## Heuristic Mapping
- `System.MicrosoftStore`

## Remediation
1. Reinstall or re-register the Microsoft Store package for all users if the package is missing or corrupted.
2. Start required services (ClipSVC, wlidsvc, BITS, Windows Update, Delivery Optimization) and set their startup types per Microsoft guidance.
3. Resolve connectivity blockers by updating proxy/firewall rules or fixing TLS inspection issues for Store endpoints.
4. Run Store diagnostics (`StoreDiag.exe`, `wsreset.exe`) and address any cache or licensing errors reported.
5. Document findings and rerun AutoHelpDesk collectors to confirm the Store functional check passes.

## References
- `docs/microsoft-store-diagnostics.md`

# Comprehensive Microsoft Store Health Checks

This playbook collects the most reliable ways to confirm the Microsoft Store is
healthy or to pinpoint what is blocking it on Windows 10 and Windows 11
endpoints. Work through the sections in order: each builds evidence so you can
rule out platform-wide outages, account problems, and local corruption before
resorting to reinstalls.

## 1. Confirm the Microsoft Store service stack is running

| Component | Why it matters | How to verify |
|-----------|----------------|---------------|
| **Microsoft Store (AppX)** | The Store itself and its dependencies must be installed for all users. | Run an elevated PowerShell session and execute:<br/>```powershell
Get-AppxPackage -AllUsers Microsoft.WindowsStore | Select-Object Name, Version, Status
```
Healthy systems return a row with `Status` blank or `Ok`. A missing row indicates the Store was removed (common on heavily debloated images), while an error in the `Status` column signals package corruption.
| **ClipSVC (Client License Service)** | Handles Store licensing. If it is disabled the Store opens but downloads fail with licensing errors. | In PowerShell run:<br/>```powershell
Get-Service -Name ClipSVC, wlidsvc | Select-Object Name, Status, StartType
```
`wlidsvc` (Microsoft Account Sign-in Assistant) should be `Running`. `ClipSVC` is demand-start and often reports `Stopped` while the Store is idle; that is healthy so long as its `StartType` is `Manual` or `Automatic`. If it refuses to start with `Start-Service ClipSVC`, record the error and re-register the Store package.
| **Windows Update & Delivery Optimization** | Store apps use Windows Update infrastructure. Stopped update services cause Store download failures. | Check:<br/>```powershell
Get-Service -Name wuauserv, bits, DoSvc | Select-Object Name, Status, StartType
```
All services must be running. Restart them if they are stuck in `Stopping`.
| **System time, region, and SSL** | Incorrect clock or region breaks secure channel handshakes. | Run:<br/>```powershell
Get-Service W32Time
w32tm /query /status
Get-Date
Get-WinSystemLocale
```
Azure AD-joined devices often have the **Windows Time** service stopped; that is expected if `Get-Service W32Time` shows a `Disabled` start type. In that case, compare `Get-Date` with a reliable time source or the **Settings > Time & language** pane. Whatever the configuration, the clock must be accurate and the locale should match the user's Microsoft account region.

## 2. Rule out Microsoft-side outages

1. Visit <https://support.microsoft.com/en-us/service-status> or, if you have
   Microsoft 365 admin rights, review the **Service health** dashboard for
   Store-related advisories.
2. From any browser, navigate to <https://apps.microsoft.com> and sign in with the
   affected account. If the site reports issues, wait for the service incident to
   resolve before touching the device.

## 3. Validate account health

1. Ask the user to sign out of the Microsoft Store app (profile icon > **Sign
   out**) and sign back in.
2. Confirm the Microsoft account can authenticate at <https://account.microsoft.com>.
   Store sign-in relies on the same token providers.
3. In PowerShell, inspect Web Account Manager (WAM) status:

   ```powershell
   Get-WebAccount -AllAccounts | Where-Object { $_.Application -match 'Store' }
   ```

   If no accounts appear, WAM is not storing the Store token; sign-in will fail
   until the account is re-added or WAM is repaired.

## 4. Check connectivity and content delivery

1. Run the built-in network tests:

   ```powershell
   Test-NetConnection -ComputerName storeedgefd.dsx.mp.microsoft.com -Port 443
   ```

   Successful TLS handshake proves the device can reach the Store CDN. If the test fails, capture the output and log an issue such as **"Microsoft Store CDN unavailable"** so downstream technicians understand that content delivery, not the Store app, is at fault.
2. If the device uses a proxy or firewall, review the rules against Microsoft's
   published endpoints (`*.microsoft.com`, `*.msedge.net`, `*.akamaized.net`).
3. On managed networks, confirm SSL inspection is disabled for the Store CDN. If
   inspection is mandatory, ensure the device trusts the inspection root
   certificate.

## 5. Use built-in diagnostics and troubleshooters

1. Launch the **Windows Store Apps** troubleshooter (Settings > System >
   Troubleshoot > Other troubleshooters). Record any fixes it applies.
2. Run the hidden Microsoft Store diagnostic tool:

   ```powershell
   & "$Env:SystemRoot\System32\StoreDiag.exe" /report "$Env:USERPROFILE\Desktop\StoreDiagReport"
   ```

   Review the generated HTML report for store cache, licensing, or service
   warnings. It also validates background intelligent transfer service (BITS)
   jobs.
3. Flush the Store cache with `wsreset.exe`. A successful run opens the Store
   automatically; if it exits immediately with an error, the cache folder has
   permission problems.

## 6. Inspect application logs

1. Open **Event Viewer** and navigate to **Applications and Services Logs >
   Microsoft > Windows > Store > Operational**. Look for error codes such as
   `0x80131500` (service outage) or `0x80072EFD` (network failure).
2. Check **Microsoft-Windows-AppXDeployment/Operational** for deployment errors
   when installing or updating Store apps.
3. Export the relevant event logs for attachment to support tickets:

   ```powershell
   wevtutil epl Microsoft-Windows-Store/Operational "%USERPROFILE%\Desktop\Store-Operational.evtx"
   ```

## 7. Repair the Store installation (only after evidence gathering)

1. Re-register the Store package for all users:

   ```powershell
   Get-AppxPackage -AllUsers Microsoft.WindowsStore | Foreach-Object {
       Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"
   }
   ```

   If the command errors with `Deployment failed with HRESULT: 0x80073CF6`, run
   DISM repair first.
2. Run system file and component store integrity checks:

   ```powershell
   sfc /scannow
   DISM /Online /Cleanup-Image /RestoreHealth
   ```

   Reboot after both commands finish before re-testing the Store.
3. As a last resort on Windows 11, reinstall the Store package from the Microsoft
   Store repository using `winget`:

   ```powershell
   winget install --id 9WZDNCRFJBMP -s msstore
   ```

   Winget surfaces clearer error codes (proxy failures, licensing blocks) than
   the Store UI.

## 8. Document findings

For every remediation, note the observed behavior before and after the change,
plus any event IDs or error codes. Technicians should include a single sentence
in customer-facing updates describing the impact, for example: *"Microsoft Store
downloads were failing because the Client License Service was stopped, which
prevented license validation."*

Following this checklist ensures you collect consistent evidence and only apply
intrusive fixes (like re-registration or DISM repairs) after verifying the
underlying platform requirements.
