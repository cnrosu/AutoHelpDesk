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
`Status` is empty on healthy installs. A missing row indicates the Store was
removed (common on heavily debloated images).
| **ClipSVC (Client License Service)** | Handles Store licensing. If it is disabled the Store opens but downloads fail with licensing errors. | In PowerShell run:<br/>```powershell
Get-Service -Name ClipSVC, wlidsvc | Select-Object Name, Status, StartType
```
Both services should report `Running` and `Manual` or `Automatic` start types. If
they are stopped, start them with `Start-Service ClipSVC` and `Start-Service wlidsvc`.
| **Windows Update & Delivery Optimization** | Store apps use Windows Update infrastructure. Stopped update services cause Store download failures. | Check:<br/>```powershell
Get-Service -Name wuauserv, bits, DoSvc | Select-Object Name, Status, StartType
```
All services must be running. Restart them if they are stuck in `Stopping`.
| **System time, region, and SSL** | Incorrect clock or region breaks secure channel handshakes. | Run:<br/>```powershell
w32tm /query /status
Get-WinSystemLocale
```
Ensure the time is synchronized and the locale matches the user's Microsoft
account region.

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

   Successful TLS handshake proves the device can reach the Store CDN.
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
