## Summary
The Microsoft Defender heuristic compares real-time monitoring, engine status, and companion safeguards to determine which cards to raise. When `RealTimeProtectionEnabled` is false, AutoHelpDesk emits a high-severity alert even if signatures and tamper protection remain healthy. This doc outlines the data sources, evaluation order, and remediation workflow so technicians can quickly restore protection.

## Signals to Collect
- `Get-MpComputerStatus | Select-Object RealTimeProtectionEnabled, AntivirusEnabled, TamperProtectionEnabled, AMServiceEnabled` → Capture the core Defender state flags.
- `Get-MpPreference | Select-Object DisableRealtimeMonitoring, MAPSReporting, SubmitSamplesConsent` → Review policies that may suppress monitoring.
- `Get-MpThreat -ThreatIDDefaultAction Unknown | Select-Object DetectionTime, ThreatName, ActionSuccess` → Confirm recent detections and ensure the engine is operating.

## Detection Rule
- Raise a **high-severity** card when `RealTimeProtectionEnabled` equals `False`.
- Raise a **critical** card when `AntivirusEnabled` equals `False`, indicating the Defender engine is disabled.
- Continue emitting **normal** cards for signatures, tamper protection, and MAPS when their respective checks pass, even if real-time protection fails.

## Heuristic Mapping
- `Security.Defender`

## Remediation
1. Re-enable real-time monitoring via PowerShell (`Set-MpPreference -DisableRealtimeMonitoring $false`) or the Windows Security app.
2. Confirm tamper protection remains on so local users cannot toggle the setting again.
3. Remove or reconfigure conflicting third-party antivirus agents that disable Defender, or reinstall Defender components if corruption is suspected.
4. Run a full `Start-MpScan -ScanType FullScan` to ensure no malware persisted while protection was off.
5. Re-run AutoHelpDesk collectors to verify real-time protection reports `True` and issue cards clear.

## References
- `docs/defender-real-time-protection.md`

# Understanding the "Defender real-time protection disabled" and companion cards

## What the cards are telling you
- **Analyzer**: Security → Microsoft Defender
- **High-severity issue**: **"Defender real-time protection disabled, creating antivirus protection gaps."**
  - Triggered when `Get-MpComputerStatus` reports `RealTimeProtectionEnabled = False`.
- **Critical issue (related but rarer)**: "Defender antivirus engine disabled, creating antivirus protection gaps." — emitted if `AntivirusEnabled = False`.
- **Normal cards**: "Defender cloud-delivered protection enabled", "Defender signatures present (...)" and "Defender tamper protection enabled" surface when their respective configuration checks still pass, even if real-time monitoring is off.

> **Impact (plain English):** When real-time protection is off, Microsoft Defender stops intercepting new files and processes, leaving the machine exposed to fresh malware until a manual or scheduled scan runs.

## Data sources used by the heuristic
- The **Defender collector** (`Collectors/Security/Collect-Defender.ps1`) runs three native cmdlets:
  - `Get-MpComputerStatus` → feeds the analyzer `Status` block, including `RealTimeProtectionEnabled`, `AntivirusEnabled`, `TamperProtectionEnabled`, and signature versions.
  - `Get-MpPreference` → supplies the `Preferences` block the analyzer inspects for tamper protection, MAPS cloud settings, and other policy toggles.
  - `Get-MpThreat` → returns recent detections for the "No recent Defender detections" card.
- The analyzer (`Analyzers/Heuristics/Security/Security.Defender.ps1`) converts those fields into issue/normal cards. Each check is evaluated independently, so one failure (real-time protection) can coexist with multiple passing checks (signatures, MAPS, tamper protection).

## Why good cards can appear next to a high-severity issue
The collector snapshots multiple Defender subsystems at once. Real-time monitoring is controlled by the `RealTimeProtectionEnabled` flag, while signature currency, tamper protection, and cloud-delivered protection have their own independent controls. It is therefore common to see:
- **High**: Real-time protection disabled.
- **Good**: Signatures present and current — because updates are still installing successfully.
- **Good**: Tamper protection enabled — the policy itself remains active even if a local admin disabled real-time scanning temporarily.
- **Good**: Cloud-delivered protection enabled — MAPS reporting and cloud block level are still configured for blocking mode.
These cards describe different aspects of Defender’s configuration, so technicians should treat the high-severity real-time protection finding as actionable even when other safeguards remain in place.

## Typical causes of the high-severity card
- A user or script ran `Set-MpPreference -DisableRealtimeMonitoring $true` (often to install unsigned software) and never re-enabled it.
- Third-party security products turned Defender’s real-time engine off to avoid conflicts, leaving Defender dormant without another AV registered.
- Tamper protection was temporarily relaxed by an administrator or Intune security task, allowing the setting to be toggled off.
- Malware disabled Defender protections before being remediated.

## How to remediate
1. **Re-enable Defender real-time monitoring**
   - From an elevated PowerShell prompt, run `Set-MpPreference -DisableRealtimeMonitoring $false`.
   - In the Windows Security app, go to **Virus & threat protection → Manage settings** and toggle **Real-time protection** back on.
2. **Confirm tamper protection remains enforced** so local users cannot disable real-time monitoring again (**Windows Security → Virus & threat protection settings → Tamper Protection**).
3. **Check for competing antivirus products.** If a third-party agent is installed, decide whether to remove it or configure Defender for passive mode intentionally. If the third-party product should protect the device, uninstalling or repairing it may allow Defender to re-register and re-enable monitoring automatically.
4. **Run a full Defender scan** after re-enabling protection to ensure no threats slipped in while monitoring was off (`Start-MpScan -ScanType FullScan`).
5. **Review Intune or Group Policy baselines** to make sure security baselines enforce real-time monitoring and tamper protection going forward.

## Verification steps
- `Get-MpComputerStatus | Select-Object RealTimeProtectionEnabled` should return `True`.
- In Windows Security, the **Real-time protection** toggle should appear as **On** and be greyed out if tamper protection is controlling it.
- Re-run the AutoHelpDesk collectors/analyzer; the high-severity card should clear, leaving only the normal cards if other checks still pass.

## Additional references
- [Microsoft Learn: Enable and configure Microsoft Defender Antivirus](https://learn.microsoft.com/microsoft-365/security/defender-endpoint/configure-microsoft-defender-antivirus)
- [Microsoft Learn: Configure tamper protection](https://learn.microsoft.com/microsoft-365/security/defender-endpoint/prevent-changes-to-security-settings-with-tamper-protection)
- [Microsoft Learn: Microsoft Defender Antivirus real-time protection](https://learn.microsoft.com/microsoft-365/security/defender-endpoint/microsoft-defender-antivirus-real-time-protection)
