## Summary
The Microsoft Defender Antivirus heuristic compares real-time monitoring, engine status, running mode, and companion safeguards to determine which cards to raise. When `RealTimeProtectionEnabled` is false, AutoHelpDesk inspects Microsoft Defender Antivirus running mode and Windows Security Center inventory before choosing the severity: **High** when no other AV is active, **Medium** when policy keys disabled scanning or the inventory is unknown, and **Info** when Microsoft Defender Antivirus is expected to run passive alongside another AV. The analyzer supplements that finding with tamper, cloud, signature age, and exclusion drift checks so technicians can quickly restore protection while noting when tamper protection prevents local preference changes. Microsoft Defender for Endpoint tenants should assume security baselines or endpoint security policies override interactive remediation until those policies reapply.

## Signals to Collect
- `Get-MpComputerStatus` → Persist `RealTimeProtectionEnabled`, `AMRunningMode`, `BehaviorMonitorEnabled`, `DefenderSignaturesOutOfDate`, `IsTamperProtected`, `AntivirusSignatureLastUpdated`, `AMServiceEnabled`, and companion health flags for state comparison across Microsoft Defender Antivirus.
- `Get-MpPreference` → Record `DisableRealtimeMonitoring`, MAPS/Cloud configuration (`MAPSReporting`, `SubmitSamplesConsent`, `CloudBlockLevel`), and all file/path/process exclusions.
- *(Optional)* Parse a local Microsoft Defender Antivirus baseline exclusions file (for example, `C:\ProgramData\AutoHelpDesk\defender-exclusions-baseline.json`) to detect drift between expected and observed exclusions.

## Detection Rule
- **RTPDisabled** → When `RealTimeProtectionEnabled = $false`, emit: **High** severity if Microsoft Defender Antivirus should be active and Security Center shows no alternate AV, **Medium** severity if policy keys (`DisableRealtimeMonitoring` or `DisableIOAVProtection`) disabled scanning or third-party coverage cannot be confirmed, and **Info** severity when Microsoft Defender Antivirus is intentionally passive alongside an active non-Microsoft AV.
- **TamperOff** → When `IsTamperProtected = $false` (from `Get-MpComputerStatus` or `Get-MpPreference`), emit a **High** severity issue for Microsoft Defender Antivirus tamper protection.
- **CloudOff** → When cloud/MAPS toggles (`MAPSReporting`, `SubmitSamplesConsent`, `CloudBlockLevel`) indicate cloud-delivered protection is disabled, emit a **Medium** severity issue.
- **SignaturesOld** → When `(Get-Date) - AntivirusSignatureLastUpdated` exceeds **SignatureAgeHoursThreshold = 72** hours, emit a **Medium** severity issue.
- **OverbroadExclusions** → When any exclusion path matches `%TEMP%`, `%USERPROFILE%`, `*\Downloads\*`, `%ProgramData%\*`, or other catch-all wildcards beyond the baseline, emit a **High** severity issue.

## Policy precedence and tamper protection
Microsoft Defender Antivirus is the antimalware component inside Microsoft Defender for Endpoint, so Intune endpoint security policies or the Microsoft Defender for Endpoint security baseline take precedence over local commands. Tamper Protection blocks `Set-MpPreference` changes unless the device is in a maintenance window or the setting is disabled centrally. When AutoHelpDesk flags real-time protection drift, technicians should confirm whether policy intentionally set the state before running local fixes. Use the policy assignment history in Intune or Microsoft Defender for Endpoint to verify whether a recent deployment forced the observed configuration.

## Heuristic Mapping
- `Security/Defender/RTPDisabled`
- `Security/Defender/TamperProtectionDisabled`
- `Security/Defender/CloudProtectionDisabled`
- `Security/Defender/OutdatedSignatures`
- `Security/Defender/OverbroadExclusions`

## Remediation
1. **Enable core protections by policy**: use Intune endpoint security policies, Microsoft Defender for Endpoint security baselines, or Group Policy to enforce real-time protection, tamper protection, and cloud-delivered protection so endpoints cannot disable them locally. If emergency remediation is required before policy reapplies, use `Set-MpPreference -DisableRealtimeMonitoring $false`, but expect tamper protection to block it unless the safeguard is disabled centrally.
2. **Refresh Microsoft Defender Antivirus signatures**: run `Update-MpSignature` (or trigger the configured update channel) to immediately clear outdated signatures and revalidate detection capability.
3. **Tighten exclusions**: review configured exclusions against the approved baseline, remove any patterns that cover `%TEMP%`, user profiles, downloads folders, or `%ProgramData%`, and scope any necessary exclusions to precise files.
4. **Verify restoration**: rerun the AutoHelpDesk collectors to confirm all flags return to expected values and that no new overbroad exclusions or stale signatures persist.

## References
- `docs/defender-real-time-protection.md`

# Understanding the "Microsoft Defender Antivirus real-time protection disabled" and companion cards

## What the cards are telling you
- **Analyzer**: Security → Microsoft Defender Antivirus
- **High-severity issue**: **"Microsoft Defender Antivirus real-time protection disabled, creating antivirus protection gaps."**
  - Triggered when `Get-MpComputerStatus` reports `RealTimeProtectionEnabled = False`, Microsoft Defender Antivirus is not in Passive or EDR Block Mode, and Windows Security Center lists no other active antivirus.
- **Medium-severity issue**: **"Microsoft Defender Antivirus real-time protection disabled by policy."** or **"Microsoft Defender Antivirus real-time protection disabled; third-party coverage unknown."**
  - Triggered when policy keys disable Microsoft Defender Antivirus scanning or when real-time protection is off but Security Center inventory is unavailable.
- **Info-severity issue**: **"Microsoft Defender Antivirus passive; third-party antivirus active."**
  - Triggered when Microsoft Defender Antivirus is in Passive or EDR Block Mode and at least one non-Microsoft antivirus is registered as present.
- **High-severity issue**: **"Microsoft Defender Antivirus tamper protection disabled, allowing unauthorized Microsoft Defender Antivirus changes."**
  - Triggered when tamper protection flags (`IsTamperProtected`, `DisableTamperProtection`) indicate the safeguard is off.
- **Medium-severity issues**: cover cloud-delivered protection disabled and Microsoft Defender Antivirus signatures older than 72 hours.
- **High-severity issue**: flags overbroad exclusions that cover `%TEMP%`, user profiles, downloads folders, or `%ProgramData%`.
- **Normal cards**: confirm healthy states when real-time protection, tamper protection, cloud delivered protection, signatures, and exclusions all align with policy.

> **Impact (plain English):** When real-time protection is off, Microsoft Defender Antivirus stops intercepting new files and processes, leaving the machine exposed to fresh malware until a manual or scheduled scan runs.

## Data sources used by the heuristic
- The **Microsoft Defender Antivirus collector** (`Collectors/Security/Collect-Defender.ps1`) runs three native cmdlets:
  - `Get-MpComputerStatus` → feeds the analyzer `Status` block, including `RealTimeProtectionEnabled`, `AntivirusEnabled`, `TamperProtectionEnabled`, and signature versions for Microsoft Defender Antivirus.
  - `Get-MpPreference` → supplies the `Preferences` block the analyzer inspects for tamper protection, MAPS cloud settings, and other Microsoft Defender Antivirus policy toggles.
  - `Get-MpThreat` → returns recent detections for the "No recent Microsoft Defender Antivirus detections" card.
- The analyzer (`Analyzers/Heuristics/Security/Security.Defender.ps1`) converts those fields into issue/normal cards. Each check is evaluated independently, so one failure (Microsoft Defender Antivirus real-time protection) can coexist with multiple passing checks (signatures, MAPS, tamper protection).

## Why good cards can appear next to a critical issue
The collector snapshots multiple Microsoft Defender Antivirus subsystems at once. Real-time monitoring is controlled by the `RealTimeProtectionEnabled` flag, while signature currency, tamper protection, exclusion hygiene, and cloud-delivered protection each have independent controls and thresholds. It is therefore common to see:
- **High**: Real-time protection disabled with no alternate antivirus or tamper protection disabled.
- **High**: Tamper protection disabled or overbroad exclusions detected.
- **Medium**: Cloud-delivered protection disabled or signatures older than the 72-hour threshold.
- **Medium**: Real-time protection disabled by policy or when third-party coverage cannot be confirmed.
- **Info**: Microsoft Defender Antivirus passive because another antivirus is active.
- **Good**: Remaining safeguards showing compliant states because updates are still installing successfully and policy is intact.
These cards describe different aspects of Microsoft Defender Antivirus configuration, so technicians should treat the real-time protection finding—and any accompanying tamper, cloud, signature, or exclusion findings—as actionable whenever it indicates a coverage gap, even when other safeguards remain in place.

## Typical causes of the critical card
- A user or script ran `Set-MpPreference -DisableRealtimeMonitoring $true` (often to install unsigned software) and never re-enabled it.
- Third-party security products turned Microsoft Defender Antivirus real-time engine off to avoid conflicts while remaining the primary AV, so Microsoft Defender Antivirus reports Passive Mode with an informational card.
- Tamper protection was temporarily relaxed by an administrator or Intune security task, allowing the setting to be toggled off.
- Malware disabled Microsoft Defender Antivirus protections before being remediated.

## How to remediate
1. **Reinforce protections through centralized policy**
   - Use Intune endpoint security policies, Microsoft Defender for Endpoint security baselines, or Group Policy to enforce real-time protection, tamper protection, and cloud-delivered protection so devices ignore local toggles.
   - If policy remediation is pending, re-enable real-time monitoring with `Set-MpPreference -DisableRealtimeMonitoring $false`; tamper protection or Microsoft Defender for Endpoint policy may block the command until disabled centrally.
2. **Confirm tamper protection remains enforced** so local users cannot disable real-time monitoring again (**Windows Security → Virus & threat protection settings → Tamper Protection**).
3. **Check for competing antivirus products.** If a third-party agent is installed, decide whether to remove it or configure Microsoft Defender Antivirus for passive mode intentionally. If the third-party product should protect the device, uninstalling or repairing it may allow Microsoft Defender Antivirus to re-register and re-enable monitoring automatically.
4. **Run a full Microsoft Defender Antivirus scan** after re-enabling protection to ensure no threats slipped in while monitoring was off (`Start-MpScan -ScanType FullScan`).
5. **Review Intune, Microsoft Defender for Endpoint security baselines, or Group Policy baselines** to make sure security baselines enforce real-time monitoring and tamper protection going forward.

## Verification steps
- `Get-MpComputerStatus | Select-Object RealTimeProtectionEnabled` should return `True`.
- In Windows Security, the **Real-time protection** toggle should appear as **On** and be greyed out if tamper protection is controlling it.
- Re-run the AutoHelpDesk collectors/analyzer; the critical card should clear, leaving only the normal cards if other checks still pass.

## Additional references
- [Microsoft Learn: Enable and configure Microsoft Defender Antivirus](https://learn.microsoft.com/microsoft-365/security/defender-endpoint/configure-microsoft-defender-antivirus)
- [Microsoft Learn: Configure tamper protection](https://learn.microsoft.com/microsoft-365/security/defender-endpoint/prevent-changes-to-security-settings-with-tamper-protection)
- [Microsoft Learn: Microsoft Defender Antivirus real-time protection](https://learn.microsoft.com/microsoft-365/security/defender-endpoint/microsoft-defender-antivirus-real-time-protection)
