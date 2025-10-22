## Summary
This card fires when AutoHelpDesk detects Credential Guard running without LSA protection (RunAsPPL), leaving LSASS exposed despite virtualization-based security. The guidance below outlines the raw data inspected, how severity is determined, and the steps to enforce protected process light. Technicians can use it to validate the alert and harden devices consistently.

> **Defaults:** Clean installs of Windows 11 22H2 and later enable LSA protection by default. Upgraded devices or legacy images may keep `RunAsPPL` disabled until policy enforcement catches up.

## Signals to Collect
- `Get-CimInstance -Namespace root\Microsoft\Windows\DeviceGuard -Class Win32_DeviceGuard` → Determine whether virtualization-based security (VBS) and hypervisor-protected code integrity (HVCI) are supported and running.
- `Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' | Select-Object RunAsPPL` → Check whether LSASS is configured to run as a protected process (RunAsPPL).
- *(Optional)* `systeminfo.exe` → Parse the **Virtualization-based security** lines to corroborate capability and current state when Device Guard data is unavailable.

## Detection Rule
- **High severity:** Hardware reports VBS/HVCI capable and `RunAsPPL` is missing or set to `0` (`RunAsPPLDisabled`).
- **Medium severity:** Hardware reports VBS/HVCI capable but VBS is not enabled or running (`VBSNotEnabled`).
- **Low severity:** Hardware reports VBS/HVCI not capable (`HardwareNotCapable`) so remediation focuses on firmware/BIOS enablement or exceptions.

## Heuristic Mapping
- `Security/LSA/RunAsPPLDisabled`
- `Security/VBS/NotEnabled`
- `Security/VBS/HardwareNotCapable`

## Remediation
1. Enable virtualization-based security (Credential Guard) and HVCI through Group Policy, MDM, or security baselines so the hypervisor isolates LSASS.
2. Configure LSASS to run as a protected process by setting `RunAsPPL = 1` and, when available, `RunAsPPLBoot = 1` for the UEFI lock.
   Apply the setting through security baselines or Defender Tamper Protection instead of ad-hoc registry edits, then reboot to enforce it.
3. If hardware is not capable, update firmware/BIOS, enable virtualization/Secure Boot features, or document a carve-out until compatible hardware is available.
4. Validate the fix by re-running collectors or checking Device Guard status to confirm VBS and RunAsPPL are active.

## References
- `docs/credential-guard-lsa-protection.md`

# Understanding the "Credential Guard or LSA protection is not enforced" card

## What the card is telling you
- **Analyzer**: Security → Credential Guard
- **Severity**: High
- **Detection**: Credential Guard reported as running, but the Local Security Authority (LSA) registry settings do not show the `RunAsPPL` value set to `1`. Without that flag, LSA is not running as a protected process.

> **Impact (plain English):** Attackers with administrative privileges can still dump LSASS memory to steal credentials because LSA isn't locked down as a protected process.

## Data sources the heuristic inspects
- `lsa.json` – produced by [`Collectors/Security/Collect-LSA.ps1`](../Collectors/Security/Collect-LSA.ps1). The analyzer looks for the `RunAsPPL` and `RunAsPPLBoot` values under `HKLM:\SYSTEM\CurrentControlSet\Control\Lsa`.
- `vbshvci.json` – produced by the Device Guard collector. Its `SecurityServicesRunning` array indicates whether Credential Guard itself is active (value `1`).

If the collector cannot read the registry values (for example, due to access denied) the analyzer records evidence lines such as `RunAsPPL registry value missing or unreadable.` to make the gap obvious.

## How the heuristic interprets the data
1. Credential Guard must be running (`SecurityServicesRunning` includes `1`).
2. LSA protection must be enforced now (`RunAsPPL` equals `1`).
3. `RunAsPPLBoot` is captured for context but is not enough by itself—it's the "apply on next boot" UEFI lock flag.

When both conditions are met, the analyzer emits a normal card titled **"Credential Guard with LSA protection enabled"**. Otherwise it raises the high-severity issue card with the evidence it gathered so technicians can see which requirement failed (for example, missing registry data or a `RunAsPPL` value of `0`).

## Why this matters
Credential Guard isolates secrets inside virtual secure mode, but without LSA protection (`RunAsPPL=1`) an attacker who gains admin-level access can still hook or dump the LSASS process to extract cached passwords and Kerberos tickets. Once that happens, they can move laterally and escalate quickly across the environment.

## How to remediate
1. **Enable LSA protection through policy:**
   - Group Policy: `Computer Configuration` → `Administrative Templates` → `System` → `Local Security Authority` → **Configure LSASS to run as a protected process** → set to **Enabled** or **Enabled with UEFI lock** (writes `RunAsPPL = 1` and `RunAsPPLBoot = 1`).
   - Microsoft Intune / MDM: deploy the Windows security baseline or endpoint security policy so `LsaRunAsPPL` and `LsaRunAsPPLBoot` are enforced without manual registry edits.
   - Ensure Microsoft Defender Tamper Protection stays on so attackers cannot roll back these values.
2. **Confirm Credential Guard prerequisites** (TPM, Secure Boot, virtualization support) and enable it through Group Policy or Windows Security settings if it was disabled.
3. **Reboot after applying the settings** so LSASS restarts with protection enabled.
4. **Validate the fix:** rerun the collector or check `Event Viewer → Applications and Services Logs → Microsoft → Windows → CodeIntegrity → Operational` for Event ID 3065 confirming LSA protection.

## Additional references
- [Microsoft Learn: Protect LSASS with Credential Guard](https://learn.microsoft.com/windows/security/identity-protection/credential-guard/credential-guard-manage)
- [Microsoft Learn: Enable LSA protection](https://learn.microsoft.com/windows/security/identity-protection/credential-guard/credential-guard-configure)
