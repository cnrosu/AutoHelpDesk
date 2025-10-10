## Summary
AutoHelpDesk inspects inbound Remote Desktop firewall rules to ensure the Public profile is not exposed. If enabled rules include Public or Any profiles, the heuristic raises a high-severity alert because untrusted networks could reach the host. This playbook clarifies the detection inputs and remediation path for Devolutions Remote Desktop Manager and similar tooling.

## Signals to Collect
- `Get-NetFirewallRule -DisplayGroup "Remote Desktop" -PolicyStore ActiveStore | Get-NetFirewallProfile` → List active RDP rules and their profiles.
- `Get-NetFirewallRule -DisplayName "Remote Desktop Manager*" | Format-Table DisplayName, Profile, Enabled, Direction` → Inspect vendor-specific rules like Devolutions RDM.
- `Get-WinEvent -LogName 'Microsoft-Windows-Security-Auditing' -FilterHashtable @{Id=4625; StartTime=(Get-Date).AddHours(-4)}` → Review failed logons that might indicate brute-force attempts.

## Detection Rule
- Normalize enabled inbound firewall rules whose display name, group, or description references "Remote Desktop" or "RDP".
- Raise a **high-severity** issue when any matching rule includes the Public profile (or equivalent tokens such as Any/All).
- Emit a **normal** card when Remote Desktop rules exist but exclude the Public profile, including evidence of the restricted profiles.
- Surface a **medium-severity** issue when firewall rule queries fail, noting that Remote Desktop exposure could not be verified.

## Heuristic Mapping
- `Security.Firewall` (Check ID `Security/RdpPublicProfile`)

## Remediation
1. Edit affected Remote Desktop firewall rules so only Domain and/or Private profiles remain selected, or restrict remote IP ranges to trusted networks.
2. Audit Remote Desktop Manager or JetSoCat configuration to prevent it from re-enabling Public profile access during updates.
3. Validate that remote access requirements are satisfied through VPN or gateway solutions instead of open Public rules.
4. Monitor Security event logs for ongoing RDP brute-force attempts and respond if suspicious activity continues.
5. Re-run AutoHelpDesk firewall collectors to confirm the Public profile is no longer present in RDP rules.

## References
- `docs/windows-firewall-remote-desktop-public-profile.md`

# Understanding the "Remote Desktop firewall rules allow the Public profile" card

## What the card is telling you
- **Analyzer**: Security → Windows Firewall
- **Severity**: High
- **Detection**: The analyzer found one or more Windows Firewall rules for Remote Desktop Manager components (`Devolutions RDM` and `Devolutions Jetsocat`) that are enabled for the **Public** firewall profile on the device.

> **Impact (plain English):** When Remote Desktop firewall rules stay open on the Public profile, anyone on an untrusted network can reach the device and hammer it with Remote Desktop password guesses.

## Why this matters
Windows treats the Public profile as the least-trusted network tier (coffee shops, hotels, guest Wi-Fi, etc.). Allowing Remote Desktop Protocol (RDP) through that profile exposes the host directly to unsolicited login attempts from anyone on the same network segment or, if the device is directly connected to the internet, from the entire internet. Attackers routinely scan for open RDP endpoints and brute-force passwords; leaving the Public profile open greatly increases the risk of compromise.

## Typical causes
- Remote Desktop Manager (Devolutions RDM) automatically creating rules that include the Public profile during installation.
- JetSoCat relay components that are configured for broad access without scoping the firewall rules.
- Administrators manually enabling the Public profile to "fix" a connection issue without realizing the security implications.

## How to remediate
1. **Restrict the firewall scope:** Edit the affected firewall rules in Windows Defender Firewall with Advanced Security so they apply only to the **Domain** and/or **Private** profiles, not Public. If you truly need RDP on Public networks, restrict the rule's remote IP addresses to trusted ranges.
2. **Review Remote Desktop Manager settings:** Within Devolutions RDM, ensure its JetSoCat tunnels and helper services are not configured to listen on broad interfaces when unnecessary.
3. **Consider conditional access:** Use a VPN or remote access gateway instead of exposing RDP directly. This keeps RDP closed on untrusted networks while still allowing remote support.
4. **Monitor sign-in attempts:** Check the Windows Security event log (Event ID 4625) and Remote Desktop Manager audit logs for signs of brute-force attempts after tightening the firewall rules.

## Verification steps
- Run `wf.msc`, locate the relevant rules under **Inbound Rules**, and confirm the Public profile checkbox is cleared.
- From PowerShell, run:
  ```powershell
  Get-NetFirewallRule -DisplayGroup "Remote Desktop Manager" | Format-Table DisplayName, Profile, Enabled
  ```
  Ensure the `Profile` column no longer lists `Public` for the affected rules.
- If remote access is still required externally, validate that users connect through the approved VPN or gateway after the change.

## Additional references
- [Microsoft Learn: Windows Defender Firewall with Advanced Security Overview](https://learn.microsoft.com/windows/security/threat-protection/windows-firewall/windows-firewall-with-advanced-security)
- [Microsoft Learn: Configure firewall rules for RDP](https://learn.microsoft.com/windows/security/threat-protection/windows-firewall/create-an-inbound-port-rule)

