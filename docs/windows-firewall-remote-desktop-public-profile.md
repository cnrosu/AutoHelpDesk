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

