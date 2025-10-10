# Windows Firewall SMB/NetBIOS exposure example

**Impact (for issue card): A ransomware infection on a guest VLAN could traverse the open firewall rule to reach the finance file server and encrypt shared documents.**

## Realistic scenario

1. **Environment layout.** A company separates workstations into VLAN A (general users) and VLAN B (finance). The finance department keeps its QuickBooks files on a Windows file server in VLAN B. A Windows 10 workstation in VLAN A is configured with the default "Remote Assistance (DCOM-In)" firewall rule that allows inbound TCP 135 from any network.
2. **Initial compromise.** An employee in VLAN A opens a phishing email that drops ransomware. The malware immediately scans for SMB/NetBIOS services over TCP 135/139/445 to move laterally.
3. **Cross-VLAN movement.** Because the firewall rule allows TCP 135 from any remote address, the ransomware can reach the finance file server even though it sits on a different VLAN. The server responds, and the malware authenticates using stolen domain credentials.
4. **Payload execution.** The ransomware copies itself to the finance file server via SMB, launches remotely, and begins encrypting the shared QuickBooks and Excel files that the finance team relies on daily.
5. **Business impact.** Finance users in VLAN B suddenly lose access to their accounting data, payroll spreadsheets, and invoices. Operations halt until backups are restored, causing downtime and potential financial penalties.

## Takeaways

- Restrict the Remote Assistance firewall rule (and other SMB/NetBIOS ports) to only trusted management subnets or disable it entirely if unused.
- Implement VLAN ACLs or firewall policies that prevent lateral SMB traffic between user segments unless explicitly required.
- Monitor for unexpected SMB connections between VLANs to detect attempted propagation early.
