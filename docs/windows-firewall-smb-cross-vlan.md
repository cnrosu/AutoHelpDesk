## Summary
AutoHelpDesk’s firewall policy matcher flags inbound SMB/NetBIOS rules that allow unrestricted remote addresses because they enable cross-VLAN propagation. This scenario illustrates how a single permissive rule on TCP 135/139/445 can let ransomware traverse network segments. Use the steps below to gather evidence, validate exposure, and tighten access without breaking legitimate workflows.

## Signals to Collect
- `Get-NetFirewallRule -DisplayName "Remote Assistance (DCOM-In)" | Get-NetFirewallAddressFilter` → Inspect remote address scope for SMB-related rules.
- `Get-NetTCPConnection -LocalPort 135` (or `netstat -an | find "135"`) → Confirm RPC Endpoint Mapper is listening.
- `Test-NetConnection -ComputerName <target> -Port 135` from another VLAN → Validate cross-segment reachability.
- `New-PSDrive -Name T -PSProvider FileSystem -Root \\<server>\TestShare` → Verify SMB authentication succeeds across VLANs (disconnect after test).

## Detection Rule
- Normalize inbound firewall rules covering TCP/UDP ports 135, 137, 138, 139, or 445.
- Raise a **high-severity** issue (`Security/Firewall/SmbInbound`) when those rules allow unrestricted or unknown remote scopes (Public, Any, or empty address filters).
- Attach evidence summarizing rule names, profiles, local ports, and remote scopes to show technicians which entries need adjustment.
- Produce additional informational cards if rule inventory is incomplete, noting that SMB exposure checks could not run.

## Heuristic Mapping
- `Security.Firewall` (Check ID `Security/Firewall/SmbInbound`)

## Remediation
1. Restrict affected firewall rules to trusted management subnets or disable them entirely if SMB/Remote Assistance is unused.
2. Implement upstream VLAN ACLs or firewall policies to block SMB ports between user segments unless explicitly required.
3. Monitor for unexpected SMB connections across VLANs using network telemetry or SIEM alerts.
4. Publish a runbook for technicians detailing how to request temporary access without creating broad permanent rules.
5. Re-run AutoHelpDesk firewall collectors to confirm inbound SMB rules now show restricted scopes.

## References
- `docs/windows-firewall-smb-cross-vlan.md`

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

## Manual verification checklist

Follow these steps on an affected workstation and file server to confirm whether the rule truly exposes SMB/NetBIOS across VLAN boundaries:

1. **Review the firewall rule scope.** Run `Get-NetFirewallRule -DisplayName "Remote Assistance (DCOM-In)" | Get-NetFirewallAddressFilter` in an elevated PowerShell window. If `RemoteAddress` returns `Any`, the rule is not restricted to trusted subnets.
2. **Confirm the service is listening.** On the workstation, execute `Get-NetTCPConnection -LocalPort 135` (or `netstat -an | find "135"`) to verify that RPC Endpoint Mapper is listening for Remote Assistance traffic.
3. **Test cross-VLAN reachability.** From a device in another VLAN, run `Test-NetConnection -ComputerName <workstation FQDN or IP> -Port 135`. A successful TCP test shows the firewall is allowing inbound RPC from outside the VLAN.
4. **Validate SMB authentication.** Use a low-privilege domain account and run `Test-NetConnection -ComputerName <file server> -Port 445` from the compromised VLAN. If it succeeds, attempt to map a test share (e.g., `New-PSDrive -Name T -PSProvider FileSystem -Root \\<server>\TestShare`). Disconnect immediately after (`Remove-PSDrive T`). Perform this in a lab or maintenance window to avoid production impact.
5. **Check for existing restrictions.** Inspect upstream firewalls or VLAN ACLs to ensure they block TCP 135/139/445 between user segments. Document any gaps so you can present hard evidence to the security team.

Collecting screenshots or command output for each step creates an audit trail that demonstrates the risk quantitatively.

## MSP operational impact

- **Remote support tools.** Restricting the Remote Assistance rule to MSP management subnets does not break RMM agents or remote-control tools (e.g., ScreenConnect, TeamViewer) that initiate outbound connections. It only blocks unsolicited inbound RPC from user VLANs.
- **Planned Remote Assistance sessions.** If you rely on Microsoft Remote Assistance (`msra.exe`) that expects peer-to-peer inbound connectivity, ensure technicians connect from an allowed management network or temporarily open the rule on a per-session basis.
- **Patch management and scripting.** PowerShell Remoting, SMB-based software deployment, and Group Policy processing continue to work when traffic originates from your management VLAN or jump boxes. Document the approved subnets in the firewall rule so routine maintenance still succeeds.
- **Operational safeguards.** Publish a runbook that tells technicians how to request temporary access if they must service an endpoint from an untrusted VLAN. This prevents ad-hoc rule changes that could reintroduce lateral-movement paths.
