# AutoHelpDesk Analysis Heuristics

This document lists the analysis functions and issue card heuristics grouped by their respective categories. Each heuristic summarizes the conditions that raise issues and the severity levels applied.

## System Heuristics
- **System/Firmware** – Raises a medium issue when firmware is still in legacy BIOS mode and a low issue when the analyzer cannot determine firmware mode from `Get-ComputerInfo`.
- **System/Secure Boot** – Marks Secure Boot as a high-severity issue if it is disabled, unsupported, or reports an unexpected state, and still escalates to high if Secure Boot details are missing even though UEFI is present.
- **System/Fast Startup** – Emits warning-severity findings when Fast Startup is enabled or when its state cannot be determined from power settings; otherwise records a healthy status when it is disabled.
- **System/Startup Programs** – Flags low issues when Autoruns output is unrecognized or empty, escalates to medium when non-Microsoft startup items exceed 10, and warns at low severity when the count is between 6 and 10.
- **System/Uptime** – Uses the uptime classification to emit issues whose severity matches the computed range (for example, medium/high/critical depending on days since reboot) when the device exceeds healthy thresholds.

## Network & DNS Heuristics
- **Network** – Critical issues are raised for missing IPv4 addresses or APIPA addresses, high for missing default gateways or default routes, high for failed pings, and low when traceroute never completes, highlighting likely connectivity faults.
- **DNS/Internal** – Adjusts severity based on domain-join health: medium/high when only one or no AD-capable resolvers are detected (with special handling if the secure channel is already broken) and medium when public DNS servers appear on a domain-joined device.
- **DNS/Order** – Creates a low-severity issue when a public DNS server sits ahead of an internal resolver in the configuration order.
- **DNS** – Reports a medium-severity issue whenever `nslookup` results show timeouts or NXDOMAIN responses.
- **Firewall profiles** – Each firewall profile that is turned off generates a medium-severity item so profile gaps are surfaced promptly.

## Outlook & Office Heuristics
- **Outlook/Connectivity** – Records informational findings when Test-NetConnection is unavailable or inconclusive and elevates to high severity when HTTPS tests to outlook.office365.com fail.
- **Outlook/OST** – Flags OST caches as critical (>25 GB), high (15–25 GB), or medium (5–15 GB) to highlight sync bloat issues.
- **Outlook/Autodiscover** – Emits info/medium issues for missing cmdlets, absent domain candidates, incorrect CNAME targets, failed lookups, or missing records so onboarding problems are obvious.
- **Outlook/SCP** – Alerts with medium severity when SCP queries fail and low severity when no SCP exists on a domain-joined client (acceptable for Exchange Online only tenants).
- **Office/Macros** – Produces a high severity when MOTW blocking is disabled and medium when macro notification policies still allow macros.
- **Office/Protected View** – Adds medium-severity findings when Protected View is disabled for any Office app context.

## Security Heuristics
- **Security (Microsoft Defender)** – Surfaces high severity when real-time protection is off, escalates signature age (medium/high/critical tiers), and reports high issues for missing engine/platform updates or informational gaps when Defender data is absent.
- **Security/BitLocker** – Covers missing cmdlets (low), query failures (low), OS volumes without protection (critical), incomplete encryption (high), unclear state (low), no protected volumes (high), unparsed output (low), empty files (low), and missing recovery passwords (high).
- **Security/TPM** – Issues medium severity when a TPM exists but is not ready and high severity when no TPM is detected on hardware that should have one.
- **Security/HVCI** – Marks medium issues when virtualization-based memory integrity is available but off or when Device Guard data is missing.
- **Security/Credential Guard** – Raises a high-severity item if Credential Guard or RunAsPPL is not enforced.
- **Security/Kernel DMA** – Produces medium findings when Kernel DMA protection is disabled/unsupported on mobile hardware or when the status cannot be determined.
- **Security/Firewall** – Warns at high severity if firewall status output is missing so administrators know to recollect data.
- **Security/RDP** – Flags high severity when RDP lacks NLA and medium when RDP is enabled on mobile systems (even with NLA).
- **Security/SMB** – Highlights a high-severity issue whenever SMBv1 is enabled.
- **Security/NTLM** – Triggers medium severity if NTLM restriction policies are not configured.
- **Security/SmartScreen** – Emits medium issues when SmartScreen policies are disabled or not enforced.
- **Security/ASR** – Issues high-severity findings whenever mandated Attack Surface Reduction rules are missing or not blocking.
- **Security/ExploitProtection** – Creates medium items when CFG/DEP/ASLR aren’t all enforced or when exploit protection data is missing.
- **Security/WDAC** – Warns (and, on modern clients, raises medium severity) when no Windows Defender Application Control policy is detected.
- **Security/SmartAppControl** – Reports medium severity when Smart App Control is not enabled on Windows 11, helping ensure application control baselines.
- **Security/LocalAdmin** – Adds a high issue when the current user remains in the local Administrators group.
- **Security/LAPS** – Surfaces a high severity whenever neither legacy LAPS nor Windows LAPS protections are detected.
- **Security/UAC** – Raises high severity for insecure UAC configurations (e.g., disabled UAC, insecure prompts).
- **Security/PowerShellLogging** – Creates medium issues when script block/module logging or transcription is absent.
- **Security/LDAPNTLM** – Flags high severity if LDAP signing, channel binding, or NTLM restrictions are not enforced on domain-joined systems.
- **Security/DHCP** – Raises high severity when DHCP servers with non-private addresses are detected.
- **Security/Office** – Emits medium/low informational issues when macro blocking, notifications, or Protected View data is missing (prompting further investigation).

## Active Directory Heuristics
- **Active Directory/DC Discovery** – Critical when no domain controllers are located via SRV lookups.
- **Active Directory/AD DNS** – Critical if no AD-capable DNS servers exist, high if only one resolver remains, and medium when public DNS servers are configured on a domain client.
- **Active Directory/Secure Channel** – Critical for broken machine secure channels.
- **Active Directory/Time & Kerberos** – High severity when time sync or Kerberos errors appear in recent logs.
- **Active Directory/SYSVOL/NETLOGON** – High severity for SYSVOL or NETLOGON access errors.
- **Active Directory/GPO Processing** – High severity when Group Policy processing reports failures.

## Services & Events Heuristics
- **Services** – Issues adopt the per-service severity computed earlier (e.g., medium/high/critical for critical service failures) and explicitly raise high severity when legacy essentials like Dhcp or WinDefend are stopped.
- **Events** – Adds informational issues for logs showing five or more errors and low-severity issues for logs with at least ten warnings in the sampled data.

## Hardware Heuristics
- **Hardware/Removable Media – Autorun/Autoplay** – Flags medium severity when Autorun or Autoplay remains enabled by checking `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoDriveTypeAutoRun = 0xFF` (or equivalent policy) and `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoAutoRun = 1`.
- **Hardware/Removable Storage Control** – Raises medium-to-high severity when removable storage controls (such as deny write/allow read policies or BitLocker To Go requirements) are not enforced in environments where policy forbids unrestricted removable storage.
- **Hardware/Bluetooth & Wireless Sharing** – Emits low-severity findings when Bluetooth, Wi-Fi sharing, or Nearby sharing features deviate from the required baseline on laptops.

## Storage Heuristics
- **Storage/SMART** – Critical when SMART output contains failure keywords (Pred Fail, Bad, Caution, etc.).
- **Storage/Disks** – Aggregates disk health problems (offline, read-only, non-OK operational/health status) and raises an issue at the worst severity observed across affected disks.
- **Storage/Volumes** – Collates per-volume health warnings and emits an issue at the worst severity among those volumes.
- **Storage/Free Space** – Issues critical warnings when free space drops below critical floors and high warnings when volumes fall under warning thresholds.

