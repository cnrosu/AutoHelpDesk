# AutoHelpDesk Diagnostics Platform

AutoHelpDesk is a modular PowerShell toolkit that collects Windows device telemetry, normalizes it into JSON, and runs heuristic analyzers to produce human-friendly diagnostic reports. The project is organized around three building blocks:

- **Collectors** – lightweight scripts that gather raw data and emit structured JSON with timestamps and payload metadata.
- **Analyzers** – parsing and rules engines that load the JSON artifacts, evaluate health heuristics, and generate HTML summaries.
- **Reports** – HTML and CSS assets that surface the analyzer results for technicians and customers.

This README documents how the system fits together and enumerates the available heuristics so you can understand what the analyzer looks for out of the box.

## Prerequisites

- Windows 10/11 (PowerShell 5.1 or PowerShell 7+). The collectors lean on built-in Windows utilities and WMI/CIM queries.
- Run the shell **as Administrator** so the collectors can reach networking, security, and event log data without access errors.
- Temporarily relax the execution policy in your session if scripts are blocked:
  ```powershell
  Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
  ```

## Quick start

The toolkit is designed to run entirely from PowerShell—no installers required. The commands below assume you are running from the repository root in an elevated shell.

### One-button orchestration (AutoL1)

To generate the report, run `AutoL1/Device-Report.ps1`; it creates a timestamped output folder (defaulting to `Desktop\DiagReports\<timestamp>`), runs the collectors, executes the analyzer, and opens the resulting HTML report. Supply `-InputFolder` to reuse an existing collection.

## Repository layout

| Path | Description |
| --- | --- |
| `/Collectors` | Stand-alone data gathering scripts grouped by domain (Network, Security, System, etc.). Each script exports a JSON file to its domain subfolder. |
| `/Analyzers` | Shared analyzer helpers, heuristic modules, and the orchestrator that renders HTML plus merged CSS assets. |
| `/AutoL1` | Turn-key “Device Health Diagnostics Toolkit” that wraps the collectors and analyzers for L1 support workflows. |
| `/Reports` | Static HTML/CSS prototypes and assets for presenting analyzer output. |
| `/Modules` | Cross-cutting PowerShell modules that can be imported by collectors, analyzers, or orchestration scripts. |
| `/styles` | Base CSS and layout primitives merged into the Device Health report output. |

### Artifact format

All collector scripts use `CollectorCommon.ps1` helpers to enforce a consistent JSON envelope:

```json
{
  "CollectedAt": "2024-03-01T15:23:45.1234567Z",
  "Payload": {
    "<CollectorSpecificData>": "..."
  }
}
```

- `CollectedAt` is always an ISO-8601 timestamp recorded on the device running the collector.
- `Payload` contains a collector-specific object. Most payload properties map to native command output (`ipconfig`, `Get-CimInstance`, `wevtutil`, etc.).
- Optional fields (for example, command failures) are represented as nested objects with `Source`/`Error` properties so analyzers can highlight gaps.

`Collect-All.ps1` aggregates the JSON artifacts into an output root (default: `Collectors/output/<Area>`). A `collection-summary.json` file tracks which collectors were executed, their success flags, and the on-disk path of each artifact.

### Analyzer expectations

`Analyze-Diagnostics.ps1` looks for `*.json` files beneath an input folder. Artifact names are matched by base filename (e.g., `network.json`, `defender.json`) and normalized to lowercase keys. Analyzer modules retrieve payloads with `Get-AnalyzerArtifact` and `Get-ArtifactPayload`, so keeping filenames descriptive and unique is crucial when adding new collectors.

HTML is produced by `HtmlComposer.ps1`, which receives category results from each heuristic module. The analyzer also returns flattened issue, normal, and check collections for programmatic consumption.

## Heuristic catalogue

The following sections list the analysis functions and issue card heuristics grouped by their respective categories. Each heuristic summarizes the conditions that raise issues and the severity levels applied.

## System Heuristics
- **System/Firmware** – Raises a medium issue when firmware is still in legacy BIOS mode and a low issue when the analyzer cannot determine firmware mode from `Get-ComputerInfo`.
- **System/Secure Boot** – Marks Secure Boot as a high-severity issue if it is disabled, unsupported, or reports an unexpected state, and still escalates to high if Secure Boot details are missing even though UEFI is present.
- **System/Fast Startup** – Emits warning-severity findings when Fast Startup is enabled or when its state cannot be determined from power settings; otherwise records a healthy status when it is disabled.
- **System/Pending Reboot** – Highlights medium-severity issues when Windows Update or servicing registry keys signal a required reboot, warns on outstanding file rename operations, and captures pending computer rename evidence, while recording a normal finding when no reboot indicators are detected.
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
- **Printing** – Flags high severity when the Spooler service is stopped/disabled or when print hosts are unreachable, raises medium/high issues for offline queues and long-running jobs, warns on WSD ports, SNMP "public" communities, and legacy drivers, enforces Point-and-Print hardening posture, surfaces PrintService event storms and recurring driver crashes, and records GOOD findings for healthy spooler state, reachable printer ports, packaged drivers, and quiet event logs.

## Hardware Heuristics
- **Hardware/Removable Media – Autorun/Autoplay** – Flags medium severity when Autorun or Autoplay remains enabled by checking `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoDriveTypeAutoRun = 0xFF` (or equivalent policy) and `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoAutoRun = 1`. The `Collectors/Security/Collect-Autorun.ps1` script exports these machine and user policy values into `autorun.json` so the analyzer can evaluate hardened baselines and surface gaps when the expected 0xFF/1 posture is missing.
- **Hardware/Removable Storage Control** – Raises medium-to-high severity when removable storage controls (such as deny write/allow read policies or BitLocker To Go requirements) are not enforced in environments where policy forbids unrestricted removable storage.
- **Hardware/Device Manager** – Surfaces high-severity issues when drivers report error states or fail to start despite boot/system/automatic start modes, flags missing-driver scenarios (Code 28) from Device Manager problem listings, and medium severity when Device Manager marks drivers as degraded so malfunctioning hardware is highlighted quickly.
- **Hardware/Bluetooth & Wireless Sharing** – Emits low-severity findings when Bluetooth, Wi-Fi sharing, or Nearby sharing features deviate from the required baseline on laptops.

## Storage Heuristics
- **Storage/SMART** – Critical when SMART output contains failure keywords (Pred Fail, Bad, Caution, etc.).
- **Storage/SMART Wear** – Surfaces medium issues when SSD wear reaches ~85% of its rated lifetime, high issues once wear exceeds ~95%, and records health checks/normals showing remaining life and temperature for each drive when SMART wear data is available.
- **Storage/Disks** – Aggregates disk health problems (offline, read-only, non-OK operational/health status) and raises an issue at the worst severity observed across affected disks.
- **Storage/Volumes** – Collates per-volume health warnings and emits an issue at the worst severity among those volumes.
- **Storage/Free Space** – Issues critical warnings when free space drops below critical floors and high warnings when volumes fall under warning thresholds.

