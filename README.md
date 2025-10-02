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
- Devices must be enrolled with Microsoft Intune or another MDM that enables health attestation if you want the measured boot collector to retrieve TPM attestation logs; without MDM integration those events are not written for remote collection.

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

### Issue card authoring conventions

When adding or updating heuristics that emit issue cards, always include a single plain-English sentence in the card that explains the practical ramifications for the technician or end user. This one-line explanation should make the impact obvious without requiring deep protocol knowledge.

## Heuristic catalogue

The sections below summarize every analyzer category and the heuristics it currently evaluates.

### System
- **Collection** – Emits informational issues when the core system inventory artifact is missing or unreadable so OS posture gaps are visible.
- **Operating System** – Raises a critical issue for unsupported Windows releases, surfaces informational gaps when inventory cannot be parsed, and records normals when supported builds are detected.
- **Firmware** – Confirms Secure Boot when enabled and raises high-severity issues when Secure Boot is disabled, unsupported, or reports an unexpected state despite UEFI firmware.
- **Hardware Inventory** – Flags informational issues when memory and hardware inventory queries fail, prompting technicians to recollect the data set.
- **Uptime** – Applies tiered severities once uptime exceeds healthy reboot windows and records checks showing the current uptime.
- **Pending Reboot** – Surfaces medium issues when Windows Update, servicing keys, or file rename operations require a restart and emits informational gaps whenever pending reboot signals cannot be enumerated.
- **Power Configuration** – Warns when Fast Startup is enabled, records a normal when it is disabled, and reports informational gaps when the setting cannot be read.
- **Performance** – Raises medium findings when memory consumption is high, notes when process inventory cannot be gathered, and captures top CPU consumers when available.
- **Startup Programs** – Highlights medium issues when more than ten non-Microsoft autoruns are enabled, low issues when six to ten are present, records normals for healthy counts, and emits informational findings when Autoruns output is empty or unrecognized.
- **Microsoft Store** – Marks the Store as not applicable on SKUs without the package, raises medium/high issues when required services are disabled or Store endpoints fail reachability checks, and records normals that document service state and endpoint results when everything succeeds.

### Network & Connectivity
- **Collection** – Emits informational issues when base network, DNS, or adapter inventories are missing so connectivity gaps are transparent.
- **IP Configuration** – Raises high-severity issues for missing IPv4 configuration or APIPA addresses that would break network access.
- **Routing** – Flags high-severity issues when default routes are absent, indicating outbound connectivity failures.
- **Latency** – Raises high issues when ping tests fail and low issues when traceroute never completes, calling out path instability.
- **Adapters** – Surfaces high issues for interfaces stuck at 100 Mb half-duplex and medium issues when negotiated speeds disagree with policy, pointing to throughput problems.
- **ARP Cache** – Detects gateway MAC changes, duplicate MAC addresses, invalid broadcast replies, and hosts answering for multiple IPs to warn about spoofing or neighbor instability.
- **Network Adapters** – Reports informational gaps when adapter inventories are missing, raises high severity when no active adapters are detected, and records normals when link data is healthy.
- **DHCP** – Runs dedicated analyzers that flag unexpected (non-private) DHCP servers, missing server metadata, static configurations, stale or expiring leases, scope exhaustion, and client event log errors while recording normals when each check passes.
- **DNS Resolution** – Issues high severity when lookups fail, medium when latency probes timeout, and notes when DNS diagnostics were not collected.
- **DNS Client** – Warns when adapters lack DNS servers, when public resolvers are configured on domain devices, when registration is disabled, and when policy queries fail.
- **DNS Autodiscover** – Raises low issues when Autodiscover DNS probes fail so Exchange onboarding gaps are visible.
- **Autodiscover DNS** – Flags high issues when CNAME lookups fail, medium issues when records point to incorrect targets, and records normals when autodiscover.outlook.com is published.
- **Outlook Connectivity** – Raises high severity when HTTPS connectivity to outlook.office365.com fails and medium issues when the diagnostic cannot run.
- **Proxy Configuration** – Surfaces informational issues when user or WinHTTP proxies are configured and escalates to medium/high severity when the WinHTTP Auto Proxy service is stopped or disabled while a proxy is required.
- **Endpoint Firewall** – Raises critical issues when any Windows Firewall profile is disabled, records passes when all profiles are enabled, and emits informational findings when the firewall profile collector is missing or unreadable.
- **Security (Wi-Fi)** – Produces critical findings for open, WEP, or TKIP networks, medium issues for mixed WPA2/WPA3 modes, weak passphrases, or WPA3 fallback, and informational findings when wireless diagnostics are unavailable.

### Outlook & Office
- **Macro Policies** – Confirms macro runtime blocking when MOTW policies are enforced, raises high severity when macros remain allowed, and emits medium/low informational issues when policy data is missing.
- **Protected View Policies** – Flags medium issues when Protected View is disabled for attachments and low informational gaps when policy data is absent.
- **Outlook Cache** – Raises medium issues when OST caches exceed 25 GB, records normals when cache counts are healthy, and emits informational gaps when the inventory is missing.
- **Outlook Data Files** – Highlights large OST files over 25 GB, records normals when data files are present without bloat, and flags informational gaps when the inventory is absent.
- **Autodiscover DNS** – Confirms healthy CNAME targets for Exchange Online and raises medium/high issues when lookups fail or point to incorrect records.

### Security
- **Microsoft Defender** – Detects disabled AV engines, real-time protection, tamper protection, and cloud-delivered protection, surfaces recent threat detections, and notes when Defender status or preferences cannot be queried.
- **Windows Firewall** – Records normals when all profiles are enabled and raises high-severity issues or informational gaps when profiles are disabled or inventory is missing.
- **BitLocker** – Highlights unprotected OS volumes, weak protector configurations, missing recovery passwords, and collection failures while documenting TPM- or TPM+PIN-backed protection when present.
- **Measured Boot** – Confirms Secure Boot and TPM attestation data when available, and otherwise records informational gaps for missing PCR bindings, attestation events, or Secure Boot confirmation.
- **TPM** – Raises issues when the TPM is absent or not ready and records normals when hardware key protection is available.
- **Kernel DMA** – Warns when kernel DMA protection is disabled, unsupported, or unknown and records normals when enforcement is confirmed.
- **Memory Integrity** – Flags devices where HVCI is available but off, notes missing diagnostics, and records normals when virtualization-based memory integrity is active.
- **Credential Guard** – Produces high-severity findings when Credential Guard or RunAsPPL is not enforced and records normals when protections are active.
- **Credential Management** – Raises high issues when LAPS/PLAP policies are absent and records normals when managed local administrator password policies are detected.
- **Attack Surface Reduction** – Confirms ASR rules operating in block mode, raises high-severity issues when required rules are missing, and flags data gaps when policy output is unavailable.
- **Exploit Protection** – Notes when CFG/DEP/ASLR mitigations are enforced and warns when diagnostics are missing.
- **Windows Defender Application Control** – Records normals when WDAC enforcement is detected and raises issues when no policy is active.
- **Smart App Control** – Flags Windows 11 devices where Smart App Control is disabled, in evaluation, or unreported, and records normals when enforcement is confirmed.
- **PowerShell Logging** – Warns when script block or module logging or transcription is disabled and records normals when logging policies are fully enabled.
- **NTLM Hardening** – Raises medium issues when RestrictSending/Audit policies are not enforced and records normals when NTLM hardening is in place.
- **Autorun Policies** – Notes hardened Autorun/Autoplay registry values, raises medium issues when required values are absent, and flags informational gaps when artifacts are missing.
- **User Account Control** – Confirms secure UAC prompts and raises high-severity issues when the configuration is insecure.

### Active Directory
- **Collection** – Emits informational findings when AD diagnostics are missing or when domain checks are not applicable (for example, Azure AD–joined devices).
- **Discovery** – Distinguishes Azure AD–only joins and raises critical issues when no domain controllers are discovered.
- **DNS Discovery** – Flags SRV lookup failures that prevent domain controller discovery and records normals when AD DNS records resolve.
- **Connectivity** – Raises critical issues when DC port tests fail, medium issues when SYSVOL/NETLOGON shares are unreachable, and records normals when controllers respond with shares available.
- **SYSVOL** – Highlights medium issues when domain shares are unreachable, signalling that GPOs cannot replicate.
- **Time Synchronization** – Flags manual NTP configurations and Kerberos time skew that break authentication while recording normals when skew stays within tolerance.
- **Secure Channel** – Raises critical issues for broken machine secure channels, notes when verification cannot run, and records normals when trust is verified.
- **Group Policy** – Surfaces event log errors accessing SYSVOL/NETLOGON and notes when the Group Policy event log cannot be read.

### Services
- **Service Inventory** – Reports collection errors, raises medium issues when automatic services are stopped, and records normals when automatic services are running.
- **Windows Search Service** – Raises medium/high issues when Windows Search is stopped or disabled and records normals when running.
- **DNS Client Service** – Flags critical issues when the DNS client service is missing or stopped and records normals when it is running.
- **Network Location Awareness** – Raises high issues when NLA is missing or stopped, medium issues when it is manual on workstations, and records normals when it is running.
- **Workstation Service** – Raises high issues when LanmanWorkstation is missing or stopped and records normals when it is running.
- **Print Spooler Service** – Issues medium findings when the spooler remains running on workstations that should disable it, informational findings when it is stopped, and normals when it runs where printing is expected.
- **RPC Services** – Raises critical issues when the RPC or endpoint mapper services are missing or stopped and records normals when they are running.
- **WinHTTP Auto Proxy Service** – Warns when the service is missing or stopped while a proxy is configured (escalating severity when necessary) and records normals when it is running.
- **BITS Service** – Highlights high/medium issues when BITS is missing, disabled, or stopped (with severity based on role) and records normals when transfers are enabled.
- **Office Click-to-Run** – Flags high/medium issues when ClickToRunSvc is misconfigured and records normals when it is running as expected.

### Events
- **Collection** – Emits informational issues when sampled event logs could not be gathered.
- **Networking / DNS** – Flags repeated DNS resolution timeouts in the event logs.
- **Netlogon/LSA (Domain Join)** – Raises issues for secure channel or domain reachability errors observed in the Netlogon logs.
- **Authentication** – Highlights repeated Kerberos pre-authentication failures and account lockouts while recording normals when skew and failure counts stay within tolerance.
- **VPN / IKE** – Warns about recurring VPN authentication failures due to certificate or IKE errors.

### Printing
- **Collection** – Alerts when printing artifacts are missing or warn about collection errors so spooler health is unknown.
- **Spooler Service** – Warns when spooler state cannot be read, raises medium issues when it runs on workstations that should disable it, issues informational findings when stopped, and records normals when the spooler is running on required hosts.
- **Printers** – Flags high issues when the default printer is offline, medium issues for other offline queues, warns about WSD-connected printers, and records normals when printers stay online.
- **Queues** – Raises medium/high issues when stale jobs linger in queues so technicians can clear backlogs.
- **Event Logs** – Warns when PrintService logs show repeated errors and records checks summarizing warning counts.
- **Network Tests** – Raises high-severity issues when printer host connectivity tests fail.

### Hardware
- **Collection** – Emits informational issues when driver or problem-device inventories are missing, unparsed, or empty.
- **Device Manager** – Raises high-severity issues for drivers in failed states, medium issues for degraded devices, informational findings for lesser warnings, and records normals when Device Manager reports every device as healthy.

### Storage
- **Collection** – Flags missing storage inventory or SMART snapshot artifacts so disk health cannot be evaluated.
- **Disk Health** – Aggregates operational/health state from physical disks, raising issues at the worst severity observed and recording normals when disks report healthy.
- **SMART** – Raises critical findings when SMART output shows failure indicators, records normals when statuses are OK, and notes informational gaps when SMART data is missing.
- **SMART Wear** – Surfaces medium issues as SSD wear approaches limits, high issues as wear nears end-of-life, records normals for healthy wear levels, and flags informational gaps when counters are unavailable.
- **Free Space** – Raises high/critical warnings when volumes drop below warning or critical free-space thresholds and notes when volume inventory is missing.

