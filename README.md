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

The catalogue below summarizes every analyzer heuristic grouped by category. Each bullet highlights the evidence the analyzer records and the conditions that raise issue cards or positive findings.

### System

* **Collection & operating system inventory** – Records informational gaps when system inventory is missing or unreadable, reports Windows 11 as supported, and raises critical issues for unsupported Windows 7/8/10 installs while still publishing OS build and last boot checks when the payload is available.【F:Analyzers/Heuristics/System/OperatingSystem.ps1†L11-L61】
* **Firmware posture** – Confirms Secure Boot when it is enabled and emits high-severity issues when Secure Boot is disabled, unsupported, reports an unexpected state, or is missing despite UEFI firmware, giving technicians the System Information evidence that triggered the finding.【F:Analyzers/Heuristics/System/OperatingSystem.ps1†L63-L99】
* **Uptime** – Adds a check that records the current uptime in days, warns when the device has run longer than 30 days without a reboot, and celebrates recent reboots with a normal card.【F:Analyzers/Heuristics/System/Uptime.ps1†L11-L37】
* **Pending reboot tracking** – Flags missing or unreadable pending reboot payloads, surfaces medium issues for Windows Update indicators, pending file rename operations, and rename mismatches, and documents a clean bill of health when no triggers are present.【F:Analyzers/Heuristics/System/PendingReboot.ps1†L11-L144】
* **Power configuration** – Warns when Fast Startup is enabled or unreadable and records a normal finding when the feature is disabled so hybrid shutdown side effects are clear.【F:Analyzers/Heuristics/System/Power.ps1†L11-L30】
* **Performance snapshot** – Publishes memory utilization checks, raises a medium issue when RAM usage exceeds 90%, captures the top CPU consumer, and flags failures to enumerate running processes.【F:Analyzers/Heuristics/System/Performance.ps1†L11-L45】
* **Startup programs** – Reports missing or incomplete Autoruns data, counts startup entries, and escalates from low to medium severity as non-Microsoft autoruns exceed five and ten items while documenting evidence for technicians; healthy counts and empty lists are recorded as normal findings.【F:Analyzers/Heuristics/System/Startup.ps1†L11-L77】
* **Microsoft Store functional checks** – Correlates Store package integrity, critical services, proxy posture, and endpoint reachability, emitting high/medium issues when binaries or services are missing or endpoints fail, an informational card when the Store is inapplicable, and a normal finding when all tests succeed with supporting evidence.【F:Analyzers/Heuristics/System/MicrosoftStore.ps1†L11-L245】

### Network, DHCP & Connectivity

* **Base collection & adapter quality** – Warns when base diagnostics are missing, when adapter inventory cannot be read, or when no interfaces report an active link, and highlights adapters stuck at 100 Mb half duplex or with mismatched speed/duplex policies to expose physical link problems.【F:Analyzers/Heuristics/Network/Network.ps1†L1620-L2105】【F:Analyzers/Heuristics/Network/Network.ps1†L1840-L1871】
* **IP configuration & routing** – Confirms IPv4 addressing, raises high-severity issues when no IPv4 configuration exists, and flags missing default routes so technicians can resolve core connectivity gaps.【F:Analyzers/Heuristics/Network/Network.ps1†L1763-L1776】
* **DNS health** – Captures DNS lookup and latency results, reports failures or missing diagnostics, inventories per-interface resolvers, calls out adapters without DNS servers or using public resolvers on domain devices, and records suffix/registration policy issues alongside positive checks when everything is healthy.【F:Analyzers/Heuristics/Network/Network.ps1†L1875-L2019】【F:Analyzers/Heuristics/Network/Network.ps1†L1917-L2014】
* **Autodiscover & Outlook connectivity** – Tests Outlook HTTPS reachability and Autodiscover lookups, emitting high-severity failures, medium informational cards when testing is impossible, and normal findings when Exchange Online endpoints respond as expected.【F:Analyzers/Heuristics/Network/Network.ps1†L2022-L2087】
* **Proxy configuration** – Documents user and WinHTTP proxy settings, praising direct access and flagging configured proxies to explain unexpected traffic flows.【F:Analyzers/Heuristics/Network/Network.ps1†L2107-L2131】
* **ARP cache integrity** – Detects gateway MAC changes, duplicate or suspicious vendor OUIs, poisoned ARP replies, and hosts impersonating multiple IPs so potential man-in-the-middle attacks are surfaced quickly.【F:Analyzers/Heuristics/Network/Network.ps1†L1620-L1739】
* **Wired 802.1X posture** – Warns when diagnostics are missing, interfaces are unauthenticated or on guest VLANs, highlights insecure MSCHAPv2 use, and raises high/medium issues for missing, expiring, or unreadable machine certificates so wired NAC problems are actionable.【F:Analyzers/Heuristics/Network/Network.ps1†L2135-L2315】
* **Wi-Fi security** – Flags missing wireless data, open or WEP networks, WPA2 networks that still allow TKIP, mixed WPA2/WPA3 transition modes, poor WPA2-Personal passphrase scores, and clients falling back to WPA2 when the AP supports WPA3, while reporting modern WPA3 usage for visibility.【F:Analyzers/Heuristics/Network/Network.ps1†L2318-L2607】
* **DHCP analyzers** – Correlate collector output to detect non-private DHCP servers, adapters that require DHCP but never received leases, profiles with DHCP disabled and no static configuration, scopes nearing exhaustion, stale leases, and frequent DHCP client failures.【F:Analyzers/Heuristics/Network/DHCP/Analyze-DhcpUnexpectedServers.ps1†L21-L61】【F:Analyzers/Heuristics/Network/DHCP/Analyze-DhcpStaticConfiguration.ps1†L35-L56】【F:Analyzers/Heuristics/Network/DHCP/Analyze-DhcpLeaseExpiry.ps1†L24-L76】
* **VPN baselines** – Reviews VPN profiles for deprecated tunnel types, split tunneling, weak MS-CHAPv2 authentication, missing certificates, unused profiles, overlapping routes, misconfigured DNS, unhealthy services, and recurring RasClient/IKEEXT errors while also recording healthy VPN profiles when security criteria are met.【F:Analyzers/Network/Analyze-Vpn.ps1†L211-L451】

### Outlook & Office

* **Outlook cache & data files** – Flags missing inventory and large OST caches so oversized profiles can be remediated quickly.【F:Analyzers/Heuristics/Office.ps1†L78-L117】
* **Autodiscover DNS diagnostics** – Reports missing lookups, unexpected targets, or absent records to highlight onboarding issues for Exchange Online tenants.【F:Analyzers/Heuristics/Network/Network.ps1†L2046-L2083】
* **Macro policies** – Detects when MOTW blocking or macro notification policies are absent, confirms macro blocking when enforced, and marks missing payloads so macro malware exposure is obvious.【F:Analyzers/Heuristics/Office.ps1†L9-L77】
* **Protected View** – Raises issues whenever Protected View is disabled or data is missing to ensure untrusted Office documents are opened safely.【F:Analyzers/Heuristics/Office.ps1†L118-L147】

### Security

* **Microsoft Defender** – Tracks Defender status, recent detections, tamper protection, cloud-delivered protection, and payload collection gaps to highlight antivirus health or praise compliant baselines.【F:Analyzers/Heuristics/Security.ps1†L237-L373】
* **BitLocker** – Surfaces missing artifacts, command failures, unprotected volumes, incomplete encryption, absent recovery passwords, and healthy TPM-backed protectors so disk encryption posture is explicit.【F:Analyzers/Heuristics/Security.ps1†L407-L575】
* **Measured boot & attestation** – Confirms TPM PCR bindings, Secure Boot confirmation, and attestation events when present, and documents the MDM requirements or data gaps when signals are missing.【F:Analyzers/Heuristics/Security.ps1†L577-L779】
* **TPM, memory integrity, and Credential Guard** – Flags missing or uninitialized TPMs, disabled virtualization-based protection, and absent Credential Guard/LSA protection, while acknowledging healthy configurations.【F:Analyzers/Heuristics/Security.ps1†L781-L890】
* **Kernel DMA, Smart App Control, WDAC, and App Control gaps** – Evaluates DMA protection, Smart App Control state, and Windows Defender Application Control enforcement to expose device control weaknesses or confirm policy enforcement.【F:Analyzers/Heuristics/Security.ps1†L892-L1013】
* **Attack surface policies** – Reviews Attack Surface Reduction rules, Exploit Protection configuration, SmartScreen, NTLM hardening, PowerShell logging, autorun policies, LAPS, local admin membership, firewall profile status, LDAP/NTLM enforcement, and DHCP server hygiene, flagging missing controls and celebrating hardened configurations.【F:Analyzers/Heuristics/Security.ps1†L1015-L1464】

### Active Directory

* **Discovery & connectivity** – Reports missing AD diagnostics, absence of discovered domain controllers, and successful Azure AD join detection.【F:Analyzers/Heuristics/AD.ps1†L9-L40】
* **Secure channel & SYSVOL access** – Flags broken machine secure channels, unreachable domain shares, and successful verification findings.【F:Analyzers/Heuristics/AD.ps1†L41-L78】
* **DNS, time, and Group Policy** – Highlights DNS SRV lookup failures, public resolvers on domain clients, Kerberos time skew, manual NTP configuration, Group Policy processing failures, and records healthy DNS/time/GPO posture when all checks pass.【F:Analyzers/Heuristics/AD.ps1†L15-L72】

### Services

* **Artifact collection** – Raises a high-severity issue when the baseline or fallback service inventory cannot be loaded so technicians know to recollect data.【F:Analyzers/Heuristics/Services.ps1†L260-L315】
* **Critical service probes** – Audits Windows Search, DNS Client, Network Location Awareness, Workstation, Print Spooler, RPC, WinHTTP Auto Proxy, BITS, and Office Click-to-Run services, emitting issues for missing entries, disabled or stopped services, manual misconfigurations, and praising healthy baselines with per-service evidence.【F:Analyzers/Heuristics/Services/Services.Checks.ps1†L1-L335】
* **Automatic service outages** – Summarizes non-running automatic services and collection errors so outages surface alongside remediation clues.【F:Analyzers/Heuristics/Services.ps1†L316-L400】

### Event log heuristics

* **Authentication & Netlogon** – Spots Kerberos pre-authentication failures, account lockouts, and secure channel or domain join errors by mining event logs, raising issues when thresholds are exceeded and confirming healthy synchronization otherwise.【F:Analyzers/Heuristics/Events.ps1†L735-L906】【F:Analyzers/Heuristics/Events.ps1†L1293-L1426】
* **DNS & VPN noise** – Surfaces DNS timeout bursts and VPN authentication or IKE failures so transient outages appear in the report.【F:Analyzers/Heuristics/Events.ps1†L311-L461】【F:Analyzers/Heuristics/Events.ps1†L1107-L1252】

### Printing

* **Collection & spooler state** – Flags missing collection artifacts, unreadable payloads, and spooler service issues while recording checks for spooler status and startup configuration.【F:Analyzers/Heuristics/Printing.ps1†L82-L144】
* **Printer queues & health** – Reports offline default printers, stuck jobs, WSD ports, weak SNMP communities, connectivity failures, and quiet healthy queues with checks summarizing queue metrics.【F:Analyzers/Heuristics/Printing.ps1†L148-L229】
* **Print event volume** – Counts PrintService Admin/Operational log warnings and errors, escalating when noisy and recording quiet logs as checks.【F:Analyzers/Heuristics/Printing.ps1†L187-L211】

### Hardware

* **Driver inventory** – Raises informational gaps when driver artifacts are missing or unreadable, correlates driver status and start modes with Device Manager evidence, and acknowledges healthy drivers when no issues are raised.【F:Analyzers/Heuristics/Hardware/InvokeHardware.ps1†L1-L160】
* **Problem devices** – Calls out missing drivers (Code 28) and generic Device Manager problem states with the parsed evidence so failing hardware is easy to locate.【F:Analyzers/Heuristics/Hardware/InvokeHardware.ps1†L161-L210】

### Storage

* **Collection gaps** – Warns when storage inventories or SMART snapshots are missing so collectors can be rerun.【F:Analyzers/Heuristics/Storage.ps1†L419-L423】
* **Disk & volume health** – Aggregates degraded disk states, unreadable inventories, and per-volume capacity checks to emit issues at the worst observed severity while publishing checks for each volume.【F:Analyzers/Heuristics/Storage.ps1†L208-L307】
* **SMART wear & status** – Flags missing SMART data, per-disk wear nearing end of life, healthy wear percentages, and explicit SMART failure keywords to prioritize disk replacements.【F:Analyzers/Heuristics/Storage.ps1†L317-L410】

