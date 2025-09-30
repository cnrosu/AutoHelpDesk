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

The analyzer orchestrator currently ships with the categories below. Each summary reflects the logic implemented in `Analyzers/Heuristics`, keeping the focus on what the current PowerShell code actually evaluates.

### System
* Checks operating system support status, Secure Boot reporting, and collects hardware inventory details from `system.json`.
* Reviews Fast Startup configuration and records when the setting is enabled or cannot be queried.
* Aggregates pending reboot indicators, pending file rename operations, and hostname change state so reboot requirements are surfaced.
* Counts Autoruns/startup entries and highlights large volumes of non-Microsoft startup programs.
* Samples memory utilisation/top CPU processes and flags sustained uptimes over 30 days while noting recent reboots.

### Network & Connectivity
* Collates adapter data from `ipconfig /all` and `route print`, warning when no IPv4 configuration or default route is present in the collected output.
* Evaluates DNS client configuration for missing servers, pseudo/adapted interfaces, use of public resolvers, and disabled registrations.
* Summarises DNS lookup failures, ping latency results against resolvers, and Outlook HTTPS connectivity tests.
* Consumes autodiscover DNS results to confirm Exchange Online targets and rolls up findings from DHCP-specific analyzers when matching artifacts are present.
* Records proxy configuration evidence from WinHTTP and user settings when available.

### Office
* Reads Office policy artifacts to confirm macro blocking, trust bar notifications, and Protected View settings.
* Highlights oversized OST files and local Outlook cache folders.
* Validates autodiscover DNS lookups for each collected domain and reports failures or unexpected targets.

### Security
* Tracks Microsoft Defender status, tamper protection, cloud-delivered protection, signature freshness, and recent threat detections.
* Reviews Windows Firewall profile state, BitLocker volume protection, and the presence of recovery password protectors.
* Checks TPM availability/readiness and Kernel DMA registry/device guard status.
* Audits Attack Surface Reduction rules, Exploit Protection mitigations, Windows Defender Application Control posture, and Smart App Control state.
* Confirms LAPS/PLAP policy application, Credential Guard with LSA protection, and virtualization-based security (memory integrity) coverage.
* Evaluates UAC configuration, PowerShell logging policies, and NTLM hardening registry keys; reports when required data is missing.

### Active Directory
* Confirms domain join state and records the joined domain when present.
* Assesses SRV record discovery, `nltest` output, and secure channel evidence to ensure domain controllers are reachable.
* Reviews SYSVOL/NETLOGON share tests, required port connectivity, and captures discovery errors for escalation.

### Storage
* Parses SMART status output, SSD wear metrics, and device temperature readings when available.
* Aggregates disk health states, per-volume warnings, and free-space thresholds to surface capacity risks.
* Emits informational issues when SMART data or storage collectors fail to return structured payloads.

### Services
* Loads collected service inventory and flags missing or stopped Windows Search, DNS Client, NLA, Workstation, RPC, Print Spooler, and related baseline services with platform-aware severity.
* Notes manual start modes, proxy-dependent services, and collection gaps so technicians can reconcile the run results.

### Events
* Tallies recent error and warning counts for the System, Application, and Group Policy Operational logs, warning when thresholds are exceeded or when logs cannot be read.

### Printing
* Reports spooler service state, offline printers, stale queue jobs, printers using WSD ports, and PrintService event volume while recording collection errors when data is incomplete.

