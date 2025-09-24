# Device Health Diagnostics Toolkit

## Elevator Pitch
A three-script PowerShell toolchain where a single orchestrator script collects a full diagnostic snapshot, runs heuristic analysis against the results, and produces a single Device Health HTML report that highlights health, red flags, and supporting evidence for rapid L1/field triage.

## Script Overview

### Device-Report.ps1 (Orchestrator)
- **Purpose**: One-button experience that collects diagnostics (when needed), analyzes them, and opens the Device Health report.
- **Workflow**:
  1. If `-InputFolder` is not provided, runs the collector to create a fresh timestamped folder under the chosen output root.
  2. Passes the newest collection folder to the analyzer.
  3. Opens the generated Device Health HTML report and writes its path to stdout.
- **Inputs**:
  - `-OutRoot` (optional): base folder for new collections (defaults to `Desktop\DiagReports`).
  - `-InputFolder` (optional): analyze an existing collection without re-running the collector.
- **Outputs**: Launches `DeviceHealth_Report_<timestamp>.html` in the default browser.

### Collect-SystemDiagnostics.ps1 (Collector)
- **Purpose**: Run safe, read-only commands to snapshot system state into discrete text files.
- **Operation**:
  - Executes networking, OS, storage, services, security, and event log commands via the `Save-Output` helper.
  - Writes each command's output to its own `.txt` file inside a timestamped folder.
  - Generates a lightweight `summary.json` and optional basic `Report.html` for raw viewing.
- **Inputs**:
  - `-OutRoot` (optional): base folder for collection output (defaults to `Desktop\DiagReports`).
  - `-NoHtml` (optional): skip building the basic HTML viewer.
- **Outputs**:
  - New folder: `DiagReports\<YYYYMMDD_HHMMSS>\` containing many `.txt` files (e.g., `ipconfig_all.txt`, `route_print.txt`, `Firewall.txt`, etc.), plus `summary.json` and `Report.html`.
- **Key Tools**: `ipconfig`, `route`, `netstat`, `ping`, `nslookup`, `wevtutil`, `Get-CimInstance`, `Get-Volume`, `Get-Disk`, and similar built-ins.
- **Why individual files?**: Keeps each data source isolated for resilient parsing and straightforward manual inspection.

### Analyze-Diagnostics.ps1 (Analyzer)
- **Purpose**: Parse the collected artifacts, run heuristics, and build the Device Health HTML report.
- **Operation**:
  - Locates required files by filename hints and content signatures using `Find-ByContent`.
  - Parses IPv4/gateway/DNS, OS details, last boot, connectivity checks, security posture, firewall status, event log samples, and service state via regex-driven extractors.
  - Applies heuristic rules to flag common L1 issues and assigns penalty-based severities that roll into a health score.
  - Produces an enriched HTML report with summary, issue table, evidence snippets, and selected raw excerpts.
- **Inputs**:
  - `-InputFolder` (required): exact path to a collector output folder.
- **Outputs**:
  - `DeviceHealth_Report_<YYYYMMDD_HHMMSS>.html` saved in the same folder.
- **Scoring Model**:
  - Severity weights: Critical = 10, High = 6, Medium = 3, Low = 1, Info = 0.
  - Penalties subtract from 100 with caps to avoid bottoming out unnecessarily.
- **Sample Heuristics**:
  - **Network**: Missing IPv4, APIPA addresses, absent default routes, failed pings or DNS lookups, inappropriate public DNS for corporate networks.
  - **Security**: Defender real-time protection disabled or signatures older than seven days.
  - **Firewall**: Any profile disabled (especially Public).
  - **Events & Services**: High error/warning counts or critical services (Dhcp, Dnscache, LanmanWorkstation/Server, WlanSvc, WinDefend) stopped.

## Typical Usage
```powershell
Set-ExecutionPolicy -Scope Process Bypass -Force
./Device-Report.ps1
```
1. Collector creates `Desktop\DiagReports\<timestamp>\` with all raw outputs.
2. Analyzer writes `DeviceHealth_Report_<timestamp>.html` into the same folder.
3. Device-Report opens the Device Health report automatically.

## Extensibility
- **Collector**: Add or remove commands by inserting new `Save-Output "Name" { <command> }` calls.
- **Analyzer**:
  - Update `Find-ByContent` needles when file naming conventions change.
  - Add new parser logic that consumes entries from the `$raw` hashtable and calls `Add-Issue`.
  - Extend the HTML with additional sections (e.g., disk health, Wi-Fi metrics).
- **Scoring & Heuristics**: Replace the additive penalty model with category weighting or new rules for disk space, Wi-Fi signal, driver versions, application inventory, etc.

## Assumptions & Limitations
- Designed for Windows 10/11 (Home or Pro); run in elevated PowerShell for fullest data access.
- Output parsing assumes English-language command results; localization requires additional regex patterns.
- Collector and analyzer rely on built-in tools—no RSAT or external modules required.

## Artifact Map
- **Collector Outputs**: `ipconfig_all.txt`, `route_print.txt`, `netstat_ano.txt`, `arp_table.txt`, `nslookup_google.txt`, `tracert_google.txt`, `ping_google.txt`, `OS_CIM.txt`, `ComputerInfo.txt`, `Firewall*.txt`, `DefenderStatus.txt`, event log samples, services/processes/drivers snapshots, disk/volume listings, program inventories, `whoami`, `ScheduledTasks.txt`, `TopCPU.txt`, `Memory.txt`, `summary.json`, `Report.html`.
- **Analyzer Output**: `DeviceHealth_Report_<timestamp>.html`.

## Safe Modification Points
- Collector command list.
- Analyzer file needles, parsers, issue logic, HTML formatting.
- Device-Report defaults (e.g., `-OutRoot`) and newest-folder selection logic.
