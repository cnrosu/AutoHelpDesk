# Device Health Diagnostics Toolkit

## Elevator Pitch
A three-script PowerShell toolchain where a single orchestrator script collects a full diagnostic snapshot, runs heuristic analysis against the results, and produces a single Device Health HTML report that highlights health, red flags, and supporting evidence for rapid L1/field triage.

## Script Overview

### Device-Report.ps1 (Orchestrator)
- **Purpose**: One-button experience that runs the shared collectors, executes the analyzer, and opens the Device Health report.
- **Elevation required**: The script enforces `Run as Administrator` via `Assert-Admin` to guarantee the collectors can reach Defender, event log, and networking data.
- **Workflow**:
  1. If `-InputFolder` is not provided, invokes `Collectors/Collect-All.ps1` to emit JSON artifacts into a fresh timestamped folder under the chosen output root.
  2. Feeds that folder to `Analyzers/Analyze-Diagnostics.ps1`, which reads every artifact and produces the HTML report.
  3. Opens the generated Device Health HTML report and writes its path to stdout.
- **Inputs**:
  - `-OutRoot` (optional): base folder for new collections (defaults to `%USERPROFILE%\Desktop\DiagReports`).
  - `-InputFolder` (optional): analyze an existing collection without re-running the collector.
- **Outputs**: Launches `diagnostics-report.html` in the default browser (and returns its resolved path).

### Collectors/Collect-All.ps1 (Collector orchestrator)
- **Purpose**: Run every JSON collector under `/Collectors` and write the results into per-area subfolders.
- **Operation**:
  - Discovers `Collect-*.ps1` scripts, ensures the run folder exists, and executes each collector with a shared output contract.
  - Produces `collection-summary.json` so automations can verify success/failure per script.
- **Inputs**:
  - `-OutputRoot` (optional): folder that will receive the area subfolders (`Network`, `Security`, etc.).
- **Outputs**:
  - Collector output written under the folder supplied to `-OutputRoot`. When `Device-Report.ps1` launches the collector it passes a timestamped directory (for example, `DiagReports\<YYYYMMDD_HHMMSS>\Network\network.json`).
- **Why JSON artifacts?**: Analyzers can deterministically parse payloads without relying on regex heuristics against raw text files.

### Collect-SystemDiagnostics.ps1 (Legacy collector)
- **Purpose**: Original text-file collector retained for backwards compatibility and ad-hoc investigations.
- **Note**: Device-Report no longer calls this script. Prefer `Collectors/Collect-All.ps1` for end-to-end workflows so the analyzer receives structured JSON.

### Analyzers/Analyze-Diagnostics.ps1 (Analyzer)
- **Purpose**: Load collector artifacts, run modular heuristics, and build the Device Health HTML report.
- **Operation**:
  - Imports `AnalyzerCommon.ps1`, loads every JSON payload, and invokes category-specific heuristic modules.
  - Calculates scores, merges issues/normals/checks, and renders HTML via `HtmlComposer.ps1`.
- **Inputs**:
  - `-InputFolder` (required): path to the collector output folder created by `Collect-All.ps1`.
  - `-OutputPath` (optional): override the default `diagnostics-report.html` destination.
- **Outputs**:
  - HTML report plus flattened issue/normal/check collections returned to the caller.
- **Artifact Contract**:
  - Assumes each collector writes an ISO-8601 `CollectedAt` stamp and a `Payload` object to JSON via `CollectorCommon.ps1`.
  - Uses lowercase base filenames as lookup keys so heuristics can locate data deterministically.
- **Sample Heuristics**:
  - **Network**: Missing IPv4, APIPA addresses, absent default routes, failed pings or DNS lookups, inappropriate public DNS for corporate networks.
  - **Security**: Defender real-time protection disabled or signatures older than seven days.
  - **Services**: Flag stopped critical services (Dhcp, Dnscache, LanmanWorkstation/Server, WlanSvc, WinDefend).
  - **Storage & Events**: Highlight low disk space and noisy event logs.

## Styling conventions
- Global foundations live in `styles/base.css` (design tokens/resets) and `styles/layout.css` (reusable layout helpers).
- Report-specific presentation lives alongside shared assets inside `styles/` (e.g., `device-health-report.css`, `system-diagnostics-report.css`).
- Use simple, BEM-like class names (e.g., `.report-card`, `.report-card--critical`) and keep selectors low in specificity.
- When editing CSS, order declarations per block as **layout → typography → color → state** to keep files scannable.
- Each HTML report links a single combined stylesheet per page; keep additions lean so reports stay fast to load offline.

## Typical Usage
```powershell
Set-ExecutionPolicy -Scope Process Bypass -Force
Set-Location .\AutoL1
Start-Process powershell.exe -Verb RunAs -ArgumentList '-ExecutionPolicy Bypass -NoProfile -File .\\Device-Report.ps1'
# …or run the script from an already elevated session:
./Device-Report.ps1
```
The snippet above assumes you start in the repository root. Adjust the path in `Set-Location` if you have copied the toolkit elsewhere.
1. Collector creates `Desktop\DiagReports\<timestamp>\` with JSON artifacts grouped by area (`Network`, `Security`, etc.).
2. Analyzer writes `diagnostics-report.html` into the same folder.
3. Device-Report opens the Device Health report automatically.

## Relationship to shared collectors/analyzers

- The `/Collectors` folder stores the reusable JSON collectors that Device-Report invokes when a fresh run is required. You can execute an individual collector (for example, `Collectors/Network/Collect-Network.ps1`) to produce a single artifact for experimentation.
- The `/Analyzers` folder contains the heuristic modules called by `Analyzers/Analyze-Diagnostics.ps1`. When a new collector is added to `/Collectors`, update or extend the appropriate analyzer module (Network, System, Security, etc.) so it understands the new payload.
- Device-Report glues the two pieces together, ensuring the collection output folder supplied to the analyzer matches the structure described above.

## Extensibility
- **Collectors**: Add or remove collector scripts under `/Collectors/<Area>/`. Each script should import `CollectorCommon.ps1`, gather data, and export JSON with `New-CollectorMetadata` + `Export-CollectorResult`.
- **Analyzers**:
  - Extend or create heuristic modules under `/Analyzers/Heuristics/` to parse new payloads.
  - Update `Analyzers/Analyze-Diagnostics.ps1` to import the module when adding a new category.
  - Customize `HtmlComposer.ps1` for new presentation needs.
- **Scoring & Heuristics**: Tweak severity weights or add category-specific scoring inside the heuristic modules.

## Assumptions & Limitations
- Designed for Windows 10/11 (Home or Pro); run in elevated PowerShell for fullest data access.
- Output parsing assumes English-language command results; localization requires additional regex patterns.
- Collector and analyzer rely on built-in tools—no RSAT or external modules required.

## Artifact Map
- **Collector Outputs**: JSON artifacts written under area subfolders (for example, `Network/network.json`, `Security/defender.json`, `System/system.json`) plus `collection-summary.json` at the run root.
- **Analyzer Output**: `diagnostics-report.html` alongside merged issue/normal/check collections returned to callers.

## Safe Modification Points
- Collector scripts and shared helpers under `/Collectors`.
- Analyzer heuristic modules, HTML composer, and severity logic under `/Analyzers`.
- Device-Report defaults (e.g., `-OutRoot`) and collection/orchestration logic.
