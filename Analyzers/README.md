# Analyzer Modules

The analyzer layer ingests collector JSON artifacts, evaluates heuristic rules, and produces HTML/device health summaries. Scripts in this folder are designed to be run from PowerShell 5.1+ on Windows but do not require elevation when reading offline data.

## Entry point

- **`Analyze-Diagnostics.ps1`** – Accepts an `-InputFolder` that points at a collector output tree. It imports shared helpers, loads every `*.json` file, runs heuristic modules per category, and writes an HTML report (`diagnostics-report.html` by default).
- Optionally pass `-OutputPath` to control the destination of the HTML report. The command returns an object containing the resolved HTML path (`HtmlPath`) and flattened collections of issues, normals, and checks for automation scenarios. The script also merges shared CSS into `<output>\styles\device-health-report.css` so the report is self-contained.

Example:
```powershell
powershell.exe -ExecutionPolicy Bypass -File .\Analyzers\Analyze-Diagnostics.ps1 -InputFolder C:\Temp\Diag\20240301
```

## Loading artifacts

`AnalyzerCommon.ps1` defines helper functions that every heuristic uses:

- `New-AnalyzerContext -InputFolder <path>` walks the input tree, loads all JSON, and indexes artifacts by lowercase base filename.
- `Get-AnalyzerArtifact -Context $context -Name 'network'` returns the parsed artifact (or all matches when duplicates exist).
- `Get-ArtifactPayload` unwraps the `Payload` object the collector stored so heuristics work with the raw data.
- `New-CategoryResult`, `Add-CategoryIssue`, `Add-CategoryNormal`, and `Add-CategoryCheck` maintain consistent shapes for analyzer output.
- `Merge-AnalyzerResults` collapses all category objects into one set of issues/normals/checks for reporting.

### Category and subcategory labeling

`New-CategoryResult` just creates an object that holds the cards for a single analyzer category. It contains three empty lists: one each for issue cards, normal cards, and health checks. Calling `Add-CategoryIssue` or `Add-CategoryNormal` simply appends a new card into the appropriate list on that object. Every card stores the title, severity (for issues), the evidence snippet, and any optional flags such as `-Subcategory` or `-CheckId`.

Because of that split, heuristics only have to say "this finding belongs in **Storage**" once when they call `New-CategoryResult -Name 'Storage'`. Any subcategory text stays attached to the specific card (`Add-CategoryIssue -Subcategory 'SMB Shares'`). When the HTML composer builds the report it walks the category objects, combines the category name with each card's subcategory, and renders the familiar `Category \ Subcategory` label. The composer can also normalize category names (for example mapping `Active Directory Health` to **Active Directory**) without the heuristics needing to know the UI rules. The end result is still the simple Issue/Normal card experience—the helper functions just keep the data grouped until the renderer flattens it for display.

### Expected JSON shape

Analyzers assume each artifact follows the collector contract:

```json
{
  "CollectedAt": "2024-03-01T15:23:45.1234567Z",
  "Payload": {
    "Property": "Value"
  }
}
```

If parsing fails, `New-AnalyzerContext` stores an `Error` property in place of `Payload` so heuristics can emit gap findings. When adding new collectors, ensure the filenames are unique and that payloads contain descriptive property names so heuristics can locate the data they need.

## Heuristic modules

Each category has its own `Invoke-<Category>Heuristics` function under `Analyzers/Heuristics/`. Modules are responsible for:

1. Pulling the relevant payloads via `Get-AnalyzerArtifact`.
2. Translating raw command output into typed data (regex, parsing, property casts, etc.).
3. Determining severity, evidence text, and health checks.
4. Returning a populated category result for the HTML composer.

Available modules:

- `System.ps1`
- `Security.ps1`
- `Network.ps1`
- `AD.ps1`
- `Office.ps1`
- `Storage.ps1`
- `Events.ps1`
- `Services.ps1`
- `Printing.ps1`

Refer to the repository root `README.md` for a full catalogue of heuristic behaviors.

## HTML composition

`HtmlComposer.ps1` accepts the category results and renders:

- A summary tile with score and high-level counts.
- Detailed tables of issues, normal findings, and health checks.
- Embedded evidence snippets sourced from the payloads.

Customize the markup or styling by editing `HtmlComposer.ps1` and the CSS files under `/Scripts/styles/`.

## Extending analyzers

1. **Add a new collector** – ensure it writes JSON following the shared envelope and choose a unique filename.
2. **Update or create a heuristic module** – parse the new payload, emit issues/normals/checks, and add the module import to `Analyze-Diagnostics.ps1` if it is a new category.
3. **Update documentation** – describe the new behavior in the analyzer README and the root heuristic catalogue so future maintainers understand the logic.

Keep heuristics focused on deterministic, repeatable checks. Prefer explicit evidence strings and severity reasoning so technicians can trace every issue back to its data source.
