# Collector Scripts

The collector layer captures raw diagnostics from Windows endpoints and writes the results to JSON so analyzers can parse them deterministically. Each folder beneath `Collectors` groups scripts by topic (for example, `Network`, `Security`, `System`, `Services`).

## Running collectors

- **Run everything:** `Collectors/Collect-All.ps1` discovers every `Collect-*.ps1` script under this directory, executes them, and drops JSON into per-area subfolders (`output/Network`, `output/Security`, etc.).
- **Run a single collector:** Execute the script directly and supply an `-OutputDirectory` if you do not want to use the default timestamped folder. Example:
  ```powershell
  powershell.exe -ExecutionPolicy Bypass -File .\Collectors\Network\Collect-Network.ps1 -OutputDirectory C:\Temp\Diag\Network
  ```
- **Automation:** Because each collector writes JSON, they can be orchestrated by other tools (scheduled tasks, RMM agents, etc.) without relying on the analyzer.

## JSON envelope

Every collector imports `CollectorCommon.ps1`, which enforces a shared schema when saving files. The helper wraps each payload with metadata and writes UTF-8 JSON:

```json
{
  "CollectedAt": "2024-03-01T15:23:45.1234567Z",
  "Payload": {
    "IpConfig": ["Windows IP Configuration", "..."],
    "Route": ["===========================================================================", "..."],
    "Errors": [{ "Source": "netstat.exe", "Error": "Access denied" }]
  }
}
```

Key conventions:

- `CollectedAt` is an ISO-8601 timestamp for traceability.
- `Payload` is an ordered object whose properties are specific to the collector.
- Command failures or missing tooling should be represented as objects with `Source` and `Error` properties so the analyzer can highlight data gaps.
- Arrays preserve native command ordering. Leave raw text intact and let the analyzer normalize it later.

## File naming

- Use clear, unique filenames (for example, `network.json`, `dns.json`, `defender.json`).
- The analyzer lowercases base filenames to build lookup keys, so avoid duplicates across folders.
- When a collector naturally produces multiple logical payloads, prefer splitting them into separate scripts/files instead of deeply nested structures.

## Adding a new collector

1. Create a new `Collect-<Name>.ps1` script inside the appropriate domain folder.
2. Import `CollectorCommon.ps1` and gather data with native commands or CIM queries.
3. Use `New-CollectorMetadata -Payload $payload` to stamp metadata.
4. Export the JSON with `Export-CollectorResult -OutputDirectory $OutputDirectory -FileName '<name>.json' -Data $result`.
5. Update the relevant analyzer (see `/Analyzers/README.md`) so the new JSON is parsed and surfaced in the HTML report.

## Output summary

`Collect-All.ps1` also writes `collection-summary.json` at the root of the output directory. This file captures:

- The overall output location.
- The timestamp of the run.
- A per-script record including full path, success flag, returned value (often the JSON path), and any error message.

This summary is useful for automation pipelines to verify that every collector succeeded before invoking the analyzer.
