# OneDrive sync health

## Overview
The OneDrive cloud analyzer helps technicians confirm whether Microsoft 365 file sync is available on a device. It pairs the `cloud-onedrive.json` payload with account and policy context so report consumers understand how local state maps to expected cloud behavior.

## Collector signals
Run [`Collectors/Cloud/Collect-OneDrive.ps1`](../Collectors/Cloud/Collect-OneDrive.ps1) in the signed-in user context so HKCU registry data, account folders, and live processes are readable. The collector records installation source, version, auto-start triggers, running state, signed-in accounts, and Known Folder Backup policies so downstream rules can pinpoint missing prerequisites. When OneDrive is absent or the module cannot be loaded, the payload captures error text instead of silently failing.

## Analyzer outcomes
`Invoke-CloudHeuristics` calls `Invoke-OneDriveHeuristic` to emit impact-focused cards in the **Cloud \ OneDrive** section of the HTML report. The analyzer raises warnings when collection gaps make sync posture unknown, medium issues when the client is missing or stopped, low issues when auto-start is disabled, and informational notices when policy blocks personal sync. It records normal findings when OneDrive is installed, running, and protecting desktop folders via Known Folder Backup so technicians can trust that files reach Microsoft 365 storage.

## Troubleshooting gaps
If the analyzer reports unknown OneDrive health, confirm the collector was run after the user signed in and that antivirus or application control policies allow the module to load. Re-run the collector, then feed the refreshed output back into the analyzer to verify the updated sync state.
