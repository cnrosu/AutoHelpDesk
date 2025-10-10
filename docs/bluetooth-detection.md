## Summary
The hardware analyzer validates Bluetooth availability by scanning driver and problem-device inventories for known radio indicators. When no evidence of a Bluetooth stack appears, AutoHelpDesk raises a warning to show technicians the data sources it evaluated. Understanding the logic helps teams defend against false positives and gather proof when adapters truly are missing or unhealthy.

## Signals to Collect
- `driverquery /v /fo csv | ConvertFrom-Csv | Where-Object { $_.Description -match 'Bluetooth' }` → Enumerate drivers with Bluetooth indicators.
- `Get-PnpDevice -Class Bluetooth, Net | Select-Object FriendlyName, Status, ProblemCode` → Confirm Windows detects a Bluetooth-class device.
- `Get-Service -Name bthserv | Select-Object Name, Status, StartType` → Verify the Bluetooth Support Service health when adapters exist.

## Detection Rule
- Parse driver inventory and mark candidates when the description, service name, or binary name contains `Bluetooth` or known vendor prefixes (`BTH`, `IBT`, `QCBT`, `BTATH`).
- Flag a **warning** card when neither driver inventory nor PnP problem devices contain Bluetooth indicators, including evidence summarizing the counts inspected.
- Escalate to **high severity** when a Bluetooth device is found but reports error states or stopped automatic services.

## Heuristic Mapping
- `Hardware.Bluetooth`

## Remediation
1. Install or update the OEM Bluetooth driver package so the adapter exposes a Bluetooth class device and loads an appropriate driver.
2. Restart or set the **Bluetooth Support Service (bthserv)** to Automatic if service health caused the issue card.
3. Re-run AutoHelpDesk hardware collectors to confirm the driver inventory now includes Bluetooth indicators.

## References
- `docs/bluetooth-detection.md`

# Bluetooth adapter detection heuristic

The hardware analyzer infers whether a Bluetooth radio is available by scanning the
`driverquery` inventory that ships with diagnostic packages. A driver is considered a
Bluetooth indicator when any of the following strings are present in the metadata we
collect for that driver:

- The literal word `Bluetooth` (case-insensitive).
- Driver, service, or module names that start with common vendor prefixes such as
  `BTH`, `IBT`, `QCBT`, or `BTATH`.

If none of the driver entries or PnP problem-device records match those indicators we
raise the "Bluetooth adapter not detected" warning. The heuristic now attaches
troubleshooting evidence that lists how many entries were scanned in each source and
confirms which indicator set was checked. This makes it clear to technicians why the
warning fired and what data was examined during detection.

When a Bluetooth driver is discovered, the analyzer continues to evaluate its health:
we flag stopped automatic services, error states, or PnP problem codes, and otherwise
report the adapter as working normally.
