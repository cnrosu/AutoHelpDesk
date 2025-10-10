## Summary
The hardware analyzer validates Bluetooth availability by scanning driver and problem-device inventories for known radio indicators. When no evidence of a Bluetooth stack appears, AutoHelpDesk raises a warning to show technicians the data sources it evaluated. Understanding the logic helps teams defend against false positives and gather proof when adapters truly are missing or unhealthy.

## Signals to Collect
- `Get-PnpDevice -Class Bluetooth -Status OK,Error,Degraded` → Enumerate Bluetooth adapters that are present, failing, or degraded.
- `Get-Service bthserv` → Confirm the Bluetooth Support Service state and startup mode.
- **Optional:** `Get-ItemProperty HKLM:\SOFTWARE\Policies\Microsoft\Windows\Bluetooth\*` → Capture baseline policies that may require or forbid Bluetooth support.

## Detection Rule
- **AdapterMissingOrDisabled (Low)**: Trigger when no adapter is reported **or** the Bluetooth Support Service is stopped while policy expects it to be enabled. Elevate to **Medium** if the policy baseline explicitly requires Bluetooth to remain enabled.
- **PolicyConflict (Medium)**: Trigger when organizational policy disables Bluetooth but an adapter and/or service is still running, indicating a configuration mismatch with the baseline.

## Heuristic Mapping
- `Hardware/Bluetooth/AdapterMissingOrDisabled`
- `Hardware/Bluetooth/PolicyConflict`

## Remediation
1. If Bluetooth support is required, install or update OEM drivers, enable the adapter in Device Manager, and set **bthserv** to the expected startup state.
2. If Bluetooth is forbidden by baseline policy, disable the adapter and set **bthserv** according to the policy to resolve the mismatch.
3. Re-run AutoHelpDesk hardware collectors to verify the adapter, service, and policy states now align with the organizational requirement matrix.

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
