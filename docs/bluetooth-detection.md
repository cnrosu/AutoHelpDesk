## Summary
The hardware analyzer now validates Bluetooth availability by asking Windows for a live radio inventory and the Bluetooth Support Service status. When no healthy USB radio is enumerated or the service is stopped, AutoHelpDesk raises guidance that explains what was checked. Understanding the logic helps teams defend against false positives and gather proof when adapters truly are missing or unhealthy.

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

The hardware analyzer evaluates Bluetooth by replaying the following one-liner against the collected payload: `if ((Get-Service bthserv).Status -eq 'Running' -and (Get-PnpDevice -Class Bluetooth | Where-Object { $_.InstanceId -like 'USB\VID*' -and $_.Status -eq 'OK' })) { 'YES' } else { 'NO' }`. Any "NO" outcome generates a technician-facing issue that includes the service status plus the enumerated radios so the real-world impact is obvious. If the query itself fails, the analyzer reports that the device or service snapshot was unavailable so technicians know the limitation came from collection rather than the endpoint.
