## Summary
AutoHelpDesk now validates Bluetooth availability by reviewing every device in the Windows Bluetooth PnP class and confirming at least one healthy radio or enumerator is present. The analyzer still records the Bluetooth Support Service state plus optional PAN and USB context so technicians see exactly which subsystems were inspected. This approach avoids false warnings on systems where vendors expose radios through PCIe, CNVi, or virtual enumerators instead of USB.

## Signals to Collect
- `Get-PnpDevice -Class Bluetooth` → Enumerate Bluetooth-class radios, enumerators, and related services regardless of bus type.
- `Get-Service bthserv` → Confirm the Bluetooth Support Service state and startup mode.
- **Optional:** `Get-ItemProperty HKLM:\SOFTWARE\Policies\Microsoft\Windows\Bluetooth\*` → Capture baseline policies that may require or forbid Bluetooth support.

## Detection Rule
- **Warning – Bluetooth adapter not detected**: Raised when no healthy Bluetooth-class radios or enumerators appear in the PnP snapshot, so pairing is unlikely to work.
- **High – Bluetooth adapter detected but reports errors**: Raised when a Bluetooth-class radio or enumerator returns a non-OK status or active problem code, indicating the stack is unhealthy.
- **High – Bluetooth adapter detected but support service is not running**: Raised when healthy radios exist but the Bluetooth Support Service is stopped, so accessories cannot connect.

## Heuristic Mapping
- `Hardware/Bluetooth` (subcategory **Bluetooth**) issues covering adapter absence, adapter errors, and service stoppage.

## Remediation
1. If Bluetooth support is required, install or update OEM drivers, enable the adapter in Device Manager, and set **bthserv** to the expected startup state.
2. If Bluetooth is forbidden by baseline policy, disable the adapter and set **bthserv** according to the policy to resolve the mismatch.
3. Re-run AutoHelpDesk hardware collectors to verify the adapter, service, and policy states now align with the organizational requirement matrix.

## References
- `docs/bluetooth-detection.md`

# Bluetooth adapter detection heuristic

The hardware analyzer now evaluates Bluetooth availability with the following steps:

```
$btPnP = Get-PnpDevice -Class Bluetooth
$btHealthy = $btPnP | Where-Object { $_.Status -eq 'OK' }
$radioLike = $btHealthy | Where-Object {
    $_.Name -match 'Bluetooth' -and
    ($_.Name -match 'Intel|Qualcomm|Realtek|MediaTek|Broadcom|Adapter|Radio' -or
     $_.Name -match 'Enumerator')
}
$hasRadio = $radioLike.Count -gt 0
```

If `$hasRadio` is false, the analyzer emits a warning that pairing is blocked; otherwise it checks for error states or a stopped **bthserv** service before declaring success. Evidence always lists the healthy PnP device names, enumerator status, service state, and USB counts so technicians understand how the decision was made. If the underlying data collection fails, the analyzer still raises an informational card explaining which snapshot was missing.
