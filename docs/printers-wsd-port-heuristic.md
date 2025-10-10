# Printers using WSD ports heuristic

**Impact (for issue card): A workstation bound to a WSD queue may intermittently lose printing until someone reinstalls the printer on a reliable TCP/IP port.**

## Data sources

- **Collector:** `Collectors/Services/Collect-Printing.ps1` queries `Get-Printer`, `Get-PrinterPort`, and `Get-PrinterDriver` to build the printer inventory emitted to the analyzer payload.
- **Connection metadata:** For each printer, `Get-PrinterPort` properties (especially `PortMonitor`, `PrinterHostAddress`, and `Name`) are normalized into a `Connection` object with a `Kind` classification such as `WSD`, `DirectIp`, or `ServerQueue`.
- **Analyzer input:** `Analyzers/Heuristics/Printing/Inventory.ps1` loads the normalized printer array and checks each printer's `Connection.Kind` value.

## Heuristic behavior

1. The collector captures every installed printer, associated port information, and driver metadata. During normalization, any port whose monitor string contains `WSD` is tagged with the `WSD` connection kind.
2. The printing inventory heuristic iterates the normalized printer list and records names whose `Connection.Kind` is `WSD`.
3. When one or more printers match, the analyzer issues a low-severity finding titled **"Printers using WSD ports"**. The evidence reminds technicians that WSD transports are less predictable than dedicated TCP/IP ports in enterprise networks.

## Remediation guidance

- Reconfigure affected printers to use a Standard TCP/IP or IPP port instead of WSD so the client keeps a persistent socket to the print device.
- Audit Group Policy Preferences, provisioning scripts, or OEM installers that may auto-create WSD queues and adjust them to deploy TCP/IP definitions.
- Remove stale WSD queues after migration so users only see the supported printer objects.
