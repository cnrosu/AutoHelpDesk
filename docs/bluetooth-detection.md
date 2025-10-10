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
