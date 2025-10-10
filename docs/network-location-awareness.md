# Network Location Awareness heuristic

## Data sources
- **Collector:** [`Collectors/Services/Collect-ServiceBaseline.ps1`](../Collectors/Services/Collect-ServiceBaseline.ps1) records the `Status`, `StartType`, and existence of core Windows services, including `NlaSvc`.
- **Lookup helper:** The analyzer retrieves this information via `Get-ServiceStateInfo`, which exposes normalized `Exists`, `StatusNormalized`, and `StartModeNormalized` fields for consistent comparisons across OS versions.

## Interpretation logic
1. If the `NlaSvc` entry is missing from the collected baseline, the heuristic raises a **high-severity** issue because Windows cannot detect network profiles without the service.
2. When the service exists and reports `running`, the heuristic records a normal outcome with the live status and start mode for auditing.
3. Any other state produces an issue:
   - **Manual + stopped (workstations only):** flagged as **medium severity**. Laptops and desktops need continuous profile detection for firewall, proxy, and VPN handoffs, which manual start undermines.
   - **Stopped or disabled (all other cases):** flagged as **high severity**, as the machine cannot detect or react to network changes.

## Issue cards
| Title | Severity | Impact | Recommended remediation |
| --- | --- | --- | --- |
| Network Location Awareness service missing — network profile detection will fail | High | Without NLA, Windows cannot recognize networks, leading to incorrect firewall rules, VPN profiles, and location-based policies. | Restore the `NlaSvc` service definition (e.g., `sc create` from a healthy system or run `sfc /scannow`), then start the service and confirm dependencies exist. |
| Network Location Awareness service not running — network profile detection is broken | High | A stopped or disabled NLA service prevents Windows from reacting to network changes, breaking firewall, VPN, and proxy automation. | Set the service to Automatic and start it (`Set-Service -Name NlaSvc -StartupType Automatic; Start-Service -Name NlaSvc`), then verify it remains running. |
| Network Location Awareness manual and stopped — network profile changes will go undetected | Medium | Manual start leaves profile detection dormant until another service triggers it, so laptops/desktops miss network changes that adjust firewall and proxy settings. | Configure the service for Automatic start and ensure it remains running, especially on roaming workstations. |

## Notes
- The heuristic currently differentiates workstation behavior through the `IsWorkstation` flag passed from the calling analyzer. Servers default to high severity when the service is not running because they commonly host features reliant on profile detection (e.g., DirectAccess, firewall policies).
- Evidence strings echo the collected `Status` and `StartType` fields so technicians can confirm telemetry against live values.
