## Summary
The services analyzer tracks the Network Location Awareness (NLA) service because Windows relies on it to classify network profiles and react to connectivity changes. Missing or stopped instances generate high-severity findings, while stopped manual services on workstations are downgraded to medium severity. This document explains the data pipeline and outcomes so technicians can validate or remediate alerts quickly.

## Signals to Collect
- `Get-NetConnectionProfile | Select Name,NetworkCategory,IPv4Connectivity,InterfaceAlias` → Track profile names, categories, and interface bindings that may flap.
- `Get-Service NlaSvc` → Verify the Windows Network Location Awareness service status and start type.
- *(Optional)* `Get-WinEvent "Microsoft-Windows-NlaSvc/Operational" -MaxEvents 200` → Review historical profile transition events when available.

## Detection Rule
- **ProfileFlaps (Medium):** Trigger when the device records three or more network category changes within a 24-hour window (`FlapThreshold24h = 3`) if event history is available, or when the active profile is *Public* while the domain controller remains reachable.
- **ServiceUnhealthy (Medium):** Trigger when the `NlaSvc` service is not running, fails to start, or shows evidence of frequent restarts.

## Heuristic Mapping
- `Network/NLA/ProfileFlaps`
- `Network/NLA/ServiceUnhealthy`

## Remediation
1. Confirm device time synchronization, DNS resolution, and domain controller reachability so NLA can correctly evaluate domain connectivity.
2. Disable or remove conflicting virtual NICs or adapters that repeatedly reset the active network profile.
3. Inspect the `NlaSvc` service for crash loops or manual stoppages and ensure it runs under the expected startup configuration.
4. After applying fixes, re-run the collectors to confirm profile stability and a healthy NLA service state.

## Windows 11 profile evaluation notes
Older troubleshooting guides that recommend editing `ProfileName` keys in `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles` are outdated for Windows 10 and 11.
Windows 11 still bases NLA decisions on the authenticated domain state and the default IPv4/IPv6 routes.
When the default route points to an unauthenticated network, Windows falls back to Public even if the registry is forced.
Technicians should verify domain reachability, gateway health, and credential providers before assuming NLA is broken.
Documenting which route NLA selected helps correlate profile flips with VPN or metered links.

## Supported override options
Use `Set-NetConnectionProfile` to temporarily correct a misclassified interface after confirming the network is trusted.
```powershell
Set-NetConnectionProfile -InterfaceAlias "Ethernet" -NetworkCategory Private
```
Group Policy objects that enforce a firewall profile override the cmdlet within the next background refresh, so coordinate with the domain admin before making the change.
Re-run the collectors after applying the supported override to confirm the profile persisted.

## References
- `docs/network-location-awareness.md`
- Microsoft Learn: [Set-NetConnectionProfile](https://learn.microsoft.com/powershell/module/netconnection/set-netconnectionprofile)

# Network Location Awareness service heuristic

The services analyzer evaluates the Network Location Awareness (NLA) service to confirm
Windows devices can classify network profiles and react to connectivity changes. The
heuristic consumes normalized service inventory, checks whether the host is treated as a
workstation, and emits one of several cards that highlight missing or unhealthy service
states.

## Data sources and normalization steps

- `Collectors/Services/Collect-ServiceBaseline.ps1` enumerates core Windows services and
  records their raw status and startup mode. NLA (`NlaSvc`) is included in the curated
  `$ServiceDefinitions` list so its state is always captured in the collector payload.
- `Analyzers/Heuristics/Services/Services.Common.ps1` converts the collected service list
  into a lookup table. `Get-ServiceStateInfo` normalizes the raw `Status` and `StartMode`
  values (for example, translating variations of "Automatic (Delayed)" to
  `automatic-delayed`) so the heuristic can reason about a consistent set of states.
- `Analyzers/Heuristics/Services.ps1` passes a boolean `IsWorkstation` flag derived from
  the platform metadata (`$platform.IsWorkstation`) to the NLA check. This allows the
  heuristic to lower severity when a workstation is intentionally configured for
  manual startup.
- `Analyzers/Heuristics/Services/Services.Checks.ps1` contains
  `Invoke-ServiceCheckNetworkLocation`, the routine that evaluates the normalized NLA
  record and produces the resulting issue or normal card.

## Decision flow

1. If the `NlaSvc` record is missing from the lookup, the analyzer emits a high-severity
   issue because Windows cannot classify networks without the service definition.
2. When the service exists and reports a normalized status of `running`, the analyzer
   records a normal with evidence that echoes the running state and startup type.
3. For non-running states, the heuristic formats an evidence string containing the raw
   `Status` and `StartType` values.
4. If the startup mode is normalized to `manual` **and** the device is a workstation,
   the heuristic raises a medium-severity issue noting that NLA is stopped and set to
   manual. This reflects reduced impact because technicians can start the service on
   demand.
5. All other non-running states (including disabled services, manual services on
   servers, or stopped automatic services) trigger a high-severity issue that warns NLA
   is not running.

## Issue cards, impact, and remediation guidance

- **Network Location Awareness service missing** (High): Fires when the collector cannot
  find an `NlaSvc` record. *Impact:* Windows cannot determine network category or apply
  location-based firewall policies, leaving connectivity logic in an unknown state.
  *Remediation:* Reinstall the NLA feature (part of the TCP/IP stack) or restore the
  service entry from a healthy system, then restart the device to rebuild the service
  registry.
- **Network Location Awareness set to Manual and stopped** (Medium): Triggers on
  workstations where `NlaSvc` is present but stopped with a manual start mode.
  *Impact:* The device will not automatically refresh network profiles after changes,
  so technicians may miss firewall or proxy policy updates until the service is
  manually started. *Remediation:* Set the startup type to Automatic and start the
  service so Windows resumes tracking network transitions, or document the exception if
  a break/fix workflow relies on manual control.
- **Network Location Awareness service not running** (High): Raised when NLA exists but
  is stopped or disabled outside the manual-on-workstation scenario. *Impact:* Network
  profile detection and dependent services such as firewall profile selection or VPN
  awareness cannot respond to changes, leading to inconsistent security posture.
  *Remediation:* Ensure the startup type is Automatic (delayed start is acceptable),
  start the service, and verify dependent services such as the DHCP client are healthy
  to prevent NLA from stopping again.
- **Network Location Awareness running** (Normal): Logged when NLA is installed and
  running. *Impact:* No action required—the service is monitoring network state as
  expected. *Remediation:* None.
