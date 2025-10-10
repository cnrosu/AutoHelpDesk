## Summary
AutoHelpDesk captures Windows VPN baselines so technicians can validate remote access health even when they are offsite. The collector records VPN profiles, recent connection statistics, RasMan/IKEEXT events, and supporting network/service state so issue cards explain what was checked. These diagnostics make it easier to confirm that VPN tunnels will launch reliably before a user is stranded outside the office.

## Signals to Collect
- `Collect-VpnBaseline.ps1` → Export VPN profiles, routing, DNS suffixes, authentication metadata, and RasMan/IKEEXT events into `Vpn/vpn-baseline.json` and `vpn-events.json`.
- `Get-VpnConnection -AllUserConnection` → Enumerate device-wide VPN profiles, including tunnel types and split-tunnel settings.
- `Get-Service RasMan, IKEEXT, PolicyAgent` → Record VPN service start modes and runtime status for health analysis.
- `Get-DnsClientGlobalSetting` and `Get-NetIPConfiguration` → Capture DNS suffixes and interface bindings applied when VPN is connected.

## Detection Rule
- **BaselineMissing (Severity: Informational):** Triggered when the collector cannot find `vpn-baseline.json`, signaling that VPN health is unknown until diagnostics are rerun.
- **SplitTunnelEnabled (Severity: High):** Raised when a managed VPN profile leaves split tunneling enabled, allowing corporate traffic to leak onto untrusted networks.
- **CertificateRequiredMissing (Severity: Critical):** Fired when a VPN profile requires a certificate but none is present or the certificate is expired, preventing successful connections.
- **RoutingFailure (Severity: Critical):** Issued when an active VPN session lacks corporate routes or the adapter reports a down state, indicating remote resources remain unreachable.

## Heuristic Mapping
- `Network/VPN/Collection`
- `Network/VPN/Profiles`
- `Network/VPN/Policies`
- `Network/VPN/Authentication`
- `Network/VPN/Routing`

## Remediation
1. Re-run `Collect-VpnBaseline.ps1` after reproducing VPN issues so the analyzer can evaluate current profiles, routes, and certificates.
2. For split tunneling warnings, enforce full tunneling in the VPN profile or restrict allowed destinations to trusted ranges per policy.
3. When certificate or routing failures appear, deploy valid client certificates, restart the RasMan and IKEEXT services, and confirm the VPN adapter applies corporate routes after reconnecting.

## References
- `Collectors/Network/Collect-VpnBaseline.ps1`
- `Analyzers/Network/Analyze-Vpn.ps1`
- `Analyzers/Heuristics/Events/Vpn.ps1`

# Understanding the "Split tunneling enabled on '{connection}' (policy violation)." card

## What the card is telling you
- **Analyzer**: Network → VPN
- **Severity**: High
- **Detection**: The analyzer found a Windows VPN profile configured with split tunneling, so only selected prefixes route through the corporate tunnel.

> **Impact (plain English):** Split tunneling lets laptops send sensitive traffic across public Wi-Fi instead of the corporate VPN, exposing data to eavesdroppers.

## Why this matters
Split tunneling breaks the assumption that remote devices send all corporate traffic through monitored links. Attackers on the same public network can sniff or tamper with unencrypted traffic, and unmanaged DNS resolvers may leak internal hostnames. Many compliance frameworks explicitly forbid split tunneling because it bypasses security monitoring and data loss prevention controls.

## Typical causes
- Administrators enabling split tunneling to improve performance without realizing the policy implications.
- Legacy VPN profiles imported from third-party clients that default to split tunnels.
- Devices configured with Always On VPN profiles that were cloned from testing environments without updating routing settings.

## How to remediate
1. Open the VPN profile in Windows Settings or via `Set-VpnConnection` and disable split tunneling so the default route points through the VPN.
2. If selective split tunneling is required, limit the allow list to approved SaaS endpoints and document the justification with security leadership.
3. Reconnect the VPN and verify that `Get-VpnConnection -Name '<connection>' | Select-Object SplitTunneling` reports `False` on the managed devices.

## Verification steps
- Run `Get-VpnConnection -Name '<connection>' | Format-List SplitTunneling, TunnelType` to confirm split tunneling is disabled and the tunnel type matches policy (IKEv2 or SSTP).
- Check `Get-NetRoute -InterfaceAlias '<VPN Adapter>'` after connecting to confirm corporate prefixes and default routes originate from the VPN interface.
- Validate sensitive applications (ERP, RMM tools, line-of-business portals) reach internal endpoints while the VPN tunnel is active.

## Additional references
- [Microsoft Learn: Configure VPN split tunneling](https://learn.microsoft.com/windows/security/identity-protection/vpn/vpn-configure-split-tunneling)
- [Microsoft Learn: Always On VPN best practices](https://learn.microsoft.com/windows-server/remote/remote-access/vpn/always-on-vpn/always-on-vpn-best-practices)
