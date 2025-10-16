# Info card failure tracker

The following analyzer outputs previously emitted INFO-severity cards but now raise warnings to highlight data-collection gaps that block validation:

| Analyzer | Check ID or Area | New Severity | Rationale |
| --- | --- | --- | --- |
| `Analyzers/Heuristics/Network/Modules/Network.Converters.ps1` | `fw.collector.missing`, `fw.profile.error`, `fw.profile.unparsed` | Warning | Missing or unparsed firewall profile data leaves Windows Firewall enforcement unknown until collection succeeds. |
| `Analyzers/Network/Analyze-Vpn.ps1` | Collection and profile availability checks | Warning | Without the VPN baseline artifact, payload, or any profiles, remote access health cannot be confirmed. |
| `Analyzers/Heuristics/Security/Security.BitLocker.ps1` | Artifact/structure presence checks | Warning | Absent BitLocker artifacts hide encryption status, so data exposure risk must be treated as unresolved. |

No other analyzers currently emit INFO-only failure cards. Update this tracker if new informational-only failure paths appear so documentation stays aligned with analyzer behavior.
