# VPN Diagnostics Artifacts

The VPN collectors write structured diagnostic artifacts into this folder. The
primary payload is `vpn-baseline.json`, which captures the Windows built-in VPN
configuration and current state. When available, the collector also emits
`vpn-events.json` containing a trimmed history of relevant RasMan, RasClient,
and IKEEXT events for the last two weeks.

These files are produced automatically by running the `Collect-VpnBaseline.ps1`
collector. They are not intended to be committed to source control.
