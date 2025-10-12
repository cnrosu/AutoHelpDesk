# Network ARP Cache analyzer card

## Summary
This Good (Normal) card, shown to technicians as **ARP Cache Healthy**, reassures them that the analyzer ignores broadcast and multicast ARP chatter, so only suspicious unicast neighbors produce warnings.

## Card Type and Impact
The analyzer records a Good → Normal finding titled **ARP Cache Healthy, so broadcast and multicast chatter is suppressed while suspicious unicast neighbors would raise alerts.** to mirror the Add-CategoryNormal output.
That single-sentence impact line tells technicians there is no action required unless future runs highlight unicast anomalies.

## Signals to Collect
- `arp -a` output from the Network collector provides the interface, IP address, and MAC address seen in the local cache.
- Gateway inference compares collected ARP rows with gateway metadata so the analyzer can flag spoofed or flapping MAC addresses.

## Detection Logic
- The heuristic separates ARP cache rows into broadcast, multicast, and unicast groups before evaluating severities.
- Broadcast (`FF:FF:FF:FF:FF:FF`) and multicast MAC entries are suppressed from alerts but echoed as evidence when present so technicians see what was ignored.
- High and medium severities trigger only when the default gateway or other unicast neighbors map to invalid MACs or show flapping behavior.

## Evidence Details
- *Suppressed broadcast entries (expected)* lists cached rows sent to the all-hosts MAC, confirming they were intentionally ignored.
- *Gateway ARP* summarizes the MAC currently associated with the default gateway, letting teams monitor for changes across reports.
- *Length* and *LongLength* reflect how many suppressed entries were in the underlying collection payload.

## Remediation Guidance
- No remediation is needed when this normal card appears; it documents healthy suppression behavior so technicians can focus on unicast anomalies if they appear later.
- If future runs reveal unexpected gateway MAC changes, clear the ARP cache (`arp -d *`), verify switch/router CAM tables, and investigate potential spoofing or loops.
