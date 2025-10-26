## Summary
AutoHelpDesk flags Windows Defender Firewall rules that leave multicast DNS (mDNS/Bonjour) open on the Domain profile because that allows enterprise endpoints to answer multicast discovery requests from beyond the local subnet (potentially other VLANs via routing). The checklist below captures the commands technicians need to validate exposure, interpret the results, and scope or disable UDP/5353 depending on business requirements. This content mirrors the updated issue card so the remediation story remains consistent across reports and tickets.

## Discovery Checklist
The following PowerShell commands enumerate the firewall rules, listeners, and policies that determine whether mDNS is active. Run them from an elevated session on the affected endpoint.

```powershell
# A. Show any ENABLED inbound firewall rules that allow UDP/5353 (mDNS)
Get-NetFirewallRule -Enabled True -Direction Inbound -Action Allow |
  Get-NetFirewallPortFilter |
  Where-Object { $_.Protocol -eq 17 -and $_.LocalPort -eq 5353 } |
  ForEach-Object {
    $r    = Get-NetFirewallRule -AssociatedNetFirewallRule $_.InstanceID
    $addr = Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $r.InstanceID
    [pscustomobject]@{
      Name          = $r.DisplayName
      Group         = $r.DisplayGroup
      Profile       = $r.Profile     # Domain/Private/Public (bitmask)
      Enabled       = $r.Enabled
      Program       = (Get-NetFirewallApplicationFilter -AssociatedNetFirewallRule $r.InstanceID -ErrorAction SilentlyContinue).Program
      RemoteAddress = ($addr.RemoteAddress -join ',')
      PolicyStore   = $r.PolicyStoreSource
    }
  } | Sort-Object Name,Profile

# B. See if any process is LISTENING on UDP/5353
Get-NetUDPEndpoint | Where-Object { $_.LocalPort -eq 5353 } |
  Select-Object LocalAddress,LocalPort,OwningProcess |
  ForEach-Object { $_, (Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue | Select-Object -Expand Name) }

# C. Check if Bonjour/mDNS services/processes exist
Get-Service *bonjour*, *mdns* -ErrorAction SilentlyContinue
Get-Process mDNSResponder -ErrorAction SilentlyContinue

# D. Check if Group Policy forces mDNS on/off (rare but important)
Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -ErrorAction SilentlyContinue |
  Select-Object EnableMulticast
```

## Interpretation
Use this table to convert raw evidence into a risk call for the report.

| Evidence you see | Meaning | Risk call |
| --- | --- | --- |
| Enabled inbound rule allows UDP/5353 with Profile including Domain and RemoteAddress = Any/blank | Host will accept mDNS from anywhere in the Domain profile | Tighten/disable unless explicitly needed |
| Enabled inbound rule scoped to LocalSubnet | Limited to link-local multicast scope | Usually acceptable when Bonjour/AirPrint is required |
| No enabled inbound rules for UDP/5353 | Firewall blocks mDNS | Low risk |
| Process (msedge, chrome, mDNSResponder) listening on 5353 | Application can send/receive mDNS; firewall decides exposure | If inbound rules are open, scope or disable |
| `EnableMulticast` policy set to `0` | mDNS disabled via policy | Good for locked-down builds |
| `EnableMulticast` policy missing | Default behavior applies | Review firewall listeners and scopes |

## Ticket Title
Security/Windows Firewall – mDNS (UDP/5353) inbound exposure on Domain profile

## Evidence to Result Mapping
- Rule example: Microsoft Edge (mDNS-In) or mDNS (UDP-In) → Action=Allow, Direction=Inbound, Profile=Domain, LocalPort=5353, RemoteAddress=Any.
- Listener example: `msedge` bound to `0.0.0.0:5353` and `:::5353`.
- Result statement: mDNS service discovery is enabled on the Domain profile and will answer/receive on the local subnet; tighten or disable unless policy requires Bonjour.

## Remediation Options
Recommended baseline: Disable or scope mDNS on Domain networks unless the business explicitly requires Bonjour/AirPlay/AirPrint.

1. **Option A — Disable all inbound mDNS (safest if not needed)**
   ```powershell
   # Disable every enabled inbound rule that allows UDP/5353
   Get-NetFirewallRule -Enabled True -Direction Inbound -Action Allow |
     Get-NetFirewallPortFilter | Where-Object { $_.Protocol -eq 17 -and $_.LocalPort -eq 5353 } |
     ForEach-Object { (Get-NetFirewallRule -AssociatedNetFirewallRule $_.InstanceID).Name } |
     ForEach-Object { Disable-NetFirewallRule -Name $_ }
   ```
2. **Option B — Keep mDNS but scope it (reduce exposure)**
   ```powershell
   # Restrict inbound UDP/5353 to LocalSubnet only
   Get-NetFirewallRule -Enabled True -Direction Inbound -Action Allow |
     Get-NetFirewallPortFilter | Where-Object { $_.Protocol -eq 17 -and $_.LocalPort -eq 5353 } |
     ForEach-Object {
       $rule = Get-NetFirewallRule -AssociatedNetFirewallRule $_.InstanceID
       Set-NetFirewallRule -Name $rule.Name -RemoteAddress LocalSubnet
     }
   ```
3. **Option C — Disable only on Domain profile (keep for Private/Public)**
   ```powershell
   # 1 = Domain, 2 = Private, 4 = Public (bit flags). Filter where Domain bit is set.
   (Get-NetFirewallRule -Enabled True -Direction Inbound -Action Allow |
     Where-Object { $_.Profile -band 1 } |
     Get-NetFirewallPortFilter |
     Where-Object { $_.Protocol -eq 17 -and $_.LocalPort -eq 5353 } |
     ForEach-Object { Get-NetFirewallRule -AssociatedNetFirewallRule $_.InstanceID }).Name |
     ForEach-Object { Disable-NetFirewallRule -Name $_ }
   ```

Optional hygiene: remove Bonjour if unused.

```powershell
Stop-Service BonjourService -ErrorAction SilentlyContinue
Set-Service  BonjourService -StartupType Disabled -ErrorAction SilentlyContinue
```

### Quick Fix
Disable UDP/5353 on the Domain profile only (recommended enterprise default):

```powershell
(Get-NetFirewallRule -Enabled True -Direction Inbound -Action Allow |
  Where-Object { $_.Profile -band 1 } |
  Get-NetFirewallPortFilter |
  Where-Object { $_.Protocol -eq 17 -and $_.LocalPort -eq 5353 } |
  ForEach-Object { Get-NetFirewallRule -AssociatedNetFirewallRule $_.InstanceID }).Name |
  ForEach-Object { Disable-NetFirewallRule -Name $_ }
```

## Impact (for issue card)
A compromised workstation or rogue app on the corporate network can use open UDP/5353 rules to discover and interact with Bonjour-enabled services across the Domain profile, expanding the lateral movement surface.
