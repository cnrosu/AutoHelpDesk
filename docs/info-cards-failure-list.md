# INFO cards that signal failures despite INFO severity

These entries identify every INFO-severity issue card whose text describes missing data, disabled protections, or service failures—conditions that read like something broke rather than routine telemetry. Each table groups cards by analyzer domain and lists every script that emits the wording so engineers can retune severity levels.


## AD

These cards surface failure conditions collected under the AD analyzers.


| Card title | Defined in |
| --- | --- |

| 'AD health data unavailable, so Active Directory reachability is unknown.' -Subcategory 'Collection' | Analyzers/Heuristics/AD.ps1 |

| 'Unable to read Group Policy event log, so device policy failures may be hidden.' -Evidence $groupPolicyLog.Error -Subcategory 'Group Policy' | Analyzers/Heuristics/AD/GroupPolicy.ps1 |


## Cloud

These cards surface failure conditions collected under the Cloud analyzers.


| Card title | Defined in |
| --- | --- |

| 'OneDrive collector missing, so cloud file sync health is unknown.' -Subcategory 'OneDrive' -Remediation 'Re-run collectors with OneDrive signed in to capture sync health signals.' | Analyzers/Heuristics/Cloud/OneDrive.ps1 |

| 'OneDrive payload missing, so cloud file sync health is unknown.' -Subcategory 'OneDrive' -Remediation 'Re-run collectors with OneDrive signed in to capture sync health signals.' | Analyzers/Heuristics/Cloud/OneDrive.ps1 |

| 'OneDrive state collection failed, so cloud file sync health is unknown.' -Evidence $state.Error -Subcategory 'OneDrive' -Remediation 'Re-run collectors with OneDrive signed in to capture sync health signals.' | Analyzers/Heuristics/Cloud/OneDrive.ps1 |

| 'OneDrive state unavailable, so cloud file sync health is unknown.' -Subcategory 'OneDrive' -Remediation 'Re-run collectors with OneDrive signed in to capture sync health signals.' | Analyzers/Heuristics/Cloud/OneDrive.ps1 |


## Hardware

These cards surface failure conditions collected under the Hardware analyzers.


| Card title | Defined in |
| --- | --- |

| 'Battery health query reported an error, so health data may be incomplete.' -Evidence ("{0}: {1}" -f $source, $errorText) -Subcategory 'Battery' | Analyzers/Heuristics/Hardware/Battery.ps1 |

| Driver inventory artifact missing, so Device Manager issues can't be evaluated." -Subcategory 'Collection' | Analyzers/Heuristics/Hardware/Drivers.ps1 |

| Driver inventory command failed, so Device Manager issues may be hidden." -Evidence ("{0}: {1}" -f $source, $evidence) -Subcategory 'Collection' | Analyzers/Heuristics/Hardware/Drivers.ps1 |

| Driver inventory payload missing, so Device Manager issues can't be evaluated." -Subcategory 'Collection' | Analyzers/Heuristics/Hardware/Drivers.ps1 |

| Problem device inventory command failed, so Device Manager issues may be hidden." -Evidence ("{0}: {1}" -f $source, $evidence) -Subcategory 'Collection' | Analyzers/Heuristics/Hardware/Drivers.ps1 |


## Network

These cards surface failure conditions collected under the Network analyzers.


| Card title | Defined in |
| --- | --- |

| 'DNS client policy query failed, so name resolution policy issues may be hidden and cause failures.' -Evidence $policy.Error -Subcategory 'DNS Client' -Data (& $createConnectivityData $connectivityContext) | Analyzers/Heuristics/Network/Modules/Network.Heuristics.ps1 |

| 'DNS diagnostics not collected, so latency and name resolution issues may be missed.' -Subcategory 'DNS Resolution' -Data (& $createConnectivityData $connectivityContext) | Analyzers/Heuristics/Network/Modules/Network.Heuristics.ps1 |

| 'Firewall profile collector missing, so firewall enforcement is unknown until the firewall profile collector runs.' -Subcategory $subcategory -CheckId $collectorMissingCheckId | Analyzers/Heuristics/Network/Modules/Network.Converters.ps1 |

| 'Firewall profile data could not be parsed, so firewall enforcement is unknown.' -Evidence $unparsedEvidence -Subcategory $subcategory -CheckId $unparsedCheckId | Analyzers/Heuristics/Network/Modules/Network.Converters.ps1 |

| 'Firewall profile data empty, so firewall enforcement is unknown.' -Subcategory $subcategory -CheckId $unparsedCheckId | Analyzers/Heuristics/Network/Modules/Network.Converters.ps1 |

| 'Firewall profile data missing, so firewall enforcement is unknown.' -Subcategory $subcategory -CheckId $errorCheckId | Analyzers/Heuristics/Network/Modules/Network.Converters.ps1 |

| 'Firewall profile query failed, so firewall enforcement is unknown until the error is resolved.' -Evidence $payloadError -Subcategory $subcategory -CheckId $errorCheckId | Analyzers/Heuristics/Network/Modules/Network.Converters.ps1 |

| 'LLDP collector missing, so switch port documentation cannot be verified and mispatches may go unnoticed.' -Subcategory $lldpSubcategory | Analyzers/Heuristics/Network/Modules/Network.Heuristics.ps1 |

| 'LLDP neighbors missing, so switch port documentation cannot be verified and mispatches may go unnoticed.' -Subcategory $lldpSubcategory | Analyzers/Heuristics/Network/Modules/Network.Heuristics.ps1 |

| 'Machine certificate inventory failed, so 802.1X certificate health is unknown.' -Evidence $certError -Subcategory $wiredSubcategory | Analyzers/Heuristics/Network/Modules/Network.Heuristics.ps1 |

| 'Network adapter inventory incomplete, so link status is unknown.' -Subcategory 'Network Adapters' | Analyzers/Heuristics/Network/Modules/Network.Heuristics.ps1 |

| 'Network adapter inventory not collected, so link status is unknown.' -Subcategory 'Network Adapters' | Analyzers/Heuristics/Network/Modules/Network.Heuristics.ps1 |

| 'Network base diagnostics not collected, so connectivity failures may go undetected.' -Subcategory 'Collection' -Data (& $createConnectivityData $connectivityContext) | Analyzers/Heuristics/Network/Modules/Network.Heuristics.ps1 |

| 'No VPN profiles detected; remote access will fail on managed devices.' -Evidence $extra -Subcategory 'Profiles' | Analyzers/Network/Analyze-Vpn.ps1 |

| 'No wired interfaces reported by netsh, so 802.1X status is unknown.' -Subcategory $wiredSubcategory | Analyzers/Heuristics/Network/Modules/Network.Heuristics.ps1 |

| 'Not connected to Wi-Fi, so wireless encryption state is unknown.' -Evidence $evidence -Subcategory 'Security' -Remediation $remediation | Analyzers/Heuristics/Network/Modules/Network.Heuristics.ps1 |

| 'Switch port inventory missing, so LLDP data cannot confirm wiring and mispatches may linger.' -Subcategory $lldpSubcategory | Analyzers/Heuristics/Network/Modules/Network.Heuristics.ps1 |

| 'Unable to enumerate DNS servers, so name resolution may fail on domain devices.' -Evidence $entry.Error -Subcategory 'DNS Client' -Data (& $createConnectivityData $connectivityContext) | Analyzers/Heuristics/Network/Modules/Network.Heuristics.ps1 |

| 'Unable to enumerate network adapters, so link status is unknown.' -Evidence $adapters[0].Error -Subcategory 'Network Adapters' | Analyzers/Heuristics/Network/Modules/Network.Heuristics.ps1 |

| 'VPN baseline artifact missing; VPN health unknown.' -Subcategory 'Collection' | Analyzers/Network/Analyze-Vpn.ps1 |

| 'VPN baseline payload unavailable or corrupted.' -Subcategory 'Collection' | Analyzers/Network/Analyze-Vpn.ps1 |

| 'Wired 802.1X diagnostics not collected, so port authentication posture is unknown.' -Subcategory $wiredSubcategory | Analyzers/Heuristics/Network/Modules/Network.Heuristics.ps1 |

| 'Wired 802.1X diagnostics returned no payload, so port authentication posture is unknown.' -Subcategory $wiredSubcategory | Analyzers/Heuristics/Network/Modules/Network.Heuristics.ps1 |

| 'Wired 802.1X diagnostics unavailable, so port authentication posture is unknown.' -Evidence $lanPayload.Error -Subcategory $wiredSubcategory | Analyzers/Heuristics/Network/Modules/Network.Heuristics.ps1 |

| 'Wireless diagnostics not collected, so Wi-Fi security posture cannot be evaluated.' -Subcategory 'Security' | Analyzers/Heuristics/Network/Modules/Network.Heuristics.ps1 |

| 'Wireless diagnostics unavailable, so Wi-Fi security posture is unknown.' -Evidence $wlanPayload.Error -Subcategory 'Security' | Analyzers/Heuristics/Network/Modules/Network.Heuristics.ps1 |

| 'Wireless interface inventory empty, so Wi-Fi security posture cannot be evaluated.' -Subcategory 'Security' | Analyzers/Heuristics/Network/Modules/Network.Heuristics.ps1 |

| 'netsh failed to enumerate wired interfaces, so 802.1X status is unknown.' -Evidence $interfaceError -Subcategory $wiredSubcategory | Analyzers/Heuristics/Network/Modules/Network.Heuristics.ps1 |

| ("Adapter {0} lacks LLDP neighbor data, so {1} cannot be verified and mispatches may go unnoticed." -f $alias, $expectedLabel) -Evidence $evidence -Subcategory $lldpSubcategory | Analyzers/Heuristics/Network/Modules/Network.Heuristics.ps1 |

| ("DHCP analyzer failed: {0}" -f $analyzer.Script.Name) -Evidence $_.Exception.Message -Subcategory 'DHCP' | Analyzers/Heuristics/Network/Modules/Network.Dhcp.ps1 |


## Office

These cards surface failure conditions collected under the Office analyzers.


| Card title | Defined in |
| --- | --- |

| 'Outlook cache inventory not collected, so oversized cache files may be missed.' -Subcategory 'Outlook Cache' | Analyzers/Heuristics/Office/OutlookCache.ps1 |

| 'Outlook data file inventory not collected, so oversized OST files may be missed.' -Subcategory 'Outlook Data Files' | Analyzers/Heuristics/Office/OutlookConnectivity.ps1 |


## Printing

These cards surface failure conditions collected under the Printing analyzers.


| Card title | Defined in |
| --- | --- |

| 'Print Spooler not running, exposing printing security and reliability risks until resolved.' -Evidence ("Status: {0}; StartMode: {1}; Note: {2}" -f $status, $startMode, $note) -Subcategory 'Spooler Service' | Analyzers/Heuristics/Printing/Spooler.ps1 |

| Printing artifact not collected, so printing security and reliability risks can't be evaluated." -Subcategory 'Collection' | Analyzers/Heuristics/Printing.ps1 |

| Printing payload missing, so printing security and reliability risks can't be evaluated." -Subcategory 'Collection' | Analyzers/Heuristics/Printing.ps1 |


## Security

These cards surface failure conditions collected under the Security analyzers.


| Card title | Defined in |
| --- | --- |

| 'Autorun policy artifact missing expected structure, so removable media autorun defenses are unknown.' -Subcategory 'Autorun Policies' | Analyzers/Heuristics/Security/Security.Autorun.ps1 |

| 'Autorun policy artifact not collected, so removable media autorun defenses are unknown.' -Subcategory 'Autorun Policies' | Analyzers/Heuristics/Security/Security.Autorun.ps1 |

| 'BitLocker PCR binding data unavailable, so boot integrity attestation cannot be confirmed.' -Subcategory 'Measured Boot' | Analyzers/Heuristics/Security/Security.MeasuredBoot.ps1 |

| 'BitLocker PCR binding query failed, so boot integrity attestation cannot be confirmed.' -Evidence $volumeData.Error -Subcategory 'Measured Boot' | Analyzers/Heuristics/Security/Security.MeasuredBoot.ps1 |

| 'BitLocker artifact not collected, so the encryption state and data exposure risk are unknown.' -Subcategory 'BitLocker' | Analyzers/Heuristics/Security/Security.BitLocker.ps1 |

| 'BitLocker data missing expected structure, so the encryption state and data exposure risk are unknown.' -Subcategory 'BitLocker' | Analyzers/Heuristics/Security/Security.BitLocker.ps1 |

| 'Defender artifact missing expected structure, leaving antivirus protection gaps unverified.' -Subcategory 'Microsoft Defender' | Analyzers/Heuristics/Security/Security.Defender.ps1 |

| 'Defender artifact not collected, leaving antivirus protection gaps unverified.' -Subcategory 'Microsoft Defender' | Analyzers/Heuristics/Security/Security.Defender.ps1 |

| 'Firewall rule inventory missing, so port exposure checks could not run.' -Subcategory 'Windows Firewall' -CheckId 'Security/Firewall/MissingRules' | Analyzers/Heuristics/Security/Security.Firewall.ps1 |

| 'Measured boot artifact missing expected structure, so boot integrity attestation cannot be confirmed.' -Subcategory 'Measured Boot' | Analyzers/Heuristics/Security/Security.MeasuredBoot.ps1 |

| 'Measured boot artifact not collected (MDM required), so boot integrity attestation cannot be confirmed.' -Subcategory 'Measured Boot' | Analyzers/Heuristics/Security/Security.MeasuredBoot.ps1 |

| 'Measured boot attestation events missing (MDM required), so remote health attestations cannot be confirmed.' -Evidence $noEventEvidence -Subcategory 'Measured Boot' | Analyzers/Heuristics/Security/Security.MeasuredBoot.ps1 |

| 'Measured boot attestation events missing (MDM required), so remote health attestations cannot be confirmed.' -Subcategory 'Measured Boot' | Analyzers/Heuristics/Security/Security.MeasuredBoot.ps1 |

| 'Measured boot attestation query failed (MDM required), so remote health attestations cannot be confirmed.' -Evidence $attestation.Error -Subcategory 'Measured Boot' | Analyzers/Heuristics/Security/Security.MeasuredBoot.ps1 |

| 'Secure Boot confirmation unavailable, so firmware integrity checks cannot be verified.' -Evidence $secureBoot.Error -Subcategory 'Measured Boot' | Analyzers/Heuristics/Security/Security.MeasuredBoot.ps1 |

| 'Secure Boot confirmation unavailable, so firmware integrity checks cannot be verified.' -Subcategory 'Measured Boot' | Analyzers/Heuristics/Security/Security.MeasuredBoot.ps1 |

| 'Smart App Control disabled, so app trust enforcement is reduced.' -Evidence $evidenceText -Subcategory 'Smart App Control' | Analyzers/Heuristics/Security/Security.DeviceProtection.ps1 |

| 'Some firewall rules could not be parsed, so port exposure coverage may be incomplete.' -Evidence ($ruleErrors.ToArray()) -Subcategory 'Windows Firewall' -CheckId 'Security/Firewall/RuleErrors' | Analyzers/Heuristics/Security/Security.Firewall.ps1 |

| 'Unable to query Smart App Control state, so app trust enforcement is unknown.' -Evidence $entry.Error -Subcategory 'Smart App Control' | Analyzers/Heuristics/Security/Security.DeviceProtection.ps1 |

| 'WDAC/Smart App Control diagnostics not collected, so app trust enforcement is unknown.' -Subcategory 'Smart App Control' | Analyzers/Heuristics/Security/Security.DeviceProtection.ps1 |


## Services

These cards surface failure conditions collected under the Services analyzers.


| Card title | Defined in |
| --- | --- |

| 'BITS manual start and currently stopped' -Evidence $evidence -Subcategory 'BITS Service' | Analyzers/Heuristics/Services/Services.Checks.ps1 |

| 'Office Click-to-Run manual/disabled on server' -Evidence $evidence -Subcategory 'Office Click-to-Run' | Analyzers/Heuristics/Services/Services.Checks.ps1 |

| 'Print Spooler not running' -Evidence $evidence -Subcategory 'Print Spooler Service' | Analyzers/Heuristics/Services/Services.Checks.ps1 |

| 'Print Spooler service missing' -Evidence 'Service entry not found; printing features unavailable.' -Subcategory 'Print Spooler Service' | Analyzers/Heuristics/Services/Services.Checks.ps1 |

| 'Service inventory reported collection errors, so outages in critical services may go unnoticed.' -Evidence ($collectionErrors -join "`n") -Subcategory 'Service Inventory' | Analyzers/Heuristics/Services.ps1 |

| 'WinHTTP Auto Proxy disabled' -Evidence $evidence -Subcategory 'WinHTTP Auto Proxy Service' | Analyzers/Heuristics/Services/Services.Checks.ps1 |

| 'Windows Search manual start and currently stopped' -Evidence $title -Subcategory 'Windows Search Service' | Analyzers/Heuristics/Services/Services.Checks.ps1 |


## Storage

These cards surface failure conditions collected under the Storage analyzers.


| Card title | Defined in |
| --- | --- |

| 'Disk health unavailable, so failing disks may go unnoticed.' -Evidence ($errorDetails -join "`n") -Subcategory 'Disk Health' -Data $issueData | Analyzers/Heuristics/Storage/Storage.DiskHealth.ps1 |

| 'SMART status unavailable, so imminent drive failure may be missed.' -Evidence $errorDetail -Subcategory 'SMART' | Analyzers/Heuristics/Storage/Storage.Snapshot.ps1 |

| 'SMART wear data not collected, so SSD end-of-life risks may be hidden.' -Subcategory 'SMART Wear' | Analyzers/Heuristics/Storage/Storage.Wear.ps1 |

| 'SMART wear data unavailable, so SSD end-of-life risks may be hidden.' -Evidence $errorMessage -Subcategory 'SMART Wear' | Analyzers/Heuristics/Storage/Storage.Wear.ps1 |

| 'SMART wear data unavailable, so SSD end-of-life risks may be hidden.' -Subcategory 'SMART Wear' | Analyzers/Heuristics/Storage/Storage.Wear.ps1 |

| 'Storage inventory artifact missing, so storage health and wear cannot be evaluated.' -Subcategory 'Collection' | Analyzers/Heuristics/Storage.ps1 |

| 'Storage snapshot artifact missing, so SMART status cannot be evaluated.' -Subcategory 'Collection' | Analyzers/Heuristics/Storage.ps1 |

| 'Volume inventory unavailable, so storage depletion risks may be hidden.' -Evidence ($errorDetails -join "`n") -Subcategory 'Free Space' -Data $issueData | Analyzers/Heuristics/Storage/Storage.Volumes.ps1 |

| ("Unable to query SMART wear for {0}, so SSD end-of-life risks may be hidden." -f $label) -Evidence $entry.Error -Subcategory 'SMART Wear' | Analyzers/Heuristics/Storage/Storage.Wear.ps1 |


## System

These cards surface failure conditions collected under the System analyzers.


| Card title | Defined in |
| --- | --- |

| 'Operating system inventory not available' -Subcategory 'Operating System' | Analyzers/Heuristics/System/OperatingSystem.ps1 |

| 'Pending reboot data unavailable, so a reboot requirement may be hidden and updates could remain blocked.' -Subcategory 'Pending Reboot' | Analyzers/Heuristics/System/PendingReboot.ps1 |

| 'Pending reboot inventory missing, so a reboot requirement may be hidden and updates could remain blocked.' -Subcategory 'Pending Reboot' | Analyzers/Heuristics/System/PendingReboot.ps1 |

| 'Startup program inventory empty, so missing autoruns that slow logins or indicate incomplete data cannot be reviewed.' -Subcategory 'Startup Programs' | Analyzers/Heuristics/System/Startup.ps1 |

| 'Startup program inventory incomplete, so excess or missing autoruns that slow logins or indicate incomplete data may be overlooked.' -Evidence $message -Subcategory 'Startup Programs' | Analyzers/Heuristics/System/Startup.ps1 |

| 'Startup program inventory unavailable, so excess or missing autoruns that slow logins or indicate incomplete data cannot be assessed.' -Subcategory 'Startup Programs' | Analyzers/Heuristics/System/Startup.ps1 |

| 'System Restore data unavailable, so recovery status cannot be verified when troubleshooting rollbacks.' -Subcategory $subcategory | Analyzers/Heuristics/System/SystemRestore.ps1 |

| 'System Restore drive settings unavailable, so per-volume protection status cannot be confirmed before troubleshooting rollbacks.' -Evidence (($driveErrors \| Select-Object -First 5) -join "`n") -Subcategory $subcategory | Analyzers/Heuristics/System/SystemRestore.ps1 |

| 'System Restore inventory missing, so recovery status cannot be verified when troubleshooting rollbacks.' -Subcategory $subcategory | Analyzers/Heuristics/System/SystemRestore.ps1 |

| 'System Restore points could not be enumerated, so available rollbacks may be hidden during troubleshooting.' -Evidence ("${restorePointSource}: $restorePointError") -Subcategory $subcategory | Analyzers/Heuristics/System/SystemRestore.ps1 |

| 'System Restore registry configuration unavailable, so protection status cannot be confirmed before troubleshooting rollbacks.' -Evidence ("${configSource}: $configError") -Subcategory $subcategory | Analyzers/Heuristics/System/SystemRestore.ps1 |

| 'System Restore status could not be determined, so rollbacks might be unavailable when recovering from issues.' -Subcategory $subcategory | Analyzers/Heuristics/System/SystemRestore.ps1 |

| 'System inventory artifact missing' -Subcategory 'Collection' | Analyzers/Heuristics/System/OperatingSystem.ps1 |

| 'Unable to enumerate pending file rename operations, so a reboot requirement may be hidden and updates could remain blocked.' -Evidence (($fileRenameErrors \| Select-Object -First 5) -join "`n") -Subcategory 'Pending Reboot' | Analyzers/Heuristics/System/PendingReboot.ps1 |

| 'Unable to enumerate running processes' -Subcategory 'Performance' | Analyzers/Heuristics/System/Performance.ps1 |

| 'Unable to query computer system details' -Evidence $payload.ComputerSystem.Error -Subcategory 'Hardware Inventory' | Analyzers/Heuristics/System/OperatingSystem.ps1 |

| 'Unable to read Fast Startup configuration, leaving hybrid shutdown risks unchecked.' -Evidence $payload.FastStartup.Error -Subcategory 'Power Configuration' | Analyzers/Heuristics/System/Power.ps1 |

| 'Unable to read OS inventory' -Evidence ($payload.OperatingSystem.Error) -Subcategory 'Operating System' | Analyzers/Heuristics/System/OperatingSystem.ps1 |

| 'Windows 11 readiness data missing, so upgrade blockers may be hidden.' -Subcategory 'Windows 11 Upgrade' | Analyzers/Heuristics/System/Windows11Upgrade.ps1 |

| 'Windows Search snapshot failed to collect, so indexing health is unknown.' -Evidence $evidence -Subcategory 'Windows Search Indexing' | Analyzers/Heuristics/System/WindowsSearch.ps1 |

| 'Windows Search snapshot missing, so indexing health is unknown.' -Evidence 'windows-search.json payload was empty or malformed.' -Subcategory 'Windows Search Indexing' | Analyzers/Heuristics/System/WindowsSearch.ps1 |
