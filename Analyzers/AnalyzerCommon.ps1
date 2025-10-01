<#!
.SYNOPSIS
    Shared helper functions for analyzer modules.
#>

function New-AnalyzerContext {
    param(
        [Parameter(Mandatory)]
        [string]$InputFolder
    )

    if (-not (Test-Path -LiteralPath $InputFolder)) {
        throw "Input folder '$InputFolder' not found."
    }

    $resolved = (Resolve-Path -LiteralPath $InputFolder).ProviderPath
    $artifactMap = @{}

    $files = Get-ChildItem -Path $resolved -File -Recurse -ErrorAction SilentlyContinue
    foreach ($file in $files) {
        $data = $null
        if ($file.Extension -ieq '.json') {
            $content = Get-Content -Path $file.FullName -Raw -ErrorAction SilentlyContinue
            if ($content) {
                try {
                    $data = $content | ConvertFrom-Json -ErrorAction Stop
                } catch {
                    $data = [pscustomobject]@{ Error = $_.Exception.Message }
                }
            }
        }

        $entry = [pscustomobject]@{
            Path = $file.FullName
            Data = $data
        }

        $key = $file.Name.ToLowerInvariant()
        if ($artifactMap.ContainsKey($key)) {
            $artifactMap[$key] = @($artifactMap[$key]) + ,$entry
        } else {
            $artifactMap[$key] = @($entry)
        }
    }

    $jsonFiles = @($files | Where-Object { $_.Extension -ieq '.json' })
    if ($jsonFiles.Count -gt 0) {
        $paths = $jsonFiles | ForEach-Object { $_.FullName }
        Write-HeuristicDebug -Source 'Context' -Message ("Discovered artifacts ({0}): {1}" -f $paths.Count, ($paths -join ', '))
    } else {
        Write-HeuristicDebug -Source 'Context' -Message 'Discovered artifacts (0): (none)'
    }

    return [pscustomobject]@{
        InputFolder = $resolved
        Artifacts   = $artifactMap
    }
}

function Write-HeuristicDebug {
    param(
        [Parameter(Mandatory)]
        [string]$Source,

        [Parameter(Mandatory)]
        [string]$Message,

        [hashtable]$Data
    )

    $formatted = "DBG [{0}] {1}" -f $Source, $Message

    if ($PSBoundParameters.ContainsKey('Data') -and $Data) {
        $detailEntries = $Data.GetEnumerator() | Sort-Object Name
        $details = [System.Collections.Generic.List[string]]::new()
        foreach ($entry in $detailEntries) {
            if ($entry -is [System.Collections.DictionaryEntry]) {
                $null = $details.Add(("{0}={1}" -f $entry.Key, $entry.Value))
            } else {
                $null = $details.Add(("{0}={1}" -f $entry.Name, $entry.Value))
            }
        }

        if ($details) {
            $formatted = "{0} :: {1}" -f $formatted, ($details -join '; ')
        }
    }

    Write-Host $formatted
}

function Get-HeuristicSourceMetadata {
    param(
        [string[]]$SkipCommands = @(
            'Get-HeuristicSourceMetadata',
            'New-CategoryResult',
            'Add-CategoryIssue',
            'Add-CategoryNormal',
            'Add-CategoryCheck'
        )
    )

    try {
        $stack = Get-PSCallStack
    } catch {
        return $null
    }

    if (-not $stack) { return $null }

    foreach ($frame in $stack) {
        if (-not $frame) { continue }

        $command = if ($frame.PSObject.Properties['Command']) { [string]$frame.Command } else { $null }
        if ($command -and $SkipCommands -contains $command) { continue }

        $script = if ($frame.PSObject.Properties['ScriptName']) { [string]$frame.ScriptName } else { $null }
        if (-not $script) { continue }

        $resolvedScript = $script
        try {
            if (Test-Path -LiteralPath $script) {
                $resolvedScript = (Resolve-Path -LiteralPath $script -ErrorAction Stop).ProviderPath
            }
        } catch {
        }

        if ($resolvedScript -and $resolvedScript.EndsWith('AnalyzerCommon.ps1', [System.StringComparison]::OrdinalIgnoreCase)) {
            continue
        }

        $functionName = if ($frame.PSObject.Properties['FunctionName'] -and $frame.FunctionName) {
            [string]$frame.FunctionName
        } elseif ($command) {
            $command
        } else {
            $null
        }

        $lineNumber = $null
        if ($frame.PSObject.Properties['ScriptLineNumber'] -and $frame.ScriptLineNumber -gt 0) {
            $lineNumber = [int]$frame.ScriptLineNumber
        }

        return [pscustomobject]@{
            Script   = $resolvedScript
            Function = $functionName
            Command  = $command
            Line     = $lineNumber
        }
    }

    return $null
}

$script:PlainLanguageAreaOverrides = @{
    'System' = @{
        'Firmware'           = 'System/Secure Boot'
        'Power Configuration' = 'System/Fast Startup'
        'Pending Reboot'     = 'System/Pending Reboot'
        'Startup Programs'   = 'System/Startup Programs'
        'Uptime'             = 'System/Uptime'
    }
    'Network' = @{
        'IP Configuration'    = 'Network'
        'Routing'             = 'Network'
        'Latency'             = 'Network'
        'Network Adapters'    = 'Network'
        'Collection'          = 'Network'
        'Proxy Configuration' = 'Network'
        'Outlook Connectivity' = 'Outlook/Connectivity'
        'Autodiscover DNS'    = 'Outlook/Autodiscover'
        'DNS Autodiscover'    = 'Outlook/Autodiscover'
        'DNS Client'          = 'Network/DNS/Internal'
        'DNS Resolution'      = 'Network/DNS'
        'DHCP'                = 'Security/DHCP'
    }
    'Office' = @{
        'Autodiscover DNS'       = 'Outlook/Autodiscover'
        'Macro Policies'         = 'Office/Macros'
        'Outlook Cache'          = 'Outlook/OST'
        'Outlook Data Files'     = 'Outlook/OST'
        'Protected View Policies' = 'Office/Protected View'
    }
    'Security' = @{
        'Microsoft Defender'              = 'Security/Microsoft Defender'
        'BitLocker'                       = 'Security/BitLocker'
        'TPM'                             = 'Security/TPM'
        'Memory Integrity'                = 'Security/HVCI'
        'Credential Guard'                = 'Security/Credential Guard'
        'Kernel DMA'                      = 'Security/Kernel DMA'
        'Windows Firewall'                = 'Security/Firewall'
        'Windows Defender Application Control' = 'Security/WDAC'
        'Smart App Control'               = 'Security/SmartAppControl'
        'Credential Management'           = 'Security/LAPS'
        'User Account Control'            = 'Security/UAC'
        'PowerShell Logging'              = 'Security/PowerShellLogging'
        'NTLM Hardening'                  = 'Security/NTLM'
        'Attack Surface Reduction'        = 'Security/ASR'
        'Exploit Protection'              = 'Security/ExploitProtection'
    }
    'Services' = @{
        'Service Inventory'          = 'Services/Service Inventory'
        'BITS Service'               = 'Services/Service Inventory'
        'DNS Client Service'         = 'Services/Service Inventory'
        'Network Location Awareness' = 'Services/Service Inventory'
        'Office Click-to-Run'        = 'Services/Service Inventory'
        'Print Spooler Service'      = 'Services/Service Inventory'
        'RPC Services'               = 'Services/Service Inventory'
        'WinHTTP Auto Proxy Service' = 'Services/Service Inventory'
        'Windows Search Service'     = 'Services/Service Inventory'
        'Workstation Service'        = 'Services/Service Inventory'
    }
    'Active Directory' = @{
        'Discovery'           = 'Active Directory/DC Discovery'
        'DNS Discovery'       = 'Active Directory/AD DNS'
        'Secure Channel'      = 'Active Directory/Secure Channel'
        'Time Synchronization' = 'Active Directory/Time & Kerberos'
        'Kerberos'            = 'Active Directory/Time & Kerberos'
        'SYSVOL'              = 'Active Directory/SYSVOL/NETLOGON'
        'Connectivity'        = 'Active Directory/SYSVOL/NETLOGON'
        'Group Policy'        = 'Active Directory/GPO Processing'
    }
    'Printing' = @{
        'Collection'      = 'Printing'
        'Event Logs'      = 'Printing'
        'Network Tests'   = 'Printing'
        'Printers'        = 'Printing'
        'Queues'          = 'Printing'
        'Spooler Service' = 'Printing'
    }
    'Storage' = @{
        'SMART'       = 'Storage/SMART'
        'SMART Wear'  = 'Storage/SMART Wear'
        'Disk Health' = 'Storage/Disks'
        'Free Space'  = 'Storage/Free Space'
        'Collection'  = 'Storage'
    }
    'Events' = @{
        'Collection' = 'Events'
    }
}

$script:PlainLanguageExplanations = [ordered]@{
    'System/Secure Boot' = 'Marks Secure Boot as high severity when disabled, unsupported, or reporting unexpected states, and still escalates when Secure Boot details are missing on UEFI hardware—plainly, if Secure Boot can''t be confirmed, the device might boot without firmware protections.'
    'System/Fast Startup' = 'Flags warnings when Fast Startup is enabled or its state can''t be read, meaning hybrid shutdowns could hide issues; records a healthy status when it''s definitely off.'
    'System/Pending Reboot' = 'Raises medium issues for Windows Update or servicing keys that demand a reboot, warns about outstanding file rename operations or rename evidence, and marks things healthy when no indicators exist—so administrators know when a restart is blocking fixes.'
    'System/Startup Programs' = 'Escalates from low to medium when non-Microsoft autoruns grow beyond 5–10 items and warns when inventory is missing or empty, signaling login slowdowns or incomplete data.'
    'System/Uptime' = 'Emits severity that matches long uptimes (e.g., medium/high/critical depending on days) so you know the box needs a reboot for stability.'
    'Network' = 'Critically flags missing or APIPA IPv4 addresses, high-severity missing gateways/routes or ping failures, and low-severity traceroute stalls so you can chase connectivity gaps.'
    'Network/DNS/Internal' = 'Scales to medium/high when too few AD-capable resolvers remain and warns when public DNS shows up on domain-joined hosts, indicating name-resolution risk.'
    'Network/DNS/Order' = 'Reports low severity when a public DNS server precedes internal resolvers, hinting at potential leakage or slow lookups.'
    'Network/DNS' = 'Raises medium issues for nslookup timeouts or NXDOMAIN responses, highlighting DNS resolution failures.'
    'Security/Firewall' = 'Issues medium findings whenever a firewall profile is off and raises high severity when firewall status output is missing, ensuring you can verify network defenses.'
    'Outlook/Connectivity' = 'Logs informational gaps when tests can''t run and high severity when HTTPS to outlook.office365.com fails—meaning users likely can''t reach Exchange Online.'
    'Outlook/OST' = 'Flags OST caches as medium/high/critical when they exceed 5/15/25 GB so you can trim bloated mail caches that slow Outlook.'
    'Outlook/Autodiscover' = 'Emits informational or medium findings for missing cmdlets, absent domains, bad CNAMEs, failed lookups, or missing records, pointing to Autodiscover onboarding trouble.'
    'Outlook/SCP' = 'Medium severity when SCP queries fail and low when no SCP exists on domain-joined clients, signaling Autodiscover misconfiguration versus expected cloud-only setups.'
    'Office/Macros' = 'High severity if MOTW blocking is disabled and medium when macro notifications still allow execution—indicating macro malware risk.'
    'Office/Protected View' = 'Medium severity when Protected View is disabled in any context, warning that untrusted documents may open directly.'
    'Security/Microsoft Defender' = 'High severity for disabled real-time protection, escalated tiers for stale signatures or missing engines/platforms, and informational warnings when data is absent—showing antivirus gaps or blind spots.'
    'Security/BitLocker' = 'Ranges from low to critical for missing cmdlets, query failures, unprotected OS volumes, incomplete encryption, unclear states, absent recovery passwords, etc., highlighting encryption risk or missing data.'
    'Security/TPM' = 'Medium severity when a TPM exists but isn''t ready and high when none is detected on compatible hardware, meaning hardware-backed key protection is missing.'
    'Security/HVCI' = 'Medium findings when memory integrity is available but off or when Device Guard data is missing, flagging lost kernel exploit protections.'
    'Security/Credential Guard' = 'High severity if Credential Guard/RunAsPPL isn''t enforced, indicating LSASS credential theft defenses are down.'
    'Security/Kernel DMA' = 'Medium findings when Kernel DMA protection is disabled/unsupported or unknown, warning that Thunderbolt-style DMA attacks may succeed.'
    'Security/RDP' = 'High when RDP lacks NLA and medium when it''s enabled on mobile systems even with NLA, warning about remote access risk.'
    'Security/SMB' = 'High severity whenever SMBv1 is enabled, pointing to vulnerable legacy protocol usage.'
    'Security/NTLM' = 'Medium severity if NTLM restriction policies aren''t configured, highlighting credential relay exposure.'
    'Security/SmartScreen' = 'Medium findings when SmartScreen policies are disabled or unenforced, indicating reduced phishing/malware filtering.'
    'Security/ASR' = 'High severity when mandated Attack Surface Reduction rules are missing or not blocking, leaving known exploit vectors open.'
    'Security/ExploitProtection' = 'Medium items when CFG/DEP/ASLR aren’t enforced or data is missing, meaning exploit mitigations can''t be trusted.'
    'Security/WDAC' = 'Warns (medium on modern clients) when no Windows Defender Application Control policy is detected, signaling unrestricted code execution paths.'
    'Security/SmartAppControl' = 'Medium when Smart App Control is off on Windows 11, showing application control baselines aren''t met.'
    'Security/LocalAdmin' = 'High severity when the current user remains a local admin, pointing to privilege escalation risk.'
    'Security/LAPS' = 'High severity when neither legacy nor Windows LAPS protections exist, meaning local admin passwords may be reused or unmanaged.'
    'Security/UAC' = 'High severity for insecure UAC configurations, indicating elevation prompts aren''t protecting administrative actions.'
    'Security/PowerShellLogging' = 'Medium findings when script block/module logging or transcription is absent, leaving PowerShell activity untraceable.'
    'Security/LDAPNTLM' = 'High severity if LDAP signing/channel binding/NTLM restrictions aren’t enforced on domain-joined systems, exposing directory services to relay attacks.'
    'Security/DHCP' = 'High severity when DHCP servers have non-private addresses, hinting at rogue or misconfigured infrastructure.'
    'Security/Office' = 'Medium/low informational items when macro blocking, notifications, or Protected View data is missing, nudging admins to verify Office hardening.'
    'Active Directory/DC Discovery' = 'Critical when no domain controllers appear via SRV lookups, signaling AD is unreachable.'
    'Active Directory/AD DNS' = 'Critical with zero AD-capable DNS servers, high with only one, and medium when public DNS is configured, all indicating AD name-resolution fragility.'
    'Active Directory/Secure Channel' = 'Critical for broken machine secure channels, meaning the workstation can''t authenticate to the domain.'
    'Active Directory/Time & Kerberos' = 'High severity for time sync or Kerberos errors in logs, pointing to authentication failures.'
    'Active Directory/SYSVOL/NETLOGON' = 'High severity when SYSVOL/NETLOGON access fails, indicating GPOs and scripts can''t be delivered.'
    'Active Directory/GPO Processing' = 'High severity when Group Policy processing fails, warning that device policies aren''t applying.'
    'Services/Service Inventory' = 'Issues adopt per-service severity (medium/high/critical) for stopped essentials like Dhcp or WinDefend, highlighting key service outages.'
    'Events' = 'Adds informational issues for logs with ≥5 errors and low-severity items for ≥10 warnings, so noisy event logs get attention.'
    'Printing' = 'High severity for stopped/disabled spooler or unreachable hosts, medium/high for offline queues and long jobs, warnings for weak ports/SNMP/drivers, and good cards for healthy posture—plainly, it surfaces printing security and reliability gaps.'
    'Hardware/Removable Media – Autorun/Autoplay' = 'Medium severity when Autorun/Autoplay remains enabled, meaning inserted media could auto-execute code.'
    'Hardware/Removable Storage Control' = 'Medium-to-high severity when required removable storage restrictions aren''t enforced, signaling data leakage or malware risk from portable drives.'
    'Hardware/Bluetooth & Wireless Sharing' = 'Low findings when Bluetooth, Wi-Fi sharing, or Nearby sharing deviate from the baseline on laptops, meaning users might share data wirelessly against policy.'
    'Storage/SMART' = 'Critical when SMART output shows failure keywords, telling you a drive may be about to fail.'
    'Storage/SMART Wear' = 'Medium at ~85% SSD wear, high at ≥95%, with normals for remaining life/temperature, so you know when flash storage is near end-of-life.'
    'Storage/Disks' = 'Raises an issue at the worst observed severity when disks report offline/read-only/bad health states, flagging imminent disk problems.'
    'Storage/Volumes' = 'Issues at the worst severity among volumes reporting health warnings, indicating logical volume problems.'
    'Storage/Free Space' = 'Critical when free space breaches critical floors and high when below warning thresholds, showing storage depletion risk.'
}

function Resolve-AnalyzerCategoryGroup {
    param([string]$Name)

    if (-not $Name) { return 'General' }
    $trimmed = $Name.Trim()
    switch -regex ($trimmed) {
        '^(?i)services'            { return 'Services' }
        '^(?i)office'              { return 'Office' }
        '^(?i)network|^dhcp'       { return 'Network' }
        '^(?i)system'              { return 'System' }
        '^(?i)storage'             { return 'Storage' }
        '^(?i)hardware'            { return 'Hardware' }
        '^(?i)security'            { return 'Security' }
        '^(?i)active\s*directory' { return 'Active Directory' }
        '^(?i)printing'            { return 'Printing' }
        '^(?i)events'              { return 'Events' }
        default                    { return $trimmed }
    }
}

function Get-PlainLanguageFallback {
    param([string]$Area)

    $label = if ([string]::IsNullOrWhiteSpace($Area)) { 'this area' } else { $Area }
    return "This card summarizes $label findings and the technical evidence below captures what the analyzer observed."
}

function Get-PlainLanguageMetadata {
    param(
        [string]$CategoryName,
        [string]$Subcategory
    )

    $base = Resolve-AnalyzerCategoryGroup -Name $CategoryName
    $subcategoryText = if ([string]::IsNullOrWhiteSpace($Subcategory)) { $null } else { $Subcategory.Trim() }

    $canonical = $null
    if ($base -and $subcategoryText) {
        if ($script:PlainLanguageAreaOverrides.ContainsKey($base) -and $script:PlainLanguageAreaOverrides[$base].ContainsKey($subcategoryText)) {
            $canonical = $script:PlainLanguageAreaOverrides[$base][$subcategoryText]
        } else {
            $canonical = ('{0}/{1}' -f $base, $subcategoryText)
        }
    } elseif ($base) {
        $canonical = $base
    }

    if (-not $canonical -and $CategoryName) {
        $canonical = $CategoryName.Trim()
    }

    $explanation = $null
    if ($canonical -and $script:PlainLanguageExplanations.ContainsKey($canonical)) {
        $explanation = $script:PlainLanguageExplanations[$canonical]
    }

    if (-not $explanation) {
        $explanation = Get-PlainLanguageFallback -Area $canonical
    }

    return [pscustomobject]@{
        Area        = $canonical
        Explanation = $explanation
    }
}

function Get-AnalyzerArtifact {
    param(
        [Parameter(Mandatory)]
        $Context,

        [Parameter(Mandatory)]
        [string]$Name
    )

    if (-not $Context -or -not $Context.Artifacts) { return $null }

    $key = $Name.ToLowerInvariant()
    $lookupKeys = @($key)
    if ($key -notmatch '\.') {
        $lookupKeys += ($key + '.json')
    }

    $entries = $null
    foreach ($candidate in $lookupKeys) {
        if ($Context.Artifacts.ContainsKey($candidate)) {
            $entries = $Context.Artifacts[$candidate]
            break
        }
    }

    if (-not $entries) { return $null }

    if ($entries.Count -gt 1) { return $entries }
    return $entries[0]
}

function New-CategoryResult {
    param(
        [Parameter(Mandatory)]
        [string]$Name
    )

    $source = Get-HeuristicSourceMetadata

    return [pscustomobject]@{
        Name    = $Name
        Issues  = New-Object System.Collections.Generic.List[pscustomobject]
        Normals = New-Object System.Collections.Generic.List[pscustomobject]
        Checks  = New-Object System.Collections.Generic.List[pscustomobject]
        Source  = $source
    }
}

function Add-CategoryIssue {
    param(
        [Parameter(Mandatory)]
        $CategoryResult,

        [Parameter(Mandatory)]
        [string]$Severity,

        [Parameter(Mandatory)]
        [string]$Title,

        [object]$Evidence = $null,

        [string]$Subcategory = $null,

        [string]$CheckId = $null
    )

    $source = Get-HeuristicSourceMetadata

    $subcategoryText = $null
    if ($PSBoundParameters.ContainsKey('Subcategory') -and $null -ne $Subcategory) {
        $subcategoryText = [string]$Subcategory
    }

    $entry = [ordered]@{
        Severity = $Severity
        Title    = $Title
        Evidence = $Evidence
    }

    if ($subcategoryText -and -not [string]::IsNullOrWhiteSpace($subcategoryText)) {
        $entry['Subcategory'] = $subcategoryText
    }

    if ($PSBoundParameters.ContainsKey('CheckId') -and -not [string]::IsNullOrWhiteSpace($CheckId)) {
        $entry['CheckId'] = $CheckId
    }

    if ($source) { $entry['Source'] = $source }

    $plain = Get-PlainLanguageMetadata -CategoryName (if ($CategoryResult.PSObject.Properties['Name']) { [string]$CategoryResult.Name } else { $null }) -Subcategory $subcategoryText
    if ($plain) {
        if ($plain.Area) { $entry['Area'] = $plain.Area }
        if ($plain.Explanation) { $entry['PlainLanguage'] = $plain.Explanation }
    }

    $CategoryResult.Issues.Add([pscustomobject]$entry) | Out-Null
}

function Add-CategoryNormal {
    param(
        [Parameter(Mandatory)]
        $CategoryResult,

        [Parameter(Mandatory)]
        [string]$Title,

        [object]$Evidence = $null,

        [string]$Subcategory = $null,

        [string]$CheckId = $null
    )

    $source = Get-HeuristicSourceMetadata

    $subcategoryText = $null
    if ($PSBoundParameters.ContainsKey('Subcategory') -and $null -ne $Subcategory) {
        $subcategoryText = [string]$Subcategory
    }

    $entry = [ordered]@{
        Title    = $Title
        Evidence = $Evidence
    }

    if ($subcategoryText -and -not [string]::IsNullOrWhiteSpace($subcategoryText)) {
        $entry['Subcategory'] = $subcategoryText
    }

    if ($PSBoundParameters.ContainsKey('CheckId') -and -not [string]::IsNullOrWhiteSpace($CheckId)) {
        $entry['CheckId'] = $CheckId
    }

    if ($source) { $entry['Source'] = $source }

    $plain = Get-PlainLanguageMetadata -CategoryName (if ($CategoryResult.PSObject.Properties['Name']) { [string]$CategoryResult.Name } else { $null }) -Subcategory $subcategoryText
    if ($plain) {
        if ($plain.Area) { $entry['Area'] = $plain.Area }
        if ($plain.Explanation) { $entry['PlainLanguage'] = $plain.Explanation }
    }

    $CategoryResult.Normals.Add([pscustomobject]$entry) | Out-Null
}

function Add-CategoryCheck {
    param(
        [Parameter(Mandatory)]
        $CategoryResult,

        [Parameter(Mandatory)]
        [string]$Name,

        [Parameter(Mandatory)]
        [string]$Status,

        [string]$Details = ''
    )

    $source = Get-HeuristicSourceMetadata

    $entry = [ordered]@{
        Name    = $Name
        Status  = $Status
        Details = $Details
    }

    if ($source) { $entry['Source'] = $source }

    $CategoryResult.Checks.Add([pscustomobject]$entry) | Out-Null
}

function Merge-AnalyzerResults {
    param(
        [Parameter(Mandatory)]
        [System.Collections.Generic.IEnumerable[object]]$Categories
    )

    $issues = New-Object System.Collections.Generic.List[pscustomobject]
    $normals = New-Object System.Collections.Generic.List[pscustomobject]
    $checks = New-Object System.Collections.Generic.List[pscustomobject]

    foreach ($category in $Categories) {
        if (-not $category) { continue }
        foreach ($item in $category.Issues) { $issues.Add($item) | Out-Null }
        foreach ($item in $category.Normals) { $normals.Add($item) | Out-Null }
        foreach ($item in $category.Checks) { $checks.Add($item) | Out-Null }
    }

    return [pscustomobject]@{
        Issues  = $issues
        Normals = $normals
        Checks  = $checks
    }
}

function Get-ArtifactPayload {
    param(
        [Parameter(Mandatory)]
        $Artifact
    )

    if (-not $Artifact) { return $null }

    if ($Artifact -is [System.Collections.IEnumerable] -and -not ($Artifact -is [string])) {
        $payloads = [System.Collections.Generic.List[object]]::new()
        foreach ($item in $Artifact) {
            $null = $payloads.Add($item.Data.Payload)
        }

        return $payloads
    }

    if ($Artifact.Data -and $Artifact.Data.PSObject.Properties['Payload']) {
        return $Artifact.Data.Payload
    }

    return $null
}

function Resolve-SinglePayload {
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        $Payload
    )

    if ($null -eq $Payload) { return $null }

    if ($Payload -is [System.Collections.IEnumerable] -and -not ($Payload -is [string])) {
        return ($Payload | Select-Object -First 1)
    }

    return $Payload
}
