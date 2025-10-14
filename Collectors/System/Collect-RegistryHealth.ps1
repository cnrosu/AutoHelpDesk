<#!
.SYNOPSIS
    Collects registry hygiene and consistency signals for analyzer heuristics.
.DESCRIPTION
    Evaluates registry-related reliability heuristics that require live system access,
    including hive transaction log status, service image paths, autorun entries,
    policy overrides, and other registry-backed configuration. Results are persisted
    as normalized check objects for the analyzer pipeline.
#>
[CmdletBinding()]
param(
    [Parameter()]
    [string]$OutputDirectory = (Join-Path -Path (Split-Path -Parent $PSCommandPath) -ChildPath '..\\output')
)

. (Join-Path -Path $PSScriptRoot -ChildPath '..\\CollectorCommon.ps1')

function New-RegistryCheckResult {
    param(
        [Parameter(Mandatory)][string]$Id,
        [Parameter(Mandatory)][string]$Title,
        [Parameter()][ValidateSet('info','warning','medium','high','critical','low')]
        [string]$Severity = 'info',
        [string]$Subcategory = 'Integrity',
        [string]$Evidence,
        [string]$Remediation
    )

    return [pscustomobject]@{
        Category    = 'Registry'
        Id          = $Id
        Severity    = $Severity
        Title       = $Title
        Subcategory = $Subcategory
        Evidence    = $Evidence
        Remediation = $Remediation
    }
}

function Resolve-ExecutableFromCommand {
    param([string]$Command)

    if ([string]::IsNullOrWhiteSpace($Command)) { return $null }

    $trimmed = $Command.Trim()
    if (-not $trimmed) { return $null }

    $candidate = $trimmed
    if ($candidate.StartsWith('"')) {
        $match = [regex]::Match($candidate, '^"([^\"]+)"')
        if ($match.Success) { $candidate = $match.Groups[1].Value }
    }

    if ($candidate -eq $trimmed) {
        $parts = $trimmed.Split([char[]]@(' ',"`t"), [StringSplitOptions]::RemoveEmptyEntries)
        if ($parts.Count -gt 0) { $candidate = $parts[0] }
    }

    $candidate = $candidate.Trim('"',"'","`t"," ")
    if (-not $candidate) { return $null }

    if ($candidate -like '\\??\\*') {
        $candidate = $candidate.Substring(4)
    }

    $expanded = [Environment]::ExpandEnvironmentVariables($candidate)

    if ($expanded -match '^(?i)(?:%SystemRoot%\\)?System32\\svchost\.exe' -or
        $expanded -match '^(?i)svchost\.exe') {
        return $null
    }

    if ($expanded -match '^(?i)rundll32\.exe') { return $null }

    if (-not [System.IO.Path]::IsPathRooted($expanded)) {
        if ($expanded -match '^(?i)\\SystemRoot\\') {
            $expanded = Join-Path $env:SystemRoot $expanded.Substring(11)
        } elseif ($expanded -match '^(?i)%SystemRoot%') {
            $expanded = $expanded -replace '^(?i)%SystemRoot%', $env:SystemRoot
        } elseif ($expanded -match '\\') {
            try {
                $expanded = Join-Path $env:SystemRoot $expanded
            } catch {
                return $null
            }
        } else {
            return $null
        }
    }

    return $expanded
}

function Test-FileExists {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return $false }

    try {
        return Test-Path -LiteralPath $Path -PathType Leaf
    } catch {
        return $false
    }
}

function Get-RegistryHiveLogChecks {
    $results = New-Object System.Collections.Generic.List[object]

    $machineHives = 'SYSTEM','SOFTWARE','SECURITY','SAM','DEFAULT'
    $configRoot = Join-Path $env:SystemRoot 'System32\\Config'

    foreach ($hive in $machineHives) {
        $hivePath = Join-Path $configRoot $hive
        foreach ($suffix in @('LOG1','LOG2')) {
            $logPath = Join-Path $configRoot ("{0}.{1}" -f $hive, $suffix)
            $exists = Test-Path -LiteralPath $logPath
            $size = 0
            if ($exists) {
                try { $size = (Get-Item -LiteralPath $logPath).Length } catch { $size = 0 }
            }

            if (-not $exists -or $size -eq 0) {
                $title = "{0} hive missing transaction log ({1}), so crash recovery resilience is reduced." -f $hive, $suffix
                $evidence = "{0} -> Exists={1} Size={2}" -f $logPath, $exists, $size
                $remediation = 'Back up the system and run SFC/DISM if registry errors occur; validate storage stability.'
                $results.Add((New-RegistryCheckResult -Id 'REG.HiveLogs.MissingOrZero' -Severity 'warning' -Subcategory 'Integrity' -Title $title -Evidence $evidence -Remediation $remediation)) | Out-Null
            }
        }
    }

    try {
        $userSids = Get-ChildItem 'HKU:' -ErrorAction Stop | Where-Object { $_.Name -match 'S-1-5-21-' }
        foreach ($sidKey in $userSids) {
            try {
                $sid = Split-Path $sidKey.Name -Leaf
                $profile = (Get-CimInstance Win32_UserProfile -Filter "SID='$sid'").LocalPath
                if (-not $profile) { continue }

                $targets = @(
                    @{ Hive = 'NTUSER.DAT'; Path = Join-Path $profile 'NTUSER.DAT'; Log1 = Join-Path $profile 'NTUSER.DAT.LOG1'; Log2 = Join-Path $profile 'NTUSER.DAT.LOG2' },
                    @{ Hive = 'UsrClass.dat'; Path = Join-Path $profile 'AppData\\Local\\Microsoft\\Windows\\UsrClass.dat'; Log1 = Join-Path $profile 'AppData\\Local\\Microsoft\\Windows\\UsrClass.dat.LOG1'; Log2 = Join-Path $profile 'AppData\\Local\\Microsoft\\Windows\\UsrClass.dat.LOG2' }
                )

                foreach ($entry in $targets) {
                    foreach ($suffix in @('Log1','Log2')) {
                        $logPath = $entry[$suffix]
                        if (-not $logPath) { continue }
                        $exists = Test-Path -LiteralPath $logPath
                        $size = 0
                        if ($exists) {
                            try { $size = (Get-Item -LiteralPath $logPath).Length } catch { $size = 0 }
                        }

                        if (-not $exists -or $size -eq 0) {
                            $title = "Profile hive {0} missing transaction log ({1}), so profile recovery after crashes may fail." -f $entry.Hive, $suffix.ToUpperInvariant()
                            $evidence = "{0} -> Exists={1} Size={2}" -f $logPath, $exists, $size
                            $remediation = 'Back up user data and repair the profile if registry errors appear; check for disk or power issues.'
                            $results.Add((New-RegistryCheckResult -Id 'REG.ProfileHiveLogs.MissingOrZero' -Severity 'warning' -Subcategory 'Integrity' -Title $title -Evidence $evidence -Remediation $remediation)) | Out-Null
                        }
                    }
                }
            } catch {
                continue
            }
        }
    } catch {
        $title = 'User hive transaction logs could not be inspected, so profile recovery risks may be missed.'
        $evidence = $_.Exception.Message
        $remediation = 'Retry the collector with administrative rights to capture user hive details.'
        $results.Add((New-RegistryCheckResult -Id 'REG.ProfileHiveLogs.AccessError' -Severity 'info' -Subcategory 'Integrity' -Title $title -Evidence $evidence -Remediation $remediation)) | Out-Null
    }

    return $results.ToArray()
}

function Get-SystemDriveFreeSpaceCheck {
    $drive = $null
    try {
        $drive = Get-PSDrive -Name 'C' -ErrorAction Stop
    } catch {
        return @()
    }

    if (-not $drive -or -not $drive.Free -or -not $drive.Used) { return @() }

    $freeBytes = [double]$drive.Free
    $thresholdBytes = 2GB

    if ($freeBytes -lt $thresholdBytes) {
        $freeGB = [math]::Round($freeBytes / 1GB, 2)
        $title = "System drive has only {0} GB free, so registry writes may fail or roll back silently." -f $freeGB
        $evidence = "Drive C: Free={0} bytes" -f [int64]$freeBytes
        $remediation = 'Free disk space on C: before deeper registry or update troubleshooting.'
        return @(New-RegistryCheckResult -Id 'REG.SystemDrive.LowFreeSpace' -Severity 'warning' -Subcategory 'Integrity' -Title $title -Evidence $evidence -Remediation $remediation)
    }

    return @()
}

function Get-ServiceImagePathChecks {
    $results = New-Object System.Collections.Generic.List[object]
    $serviceRoot = 'HKLM:\SYSTEM\CurrentControlSet\Services'

    if (-not (Test-Path -LiteralPath $serviceRoot)) { return @() }

    foreach ($serviceKey in Get-ChildItem -Path $serviceRoot -ErrorAction SilentlyContinue) {
        $serviceName = Split-Path $serviceKey.Name -Leaf
        try {
            $props = Get-ItemProperty -LiteralPath $serviceKey.PSPath -ErrorAction Stop
        } catch {
            continue
        }

        if (-not $props) { continue }

        $imagePath = $null
        if ($props.PSObject.Properties['ImagePath']) { $imagePath = [string]$props.ImagePath }
        if ([string]::IsNullOrWhiteSpace($imagePath)) { continue }

        $resolvedPath = Resolve-ExecutableFromCommand -Command $imagePath
        if (-not $resolvedPath) { continue }

        $typeValue = $null
        if ($props.PSObject.Properties['Type']) {
            try { $typeValue = [int]$props.Type } catch { $typeValue = $null }
        }

        $pathMissing = -not (Test-FileExists -Path $resolvedPath)

        if ($typeValue -in @(1,2) -and $pathMissing) {
            $displayName = $serviceName
            if ($props.PSObject.Properties['DisplayName'] -and $props.DisplayName) { $displayName = [string]$props.DisplayName }
            $title = "Driver service '{0}' points to missing binary '{1}', so boot or device initialization can fail." -f $displayName, $resolvedPath
            $evidence = "{0} -> Type={1} ImagePath='{2}'" -f $serviceKey.Name, $typeValue, $imagePath
            $remediation = 'Remove the orphaned driver entry or reinstall the hardware/vendor driver.'
            $results.Add((New-RegistryCheckResult -Id 'REG.DriverImagePath.MissingBinary' -Severity 'high' -Subcategory 'Services' -Title $title -Evidence $evidence -Remediation $remediation)) | Out-Null
            continue
        }

        if ($pathMissing) {
            $displayName = $serviceName
            if ($props.PSObject.Properties['DisplayName'] -and $props.DisplayName) { $displayName = [string]$props.DisplayName }
            $title = "Service '{0}' points to missing executable '{1}', so it cannot start or indicates a stale entry." -f $displayName, $resolvedPath
            $evidence = "{0} -> ImagePath='{1}'" -f $serviceKey.Name, $imagePath
            $remediation = 'Repair or remove the service entry; reinstall the associated vendor package if needed.'
            $results.Add((New-RegistryCheckResult -Id 'REG.ServiceImagePath.MissingBinary' -Severity 'warning' -Subcategory 'Services' -Title $title -Evidence $evidence -Remediation $remediation)) | Out-Null
        }
    }

    return $results.ToArray()
}

function Get-StartupMissingFileChecks {
    $results = New-Object System.Collections.Generic.List[object]
    try {
        $entries = Get-CimInstance -ClassName Win32_StartupCommand -ErrorAction Stop
    } catch {
        try {
            $entries = Get-WmiObject -Class Win32_StartupCommand -ErrorAction Stop
        } catch {
            $title = 'Startup command inventory failed, so missing autoruns that slow logons may go unnoticed.'
            $results.Add((New-RegistryCheckResult -Id 'REG.Autostart.InventoryError' -Severity 'info' -Subcategory 'Autostarts' -Title $title -Evidence $_.Exception.Message -Remediation 'Re-run collection with administrative rights to inventory startup entries.')) | Out-Null
            return $results.ToArray()
        }
    }

    foreach ($entry in @($entries)) {
        if (-not $entry) { continue }
        $command = $null
        if ($entry.PSObject.Properties['Command']) { $command = [string]$entry.Command }
        if ([string]::IsNullOrWhiteSpace($command)) { continue }

        $path = Resolve-ExecutableFromCommand -Command $command
        if (-not $path) { continue }
        if (Test-FileExists -Path $path) { continue }

        $name = if ($entry.PSObject.Properties['Name']) { [string]$entry.Name } else { '(Unknown)' }
        $location = if ($entry.PSObject.Properties['Location']) { [string]$entry.Location } else { '(Unknown)' }
        $title = "Startup entry '{0}' references missing file '{1}', so the app will not launch at logon and may indicate persistence remnants." -f $name, $path
        $evidence = "Command='{0}' Location='{1}'" -f $command, $location
        $remediation = 'Remove the stale autorun or reinstall the application to restore the startup executable.'
        $results.Add((New-RegistryCheckResult -Id 'REG.Autostart.MissingBinary' -Severity 'info' -Subcategory 'Autostarts' -Title $title -Evidence $evidence -Remediation $remediation)) | Out-Null
    }

    return $results.ToArray()
}

function Get-IfeoDebuggerChecks {
    $path = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'
    if (-not (Test-Path -LiteralPath $path)) { return @() }

    $results = New-Object System.Collections.Generic.List[object]
    foreach ($key in Get-ChildItem -Path $path -ErrorAction SilentlyContinue) {
        try {
            $props = Get-ItemProperty -LiteralPath $key.PSPath -Name Debugger -ErrorAction Stop
        } catch {
            continue
        }

        if ($props -and $props.Debugger) {
            $exe = Split-Path $key.Name -Leaf
            $title = "IFEO debugger set for '{0}', so process launches can be hijacked or disabled." -f $exe
            $evidence = "Debugger='{0}'" -f $props.Debugger
            $remediation = 'Verify the debugger is from a trusted security tool; remove the value if unintended.'
            $results.Add((New-RegistryCheckResult -Id 'REG.IFEO.DebuggerSet' -Severity 'high' -Subcategory 'Persistence' -Title $title -Evidence $evidence -Remediation $remediation)) | Out-Null
        }
    }

    return $results.ToArray()
}

function Get-AppInitChecks {
    $path = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows'
    if (-not (Test-Path -LiteralPath $path)) { return @() }

    try {
        $props = Get-ItemProperty -LiteralPath $path -ErrorAction Stop
    } catch {
        return @()
    }

    $loadValue = $null
    if ($props.PSObject.Properties['LoadAppInit_DLLs']) {
        try { $loadValue = [int]$props.LoadAppInit_DLLs } catch { $loadValue = $props.LoadAppInit_DLLs }
    }

    $dlls = $null
    if ($props.PSObject.Properties['AppInit_DLLs']) { $dlls = [string]$props.AppInit_DLLs }

    if ($loadValue -eq 1 -and -not [string]::IsNullOrWhiteSpace($dlls)) {
        $title = 'AppInit_DLLs is enabled, so legacy DLL injection will occur for user32-hosted processes.'
        $evidence = "LoadAppInit_DLLs={0} AppInit_DLLs='{1}'" -f $loadValue, $dlls
        $remediation = 'Disable AppInit_DLLs unless required and verify referenced DLLs are present and trusted.'
        return @(New-RegistryCheckResult -Id 'REG.AppInit.Enabled' -Severity 'warning' -Subcategory 'Persistence' -Title $title -Evidence $evidence -Remediation $remediation)
    }

    return @()
}

function Get-WinlogonChecks {
    $path = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
    if (-not (Test-Path -LiteralPath $path)) { return @() }

    try { $props = Get-ItemProperty -LiteralPath $path -ErrorAction Stop } catch { return @() }

    $results = New-Object System.Collections.Generic.List[object]

    if ($props.PSObject.Properties['Shell']) {
        $shell = [string]$props.Shell
        if (-not [string]::Equals($shell.Trim(), 'explorer.exe', [System.StringComparison]::OrdinalIgnoreCase)) {
            $title = "Winlogon shell set to '{0}', so users may receive a nonstandard desktop shell." -f $shell
            $remediation = 'Restore Shell to explorer.exe unless a managed shell replacement is intentional.'
            $evidence = "Shell='{0}'" -f $shell
            $results.Add((New-RegistryCheckResult -Id 'REG.Winlogon.ShellOverride' -Severity 'warning' -Subcategory 'Persistence' -Title $title -Evidence $evidence -Remediation $remediation)) | Out-Null
        }
    }

    if ($props.PSObject.Properties['Userinit']) {
        $userInit = [string]$props.Userinit
        if (-not $userInit.Trim().EndsWith('userinit.exe,', [System.StringComparison]::OrdinalIgnoreCase)) {
            $title = "Winlogon Userinit set to '{0}', so profile logons may hang or run unexpected code." -f $userInit
            $remediation = 'Reset Userinit to userinit.exe, to ensure standard profile initialization.'
            $evidence = "Userinit='{0}'" -f $userInit
            $results.Add((New-RegistryCheckResult -Id 'REG.Winlogon.UserinitOverride' -Severity 'warning' -Subcategory 'Persistence' -Title $title -Evidence $evidence -Remediation $remediation)) | Out-Null
        }
    }

    return $results.ToArray()
}

function Resolve-LsaPackagePath {
    param([string]$Value)

    if ([string]::IsNullOrWhiteSpace($Value)) { return $null }
    $trimmed = $Value.Trim()
    if (-not $trimmed) { return $null }

    if ($trimmed -notmatch '\\' -and $trimmed -notmatch ':' -and $trimmed -notmatch '\.dll$') {
        return $null
    }

    $expanded = [Environment]::ExpandEnvironmentVariables($trimmed)
    if (-not [System.IO.Path]::IsPathRooted($expanded)) {
        $expanded = Join-Path $env:SystemRoot 'System32' $expanded
    }

    return $expanded
}

function Get-LsaPackageChecks {
    $path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
    if (-not (Test-Path -LiteralPath $path)) { return @() }

    try { $props = Get-ItemProperty -LiteralPath $path -ErrorAction Stop } catch { return @() }

    $results = New-Object System.Collections.Generic.List[object]

    foreach ($name in @('Authentication Packages','Security Packages','Notification Packages')) {
        if (-not $props.PSObject.Properties[$name]) { continue }
        $values = $props.$name
        if (-not $values) { continue }

        if ($values -isnot [System.Collections.IEnumerable] -or $values -is [string]) {
            $values = @($values)
        }

        foreach ($value in $values) {
            $candidatePath = Resolve-LsaPackagePath -Value ([string]$value)
            if (-not $candidatePath) { continue }
            if (Test-FileExists -Path $candidatePath) { continue }

            $title = "LSA package '{0}' references missing file '{1}', so authentication providers may fail to load." -f $value, $candidatePath
            $evidence = "{0} -> '{1}'" -f $name, $value
            $remediation = 'Remove the stale LSA package entry or restore the referenced DLL.'
            $results.Add((New-RegistryCheckResult -Id 'REG.Lsa.PackageMissing' -Severity 'high' -Subcategory 'Security' -Title $title -Evidence $evidence -Remediation $remediation)) | Out-Null
        }
    }

    return $results.ToArray()
}

function Get-ApprovedShellExtensionChecks {
    $approvedPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Approved'
    if (-not (Test-Path -LiteralPath $approvedPath)) { return @() }

    $clsids = New-Object System.Collections.Generic.HashSet[string]
    try {
        $props = Get-ItemProperty -LiteralPath $approvedPath -ErrorAction Stop
        foreach ($prop in $props.PSObject.Properties) {
            if ($prop.MemberType -ne 'NoteProperty') { continue }
            $name = [string]$prop.Name
            if ($name -match '^\{[0-9A-Fa-f-]+\}$') { $null = $clsids.Add($name) }
        }
    } catch {
        return @()
    }

    $results = New-Object System.Collections.Generic.List[object]
    foreach ($clsid in $clsids) {
        $inprocPath = "HKCR:\CLSID\\$clsid\\InprocServer32"
        if (-not (Test-Path -LiteralPath $inprocPath)) {
            $title = "Approved shell extension {0} missing InprocServer32 key, so Explorer may load a broken extension." -f $clsid
            $remediation = 'Remove the stale shell extension registration or reinstall the related application.'
            $results.Add((New-RegistryCheckResult -Id 'REG.CLSID.InprocMissing' -Severity 'info' -Subcategory 'COM' -Title $title -Evidence "$inprocPath not found" -Remediation $remediation)) | Out-Null
            continue
        }

        try {
            $defaultValue = (Get-ItemProperty -LiteralPath $inprocPath -ErrorAction Stop)."(default)"
            if ($defaultValue) {
                $candidate = Resolve-ExecutableFromCommand -Command ([string]$defaultValue)
                if (-not $candidate) { $candidate = [Environment]::ExpandEnvironmentVariables([string]$defaultValue) }
                if (-not (Test-FileExists -Path $candidate)) {
                    $title = "Shell extension {0} points to missing DLL '{1}', so Explorer may crash or load errors." -f $clsid, $candidate
                    $evidence = "{0} -> '{1}'" -f $inprocPath, $defaultValue
                    $remediation = 'Remove or repair the shell extension registration.'
                    $results.Add((New-RegistryCheckResult -Id 'REG.CLSID.InprocBroken' -Severity 'warning' -Subcategory 'COM' -Title $title -Evidence $evidence -Remediation $remediation)) | Out-Null
                }
            }
        } catch {
            $title = "Shell extension {0} could not be inspected, so DLL presence is unknown." -f $clsid
            $results.Add((New-RegistryCheckResult -Id 'REG.CLSID.InspectError' -Severity 'info' -Subcategory 'COM' -Title $title -Evidence $_.Exception.Message -Remediation 'Re-run collection with administrative rights to inspect CLSID registrations.')) | Out-Null
        }
    }

    return $results.ToArray()
}

function Get-UninstallMissingFileChecks {
    $roots = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'
    )

    $results = New-Object System.Collections.Generic.List[object]

    foreach ($root in $roots) {
        if (-not (Test-Path -LiteralPath $root)) { continue }
        foreach ($child in Get-ChildItem -Path $root -ErrorAction SilentlyContinue) {
            try { $props = Get-ItemProperty -LiteralPath $child.PSPath -ErrorAction Stop } catch { continue }
            if (-not $props) { continue }

            $command = $null
            if ($props.PSObject.Properties['UninstallString']) { $command = [string]$props.UninstallString }
            if ([string]::IsNullOrWhiteSpace($command)) { continue }

            $path = Resolve-ExecutableFromCommand -Command $command
            if (-not $path) { continue }
            if (Test-FileExists -Path $path) { continue }

            $displayName = if ($props.PSObject.Properties['DisplayName'] -and $props.DisplayName) { [string]$props.DisplayName } else { Split-Path $child.Name -Leaf }
            $title = "Uninstall entry '{0}' references missing file '{1}', so the program cannot be removed cleanly." -f $displayName, $path
            $evidence = "{0} -> UninstallString='{1}'" -f $child.Name, $command
            $remediation = 'Repair or reinstall the application, or remove the stale uninstall entry with care.'
            $results.Add((New-RegistryCheckResult -Id 'REG.Uninstall.MissingUninstaller' -Severity 'info' -Subcategory 'Uninstall' -Title $title -Evidence $evidence -Remediation $remediation)) | Out-Null
        }
    }

    return $results.ToArray()
}

function Get-FileAssociationChecks {
    $extensions = '.html','.pdf','.docx'
    $results = New-Object System.Collections.Generic.List[object]

    foreach ($ext in $extensions) {
        $extKey = "HKCR:$ext"
        if (-not (Test-Path -LiteralPath $extKey)) { continue }
        try { $default = (Get-ItemProperty -LiteralPath $extKey -ErrorAction Stop)."(default)" } catch { continue }
        if (-not $default) { continue }

        $progId = [string]$default
        $commandKey = "HKCR:\$progId\\shell\\open\\command"
        if (-not (Test-Path -LiteralPath $commandKey)) { continue }
        try { $commandValue = (Get-ItemProperty -LiteralPath $commandKey -ErrorAction Stop)."(default)" } catch { continue }
        if (-not $commandValue) { continue }

        $path = Resolve-ExecutableFromCommand -Command ([string]$commandValue)
        if (-not $path) { continue }
        if (Test-FileExists -Path $path) { continue }

        $title = "File association for {0} uses missing executable '{1}', so double-click open may fail." -f $ext, $path
        $evidence = "{0} -> '{1}'" -f $commandKey, $commandValue
        $remediation = 'Reassociate the file type with an installed application or reinstall the handler.'
        $results.Add((New-RegistryCheckResult -Id 'REG.FileAssoc.MissingHandler' -Severity 'info' -Subcategory 'Associations' -Title $title -Evidence $evidence -Remediation $remediation)) | Out-Null
    }

    return $results.ToArray()
}

function Get-PolicyAntiPatternChecks {
    $results = New-Object System.Collections.Generic.List[object]

    $defPol = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender'
    if (Test-Path -LiteralPath $defPol) {
        try {
            $spynet = Get-ItemProperty -LiteralPath (Join-Path $defPol 'Spynet') -ErrorAction Stop
            if ($spynet -and $spynet.PSObject.Properties['SpynetReporting']) {
                $value = [int]$spynet.SpynetReporting
                if ($value -eq 0) {
                    $title = 'Defender MAPS reporting disabled by policy, so cloud-delivered protection is offline.'
                    $evidence = "{0} -> SpynetReporting={1}" -f (Join-Path $defPol 'Spynet'), $value
                    $remediation = 'Re-enable Defender cloud reporting via policy or security baseline.'
                    $results.Add((New-RegistryCheckResult -Id 'REG.Policy.Defender.MAPSOff' -Severity 'warning' -Subcategory 'Policy' -Title $title -Evidence $evidence -Remediation $remediation)) | Out-Null
                }
            }
        } catch {
        }
    }

    $systemPolicy = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System'
    if (Test-Path -LiteralPath $systemPolicy) {
        try {
            $smartScreen = Get-ItemProperty -LiteralPath $systemPolicy -ErrorAction Stop
            if ($smartScreen -and $smartScreen.PSObject.Properties['EnableSmartScreen']) {
                $enable = [int]$smartScreen.EnableSmartScreen
                if ($enable -eq 0) {
                    $title = 'SmartScreen disabled by policy, so phishing and app reputation checks are bypassed.'
                    $evidence = "{0} -> EnableSmartScreen={1}" -f $systemPolicy, $enable
                    $remediation = 'Re-enable SmartScreen through policy or security baseline.'
                    $results.Add((New-RegistryCheckResult -Id 'REG.Policy.SmartScreen.Disabled' -Severity 'warning' -Subcategory 'Policy' -Title $title -Evidence $evidence -Remediation $remediation)) | Out-Null
                }
            }
        } catch {
        }
    }

    $wuPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'
    if (Test-Path -LiteralPath $wuPath) {
        try {
            $au = Get-ItemProperty -LiteralPath $wuPath -ErrorAction Stop
            if ($au -and $au.PSObject.Properties['NoAutoUpdate']) {
                $value = [int]$au.NoAutoUpdate
                if ($value -eq 1) {
                    $title = 'Automatic Updates disabled by policy, so devices may miss critical fixes.'
                    $evidence = "{0} -> NoAutoUpdate={1}" -f $wuPath, $value
                    $remediation = 'Enable managed Windows Update or confirm the policy exception is intentional.'
                    $results.Add((New-RegistryCheckResult -Id 'REG.Policy.WU.NoAutoUpdate' -Severity 'info' -Subcategory 'Policy' -Title $title -Evidence $evidence -Remediation $remediation)) | Out-Null
                }
            }
        } catch {
        }
    }

    return $results.ToArray()
}

function Get-RegBackCheck {
    $regBack = Join-Path $env:windir 'System32\\Config\\RegBack'
    if (-not (Test-Path -LiteralPath $regBack)) { return @() }

    try {
        $total = (Get-ChildItem -Path $regBack -File -ErrorAction Stop | Measure-Object Length -Sum).Sum
        if (-not $total -or $total -eq 0) {
            $title = 'RegBack folder contains zero-byte files, so legacy automatic hive backups are unavailable.'
            $evidence = "{0} -> total bytes {1}" -f $regBack, $total
            $remediation = 'Rely on System Restore or full backups; RegBack is disabled by default on modern Windows.'
            return @(New-RegistryCheckResult -Id 'REG.RegBack.ZeroByte' -Severity 'info' -Subcategory 'Recovery' -Title $title -Evidence $evidence -Remediation $remediation)
        }
    } catch {
        $title = 'RegBack folder could not be inspected, so registry backup status is unknown.'
        return @(New-RegistryCheckResult -Id 'REG.RegBack.InspectError' -Severity 'info' -Subcategory 'Recovery' -Title $title -Evidence $_.Exception.Message -Remediation 'Check RegBack permissions or rerun collection as administrator.')
    }

    return @()
}

function Get-RegistryEventChecks {
    $providers = @(
        'Microsoft-Windows-User Profiles Service',
        'Microsoft-Windows-Kernel-General',
        'Ntfs',
        'volsnap'
    )

    $results = New-Object System.Collections.Generic.List[object]
    $start = (Get-Date).AddDays(-7)

    foreach ($provider in $providers) {
        try {
            $events = Get-WinEvent -FilterHashtable @{ LogName = 'System'; ProviderName = $provider; StartTime = $start } -MaxEvents 50 -ErrorAction Stop
            foreach ($event in @($events | Sort-Object TimeCreated -Descending | Select-Object -First 5)) {
                if (-not $event) { continue }
                $snippet = $event.Message
                if ($snippet -and $snippet.Length -gt 200) { $snippet = $snippet.Substring(0, 200) + '…' }
                $title = "Recent {0} event {1} references registry recovery, so recent crashes may have impacted hive integrity." -f $provider, $event.Id
                $evidence = "[{0}] #{1} {2}" -f $event.TimeCreated, $event.Id, $snippet
                $remediation = 'Investigate power stability and storage errors; consider running chkdsk /scan and reviewing system logs.'
                $results.Add((New-RegistryCheckResult -Id 'REG.Events.RecoveryHint' -Severity 'info' -Subcategory 'Integrity' -Title $title -Evidence $evidence -Remediation $remediation)) | Out-Null
            }
        } catch {
            continue
        }
    }

    try {
        $events1530 = Get-WinEvent -FilterHashtable @{ LogName = 'Application'; Id = 1530; ProviderName = 'Microsoft-Windows-User Profiles Service'; StartTime = $start } -MaxEvents 20 -ErrorAction Stop
        foreach ($event in @($events1530)) {
            if (-not $event) { continue }
            $snippet = $event.Message
            if ($snippet -and $snippet.Length -gt 200) { $snippet = $snippet.Substring(0, 200) + '…' }
            $title = 'Event 1530 reported leaked registry handles during logoff, so user profiles may not unload cleanly.'
            $evidence = "[{0}] #{1} {2}" -f $event.TimeCreated, $event.Id, $snippet
            $remediation = 'Identify the process listed in Event 1530 and close it before logoff or update the offending software.'
            $results.Add((New-RegistryCheckResult -Id 'REG.Events.Profile1530' -Severity 'info' -Subcategory 'Profile' -Title $title -Evidence $evidence -Remediation $remediation)) | Out-Null
        }
    } catch {
    }

    return $results.ToArray()
}

function Invoke-Main {
    $checks = New-Object System.Collections.Generic.List[object]

    foreach ($item in Get-RegistryHiveLogChecks) { $checks.Add($item) | Out-Null }
    foreach ($item in Get-SystemDriveFreeSpaceCheck) { $checks.Add($item) | Out-Null }
    foreach ($item in Get-ServiceImagePathChecks) { $checks.Add($item) | Out-Null }
    foreach ($item in Get-StartupMissingFileChecks) { $checks.Add($item) | Out-Null }
    foreach ($item in Get-IfeoDebuggerChecks) { $checks.Add($item) | Out-Null }
    foreach ($item in Get-AppInitChecks) { $checks.Add($item) | Out-Null }
    foreach ($item in Get-WinlogonChecks) { $checks.Add($item) | Out-Null }
    foreach ($item in Get-LsaPackageChecks) { $checks.Add($item) | Out-Null }
    foreach ($item in Get-ApprovedShellExtensionChecks) { $checks.Add($item) | Out-Null }
    foreach ($item in Get-UninstallMissingFileChecks) { $checks.Add($item) | Out-Null }
    foreach ($item in Get-FileAssociationChecks) { $checks.Add($item) | Out-Null }
    foreach ($item in Get-PolicyAntiPatternChecks) { $checks.Add($item) | Out-Null }
    foreach ($item in Get-RegBackCheck) { $checks.Add($item) | Out-Null }
    foreach ($item in Get-RegistryEventChecks) { $checks.Add($item) | Out-Null }

    $payload = [ordered]@{
        Checks = $checks.ToArray()
        Metadata = [ordered]@{
            GeneratedAt = (Get-Date).ToString('o')
            CheckCount  = $checks.Count
        }
    }

    $result = New-CollectorMetadata -Payload $payload
    $outputPath = Export-CollectorResult -OutputDirectory $OutputDirectory -FileName 'registry-health.json' -Data $result -Depth 6
    Write-Output $outputPath
}

Invoke-Main
