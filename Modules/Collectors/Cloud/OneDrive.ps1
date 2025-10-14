function Get-OneDriveState {
    <#
      .SYNOPSIS
        Collects per-user OneDrive state: install, startup, accounts, KFM, policies.
      .NOTES
        Windows PowerShell 5.1 / PowerShell 7 compatible. No admin required.
        Runs in the current user context to read HKCU.
    #>
    [CmdletBinding()]
    param()

    $out = [ordered]@{
        Installed        = $false
        InstallSource    = $null            # PerUser | PerMachine | Unknown
        InstallPath      = $null
        Version          = $null
        AutoStartEnabled = $false
        AutoStartSource  = @()              # RunKey | ScheduledTask | StartupFolder
        Running          = $false
        Accounts         = @()              # [{Type, UserEmail, TenantName, UserFolder, Exists}]
        KFM              = [ordered]@{
            EffectivePolicy = [ordered]@{
                KFMSilentOptIn        = $null
                KFMSilentOptInDesktop = $null
                KFMBlockOptIn         = $null
                DisablePersonalSync   = $null
            }
            EffectiveStatus = [ordered]@{
                DesktopRedirected   = $false
                DocumentsRedirected = $false
                PicturesRedirected  = $false
            }
            Notes = @()
        }
        Notes            = @()
    }

    $candidatePaths = [System.Collections.Generic.List[string]]::new()
    if (-not [string]::IsNullOrWhiteSpace($env:LOCALAPPDATA)) {
        $candidatePaths.Add((Join-Path -Path $env:LOCALAPPDATA -ChildPath 'Microsoft/OneDrive/OneDrive.exe'))
    }

    $programFilesX86 = [Environment]::GetEnvironmentVariable('ProgramFiles(x86)')
    if (-not [string]::IsNullOrWhiteSpace($programFilesX86)) {
        $candidatePaths.Add((Join-Path -Path $programFilesX86 -ChildPath 'Microsoft OneDrive/OneDrive.exe'))
    }

    if (-not [string]::IsNullOrWhiteSpace($env:ProgramFiles)) {
        $candidatePaths.Add((Join-Path -Path $env:ProgramFiles -ChildPath 'Microsoft OneDrive/OneDrive.exe'))
    }

    $candidatePaths = $candidatePaths | Select-Object -Unique

    $exe = $candidatePaths | ForEach-Object { if (Test-Path -LiteralPath $_) { $_ } } | Select-Object -First 1
    if ($exe) {
        $out.Installed = $true
        $out.InstallPath = $exe
        try {
            $out.Version = (Get-Item -LiteralPath $exe).VersionInfo.FileVersion
        } catch {
        }

        if ($exe -like "$env:LOCALAPPDATA*") {
            $out.InstallSource = 'PerUser'
        } elseif ($exe -like "$env:ProgramFiles*") {
            $out.InstallSource = 'PerMachine'
        } else {
            $out.InstallSource = 'Unknown'
        }
    }

    try {
        $run = Get-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -ErrorAction Stop
        if ($run -and $run.PSObject.Properties['OneDrive'] -and $run.OneDrive) {
            $out.AutoStartEnabled = $true
            $out.AutoStartSource += 'RunKey'
        }
    } catch {
    }

    try {
        if (Get-Command -Name Get-ScheduledTask -ErrorAction SilentlyContinue) {
            $tasks = Get-ScheduledTask -TaskPath '\\Microsoft\\OneDrive\\' -ErrorAction SilentlyContinue
            if ($tasks -and $tasks.Count -gt 0) {
                $out.AutoStartSource += 'ScheduledTask'
                $out.AutoStartEnabled = $true
            }
        } else {
            $taskOutput = & schtasks.exe /Query /FO LIST /TN '\\Microsoft\\OneDrive\\*' 2>$null
            if ($taskOutput) {
                $out.AutoStartSource += 'ScheduledTask'
                $out.AutoStartEnabled = $true
            }
        }
    } catch {
    }

    try {
        $startupFolder = [Environment]::GetFolderPath('Startup')
        if ($startupFolder) {
            $startupShortcut = Join-Path -Path $startupFolder -ChildPath 'OneDrive.lnk'
            if (Test-Path -LiteralPath $startupShortcut) {
                $out.AutoStartSource += 'StartupFolder'
                $out.AutoStartEnabled = $true
            }
        }
    } catch {
    }

    $out.Running = [bool](Get-Process -Name 'OneDrive' -ErrorAction SilentlyContinue)

    $accounts = [System.Collections.Generic.List[object]]::new()

    foreach ($keyPath in @('HKCU:\Software\Microsoft\SkyDrive', 'HKCU:\Software\Microsoft\OneDrive')) {
        try {
            if (Test-Path -LiteralPath $keyPath) {
                $props = Get-ItemProperty -Path $keyPath -ErrorAction Stop
                $userFolder = $props.UserFolder
                if (-not $userFolder) { $userFolder = $props.OneDrivePath }

                if ($userFolder) {
                    $accounts.Add([pscustomobject]@{
                        Type       = 'Personal'
                        UserEmail  = $props.UserEmail
                        TenantName = $null
                        UserFolder = $userFolder
                        Exists     = Test-Path -LiteralPath $userFolder
                    })
                }
            }
        } catch {
        }
    }

    $businessRoot = 'HKCU:\Software\Microsoft\OneDrive\Accounts'
    if (Test-Path -LiteralPath $businessRoot) {
        Get-ChildItem -Path $businessRoot -ErrorAction SilentlyContinue | ForEach-Object {
            try {
                $props = Get-ItemProperty -Path $_.PSPath -ErrorAction Stop
                $accounts.Add([pscustomobject]@{
                    Type       = 'Business'
                    UserEmail  = $props.UserEmail
                    TenantName = $props.DisplayName
                    UserFolder = $props.UserFolder
                    Exists     = if ($props.UserFolder) { Test-Path -LiteralPath $props.UserFolder } else { $false }
                })
            } catch {
            }
        }
    }
    $out.Accounts = $accounts.ToArray()

    $policyPath = 'HKLM:\SOFTWARE\Policies\Microsoft\OneDrive'
    if (Test-Path -LiteralPath $policyPath) {
        try {
            $policyValues = Get-ItemProperty -Path $policyPath -ErrorAction Stop
            $out.KFM.EffectivePolicy.KFMSilentOptIn = $policyValues.KFMSilentOptIn
            $out.KFM.EffectivePolicy.KFMSilentOptInDesktop = $policyValues.KFMSilentOptInDesktop
            $out.KFM.EffectivePolicy.KFMBlockOptIn = $policyValues.KFMBlockOptIn
            $out.KFM.EffectivePolicy.DisablePersonalSync = $policyValues.DisablePersonalSync
        } catch {
        }
    }

    try {
        $userShellFolders = Get-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders' -ErrorAction Stop
        $oneDrivePaths = [System.Collections.Generic.List[string]]::new()
        foreach ($account in $accounts) {
            if ($account.UserFolder) {
                try {
                    $resolved = Resolve-Path -Path $account.UserFolder -ErrorAction Stop
                    if ($resolved -and $resolved.ProviderPath) {
                        $oneDrivePaths.Add($resolved.ProviderPath)
                    } elseif ($resolved -and $resolved.Path) {
                        $oneDrivePaths.Add($resolved.Path)
                    }
                } catch {
                    $oneDrivePaths.Add($account.UserFolder)
                }
            }
        }

        function Test-IsPathInOneDrive {
            param([string]$Value)

            if ([string]::IsNullOrWhiteSpace($Value)) { return $false }
            $expanded = [Environment]::ExpandEnvironmentVariables($Value)
            foreach ($odPath in $oneDrivePaths) {
                if (-not [string]::IsNullOrWhiteSpace($odPath) -and $expanded -like "$odPath*") {
                    return $true
                }
            }
            return $false
        }

        $out.KFM.EffectiveStatus.DesktopRedirected = Test-IsPathInOneDrive -Value $userShellFolders.Desktop
        $out.KFM.EffectiveStatus.DocumentsRedirected = Test-IsPathInOneDrive -Value $userShellFolders.Personal
        $out.KFM.EffectiveStatus.PicturesRedirected = Test-IsPathInOneDrive -Value $userShellFolders.'My Pictures'
    } catch {
    }

    if ($out.Installed -and -not $out.Running) {
        $out.Notes += 'Installed but process not running.'
    }
    if ($out.Installed -and -not $out.AutoStartEnabled) {
        $out.Notes += 'Installed but not set to start on sign-in.'
    }
    if ($out.Accounts.Count -eq 0) {
        $out.Notes += 'No signed-in OneDrive accounts detected.'
    }

    return [pscustomobject]$out
}
