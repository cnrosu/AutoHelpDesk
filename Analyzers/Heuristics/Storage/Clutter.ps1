# Requires: PowerShell 5+ (works fine on 7 too)

Set-StrictMode -Version Latest

function Get-SizeAndSamples {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [int]$SampleCount = 5,
        [switch]$Fast
    )
    $result = [ordered]@{
        Exists       = $false
        FileCount    = 0
        SizeBytes    = 0
        OldestWrite  = $null
        NewestWrite  = $null
        TopLargest   = @()
        Error        = $null
    }

    if (-not (Test-Path -LiteralPath $Path)) { return $result }

    $result.Exists = $true

    try {
        if ($Fast) {
            # Fast path: fewer stats (quick size + count)
            $files = Get-ChildItem -LiteralPath $Path -Force -Recurse -File -ErrorAction SilentlyContinue
            $m = $files | Measure-Object Length -Sum
            $result.FileCount = $m.Count
            $result.SizeBytes = [int64]$m.Sum
            $times = $files | Sort-Object LastWriteTime -Descending
            if ($times) {
                $result.NewestWrite = $times[0].LastWriteTime
                $result.OldestWrite = $times[-1].LastWriteTime
            }
        } else {
            # Full stats + top N largest for evidence
            $files = Get-ChildItem -LiteralPath $Path -Force -Recurse -File -ErrorAction SilentlyContinue
            $m = $files | Measure-Object Length -Sum
            $result.FileCount = $m.Count
            $result.SizeBytes = [int64]$m.Sum

            if ($result.FileCount -gt 0) {
                $sortedByWrite = $files | Sort-Object LastWriteTime
                $result.OldestWrite = $sortedByWrite[0].LastWriteTime
                $result.NewestWrite = $sortedByWrite[-1].LastWriteTime

                $top = $files | Sort-Object Length -Descending | Select-Object -First $SampleCount
                $result.TopLargest = $top | ForEach-Object {
                    [ordered]@{
                        Path       = $_.FullName
                        SizeBytes  = [int64]$_.Length
                        SizeMB     = [math]::Round($_.Length/1MB,2)
                        LastWrite  = $_.LastWriteTime
                    }
                }
            }
        }
    }
    catch {
        $result.Error = $_.Exception.Message
    }

    return $result
}

function Stop-ServicesIfRunning {
    param([string[]]$Names)
    $stopped = @()
    foreach ($n in $Names) {
        $svc = Get-Service -Name $n -ErrorAction SilentlyContinue
        if ($svc -and $svc.Status -eq 'Running') {
            try { Stop-Service -Name $n -Force -ErrorAction Stop; $stopped += $n } catch {}
        }
    }
    return ,$stopped
}

function Start-ServicesSafe {
    param([string[]]$Names)
    foreach ($n in $Names) { try { Start-Service -Name $n -ErrorAction SilentlyContinue } catch {} }
}

function Get-StorageClutterTargets {
    [CmdletBinding()]
    param(
        [switch]$IncludeEnterprise,  # SCCM/PDQ/IIS if present
        [switch]$IncludeSpooler,     # Spool stuck jobs
        [switch]$IncludeBigRocks     # Memory.dmp, hiberfil, etc. (read-only scan)
    )

    $targets = @(
        # Windows Update download cache
        [pscustomobject]@{
            Key="WU-Download"; Path="C:\Windows\SoftwareDistribution\Download"
            Services=@('wuauserv','bits'); Note="Windows Update download cache"
            RemediationPS=@(
                'Stop-Service wuauserv -Force; Stop-Service bits -Force',
                'Remove-Item "C:\Windows\SoftwareDistribution\Download\*" -Recurse -Force -ErrorAction SilentlyContinue',
                'Start-Service bits; Start-Service wuauserv'
            )
            RemediationCmd=@(
                'net stop wuauserv & net stop bits',
                'rd /s /q C:\Windows\SoftwareDistribution\Download',
                'net start bits & net start wuauserv'
            )
        },
        # Delivery Optimization
        [pscustomobject]@{
            Key="DeliveryOptimization"; Path="C:\ProgramData\Microsoft\Windows\DeliveryOptimization\Cache"
            Services=@('dosvc'); Note="Delivery Optimization P2P cache"
            RemediationPS=@(
                'Stop-Service dosvc -Force',
                'Remove-Item "C:\ProgramData\Microsoft\Windows\DeliveryOptimization\Cache\*" -Recurse -Force -ErrorAction SilentlyContinue',
                'Start-Service dosvc'
            )
            RemediationCmd=@(
                'net stop dosvc',
                'rd /s /q "C:\ProgramData\Microsoft\Windows\DeliveryOptimization\Cache"',
                'net start dosvc'
            )
        },
        # WER queues
        [pscustomobject]@{
            Key="WER-Queue"; Path="C:\ProgramData\Microsoft\Windows\WER\ReportQueue"
            Services=@(); Note="Windows Error Reporting queued reports"
            RemediationPS=@('Remove-Item "C:\ProgramData\Microsoft\Windows\WER\ReportQueue\*" -Recurse -Force -ErrorAction SilentlyContinue')
            RemediationCmd=@('rd /s /q "C:\ProgramData\Microsoft\Windows\WER\ReportQueue"')
        },
        [pscustomobject]@{
            Key="WER-Archive"; Path="C:\ProgramData\Microsoft\Windows\WER\ReportArchive"
            Services=@(); Note="Windows Error Reporting archived reports"
            RemediationPS=@('Remove-Item "C:\ProgramData\Microsoft\Windows\WER\ReportArchive\*" -Recurse -Force -ErrorAction SilentlyContinue')
            RemediationCmd=@('rd /s /q "C:\ProgramData\Microsoft\Windows\WER\ReportArchive"')
        },
        # System/Local temp
        [pscustomobject]@{
            Key="Temp-System"; Path="C:\Windows\Temp"
            Services=@(); Note="System temp files"
            RemediationPS=@('Remove-Item "C:\Windows\Temp\*" -Recurse -Force -ErrorAction SilentlyContinue')
            RemediationCmd=@('del /f /s /q C:\Windows\Temp\*')
        },
        [pscustomobject]@{
            Key="Temp-UserLocal"; Path="$env:LOCALAPPDATA\Temp"
            Services=@(); Note="User local temp (current user)"
            RemediationPS=@('Remove-Item "$env:LOCALAPPDATA\Temp\*" -Recurse -Force -ErrorAction SilentlyContinue')
            RemediationCmd=@('del /f /s /q "%LOCALAPPDATA%\Temp\*"')
        },
        [pscustomobject]@{
            Key="Temp-UserEnv"; Path="$env:TEMP"
            Services=@(); Note="User temp (current user)"
            RemediationPS=@('Remove-Item "$env:TEMP\*" -Recurse -Force -ErrorAction SilentlyContinue')
            RemediationCmd=@('del /f /s /q "%TEMP%\*"')
        }
    )

    if ($IncludeSpooler) {
        $targets += [pscustomobject]@{
            Key="PrintSpool"; Path="C:\Windows\System32\spool\PRINTERS"
            Services=@('Spooler'); Note="Stuck printer spool files"
            RemediationPS=@(
                'Stop-Service Spooler -Force',
                'Remove-Item "C:\Windows\System32\spool\PRINTERS\*" -Recurse -Force -ErrorAction SilentlyContinue',
                'Start-Service Spooler'
            )
            RemediationCmd=@(
                'net stop spooler',
                'del /f /s /q "C:\Windows\System32\spool\PRINTERS\*"',
                'net start spooler'
            )
        }
    }

    if ($IncludeEnterprise) {
        # Add only if present to avoid noise
        if (Test-Path "C:\Windows\CCMCache") {
            $targets += [pscustomobject]@{
                Key="SCCM-CCMCache"; Path="C:\Windows\CCMCache"
                Services=@(); Note="SCCM client cache (ensure no install running)"
                RemediationPS=@('Remove-Item "C:\Windows\CCMCache\*" -Recurse -Force -ErrorAction SilentlyContinue')
                RemediationCmd=@('rd /s /q "C:\Windows\CCMCache"')
            }
        }
        if (Test-Path "C:\ProgramData\Admin Arsenal\PDQ Deploy\Patch") {
            $targets += [pscustomobject]@{
                Key="PDQ-PatchCache"; Path="C:\ProgramData\Admin Arsenal\PDQ Deploy\Patch"
                Services=@(); Note="PDQ patch payload cache (ensure no job running)"
                RemediationPS=@('Remove-Item "C:\ProgramData\Admin Arsenal\PDQ Deploy\Patch\*" -Recurse -Force -ErrorAction SilentlyContinue')
                RemediationCmd=@('rd /s /q "C:\ProgramData\Admin Arsenal\PDQ Deploy\Patch"')
            }
        }
        if (Test-Path "C:\inetpub\logs\LogFiles") {
            $targets += [pscustomobject]@{
                Key="IIS-Logs"; Path="C:\inetpub\logs\LogFiles"
                Services=@(); Note="IIS web logs (prune by age)"
                RemediationPS=@('Get-ChildItem "C:\inetpub\logs\LogFiles" -Recurse | Where-Object LastWriteTime -lt (Get-Date).AddDays(-14) | Remove-Item -Force -ErrorAction SilentlyContinue')
                RemediationCmd=@('forfiles /p "C:\inetpub\logs\LogFiles" /s /d -14 /c "cmd /c del @file"')
            }
        }
    }

    if ($IncludeBigRocks) {
        $targets += @(
            [pscustomobject]@{
                Key="Crash-MiniDump"; Path="C:\Windows\Minidump"
                Services=@(); Note="Mini crash dumps"
                RemediationPS=@('Remove-Item "C:\Windows\Minidump\*" -Recurse -Force -ErrorAction SilentlyContinue')
                RemediationCmd=@('rd /s /q "C:\Windows\Minidump"')
            },
            [pscustomobject]@{
                Key="Crash-MemoryDmp"; Path="C:\Windows\MEMORY.DMP"
                Services=@(); Note="Full memory dump (often GBs)"
                RemediationPS=@('Remove-Item "C:\Windows\MEMORY.DMP" -Force -ErrorAction SilentlyContinue')
                RemediationCmd=@('del /f /q "C:\Windows\MEMORY.DMP"')
            }
            # hiberfil.sys is not deleted directly; show guidance in the card
        )
    }

    return ,$targets
}

function Map-SizeToSeverity {
    param(
        [int64]$Bytes,
        [hashtable]$Thresholds = @{
            LowMB    =  2048   # ≥ 2 GB
            MediumMB =  5120   # ≥ 5 GB
            HighMB   = 10240   # ≥ 10 GB
        }
    )
    $mb = $Bytes/1MB
    if ($mb -ge $Thresholds.HighMB) { return 'High' }
    elseif ($mb -ge $Thresholds.MediumMB) { return 'Medium' }
    elseif ($mb -ge $Thresholds.LowMB) { return 'Low' }
    else { return 'Info' }
}

function Invoke-StorageClutterHeuristics {
    <#
    .SYNOPSIS
        Scans high-impact disk bloat locations and emits AutoHelpDesk-ready cards.

    .PARAMETER Context
        Pipeline object for your framework (optional).

    .PARAMETER IncludeEnterprise
        Also scan SCCM/PDQ/IIS if found.

    .PARAMETER IncludeSpooler
        Include Printer Spool directory.

    .PARAMETER IncludeBigRocks
        Include crash dumps (and guidance for hiberfil).

    .PARAMETER Fast
        Faster scan (no TopLargest sampling).

    .PARAMETER Thresholds
        Hashtable with MB cutoffs: LowMB, MediumMB, HighMB.
    #>
    [CmdletBinding()]
    param(
        $Context,
        [switch]$IncludeEnterprise,
        [switch]$IncludeSpooler,
        [switch]$IncludeBigRocks,
        [switch]$Fast,
        [hashtable]$Thresholds
    )

    if (-not $Thresholds) {
        $Thresholds = @{
            LowMB    =  2048
            MediumMB =  5120
            HighMB   = 10240
        }
    }

    $category = [ordered]@{
        Key         = "Storage/Clutter"
        Title       = "Storage: Large Cache/Temp/Log Buildup"
        Description = "Scans well-known locations that often consume significant disk space and provides clean-up commands."
        Items       = @()
    }

    $targets = Get-StorageClutterTargets -IncludeEnterprise:$IncludeEnterprise -IncludeSpooler:$IncludeSpooler -IncludeBigRocks:$IncludeBigRocks

    foreach ($t in $targets) {
        # Temporarily stop services that may lock files
        $stopped = @()
        if ($t.Services.Count -gt 0) {
            $stopped = Stop-ServicesIfRunning -Names $t.Services
        }

        $stats = Get-SizeAndSamples -Path $t.Path -Fast:$Fast

        if ($stopped.Count -gt 0) {
            Start-ServicesSafe -Names $stopped
        }

        # Translate stats to card
        $sizeMB = [math]::Round($stats.SizeBytes/1MB,2)
        $sizeGB = [math]::Round($stats.SizeBytes/1GB,2)
        $severity = Map-SizeToSeverity -Bytes $stats.SizeBytes -Thresholds $Thresholds

        $remediation = @()
        $remediation += [ordered]@{ Type="PowerShell"; Lines=$t.RemediationPS }
        if ($t.RemediationCmd) {
            $remediation += [ordered]@{ Type="cmd"; Lines=$t.RemediationCmd }
        }

        # Optional extra guidance
        $notes = @($t.Note)
        if ($t.Key -eq "Crash-MemoryDmp") {
            $notes += "If you don't need full dumps, set crash to Small memory dump: sysdm.cpl → Advanced → Startup and Recovery."
        }

        $item = [ordered]@{
            Key        = "Storage/Clutter/$($t.Key)"
            Title      = "$($t.Note)"
            Severity   = $severity
            Evidence   = [ordered]@{
                Path        = $t.Path
                Exists      = $stats.Exists
                FileCount   = $stats.FileCount
                SizeBytes   = $stats.SizeBytes
                SizeMB      = $sizeMB
                SizeGB      = $sizeGB
                OldestWrite = $stats.OldestWrite
                NewestWrite = $stats.NewestWrite
                TopLargest  = $stats.TopLargest
                Error       = $stats.Error
            }
            Remediation = $remediation
            Notes       = $notes
            Impact      = "Clearing this location frees disk space but may briefly slow the next update or install as caches rebuild."
            Risk        = "Low if commands are followed; ensure no software installs are in progress for SCCM/PDQ."
        }

        $category.Items += $item
    }

    # Bonus: informational card for hiberfil (scan-only note, because deletion is a mode change)
    if ($IncludeBigRocks) {
        try {
            $hiber = (powercfg /a) 2>$null
            $hiberEnabled = ($hiber -join "`n") -notmatch 'Hibernate has been disabled'
            if ($hiberEnabled) {
                $category.Items += [ordered]@{
                    Key      = "Storage/Clutter/Hibernation"
                    Title    = "Hibernation file (hiberfil.sys)"
                    Severity = "Info"
                    Evidence = [ordered]@{ Path="C:\hiberfil.sys"; Exists=$true }
                    Remediation = @(
                        [ordered]@{ Type="PowerShell"; Lines=@('powercfg /h off') }
                    )
                    Notes    = @("Disables Hibernation and Fast Startup; frees space ≈ RAM size.")
                    Impact   = "Frees several GBs instantly."
                    Risk     = "Medium: behaviour change; users lose Hibernate & Fast Startup."
                }
            }
        } catch {}
    }

    return ,$category
}
