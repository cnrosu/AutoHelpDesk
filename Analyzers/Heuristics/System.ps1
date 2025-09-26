<#!
.SYNOPSIS
    System state heuristics covering uptime, power configuration, and hardware inventory.
#>

. (Join-Path -Path (Split-Path $PSScriptRoot -Parent) -ChildPath 'AnalyzerCommon.ps1')

function Get-StartupCommandPath {
    param(
        [string]$Command
    )

    if ([string]::IsNullOrWhiteSpace($Command)) { return $null }

    $expanded = [System.Environment]::ExpandEnvironmentVariables($Command).Trim()
    if ([string]::IsNullOrWhiteSpace($expanded)) { return $null }

    if ($expanded.StartsWith('"')) {
        $closing = $expanded.IndexOf('"', 1)
        if ($closing -gt 1) {
            return $expanded.Substring(1, $closing - 1)
        }
    }

    $parts = $expanded -split '\s+', 2
    if ($parts.Count -gt 0 -and -not [string]::IsNullOrWhiteSpace($parts[0])) {
        return $parts[0]
    }

    return $expanded
}

function Test-IsMicrosoftStartupEntry {
    param(
        $Entry
    )

    if (-not $Entry) { return $false }

    $command = $null
    if ($Entry.PSObject.Properties['Command']) {
        $command = [string]$Entry.Command
    }

    if ($command) {
        $commandLower = $command.ToLowerInvariant().Trim('"')
        if ($commandLower -eq 'rundll32.exe' -or $commandLower -eq 'rundll32.exe,' -or $commandLower -eq 'explorer.exe') {
            return $true
        }
    }

    $path = Get-StartupCommandPath -Command $command
    if ($path) {
        $pathLower = $path.ToLowerInvariant()
        if ($pathLower -match '\\windows\\system32\\' -or $pathLower -match '^c:\\windows\\') {
            return $true
        }
        if ($pathLower -match '\\microsoft\\') {
            return $true
        }
    }

    foreach ($prop in @('Name', 'Description')) {
        if ($Entry.PSObject.Properties[$prop]) {
            $value = [string]$Entry.$prop
            if (-not [string]::IsNullOrWhiteSpace($value)) {
                $lower = $value.ToLowerInvariant()
                if ($lower -match 'microsoft' -or $lower -match 'windows defender' -or $lower -match 'onedrive') {
                    return $true
                }
            }
        }
    }

    return $false
}

function Invoke-SystemHeuristics {
    param(
        [Parameter(Mandatory)]
        $Context
    )

    $result = New-CategoryResult -Name 'System'

    $systemArtifact = Get-AnalyzerArtifact -Context $Context -Name 'system'
    if ($systemArtifact) {
        $payload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $systemArtifact)
        if ($payload -and $payload.OperatingSystem -and -not $payload.OperatingSystem.Error) {
            $os = $payload.OperatingSystem
            $caption = $os.Caption
            $build = $os.BuildNumber
            if ($caption) {
                $description = if ($build) { "{0} (build {1})" -f $caption, $build } else { [string]$caption }
                $captionLower = $caption.ToLowerInvariant()
                if ($captionLower -match 'windows\s+11') {
                    Add-CategoryNormal -CategoryResult $result -Title ("Operating system supported: {0}" -f $description)
                } else {
                    $unsupportedMatch = [regex]::Match($captionLower, 'windows\s+(7|8(\.1)?|10)')
                    if ($unsupportedMatch.Success) {
                        $versionLabel = $unsupportedMatch.Groups[1].Value
                        $evidence = "Detected operating system: {0}. Microsoft support for Windows {1} has ended; upgrade to Windows 11." -f $description, $versionLabel
                        Add-CategoryIssue -CategoryResult $result -Severity 'critical' -Title 'Operating system unsupported' -Evidence $evidence -Subcategory 'Operating System'
                    } else {
                        Add-CategoryCheck -CategoryResult $result -Name 'Operating system' -Status $description
                    }
                }
            }
            if ($os.LastBootUpTime) {
                Add-CategoryCheck -CategoryResult $result -Name 'Last boot time' -Status ([string]$os.LastBootUpTime)
            }
        } elseif ($payload -and $payload.OperatingSystem -and $payload.OperatingSystem.Error) {
            Add-CategoryIssue -CategoryResult $result -Severity 'info' -Title 'Unable to read OS inventory' -Evidence ($payload.OperatingSystem.Error) -Subcategory 'Operating System'
        } else {
            Add-CategoryIssue -CategoryResult $result -Severity 'info' -Title 'Operating system inventory not available' -Subcategory 'Operating System'
        }

        if ($payload -and $payload.ComputerSystem -and -not $payload.ComputerSystem.Error) {
            $cs = $payload.ComputerSystem
            if ($cs.TotalPhysicalMemory) {
                $gb = [math]::Round($cs.TotalPhysicalMemory / 1GB, 2)
                Add-CategoryCheck -CategoryResult $result -Name 'Physical memory (GB)' -Status ([string]$gb)
            }
        } elseif ($payload -and $payload.ComputerSystem -and $payload.ComputerSystem.Error) {
            Add-CategoryIssue -CategoryResult $result -Severity 'info' -Title 'Unable to query computer system details' -Evidence $payload.ComputerSystem.Error -Subcategory 'Hardware Inventory'
        }

        if ($payload -and $payload.SystemInfoText -and -not ($payload.SystemInfoText.Error)) {
            $systemInfo = $payload.SystemInfoText
            if ($systemInfo -is [System.Collections.IEnumerable] -and -not ($systemInfo -is [string])) {
                $systemInfo = ($systemInfo | ForEach-Object { [string]$_ }) -join "`n"
            }
            $systemInfoText = [string]$systemInfo
            if ($systemInfoText) {
                $biosModeMatch = [regex]::Match($systemInfoText,'(?im)^\s*BIOS\s+Mode\s*:\s*(?<value>.+)$')
                $secureBootMatch = [regex]::Match($systemInfoText,'(?im)^\s*Secure\s+Boot\s+State\s*:\s*(?<value>.+)$')
                if ($biosModeMatch.Success) {
                    $biosMode = $biosModeMatch.Groups['value'].Value.Trim()
                    $uefi = ($biosMode -match '(?i)UEFI')
                    if ($uefi -and -not $secureBootMatch.Success) {
                        $evidence = ($systemInfoText -split "\r?\n" | Where-Object { $_ -match '(?i)(BIOS\s+Mode|Secure\s+Boot)' } | Select-Object -First 5)
                        if ($evidence.Count -eq 0) { $evidence = ($systemInfoText -split "\r?\n" | Select-Object -First 10) }
                        Add-CategoryIssue -CategoryResult $result -Severity 'high' -Title 'Secure Boot state not reported despite UEFI firmware.' -Evidence (($evidence | Where-Object { $_ }) -join "`n") -Subcategory 'Firmware'
                    }
                }
            }
        }
    } else {
        Add-CategoryIssue -CategoryResult $result -Severity 'info' -Title 'System inventory artifact missing' -Subcategory 'Collection'
    }

    $uptimeArtifact = Get-AnalyzerArtifact -Context $Context -Name 'uptime'
    if ($uptimeArtifact) {
        $payload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $uptimeArtifact)
        if ($payload -and $payload.Uptime -and -not $payload.Uptime.Error) {
            $uptimeRecord = $payload.Uptime
            $uptimeText = $uptimeRecord.Uptime
            $span = $null
            if ($uptimeText) {
                try { $span = [TimeSpan]::Parse($uptimeText) } catch { $span = $null }
            }

            if ($span) {
                $days = [math]::Floor($span.TotalDays)
                Add-CategoryCheck -CategoryResult $result -Name 'Current uptime (days)' -Status ([string][math]::Round($span.TotalDays,2))
                if ($span.TotalDays -gt 30) {
                    Add-CategoryIssue -CategoryResult $result -Severity 'medium' -Title 'Device has not rebooted in over 30 days' -Evidence ("Reported uptime: {0}" -f $uptimeText) -Subcategory 'Uptime'
                } elseif ($span.TotalDays -lt 1) {
                    Add-CategoryNormal -CategoryResult $result -Title 'Recent reboot detected'
                }
            }
        }
    }

    $powerArtifact = Get-AnalyzerArtifact -Context $Context -Name 'power'
    if ($powerArtifact) {
        $payload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $powerArtifact)
        if ($payload -and $payload.FastStartup -and -not $payload.FastStartup.Error) {
            $fast = $payload.FastStartup
            if ($fast.HiberbootEnabled -eq 1) {
                Add-CategoryIssue -CategoryResult $result -Severity 'warning' -Title 'Fast Startup (Fast Boot) is enabled. Disable Fast Startup for consistent shutdown and troubleshooting.' -Evidence 'Fast Startup keeps Windows in a hybrid hibernation state and can mask reboot-dependent fixes.' -Subcategory 'Power Configuration'
            } else {
                Add-CategoryNormal -CategoryResult $result -Title 'Fast Startup disabled'
            }
        } elseif ($payload -and $payload.FastStartup -and $payload.FastStartup.Error) {
            Add-CategoryIssue -CategoryResult $result -Severity 'info' -Title 'Unable to read Fast Startup configuration' -Evidence $payload.FastStartup.Error -Subcategory 'Power Configuration'
        }
    }

    $performanceArtifact = Get-AnalyzerArtifact -Context $Context -Name 'performance'
    if ($performanceArtifact) {
        $payload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $performanceArtifact)
        if ($payload -and $payload.Memory -and -not $payload.Memory.Error) {
            $memory = $payload.Memory
            if ($memory.TotalVisibleMemory -and $memory.FreePhysicalMemory) {
                $totalMb = [double]$memory.TotalVisibleMemory
                $freeMb = [double]$memory.FreePhysicalMemory
                if ($totalMb -gt 0) {
                    $usedPct = [math]::Round((($totalMb - $freeMb) / $totalMb) * 100, 1)
                    Add-CategoryCheck -CategoryResult $result -Name 'Memory utilization (%)' -Status ([string]$usedPct)
                    if ($usedPct -ge 90) {
                        Add-CategoryIssue -CategoryResult $result -Severity 'medium' -Title 'High memory utilization detected' -Evidence ("Used memory percentage: {0}%" -f $usedPct) -Subcategory 'Performance'
                    }
                }
            }
        }

        if ($payload -and $payload.TopCpuProcesses) {
            if (($payload.TopCpuProcesses | Where-Object { $_.Error }).Count -gt 0) {
                Add-CategoryIssue -CategoryResult $result -Severity 'info' -Title 'Unable to enumerate running processes' -Subcategory 'Performance'
            } else {
            $topProcess = $payload.TopCpuProcesses | Select-Object -First 1
            if ($topProcess -and $topProcess.CPU -gt 0) {
                Add-CategoryCheck -CategoryResult $result -Name 'Top CPU process' -Status ($topProcess.Name) -Details ("CPU time: {0}" -f $topProcess.CPU)
            }
            }
        }
    }

    $pendingRebootArtifact = Get-AnalyzerArtifact -Context $Context -Name 'pending-reboot'
    if ($pendingRebootArtifact) {
        $payload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $pendingRebootArtifact)
        if ($payload -and $payload.Registry) {
            $entries = @($payload.Registry)

            $presentEntries = @($entries | Where-Object { $_ -and $_.PSObject.Properties['Present'] -and $_.Present })
            $evidenceLines = New-Object System.Collections.Generic.List[string]

            foreach ($entry in $entries) {
                $descriptor = if ($entry.ValueName) { "{0}::{1}" -f $entry.Path, $entry.ValueName } else { [string]$entry.Path }
                $status = if ($entry.Present) { 'present' } else { 'absent' }
                $timestamp = if ($entry.LastWriteTime) { [string]$entry.LastWriteTime } else { 'timestamp unavailable' }

                $additional = $null
                if ($entry.PSObject.Properties['Values'] -and $entry.Values) {
                    if ($entry.Values -is [System.Collections.IEnumerable] -and -not ($entry.Values -is [string])) {
                        $additional = "values={0}" -f ((@($entry.Values) | Select-Object -First 3) -join ', ')
                    } else {
                        $additional = "value={0}" -f $entry.Values
                    }
                } elseif ($entry.PSObject.Properties['ValueReadError'] -and $entry.ValueReadError) {
                    $additional = "value read error: {0}" -f $entry.ValueReadError
                } elseif ($entry.PSObject.Properties['Error'] -and $entry.Error) {
                    $additional = "error: {0}" -f $entry.Error
                }

                $lineParts = @("{0} → {1}" -f $descriptor, $status)
                $lineParts += "LastWriteTime={0}" -f $timestamp
                if ($additional) { $lineParts += $additional }
                $evidenceLines.Add(($lineParts -join ' | ')) | Out-Null
            }

            $oldestRecord = $null
            foreach ($entry in $presentEntries) {
                if (-not ($entry.PSObject.Properties['LastWriteTime']) -or -not $entry.LastWriteTime) { continue }
                try {
                    $parsed = [datetime]::Parse($entry.LastWriteTime)
                } catch {
                    continue
                }

                if (-not $oldestRecord -or $parsed -lt $oldestRecord.Timestamp) {
                    $oldestRecord = [pscustomobject]@{ Entry = $entry; Timestamp = $parsed }
                }
            }

            if ($presentEntries.Count -gt 0) {
                $now = Get-Date
                $severity = 'medium'
                $title = 'Pending reboot required'
                if ($oldestRecord) {
                    $age = $now - $oldestRecord.Timestamp
                    if ($age.TotalDays -ge 7) {
                        $severity = 'high'
                        $title = 'Pending reboot overdue'
                    }

                    $descriptor = if ($oldestRecord.Entry.ValueName) { "{0}::{1}" -f $oldestRecord.Entry.Path, $oldestRecord.Entry.ValueName } else { [string]$oldestRecord.Entry.Path }
                    $ageLine = "Oldest pending marker: {0} (recorded {1:yyyy-MM-ddTHH:mm:ssK}, ~{2:N1} days ago)" -f $descriptor, $oldestRecord.Timestamp, $age.TotalDays
                    $evidenceLines.Add($ageLine) | Out-Null
                }

                $evidence = $evidenceLines -join "`n"
                Add-CategoryIssue -CategoryResult $result -Severity $severity -Title $title -Evidence $evidence -Subcategory 'Pending Reboot' -CheckId 'System/PendingReboot'
            } else {
                $evidence = $evidenceLines -join "`n"
                if (-not [string]::IsNullOrWhiteSpace($evidence)) {
                    Add-CategoryNormal -CategoryResult $result -Title 'No reboot pending' -Evidence $evidence -CheckId 'System/PendingReboot'
                } else {
                    Add-CategoryNormal -CategoryResult $result -Title 'No reboot pending' -CheckId 'System/PendingReboot'
                }
            }
        } else {
            Add-CategoryIssue -CategoryResult $result -Severity 'info' -Title 'Pending reboot data unavailable' -Subcategory 'Pending Reboot' -CheckId 'System/PendingReboot'
        }
    } else {
        Add-CategoryIssue -CategoryResult $result -Severity 'info' -Title 'Pending reboot artifact missing' -Subcategory 'Pending Reboot' -CheckId 'System/PendingReboot'
    }

    $startupArtifact = Get-AnalyzerArtifact -Context $Context -Name 'startup'
    if ($startupArtifact) {
        $payload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $startupArtifact)
        if ($payload -and $payload.StartupCommands) {
            $entries = $payload.StartupCommands
            if ($entries -isnot [System.Collections.IEnumerable] -or $entries -is [string]) {
                $entries = @($entries)
            }

            $entries = @($entries)
            $errorEntries = @($entries | Where-Object { $_.PSObject.Properties['Error'] -and $_.Error })
            if ($errorEntries.Count -gt 0) {
                $message = "Unable to enumerate all startup items ({0})." -f ($errorEntries[0].Error)
                Add-CategoryIssue -CategoryResult $result -Severity 'info' -Title 'Startup program inventory incomplete' -Evidence $message -Subcategory 'Startup Programs'
            }

            $validEntries = @($entries | Where-Object { -not ($_.PSObject.Properties['Error'] -and $_.Error) })
            if ($validEntries.Count -gt 0) {
                $nonMicrosoftEntries = @($validEntries | Where-Object { -not (Test-IsMicrosoftStartupEntry $_) })

                Add-CategoryCheck -CategoryResult $result -Name 'Startup entries detected' -Status ([string]$validEntries.Count)
                Add-CategoryCheck -CategoryResult $result -Name 'Startup entries (non-Microsoft)' -Status ([string]$nonMicrosoftEntries.Count)

                $evidenceBuilder = New-Object System.Collections.Generic.List[string]
                [void]$evidenceBuilder.Add("Total startup entries evaluated: {0}" -f $validEntries.Count)
                [void]$evidenceBuilder.Add("Non-Microsoft startup entries: {0}" -f $nonMicrosoftEntries.Count)

                $topEntries = $nonMicrosoftEntries | Select-Object -First 8
                foreach ($entry in $topEntries) {
                    $parts = New-Object System.Collections.Generic.List[string]
                    if ($entry.Name) { [void]$parts.Add([string]$entry.Name) }
                    if ($entry.Command) { [void]$parts.Add([string]$entry.Command) }
                    if ($entry.Location) { [void]$parts.Add(("Location: {0}" -f $entry.Location)) }
                    if ($entry.User) { [void]$parts.Add(("User: {0}" -f $entry.User)) }
                    $line = ($parts -join ' | ')
                    if ($line) { [void]$evidenceBuilder.Add($line) }
                }

                $remaining = $nonMicrosoftEntries.Count - $topEntries.Count
                if ($remaining -gt 0) {
                    [void]$evidenceBuilder.Add("(+{0} additional non-Microsoft startup entries)" -f $remaining)
                }

                $evidence = $evidenceBuilder -join "`n"

                if ($nonMicrosoftEntries.Count -gt 10) {
                    $title = "Startup autoruns bloat: {0} non-Microsoft entries detected. Review and trim startup apps to reduce login delay." -f $nonMicrosoftEntries.Count
                    Add-CategoryIssue -CategoryResult $result -Severity 'medium' -Title $title -Evidence $evidence -Subcategory 'Startup Programs'
                } elseif ($nonMicrosoftEntries.Count -gt 5) {
                    $title = "Startup autoruns trending high ({0} non-Microsoft entries)." -f $nonMicrosoftEntries.Count
                    Add-CategoryIssue -CategoryResult $result -Severity 'low' -Title $title -Evidence $evidence -Subcategory 'Startup Programs'
                } else {
                    $title = "Startup autoruns manageable ({0} non-Microsoft of {1} total)." -f $nonMicrosoftEntries.Count, $validEntries.Count
                    Add-CategoryNormal -CategoryResult $result -Title $title -Evidence $evidence
                }
            } else {
                Add-CategoryNormal -CategoryResult $result -Title 'No startup entries detected'
            }
        } elseif ($payload -and $payload.StartupCommands -eq $null) {
            Add-CategoryIssue -CategoryResult $result -Severity 'info' -Title 'Startup program inventory empty' -Subcategory 'Startup Programs'
        }
    } else {
        Add-CategoryIssue -CategoryResult $result -Severity 'info' -Title 'Startup program artifact missing' -Subcategory 'Startup Programs'
    }

    return $result
}
