<#!
.SYNOPSIS
    System state heuristics covering uptime, power configuration, and hardware inventory.
#>

. (Join-Path -Path (Split-Path $PSScriptRoot -Parent) -ChildPath 'AnalyzerCommon.ps1')

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
                Add-CategoryNormal -CategoryResult $result -Title ("Operating system: {0} (build {1})" -f $caption, $build)
            }
            if ($os.LastBootUpTime) {
                Add-CategoryCheck -CategoryResult $result -Name 'Last boot time' -Status ([string]$os.LastBootUpTime)
            }
        } elseif ($payload -and $payload.OperatingSystem -and $payload.OperatingSystem.Error) {
            Add-CategoryIssue -CategoryResult $result -Severity 'info' -Title 'Unable to read OS inventory' -Evidence ($payload.OperatingSystem.Error)
        } else {
            Add-CategoryIssue -CategoryResult $result -Severity 'info' -Title 'Operating system inventory not available'
        }

        if ($payload -and $payload.ComputerSystem -and -not $payload.ComputerSystem.Error) {
            $cs = $payload.ComputerSystem
            if ($cs.Manufacturer -or $cs.Model) {
                Add-CategoryNormal -CategoryResult $result -Title ("Hardware: {0} {1}" -f $cs.Manufacturer, $cs.Model)
            }
            if ($cs.TotalPhysicalMemory) {
                $gb = [math]::Round($cs.TotalPhysicalMemory / 1GB, 2)
                Add-CategoryCheck -CategoryResult $result -Name 'Physical memory (GB)' -Status ([string]$gb)
            }
        } elseif ($payload -and $payload.ComputerSystem -and $payload.ComputerSystem.Error) {
            Add-CategoryIssue -CategoryResult $result -Severity 'info' -Title 'Unable to query computer system details' -Evidence $payload.ComputerSystem.Error
        }
    } else {
        Add-CategoryIssue -CategoryResult $result -Severity 'info' -Title 'System inventory artifact missing'
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
                    Add-CategoryIssue -CategoryResult $result -Severity 'medium' -Title 'Device has not rebooted in over 30 days' -Evidence ("Reported uptime: {0}" -f $uptimeText)
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
                Add-CategoryIssue -CategoryResult $result -Severity 'low' -Title 'Fast Startup enabled' -Evidence 'Fast Startup (hiberboot) can interfere with troubleshooting; consider disabling.'
            } else {
                Add-CategoryNormal -CategoryResult $result -Title 'Fast Startup disabled'
            }
        } elseif ($payload -and $payload.FastStartup -and $payload.FastStartup.Error) {
            Add-CategoryIssue -CategoryResult $result -Severity 'info' -Title 'Unable to read Fast Startup configuration' -Evidence $payload.FastStartup.Error
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
                        Add-CategoryIssue -CategoryResult $result -Severity 'medium' -Title 'High memory utilization detected' -Evidence ("Used memory percentage: {0}%" -f $usedPct)
                    }
                }
            }
        }

        if ($payload -and $payload.TopCpuProcesses) {
            if (($payload.TopCpuProcesses | Where-Object { $_.Error }).Count -gt 0) {
                Add-CategoryIssue -CategoryResult $result -Severity 'info' -Title 'Unable to enumerate running processes'
            } else {
            $topProcess = $payload.TopCpuProcesses | Select-Object -First 1
            if ($topProcess -and $topProcess.CPU -gt 0) {
                Add-CategoryCheck -CategoryResult $result -Name 'Top CPU process' -Status ($topProcess.Name) -Details ("CPU time: {0}" -f $topProcess.CPU)
            }
            }
        }
    }

    return $result
}
