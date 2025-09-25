<#!
.SYNOPSIS
    Security-focused heuristic evaluations based on collected JSON artifacts.
#>

. (Join-Path -Path (Split-Path $PSScriptRoot -Parent) -ChildPath 'AnalyzerCommon.ps1')

function Invoke-SecurityHeuristics {
    param(
        [Parameter(Mandatory)]
        $Context
    )

    $result = New-CategoryResult -Name 'Security'

    $operatingSystem = $null
    $isWindows11 = $false
    $systemArtifact = Get-AnalyzerArtifact -Context $Context -Name 'system'
    if ($systemArtifact) {
        $systemPayload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $systemArtifact)
        if ($systemPayload -and $systemPayload.OperatingSystem -and -not $systemPayload.OperatingSystem.Error) {
            $operatingSystem = $systemPayload.OperatingSystem
            if ($operatingSystem.Caption -and $operatingSystem.Caption -match 'Windows\s*11') {
                $isWindows11 = $true
            }
        }
    }

    $defenderArtifact = Get-AnalyzerArtifact -Context $Context -Name 'defender'
    if ($defenderArtifact) {
        $payload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $defenderArtifact)
        if ($payload -and $payload.Status -and -not $payload.Status.Error) {
            $status = $payload.Status
            $rtp = ConvertTo-NullableBool $status.RealTimeProtectionEnabled
            if ($rtp -eq $false) {
                Add-CategoryIssue -CategoryResult $result -Severity 'high' -Title 'Defender real-time protection disabled' -Evidence 'Get-MpComputerStatus reports RealTimeProtectionEnabled = False.'
            }

            $av = ConvertTo-NullableBool $status.AntivirusEnabled
            if ($av -eq $false) {
                Add-CategoryIssue -CategoryResult $result -Severity 'critical' -Title 'Defender antivirus engine disabled' -Evidence 'Get-MpComputerStatus reports AntivirusEnabled = False.'
            }

            $tamper = ConvertTo-NullableBool $status.TamperProtectionEnabled
            if ($tamper -eq $false) {
                Add-CategoryIssue -CategoryResult $result -Severity 'medium' -Title 'Tamper protection not enabled' -Evidence 'Get-MpComputerStatus indicates tamper protection is disabled.'
            }

            $definitions = @($status.AntivirusSignatureVersion, $status.AntispywareSignatureVersion) | Where-Object { $_ }
            if ($definitions.Count -gt 0) {
                Add-CategoryNormal -CategoryResult $result -Title ('Defender signatures present ({0})' -f ($definitions -join ', '))
            }

            if ($payload.Threats -and $payload.Threats.Count -gt 0 -and -not ($payload.Threats[0] -is [string])) {
                $threatNames = $payload.Threats | Where-Object { $_.ThreatName } | Select-Object -First 5 -ExpandProperty ThreatName
                Add-CategoryIssue -CategoryResult $result -Severity 'high' -Title ('Recent threats detected: {0}' -f ($threatNames -join ', ')) -Evidence 'Get-MpThreat returned recent detections; confirm remediation.'
            } else {
                Add-CategoryNormal -CategoryResult $result -Title 'No recent Defender detections'
            }
        } elseif ($payload -and $payload.Status -and $payload.Status.Error) {
            Add-CategoryIssue -CategoryResult $result -Severity 'medium' -Title 'Unable to query Defender status' -Evidence $payload.Status.Error
        } else {
            Add-CategoryIssue -CategoryResult $result -Severity 'info' -Title 'Defender artifact missing expected structure'
        }
    } else {
        Add-CategoryIssue -CategoryResult $result -Severity 'info' -Title 'Defender artifact not collected'
    }

    $firewallArtifact = Get-AnalyzerArtifact -Context $Context -Name 'firewall'
    if ($firewallArtifact) {
        $payload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $firewallArtifact)
        if ($payload -and $payload.Profiles) {
            $disabledProfiles = @()
            foreach ($profile in $payload.Profiles) {
                if ($profile.PSObject.Properties['Enabled']) {
                    $enabled = ConvertTo-NullableBool $profile.Enabled
                    if ($enabled -eq $false) {
                        $disabledProfiles += $profile.Name
                    }
                    Add-CategoryCheck -CategoryResult $result -Name ("Firewall profile: {0}" -f $profile.Name) -Status ($(if ($enabled) { 'Enabled' } elseif ($enabled -eq $false) { 'Disabled' } else { 'Unknown' })) -Details ("Inbound: {0}; Outbound: {1}" -f $profile.DefaultInboundAction, $profile.DefaultOutboundAction)
                }
            }

            if ($disabledProfiles.Count -gt 0) {
                Add-CategoryIssue -CategoryResult $result -Severity 'high' -Title ('Firewall profiles disabled: {0}' -f ($disabledProfiles -join ', '))
            } else {
                Add-CategoryNormal -CategoryResult $result -Title 'All firewall profiles enabled'
            }
        } elseif ($payload -and $payload.Profiles -and $payload.Profiles.Error) {
            Add-CategoryIssue -CategoryResult $result -Severity 'medium' -Title 'Firewall profile query failed' -Evidence $payload.Profiles.Error
        } else {
            Add-CategoryIssue -CategoryResult $result -Severity 'info' -Title 'Firewall data missing expected profile list'
        }
    } else {
        Add-CategoryIssue -CategoryResult $result -Severity 'info' -Title 'Firewall artifact not collected'
    }

    $bitlockerArtifact = Get-AnalyzerArtifact -Context $Context -Name 'bitlocker'
    if ($bitlockerArtifact) {
        $payload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $bitlockerArtifact)
        if ($payload -and $payload.Volumes) {
            $unprotected = @()
            foreach ($volume in $payload.Volumes) {
                $status = $volume.ProtectionStatus
                $mount = if ($volume.MountPoint) { $volume.MountPoint } else { $volume.VolumeType }
                Add-CategoryCheck -CategoryResult $result -Name ("BitLocker: {0}" -f $mount) -Status ($status)
                if ($status -and ($status -eq 0 -or $status -eq 'Off' -or $status -like '*Off*')) {
                    $unprotected += $mount
                }
            }

            if ($unprotected.Count -gt 0) {
                Add-CategoryIssue -CategoryResult $result -Severity 'high' -Title ('BitLocker disabled on {0}' -f ($unprotected -join ', '))
            } else {
                Add-CategoryNormal -CategoryResult $result -Title 'BitLocker protection present'
            }
        } elseif ($payload -and $payload.Volumes -and $payload.Volumes.Error) {
            Add-CategoryIssue -CategoryResult $result -Severity 'medium' -Title 'BitLocker query failed' -Evidence $payload.Volumes.Error
        } else {
            Add-CategoryIssue -CategoryResult $result -Severity 'info' -Title 'BitLocker data missing expected structure'
        }
    } else {
        Add-CategoryIssue -CategoryResult $result -Severity 'info' -Title 'BitLocker artifact not collected'
    }

    $tpmArtifact = Get-AnalyzerArtifact -Context $Context -Name 'tpm'
    if ($tpmArtifact) {
        $payload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $tpmArtifact)
        if ($payload -and $payload.Tpm -and -not $payload.Tpm.Error) {
            $tpm = $payload.Tpm
            $present = ConvertTo-NullableBool $tpm.TpmPresent
            $ready = ConvertTo-NullableBool $tpm.TpmReady
            if ($present -eq $false) {
                Add-CategoryIssue -CategoryResult $result -Severity 'high' -Title 'No TPM detected' -Evidence 'Get-Tpm reported TpmPresent = False.'
            } elseif ($ready -eq $false) {
                Add-CategoryIssue -CategoryResult $result -Severity 'medium' -Title 'TPM not initialized' -Evidence 'Get-Tpm reported TpmReady = False.'
            } else {
                Add-CategoryNormal -CategoryResult $result -Title 'TPM present and ready'
            }
        } elseif ($payload -and $payload.Tpm -and $payload.Tpm.Error) {
            Add-CategoryIssue -CategoryResult $result -Severity 'medium' -Title 'Unable to query TPM status' -Evidence $payload.Tpm.Error
        }
    }

    $wdacArtifact = Get-AnalyzerArtifact -Context $Context -Name 'wdac'
    if ($wdacArtifact) {
        $payload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $wdacArtifact)
        $smartAppEvidence = @()
        $smartAppState = $null

        if ($payload -and $payload.SmartAppControl) {
            $entry = $payload.SmartAppControl
            if ($entry.Error) {
                Add-CategoryIssue -CategoryResult $result -Severity 'info' -Title 'Unable to query Smart App Control state' -Evidence $entry.Error
            } elseif ($entry.Values) {
                foreach ($prop in $entry.Values.PSObject.Properties) {
                    if ($prop.Name -match '^PS') { continue }
                    $smartAppEvidence += ("{0}: {1}" -f $prop.Name, $prop.Value)
                    $candidate = $prop.Value
                    if ($null -ne $candidate) {
                        $parsed = 0
                        if ([int]::TryParse($candidate.ToString(), [ref]$parsed)) {
                            if ($prop.Name -match 'Enabled' -or $prop.Name -match 'State') {
                                $smartAppState = $parsed
                            }
                        }
                    }
                }
            }
        }

        if ($null -eq $smartAppState -and $payload -and $payload.Registry) {
            $registryEntries = @()
            if ($payload.Registry -is [System.Collections.IEnumerable] -and -not ($payload.Registry -is [string])) {
                $registryEntries = @($payload.Registry)
            } else {
                $registryEntries = @($payload.Registry)
            }

            $registryMatch = $registryEntries | Where-Object { $_.Path -and $_.Path -match 'SmartAppControl' } | Select-Object -First 1
            if ($registryMatch -and $registryMatch.Values) {
                foreach ($prop in $registryMatch.Values.PSObject.Properties) {
                    if ($prop.Name -match '^PS') { continue }
                    $smartAppEvidence += ("{0}: {1}" -f $prop.Name, $prop.Value)
                    $candidate = $prop.Value
                    if ($null -ne $candidate) {
                        $parsed = 0
                        if ([int]::TryParse($candidate.ToString(), [ref]$parsed)) {
                            if ($prop.Name -match 'Enabled' -or $prop.Name -match 'State') {
                                $smartAppState = $parsed
                            }
                        }
                    }
                }
            }
        }

        $evidenceText = if ($smartAppEvidence.Count -gt 0) { $smartAppEvidence -join "`n" } else { '' }

        if ($smartAppState -eq 1) {
            Add-CategoryNormal -CategoryResult $result -Title 'Smart App Control enforced' -Evidence $evidenceText
        } elseif ($smartAppState -eq 2) {
            $severity = if ($isWindows11) { 'low' } else { 'info' }
            Add-CategoryIssue -CategoryResult $result -Severity $severity -Title 'Smart App Control in evaluation mode' -Evidence $evidenceText
        } elseif ($isWindows11) {
            Add-CategoryIssue -CategoryResult $result -Severity 'medium' -Title 'Smart App Control not enabled on Windows 11 device' -Evidence $evidenceText
        } elseif ($smartAppState -ne $null) {
            Add-CategoryIssue -CategoryResult $result -Severity 'info' -Title 'Smart App Control disabled' -Evidence $evidenceText
        }
    }

    $lapsArtifact = Get-AnalyzerArtifact -Context $Context -Name 'laps'
    if ($lapsArtifact) {
        $payload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $lapsArtifact)
        if ($payload -and $payload.LocalAdministrators) {
            $admins = $payload.LocalAdministrators | Where-Object { $_.AccountName -and -not $_.IsBuiltIn }
            if ($admins.Count -gt 0) {
                $names = $admins | Select-Object -First 5 -ExpandProperty AccountName
                Add-CategoryIssue -CategoryResult $result -Severity 'medium' -Title ('Standing local administrators detected: {0}' -f ($names -join ', '))
            } else {
                Add-CategoryNormal -CategoryResult $result -Title 'No additional local administrators detected'
            }
        }
    }

    return $result
}
