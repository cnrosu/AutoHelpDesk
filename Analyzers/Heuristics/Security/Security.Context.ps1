function New-SecurityEvaluationContext {
    param(
        [Parameter(Mandatory)]
        $Context
    )

    $operatingSystem = $null
    $isWindows11 = $false
    $systemPayload = $null

    $systemArtifact = Get-AnalyzerArtifact -Context $Context -Name 'system'
    Write-HeuristicDebug -Source 'Security' -Message 'Resolved system artifact' -Data ([ordered]@{
        Found = [bool]$systemArtifact
    })
    if ($systemArtifact) {
        $systemPayload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $systemArtifact)
        Write-HeuristicDebug -Source 'Security' -Message 'Evaluating system payload for OS details' -Data ([ordered]@{
            HasPayload = [bool]$systemPayload
        })
        if ($systemPayload -and $systemPayload.OperatingSystem -and -not $systemPayload.OperatingSystem.Error) {
            $operatingSystem = $systemPayload.OperatingSystem
            if ($operatingSystem.Caption -and $operatingSystem.Caption -match 'Windows\s*11') {
                $isWindows11 = $true
            }
        }
    }

    $securityServicesRunning = @()
    $securityServicesConfigured = @()
    $availableSecurityProperties = @()
    $requiredSecurityProperties = @()

    $vbshvciArtifact = Get-AnalyzerArtifact -Context $Context -Name 'vbshvci'
    Write-HeuristicDebug -Source 'Security' -Message 'Resolved VBS/HVCI artifact' -Data ([ordered]@{
        Found = [bool]$vbshvciArtifact
    })
    if ($vbshvciArtifact) {
        $vbPayload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $vbshvciArtifact)
        Write-HeuristicDebug -Source 'Security' -Message 'Evaluating VBS/HVCI payload' -Data ([ordered]@{
            HasPayload = [bool]$vbPayload
        })
        if ($vbPayload -and $vbPayload.DeviceGuard -and -not $vbPayload.DeviceGuard.Error) {
            $dg = $vbPayload.DeviceGuard
            $securityServicesRunning = ConvertTo-IntArray $dg.SecurityServicesRunning
            $securityServicesConfigured = ConvertTo-IntArray $dg.SecurityServicesConfigured
            $availableSecurityProperties = ConvertTo-IntArray $dg.AvailableSecurityProperties
            $requiredSecurityProperties = ConvertTo-IntArray $dg.RequiredSecurityProperties
        }
    }

    $lsaEntries = @()
    $lsaArtifact = Get-AnalyzerArtifact -Context $Context -Name 'lsa'
    Write-HeuristicDebug -Source 'Security' -Message 'Resolved LSA artifact' -Data ([ordered]@{
        Found = [bool]$lsaArtifact
    })
    if ($lsaArtifact) {
        $lsaPayload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $lsaArtifact)
        Write-HeuristicDebug -Source 'Security' -Message 'Evaluating LSA payload' -Data ([ordered]@{
            HasRegistry = [bool]($lsaPayload -and $lsaPayload.Registry)
        })
        if ($lsaPayload -and $lsaPayload.Registry) {
            $lsaEntries = ConvertTo-List $lsaPayload.Registry
        }
    }

    return [pscustomobject]@{
        OperatingSystem            = $operatingSystem
        IsWindows11                = $isWindows11
        SystemPayload              = $systemPayload
        SecurityServicesRunning    = $securityServicesRunning
        SecurityServicesConfigured = $securityServicesConfigured
        AvailableSecurityProperties = $availableSecurityProperties
        RequiredSecurityProperties  = $requiredSecurityProperties
        LsaEntries                 = $lsaEntries
    }
}
