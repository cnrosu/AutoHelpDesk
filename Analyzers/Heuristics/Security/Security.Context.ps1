function New-SecurityEvaluationContext {
    param(
        [Parameter(Mandatory)]
        $Context
    )

    $operatingSystem = $null
    $isWindows11 = $false
    $systemPayload = $null

    $msinfoIdentity = Get-MsinfoSystemIdentity -Context $Context
    Write-HeuristicDebug -Source 'Security' -Message 'Resolved msinfo system identity' -Data ([ordered]@{
        Found = [bool]$msinfoIdentity
    })
    if ($msinfoIdentity) {
        $caption = $msinfoIdentity.OSName
        $version = if ($msinfoIdentity.OSVersion) { $msinfoIdentity.OSVersion } else { $msinfoIdentity.OSVersionRaw }
        $build = $msinfoIdentity.OSBuild
        $architecture = $msinfoIdentity.OSArchitecture
        $displayVersion = $msinfoIdentity.DisplayVersion

        $operatingSystem = [pscustomobject]@{
            Caption        = $caption
            Version        = $version
            BuildNumber    = $build
            OSArchitecture = $architecture
            DisplayVersion = $displayVersion
        }

        if ($caption -and $caption -match 'Windows\s*11') {
            $isWindows11 = $true
        }

        $systemPayload = [pscustomobject]@{ OperatingSystem = $operatingSystem }
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
