function Get-PrintingPlatformInfo {
    param($Context)

    $isWindowsServer = $null
    $systemArtifact = Get-AnalyzerArtifact -Context $Context -Name 'system'
    if ($systemArtifact) {
        $payload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $systemArtifact)
        if ($payload -and $payload.OperatingSystem -and -not $payload.OperatingSystem.Error) {
            $caption = [string]$payload.OperatingSystem.Caption
            if ($caption) {
                $isWindowsServer = ($caption -match '(?i)windows\s+server')
            }
        }
    }

    $isWorkstation = $null
    if ($isWindowsServer -eq $true) { $isWorkstation = $false }
    elseif ($isWindowsServer -eq $false) { $isWorkstation = $true }

    return [pscustomobject]@{
        IsWindowsServer = $isWindowsServer
        IsWorkstation   = $isWorkstation
    }
}
