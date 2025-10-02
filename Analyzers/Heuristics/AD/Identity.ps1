function Add-AdIdentityFindings {
    param(
        [Parameter(Mandatory)]
        $Result,
        $Context
    )

    $identityArtifact = Get-AnalyzerArtifact -Context $Context -Name 'identity'
    if (-not $identityArtifact) { return }

    $identityPayload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $identityArtifact)
    if ($identityPayload -and $identityPayload.DsRegCmd) {
        $text = if ($identityPayload.DsRegCmd -is [string[]]) { $identityPayload.DsRegCmd -join "`n" } else { [string]$identityPayload.DsRegCmd }
        if ($text -match 'AzureAdJoined\s*:\s*YES') {
            Add-CategoryNormal -CategoryResult $Result -Title 'Azure AD join detected' -Subcategory 'Discovery'
        }
    }
}
