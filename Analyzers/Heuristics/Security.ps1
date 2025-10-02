<#!
.SYNOPSIS
    Security-focused heuristic evaluations based on collected JSON artifacts.
#>

. (Join-Path -Path (Split-Path $PSScriptRoot -Parent) -ChildPath 'AnalyzerCommon.ps1')

$securityModuleRoot = Join-Path -Path $PSScriptRoot -ChildPath 'Security'
foreach ($moduleName in @(
    'Security.Helpers.ps1',
    'Security.Context.ps1',
    'Security.Defender.ps1',
    'Security.Firewall.ps1',
    'Security.BitLocker.ps1',
    'Security.MeasuredBoot.ps1',
    'Security.DeviceProtection.ps1',
    'Security.CredentialPolicies.ps1',
    'Security.Autorun.ps1'
)) {
    $modulePath = Join-Path -Path $securityModuleRoot -ChildPath $moduleName
    if (Test-Path -LiteralPath $modulePath) {
        . $modulePath
    }
}

function Invoke-SecurityHeuristics {
    param(
        [Parameter(Mandatory)]
        $Context
    )

    Write-HeuristicDebug -Source 'Security' -Message 'Starting security heuristics' -Data ([ordered]@{
        ArtifactCount = if ($Context -and $Context.Artifacts) { $Context.Artifacts.Count } else { 0 }
    })

    $result = New-CategoryResult -Name 'Security'
    $evaluationContext = New-SecurityEvaluationContext -Context $Context

    Invoke-SecurityDefenderChecks -Context $Context -CategoryResult $result
    Invoke-SecurityFirewallChecks -Context $Context -CategoryResult $result
    Invoke-SecurityBitLockerChecks -Context $Context -CategoryResult $result
    Invoke-SecurityMeasuredBootChecks -Context $Context -CategoryResult $result
    Invoke-SecurityTpmChecks -Context $Context -CategoryResult $result
    Invoke-SecurityKernelDmaChecks -Context $Context -CategoryResult $result
    Invoke-SecurityAttackSurfaceChecks -Context $Context -CategoryResult $result
    Invoke-SecurityWdacChecks -Context $Context -CategoryResult $result -EvaluationContext $evaluationContext
    Invoke-SecurityCredentialManagementChecks -Context $Context -CategoryResult $result -EvaluationContext $evaluationContext
    Invoke-SecurityPolicyChecks -Context $Context -CategoryResult $result -EvaluationContext $evaluationContext
    Invoke-SecurityAutorunChecks -Context $Context -CategoryResult $result

    return $result
}
