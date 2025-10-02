Import-Module Pester -ErrorAction Stop

$testsRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$analyzersRoot = Split-Path -Parent $testsRoot
$repoRoot = Split-Path -Parent $analyzersRoot

. (Join-Path $analyzersRoot 'AnalyzerCommon.ps1')
. (Join-Path $analyzersRoot 'Heuristics/Hardware.ps1')

Describe 'Invoke-HardwareHeuristics Autorun assessment' {
    It 'records a normal when autorun and autoplay are hardened' {
        $fixturePath = Join-Path $testsRoot 'Fixtures/Hardware/AutorunCompliant'
        $context = New-AnalyzerContext -InputFolder $fixturePath
        $result = Invoke-HardwareHeuristics -Context $context

        $autorunIssues = $result.Issues | Where-Object { $_.Subcategory -eq 'Removable Media' -and $_.Severity -eq 'medium' }
        $autorunIssues | Should -BeNullOrEmpty

        $autorunNormals = $result.Normals | Where-Object { $_.Subcategory -eq 'Removable Media' }
        $autorunNormals | Should -Not -BeNullOrEmpty
        $autorunNormals[0].Title | Should -Match 'disabled'
    }

    It 'flags a medium issue when autorun remains enabled' {
        $fixturePath = Join-Path $testsRoot 'Fixtures/Hardware/AutorunNonCompliant'
        $context = New-AnalyzerContext -InputFolder $fixturePath
        $result = Invoke-HardwareHeuristics -Context $context

        $autorunIssues = $result.Issues | Where-Object { $_.Subcategory -eq 'Removable Media' -and $_.Severity -eq 'medium' }
        $autorunIssues | Should -Not -BeNullOrEmpty
        $autorunIssues[0].Title | Should -Match 'remains enabled'
        $autorunIssues[0].Evidence | Should -Match 'NoAutoRun'

        $autorunNormals = $result.Normals | Where-Object { $_.Subcategory -eq 'Removable Media' }
        $autorunNormals | Should -BeNullOrEmpty
    }
}
