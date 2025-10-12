param()

$ErrorActionPreference = 'Stop'

$parsersTestRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$parsersDir = Split-Path -Parent $parsersTestRoot
$analyzersDir = Split-Path -Parent $parsersDir

. (Join-Path $analyzersDir 'AnalyzerCommon.ps1')
. (Join-Path $parsersDir 'IntuneParsers.ps1')

function New-ScheduledTasksContext {
    param(
        [Parameter(Mandatory)]
        [string]$TaskText
    )

    $payload = [pscustomobject]@{ Tasks = $TaskText }
    $artifact = [pscustomobject]@{
        Path = 'diagnostics\\scheduled-tasks.json'
        Data = [pscustomobject]@{ Payload = $payload }
    }

    $artifactList = [System.Collections.Generic.List[object]]::new()
    $null = $artifactList.Add($artifact)

    return [pscustomobject]@{
        Artifacts = @{ 'scheduled-tasks' = $artifactList }
    }
}

Describe 'Get-IntunePushLaunchTaskStatus' {
    It 'selects the EnterpriseMgmt PushLaunch task when present' {
        $fixturePath = Join-Path $parsersTestRoot 'Fixtures/scheduled-tasks-enterprisemgmt.txt'
        $taskText = Get-Content -LiteralPath $fixturePath -Raw
        $context = New-ScheduledTasksContext -TaskText $taskText

        $result = Get-IntunePushLaunchTaskStatus -Context $context

        $result.Collected | Should -BeTrue
        $result.Found | Should -BeTrue
        $result.TaskName | Should -Be '\\Microsoft\\Windows\\EnterpriseMgmt\\{11111111-2222-3333-4444-555555555555}\\PushLaunch'
        $result.Status | Should -Be 'Ready'
        $result.LastResult | Should -Be '0x0'
    }

    It 'ignores Push-to-Install PushLaunch tasks' {
        $fixturePath = Join-Path $parsersTestRoot 'Fixtures/scheduled-tasks-pushtoinstall.txt'
        $taskText = Get-Content -LiteralPath $fixturePath -Raw
        $context = New-ScheduledTasksContext -TaskText $taskText

        $result = Get-IntunePushLaunchTaskStatus -Context $context

        $result.Collected | Should -BeTrue
        $result.Found | Should -BeFalse
        $result.TaskName | Should -Be $null
    }
}
