<#!
.SYNOPSIS
    Analyzer orchestrator that loads JSON artifacts, runs heuristic modules, and generates an HTML report.
.PARAMETER InputFolder
    Specifies the folder containing collector artifacts to be analyzed.
.PARAMETER OutputPath
    Optional path for the generated HTML report. When omitted, the report is written next to the input folder.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$InputFolder,

    [Parameter()]
    [string]$OutputPath
)

$ErrorActionPreference = 'Stop'

$commonModulePath = Join-Path -Path (Split-Path $PSScriptRoot -Parent) -ChildPath 'Modules/Common.psm1'
if (Test-Path -Path $commonModulePath) {
    Import-Module $commonModulePath -Force
}

. (Join-Path -Path $PSScriptRoot -ChildPath 'AnalyzerCommon.ps1')
. (Join-Path -Path $PSScriptRoot -ChildPath 'Heuristics/System.ps1')
. (Join-Path -Path $PSScriptRoot -ChildPath 'Heuristics/Security.ps1')
. (Join-Path -Path $PSScriptRoot -ChildPath 'Heuristics/Network.ps1')
. (Join-Path -Path $PSScriptRoot -ChildPath 'Heuristics/AD.ps1')
. (Join-Path -Path $PSScriptRoot -ChildPath 'Heuristics/Office.ps1')
. (Join-Path -Path $PSScriptRoot -ChildPath 'Heuristics/Storage.ps1')
. (Join-Path -Path $PSScriptRoot -ChildPath 'Heuristics/Events.ps1')
. (Join-Path -Path $PSScriptRoot -ChildPath 'Heuristics/Services.ps1')
. (Join-Path -Path $PSScriptRoot -ChildPath 'Heuristics/Printing.ps1')
. (Join-Path -Path $PSScriptRoot -ChildPath 'HtmlComposer.ps1')

$context = New-AnalyzerContext -InputFolder $InputFolder

$categories = @()
$categories += Invoke-SystemHeuristics   -Context $context
$categories += Invoke-SecurityHeuristics -Context $context
$categories += Invoke-NetworkHeuristics  -Context $context
$categories += Invoke-ADHeuristics       -Context $context
$categories += Invoke-OfficeHeuristics   -Context $context
$categories += Invoke-StorageHeuristics  -Context $context
$categories += Invoke-EventsHeuristics   -Context $context
$categories += Invoke-ServicesHeuristics -Context $context
$categories += Invoke-PrintingHeuristics -Context $context

$merged = Merge-AnalyzerResults -Categories $categories

$html = New-AnalyzerHtml -Categories $categories

if (-not $OutputPath) {
    $OutputPath = Join-Path -Path $InputFolder -ChildPath 'diagnostics-report.html'
}

$directory = Split-Path -Path $OutputPath -Parent
if (-not (Test-Path -Path $directory)) {
    $null = New-Item -Path $directory -ItemType Directory -Force
}

$html | Out-File -FilePath $OutputPath -Encoding UTF8

[pscustomobject]@{
    HtmlPath = (Resolve-Path -Path $OutputPath).ProviderPath
    Issues   = $merged.Issues
    Normals  = $merged.Normals
    Checks   = $merged.Checks
}
