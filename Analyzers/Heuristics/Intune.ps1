<#!
.SYNOPSIS
    Intune enrollment and connectivity heuristics module loader.
#>

. (Join-Path -Path (Split-Path $PSScriptRoot -Parent) -ChildPath 'AnalyzerCommon.ps1')
$script:intuneParserPath = Join-Path -Path (Split-Path $PSScriptRoot -Parent) -ChildPath 'Parsers/IntuneParsers.ps1'
if (Test-Path -LiteralPath $script:intuneParserPath) {
    . $script:intuneParserPath
}

$intuneModulePath = Join-Path -Path $PSScriptRoot -ChildPath 'Intune'
if (Test-Path -LiteralPath $intuneModulePath) {
    Get-ChildItem -Path $intuneModulePath -Filter '*.ps1' -File | Sort-Object Name | ForEach-Object {
        . $_.FullName
    }
}
