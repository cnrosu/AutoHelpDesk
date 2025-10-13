<#!
.SYNOPSIS
    Hardware heuristics evaluating Device Manager driver health and startup state.
#>

. (Join-Path -Path (Split-Path $PSScriptRoot -Parent) -ChildPath 'AnalyzerCommon.ps1')

$hardwareModuleRoot = Join-Path -Path $PSScriptRoot -ChildPath 'Hardware'
. (Join-Path -Path $hardwareModuleRoot -ChildPath 'Inventory.ps1')
. (Join-Path -Path $hardwareModuleRoot -ChildPath 'Common.ps1')
. (Join-Path -Path $hardwareModuleRoot -ChildPath 'Normalization.ps1')
. (Join-Path -Path $hardwareModuleRoot -ChildPath 'Events.ps1')
. (Join-Path -Path $hardwareModuleRoot -ChildPath 'InvokeHardware.ps1')
