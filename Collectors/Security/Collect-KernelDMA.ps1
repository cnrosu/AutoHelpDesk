<#!
.SYNOPSIS
    Collects Kernel DMA protection configuration using gold-standard module with msinfo32 fallback.
#>
[CmdletBinding()]
param(
    [Parameter()]
    [string]$OutputDirectory = (Join-Path -Path (Split-Path -Parent $PSCommandPath) -ChildPath '..\output')
)

. (Join-Path -Path $PSScriptRoot -ChildPath '..\CollectorCommon.ps1')

$collectorRoot = Split-Path -Path $PSScriptRoot -Parent
$repositoryRoot = Split-Path -Path $collectorRoot -Parent
$kernelDmaModulePath = Join-Path -Path $repositoryRoot -ChildPath 'Modules\KernelDmaProtection.psm1'
if (Test-Path -LiteralPath $kernelDmaModulePath) {
    Import-Module -Name $kernelDmaModulePath -ErrorAction Stop -Verbose:$false
} else {
    throw "KernelDmaProtection module not found at $kernelDmaModulePath"
}

function ConvertTo-NoteArray {
    param(
        [object]$Value
    )

    if ($null -eq $Value) { return @() }
    if ($Value -is [string]) { return @($Value) }
    if ($Value -is [System.Collections.IEnumerable] -and -not ($Value -is [string])) {
        $notes = [System.Collections.Generic.List[string]]::new()
        foreach ($item in $Value) {
            if ($null -eq $item) { continue }
            $notes.Add([string]$item) | Out-Null
        }
        return $notes.ToArray()
    }

    return @([string]$Value)
}

function Invoke-Main {
    $status = Get-KernelDmaProtection

    $notes = ConvertTo-NoteArray -Value $status.Notes

    $payload = [ordered]@{
        KernelDmaProtection = $status.KernelDmaProtection
        Source              = $status.Source
        OS                  = $status.OS
        MsInfo              = $status.MsInfo
        Registry            = $status.Registry
        Notes               = $notes
        Raw                 = $status
    }

    $result = New-CollectorMetadata -Payload $payload
    $outputPath = Export-CollectorResult -OutputDirectory $OutputDirectory -FileName 'kerneldma.json' -Data $result -Depth 6
    Write-Output $outputPath
}

Invoke-Main
