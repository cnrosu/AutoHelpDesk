function Invoke-PrintingSpoolerChecks {
    param(
        [Parameter(Mandatory)]
        $Result,
        $Spooler,
        [bool]$IsWorkstation
    )

    if (-not $Spooler) { return }

    if ($Spooler.Error) {
        Add-CategoryIssue -CategoryResult $Result -Severity 'high' -Title "Print Spooler state unavailable, so printing security and reliability risks can't be evaluated." -Evidence $Spooler.Error -Subcategory 'Spooler Service'
        return
    }

    $status = if ($Spooler.Status) { [string]$Spooler.Status } else { 'Unknown' }
    $startMode = if ($Spooler.StartMode) { [string]$Spooler.StartMode } else { $Spooler.StartType }
    $statusNorm = Normalize-PrintingServiceState -Value $status

    Add-CategoryCheck -CategoryResult $Result -Name 'Spooler status' -Status $status -Details ("StartMode: {0}" -f $startMode)

    if ($statusNorm -eq 'running') {
        if (-not $IsWorkstation) {
            Add-CategoryNormal -CategoryResult $Result -Title 'Print Spooler running' -Evidence ("Status: {0}; StartMode: {1}" -f $status, $startMode) -Subcategory 'Spooler Service'
        }
        return
    }

    $note = if ($IsWorkstation) { 'PrintNightmare guidance: disable spooler unless required.' } else { 'Printing will remain offline until the spooler is started.' }
    Add-CategoryIssue -CategoryResult $Result -Severity 'warning' -Title 'Print Spooler not running, exposing printing security and reliability risks until resolved.' -Evidence ("Status: {0}; StartMode: {1}; Note: {2}" -f $status, $startMode, $note) -Subcategory 'Spooler Service'
}
