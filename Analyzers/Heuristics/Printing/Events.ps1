function Invoke-PrinterEventChecks {
    param(
        [Parameter(Mandatory)]
        $Result,
        $Events
    )

    if (-not $Events) { return }

    if ($Events.Admin) {
        $admin = $Events.Admin
        Add-CategoryCheck -CategoryResult $Result -Name 'PrintService/Admin errors' -Status ([string]$admin.ErrorCount)
        if ($admin.ErrorCount -gt 0) {
            $severity = if ($admin.ErrorCount -ge 5) { 'high' } else { 'medium' }
            $driverCrashSummaries = [System.Collections.Generic.List[string]]::new()
            foreach ($entry in $admin.DriverCrashCount.GetEnumerator()) {
                $null = $driverCrashSummaries.Add(("{0}={1}" -f $entry.Key, $entry.Value))
            }

            $evidence = "Errors: {0}; Driver crash IDs: {1}" -f $admin.ErrorCount, ($driverCrashSummaries -join ', ')
            Add-CategoryIssue -CategoryResult $Result -Severity $severity -Title 'PrintService Admin log reporting errors, exposing printing security and reliability risks.' -Evidence $evidence -Subcategory 'Event Logs'
        }
    }

    if ($Events.Operational) {
        $op = $Events.Operational
        Add-CategoryCheck -CategoryResult $Result -Name 'PrintService/Operational warnings' -Status ([string]$op.WarningCount)
        if ($op.ErrorCount -gt 10) {
            Add-CategoryIssue -CategoryResult $Result -Severity 'medium' -Title 'PrintService Operational log has frequent errors, exposing printing security and reliability risks.' -Evidence ("Errors: {0}" -f $op.ErrorCount) -Subcategory 'Event Logs'
        }
    }
}
