function Invoke-PrinterNetworkTestChecks {
    param(
        [Parameter(Mandatory)]
        $Result,
        $NetworkTests
    )

    if (-not $NetworkTests) { return }

    foreach ($testGroup in (ConvertTo-PrintingArray $NetworkTests)) {
        if (-not $testGroup) { continue }
        foreach ($test in (ConvertTo-PrintingArray $testGroup.Tests)) {
            if (-not $test) { continue }
            if ($test.Success -eq $false -or $test.Error) {
                $evidence = "Host: {0}; Test: {1}; Error: {2}" -f $testGroup.Host, $test.Name, ($test.Error ? $test.Error : 'Connection failure')
                Add-CategoryIssue -CategoryResult $Result -Severity 'high' -Title ('Printer host connectivity test failed ({0}), exposing printing security and reliability risks.' -f $testGroup.Host) -Evidence $evidence -Subcategory 'Network Tests'
            }
        }
    }
}
