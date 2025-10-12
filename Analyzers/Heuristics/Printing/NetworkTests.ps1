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
                $errorDetail = if ($test.Error) { $test.Error } else { 'Connection failure' }
                $evidence = "Host: {0}; Test: {1}; Error: {2}" -f $testGroup.Host, $test.Name, $errorDetail
                Add-CategoryIssue -CategoryResult $Result -CardId 'Printing/NetworkTests/printer-host-connectivity-test-failed-0' -Evidence $evidence -Data @{
                    Host      = $testGroup.Host
                    TestName  = $test.Name
                    Error     = $errorDetail
                    Transport = if ($test.PSObject.Properties['Protocol']) { [string]$test.Protocol } else { $null }
                }
            }
        }
    }
}
