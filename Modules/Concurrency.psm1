function Invoke-Parallel {
  <#
  .SYNOPSIS
    Run a scriptblock across many items concurrently with robust control.

  .DESCRIPTION
    Cross-version (Windows PowerShell 5.x & PowerShell 7+) parallel helper using a RunspacePool.
    Features:
      - Throttle control (DegreeOfParallelism)
      - Per-item timeout
      - Cancellation (CancellationTokenSource)
      - Ordered or streaming outputs
      - Main-thread-only progress updates (no garbled bars)
      - Rich result objects (Success/Error/Duration/Item/Index)

  .PARAMETER InputObject
    Items to process. Each item is passed as -ArgumentList to the ScriptBlock:
      param($Item, $Index, $CancellationToken)

  .PARAMETER ScriptBlock
    The work to run for each item. MUST accept: param($Item, $Index, $CancellationToken)

  .PARAMETER DegreeOfParallelism
    Max concurrent workers (default: [Environment]::ProcessorCount).

  .PARAMETER TimeoutSeconds
    Per-item timeout. If exceeded, the worker is stopped and an error is recorded. Default: 0 (no timeout).

  .PARAMETER Ordered
    If set, outputs are emitted in input order. Otherwise they stream as they finish.

  .PARAMETER ErrorAction
    Controls behavior when an item fails:
      - Stop: Stop all remaining work and throw
      - Continue: Emit error in result object and continue (default)
      - SilentlyContinue: Swallow errors but mark result as unsuccessful

  .PARAMETER ProgressActivity
    Optional label for Write-Progress. If omitted, progress is suppressed.

  .PARAMETER CancellationToken
    Optional external CancellationTokenSource. If supplied, the run stops when cancelled.

  .EXAMPLE
    $results = Invoke-Parallel -InputObject $Computers -DegreeOfParallelism 8 -TimeoutSeconds 30 -Ordered -ProgressActivity "Collectors" -ScriptBlock {
      param($item, $i, $cts)
      # Example collector call
      Test-Connection -ComputerName $item -Count 1 -Quiet
    }

  .OUTPUTS
    [pscustomobject] with properties:
      Index, Item, Success, Result, ErrorRecord, StartTime, EndTime, DurationMs, ThreadId
  #>
  [CmdletBinding()]
  param(
    [Parameter(Mandatory, ValueFromPipeline)]
    [object[]]$InputObject,

    [Parameter(Mandatory)]
    [scriptblock]$ScriptBlock,

    [ValidateRange(1, 2048)]
    [int]$DegreeOfParallelism = [Environment]::ProcessorCount,

    [ValidateRange(0, 86400)]
    [int]$TimeoutSeconds = 0,

    [switch]$Ordered,

    [ValidateSet('Stop','Continue','SilentlyContinue')]
    [string]$ErrorAction = 'Continue',

    [string]$ProgressActivity,

    [System.Threading.CancellationTokenSource]$CancellationToken
  )

  begin {
    $allItems = [System.Collections.Generic.List[object]]::new()
  }
  process {
    foreach ($it in $InputObject) {
      [void]$allItems.Add($it)
    }
  }
  end {
    $externalCts = $null
    if (-not $CancellationToken) {
      $externalCts = [System.Threading.CancellationTokenSource]::new()
      $CancellationToken = $externalCts
    }

    $results = [System.Collections.Generic.List[object]]::new()
    $slots = [System.Collections.Generic.List[object]]::new()

    $iss = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
    $pool = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspacePool(1, $DegreeOfParallelism, $iss, $Host)
    $pool.ApartmentState = 'MTA'
    $pool.Open()

    $showProgress = -not [string]::IsNullOrWhiteSpace($ProgressActivity)
    $total = $allItems.Count
    $completed = 0
    $failed = 0

    function New-Work {
      param($item, $index)

      $ps = [System.Management.Automation.PowerShell]::Create()
      $ps.RunspacePool = $pool

      $wrapper = {
        param($UserScript, $Item, $Index, $Token)
        $ErrorActionPreference = 'Stop'
        $out = $null
        try {
          $start = Get-Date
          $out = & $UserScript $Item $Index $Token
          $end = Get-Date
          [pscustomobject]@{
            Index       = $Index
            Item        = $Item
            Success     = $true
            Result      = $out
            ErrorRecord = $null
            StartTime   = $start
            EndTime     = $end
            DurationMs  = [int]($end - $start).TotalMilliseconds
            ThreadId    = [System.Threading.Thread]::CurrentThread.ManagedThreadId
          }
        } catch {
          $end = Get-Date
          [pscustomobject]@{
            Index       = $Index
            Item        = $Item
            Success     = $false
            Result      = $null
            ErrorRecord = $_
            StartTime   = $null
            EndTime     = $end
            DurationMs  = $null
            ThreadId    = [System.Threading.Thread]::CurrentThread.ManagedThreadId
          }
        }
      }

      [void]$ps.AddScript($wrapper).AddArgument($ScriptBlock).AddArgument($item).AddArgument($index).AddArgument($CancellationToken.Token)
      $async = $ps.BeginInvoke()

      [pscustomobject]@{
        Index      = $index
        Item       = $item
        PowerShell = $ps
        Async      = $async
        Started    = Get-Date
      }
    }

    try {
      $nextIndex = 0
      while (($slots.Count -lt $DegreeOfParallelism) -and ($nextIndex -lt $total)) {
        $slots.Add((New-Work -item $allItems[$nextIndex] -index $nextIndex)) | Out-Null
        $nextIndex++
      }

      while ($slots.Count -gt 0) {
        if ($CancellationToken.IsCancellationRequested) {
          foreach ($s in $slots) {
            try {
              $s.PowerShell.Stop()
            } catch {}
            try {
              $s.PowerShell.Dispose()
            } catch {}
          }

          throw [System.OperationCanceledException]::new('Invoke-Parallel cancelled.')
        }

        for ($i = $slots.Count - 1; $i -ge 0; $i--) {
          $s = $slots[$i]

          $timedOut = $false
          if ($TimeoutSeconds -gt 0) {
            $elapsed = (Get-Date) - $s.Started
            if ($elapsed.TotalSeconds -ge $TimeoutSeconds) {
              $timedOut = $true
            }
          }

          if ($timedOut) {
            try {
              $s.PowerShell.Stop()
            } catch {}
            $null = $s.PowerShell.EndInvoke($s.Async)
            $s.PowerShell.Dispose()
            $failed++
            $completed++
            $res = [pscustomobject]@{
              Index       = $s.Index
              Item        = $s.Item
              Success     = $false
              Result      = $null
              ErrorRecord = [System.Management.Automation.ErrorRecord]::new(
                ([System.TimeoutException]::new("Timeout after $TimeoutSeconds seconds.")),
                'InvokeParallelTimeout',
                [System.Management.Automation.ErrorCategory]::OperationTimeout,
                $s.Item
              )
              StartTime   = $s.Started
              EndTime     = Get-Date
              DurationMs  = [int]((Get-Date) - $s.Started).TotalMilliseconds
              ThreadId    = $null
            }
            $results.Add($res) | Out-Null
            $slots.RemoveAt($i)

            if ($ErrorAction -eq 'Stop') {
              throw "Invoke-Parallel: timeout on item index $($s.Index)."
            }
            continue
          }

          if ($s.Async.IsCompleted) {
            $output = $s.PowerShell.EndInvoke($s.Async)
            $s.PowerShell.Dispose()

            foreach ($res in $output) {
              if ($res -and ($res | Get-Member -Name Success -MemberType NoteProperty -ErrorAction SilentlyContinue)) {
                if (-not $res.Success) {
                  $failed++
                }
                $results.Add($res) | Out-Null
              } else {
                $results.Add([pscustomobject]@{
                  Index       = $s.Index
                  Item        = $s.Item
                  Success     = $true
                  Result      = $output
                  ErrorRecord = $null
                  StartTime   = $s.Started
                  EndTime     = Get-Date
                  DurationMs  = [int]((Get-Date) - $s.Started).TotalMilliseconds
                  ThreadId    = [System.Threading.Thread]::CurrentThread.ManagedThreadId
                }) | Out-Null
              }
            }

            $completed++
            $slots.RemoveAt($i)

            if ($ErrorAction -eq 'Stop' -and -not $results[-1].Success) {
              throw "Invoke-Parallel: failure on item index $($s.Index): $($results[-1].ErrorRecord.Exception.Message)"
            }
          }
        }

        while (($slots.Count -lt $DegreeOfParallelism) -and ($nextIndex -lt $total)) {
          $slots.Add((New-Work -item $allItems[$nextIndex] -index $nextIndex)) | Out-Null
          $nextIndex++
        }

        if ($showProgress) {
          $pct = if ($total -gt 0) { [int](($completed / $total) * 100) } else { 100 }
          Write-Progress -Activity $ProgressActivity -Status "Completed: $completed / $total; Failed: $failed; Running: $($slots.Count)" -PercentComplete $pct
        }

        Start-Sleep -Milliseconds 50
      }

      if ($showProgress) {
        Write-Progress -Activity $ProgressActivity -Completed
      }

      if ($Ordered) {
        $results | Sort-Object Index | ForEach-Object { $_ }
      } else {
        $results | ForEach-Object { $_ }
      }
    } finally {
      if ($pool) {
        $pool.Close()
        $pool.Dispose()
      }
      if ($externalCts) {
        $externalCts.Dispose()
      }
    }
  }
}
