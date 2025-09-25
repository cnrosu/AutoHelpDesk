<#!
.SYNOPSIS
    Renders analyzer findings into an HTML report.
#>

Add-Type -AssemblyName System.Web -ErrorAction SilentlyContinue

function Convert-SeverityToColor {
    param([string]$Severity)

    switch ($Severity.ToLowerInvariant()) {
        'critical' { return '#b91c1c' }
        'high'     { return '#dc2626' }
        'medium'   { return '#f97316' }
        'low'      { return '#fbbf24' }
        'warning'  { return '#facc15' }
        default    { return '#2563eb' }
    }
}

function Convert-EvidenceToHtml {
    param($Value)

    if ($null -eq $Value) { return '' }

    if ($Value -is [string]) {
        $text = $Value
    } elseif ($Value -is [ValueType]) {
        $text = $Value.ToString()
    } else {
        try {
            $text = ($Value | ConvertTo-Json -Depth 6)
        } catch {
            $text = $Value.ToString()
        }
    }

    if (-not $text) { return '' }

    $encoded = [System.Web.HttpUtility]::HtmlEncode([string]$text)
    return ($encoded -replace "(\r\n|\n|\r)", '<br/>')
}

function New-AnalyzerHtml {
    param(
        [Parameter(Mandatory)]
        [System.Collections.Generic.IEnumerable[object]]$Categories
    )

    $sb = New-Object System.Text.StringBuilder
    $null = $sb.AppendLine('<!DOCTYPE html>')
    $null = $sb.AppendLine('<html lang="en">')
    $null = $sb.AppendLine('<head>')
    $null = $sb.AppendLine('<meta charset="utf-8" />')
    $null = $sb.AppendLine('<title>Device Diagnostics</title>')
    $null = $sb.AppendLine('<style>body{font-family:Segoe UI,Arial,sans-serif;background:#f8fafc;color:#0f172a;margin:32px;}h1{font-size:28px;margin-bottom:4px;}h2{margin-top:32px;}table{border-collapse:collapse;width:100%;margin-top:12px;}th,td{border:1px solid #cbd5f5;padding:8px;text-align:left;}th{background:#e2e8f0;text-transform:uppercase;font-size:12px;letter-spacing:0.05em;}tr:nth-child(even){background:#f1f5f9;}span.badge{display:inline-block;padding:2px 8px;border-radius:12px;color:#fff;font-size:11px;margin-right:6px;}section{margin-bottom:32px;}p.small{font-size:12px;color:#64748b;margin-top:4px;}ul{margin:8px 0 0 18px;}li{margin-bottom:6px;}</style>')
    $null = $sb.AppendLine('</head>')
    $null = $sb.AppendLine('<body>')
    $null = $sb.AppendLine('<h1>Device Diagnostics</h1>')
    $null = $sb.AppendLine('<p class="small">Generated at ' + (Get-Date).ToString('u') + '</p>')

    foreach ($category in $Categories) {
        $null = $sb.AppendLine(("<section><h2>{0}</h2>" -f [System.Web.HttpUtility]::HtmlEncode($category.Name)))
        if ($category.Issues.Count -gt 0) {
            $null = $sb.AppendLine('<table><thead><tr><th>Severity</th><th>Finding</th><th>Evidence</th></tr></thead><tbody>')
            foreach ($issue in $category.Issues) {
                $color = Convert-SeverityToColor -Severity $issue.Severity
                $badge = "<span class='badge' style='background:$color'>{0}</span>" -f ([System.Web.HttpUtility]::HtmlEncode(($issue.Severity)))
                $title = [System.Web.HttpUtility]::HtmlEncode($issue.Title)
                $evidence = Convert-EvidenceToHtml $issue.Evidence
                $null = $sb.AppendLine("<tr><td>$badge</td><td>$title</td><td>$evidence</td></tr>")
            }
            $null = $sb.AppendLine('</tbody></table>')
        } else {
            $null = $sb.AppendLine('<p>No issues detected.</p>')
        }

        if ($category.Normals.Count -gt 0) {
            $null = $sb.AppendLine('<h3>Healthy signals</h3><ul>')
            foreach ($normal in $category.Normals) {
                $text = [System.Web.HttpUtility]::HtmlEncode($normal.Title)
                $detail = Convert-EvidenceToHtml $normal.Evidence
                if ($detail) {
                    $null = $sb.AppendLine("<li><strong>$text</strong><br/><span class='small'>$detail</span></li>")
                } else {
                    $null = $sb.AppendLine("<li>$text</li>")
                }
            }
            $null = $sb.AppendLine('</ul>')
        }

        if ($category.Checks.Count -gt 0) {
            $null = $sb.AppendLine('<h3>Checks</h3><table><thead><tr><th>Check</th><th>Status</th><th>Details</th></tr></thead><tbody>')
            foreach ($check in $category.Checks) {
                $name = [System.Web.HttpUtility]::HtmlEncode($check.Name)
                $status = [System.Web.HttpUtility]::HtmlEncode($check.Status)
                $details = [System.Web.HttpUtility]::HtmlEncode($check.Details)
                $null = $sb.AppendLine("<tr><td>$name</td><td>$status</td><td>$details</td></tr>")
            }
            $null = $sb.AppendLine('</tbody></table>')
        }

        $null = $sb.AppendLine('</section>')
    }

    $null = $sb.AppendLine('</body></html>')
    return $sb.ToString()
}
