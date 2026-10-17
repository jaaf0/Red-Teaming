<#
.SYNOPSIS
  Analyze-AdGraph - OFFLINE attack-path analysis over a graph from Invoke-AdGraphCollect.ps1.
  The "find shortest path to Domain Admins"-style analysis, done locally. No network, no AD.
.DESCRIPTION
  Pure offline graph math on the JSON produced by the collector. Reads a file, prints paths.
  It touches no host and no directory service - it only reasons about data already collected.
  Edges are treated as directed "control/escalation" steps (MemberOf, GenericAll, WriteDacl,
  WriteOwner, GenericWrite, AllowedToDelegate). BFS finds the shortest path from each start
  principal to any high-value target (members-of Domain/Enterprise Admins, Administrators).
.PARAMETER GraphFile
  JSON from Invoke-AdGraphCollect.ps1.
.PARAMETER From
  Optional start principal (samAccountName). If omitted, every node that can reach an HVT is reported.
.PARAMETER HighValue
  Target group names to treat as crown jewels (default: Domain Admins, Enterprise Admins, Administrators).
.EXAMPLE
  .\Analyze-AdGraph.ps1 -GraphFile adgraph.json
  .\Analyze-AdGraph.ps1 -GraphFile adgraph.json -From jdoe
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$GraphFile,
    [string]$From,
    [string[]]$HighValue = @('Domain Admins','Enterprise Admins','Administrators'),
    [int]$MaxPaths = 50,
    [string]$OutFile = "adgraph_paths.json"
)

if (-not (Test-Path -LiteralPath $GraphFile)) { throw "Graph file not found: $GraphFile" }
$g = Get-Content -LiteralPath $GraphFile -Raw | ConvertFrom-Json

# adjacency list: from -> list of @{ to; type }
$adj = @{}
foreach ($e in $g.edges) {
    if (-not $adj.ContainsKey($e.from)) { $adj[$e.from] = [System.Collections.Generic.List[object]]::new() }
    $adj[$e.from].Add([pscustomobject]@{ to = $e.to; type = $e.type })
}

# crown-jewel node set = the HVT groups themselves plus their direct members
$hvtSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
foreach ($h in $HighValue) { [void]$hvtSet.Add($h) }
foreach ($e in $g.edges) { if ($e.type -eq 'MemberOf' -and ($HighValue -contains $e.to)) { [void]$hvtSet.Add($e.from) } }

function Find-Path([string]$start) {
    # BFS; returns the shortest edge path from $start to any HVT node, or $null
    if ($hvtSet.Contains($start)) { return @() }   # already crown jewel
    $q = [System.Collections.Generic.Queue[object]]::new()
    $seen = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    [void]$seen.Add($start)
    $q.Enqueue([pscustomobject]@{ node = $start; path = @() })
    while ($q.Count) {
        $cur = $q.Dequeue()
        if (-not $adj.ContainsKey($cur.node)) { continue }
        foreach ($edge in $adj[$cur.node]) {
            if ($seen.Contains($edge.to)) { continue }
            $newPath = $cur.path + ,([pscustomobject]@{ from = $cur.node; via = $edge.type; to = $edge.to })
            if ($hvtSet.Contains($edge.to)) { return $newPath }
            [void]$seen.Add($edge.to)
            $q.Enqueue([pscustomobject]@{ node = $edge.to; path = $newPath })
        }
    }
    return $null
}

$starts = if ($From) { @($From) } else { @($g.nodes | Where-Object { $_.type -ne 'Group' } | ForEach-Object { $_.name }) }

$results = [System.Collections.Generic.List[object]]::new()
foreach ($s in $starts) {
    $p = Find-Path $s
    if ($null -ne $p -and $p.Count -gt 0) {
        $results.Add([pscustomobject]@{ start = $s; hops = $p.Count; path = $p })
    }
}
$results = $results | Sort-Object hops | Select-Object -First $MaxPaths

[ordered]@{
    graphFile  = $GraphFile
    analyzedUtc= (Get-Date).ToUniversalTime().ToString('o')
    highValue  = $HighValue
    pathsFound = $results.Count
    paths      = $results
} | ConvertTo-Json -Depth 10 | Out-File -LiteralPath $OutFile -Encoding utf8

Write-Host "[+] Offline path analysis -> $OutFile" -ForegroundColor Green
Write-Host "    Principals with a path to a high-value target: $($results.Count)" -ForegroundColor Cyan
foreach ($r in ($results | Select-Object -First 10)) {
    $chain = ($r.path | ForEach-Object { "$($_.from) -[$($_.via)]-> $($_.to)" }) -join '  ==>  '
    Write-Host ("    ({0} hop) {1}" -f $r.hops, $chain) -ForegroundColor Gray
}
Write-Host "    Hand these paths to the blue team as remediation targets (break the edges)." -ForegroundColor Yellow
