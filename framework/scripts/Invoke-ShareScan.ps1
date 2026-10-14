<#
.SYNOPSIS
  Invoke-ShareScan - custom, read-only SMB share discovery across in-scope hosts.
  No community modules. Enumerates shares and read access only (ATT&CK T1135/T1083).
.DESCRIPTION
  For each in-scope target it lists shares (net view) and, optionally, top-level readable
  paths. It NEVER writes, deletes, or reads file contents - directory listing only.
  Every target passes Test-RTScope first; out-of-scope hosts are skipped.
.EXAMPLE
  .\Invoke-ShareScan.ps1 -Targets dc01,fs01 -OutFile shares.json
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string[]]$Targets,
    [switch]$ListTopLevel,                 # also list root entries of each readable share
    [string]$OutFile = "sharescan.json"
)

Import-Module "$PSScriptRoot/RTSafety.psm1" -Force
$scope = Import-RTScope
$results = @()

foreach ($t in $Targets) {
    if (-not (Test-RTScope -Target $t -Scope $scope)) { continue }   # fail-closed skip

    $entry = [ordered]@{ target = $t; shares = @() }
    $raw = net view "\\$t" /all 2>$null
    foreach ($line in $raw) {
        if ($line -match '^\s*(\S.*?)\s+Disk\s*$') {
            $share = $matches[1].Trim()
            $unc = "\\$t\$share"
            $readable = $false; $top = @()
            try {
                $items = Get-ChildItem -LiteralPath $unc -ErrorAction Stop | Select-Object -First 25
                $readable = $true
                if ($ListTopLevel) { $top = $items | Select-Object Name, @{n='Type';e={ if ($_.PSIsContainer) {'dir'} else {'file'} }} }
            } catch { $readable = $false }
            $entry.shares += [ordered]@{ name = $share; unc = $unc; readable = $readable; topLevel = $top }
        }
    }
    $results += $entry
    Write-Host "[+] $t : $($entry.shares.Count) share(s), readable: $(@($entry.shares | Where-Object readable).Count)" -ForegroundColor Green
}

$results | ConvertTo-Json -Depth 6 | Out-File -LiteralPath $OutFile -Encoding utf8

Write-RTEvidence -Technique 'Network share discovery' -TechniqueId 'T1135,T1083' `
    -Target ($Targets -join ',') -Command ".\Invoke-ShareScan.ps1 -Targets $($Targets -join ',')" `
    -Result "scanned $($results.Count) host(s) -> $OutFile" `
    -TelemetryExpected 'SMB tree-connect / share-access events' | Out-Null
