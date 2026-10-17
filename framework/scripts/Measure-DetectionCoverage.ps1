<#
.SYNOPSIS
  Measure-DetectionCoverage - OFFLINE scoring of detection coverage by ATT&CK technique.
.DESCRIPTION
  Compares a CSV of expected detections (columns: Technique,Rule) against a CSV of rules your
  SOC confirmed fired during the purple-team exercise (column: Rule). Touches no host or network.
.EXAMPLE
  .\Measure-DetectionCoverage.ps1 -ExpectedCsv expected.csv -ObservedCsv observed.csv -OutFile coverage.json
#>
[CmdletBinding()]
param([Parameter(Mandatory)][string]$ExpectedCsv, [string]$ObservedCsv, [string]$OutFile = 'coverage.json')
Import-Module "$PSScriptRoot/RTCommon.psm1" -Force
$exp = Import-Csv -LiteralPath $ExpectedCsv
$obs = if ($ObservedCsv) { Import-Csv -LiteralPath $ObservedCsv } else { @() }
$rows = @(Measure-RTCoverage -Expected $exp -Observed $obs)
$rows | ConvertTo-Json | Out-File -LiteralPath $OutFile -Encoding utf8
$overall = [math]::Round(100 * (($rows | Measure-Object detected -Sum).Sum) / (($rows | Measure-Object expected -Sum).Sum), 0)
Write-Host "[+] Coverage $overall% across $($rows.Count) technique(s) -> $OutFile" -ForegroundColor Green
$rows | Where-Object status -ne 'covered' | ForEach-Object { Write-Host ("    {0,-10} {1,-8} {2}/{3}" -f $_.technique,$_.status,$_.detected,$_.expected) -ForegroundColor Yellow }
