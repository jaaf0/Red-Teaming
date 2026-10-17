<#
.SYNOPSIS
  Invoke-AllChecks - runs the read-only audit suite and merges the results into one severity-ranked report.
.DESCRIPTION
  Host checks always run. Domain checks run when -Domain is given. Each step is isolated, so one
  failure is recorded and the rest continue. Output: per-tool JSON files plus report.json / report.md.
.EXAMPLE
  .\Invoke-AllChecks.ps1 -Domain corp.example.com -OutDir .\out
#>
[CmdletBinding()]
param([string]$Domain, [string]$OutDir = '.\rt-report')
Import-Module "$PSScriptRoot/RTSafety.psm1" -Force
Import-Module "$PSScriptRoot/RTCommon.psm1" -Force
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

$steps = [ordered]@{
    HostSurvey   = { & "$PSScriptRoot/Invoke-HostSurvey.ps1"   -OutFile "$OutDir/hostsurvey.json" }
    PrivEsc      = { & "$PSScriptRoot/Invoke-PrivEscAudit.ps1" -OutFile "$OutDir/privesc.json" }
    CredExposure = { & "$PSScriptRoot/Invoke-CredExposureAudit.ps1" -OutFile "$OutDir/credexposure.json" }
}
if ($Domain) {
    $steps.AdEnum   = { & "$PSScriptRoot/Invoke-AdEnum.ps1"          -Domain $Domain -OutFile "$OutDir/adenum.json" }
    $steps.Adcs     = { & "$PSScriptRoot/Invoke-AdcsAudit.ps1"       -Domain $Domain -OutFile "$OutDir/adcs.json" }
    $steps.Sysvol   = { & "$PSScriptRoot/Invoke-SysvolAudit.ps1"     -Domain $Domain -OutFile "$OutDir/sysvol.json" }
    $steps.Kerberos = { & "$PSScriptRoot/Invoke-KerberosPosture.ps1" -Domain $Domain -OutFile "$OutDir/kerberos.json" }
}

$status = [ordered]@{}; $findings = @()
foreach ($k in $steps.Keys) {
    try { & $steps[$k] | Out-Null; $status[$k] = 'ok' } catch { $status[$k] = "failed: $($_.Exception.Message)" }
}
foreach ($f in Get-ChildItem $OutDir -Filter *.json -ErrorAction SilentlyContinue | Where-Object { $_.Name -notlike 'report*' }) {
    $j = Get-Content $f.FullName -Raw | ConvertFrom-Json
    if ($j.PSObject.Properties.Name -contains 'findings') { $findings += @($j.findings) }
}
$merged = @(Merge-RTFindings $findings)
$sum = $merged | Group-Object severity | ForEach-Object { [pscustomobject]@{ severity=$_.Name; count=$_.Count } }

[ordered]@{ generatedUtc=(Get-Date).ToUniversalTime().ToString('o'); steps=$status; summary=$sum; findings=$merged } |
    ConvertTo-Json -Depth 8 | Out-File "$OutDir/report.json" -Encoding utf8

$md = @('# Audit report', '', "Generated: $((Get-Date).ToUniversalTime().ToString('u'))", '', '## Steps')
$md += $status.GetEnumerator() | ForEach-Object { "- $($_.Key): $($_.Value)" }
$md += '', '## Findings'
foreach ($f in $merged) { $md += "- **[$($f.severity)] $($f.id)** $($f.title) (`$($f.object)`) - $($f.remediation)" }
$md | Out-File "$OutDir/report.md" -Encoding utf8
Write-Host "[+] Report: $OutDir/report.md  ($($merged.Count) finding(s))" -ForegroundColor Green
Write-RTEvidence -Technique 'Audit suite run' -TechniqueId 'multiple' -Target $(if ($Domain) {$Domain} else {$env:COMPUTERNAME}) `
  -Command '.\Invoke-AllChecks.ps1' -Result "$($merged.Count) finding(s) -> $OutDir" | Out-Null
