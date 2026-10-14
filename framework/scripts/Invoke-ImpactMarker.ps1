<#
.SYNOPSIS
  Invoke-ImpactMarker - SAFE, benign impact-simulation for Scenario C / docs/10.
  Proves the "reach + would-be impact" of a ransomware/impact operator WITHOUT any
  destructive action. It drops harmless marker files in an approved sandbox and inventories
  them, so detection (ransomware canaries, mass-file-write) can be validated.
.DESCRIPTION
  This script does NOT encrypt, delete, rename real data, touch shadow copies, stop services,
  or modify anything outside -SandboxDir. It writes marker files, records their hashes, and
  provides -Cleanup to remove them. That is the entire capability by design.
  ATT&CK T1486 (simulated only). Requires -ApprovalRef (impact sim is approval-gated).
.EXAMPLE
  .\Invoke-ImpactMarker.ps1 -SandboxDir C:\RT-Sandbox -Count 50 -ApprovalRef ENG-2026-001
  .\Invoke-ImpactMarker.ps1 -SandboxDir C:\RT-Sandbox -Cleanup
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][string]$SandboxDir,
    [int]$Count = 25,
    [string]$Marker = 'REDTEAM-IMPACT-CANARY',
    [switch]$Cleanup,
    [string]$ApprovalRef
)

Import-Module "$PSScriptRoot/RTSafety.psm1" -Force

# Refuse to operate anywhere but a dedicated sandbox dir (guards against real data).
$full = [System.IO.Path]::GetFullPath($SandboxDir)
if ($full -notmatch 'RT[-_]?Sandbox') {
    throw "STOP: SandboxDir must be a dedicated path containing 'RT-Sandbox'. Refusing to touch '$full'."
}

if ($Cleanup) {
    if (Test-Path $full) {
        Get-ChildItem -LiteralPath $full -Filter "*.rtmarker" -ErrorAction SilentlyContinue | Remove-Item -Force
        Write-Host "[+] Removed marker files from $full" -ForegroundColor Green
    }
    Write-RTEvidence -Technique 'Impact simulation cleanup' -TechniqueId 'T1486(sim)' -Target $env:COMPUTERNAME `
        -Command ".\Invoke-ImpactMarker.ps1 -Cleanup" -Result "sandbox cleaned" -Impact 'none' | Out-Null
    return
}

Assert-RTApproval -Technique 'Impact simulation (T1486 sim)' -ApprovalRef $ApprovalRef

New-Item -ItemType Directory -Force -Path $full | Out-Null
$records = @()
for ($i=1; $i -le $Count; $i++) {
    $f = Join-Path $full ("canary_{0:D4}.rtmarker" -f $i)
    "$Marker id=$i created=$((Get-Date).ToUniversalTime().ToString('o')) host=$env:COMPUTERNAME" |
        Out-File -LiteralPath $f -Encoding ascii
    $records += [ordered]@{ file = $f; sha256 = (Get-FileHash -LiteralPath $f -Algorithm SHA256).Hash }
}

$report = Join-Path $full 'impact_marker_report.json'
$records | ConvertTo-Json -Depth 4 | Out-File -LiteralPath $report -Encoding utf8

Write-Host "[+] Dropped $Count benign marker files in $full (NO real data touched)." -ForegroundColor Green
Write-Host "    This simulates the write-burst a ransomware operator would create, for detection testing." -ForegroundColor Cyan
Write-Host "    Run with -Cleanup to remove them. No encryption/deletion/service-stop was performed." -ForegroundColor Yellow

Write-RTEvidence -Technique 'Impact simulation (benign markers)' -TechniqueId 'T1486(sim)' `
    -Target $env:COMPUTERNAME -Command ".\Invoke-ImpactMarker.ps1 -SandboxDir $full -Count $Count" `
    -Result "dropped $Count markers -> $report" -Impact 'reversible (sandbox markers only)' `
    -TelemetryExpected 'mass file-create burst / ransomware canary alert' -CleanupRequired $true | Out-Null
