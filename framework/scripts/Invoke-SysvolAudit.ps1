<#
.SYNOPSIS
  Invoke-SysvolAudit - read-only SYSVOL audit: GPP cpassword exposure and writable policy/script locations.
.DESCRIPTION
  Scans SYSVOL XML for the presence of cpassword attributes (value never read or decoded) and
  reports script/policy files that non-admin principals can write. ATT&CK T1552.006 / T1484.001.
.EXAMPLE
  .\Invoke-SysvolAudit.ps1 -Domain corp.example.com -OutFile sysvol.json
#>
[CmdletBinding()]
param([string]$Domain, [string]$OutFile = 'sysvol_audit.json')
Import-Module "$PSScriptRoot/RTSafety.psm1" -Force
Import-Module "$PSScriptRoot/RTCommon.psm1" -Force

if (-not $Domain) { $Domain = (Get-CimInstance Win32_ComputerSystem).Domain }
if (-not (Test-RTScope -Target $Domain)) { throw "Domain $Domain failed scope check." }

$root = "\\$Domain\SYSVOL\$Domain"
if (-not (Test-Path -LiteralPath $root)) { throw "Cannot reach $root" }
$findings = @()
$lowPriv = 'Authenticated Users','Domain Users','Everyone','BUILTIN\Users'

Get-ChildItem -LiteralPath $root -Recurse -Include *.xml -File -ErrorAction SilentlyContinue | ForEach-Object {
    $text = Get-Content -LiteralPath $_.FullName -Raw -ErrorAction SilentlyContinue
    if ($text) { $findings += Find-GppCpassword -Text $text -Path $_.FullName }
}
Get-ChildItem -LiteralPath $root -Recurse -Include *.bat,*.cmd,*.ps1,*.vbs,GptTmpl.inf -File -ErrorAction SilentlyContinue | ForEach-Object {
    try {
        foreach ($ace in (Get-Acl -LiteralPath $_.FullName).Access) {
            if ($ace.AccessControlType -eq 'Allow' -and $ace.FileSystemRights -match 'Write|Modify|FullControl' -and
                ($lowPriv | Where-Object { $ace.IdentityReference.Value -like "*$_" })) {
                $findings += New-RTFinding -Id 'SYSVOL-WRITABLE' -Severity High -Object $_.FullName -Attack 'T1484.001' `
                    -Title 'Policy/script file in SYSVOL is writable by a low-privileged principal' `
                    -Detail "$($ace.IdentityReference) has $($ace.FileSystemRights)" `
                    -Remediation 'Restrict write access on SYSVOL content to administrators.'
                break
            }
        }
    } catch {}
}
$findings = @(Merge-RTFindings $findings)
[ordered]@{ domain=$Domain; collectedUtc=(Get-Date).ToUniversalTime().ToString('o'); findings=$findings } |
    ConvertTo-Json -Depth 6 | Out-File -LiteralPath $OutFile -Encoding utf8
Write-Host "[+] SYSVOL audit -> $OutFile ($($findings.Count) finding(s); passwords never read)" -ForegroundColor Green
Write-RTEvidence -Technique 'SYSVOL GPP/ACL audit' -TechniqueId 'T1552.006,T1484.001' -Target $Domain `
  -Command ".\Invoke-SysvolAudit.ps1 -Domain $Domain" -Result "$($findings.Count) finding(s) -> $OutFile" `
  -TelemetryExpected 'SMB reads of SYSVOL (5145)' | Out-Null
