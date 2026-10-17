<#
.SYNOPSIS
  Invoke-CredExposureAudit - read-only CREDENTIAL-EXPOSURE auditor (Windows).
  Reports the conditions that make credential theft (LSASS dumping, pass-the-hash,
  Kerberos ticket abuse, DCSync) possible - so the client can REMEDIATE them.
.DESCRIPTION
  This is the defensive counterpart to tools like Mimikatz. It does NOT touch LSASS
  memory, does NOT read SAM/LSA secrets, does NOT request or extract tickets, and does
  NOT read any password value. It only inspects configuration and reports exposure,
  all read-only (defensive context around ATT&CK T1003/T1558/T1552/T1550):
    - WDigest UseLogonCredential (cleartext creds held in LSASS)
    - LSASS protection: RunAsPPL / LSA protection
    - Credential Guard / VBS status
    - Cached domain logon count (offline cracking surface)
    - Autologon DefaultPassword present in registry (flag only, value NOT read)
    - cmdkey / stored-credential entries present (count only)
    - Unattend / sysprep answer files present (presence only)
    - WLAN profiles present (presence/count only, keys NOT exported)
    - Restricted Admin mode / LAPS presence
  Output = a findings report an operator hands to the blue team. Nothing is modified
  and no secret is ever read. For the approval-gated offensive counterpart, use
  established signed tooling under ROE - see docs/09. (This script does not do it.)
.EXAMPLE
  .\Invoke-CredExposureAudit.ps1 -OutFile credexposure.json
#>
[CmdletBinding()]
param([string]$OutFile = "credexposure_$($env:COMPUTERNAME).json")
Import-Module "$PSScriptRoot/RTSafety.psm1" -Force

function Get-Reg([string]$Path, [string]$Name) {
    try { (Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop).$Name } catch { $null }
}

$f = [ordered]@{
    host         = $env:COMPUTERNAME
    collectedUtc = (Get-Date).ToUniversalTime().ToString('o')
    note         = 'Read-only exposure audit. No LSASS/SAM access, no secret values read.'
}

# 1) WDigest cleartext-credential caching (exploitable if UseLogonCredential = 1)
$wdigest = Get-Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' 'UseLogonCredential'
$f.wdigestCleartext = [ordered]@{
    useLogonCredential = $wdigest
    exposed            = ($wdigest -eq 1)
    remediation        = 'Set UseLogonCredential = 0 (default on modern Windows).'
}

# 2) LSASS protection (PPL) - makes LSASS memory much harder to read
$runAsPPL = Get-Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'RunAsPPL'
$f.lsassProtection = [ordered]@{
    runAsPPL   = $runAsPPL
    protected  = ($runAsPPL -ge 1)
    remediation= 'Enable LSA protection (RunAsPPL = 1) and secure boot/UEFI.'
}

# 3) Credential Guard / VBS (read-only via CIM; not all SKUs expose it)
$cg = $null
try {
    $dg = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace 'root\Microsoft\Windows\DeviceGuard' -ErrorAction Stop
    $cg = [ordered]@{
        securityServicesConfigured = @($dg.SecurityServicesConfigured)
        securityServicesRunning    = @($dg.SecurityServicesRunning)
        credentialGuardRunning     = (@($dg.SecurityServicesRunning) -contains 1)
    }
} catch { $cg = [ordered]@{ available = $false } }
$f.credentialGuard = $cg

# 4) Cached domain logons (cracking surface if a host is compromised offline)
$cached = Get-Reg 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' 'CachedLogonsCount'
$f.cachedLogons = [ordered]@{
    cachedLogonsCount = $cached
    remediation       = 'Lower CachedLogonsCount (e.g. 0-2) on high-value / fixed hosts.'
}

# 5) Autologon password stored in registry (FLAG ONLY - value is never read)
$winlogon = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
$autoAdmin = Get-Reg $winlogon 'AutoAdminLogon'
$hasDefaultPassword = $false
try { $hasDefaultPassword = [bool](Get-ItemProperty -Path $winlogon -Name 'DefaultPassword' -ErrorAction Stop) } catch {}
$f.autologon = [ordered]@{
    autoAdminLogon        = $autoAdmin
    defaultPasswordPresent= $hasDefaultPassword   # presence only; value intentionally NOT read
    exposed               = (($autoAdmin -eq '1') -and $hasDefaultPassword)
    remediation           = 'Remove DefaultPassword; use LAPS / gMSA instead of autologon.'
}

# 6) Stored credential surfaces (counts / presence only)
$f.storedCredentials = [ordered]@{
    cmdkeyEntryCount = @((cmdkey /list 2>$null) -match 'Target:').Count
    unattendFiles    = @(Get-ChildItem 'C:\Windows\Panther\Unattend.xml','C:\Windows\System32\Sysprep\unattend.xml','C:\unattend.xml' -EA SilentlyContinue |
                         Select-Object -ExpandProperty FullName)
    wlanProfileCount = @((netsh wlan show profiles 2>$null) -match 'All User Profile').Count  # keys NOT exported
}

# 7) Restricted Admin mode + LAPS presence (both reduce credential reuse / PtH impact)
$f.restrictedAdminMode = Get-Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'DisableRestrictedAdmin'
$f.lapsPresent = [bool]((Get-Reg 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS' 'BackupDirectory') -or
                        (Test-Path 'C:\Program Files\LAPS\CSE\AdmPwd.dll'))

# --- summarise exposures ---
$exposed = @()
if ($f.wdigestCleartext.exposed)          { $exposed += 'WDigest-cleartext' }
if (-not $f.lsassProtection.protected)    { $exposed += 'LSASS-not-PPL' }
if (-not ($cg.credentialGuardRunning))    { $exposed += 'no-CredentialGuard' }
if ($f.autologon.exposed)                 { $exposed += 'autologon-password' }
if ($f.storedCredentials.cmdkeyEntryCount -gt 0) { $exposed += "cmdkey:$($f.storedCredentials.cmdkeyEntryCount)" }
if (-not $f.lapsPresent)                  { $exposed += 'no-LAPS' }
$f.exposuresSummary = $exposed

$f | ConvertTo-Json -Depth 6 | Out-File $OutFile -Encoding utf8

Write-Host "[+] Credential-exposure audit -> $OutFile" -ForegroundColor Green
Write-Host "    Exposures: $([string]::Join(', ', $exposed))" -ForegroundColor Cyan
Write-Host "    Read-only. No LSASS/SAM access, no secret values read. Hand this to the blue team." -ForegroundColor Yellow

Write-RTEvidence -Technique 'Credential-exposure configuration audit (defensive)' -TechniqueId 'T1003,T1552,T1558,T1550' `
  -Target $env:COMPUTERNAME -Command '.\Invoke-CredExposureAudit.ps1' `
  -Result "exposures: $([string]::Join(', ', $exposed)) -> $OutFile" `
  -Impact 'none (read-only config audit; no memory/secret access)' `
  -TelemetryExpected 'registry/CIM reads only (low signal); no LSASS access events' | Out-Null
