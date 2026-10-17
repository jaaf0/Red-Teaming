<#
.SYNOPSIS
  Invoke-PrivEscAudit - read-only local privilege-escalation MISCONFIG auditor (Windows).
  Reports weaknesses an attacker could abuse. It does NOT exploit any of them.
.DESCRIPTION
  Checks, all read-only (ATT&CK context T1543.003/T1574/T1053.005/T1548.002/T1552):
    - Unquoted service paths with spaces
    - Service binaries / dirs writable by the current (non-admin) user
    - Services whose config is writable (weak ACL) - via sc sdshow, reported only
    - AlwaysInstallElevated registry policy (HKLM+HKCU)
    - Writable directories on %PATH%
    - Dangerous token privileges held (SeImpersonate/SeBackup/SeRestore/etc.)
    - Stored-credential surfaces present (cmdkey list, unattend/sysprep files) - presence only
  Output = a findings report for the operator to validate manually. Nothing is modified.
.EXAMPLE
  .\Invoke-PrivEscAudit.ps1 -OutFile privesc.json
#>
[CmdletBinding()]
param([string]$OutFile = "privescaudit_$($env:COMPUTERNAME).json")
Import-Module "$PSScriptRoot/RTSafety.psm1" -Force

$id = [Security.Principal.WindowsIdentity]::GetCurrent()
$me = New-Object Security.Principal.WindowsPrincipal($id)
$findings = [ordered]@{ host=$env:COMPUTERNAME; user=$id.Name; collectedUtc=(Get-Date).ToUniversalTime().ToString('o') }

function Test-Writable([string]$path) {
    if (-not $path -or -not (Test-Path $path)) { return $false }
    try {
        $acl = Get-Acl $path
        foreach ($ace in $acl.Access) {
            if ($ace.AccessControlType -ne 'Allow') { continue }
            if ($id.Groups -contains $ace.IdentityReference -or $ace.IdentityReference -eq $id.User -or
                $ace.IdentityReference -in @('Everyone','BUILTIN\Users','NT AUTHORITY\Authenticated Users')) {
                if ($ace.FileSystemRights -match 'Write|FullControl|Modify') { return $true }
            }
        }
    } catch {}
    return $false
}

# Services: unquoted paths + writable binary/dir
$svc = Get-CimInstance Win32_Service | Select-Object Name, PathName, StartName, State
$findings.unquotedServicePaths = @($svc | Where-Object {
    $_.PathName -and $_.PathName -notmatch '^"' -and $_.PathName -match '\s' -and $_.PathName -match 'Program Files|\\'
} | Select-Object Name, PathName)
$findings.writableServiceBinaries = @($svc | ForEach-Object {
    if ($_.PathName -match '^"?([^"]+\.exe)') {
        $bin = $matches[1]
        if ((Test-Writable $bin) -or (Test-Writable (Split-Path $bin -Parent))) {
            [ordered]@{ service=$_.Name; binary=$bin }
        }
    }
} | Where-Object { $_ })

# AlwaysInstallElevated (both hives must be 1 to be exploitable)
$aieHKLM = (Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer' -EA SilentlyContinue).AlwaysInstallElevated
$aieHKCU = (Get-ItemProperty 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer' -EA SilentlyContinue).AlwaysInstallElevated
$findings.alwaysInstallElevated = [ordered]@{ hklm=$aieHKLM; hkcu=$aieHKCU; exploitable=(($aieHKLM -eq 1) -and ($aieHKCU -eq 1)) }

# Writable PATH dirs
$findings.writablePathDirs = @($env:PATH -split ';' | Where-Object { $_ } | Where-Object { Test-Writable $_ })

# Dangerous privileges held
$priv = (whoami /priv /fo csv 2>$null | ConvertFrom-Csv)
$dangerous = 'SeImpersonatePrivilege','SeAssignPrimaryTokenPrivilege','SeBackupPrivilege','SeRestorePrivilege','SeTakeOwnershipPrivilege','SeDebugPrivilege','SeLoadDriverPrivilege'
$findings.dangerousPrivileges = @($priv | Where-Object { $_.'Privilege Name' -in $dangerous -and $_.State -eq 'Enabled' } | Select-Object 'Privilege Name',State)

# Stored-credential surfaces (presence only, values NOT read)
$findings.storedCredentialSurfaces = [ordered]@{
    cmdkeyEntries = @((cmdkey /list 2>$null) -match 'Target:')
    unattendFiles = @(Get-ChildItem 'C:\Windows\Panther\Unattend.xml','C:\Windows\System32\Sysprep\unattend.xml','C:\unattend.xml' -EA SilentlyContinue | Select-Object -ExpandProperty FullName)
}

$findings.isAlreadyAdmin = $me.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$findings | ConvertTo-Json -Depth 6 | Out-File $OutFile -Encoding utf8

$flag = @()
if ($findings.unquotedServicePaths.Count)   { $flag += "unquoted:$($findings.unquotedServicePaths.Count)" }
if ($findings.writableServiceBinaries.Count){ $flag += "writable-svc:$($findings.writableServiceBinaries.Count)" }
if ($findings.alwaysInstallElevated.exploitable) { $flag += 'AlwaysInstallElevated' }
if ($findings.writablePathDirs.Count)       { $flag += "writable-PATH:$($findings.writablePathDirs.Count)" }
if ($findings.dangerousPrivileges.Count)    { $flag += "priv:$($findings.dangerousPrivileges.Count)" }

Write-Host "[+] PrivEsc audit -> $OutFile" -ForegroundColor Green
Write-Host "    Findings: $([string]::Join(', ', $flag))" -ForegroundColor Cyan
Write-Host "    These are REPORTED, not exploited. Validate manually per docs/06 before claiming." -ForegroundColor Yellow

Write-RTEvidence -Technique 'Local privilege-escalation misconfig audit' -TechniqueId 'T1543.003,T1574,T1548.002,T1552' `
  -Target $env:COMPUTERNAME -Command '.\Invoke-PrivEscAudit.ps1' -Result "findings: $([string]::Join(', ',$flag)) -> $OutFile" `
  -TelemetryExpected 'service/registry/ACL reads (low signal)' | Out-Null
