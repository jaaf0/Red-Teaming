<#
.SYNOPSIS
  Invoke-SmbEnum - read-only SMB security-posture enumeration ("NetExec"-style, enumeration ONLY).
.DESCRIPTION
  The SAFE, read-only enumeration subset of tools like NetExec/CrackMapExec. For each
  in-scope target it checks the SMB posture an attacker would fingerprint, and that a
  defender should fix (ATT&CK context T1135/T1018/T1021.002):
    - TCP 445 reachability
    - Null/anonymous session allowed (single empty-credential connect - NOT password guessing)
    - Anonymous share listing (if the null session is permitted)
    - For the local host (or -IncludeLocalConfig): SMBv1 enabled, SMB signing required,
      via Get-SmbServerConfiguration (authoritative, read-only)

  DELIBERATELY NOT DONE (see scripts/README "Deliberately NOT in this toolkit"):
    - password spraying / credentialed login attempts of any kind
    - credentialed command execution (--exec), hash dumping (--sam/--lsa), pass-the-hash
  Those are approval-gated and use authorized, signed tooling under ROE - not this script.
.EXAMPLE
  .\Invoke-SmbEnum.ps1 -Targets dc01,fs01 -OutFile smbenum.json
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string[]]$Targets,
    [int]$TimeoutMs = 1000,
    [switch]$IncludeLocalConfig,
    [string]$OutFile = "smbenum.json"
)
Import-Module "$PSScriptRoot/RTSafety.psm1" -Force
$scope = Import-RTScope

function Test-Port([string]$h,[int]$p,[int]$t){
    $c = New-Object System.Net.Sockets.TcpClient
    try { $ar=$c.BeginConnect($h,$p,$null,$null); return ($ar.AsyncWaitHandle.WaitOne($t) -and $c.Connected) }
    catch { return $false } finally { $c.Close() }
}

$localNames = @($env:COMPUTERNAME, 'localhost', '127.0.0.1', '.')

$results = foreach ($t in $Targets) {
    if (-not (Test-RTScope -Target $t -Scope $scope)) { continue }
    $o = [ordered]@{ target = $t; smbReachable = (Test-Port $t 445 $TimeoutMs) }

    if ($o.smbReachable) {
        # single anonymous (empty-credential) connect - a posture check, not a guess
        $o.nullSession = $false
        $null = net use "\\$t\IPC$" '""' /user:'""' 2>$null
        if ($LASTEXITCODE -eq 0) {
            $o.nullSession = $true
            $o.anonymousShares = @((net view "\\$t" /all 2>$null) | Where-Object { $_ -match '\bDisk\b|\bIPC\b' })
            net use "\\$t\IPC$" /delete 2>$null | Out-Null
        }
    }

    # authoritative local SMB server config (self only)
    if (($t -in $localNames) -or ($IncludeLocalConfig -and ($t -eq $env:COMPUTERNAME))) {
        try {
            $cfg = Get-SmbServerConfiguration -ErrorAction Stop
            $o.localSmbConfig = [ordered]@{
                smb1Enabled            = $cfg.EnableSMB1Protocol
                requireSecuritySigning = $cfg.RequireSecuritySigning
                enableSecuritySignature= $cfg.EnableSecuritySignature
            }
        } catch { $o.localSmbConfig = 'unavailable (not local / insufficient rights)' }
    }

    Write-Host ("[+] {0,-22} 445:{1,-6} null-session:{2}" -f $t,$o.smbReachable,$o.nullSession) -ForegroundColor Green
    $o
}

@($results) | ConvertTo-Json -Depth 6 | Out-File -LiteralPath $OutFile -Encoding utf8

$reachable = @($results | Where-Object { $_.smbReachable }).Count
$nullSess  = @($results | Where-Object { $_.nullSession }).Count
Write-Host "[+] SMB enum -> $OutFile  (reachable:$reachable  null-session:$nullSess)" -ForegroundColor Cyan
Write-Host "    Enumeration only. No credentials were supplied, guessed, or sprayed." -ForegroundColor Yellow

Write-RTEvidence -Technique 'SMB security-posture enumeration' -TechniqueId 'T1135,T1018,T1021.002' `
  -Target ($Targets -join ',') -Command '.\Invoke-SmbEnum.ps1' `
  -Result "reachable=$reachable null-session=$nullSess -> $OutFile" `
  -Impact 'none (read-only enumeration; single anonymous connect per host)' `
  -TelemetryExpected 'SMB session setup attempts; anonymous IPC$ connects (5140/5145)' | Out-Null
