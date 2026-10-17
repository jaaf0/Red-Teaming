<#
.SYNOPSIS
  Invoke-LateralRecon - read-only lateral-movement exposure recon (ATT&CK T1046, T1021.x, T1135).
.DESCRIPTION
  For each in-scope target: TCP-connect check on remote-admin ports (SMB 445, RDP 3389,
  WinRM 5985/5986, SSH 22, RPC 135) and whether the CURRENT token can list ADMIN$/C$
  (= local-admin indicator). No commands are executed on targets, no credentials are
  supplied or guessed. Output = a lateral-movement candidate map for the attack graph.
.EXAMPLE
  .\Invoke-LateralRecon.ps1 -Targets (Get-Content hosts.txt) -OutFile lateral.json
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string[]]$Targets,
    [int]$TimeoutMs = 800,
    [string]$OutFile = "lateralrecon.json"
)
Import-Module "$PSScriptRoot/RTSafety.psm1" -Force
$scope = Import-RTScope
$ports = [ordered]@{ SMB=445; RDP=3389; WinRM_HTTP=5985; WinRM_HTTPS=5986; SSH=22; RPC=135 }

function Test-Port([string]$h,[int]$p,[int]$t) {
    $c = New-Object System.Net.Sockets.TcpClient
    try { $ar = $c.BeginConnect($h,$p,$null,$null); $ok = $ar.AsyncWaitHandle.WaitOne($t) -and $c.Connected; return [bool]$ok }
    catch { return $false } finally { $c.Close() }
}

$results = foreach ($t in $Targets) {
    if (-not (Test-RTScope -Target $t -Scope $scope)) { continue }
    $open = [ordered]@{}; foreach ($k in $ports.Keys) { $open[$k] = Test-Port $t $ports[$k] $TimeoutMs }
    $adminShare = $false
    if ($open.SMB) { try { $null = Get-ChildItem "\\$t\ADMIN$" -ErrorAction Stop | Select-Object -First 1; $adminShare = $true } catch {} }
    $methods = @()
    if ($adminShare)                         { $methods += 'SMB/admin-share (current token is local admin)' }
    if ($open.WinRM_HTTP -or $open.WinRM_HTTPS) { $methods += 'WinRM (needs creds w/ remote-mgmt rights)' }
    if ($open.RDP)                           { $methods += 'RDP (needs RDP-allowed creds)' }
    if ($open.SSH)                           { $methods += 'SSH' }
    [ordered]@{ target=$t; open=$open; currentTokenAdmin=$adminShare; candidateMethods=$methods }
    Write-Host ("[+] {0,-25} admin:{1,-5} methods: {2}" -f $t,$adminShare,($methods -join '; ')) -ForegroundColor Green
}
$results | ConvertTo-Json -Depth 5 | Out-File $OutFile -Encoding utf8
Write-RTEvidence -Technique 'Lateral-movement exposure recon' -TechniqueId 'T1046,T1021,T1135' `
  -Target ($Targets -join ',') -Command '.\Invoke-LateralRecon.ps1' `
  -Result "$(@($results).Count) host(s); admin-on: $(@($results|?{$_.currentTokenAdmin}).Count) -> $OutFile" `
  -TelemetryExpected 'connection attempts to 445/3389/5985; ADMIN$ access (5140)' | Out-Null
