<#
.SYNOPSIS
  Invoke-EgressRecon - read-only outbound EGRESS-PATH recon for exfiltration feasibility.
  Tests which outbound channels are reachable from a host. Moves NO data out.
.DESCRIPTION
  An exfil operator first needs to know which egress channels are open. This maps that,
  for the client to understand their containment posture (ATT&CK context TA0010/T1046).
  It only measures reachability to an OPERATOR-CONTROLLED, in-scope test endpoint:
    - direct TCP to common egress ports (443/80/53/22) to your test collector
    - whether a proxy is configured, and whether it is required
    - external DNS resolution capability
  It sends NO engagement data - at most a fixed benign token "EGRESS-RECON-PROBE".
  Use it to prove "channel X is open/closed", then test DLP separately with canary data
  via docs/10 under approval. Nothing real leaves the network.
.EXAMPLE
  .\Invoke-EgressRecon.ps1 -Collector test-collector.redteam.lab -OutFile egress.json
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Collector,   # YOUR in-scope test endpoint only
    [int[]]$Ports = @(443,80,53,22),
    [int]$TimeoutMs = 1500,
    [string]$OutFile = "egressrecon.json"
)
Import-Module "$PSScriptRoot/RTSafety.psm1" -Force
if (-not (Test-RTScope -Target $Collector)) { throw "Collector $Collector must be an in-scope test endpoint." }

function Test-Port([string]$h,[int]$p,[int]$t){
    $c = New-Object System.Net.Sockets.TcpClient
    try { $ar=$c.BeginConnect($h,$p,$null,$null); return ($ar.AsyncWaitHandle.WaitOne($t) -and $c.Connected) }
    catch { return $false } finally { $c.Close() }
}

$out = [ordered]@{ host=$env:COMPUTERNAME; collector=$Collector; collectedUtc=(Get-Date).ToUniversalTime().ToString('o') }

# 1) direct outbound reachability per port (connection only; no payload)
$out.directPorts = [ordered]@{}
foreach ($p in $Ports) { $out.directPorts["$p"] = Test-Port $Collector $p $TimeoutMs }

# 2) proxy configuration (read-only)
$out.proxy = [ordered]@{
    winHttp = (netsh winhttp show proxy 2>$null) -join '; '
    userIE  = (Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -EA SilentlyContinue |
               Select-Object ProxyEnable, ProxyServer)
}

# 3) external DNS resolution capability (does egress via DNS resolve at all)
try { $out.externalDnsResolves = [bool](Resolve-DnsName -Name $Collector -Type A -ErrorAction Stop) }
catch { $out.externalDnsResolves = $false }

# 4) single benign reachability probe over 443 if open (fixed token, NOT engagement data)
$out.httpsProbe = 'not-attempted'
if ($out.directPorts['443']) {
    try {
        $body = 'EGRESS-RECON-PROBE'
        $r = Invoke-WebRequest -Uri "https://$Collector/__egress_probe" -Method POST -Body $body -TimeoutSec 5 -UseBasicParsing -ErrorAction Stop
        $out.httpsProbe = "reachable (HTTP $($r.StatusCode))"
    } catch { $out.httpsProbe = "attempted; $($_.Exception.Message)" }
}

$open = @($out.directPorts.GetEnumerator() | Where-Object { $_.Value } | ForEach-Object { $_.Key })
$out | ConvertTo-Json -Depth 6 | Out-File $OutFile -Encoding utf8

Write-Host "[+] Egress recon -> $OutFile" -ForegroundColor Green
Write-Host "    Open outbound ports to collector: $([string]::Join(',', $open))" -ForegroundColor Cyan
Write-Host "    No engagement data was transmitted. For DLP testing use canary data (docs/10) under approval." -ForegroundColor Yellow

Write-RTEvidence -Technique 'Egress-path feasibility recon' -TechniqueId 'TA0010,T1046' `
  -Target $Collector -Command ".\Invoke-EgressRecon.ps1 -Collector $Collector" `
  -Result "open egress ports: $([string]::Join(',',$open)); dns:$($out.externalDnsResolves)" `
  -Impact 'none (reachability probe only, no data moved)' `
  -TelemetryExpected 'outbound conn to new host; proxy/DLP logs; DNS to external' | Out-Null
