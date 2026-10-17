<#
.SYNOPSIS
  RTSafety - the Global Safety Controller and evidence pipeline as a PowerShell module.
  Custom, dependency-free. Import this first; every operator script below uses it.
.NOTES
  Authorized engagements only. Reads config/scope.yaml + exclusions.yaml.
  All operator scripts call Test-RTScope before acting and Write-RTEvidence after.
#>

# --- minimal YAML-ish loader (flat lists under in_scope/never_touch) ---
function Import-RTScope {
    [CmdletBinding()]
    param(
        [string]$ScopePath       = "$PSScriptRoot/../config/scope.yaml",
        [string]$ExclusionsPath  = "$PSScriptRoot/../config/exclusions.yaml"
    )
    function Read-ListBlock($lines, $header) {
        # returns array values from a `key: [a, b]` line or an indented block list
        $out = @()
        for ($i=0; $i -lt $lines.Count; $i++) {
            if ($lines[$i] -match "^\s*$header\s*:\s*\[(.*)\]\s*$") {
                $out += ($matches[1] -split ',') | ForEach-Object { $_.Trim(' "''') } | Where-Object { $_ }
            }
        }
        return $out
    }
    $scopeLines = Get-Content -LiteralPath $ScopePath -ErrorAction Stop
    $exclLines  = Get-Content -LiteralPath $ExclusionsPath -ErrorAction SilentlyContinue
    [pscustomobject]@{
        InScopeHosts   = Read-ListBlock $scopeLines 'hosts'
        InScopeCidrs   = Read-ListBlock $scopeLines 'cidrs'
        InScopeDomains = Read-ListBlock $scopeLines 'domains'
        ExcludeHosts   = Read-ListBlock $exclLines  'hosts'
        ExcludeCidrs   = Read-ListBlock $exclLines  'cidrs'
        ExcludeDomains = Read-ListBlock $exclLines  'domains'
    }
}

function Test-RTIpInCidr {
    param([string]$Ip, [string]$Cidr)
    if ($Cidr -notmatch '^(.+)/(\d+)$') { return $false }
    try {
        $net  = [System.Net.IPAddress]::Parse($matches[1])
        $bits = [int]$matches[2]
        $addr = [System.Net.IPAddress]::Parse($Ip)
        if ($net.AddressFamily -ne $addr.AddressFamily) { return $false }
        $nb = $net.GetAddressBytes(); $ab = $addr.GetAddressBytes()
        $full = [math]::Floor($bits/8); $rem = $bits % 8
        for ($i=0;$i -lt $full;$i++){ if ($nb[$i] -ne $ab[$i]) { return $false } }
        if ($rem -gt 0) {
            $mask = [byte](0xFF -shl (8-$rem) -band 0xFF)
            if (($nb[$full] -band $mask) -ne ($ab[$full] -band $mask)) { return $false }
        }
        return $true
    } catch { return $false }
}

function Test-RTScope {
<#  Returns $true only if the target is in scope AND not excluded. Fail-closed. #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Target,   # host name or IP
        [object]$Scope = (Import-RTScope)
    )
    $isIp = [System.Net.IPAddress]::TryParse($Target, [ref]([System.Net.IPAddress]$null))

    # 1) exclusions win
    if ($Scope.ExcludeHosts -contains $Target) { Write-Warning "BLOCKED: $Target is excluded."; return $false }
    foreach ($d in $Scope.ExcludeDomains) { if ($Target -like "*$d") { Write-Warning "BLOCKED: $Target in excluded domain $d."; return $false } }
    if ($isIp) { foreach ($c in $Scope.ExcludeCidrs) { if (Test-RTIpInCidr $Target $c) { Write-Warning "BLOCKED: $Target in excluded $c."; return $false } } }

    # 2) must be included
    if ($Scope.InScopeHosts -contains $Target) { return $true }
    foreach ($d in $Scope.InScopeDomains) { if ($Target -like "*$($d.TrimStart('*.'))") { return $true } }
    if ($isIp) { foreach ($c in $Scope.InScopeCidrs) { if (Test-RTIpInCidr $Target $c) { return $true } } }

    Write-Warning "BLOCKED: $Target is not in scope."
    return $false
}

function Assert-RTApproval {
<#  Hard gate for approval-required techniques. Refuses unless -Approved passed with a ticket id. #>
    param([Parameter(Mandatory)][string]$Technique, [string]$ApprovalRef)
    if (-not $ApprovalRef) { throw "STOP: '$Technique' requires explicit approval. Re-run with -ApprovalRef <ticket>." }
    Write-Host "[approval] $Technique authorized under $ApprovalRef" -ForegroundColor Yellow
}

function Write-RTEvidence {
<#  Append one structured evidence record (JSON lines) matching docs/23 schema. #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Technique,
        [Parameter(Mandatory)][string]$TechniqueId,
        [Parameter(Mandatory)][string]$Target,
        [string]$Tool = $MyInvocation.MyCommand.Name,
        [string]$Command,
        [string]$Result,
        [string]$Impact = 'none (read-only)',
        [string]$TelemetryExpected,
        [bool]$CleanupRequired = $false,
        [string]$EvidenceDir = "$PSScriptRoot/../../output/evidence/$(Get-Date -Format yyyy-MM-dd)"
    )
    New-Item -ItemType Directory -Force -Path $EvidenceDir | Out-Null
    $rec = [ordered]@{
        timestamp          = (Get-Date).ToUniversalTime().ToString('o')
        operator           = $env:USERNAME
        source_host        = $env:COMPUTERNAME
        target             = $Target
        technique          = $Technique
        technique_id       = $TechniqueId
        tool               = $Tool
        command            = $Command
        result             = $Result
        impact             = $Impact
        telemetry_expected = $TelemetryExpected
        telemetry_observed = 'pending'
        cleanup_required   = $CleanupRequired
    }
    $line = ($rec | ConvertTo-Json -Compress)
    Add-Content -LiteralPath (Join-Path $EvidenceDir 'attacklog.jsonl') -Value $line
    Write-Verbose "evidence recorded -> $EvidenceDir/attacklog.jsonl"
    return $rec
}

Export-ModuleMember -Function Import-RTScope,Test-RTScope,Test-RTIpInCidr,Assert-RTApproval,Write-RTEvidence
