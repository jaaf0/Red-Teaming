<#
.SYNOPSIS
  Invoke-DomainRecon - custom, read-only Active Directory discovery via native .NET LDAP.
  No ActiveDirectory module, no community tooling. Read-only LDAP queries only.
.DESCRIPTION
  Enumerates users, groups, computers, OUs, privileged-group membership, and domain trusts
  using System.DirectoryServices (DirectorySearcher). ATT&CK T1087.002/T1069.002/T1018/T1482.
  Honours scope: the domain must match config/scope.yaml. Entirely read-only.
.EXAMPLE
  .\Invoke-DomainRecon.ps1 -Domain corp.example.com -OutFile domain.json
#>
[CmdletBinding()]
param(
    [string]$Domain,                       # defaults to current machine domain
    [int]$MaxResults = 2000,
    [string]$OutFile = "domainrecon.json"
)

Import-Module "$PSScriptRoot/RTSafety.psm1" -Force

if (-not $Domain) { $Domain = (Get-CimInstance Win32_ComputerSystem).Domain }
if (-not (Test-RTScope -Target $Domain)) { throw "Domain $Domain failed scope check." }

function New-Searcher {
    param([string]$Filter, [string[]]$Props)
    $root = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$Domain")
    $ds = New-Object System.DirectoryServices.DirectorySearcher($root)
    $ds.Filter = $Filter
    $ds.PageSize = 1000
    $ds.SizeLimit = $MaxResults
    foreach ($p in $Props) { [void]$ds.PropertiesToLoad.Add($p) }
    return $ds
}
function Get-Prop { param($res,$name) if ($res.Properties[$name].Count) { $res.Properties[$name][0] } else { $null } }

$out = [ordered]@{ domain = $Domain; collectedUtc = (Get-Date).ToUniversalTime().ToString('o') }

# Users (read-only) - do NOT read password attributes
$u = New-Searcher '(&(objectCategory=person)(objectClass=user))' @('samaccountname','displayname','useraccountcontrol','serviceprincipalname','memberof','lastlogontimestamp')
$out.users = $u.FindAll() | ForEach-Object {
    [ordered]@{
        sam  = Get-Prop $_ 'samaccountname'
        name = Get-Prop $_ 'displayname'
        uac  = Get-Prop $_ 'useraccountcontrol'
        spn  = @($_.Properties['serviceprincipalname'])      # SPN presence = Kerberoast candidate (flag only)
        asrep = (([int](Get-Prop $_ 'useraccountcontrol')) -band 0x400000) -ne 0   # DONT_REQ_PREAUTH
    }
}

# Groups + privileged membership
$g = New-Searcher '(objectCategory=group)' @('samaccountname','member')
$out.groups = $g.FindAll() | ForEach-Object { [ordered]@{ sam = Get-Prop $_ 'samaccountname'; members = @($_.Properties['member']).Count } }

$priv = New-Searcher '(&(objectCategory=group)(|(samaccountname=Domain Admins)(samaccountname=Enterprise Admins)(samaccountname=Administrators)))' @('samaccountname','member')
$out.privilegedGroups = $priv.FindAll() | ForEach-Object { [ordered]@{ group = Get-Prop $_ 'samaccountname'; members = @($_.Properties['member']) } }

# Computers (inventory -> potential targets, flagged not touched)
$c = New-Searcher '(objectCategory=computer)' @('dnshostname','operatingsystem')
$out.computers = $c.FindAll() | ForEach-Object { [ordered]@{ host = Get-Prop $_ 'dnshostname'; os = Get-Prop $_ 'operatingsystem' } }

# OUs
$o = New-Searcher '(objectCategory=organizationalUnit)' @('ou','distinguishedname')
$out.ous = $o.FindAll() | ForEach-Object { Get-Prop $_ 'distinguishedname' }

# Trusts - T1482 (read-only)
$t = New-Searcher '(objectClass=trustedDomain)' @('trustpartner','trustdirection','trusttype')
$out.trusts = $t.FindAll() | ForEach-Object { [ordered]@{ partner = Get-Prop $_ 'trustpartner'; direction = Get-Prop $_ 'trustdirection'; type = Get-Prop $_ 'trusttype' } }

# Analyst hints (flags only - no action taken)
$out.hints = [ordered]@{
    kerberoastCandidates = @($out.users | Where-Object { $_.spn.Count -gt 0 } | ForEach-Object { $_.sam })
    asrepCandidates      = @($out.users | Where-Object { $_.asrep } | ForEach-Object { $_.sam })
}

$out | ConvertTo-Json -Depth 8 | Out-File -LiteralPath $OutFile -Encoding utf8

Write-RTEvidence -Technique 'AD discovery (users/groups/computers/trusts)' -TechniqueId 'T1087.002,T1069.002,T1018,T1482' `
    -Target $Domain -Command ".\Invoke-DomainRecon.ps1 -Domain $Domain" `
    -Result "collected -> $OutFile ; kerberoast=$($out.hints.kerberoastCandidates.Count) asrep=$($out.hints.asrepCandidates.Count)" `
    -TelemetryExpected 'LDAP query volume / AD recon burst' | Out-Null

Write-Host "[+] Domain recon written to $OutFile (read-only LDAP)." -ForegroundColor Green
Write-Host "    Kerberoast candidates: $($out.hints.kerberoastCandidates.Count) | AS-REP candidates: $($out.hints.asrepCandidates.Count)" -ForegroundColor Cyan
Write-Host "    NOTE: roasting/cracking those is an approval-gated step - use authorized tooling, not this script." -ForegroundColor Yellow
