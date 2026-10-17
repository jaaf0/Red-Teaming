<#
.SYNOPSIS
  Invoke-AdGraphCollect - read-only AD graph collector ("SharpHound"-style), native .NET LDAP.
  Emits a nodes+edges JSON for offline attack-path analysis by Analyze-AdGraph.ps1.
.DESCRIPTION
  Collects the graph an attacker (and defender) cares about - entirely read-only LDAP
  (ATT&CK context T1087.002/T1069.002/T1482). No writes, no secrets, no community tooling.
  Nodes:  users, groups, computers (by samAccountName / name).
  Edges:
    - MemberOf        principal  -> group            (group membership)
    - GenericAll / GenericWrite / WriteDacl / WriteOwner
                      principal  -> object           (ACL-derived control, "owns")
    - AllowedToDelegate computer/user -> target      (constrained delegation)
  The output is a graph, not an action. Analysis is done offline by Analyze-AdGraph.ps1.
.EXAMPLE
  .\Invoke-AdGraphCollect.ps1 -Domain corp.example.com -OutFile adgraph.json
#>
[CmdletBinding()]
param(
    [string]$Domain,
    [int]$MaxResults = 10000,
    [string]$OutFile = "adgraph.json"
)
Import-Module "$PSScriptRoot/RTSafety.psm1" -Force

if (-not $Domain) { $Domain = (Get-CimInstance Win32_ComputerSystem).Domain }
if (-not (Test-RTScope -Target $Domain)) { throw "Domain $Domain failed scope check." }

function New-Searcher {
    param([string]$Filter, [string[]]$Props, [switch]$WithSecurity)
    $root = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$Domain")
    $ds = New-Object System.DirectoryServices.DirectorySearcher($root)
    $ds.Filter = $Filter; $ds.PageSize = 1000; $ds.SizeLimit = $MaxResults
    if ($WithSecurity) { $ds.SecurityMasks = [System.DirectoryServices.SecurityMasks]::Dacl }
    foreach ($p in $Props) { [void]$ds.PropertiesToLoad.Add($p) }
    return $ds
}
function Get-Prop { param($res,$name) if ($res.Properties[$name].Count) { $res.Properties[$name][0] } else { $null } }

$nodes = [System.Collections.Generic.List[object]]::new()
$edges = [System.Collections.Generic.List[object]]::new()
$dnToName = @{}   # distinguishedName -> samAccountName/name, to resolve member/memberof links

# --- collect principals (users, groups, computers) ---
$princ = New-Searcher '(|(objectCategory=user)(objectCategory=group)(objectCategory=computer))' `
         @('samaccountname','distinguishedname','objectclass','memberof','msds-allowedtodelegateto','name')
$records = @($princ.FindAll())
foreach ($r in $records) {
    $dn   = Get-Prop $r 'distinguishedname'
    $sam  = (Get-Prop $r 'samaccountname'); if (-not $sam) { $sam = Get-Prop $r 'name' }
    $classes = @($r.Properties['objectclass'])
    $type = if ($classes -contains 'computer') { 'Computer' } elseif ($classes -contains 'group') { 'Group' } else { 'User' }
    if ($dn) { $dnToName[$dn] = $sam }
    $nodes.Add([ordered]@{ name = $sam; type = $type; dn = $dn })
}

# --- MemberOf + delegation edges (second pass so DN->name is resolvable) ---
foreach ($r in $records) {
    $sam = (Get-Prop $r 'samaccountname'); if (-not $sam) { $sam = Get-Prop $r 'name' }
    foreach ($grpDn in $r.Properties['memberof']) {
        $grp = $dnToName[$grpDn]; if (-not $grp) { $grp = ($grpDn -split ',')[0] -replace '^CN=','' }
        $edges.Add([ordered]@{ from = $sam; to = $grp; type = 'MemberOf' })
    }
    foreach ($to in $r.Properties['msds-allowedtodelegateto']) {
        $edges.Add([ordered]@{ from = $sam; to = "$to"; type = 'AllowedToDelegate' })
    }
}

# --- ACL-derived control edges ---
$builtins = 'NT AUTHORITY\SYSTEM','BUILTIN\Administrators','Domain Admins','Enterprise Admins',
            'NT AUTHORITY\SELF','CREATOR OWNER','Enterprise Domain Controllers'
$aclRights = 'GenericAll','GenericWrite','WriteDacl','WriteOwner'
$aclTargets = New-Searcher '(|(objectCategory=user)(objectCategory=group)(objectCategory=computer))' `
              @('samaccountname','name') -WithSecurity
foreach ($r in $aclTargets.FindAll()) {
    $obj = (Get-Prop $r 'samaccountname'); if (-not $obj) { $obj = Get-Prop $r 'name' }
    try {
        $de = $r.GetDirectoryEntry()
        foreach ($ace in $de.ObjectSecurity.GetAccessRules($true,$true,[System.Security.Principal.NTAccount])) {
            if ($ace.AccessControlType -ne 'Allow') { continue }
            $idn = ($ace.IdentityReference.Value -split '\\')[-1]
            if ($builtins | Where-Object { $ace.IdentityReference.Value -like "*$_" }) { continue }
            $rights = $ace.ActiveDirectoryRights.ToString()
            foreach ($rr in $aclRights) {
                if ($rights -match $rr) { $edges.Add([ordered]@{ from = $idn; to = $obj; type = $rr }); break }
            }
        }
    } catch {}
}

$graph = [ordered]@{
    domain       = $Domain
    collectedUtc = (Get-Date).ToUniversalTime().ToString('o')
    stats        = [ordered]@{ nodes = $nodes.Count; edges = $edges.Count }
    nodes        = $nodes
    edges        = $edges
}
$graph | ConvertTo-Json -Depth 8 | Out-File -LiteralPath $OutFile -Encoding utf8

Write-Host "[+] AD graph collected -> $OutFile (read-only LDAP)" -ForegroundColor Green
Write-Host "    nodes=$($nodes.Count) edges=$($edges.Count). Analyse offline: .\Analyze-AdGraph.ps1 -GraphFile $OutFile" -ForegroundColor Cyan

Write-RTEvidence -Technique 'AD graph collection for attack-path analysis' -TechniqueId 'T1087.002,T1069.002,T1482' `
  -Target $Domain -Command ".\Invoke-AdGraphCollect.ps1 -Domain $Domain" `
  -Result "nodes=$($nodes.Count) edges=$($edges.Count) -> $OutFile" `
  -TelemetryExpected 'high LDAP query volume; DACL reads (AD recon burst)' | Out-Null
