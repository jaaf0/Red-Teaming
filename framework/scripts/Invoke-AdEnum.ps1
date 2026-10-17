<#
.SYNOPSIS
  Invoke-AdEnum - read-only "PowerView-style" Active Directory enumeration via native .NET LDAP.
  Deep enumeration of the abuse-relevant objects: delegation, risky ACLs, GPOs, policy.
.DESCRIPTION
  Complements Invoke-DomainRecon with the attack-path-relevant attributes, all read-only
  (ATT&CK context T1087.002/T1069.002/T1482/T1207). No ActiveDirectory module, no community
  tooling, no writes. It IDENTIFIES abusable conditions; it does not abuse them:
    - Kerberos delegation: unconstrained (TRUSTED_FOR_DELEGATION), constrained
      (msDS-AllowedToDelegateTo), and RBCD (msDS-AllowedToActOnBehalfOfOtherIdentity present)
    - Risky object ACLs: GenericAll/GenericWrite/WriteDacl/WriteOwner/AllExtendedRights
      granted to non-default principals on users/groups/computers
    - GPOs (names + gPCFileSysPath) and where they are linked
    - Domain password policy (from domain root attributes)
    - Accounts with SPNs (Kerberoastable) and DONT_REQ_PREAUTH (AS-REP-roastable) - flag only
    - Computers with LAPS (ms-Mcs-AdmPwdExpirationTime present) - presence, value NOT read
.EXAMPLE
  .\Invoke-AdEnum.ps1 -Domain corp.example.com -OutFile adenum.json
#>
[CmdletBinding()]
param(
    [string]$Domain,
    [int]$MaxResults = 5000,
    [string]$OutFile = "adenum.json"
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

# default/built-in principals we don't flag as "interesting" ACL grantees
$builtins = 'NT AUTHORITY\SYSTEM','BUILTIN\Administrators','Domain Admins','Enterprise Admins',
            'NT AUTHORITY\SELF','CREATOR OWNER','Enterprise Domain Controllers','Everyone','BUILTIN\Account Operators'
$riskyRights = 'GenericAll','GenericWrite','WriteDacl','WriteOwner','WriteProperty','ExtendedRight'

$out = [ordered]@{ domain = $Domain; collectedUtc = (Get-Date).ToUniversalTime().ToString('o') }

# --- Delegation ---
$delProps = @('samaccountname','useraccountcontrol','msds-allowedtodelegateto',
              'msds-allowedtoactonbehalfofotheridentity','dnshostname')
$dsAll = New-Searcher '(|(objectCategory=user)(objectCategory=computer))' $delProps -WithSecurity
$unconstrained = @(); $constrained = @(); $rbcd = @()
foreach ($r in $dsAll.FindAll()) {
    $sam = Get-Prop $r 'samaccountname'
    $uac = [int](Get-Prop $r 'useraccountcontrol')
    if ($uac -band 0x80000) { $unconstrained += $sam }                       # TRUSTED_FOR_DELEGATION
    if ($r.Properties['msds-allowedtodelegateto'].Count) {
        $constrained += [ordered]@{ principal=$sam; to=@($r.Properties['msds-allowedtodelegateto']) }
    }
    if ($r.Properties['msds-allowedtoactonbehalfofotheridentity'].Count) { $rbcd += $sam }
}
$out.delegation = [ordered]@{ unconstrained=$unconstrained; constrained=$constrained; resourceBased=$rbcd }

# --- Risky ACLs on principals (read DACLs, report non-default grantees of risky rights) ---
$aclTargets = New-Searcher '(|(objectCategory=user)(objectCategory=group)(objectCategory=computer))' @('samaccountname','distinguishedname') -WithSecurity
$riskyAcls = @()
foreach ($r in $aclTargets.FindAll()) {
    $de = $r.GetDirectoryEntry()
    try {
        foreach ($ace in $de.ObjectSecurity.GetAccessRules($true,$true,[System.Security.Principal.NTAccount])) {
            if ($ace.AccessControlType -ne 'Allow') { continue }
            $idn = $ace.IdentityReference.Value
            if ($builtins | Where-Object { $idn -like "*$_" }) { continue }
            $rights = $ace.ActiveDirectoryRights.ToString()
            if ($riskyRights | Where-Object { $rights -match $_ }) {
                $riskyAcls += [ordered]@{ object = (Get-Prop $r 'samaccountname'); principal = $idn; rights = $rights }
            }
        }
    } catch {}
}
$out.riskyAcls = $riskyAcls

# --- GPOs ---
$gpo = New-Searcher '(objectCategory=groupPolicyContainer)' @('displayname','gpcfilesyspath','cn')
$out.gpos = $gpo.FindAll() | ForEach-Object { [ordered]@{ name = Get-Prop $_ 'displayname'; path = Get-Prop $_ 'gpcfilesyspath' } }

# --- Password policy (domain root) ---
try {
    $rootDe = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$Domain")
    $out.passwordPolicy = [ordered]@{
        minPwdLength     = [int]$rootDe.Properties['minPwdLength'].Value
        lockoutThreshold = [int]$rootDe.Properties['lockoutThreshold'].Value
        maxPwdAgeTicks   = "$($rootDe.Properties['maxPwdAge'].Value)"
    }
} catch { $out.passwordPolicy = 'unavailable' }

# --- LAPS presence (value never read) ---
$laps = New-Searcher '(ms-Mcs-AdmPwdExpirationTime=*)' @('dnshostname','cn')
$out.lapsManagedComputers = @($laps.FindAll() | ForEach-Object { Get-Prop $_ 'cn' })

# --- Roastable (flag only) ---
$spn = New-Searcher '(&(objectCategory=person)(objectClass=user)(servicePrincipalName=*))' @('samaccountname')
$out.kerberoastable = @($spn.FindAll() | ForEach-Object { Get-Prop $_ 'samaccountname' })
$asrep = New-Searcher '(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))' @('samaccountname')
$out.asrepRoastable = @($asrep.FindAll() | ForEach-Object { Get-Prop $_ 'samaccountname' })

$out | ConvertTo-Json -Depth 8 | Out-File -LiteralPath $OutFile -Encoding utf8

Write-Host "[+] AD enumeration -> $OutFile (read-only LDAP)" -ForegroundColor Green
Write-Host ("    unconstrained:{0} rbcd:{1} riskyACLs:{2} GPOs:{3} kerberoastable:{4}" -f `
    $unconstrained.Count,$rbcd.Count,$riskyAcls.Count,@($out.gpos).Count,$out.kerberoastable.Count) -ForegroundColor Cyan
Write-Host "    Abuse of any of these is an approval-gated step with authorized tooling - NOT this script." -ForegroundColor Yellow

Write-RTEvidence -Technique 'AD attack-path enumeration (delegation/ACLs/GPO/policy)' -TechniqueId 'T1087.002,T1069.002,T1482,T1207' `
  -Target $Domain -Command ".\Invoke-AdEnum.ps1 -Domain $Domain" `
  -Result "unconstrained=$($unconstrained.Count) rbcd=$($rbcd.Count) riskyAcls=$($riskyAcls.Count) -> $OutFile" `
  -TelemetryExpected 'high LDAP query volume; DACL reads (1644 if diagnostics on)' | Out-Null
