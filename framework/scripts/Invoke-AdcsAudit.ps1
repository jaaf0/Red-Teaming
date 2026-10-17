<#
.SYNOPSIS
  Invoke-AdcsAudit - read-only AD Certificate Services configuration audit (ESC1-ESC4 style misconfigurations).
.DESCRIPTION
  Reads certificate template objects from the Configuration partition and evaluates them with
  Test-AdcsTemplate (RTCommon). Reports risky configuration only. Requests no certificates,
  modifies no templates. ATT&CK context T1649.
.EXAMPLE
  .\Invoke-AdcsAudit.ps1 -Domain corp.example.com -OutFile adcs.json
#>
[CmdletBinding()]
param([string]$Domain, [string]$OutFile = 'adcs_audit.json')
Import-Module "$PSScriptRoot/RTSafety.psm1" -Force
Import-Module "$PSScriptRoot/RTCommon.psm1" -Force

if (-not $Domain) { $Domain = (Get-CimInstance Win32_ComputerSystem).Domain }
if (-not (Test-RTScope -Target $Domain)) { throw "Domain $Domain failed scope check." }

$cfg  = Get-RTConfigNC -Domain $Domain
$base = "CN=Certificate Templates,CN=Public Key Services,CN=Services,$cfg"
$ds   = New-RTSearcher -Filter '(objectClass=pKICertificateTemplate)' -SearchBase $base -WithSecurity `
        -Props @('cn','msPKI-Certificate-Name-Flag','msPKI-Enrollment-Flag','msPKI-RA-Signature','pKIExtendedKeyUsage','nTSecurityDescriptor')

# principals treated as "low privilege" for enroll/write checks
$lowPriv = 'Authenticated Users','Domain Users','Domain Computers','Everyone','BUILTIN\Users'
$enrollGuid = '0e10c968-78fb-11d2-90d4-00c04f79dc55'
$findings = @()
foreach ($r in $ds.FindAll()) {
    $de = $r.GetDirectoryEntry()
    $enroll = $false; $write = $false
    try {
        foreach ($ace in $de.ObjectSecurity.GetAccessRules($true,$true,[System.Security.Principal.NTAccount])) {
            if ($ace.AccessControlType -ne 'Allow') { continue }
            if (-not ($lowPriv | Where-Object { $ace.IdentityReference.Value -like "*$_" })) { continue }
            $rights = $ace.ActiveDirectoryRights.ToString()
            if ($rights -match 'GenericAll|WriteDacl|WriteOwner|GenericWrite') { $write = $true }
            if ($rights -match 'ExtendedRight|GenericAll' -and ($ace.ObjectType -eq [guid]$enrollGuid -or $ace.ObjectType -eq [guid]::Empty)) { $enroll = $true }
        }
    } catch {}
    $t = [pscustomobject]@{
        Name          = Get-RTProp $r 'cn'
        NameFlag      = [int](Get-RTProp $r 'mspki-certificate-name-flag')
        EnrollFlag    = [int](Get-RTProp $r 'mspki-enrollment-flag')
        RaSignatures  = [int](Get-RTProp $r 'mspki-ra-signature')
        Ekus          = @($r.Properties['pkiextendedkeyusage'])
        LowPrivEnroll = $enroll
        LowPrivWrite  = $write
    }
    $findings += Test-AdcsTemplate $t
}
$findings = @(Merge-RTFindings $findings)
[ordered]@{ domain=$Domain; collectedUtc=(Get-Date).ToUniversalTime().ToString('o'); findings=$findings } |
    ConvertTo-Json -Depth 6 | Out-File -LiteralPath $OutFile -Encoding utf8
Write-Host "[+] AD CS audit -> $OutFile ($($findings.Count) finding(s); read-only)" -ForegroundColor Green
Write-RTEvidence -Technique 'AD CS template configuration audit' -TechniqueId 'T1649' -Target $Domain `
  -Command ".\Invoke-AdcsAudit.ps1 -Domain $Domain" -Result "$($findings.Count) finding(s) -> $OutFile" `
  -TelemetryExpected 'LDAP reads of the Configuration partition' | Out-Null
