<#
.SYNOPSIS
  Invoke-KerberosPosture - read-only Kerberos/identity hygiene audit: SPN accounts, encryption types, krbtgt age, trusts, Protected Users.
.DESCRIPTION
  Reads directory attributes only. Requests no tickets and reads no password material.
  ATT&CK context T1558.x / T1134.005.
.EXAMPLE
  .\Invoke-KerberosPosture.ps1 -Domain corp.example.com -OutFile kerberos.json
#>
[CmdletBinding()]
param([string]$Domain, [string]$OutFile = 'kerberos_posture.json')
Import-Module "$PSScriptRoot/RTSafety.psm1" -Force
Import-Module "$PSScriptRoot/RTCommon.psm1" -Force

if (-not $Domain) { $Domain = (Get-CimInstance Win32_ComputerSystem).Domain }
if (-not (Test-RTScope -Target $Domain)) { throw "Domain $Domain failed scope check." }

$findings = @()

# privileged membership (direct + nested via matching rule)
$priv = New-RTSearcher -Domain $Domain -Filter '(&(objectCategory=person)(objectClass=user)(adminCount=1))' -Props @('samaccountname')
$privSet = @($priv.FindAll() | ForEach-Object { Get-RTProp $_ 'samaccountname' })

$users = New-RTSearcher -Domain $Domain -Filter '(&(objectCategory=person)(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))' `
         -Props @('samaccountname','useraccountcontrol','msds-supportedencryptiontypes','pwdlastset','serviceprincipalname')
foreach ($r in $users.FindAll()) {
    $sam = Get-RTProp $r 'samaccountname'
    $pls = Get-RTProp $r 'pwdlastset'
    $acct = [pscustomobject]@{
        Sam = $sam; UserAccountControl = [int](Get-RTProp $r 'useraccountcontrol')
        SupportedEncTypes = Get-RTProp $r 'msds-supportedencryptiontypes'
        PwdLastSet = if ($pls) { [datetime]::FromFileTimeUtc([int64]$pls) } else { $null }
        IsPrivileged = ($privSet -contains $sam); HasSpn = ($r.Properties['serviceprincipalname'].Count -gt 0)
    }
    if ($sam -eq 'krbtgt' -and $acct.PwdLastSet) { $findings += Test-KrbtgtAge -PwdLastSet $acct.PwdLastSet }
    else { $findings += Test-KerberosAccount $acct }
}

# trusts
$tr = New-RTSearcher -Domain $Domain -Filter '(objectClass=trustedDomain)' -Props @('trustpartner','trustdirection','trusttype','trustattributes')
foreach ($r in $tr.FindAll()) {
    $findings += Test-DomainTrust ([pscustomobject]@{
        Partner=(Get-RTProp $r 'trustpartner'); Direction=[int](Get-RTProp $r 'trustdirection')
        TrustType=[int](Get-RTProp $r 'trusttype'); TrustAttributes=[int](Get-RTProp $r 'trustattributes') })
}

# Protected Users group usage
$pu = New-RTSearcher -Domain $Domain -Filter '(&(objectCategory=group)(cn=Protected Users))' -Props @('member')
$puRes = $pu.FindOne()
if (-not $puRes -or $puRes.Properties['member'].Count -eq 0) {
    $findings += New-RTFinding -Id 'KRB-NO-PROTECTED-USERS' -Severity Medium -Object 'Protected Users' -Attack 'T1550' `
        -Title 'Protected Users group is empty or missing' -Remediation 'Add privileged accounts (not service accounts) to Protected Users.'
}

$findings = @(Merge-RTFindings $findings)
[ordered]@{ domain=$Domain; collectedUtc=(Get-Date).ToUniversalTime().ToString('o'); findings=$findings } |
    ConvertTo-Json -Depth 6 | Out-File -LiteralPath $OutFile -Encoding utf8
Write-Host "[+] Kerberos posture -> $OutFile ($($findings.Count) finding(s); read-only)" -ForegroundColor Green
Write-RTEvidence -Technique 'Kerberos and trust posture audit' -TechniqueId 'T1558,T1134.005' -Target $Domain `
  -Command ".\Invoke-KerberosPosture.ps1 -Domain $Domain" -Result "$($findings.Count) finding(s) -> $OutFile" `
  -TelemetryExpected 'LDAP query volume' | Out-Null
