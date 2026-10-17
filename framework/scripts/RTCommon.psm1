<#
.SYNOPSIS
  RTCommon - shared helpers for the audit scripts: LDAP access and pure, unit-testable analysis functions.
  Read-only. Analysis functions take plain objects so Pester can test them without a domain.
#>

function New-RTSearcher {
    param([Parameter(Mandatory)][string]$Filter, [string[]]$Props, [string]$SearchBase,
          [string]$Domain, [int]$Max = 5000, [switch]$WithSecurity)
    $path = if ($SearchBase) { "LDAP://$SearchBase" } elseif ($Domain) { "LDAP://$Domain" } else { 'LDAP://RootDSE' }
    $ds = New-Object System.DirectoryServices.DirectorySearcher((New-Object System.DirectoryServices.DirectoryEntry($path)))
    $ds.Filter = $Filter; $ds.PageSize = 1000; $ds.SizeLimit = $Max
    if ($WithSecurity) { $ds.SecurityMasks = [System.DirectoryServices.SecurityMasks]::Dacl }
    foreach ($p in $Props) { [void]$ds.PropertiesToLoad.Add($p) }
    $ds
}

function Get-RTProp { param($Result, [string]$Name) if ($Result.Properties[$Name].Count) { $Result.Properties[$Name][0] } else { $null } }

function Get-RTConfigNC {
    param([string]$Domain)
    $p = if ($Domain) { "LDAP://$Domain/RootDSE" } else { 'LDAP://RootDSE' }
    (New-Object System.DirectoryServices.DirectoryEntry($p)).Properties['configurationNamingContext'][0]
}

function New-RTFinding {
    param([Parameter(Mandatory)][string]$Id, [Parameter(Mandatory)][ValidateSet('Critical','High','Medium','Low','Info')][string]$Severity,
          [Parameter(Mandatory)][string]$Title, [string]$Object, [string]$Detail, [string]$Remediation, [string]$Attack)
    [pscustomobject][ordered]@{ id=$Id; severity=$Severity; title=$Title; object=$Object; detail=$Detail; remediation=$Remediation; attack=$Attack }
}

# --- AD CS template analysis (pure) -------------------------------------------------------
$script:EkuClientAuth  = '1.3.6.1.5.5.7.3.2'
$script:EkuPkinitAuth  = '1.3.6.1.5.2.3.4'
$script:EkuSmartcard   = '1.3.6.1.4.1.311.20.2.2'
$script:EkuAnyPurpose  = '2.5.29.37.0'
$script:EkuCertReqAgent= '1.3.6.1.4.1.311.20.2.1'

function Test-AdcsTemplate {
<# Input: object with Name, NameFlag, EnrollFlag, RaSignatures, Ekus[], LowPrivEnroll(bool), LowPrivWrite(bool).
   Output: findings for ESC1-ESC4 style template misconfigurations. Config analysis only. #>
    param([Parameter(Mandatory)]$Template)
    $f = @()
    $suppliesSubject = [bool]($Template.NameFlag -band 1)
    $noApproval      = -not ($Template.EnrollFlag -band 2)
    $noSignatures    = [int]$Template.RaSignatures -eq 0
    $ekus = @($Template.Ekus)
    $authEku = (@($ekus | Where-Object { $_ -in $script:EkuClientAuth,$script:EkuPkinitAuth,$script:EkuSmartcard,$script:EkuAnyPurpose }).Count -gt 0) -or ($ekus.Count -eq 0)
    if ($Template.LowPrivEnroll -and $suppliesSubject -and $authEku -and $noApproval -and $noSignatures) {
        $f += New-RTFinding -Id 'ADCS-ESC1' -Severity Critical -Object $Template.Name -Attack 'T1649' `
            -Title 'Template lets low-privileged enrollees supply the subject on an authentication certificate' `
            -Detail 'ENROLLEE_SUPPLIES_SUBJECT set, auth-capable EKU, no manager approval, no authorized signatures.' `
            -Remediation 'Clear ENROLLEE_SUPPLIES_SUBJECT or require manager approval; restrict enrollment rights.'
    }
    if ($Template.LowPrivEnroll -and ($ekus.Count -eq 0 -or $ekus -contains $script:EkuAnyPurpose) -and $noApproval) {
        $f += New-RTFinding -Id 'ADCS-ESC2' -Severity High -Object $Template.Name -Attack 'T1649' `
            -Title 'Template allows Any Purpose / no EKU for low-privileged enrollees' `
            -Remediation 'Define explicit EKUs; require approval.'
    }
    if ($Template.LowPrivEnroll -and ($ekus -contains $script:EkuCertReqAgent) -and $noApproval) {
        $f += New-RTFinding -Id 'ADCS-ESC3' -Severity High -Object $Template.Name -Attack 'T1649' `
            -Title 'Certificate Request Agent template enrollable by low-privileged principals' `
            -Remediation 'Restrict enrollment agents; use enrollment-agent restrictions on the CA.'
    }
    if ($Template.LowPrivWrite) {
        $f += New-RTFinding -Id 'ADCS-ESC4' -Severity Critical -Object $Template.Name -Attack 'T1649' `
            -Title 'Low-privileged principal can modify the certificate template' `
            -Remediation 'Remove write/owner/DACL rights for non-admin principals on the template object.'
    }
    $f
}

# --- SYSVOL/GPP scan (pure, pattern-presence only) -------------------------------------------
function Find-GppCpassword {
<# Reports THAT a cpassword attribute exists in XML text. It never extracts or decodes the value. #>
    param([Parameter(Mandatory)][string]$Text, [string]$Path)
    if ($Text -match 'cpassword\s*=\s*"[^"]+"') {
        New-RTFinding -Id 'GPP-CPASSWORD' -Severity Critical -Object $Path -Attack 'T1552.006' `
            -Title 'Group Policy Preferences file contains a cpassword attribute' `
            -Detail 'Value intentionally not read or decoded. The key is public, so the password is recoverable by any domain user.' `
            -Remediation 'Delete the preference item, rotate the exposed account password, and use LAPS/gMSA.'
    }
}

# --- Kerberos posture (pure) ---------------------------------------------------------------
function Test-KerberosAccount {
<# Input: Sam, UserAccountControl(int), SupportedEncTypes(int or $null), PwdLastSet(datetime), IsPrivileged(bool). #>
    param([Parameter(Mandatory)]$Account, [int]$MaxPasswordAgeDays = 365)
    $f = @()
    $uac = [int]$Account.UserAccountControl
    if ($uac -band 0x200000) {
        $f += New-RTFinding -Id 'KRB-DES' -Severity Medium -Object $Account.Sam -Title 'Account restricted to legacy DES Kerberos' -Remediation 'Clear USE_DES_KEY_ONLY.'
    }
    $enc = $Account.SupportedEncTypes
    if ($null -eq $enc -or ([int]$enc -band 0x18) -eq 0) {
        if ($Account.HasSpn) {
            $f += New-RTFinding -Id 'KRB-RC4' -Severity Medium -Object $Account.Sam -Attack 'T1558.003' `
                -Title 'Service account has an SPN and no AES encryption types configured (RC4 tickets)' `
                -Remediation 'Set msDS-SupportedEncryptionTypes to AES128/256 and rotate the password.'
        }
    }
    if ($Account.IsPrivileged -and $Account.HasSpn) {
        $f += New-RTFinding -Id 'KRB-PRIV-SPN' -Severity High -Object $Account.Sam -Attack 'T1558.003' `
            -Title 'Privileged account has a service principal name' -Remediation 'Remove the SPN or move the service to a gMSA.'
    }
    if ($Account.HasSpn -and $Account.PwdLastSet -and ((Get-Date) - [datetime]$Account.PwdLastSet).TotalDays -gt $MaxPasswordAgeDays) {
        $f += New-RTFinding -Id 'KRB-OLD-SPN-PWD' -Severity Medium -Object $Account.Sam -Attack 'T1558.003' `
            -Title "Service account password older than $MaxPasswordAgeDays days" -Remediation 'Rotate to a long random password or a gMSA.'
    }
    if ($uac -band 0x400000) {
        $f += New-RTFinding -Id 'KRB-NOPREAUTH' -Severity High -Object $Account.Sam -Attack 'T1558.004' `
            -Title 'Kerberos pre-authentication disabled' -Remediation 'Clear DONT_REQ_PREAUTH.'
    }
    $f
}

function Test-KrbtgtAge {
    param([Parameter(Mandatory)][datetime]$PwdLastSet, [int]$MaxDays = 180)
    $age = [int]((Get-Date) - $PwdLastSet).TotalDays
    if ($age -gt $MaxDays) {
        New-RTFinding -Id 'KRB-KRBTGT-AGE' -Severity High -Object 'krbtgt' -Attack 'T1558.001' `
            -Title "krbtgt password is $age days old" -Detail "Policy maximum: $MaxDays days." `
            -Remediation 'Reset krbtgt twice with the standard interval between resets.'
    }
}

# --- Trust analysis (pure) -----------------------------------------------------------------
function Test-DomainTrust {
<# Input: Partner, Direction(int), TrustType(int), TrustAttributes(int). 0x4 = quarantined (SID filtering on). #>
    param([Parameter(Mandatory)]$Trust)
    $attr = [int]$Trust.TrustAttributes
    $external = ($attr -band 0x4) -ne 0
    $forest   = ($attr -band 0x8) -ne 0
    if (-not $external -and -not $forest -and $Trust.Direction -in 2,3) {
        New-RTFinding -Id 'TRUST-NO-SIDFILTER' -Severity High -Object $Trust.Partner -Attack 'T1134.005' `
            -Title 'Inbound-capable trust without SID filtering (quarantine) enabled' `
            -Remediation 'Enable SID filtering: netdom trust <trusting> /domain:<trusted> /quarantine:yes'
    }
    if (($attr -band 0x40) -ne 0 -and -not $forest) { } # treat-as-external noted elsewhere
}

# --- Severity roll-up (pure) ---------------------------------------------------------------
function Get-RTSeverityRank { param([string]$Severity) @{Critical=4;High=3;Medium=2;Low=1;Info=0}[$Severity] }

function Merge-RTFindings {
    param([Parameter(Mandatory)][object[]]$Findings)
    $Findings | Where-Object { $_ } | Sort-Object @{e={ Get-RTSeverityRank $_.severity };Descending=$true}, id, object
}

# --- Detection coverage scoring (pure) -----------------------------------------------------
function Measure-RTCoverage {
<# Expected: objects with Technique, Rule. Observed: objects with Rule (rules your SOC confirms fired). Offline comparison only. #>
    param([Parameter(Mandatory)][object[]]$Expected, [object[]]$Observed = @())
    $fired = @($Observed | ForEach-Object { $_.Rule })
    $rows = foreach ($g in ($Expected | Group-Object Technique)) {
        $total = $g.Count
        $hit = @($g.Group | Where-Object { $fired -contains $_.Rule }).Count
        [pscustomobject]@{ technique=$g.Name; expected=$total; detected=$hit; pct=[math]::Round(100*$hit/$total,0);
                           status = if ($hit -eq $total) {'covered'} elseif ($hit -gt 0) {'partial'} else {'gap'} }
    }
    $rows | Sort-Object pct, technique
}

Export-ModuleMember -Function *
