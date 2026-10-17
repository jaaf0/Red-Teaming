BeforeAll { Import-Module "$PSScriptRoot/../scripts/RTCommon.psm1" -Force }

Describe 'Test-AdcsTemplate' {
    It 'flags ESC1 for enrollee-supplied subject + client auth + no approval' {
        $t = [pscustomobject]@{ Name='T1'; NameFlag=1; EnrollFlag=0; RaSignatures=0; Ekus=@('1.3.6.1.5.5.7.3.2'); LowPrivEnroll=$true; LowPrivWrite=$false }
        (Test-AdcsTemplate $t).id | Should -Contain 'ADCS-ESC1'
    }
    It 'does not flag ESC1 when manager approval is required' {
        $t = [pscustomobject]@{ Name='T2'; NameFlag=1; EnrollFlag=2; RaSignatures=0; Ekus=@('1.3.6.1.5.5.7.3.2'); LowPrivEnroll=$true; LowPrivWrite=$false }
        (Test-AdcsTemplate $t).id | Should -Not -Contain 'ADCS-ESC1'
    }
    It 'does not flag when only admins can enroll' {
        $t = [pscustomobject]@{ Name='T3'; NameFlag=1; EnrollFlag=0; RaSignatures=0; Ekus=@(); LowPrivEnroll=$false; LowPrivWrite=$false }
        @(Test-AdcsTemplate $t).Count | Should -Be 0
    }
    It 'flags ESC2 for no EKU' {
        $t = [pscustomobject]@{ Name='T4'; NameFlag=0; EnrollFlag=0; RaSignatures=0; Ekus=@(); LowPrivEnroll=$true; LowPrivWrite=$false }
        (Test-AdcsTemplate $t).id | Should -Contain 'ADCS-ESC2'
    }
    It 'flags ESC3 for certificate request agent EKU' {
        $t = [pscustomobject]@{ Name='T5'; NameFlag=0; EnrollFlag=0; RaSignatures=0; Ekus=@('1.3.6.1.4.1.311.20.2.1'); LowPrivEnroll=$true; LowPrivWrite=$false }
        (Test-AdcsTemplate $t).id | Should -Contain 'ADCS-ESC3'
    }
    It 'flags ESC4 when low-priv principals can write the template' {
        $t = [pscustomobject]@{ Name='T6'; NameFlag=0; EnrollFlag=2; RaSignatures=0; Ekus=@('1.3.6.1.5.5.7.3.1'); LowPrivEnroll=$false; LowPrivWrite=$true }
        (Test-AdcsTemplate $t).id | Should -Contain 'ADCS-ESC4'
    }
}

Describe 'Find-GppCpassword' {
    It 'reports presence without echoing the value' {
        $xml = '<Properties cpassword="AbCdEf123" userName="svc"/>'
        $r = Find-GppCpassword -Text $xml -Path '\\d\SYSVOL\Groups.xml'
        $r.id | Should -Be 'GPP-CPASSWORD'
        ($r | ConvertTo-Json) | Should -Not -Match 'AbCdEf123'
    }
    It 'returns nothing for clean XML' {
        Find-GppCpassword -Text '<Properties userName="svc"/>' -Path 'x' | Should -BeNullOrEmpty
    }
}

Describe 'Test-KerberosAccount' {
    It 'flags privileged account with SPN' {
        $a = [pscustomobject]@{ Sam='svc'; UserAccountControl=512; SupportedEncTypes=24; PwdLastSet=(Get-Date); IsPrivileged=$true; HasSpn=$true }
        (Test-KerberosAccount $a).id | Should -Contain 'KRB-PRIV-SPN'
    }
    It 'flags missing pre-auth' {
        $a = [pscustomobject]@{ Sam='u'; UserAccountControl=(512 -bor 0x400000); SupportedEncTypes=24; PwdLastSet=(Get-Date); IsPrivileged=$false; HasSpn=$false }
        (Test-KerberosAccount $a).id | Should -Contain 'KRB-NOPREAUTH'
    }
    It 'flags old SPN account password' {
        $a = [pscustomobject]@{ Sam='s'; UserAccountControl=512; SupportedEncTypes=24; PwdLastSet=(Get-Date).AddDays(-900); IsPrivileged=$false; HasSpn=$true }
        (Test-KerberosAccount $a).id | Should -Contain 'KRB-OLD-SPN-PWD'
    }
    It 'is quiet for a healthy account' {
        $a = [pscustomobject]@{ Sam='ok'; UserAccountControl=512; SupportedEncTypes=24; PwdLastSet=(Get-Date); IsPrivileged=$false; HasSpn=$false }
        @(Test-KerberosAccount $a).Count | Should -Be 0
    }
}

Describe 'Test-KrbtgtAge' {
    It 'flags a stale krbtgt' { (Test-KrbtgtAge -PwdLastSet (Get-Date).AddDays(-400)).id | Should -Be 'KRB-KRBTGT-AGE' }
    It 'passes a fresh krbtgt' { Test-KrbtgtAge -PwdLastSet (Get-Date).AddDays(-10) | Should -BeNullOrEmpty }
}

Describe 'Test-DomainTrust' {
    It 'flags bidirectional trust without SID filtering' {
        (Test-DomainTrust ([pscustomobject]@{ Partner='b.local'; Direction=3; TrustType=2; TrustAttributes=0 })).id | Should -Be 'TRUST-NO-SIDFILTER'
    }
    It 'passes when quarantined' {
        Test-DomainTrust ([pscustomobject]@{ Partner='b.local'; Direction=3; TrustType=2; TrustAttributes=4 }) | Should -BeNullOrEmpty
    }
}

Describe 'Merge-RTFindings / Measure-RTCoverage' {
    It 'sorts by severity' {
        $m = Merge-RTFindings @((New-RTFinding -Id 'a' -Severity Low -Title t), (New-RTFinding -Id 'b' -Severity Critical -Title t))
        $m[0].id | Should -Be 'b'
    }
    It 'scores coverage by technique' {
        $exp = @([pscustomobject]@{Technique='T1';Rule='r1'},[pscustomobject]@{Technique='T1';Rule='r2'},[pscustomobject]@{Technique='T2';Rule='r3'})
        $obs = @([pscustomobject]@{Rule='r1'})
        $r = Measure-RTCoverage -Expected $exp -Observed $obs
        ($r | Where-Object technique -eq 'T1').status | Should -Be 'partial'
        ($r | Where-Object technique -eq 'T2').status | Should -Be 'gap'
    }
}
