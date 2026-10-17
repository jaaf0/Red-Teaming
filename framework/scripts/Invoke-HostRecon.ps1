<#
.SYNOPSIS
  Invoke-HostRecon - custom, read-only local host situational-awareness collector.
  Replaces community discovery scripts for the Foothold/Discovery phase (docs/14 Phase 4/6).
.DESCRIPTION
  Uses only built-in cmdlets / CIM. No files written to disk except the JSON evidence report.
  Entirely read-only (ATT&CK T1082/T1033/T1057/T1518/T1016/T1049). Safe to run.
.EXAMPLE
  .\Invoke-HostRecon.ps1 -OutFile host.json
#>
[CmdletBinding()]
param([string]$OutFile = "hostrecon_$($env:COMPUTERNAME).json")

Import-Module "$PSScriptRoot/RTSafety.psm1" -Force

# This host is implicitly in scope for self-enumeration; still record evidence.
$data = [ordered]@{}

$data.system = Get-CimInstance Win32_OperatingSystem |
    Select-Object Caption, Version, BuildNumber, OSArchitecture, CSName, LastBootUpTime

$data.identity = [ordered]@{
    user       = "$env:USERDOMAIN\$env:USERNAME"
    groups     = (whoami /groups /fo csv 2>$null | ConvertFrom-Csv | Select-Object 'Group Name','Type')
    privileges = (whoami /priv /fo csv 2>$null | ConvertFrom-Csv | Select-Object 'Privilege Name','State')
    isAdmin    = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
                    [Security.Principal.WindowsBuiltInRole]::Administrator)
}

$data.localUsers  = Get-CimInstance Win32_UserAccount -Filter "LocalAccount=True" |
                    Select-Object Name, Disabled, Lockout, SID
$data.localAdmins = (net localgroup administrators 2>$null)

$data.network = [ordered]@{
    adapters    = Get-CimInstance Win32_NetworkAdapterConfiguration -Filter "IPEnabled=True" |
                  Select-Object Description, @{n='IP';e={$_.IPAddress -join ','}}, @{n='GW';e={$_.DefaultIPGateway -join ','}}, @{n='DNS';e={$_.DNSServerSearchOrder -join ','}}
    listeners   = (Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
                   Select-Object LocalAddress, LocalPort, OwningProcess)
    domain      = (Get-CimInstance Win32_ComputerSystem).Domain
}

$data.processes = Get-CimInstance Win32_Process |
    Select-Object ProcessId, Name, @{n='Owner';e={ try { ($_.GetOwner()).User } catch { '' } }} |
    Sort-Object Name

# Security products present (read-only identification, no tampering) - T1518.001
$data.securityProducts = Get-CimInstance -Namespace root/SecurityCenter2 -Class AntiVirusProduct -ErrorAction SilentlyContinue |
    Select-Object displayName, pathToSignedProductExe

$data.services = Get-CimInstance Win32_Service |
    Select-Object Name, State, StartMode, StartName, PathName

$data | ConvertTo-Json -Depth 6 | Out-File -LiteralPath $OutFile -Encoding utf8

Write-RTEvidence -Technique 'System/Owner/Network discovery' -TechniqueId 'T1082,T1033,T1016,T1518.001' `
    -Target $env:COMPUTERNAME -Command '.\Invoke-HostRecon.ps1' `
    -Result "collected -> $OutFile" -TelemetryExpected 'process-create, whoami/net usage' | Out-Null

Write-Host "[+] Host recon written to $OutFile" -ForegroundColor Green
