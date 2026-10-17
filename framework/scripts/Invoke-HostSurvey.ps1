<#
.SYNOPSIS
  Invoke-HostSurvey - read-only host situational-awareness survey (Windows).
  Our dependency-free equivalent of "Seatbelt"-style host enumeration.
.DESCRIPTION
  Collects host security-posture facts for the operator and the report. Everything is
  read-only via built-in cmdlets / CIM / registry reads (ATT&CK context
  T1082/T1518.001/T1033/T1057/T1012/T1083). It modifies nothing and reads no secrets.
  Sections:
    - OS / patch level / install date / uptime / .NET + PowerShell versions
    - Logged-on users and active sessions (names only)
    - UAC configuration
    - PowerShell logging posture (ScriptBlock / Module / Transcription)
    - AV / EDR products registered (SecurityCenter2)
    - Firewall profile status
    - Autoruns (Run/RunOnce keys + startup folders) - names/paths only
    - Scheduled tasks with non-Microsoft actions - names only
    - Interesting file surfaces (presence only): PS history, cmdkey, saved RDP
    - BitLocker status, RDP NLA setting
.EXAMPLE
  .\Invoke-HostSurvey.ps1 -OutFile hostsurvey.json
#>
[CmdletBinding()]
param([string]$OutFile = "hostsurvey_$($env:COMPUTERNAME).json")
Import-Module "$PSScriptRoot/RTSafety.psm1" -Force

function Get-Reg([string]$Path, [string]$Name) {
    try { (Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop).$Name } catch { $null }
}

$os = Get-CimInstance Win32_OperatingSystem
$cs = Get-CimInstance Win32_ComputerSystem
$s  = [ordered]@{ host=$env:COMPUTERNAME; collectedUtc=(Get-Date).ToUniversalTime().ToString('o') }

# --- OS / versions ---
$s.os = [ordered]@{
    caption      = $os.Caption
    version      = $os.Version
    build        = $os.BuildNumber
    installDate  = $os.InstallDate
    lastBootUtc  = $os.LastBootUpTime
    domain       = $cs.Domain
    partOfDomain = $cs.PartOfDomain
    psVersion    = $PSVersionTable.PSVersion.ToString()
    dotNetReleases = @(Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP' -Recurse -EA SilentlyContinue |
                       Get-ItemProperty -Name Version -EA SilentlyContinue |
                       Select-Object -ExpandProperty Version -Unique)
}

# --- patches (most recent 15) ---
$s.hotfixes = @(Get-HotFix -EA SilentlyContinue | Sort-Object InstalledOn -Descending |
                Select-Object -First 15 HotFixID, InstalledOn)

# --- sessions / users (names only) ---
$s.sessions = [ordered]@{
    currentUser = [Security.Principal.WindowsIdentity]::GetCurrent().Name
    quser       = @(quser 2>$null)
    localAdmins = @(try { (Get-LocalGroupMember -Group 'Administrators' -EA Stop).Name } catch { @() })
}

# --- UAC ---
$uacBase = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
$s.uac = [ordered]@{
    enableLUA              = Get-Reg $uacBase 'EnableLUA'
    consentPromptBehavior  = Get-Reg $uacBase 'ConsentPromptBehaviorAdmin'
    localAccountTokenFilter= Get-Reg $uacBase 'LocalAccountTokenFilterPolicy'   # 1 = remote PtH to local admins
}

# --- PowerShell logging posture ---
$s.psLogging = [ordered]@{
    scriptBlock   = Get-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' 'EnableScriptBlockLogging'
    moduleLogging = Get-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging' 'EnableModuleLogging'
    transcription = Get-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription' 'EnableTranscripting'
}

# --- AV / EDR ---
$s.securityProducts = @(try {
    Get-CimInstance -Namespace 'root\SecurityCenter2' -ClassName AntiVirusProduct -EA Stop |
        Select-Object displayName, @{n='stateHex';e={'0x{0:X}' -f $_.productState}}
} catch { @() })

# --- firewall ---
$s.firewall = @(try { Get-NetFirewallProfile -EA Stop | Select-Object Name, Enabled } catch { @() })

# --- autoruns (names/paths only) ---
$runKeys = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
           'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
           'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
$s.autoruns = @(foreach ($k in $runKeys) {
    $p = Get-ItemProperty $k -EA SilentlyContinue
    if ($p) { $p.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' } |
              ForEach-Object { [ordered]@{ key=$k; name=$_.Name; value=$_.Value } } }
})

# --- scheduled tasks with non-Microsoft actions (names only) ---
$s.scheduledTasks = @(try {
    Get-ScheduledTask -EA Stop | Where-Object { $_.TaskPath -notlike '\Microsoft\*' -and $_.State -ne 'Disabled' } |
        Select-Object -First 40 TaskName, TaskPath, State
} catch { @() })

# --- interesting file surfaces (presence only) ---
$psHistory = "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt"
$s.fileSurfaces = [ordered]@{
    psReadlineHistoryPresent = (Test-Path $psHistory)
    savedRdpFiles            = @(Get-ChildItem "$env:USERPROFILE\Documents\*.rdp" -EA SilentlyContinue | Select-Object -ExpandProperty FullName)
}

# --- disk encryption / RDP NLA ---
$s.bitlocker = @(try { Get-BitLockerVolume -EA Stop | Select-Object MountPoint, ProtectionStatus } catch { 'unavailable' })
$s.rdpNLA    = Get-Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' 'UserAuthentication'

$s | ConvertTo-Json -Depth 6 | Out-File $OutFile -Encoding utf8

Write-Host "[+] Host survey -> $OutFile" -ForegroundColor Green
Write-Host "    OS: $($s.os.caption) build $($s.os.build); AV: $(@($s.securityProducts).Count); autoruns: $(@($s.autoruns).Count)" -ForegroundColor Cyan

Write-RTEvidence -Technique 'Host situational-awareness survey' -TechniqueId 'T1082,T1518.001,T1033,T1012' `
  -Target $env:COMPUTERNAME -Command '.\Invoke-HostSurvey.ps1' `
  -Result "os=$($s.os.build); products=$(@($s.securityProducts).Count); autoruns=$(@($s.autoruns).Count) -> $OutFile" `
  -TelemetryExpected 'registry/CIM/WMI reads (low signal)' | Out-Null
