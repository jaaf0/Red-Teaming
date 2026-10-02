# 14 — Step-by-Step Operator Walkthrough

A guided, numbered walkthrough for someone running the engagement **phase by phase**. For
each phase: the goal, numbered steps, the tool used at each step and *how to use it*, how to
read the output, and the decision that routes you to the next phase. Pair with the command
reference (`docs/12`), the decision trees (`docs/19`), and the "what next" engine (`docs/27`).

> Before **every** step run the Global Safety Controller (`docs/01`): scope ✓, exclusions ✓,
> window ✓, approval if needed ✓, write the evidence record (`docs/23`) ✓.

---

## Phase 0 — Set up (do this once, first)
1. **Fill `config/scope.yaml`** — put every in-scope domain/CIDR/host/app and your egress IP.
   *Why*: the safety controller reads this before every action.
2. **Fill `config/exclusions.yaml`** — anything off-limits (OT, backups, prod DBs).
3. **Confirm approvals** for credential dumping, persistence, impact, exfil (if planned).
4. **Create the evidence folder** `output/evidence/<date>/` and open the attack log (`docs/23`).
- **Decision**: scope + authorization confirmed → go to Phase 1. Missing authorization → STOP.

---

## Phase 1 — Recon (map the attack surface, passively first)
**Goal**: a list of in-scope hosts/subdomains/IPs and the technologies they run.

1. **Subdomain discovery — `subfinder`**
   `subfinder -d example.com -silent | tee subs.txt`
   *Usage*: pulls subdomains from passive sources. Output = one host per line.
   *Read*: each line is a candidate; keep only those that fall in scope.
2. **Broaden — `amass` (passive)**
   `amass enum -passive -d example.com -o amass.txt`
   *Usage*: more passive sources; merge with `subs.txt` (`sort -u`).
3. **Resolve to IPs — `dnsx`**
   `dnsx -l subs.txt -resp -a -o resolved.txt`
   *Read*: hosts that resolve to IPs **inside your scope CIDRs** stay; others → STOP/record.
4. **Fingerprint live web — `httpx`**
   `httpx -l resolved.txt -title -tech-detect -status-code -o httpx.txt`
   *Read*: note titles, tech stack, status codes — these point at the right playbook later.
5. **(Optional) secret exposure — `trufflehog`** on authorized repos only.
- **Decision**: you now have an asset inventory. → Phase 2. If nothing resolves in scope,
  document "no external surface" (a valid result) and consult the client.

---

## Phase 2 — Attack-Surface Mapping (what's listening)
**Goal**: open ports, services, and which hosts are web/VPN/remote-access.

1. **Fast port sweep — `naabu`**
   `naabu -list resolved.txt -top-ports 1000 -rate 500 -o ports.txt`
   *Usage*: quick TCP discovery at a safe rate. Output `host:port`.
   *Read*: group hosts by what's open (445 = SMB/AD, 3389 = RDP, 5985/5986 = WinRM, 88/389 = AD).
2. **Deep service scan — `nmap`** (only the open ports)
   `nmap -sV -sC -Pn -p<open-ports> -oA nmap_target <host>`
   *Usage*: `-sV` versions, `-sC` default scripts. `-oA` saves all formats for evidence.
   *Read*: service + version → look it up in `docs/27` for the next action.
3. **Web candidates — `nuclei`** (after `httpx`)
   `nuclei -l web.json -severity medium,high,critical -o nuclei.txt`
   *Usage*: template scanner. **Output is candidates, not proof** — always manual-validate.
- **Decision** (per `docs/19` EXTERNAL branch): web exposed → Phase 3 via web playbook
  (`docs/07`); VPN gateway → Scenario 12; remote service → exposed-service branch.

---

## Phase 3 — Initial Access (get the first foothold, least-impact)
**Goal**: one validated foothold, with the least disruptive vector.

1. **If you have creds — validate with `netexec` (one attempt per account, NO spraying)**
   `netexec smb <host> -u <user> -p <pass>`
   *Read*: `[+]` = valid; `(Pwn3d!)` = admin on that host. Invalid → STOP, do not retry other passwords.
2. **If web — use `Burp Suite`** to confirm a finding manually (proxy the app, test the one
   candidate from nuclei). *Usage*: intercept → modify → observe. Record request/response.
3. **Content discovery — `ffuf`** when you need hidden endpoints:
   `ffuf -u https://app/FUZZ -w <wordlist> -mc 200,301,403`
4. **If exposed mgmt UI** — test default/weak creds **once** in the browser.
- **Decision**: foothold achieved → Phase 4. No vector found → document and return to recon.

---

## Phase 4 — Foothold (orient before you move)
**Goal**: understand *where you are* and *as whom*, using native tools (quietest).

1. **Windows**: `whoami /all` (user, groups, privileges), `ipconfig /all`, `systeminfo`.
   *Read*: are you local admin? what privileges (look for SeImpersonate/SeBackup)? what domain?
2. **Linux**: `id`, `uname -a`, `ip a`, `ss -tulpn` (listening services), `cat /etc/os-release`.
- **Decision**: domain-joined Windows → AD path (Phase 6 → AD branch). Local-only → host
  privesc (Phase 7). Note your privilege level now.

---

## Phase 5 — C2 (only if emulating a real adversary)
**Goal**: a managed control channel on the in-scope foothold. (Skip for pure pentest.)
1. **Pick a platform** (`docs/08`): Caldera for ATT&CK-mapped emulation + detection tests.
2. **Stand up a listener**, then **deploy the agent** to the authorized host only.
3. **Confirm check-in** in the console; set realistic sleep/jitter.
- **Decision**: agent healthy → run ATT&CK-mapped actions via the C2 in later phases, and
  record its indicators (`docs/08.3`) for detection validation.

---

## Phase 6 — Discovery (feed the attack graph)
**Goal**: enumerate identities, hosts, shares, and (if AD) the whole directory.

1. **Native quiet enum first**: `net user /domain`, `net group "Domain Admins" /domain`,
   `nltest /dclist:<domain>`. *Read*: who are the privileged users / where are the DCs.
2. **Shares across scope — `netexec`**: `netexec smb <CIDR> -u <u> -p <p> --shares`.
   *Read*: readable/writable shares are collection + lateral candidates.
3. **AD graph — `bloodhound-python` → BloodHound**
   `bloodhound-python -u <u> -p <p> -d <domain> -c All -ns <DC-ip> --zip`
   *Usage*: collects users, groups, ACLs, sessions, local-admin, trusts into a ZIP.
   *Then*: import the ZIP into the **BloodHound** GUI.
4. **Query BloodHound**: run "Shortest paths to Domain Admins", "Kerberoastable accounts",
   "Principals with DCSync rights". *Read*: each returned edge is a candidate path.
- **Decision**: you now have candidate edges → **prioritize** (`docs/21`) → pick the most
  reliable + reversible one → Phase 7 or 8 depending on the edge type.

---

## Phase 7 — Privilege Escalation (controlled, least-risk first)
**Goal**: raise privilege on the host, validating the safest candidate first.

1. **Enumerate candidates**
   - Windows: `.\winPEASx64.exe quiet` and `whoami /priv`; or `PowerUp` `Invoke-AllChecks`.
   - Linux: `./linpeas.sh -a` ; `sudo -l` ; `find / -perm -4000 -type f 2>/dev/null` ;
     `getcap -r / 2>/dev/null`.
   *Read*: the tools rank findings; cross-check against `docs/06` candidate order.
2. **Pick the least-risk, most-reversible candidate** (stored cred > token > service/cron change).
3. **Validate it minimally** (a single reversible action), then **DOCUMENT**.
- **Decision**: higher privilege gained → re-enter Discovery (Phase 6) with new context.
  Nothing viable → pivot to credential access (Phase 8) or lateral movement (Phase 9).

---

## Phase 8 — Credential Access (approval-gated; offline where possible)
**Goal**: usable credentials, with the least network noise and no lockouts.

1. **Read the password policy FIRST — `netexec --pass-pol`** so you never hit lockout.
2. **Kerberoast (low impact) — `GetUserSPNs.py`**
   `GetUserSPNs.py <domain>/<u>:<p> -dc-ip <DC> -request -outputfile spns.hash`
   then crack **offline**: `hashcat -m 13100 spns.hash wordlist.txt`.
   *Read*: a cracked service-account password → check where it's admin (Phase 9).
3. **AS-REP roast — `GetNPUsers.py`** for accounts without pre-auth; crack offline (`-m 18200`).
4. **Dumping / DCSync** (`secretsdump.py`) — **explicit approval only**: prove capability on
   a single test account, then STOP. Highly detectable (a purple-team win).
- **Decision**: new creds → re-enter Discovery, update the graph, re-prioritize.

---

## Phase 9 — Lateral Movement (one chosen host at a time, never auto-spread)
**Goal**: reach a higher-value host using valid authentication.

1. **Find where your creds are admin — `netexec`**
   `netexec smb <CIDR> -u <u> -p <p> | grep "(Pwn3d!)"`.
2. **Move to the one highest-value reachable host** with the most reliable method:
   - WinRM: `evil-winrm -i <host> -u <u> -p <p>`
   - WMI: `wmiexec.py <domain>/<u>:<p>@<host>`
   - RDP: `xfreerdp /u:<u> /p:<p> /v:<host> /cert:ignore`
   - SSH: `ssh <u>@<host>`
   *(Pass-the-Hash `-H <hash>` requires approval.)*
3. **Run one minimal command** to confirm access, **DOCUMENT**, then re-enter Discovery.
- **Decision**: objective host reached → Phase 10. Else pick the next graph edge.

---

## Phase 10 — Objective Discovery (find the crown jewels; don't auto-exploit)
**Goal**: locate DCs, backups, DB/file/management servers, sensitive apps.
1. **BloodHound**: shortest path from your owned principal to Tier-0.
2. **`setspn -Q */*`** to find service accounts tied to SQL/backup/virtualization.
3. **Share hunting — `netexec -M spider_plus`** for sensitive data stores.
- **Decision**: map the *theoretical* path to each HVA, prioritize (`docs/21`), validate only
  the approved path → Phase 11.

---

## Phase 11 — Controlled Objective Simulation (prove, then STOP)
**Goal**: demonstrate impact safely with synthetic/canary data only.
1. **Place a synthetic canary** in an approved sandbox dir.
2. **Reversible demo** (e.g. `openssl enc` to "encrypt" the canary, then decrypt to revert).
3. For destructive objectives, **prove the permission** (read/list/stop-permission) and STOP
   before the irreversible call. ESCALATE for each expansion.
- **Decision**: proof captured → Phase 12.

---

## Phase 12 — Detection Validation (the purple payoff)
**Goal**: for every technique used, record what the SOC saw.
1. For each action in the attack log, **correlate its timestamp** with SIEM/EDR (`docs/11`).
2. **Classify** DETECTED / PARTIALLY DETECTED / NOT DETECTED.
3. Hand any gaps (with indicators) to detection engineering; re-run to confirm the new rule.
- **Decision**: coverage map complete → Phase 13.

---

## Phase 13 — Cleanup (leave it as you found it)
1. Work the cleanup checklist (`docs/99`): remove tools/files/markers, revert services/tasks/
   ACLs, decrypt/remove canaries, kill C2 agents, revoke test certs/keys.
2. **Verify** each `cleanup_required` record is closed; confirm no persistence remains.
- **Decision**: environment restored → Phase 14.

---

## Phase 14 — Reporting
1. Assemble the report (`docs/99`): narrative + per-technique detection coverage + remediation.
2. Attach the attack log, ATT&CK heatmap (Navigator), evidence index, canary IDs.
- **Done**: deliver + debrief with the blue team.

---

### One-screen operator loop
```
Safety check → act (least-impact) → read output → VALIDATE → DOCUMENT →
update attack graph → prioritize (docs/21) → pick next edge (docs/27/19) → repeat
```
