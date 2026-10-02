# 03 — TTP Library

Each entry uses the universal TTP template (`docs/02`). Commands shown are
**safe enumeration / validation** examples; sensitive techniques are described at a
controlled proof-of-capability level only. Risk ratings assume an authorized,
scoped engagement.

Legend for Required Access: EXT=external, WS=compromised workstation, VC=valid creds,
LA=local admin, DU=domain user, DA=domain admin, SRV=server, VPN, CLD=cloud creds.

---

## A. Reconnaissance (TA0043)

### A1. Passive DNS & domain enumeration
- **ATT&CK**: T1590 (.002 DNS), T1596 — Gather Victim Network Info.
- **Objective**: Map owned domains/subdomains/IP space without touching targets.
- **Preconditions / Access**: Scope list. EXT.
- **Primary**: amass (passive), subfinder, dnsx. **Alt**: crt.sh, SecurityTrails, Censys.
  **Native/OSINT**: `whois`, `dig`, certificate transparency logs.
- **Workflow**: 1) `subfinder -d example.com -silent` 2) `amass enum -passive -d example.com`
  3) resolve with `dnsx` 4) dedupe into asset inventory.
- **Decision Tree**: IF new subdomains resolve to in-scope IPs THEN add to surface map;
  ELSE IF resolve out-of-scope THEN STOP/record (do not probe). FALLBACK: cert
  transparency (crt.sh) + ASN lookup.
- **Validation**: resolved A/AAAA records inside scope CIDRs.
- **Evidence**: tool output JSON, resolved host list, timestamps.
- **Detection**: minimal (passive); some providers log API queries.
- **SOC Telemetry**: external threat-intel / brand monitoring may flag bulk cert queries.
- **Cleanup**: none (no target contact).
- **Risk**: LOW. **Next**: A2/A3 → Surface mapping.

### A2. ASN / IP / CIDR & cloud-footprint discovery
- **ATT&CK**: T1590.005, T1596.005.
- **Objective**: Identify netblocks and cloud assets owned by target.
- **Tools**: `whois`/`bgp.he.net`, amass intel, cloud_enum, dnsx.
- **Decision Tree**: IF ASN maps to in-scope org THEN enumerate CIDRs → confirm against
  `scope.yaml`; ELSE exclude. IF cloud buckets/endpoints found THEN record for cloud
  playbook (`docs/07`), do not access yet.
- **Risk**: LOW. **Next**: A4, Surface map.

### A3. Technology fingerprinting
- **ATT&CK**: T1592 (.002 Software).
- **Tools**: httpx (`-td -title -sc`), WhatWeb, Wappalyzer.
- **Decision Tree**: IF known-vuln stack identified THEN tag for nuclei/web playbook
  (VALIDATE manually before claiming).
- **Risk**: LOW. **Next**: Web/API playbook (`docs/07`).

### A4. Public exposure & credential-exposure assessment
- **ATT&CK**: T1593 (.003 Code Repos), T1589.
- **Objective**: Find exposed secrets/repos/metadata (read-only, OSINT).
- **Tools**: GitHub code search, trufflehog (against *authorized* repos only), Shodan.
- **Decision Tree**: IF credential-like strings found THEN DOCUMENT + flag for careful,
  rate-limited validation (ESCALATE if production). Never spray.
- **Risk**: LOW (discovery) → MEDIUM if validating creds. **Next**: Initial Access.

---

## B. Resource / Attack-Surface Discovery

### B1. Port & service enumeration
- **ATT&CK**: T1595.001/.002 (active scanning), T1046 (internal).
- **Objective**: Enumerate open ports/services across in-scope hosts.
- **Tools**: nmap (`-sV -sC`), naabu/RustScan (fast port sweep), masscan (**only** with
  approval + rate limit). **Native**: PowerShell `Test-NetConnection`, `/dev/tcp`.
- **Workflow**: 1) fast sweep (naabu) 2) targeted `nmap -sV -sC -p <open>` 3) parse to map.
- **Decision Tree**: see `docs/27` for per-port next actions (445/3389/5985/5986/389/88/etc.).
- **Validation**: service banners/version confirmed.
- **Evidence**: nmap XML/greppable, service map.
- **Detection**: IDS/firewall connection logs, EDR network telemetry, high-volume SYN.
- **Risk**: LOW–MEDIUM (noise). **Next**: service-specific playbook.

### B2. Identity / mail / DNS / VPN infrastructure discovery
- **ATT&CK**: T1590.002, T1591.
- **Tools**: nmap scripts, `dig` MX/SPF/DMARC, Entra/ADFS endpoint checks, VPN gateway
  fingerprinting via httpx.
- **Decision Tree**: IF VPN gateway found THEN VPN playbook (Scenario 12); IF federation
  endpoints THEN cloud identity playbook.
- **Risk**: LOW. **Next**: `docs/05` Scenario 12 / `docs/07`.

---

## C. Initial Access (TA0001) — branch, don't assume one vector

For each vector: prerequisites + **safe validation** (prove access minimally, then stop).

### C1. Valid accounts (T1078 + .001/.002/.003/.004)
- **Objective**: Authenticate with discovered/provided credentials.
- **Access**: VC. **Tools**: NetExec (auth check), cloud CLI, OWA/portal.
- **Decision Tree**: IF creds valid on one service THEN enumerate what they reach (Scenario
  4) — DO NOT assume admin. IF invalid THEN STOP (no spraying). ESCALATE before any
  multi-account attempt; observe lockout policy first.
- **Risk**: MEDIUM. **Detection**: auth success from new geo/IP, impossible travel.

### C2. Exploit public-facing application (T1190)
- **Access**: EXT. **Tools**: Burp Suite, nuclei (validated templates), manual PoC.
- **Decision Tree**: IF nuclei flags a finding THEN VALIDATE manually (no blind mass
  exploitation); IF confirmed foothold THEN minimal PoC + DOCUMENT → Foothold.
  Web specifics in `docs/07`.
- **Risk**: HIGH (state change possible). ESCALATE for anything disruptive.

### C3. Exposed services / management interfaces / weak auth
- **ATT&CK**: T1133 (external remote services), T1190.
- **Tools**: NetExec, ssh, RDP client, nmap auth scripts.
- **Decision Tree**: IF exposed mgmt UI (iDRAC/iLO/Jenkins/etc.) THEN check default/weak
  auth *once* per account; IF default creds THEN DOCUMENT → Foothold.
- **Risk**: HIGH.

### C4. Trusted-relationship abuse (T1199) / misconfigured cloud (T1078.004 + T1190)
- **Decision Tree**: IF SaaS/partner integration or public cloud resource (object storage,
  exposed metadata) THEN cloud playbook (`docs/07`), read-only first.
- **Risk**: MEDIUM–HIGH.

### C5. Approved phishing / social engineering simulation (T1566 .001/.002)
- **Access**: EXT, explicit approval. **Tools**: GoPhish, approved payload stagers.
- **Decision Tree**: Only with named approval + target list from client. IF click/cred
  capture THEN record metrics → (optionally) controlled payload for execution test.
  No credential harvesting of real third-party accounts.
- **Risk**: MEDIUM (people impact) — always ESCALATE/approve.

---

## D. Execution (TA0002)
For each: Execution → Telemetry → Detection → Fallback → Cleanup.

| Technique | ATT&CK | Telemetry | Detection | Fallback | Cleanup |
|---|---|---|---|---|---|
| PowerShell | T1059.001 | Script-block/module logging, AMSI | EDR, PS logs | cmd/WMI | remove scripts, clear temp |
| Windows cmd | T1059.003 | process-create w/ cmdline | EDR cmdline | PowerShell | n/a |
| WMI | T1047 | WMI-Activity op log | EDR | PS remoting | remove subscriptions |
| Scheduled task | T1053.005 | task create/op log | EDR, task audit | service | delete task (DOCUMENT) |
| Service exec | T1569.002 | service-install log | EDR | task | delete service |
| Unix shell | T1059.004 | auditd execve, bash history | HIDS/EDR | python | clear artifacts you created |
| Python | T1059.006 | auditd, proc telemetry | EDR | shell | remove scripts |
| SSH remote exec | T1021.004 | sshd auth, auditd | SIEM auth | — | n/a |
| Container exec | T1609/T1610 | k8s audit, runtime logs | runtime EDR | — | remove ephemeral pods |

- **Decision Tree (generic)**: IF EDR present (see `docs/27` "EDR detected") THEN prefer
  native/LOLBin, minimal footprint, and purple-team coordination; IF execution blocked
  THEN FALLBACK to alternate interpreter; IF repeatedly blocked THEN DOCUMENT as a
  detection win and choose another path.

---

## E. Persistence (TA0003) — authorized targets only, always DOCUMENT + remove
Conceptual coverage + safe validation. **Never** persist outside explicitly approved hosts.

- **Windows**: scheduled task (T1053.005), service (T1543.003), Run keys (T1547.001),
  startup folder, local account create (T1136.001). Validate by confirming the mechanism
  exists; evidence = before/after state. Cleanup = remove and verify.
- **Linux**: cron (T1053.003), systemd service/timer (T1543.002), SSH authorized_keys
  (T1098.004), rc/profile. Cleanup = remove added entries, restore noted file mtime.
- **AD**: group/ACL changes (T1098), AdminSDHolder, GPO-based (T1484.001) — HIGH risk,
  ESCALATE, prefer demonstrate-then-revert.
- **Cloud**: access keys / app registrations / role assignments (T1098.001/.003) —
  ESCALATE; create short-lived, revoke immediately after proof.
- **Detection/Telemetry**: task/service creation events, Run-key auditing, auditd for
  cron/systemd, AD object-change events, cloud audit logs.
- **Risk**: HIGH. **Cleanup is mandatory and verified.**

---

## F. Privilege Escalation (TA0004)
See host playbooks (`docs/06`) for full detail. Library index:
- **Windows**: unquoted service path / weak service ACL (T1543.003, T1574), scheduled
  task weakness (T1053.005), token privileges e.g. SeImpersonate (T1134), insecure file
  perms, stored creds (T1552), vuln software, UAC bypass scenarios (T1548.002).
- **Linux**: sudo misconfig (T1548.003), SUID/SGID (T1548.001), capabilities, cron,
  writable systemd units, writable PATH, stored creds, kernel/software vulns.
- **AD**: group rights, ACL abuse, delegated rights, service accounts/SPNs, trusts, AD CS.
- **Decision Tree (generic)**: run enum (WinPEAS/linPEAS/PowerUp) → rank candidates by
  reliability + reversibility (`docs/21`) → VALIDATE lowest-risk candidate first →
  IF success DOCUMENT → re-enter Discovery with new context; ELSE next candidate; IF none
  THEN pivot to credential access or lateral path.
- **Risk**: MEDIUM–HIGH.

---

## G. Credential Access (TA0006) — approval-gated, no spraying
For each: Prerequisite / Risk / Detection / Safe validation / Evidence / Cleanup.

- **Credential discovery in files/config** (T1552.001): grep configs, scripts, histories.
  Safe. Evidence = file path + redacted sample. Cleanup none.
- **Exposed secrets / API keys / tokens** (T1552.001/.004): validate ONE token minimally
  against an authorized endpoint; ESCALATE if production.
- **SSH keys** (T1552.004): identify keys + reachable hosts; validate via a single auth.
- **Password policy / reuse assessment**: read policy (`net accounts`, PSOs) BEFORE any
  guessing; never exceed lockout threshold; prefer offline analysis of provided hashes.
- **Kerberoasting / AS-REP** (T1558.003 / T1558.004): request SPN/AS-REP tickets, crack
  **offline**. Low network impact; detection = ticket-request anomalies. Evidence = ticket
  metadata, cracked account (do not print recovered password in clear in the report body).
- **Credential dumping / memory access** (T1003 .001/.002/.003/.006): **explicit approval
  only**. Controlled proof-of-capability: demonstrate capability on one approved host,
  record that it is possible, avoid mass harvesting. Detection = process-access to the
  LSA process, SAM-handle auditing, EDR. Cleanup = remove any dump files, DOCUMENT.
- **Browser credentials** (T1555.003): authorized hosts only, proof-of-capability.
- **Risk**: HIGH–CRITICAL. **Always honor lockout guard and approval gate.**

---

## H. Discovery (TA0007) — mostly LOW risk, read-only
- **Windows**: users/groups (T1087 .001/.002), processes (T1057), services, shares
  (T1135), sessions (T1033/T1049), net config (T1016), domain trusts (T1482), GPOs,
  software (T1518), security products (T1518.001). Native: `whoami /all`, `net`,
  PowerShell AD cmdlets, `nltest`.
- **Linux**: users/groups, processes, services, sockets (`ss`), net (T1016), filesystems/
  mounts, containers, stored creds. Native: `id`, `ps`, `ss -tulpn`, `cat /etc/*`.
- **Network**: routes/VLANs/segmentation/gateways/DNS/management nets (T1016, T1046).
- **Decision Tree**: discovery continuously feeds the attack graph; see `docs/27` for how
  each finding routes. Prefer native tooling (quietest, LOLBin).
- **Detection**: individually low-signal; **bursts** of discovery (esp. AD recon via LDAP)
  are detectable — expected telemetry in `docs/11`.
- **Risk**: LOW. **Next**: prioritization → lateral/priv paths.

---

## I. Lateral Movement (TA0008)
Full method table in `docs/09`. Index: SMB/admin shares (T1021.002), WinRM (T1021.006),
RDP (T1021.001), WMI (T1047), remote service create (T1021/T1569.002), SSH (T1021.004),
DCOM, pass-the-hash/ticket (T1550.002/.003 — approval-gated), database links.
- **Decision Tree**: IF valid creds/hash + reachable admin service THEN authenticate →
  VALIDATE access level → minimal command to confirm → DOCUMENT → re-enter Discovery.
  Prefer the most reliable method unless purple-team coordination calls for exercising a
  specific technique. No auto-spread.

---

## J. Defense Evasion (TA0005) — controlled simulation, measure detection
Treat as *detection tests*, not as a way to actually blind defenders. **Never** disable
EDR/AV/logging without explicit authorization.
- Process masquerading (T1036.005), command-line obfuscation (T1027.010), LOLBins/signed
  binaries (T1218), alternate execution paths, timestomp **simulation** (T1070.006),
  log-visibility testing, control-response testing.
- For each: Purpose = measure whether the control catches it; Detection opportunity;
  Expected telemetry; Risk; **Safe validation** = run the benign variant and confirm
  whether SOC alerts. DOCUMENT detected / partially / not detected.
- **Risk**: MEDIUM. The deliverable is the detection gap, not persistence of evasion.

---

## K. Collection (TA0009) — synthetic data for sensitive demos
File/share discovery (T1083/T1135), database discovery, email/doc discovery, cloud
storage, screenshots (T1113), system info (T1082), browser data (authorized).
- **Decision Tree**: IF sensitive data located THEN prove *access* against a **canary/
  synthetic** item or metadata only — do not collect real sensitive content. DOCUMENT
  location + access proof. **Next**: exfiltration simulation.
- **Risk**: LOW–MEDIUM.

---

## L. Exfiltration Simulation (TA0010) — canary data only
Channels (conceptual, for detection testing): HTTPS (T1041/T1567), SFTP, approved C2
channel, cloud storage (T1567.002), DNS (T1048 — as a detection simulation).
- **Decision Tree**: Stage → compress → transfer a **synthetic marked file** over one
  channel → confirm whether DLP/proxy/DNS logging detects it → DOCUMENT expected vs
  observed. Never move real sensitive data.
- **Evidence**: file hash of synthetic payload, channel, timestamps, egress logs.
- **Detection**: proxy/DLP, large/anomalous egress, DNS volume/entropy, cloud API logs.
- **Risk**: MEDIUM. **Cleanup**: remove staged archives, note canary IDs.

---

## M. Impact Simulation (TA0040) — safe, bounded, reversible
Ransomware, data destruction, service disruption, account lockout, resource exhaustion,
backup deletion — **simulate only**, never execute destructive procedures.
- **How to simulate**: encrypt a single synthetic file in an approved sandbox dir with a
  reversible, documented key; create a benign "impact marker"; for backup/disruption,
  demonstrate the *access/permission* that would allow it (read/list) and STOP before the
  destructive call.
- **Evidence**: proof of the capability/permission, marker artifacts, exact stop point.
- **Logs to monitor**: volume-shadow deletion attempts, mass file-rename / EDR ransomware
  canaries, backup API calls, account-lockout events, service-stop events.
- **Where to stop**: before any irreversible or environment-wide action. ESCALATE.
- **Risk**: CRITICAL if mishandled — hence simulation-only + approval + sandbox.
