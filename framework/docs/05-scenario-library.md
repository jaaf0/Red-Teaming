# 05 — Scenario Library (18 Playbooks)

Every scenario uses the same contract:
**OBJECTIVE · STARTING POSITION · ASSUMPTIONS · ATTACK PATH (branched) · TTPs · TOOLS ·
DECISION TREE · EXPECTED TELEMETRY · SUCCESS CRITERIA · STOP CONDITIONS · EVIDENCE ·
CLEANUP.** Scenarios are entry points into the same TTP library and decision engine — they
are not linear scripts. Branch at every decision point.

---

## Scenario 1 — External Attacker
- **Objective**: From the internet, reach an internal/high-value asset via a documented path.
- **Starting position**: External, scope IPs/domains only.
- **Assumptions**: No creds. Perimeter present. Scope authorized.
- **Attack path (branched)**:
  ```
  External Recon → Surface Discovery → Service Enum →
    ├─[web exposed]      → Web/API assessment (Scenario 2)
    ├─[VPN gateway]      → VPN assessment (Scenario 12)
    ├─[remote service]   → exposed-service / valid-account branch (C1/C3)
    └─[exposed creds OSINT] → valid-account validation (C1)
  → Initial Access → Foothold → (PrivEsc?) → Credential Access →
  Internal access → Internal Discovery → Lateral Movement → Objective
  ```
- **TTPs**: A1–A4, B1–B2, C1–C5, then internal chain (H→F→G→I).
- **Tools**: subfinder/amass, naabu, nmap, httpx, nuclei, Burp, NetExec, BloodHound.
- **Decision tree**: IF web → Scenario 2; ELSE IF VPN → Scenario 12; ELSE IF remote svc
  with weak/default auth → C3; ELSE IF OSINT creds → C1; ELSE continue recon / report
  "no external foothold" (a valid, valuable result).
- **Expected telemetry**: perimeter scan logs, WAF events, auth attempts, new-geo logins.
- **Success criteria**: documented reproducible path to an internal asset.
- **Stop conditions**: out-of-scope pivot, disruptive-only path without approval.
- **Evidence**: per-step records (`docs/23`), screenshots of each foothold.
- **Cleanup**: remove any uploaded files/webshells, close sessions, revert changes.

## Scenario 2 — External → Web → Internal
- **Objective**: Use a web-app compromise to reach internal infrastructure.
- **Starting position**: Public web application in scope.
- **Attack path (branched)**: app discovery → endpoint discovery → authn testing →
  authz testing → injection classes → file handling → server-side vulns → exposed secrets
  → API abuse → **SSRF (authorized)** → cloud metadata (if applicable) → web-to-host pivot
  → internal service discovery.
- **Branches**: {SSRF→metadata→cloud creds} | {file upload→exec→foothold} |
  {auth bypass→admin→data} | {exposed secret→valid account}. Full detail in `docs/07`.
- **Decision tree**: IF SSRF reaches metadata endpoint THEN controlled read of a non-secret
  field first, ESCALATE before retrieving creds; IF upload yields exec THEN minimal PoC;
  ELSE enumerate next class.
- **Telemetry**: WAF, app logs, egress from web host, cloud metadata access logs.
- **Success / stop / evidence / cleanup**: as Scenario 1; remove any test artifacts.

## Scenario 3 — Compromised User Workstation
- **Objective**: From a standard domain-user workstation, reach privileged assets.
- **Starting position**: Interactive access as domain user (WS).
- **Attack path**: Host discovery → identity discovery → local enum → credential exposure
  → privesc → AD discovery → attack-path analysis → session/cred discovery → lateral
  movement → privileged account → high-value asset.
- **Branches**: {local privesc→local admin→cred access} | {no local priv→AD path via
  BloodHound (Kerberoast/ACL)} | {session of privileged user on another host → lateral}.
- **Tools**: Seatbelt/WinPEAS, PowerUp, SharpHound→BloodHound, NetExec.
- **Decision tree**: `docs/19` Internal→Windows→AD branch. VALIDATE each step; DOCUMENT.
- **Telemetry**: process-create, LDAP recon bursts, Kerberoast TGS requests, lateral auth.
- **Cleanup**: remove dropped tools, clear temp, revert any persistence.

## Scenario 4 — Stolen Valid Credentials
- **Objective**: Determine exactly what the account can access (no DA assumption).
- **Starting position**: One set of valid domain creds (VC).
- **Attack path**: authentication validation across SMB/WinRM/RDP/LDAP/Kerberos → file
  shares → app auth → DB access → privilege discovery → group membership → delegated perms
  → accessible systems.
- **Tools**: NetExec (`--shares`, `--users`, protocol checks), BloodHound (as the owned
  principal), ldapsearch.
- **Decision tree**: IF local admin anywhere THEN note (cred-access candidate, approval
  gated); IF member of privileged group THEN map blast radius; IF Kerberoastable SPNs
  reachable THEN offline crack branch; ELSE enumerate reachable data.
- **Stop**: no spraying; one auth per service; honor lockout policy.
- **Telemetry**: multi-service auth from one principal/IP, share access, LDAP queries.

## Scenario 5 — Active Directory Attack Path
- **Objective**: From low-priv domain user, reach a privileged account/HVA via a graphed path.
- **Attack path**: domain/user/group/computer/OU/GPO enumeration → ACL analysis →
  delegated perms → service accounts/SPNs → sessions → local admins → trusts → AD CS (if
  present, Scenario 6) → attack-path graphing → privesc paths → lateral movement.
- **Tool contributions**:
  - **SharpHound/bloodhound-python**: collects AD objects, ACLs, sessions, local-admin.
  - **BloodHound**: graphs shortest paths to Tier-0; pre-built queries (Kerberoastable,
    DCSync rights, shortest path to DA).
  - **ldapsearch / NetExec**: targeted queries, cred validation, where-am-I-admin.
  - **Kerberos tooling (Impacket)**: Kerberoast / AS-REP roast → offline crack.
  - **Native (PowerShell AD, nltest, setspn)**: quiet enumeration / LOLBin.
- **Decision tree**: build graph → pick path with best reliability/reversibility
  (`docs/21`) → validate minimal step → re-collect → repeat. ESCALATE for DCSync/dumping.
- **Telemetry**: LDAP recon volume, TGS/TGT request anomalies, ACL changes, DCSync
  replication from non-DC. **Cleanup**: revert any ACL/group changes made for validation.

## Scenario 6 — AD Certificate Services
- **Objective**: Assess AD CS for privilege-impacting misconfigurations (do not assume vuln).
- **Attack path**: Discovery → CA enumeration → template enumeration → misconfig ID →
  permission analysis → **controlled exploitation validation** → privilege-impact
  assessment → detection → cleanup.
- **Tools**: Certipy (`find`), `certutil`, NetExec ADCS module.
- **Decision tree**: IF CA present THEN enumerate templates; IF a template allows enrollee-
  supplied SAN / dangerous EKU / weak enrollment rights THEN classify the misconfig class
  → controlled validation that proves the path exists → STOP before broad abuse → ESCALATE
  → DOCUMENT impact. ELSE record "AD CS present, no exploitable misconfig found."
- **Telemetry**: certificate enrollment events, CA audit logs, abnormal template requests.
- **Cleanup**: revoke any test certificate issued; remove request artifacts.

## Scenario 7 — Windows Server Compromise
- **Objective**: From a compromised Windows server, enumerate then branch.
- **Local enum**: services, scheduled tasks, installed software, registry, net config,
  firewall, local users/groups, privileges, stored secrets, processes, security products,
  domain membership, sessions, shares, tokens, service accounts.
- **Branch**: → PrivEsc | → Credential Access | → Lateral Movement | → Persistence (each in
  `docs/06`/`docs/09`). Decision in `docs/19` Windows-enumeration subtree.
- **Telemetry**: process-create, service/task creation, token use, LSA-process access.

## Scenario 8 — Linux Server Compromise
- **Objective**: From a low-priv Linux shell, enumerate then escalate/pivot.
- **Local enum**: OS/kernel, users/groups, sudo, SUID/SGID, capabilities, cron, systemd,
  services, Docker, Kubernetes (if present), SSH, env vars, config files, creds/secrets,
  mounts, network connections, processes, containers.
- **Attack path**: PrivEsc → Credential Access → Lateral Movement → Objective.
- **Decision tree**: `docs/06` Linux subtree. IF Docker socket writable THEN host-access
  branch (controlled); IF sudo misconfig THEN GTFOBins-style validation; etc.
- **Telemetry**: auditd execve, sudo logs, new cron/systemd units, container runtime logs.

## Scenario 9 — Ransomware-like Objective Simulation (SAFE)
- **Objective**: Emulate ransomware operator TTPs **without** destructive payloads.
- **Attack path**: Initial Access → PrivEsc → domain discovery → **backup discovery** →
  security-control discovery → lateral movement → HVA identification → **controlled
  encryption simulation** → impact evidence → detection/response.
- **Controlled encryption**: encrypt only pre-placed **synthetic/canary files** in an
  approved sandbox path, reversible documented key, single host unless approved broader.
- **Stop (hard)**: before touching real data, before disabling shadow copies/backups,
  before any environment-wide or irreversible action. ESCALATE for each expansion.
- **Telemetry to validate**: mass-file-modification/ransomware canaries, shadow-copy
  deletion attempts (not performed — detect the *attempt* in a lab), backup API access.
- **Evidence**: proof of reach to backups/HVAs (read/list perms), the sandbox encryption
  demo, exact stop points. **Cleanup**: decrypt/remove synthetic files, remove tools.

## Scenario 10 — Data Exfiltration Simulation (SAFE)
- **Objective**: Test detection of exfil using **synthetic/canary** data only.
- **Attack path**: Collection → staging → compression → controlled transfer → detection →
  cleanup. Channels (conceptual): HTTPS, DNS (detection sim), cloud storage, approved C2,
  SFTP.
- **Per channel**: what defenders should detect, what logs should exist, what evidence to
  collect. Never move real sensitive data.
- **Decision tree**: pick one channel → transfer marked canary → check proxy/DLP/DNS logs →
  DOCUMENT detected/partial/not. Repeat per channel as time allows.
- **Cleanup**: delete staged archives on host and destination; record canary IDs.

## Scenario 11 — Insider Threat Simulation
- **Objective**: Model a malicious authorized user; map each action to telemetry.
- **Starting position**: Authorized test user account (synthetic data environment).
- **Simulate**: excessive file access, sensitive-share discovery, credential exposure,
  data staging, suspicious archive creation, controlled exfiltration (canary).
- **Decision tree**: each action → expected log → was it detected? Build coverage map.
- **Telemetry**: file-access auditing, share enumeration, archive creation, egress.

## Scenario 12 — VPN Compromise
- **Objective**: Test whether VPN access grants unintended network reach.
- **Starting position**: Valid VPN creds (provided/authorized).
- **Attack path**: VPN auth → network access → **segmentation discovery** → internal host
  discovery → service enum → credential validation → lateral movement.
- **Decision tree**: IF VPN lands in a flat network reaching Tier-0 THEN that is itself a
  finding (segmentation gap) — DOCUMENT; map reachable segments; probe minimally.
- **Telemetry**: VPN auth logs, east-west traffic, segment-crossing flows.

## Scenario 13 — Remote Access Attack
- **Objective**: For RDP/WinRM/SSH/SMB/remote-admin/remote-service-exec, test
  Authentication, Authorization, Privilege, Logging, Detection, Lateral Movement.
- **Decision tree**: per protocol, IF reachable + creds THEN single auth → confirm access
  level → minimal exec → DOCUMENT telemetry. Detail in `docs/09`.
- **Telemetry**: per-protocol auth events, session creation, remote exec traces.

## Scenario 14 — Server-to-Server Movement
- **Objective**: From a compromised app/server, move to another server.
- **Attack path**: Discovery → credentials → trust relationships → remote services →
  lateral movement → privilege escalation.
- **Decision tree**: IF service account creds found THEN map where they are admin (NetExec)
  → move to highest-value reachable → re-enumerate. ELSE harvest trusts/keys.

## Scenario 15 — High-Value Asset Discovery
- **Objective**: From low privilege, *identify* DCs, backup/DB/file/management servers,
  virtualization, security infra, sensitive apps — then determine the **theoretical** path.
- **Rule**: Do **not** auto-exploit everything discovered. Map, then prioritize (`docs/21`).
- **Tools**: BloodHound, DNS/SPN enumeration, share/service discovery.
- **Decision tree**: build an HVA inventory + a "what path would allow access" note per
  asset → present options to operator → validate only the chosen path.

## Scenario 16 — C2 / Command and Control
- See `docs/08` for the full dedicated methodology comparing Caldera, Sliver, Mythic,
  Havoc, Cobalt Strike (licensed), and the indicators (network/process/DNS/HTTPS/auth/
  endpoint) each produces.

## Scenario 17 — CALDERA Adversary Emulation
- See `docs/08` for installation, config, agent deployment, adversary profiles, ability
  selection, operation setup, grouping, execution, telemetry, ATT&CK mapping, detection
  validation, cleanup — and the five operation profiles (A–E).

## Scenario 18 — Purple Team
- See `docs/11` for the per-technique RED ACTION → ATT&CK → LOG SOURCE → SIEM → EDR → ALERT
  → SOC INVESTIGATION → RESPONSE pipeline and the DETECTED / PARTIAL / NOT-DETECTED method.
