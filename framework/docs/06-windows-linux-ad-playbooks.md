# 06 — Windows, Linux & Active Directory Playbooks

Methodology + safe enumeration. Exploitation steps are described as controlled validation;
no weaponized payloads. Every escalation/change has a cleanup entry.

---

## 6.1 Windows host playbook

### Enumeration (read-only, LOLBin first)
| Area | Native / LOLBin | Tool | Routes to |
|---|---|---|---|
| Identity & privileges | `whoami /all`, `whoami /priv` | Seatbelt | token-priv branch |
| Local users/groups | `net user`, `net localgroup administrators` | — | local-admin check |
| Services | `sc query`, `wmic service` | PowerUp (Get-ServiceUnquoted etc.) | service-misconfig |
| Scheduled tasks | `schtasks /query /v` | — | task-weakness |
| Installed software | registry uninstall keys | Seatbelt | vuln-software |
| Stored secrets | `cmdkey /list`, registry, unattend.xml, DPAPI | LaZagne (authz) | credential access |
| Network/domain | `ipconfig /all`, `nltest /dsgetdc:`, `net view` | — | AD discovery |
| Security products | services/processes (EDR/AV) | Seatbelt | `docs/27` "EDR detected" |

### Privilege-escalation candidates → validation order (reliability × reversibility)
1. **Stored credentials** (T1552) — least invasive; validate by using a found cred once.
2. **Token privileges** (SeImpersonate/SeAssignPrimaryToken, T1134) — controlled PoC via a
   named potato-class technique only with approval; reversible (no file changes).
3. **Weak service ACL / unquoted path** (T1543.003 / T1574) — DOCUMENT the misconfig; only
   demonstrate by a reversible, approved change; **restore the service config after**.
4. **Scheduled task weakness** (T1053.005) — same: demonstrate then revert.
5. **Insecure file permissions on privileged binaries** — DOCUMENT; demonstrate minimally.
6. **Vulnerable software / UAC-bypass scenarios** (T1548.002) — ESCALATE; proof-of-concept.

- **Decision tree**: enum → pick #1 if present → VALIDATE → DOCUMENT → re-enter Discovery;
  ELSE next. IF none viable THEN pivot to AD path or lateral movement.
- **Telemetry**: process-create w/ cmdline, service/task creation, token manipulation,
  LSA-process access. **Cleanup**: revert every service/task/ACL change; remove dropped
  tools; clear only artifacts you created (never tamper with existing logs).

### Branch after local admin
→ Credential Access (`docs/09`, approval-gated) · → Lateral Movement · → Persistence
(authorized host only) · → Domain path (SharpHound).

---

## 6.2 Linux host playbook

### Enumeration (read-only)
| Area | Native | Tool | Routes to |
|---|---|---|---|
| OS/kernel | `uname -a`, `/etc/os-release` | linPEAS | kernel-vuln (last resort) |
| Sudo | `sudo -l` | — | sudo-misconfig (GTFOBins-style) |
| SUID/SGID | `find / -perm -4000 -type f 2>/dev/null` | linPEAS | SUID branch |
| Capabilities | `getcap -r / 2>/dev/null` | — | capability branch |
| Cron | `cat /etc/crontab`, `/etc/cron.*`, `crontab -l` | — | cron branch |
| Systemd | `systemctl list-units`, writable unit files | — | writable-unit branch |
| Docker/K8s | `id` (docker group), `/var/run/docker.sock`, `kubectl auth can-i` | — | container-escape branch |
| Secrets | configs, `.env`, history, keys in `~/.ssh` | — | credential access |
| Mounts/net | `mount`, `ss -tulpn`, `ip a` | — | lateral candidates |

### Privilege-escalation candidates (validate with least-impact first)
- **sudo misconfig** (T1548.003): IF `sudo -l` shows an exploitable binary/NOPASSWD THEN
  validate via the documented GTFOBins technique (reversible).
- **SUID/SGID** (T1548.001): IF a known-abusable SUID binary THEN controlled PoC.
- **Capabilities** (e.g. cap_setuid on an interpreter): controlled PoC.
- **Writable cron/systemd**: demonstrate with a benign marker command, then **remove it**.
- **Docker socket / docker group**: controlled host-access PoC; STOP before persistence.
- **Stored creds / SSH keys** (T1552.004): validate one auth to a reachable host.
- **Kernel/software vulns**: last resort, ESCALATE (stability risk).

- **Decision tree**: `docs/19` Linux subtree. VALIDATE → DOCUMENT → re-enter Discovery.
- **Telemetry**: auditd execve, sudo logs, new cron/systemd units, docker/k8s API, SSH auth.
- **Cleanup**: remove any cron/unit/marker you added; delete dropped tools; note file mtimes.

---

## 6.3 Active Directory playbook

### Collection
- **SharpHound** (on-host) or **bloodhound-python** (remote with DU creds) → ingest into
  **BloodHound**. Collect sessions, local-admin, ACLs, trusts, GPOs, cert templates.
- Native/quiet: PowerShell AD module, `nltest`, `setspn -Q`, `Get-ADUser/Group/Computer`.

### Analysis → path selection (BloodHound queries)
- Shortest path to Domain Admins / Tier-0.
- Kerberoastable accounts (SPNs) and AS-REP-roastable accounts.
- Principals with DCSync rights (GetChanges/GetChangesAll).
- Dangerous ACLs (GenericAll/WriteDACL/WriteOwner, AddMember, ForceChangePassword).
- Computers where owned principal is local admin; active sessions of privileged users.

### Controlled technique branches (each: validate minimally, approval for the sensitive ones)
- **Kerberoasting** (T1558.003): `GetUserSPNs.py` → crack **offline**. LOW network impact.
- **AS-REP roasting** (T1558.004): `GetNPUsers.py` → crack offline.
- **ACL abuse** (T1222/T1098): IF WriteDACL/GenericAll over a target THEN demonstrate the
  grant on a **test object** or with a reversible change, then **revert**. ESCALATE for
  changes to privileged objects.
- **Delegation abuse** (unconstrained/constrained/RBCD, T1558/T1550): map reachability;
  controlled validation; ESCALATE.
- **DCSync** (T1003.006): **explicit approval only**; prove the right exists, perform a
  minimal replication of a single non-privileged test account to demonstrate capability,
  STOP. Highly detectable — that is a purple-team win.
- **Trusts** (T1482): enumerate inter/intra-forest trusts; determine theoretical cross-trust
  paths; validate only the approved one.

- **Decision tree**: graph → prioritize (`docs/21`) → validate least-risk edge → DOCUMENT →
  re-collect (environment changed) → repeat until objective or no viable edge.
- **Telemetry**: LDAP recon volume, TGS/TGT request anomalies (roasting), directory
  object-change events (ACL/group), replication requests from non-DC (DCSync), abnormal
  cert enrollment.
- **Cleanup**: revert every ACL/group/object change; revoke test certs; remove collectors.

### AD CS sub-playbook → see Scenario 6 (`docs/05`). Certipy `find` → classify misconfig →
controlled validation → revoke test cert → DOCUMENT.
