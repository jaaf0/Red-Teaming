# 10 — Collection, Exfiltration Simulation & Impact Simulation

All sensitive-data and destructive concepts here are **simulated with synthetic/canary
data** and bounded by explicit stop conditions. Never move real sensitive data; never run
destructive procedures.

---

## 10.1 Collection (TA0009)
| Target | ATT&CK | Approach (non-destructive) | Evidence |
|---|---|---|---|
| Files / shares | T1083 / T1135 | enumerate names/ACLs; read only canary files | share list, ACLs |
| Databases | T1213 | list DBs/tables; read a seeded test row | schema, test row |
| Email / docs | T1114 / T1083 | locate mailbox/doc stores; access test item | location proof |
| Cloud storage | T1530 | list buckets/objects; read canary object | listing, canary read |
| Browser data | T1555.003 | authorized host; proof-of-capability | capability proof |
| Screenshots | T1113 | capture non-sensitive screen as proof | image |
| System info | T1082 | native host info | output |

- **Decision tree**: IF real sensitive data located THEN prove **access** via a canary /
  metadata only → DOCUMENT location + permission → STOP (do not collect content). Route to
  exfiltration simulation.

## 10.2 Exfiltration Simulation (TA0010) — canary only
Stage → compress → **controlled transfer of a marked synthetic file** → detection → cleanup.

| Channel | ATT&CK | What defenders should detect | Logs that should exist | Evidence |
|---|---|---|---|---|
| HTTPS | T1041 / T1567 | large/anomalous egress, rare dest | proxy/DLP, netflow | hash, dest, time |
| SFTP | T1048 | outbound SFTP to new host | firewall/netflow | transfer log |
| Cloud storage | T1567.002 | upload to personal/cloud store | proxy, cloud API | API log |
| Approved C2 | T1041 | beacon + data-sized responses | EDR/network | C2 log |
| DNS (detection sim) | T1048.001 | high-volume/high-entropy DNS | DNS logs | query log |

- **Decision tree**: pick one channel → transfer the canary → check whether DLP/proxy/DNS
  logging detected it → DOCUMENT expected vs observed → repeat per channel as time allows.
- **Canary design**: uniquely marked, non-sensitive, hash-tracked; register the marker so
  the blue team can confirm detection. **Cleanup**: delete staged archives at source and
  destination; record canary IDs and hashes.

## 10.3 Impact Simulation (TA0040) — safe, bounded, reversible
| Impact | ATT&CK | How to SIMULATE | Where to STOP | Logs to monitor |
|---|---|---|---|---|
| Ransomware | T1486 | encrypt ONE synthetic file in sandbox, reversible key | before real data / shadow-copy deletion | ransomware canaries, mass-rename, VSS-delete attempts |
| Data destruction | T1485 | prove delete *permission* on a canary; do not delete real data | before any real deletion | file-delete auditing |
| Service disruption | T1489 | identify stoppable service + permission; do not stop prod | before stopping a real service | service-stop events |
| Account lockout | T1531 | demonstrate the *capability*; never actually lock accounts | before locking a real account | account-mgmt events |
| Resource exhaustion | T1499 | lab-only, bounded, approved window | before any prod load | perf/availability metrics |
| Backup deletion | T1490 | prove read/list/delete *permission* on backups | before deleting any backup | backup API/audit logs |

- **Decision tree**: for every impact, demonstrate the **access/permission** that would
  enable it (read/list/stop-permission), produce evidence of the capability, and **STOP
  before the irreversible call**. ESCALATE for each.
- **Evidence**: capability proof (permission/reach), sandbox artifacts, the exact stop point,
  timestamps. **Cleanup**: decrypt/remove synthetic files, remove markers, confirm the
  environment is untouched beyond the sandbox.
