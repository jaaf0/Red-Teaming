# 09 — Credential Access, Lateral Movement & Defense Evasion (detail)

---

## 9.1 Credential Access (approval-gated; no spraying, no lockouts)

| Technique | ATT&CK | Prereq | Risk | Safe validation | Detection | Evidence | Cleanup |
|---|---|---|---|---|---|---|---|
| Creds in files/config | T1552.001 | shell | LOW | grep configs/history | file-read auditing | path + redacted sample | none |
| API keys / tokens | T1552 | file/web access | MED | one minimal authorized call | app/cloud audit logs | redacted key, response | revoke if created |
| SSH keys | T1552.004 | shell | MED | one auth to reachable host | sshd auth logs | key path, host | none |
| Password policy read | — | DU | LOW | `net accounts`, PSOs | — | policy snapshot | none |
| Kerberoast | T1558.003 | DU | LOW-MED | request SPN tix, crack offline | TGS-request anomalies | ticket meta, account | none |
| AS-REP roast | T1558.004 | DU | LOW-MED | request AS-REP, crack offline | AS-REP request anomalies | ticket meta | none |
| LLMNR/NBT-NS poisoning | T1557.001 | L2 + **approval** | HIGH | Responder, scoped + time-boxed | poisoned-response/auth logs | captured hash meta | stop capture |
| Credential dumping | T1003.* | LA/**approval** | CRIT | PoC on ONE host, no mass harvest | LSA-process access, SAM handle | proof screenshot | delete dumps |
| Browser creds | T1555.003 | user ctx/**approval** | HIGH | PoC on authorized host | credential-store access | proof | remove extracts |
| DCSync | T1003.006 | repl rights/**approval** | CRIT | replicate ONE test acct | replication from non-DC | proof | none |

- **Lockout guard (always on)**: read the policy first; ≤1 attempt per account per window;
  never approach the lockout threshold. Prefer **offline** cracking (hashcat/john) so
  attacks stay off the target network.
- **Report hygiene**: reference recovered credentials by account + strength, not plaintext,
  in the report body; store secrets only in the encrypted evidence vault.

## 9.2 Lateral Movement (per-method; no auto-spread)
For each: Prerequisites → Discovery → Authentication → Authorization → Execution →
Telemetry → Detection → Cleanup.

| Method | ATT&CK | Prereq | Auth | Telemetry / Detection | Cleanup |
|---|---|---|---|---|---|
| SMB / admin shares | T1021.002 | creds admin on target | NTLM/Kerberos | logon type 3, share access, service-install (psexec) | remove service/file |
| WinRM | T1021.006 | creds + 5985/5986 | Negotiate/Kerberos | WinRM op log, PS logs | end session |
| RDP | T1021.001 | creds + 3389 | — | logon type 10, session events | log off |
| WMI | T1047 | creds + DCOM/135 | — | WMI-Activity, process-create | remove subscription |
| Remote service create | T1569.002 | admin | — | service-install event | delete service |
| SSH | T1021.004 | key/creds + 22 | — | sshd auth, auditd | close session |
| DCOM | T1021.003 | admin + DCOM | — | process-create via DCOM | — |
| Pass-the-Hash | T1550.002 | NT hash/**approval** | NTLM | logon type 3, NTLM-only auth | — |
| Pass-the-Ticket | T1550.003 | ticket/**approval** | Kerberos | ticket anomalies | purge tickets |
| Overpass-the-hash | T1550 | hash/**approval** | Kerberos | TGT request anomalies | — |
| DB links | — | DB creds | SQL auth | SQL audit, xp_cmdshell use | disable anything enabled |

- **Decision tree**: query BloodHound for *where creds are admin* → pick highest-value
  reachable host with the most reliable method → single authenticated command to confirm →
  DOCUMENT → re-enter Discovery on the new host. IF access denied THEN try alternate
  protocol; IF all denied THEN pick another edge from the graph. Never loop over all hosts.

## 9.3 Defense Evasion (controlled; measure detection, don't blind defenders)
For each: Purpose · Detection opportunity · Expected telemetry · Risk · Safe validation.

| Technique | ATT&CK | Purpose (what we measure) | Expected telemetry | Safe validation |
|---|---|---|---|---|
| Process masquerading | T1036.005 | Does EDR catch name/path spoof? | process image/path mismatch | benign renamed binary |
| Cmd-line obfuscation | T1027.010 | Do PS/cmd logs still parse intent? | script-block logs, AMSI | benign obfuscated echo |
| LOLBins / signed binaries | T1218 | Are living-off-the-land execs flagged? | process-create lineage | benign LOLBin invocation |
| Alternate execution paths | T1218 | Coverage of non-standard launchers | process telemetry | benign run |
| Timestomp **simulation** | T1070.006 | Is file-time tampering detected? | file-metadata change events | on a throwaway test file |
| Log-visibility testing | — | Which actions produce NO log? | absence of expected events | run action, check SIEM |
| Control-response testing | — | How does EDR respond (alert/block)? | EDR alert/quarantine | benign EICAR-style test |

- **Hard rule**: never disable EDR/AV/logging without explicit authorization. The
  deliverable is the **detection gap** (DOCUMENT detected/partial/not), never a persistent
  evasion. **Risk**: MEDIUM. **Cleanup**: restore any file times/attributes you changed on
  test files; remove test binaries.
