# 11 — Purple Team, SOC Telemetry Matrix & Wazuh/SIEM Validation

---

## 11.1 Purple-team pipeline (per technique)
```
RED TEAM ACTION → EXPECTED ATT&CK TECHNIQUE → EXPECTED LOG SOURCE →
EXPECTED SIEM EVENT → EXPECTED EDR EVENT → EXPECTED ALERT →
SOC INVESTIGATION → RESPONSE
```
Run each technique with the SOC aware (for validation runs), then compare expected vs
observed at every stage.

### Determining coverage (factual, not "best/worst")
- **DETECTED** — expected alert fired, SOC could investigate from available telemetry.
- **PARTIALLY DETECTED** — telemetry/log existed but no alert, OR alert without enough
  context to investigate, OR only one of several stages fired.
- **NOT DETECTED** — no relevant telemetry/alert at any stage.

Record per technique: {technique_id, log_source_present?, siem_event?, edr_event?,
alert_fired?, investigable?, response_taken, coverage_verdict, gap_notes}. Do not assign an
overall "best/worst" rating — report factual coverage per technique and aggregate counts.

### Purple-team loop
```
Pick technique → notify SOC (validation mode) → execute (safe) → observe each stage →
classify coverage → if gap: hand detection-engineering the indicators (docs/08, docs/27) →
rebuild/tune detection → re-run → re-classify → DOCUMENT.
```

## 11.2 SOC Telemetry Matrix
Columns: Endpoint · Network · Authentication · DNS · Proxy · Firewall · SIEM · EDR ·
Expected Alert. (Event *names* described generically; verify exact IDs in the target env —
see 11.3.)

| TTP | Endpoint | Network | Auth | DNS | Proxy | Firewall | SIEM correlation | EDR | Expected alert |
|---|---|---|---|---|---|---|---|---|---|
| PowerShell exec | script-block/module logs, AMSI | — | — | — | — | — | suspicious PS + download | behavioral | malicious PS |
| SMB lateral | share/service-install | SMB flows | logon type 3 | — | — | east-west SMB | remote-exec | psexec-style exec |
| RDP lateral | session events | 3389 flows | logon type 10 | — | — | new RDP path | — | anomalous RDP |
| WinRM | WinRM op log | 5985/5986 flows | Negotiate auth | — | — | WinRM from non-admin host | remote-exec | WinRM abuse |
| Kerberos roast | — | — | TGS requests | — | — | many TGS for SPNs | — | Kerberoasting |
| LDAP recon | — | LDAP flows | — | — | — | high LDAP query volume | — | AD recon burst |
| DNS C2/exfil | — | — | — | high-entropy/volume queries | — | — | — | DNS tunneling |
| HTTP/S C2 | proc lineage | beacon periodicity | — | — | rare dest, fixed URI | — | beaconing | C2 behavior | beaconing |
| SSH | auditd | 22 flows | sshd auth | — | — | — | new SSH path | — | anomalous SSH |
| Service creation | service-install | — | — | — | — | — | new service | behavioral | suspicious service |
| Scheduled task | task-create/op log | — | — | — | — | — | new task | behavioral | persistence task |
| Credential access | LSA-process access, SAM handle | — | — | — | — | — | LSA access | LSASS access | credential dumping |
| C2 beacon (generic) | proc + net | periodic small POSTs | — | NRD lookups | new-domain | egress to NRD | beacon + NRD | C2 | C2 channel |

## 11.3 Wazuh / SIEM validation
Wazuh may be present; this section is tool-agnostic but Wazuh-aware. **Do not invent exact
event IDs** — confirm them in the target environment before asserting coverage.

For each TTP, document:
- **What Wazuh may observe** — which decoders/rulesets (Sysmon integration, Windows
  Security channel, auditd, osquery, FIM) would carry the signal.
- **Relevant Windows/Linux telemetry** — e.g. Windows process-creation + PowerShell
  script-block channels; Linux auditd execve + sudo; FIM for file changes.
- **What event type should exist** — described by meaning (process creation with command
  line, service install, remote logon, LDAP query volume), to be mapped to the env's real
  IDs/decoders.
- **What correlation could be created** — e.g. "process-create spawning encoded PowerShell
  that also makes an outbound connection within N seconds."
- **What evidence to capture** — raw event JSON, rule ID that fired (or none), timestamp,
  agent/host.
- **If no telemetry appears** — investigate in order: (1) is the log source enabled on the
  host? (2) is the Wazuh agent forwarding that channel? (3) is there a decoder/rule for it?
  (4) is the action actually producing a log at all (log-visibility gap)? Record which layer
  is missing — that *is* the finding.

### Example (PowerShell execution)
- Observe: Sysmon process-create + Windows PowerShell script-block channel via Wazuh agent.
- Should exist: process-creation event with full command line; script-block content event.
- Correlation: encoded/`-enc` PowerShell + network connection + unusual parent.
- Evidence: both raw events, firing rule ID or absence, host, time.
- If missing: check script-block logging GPO → agent channel subscription → rule coverage.
