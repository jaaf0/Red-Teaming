# 23 — Evidence Collection & Attack Log

Every action produces a structured record **before** (intent) and **after** (result).
Evidence is the backbone of both the report and the attack-graph state.

## Per-action evidence record (write before acting, complete after)
```json
{
  "timestamp": "2026-10-02T14:03:22Z",
  "operator": "opname",
  "target": "host-or-url",
  "source_ip": "your-egress-ip",
  "technique": "Kerberoasting",
  "technique_id": "T1558.003",
  "tool": "impacket GetUserSPNs.py",
  "command": "<exact command, secrets redacted>",
  "result": "3 SPN tickets retrieved for offline cracking",
  "impact": "none (read-only request)",
  "telemetry_expected": "TGS-request anomaly / Kerberoasting alert",
  "telemetry_observed": "pending purple-team confirmation",
  "evidence_path": "evidence/2026-10-02/kerberoast/",
  "cleanup_required": false
}
```

## Attack log (human-readable timeline)
| Time | Target | Action | TTP | Tool | Result | Evidence | Detection | Next action |
|---|---|---|---|---|---|---|---|---|
| 14:03Z | DC01 | Kerberoast | T1558.003 | GetUserSPNs | 3 tickets | kerberoast/ | pending | offline crack |
| 14:20Z | — | crack hash | — | hashcat | SVC_sql recovered | hash/ | n/a | check admin rights |
| 14:35Z | SQL01 | auth check | T1078 | NetExec | local admin | netexec/ | logon type 3 | enum SQL01 |

## Maintaining evidence through the engagement
- **Store immutably**: one directory per day/technique; keep raw tool output (nmap XML,
  BloodHound ZIP, pcaps, request/response), screenshots with timestamps, and the JSON record.
- **Redact secrets** in records/reports; keep plaintext secrets only in an encrypted vault,
  referenced by ID.
- **Chain of custody**: note who collected, when, from where; hash large artifacts.
- **Link to the graph**: each record's result updates attack-graph nodes/edges and may
  trigger re-prioritization (`docs/21`).
- **Cleanup linkage**: any record with `cleanup_required: true` must have a matching cleanup
  record before the engagement closes (see `docs/99`).
- **Synthetic-data marker**: for collection/exfil/impact records, note the canary ID so the
  blue team can confirm detection and so nothing real was touched.
