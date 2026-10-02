# 02 — Master Methodology: Operational Lifecycle & TTP Template

## The 15-phase lifecycle
Phases are **selected, not mandatory**. The decision trees (`docs/19`) choose which
apply. Each phase takes INPUT, produces OUTPUT that feeds the attack graph, and names
decision points.

| Phase | Name | Input | Objective | Primary tools | Output → Next |
|---|---|---|---|---|---|
| 0 | Rules of Engagement | SOW | Authorize + bound scope | scope/exclusions/rules YAML | Approved scope → 1 |
| 1 | Recon | Scope | Enumerate attack surface (passive→active) | amass, subfinder, crt.sh, dnsx, shodan | Asset inventory → 2 |
| 2 | Attack Surface Mapping | Assets | Port/service/app map | nmap, naabu, httpx, nuclei | Service map → 3 |
| 3 | Initial Access | Service map | Gain first foothold (least-impact branch) | per-vector playbooks | Foothold → 4 |
| 4 | Foothold | Access | Stabilize, situational awareness | native tooling | Stable access → 5/6 |
| 5 | C2 | Foothold | Establish control channel (if emulating) | Caldera, Sliver, Mythic | Managed agent → 6 |
| 6 | Discovery | Access | Host/identity/network enumeration | native + BloodHound/NetExec | Graph data → 7/9 |
| 7 | Privilege Escalation | Local context | Raise privilege (controlled) | WinPEAS/linPEAS, PowerUp | Higher priv → 8 |
| 8 | Credential Access | Priv/host | Obtain usable credentials (approved) | Impacket, Kerberos tooling | Creds → 9 |
| 9 | Lateral Movement | Creds/paths | Reach new hosts via valid auth | NetExec, WinRM, SSH | New access → 6/10 |
| 10 | Objective Discovery | Access | Locate high-value assets | BloodHound, share enum | HVA list → 11 |
| 11 | Controlled Objective Simulation | HVA | Prove impact safely (canary) | synthetic payloads | Proof → 12 |
| 12 | Detection Validation | All actions | Compare expected vs observed telemetry | SIEM/EDR, Wazuh | Coverage map → 14 |
| 13 | Cleanup | Change log | Restore original state | per-action cleanup | Clean env → 14 |
| 14 | Reporting | Evidence | Deliver findings + detection gaps | report templates | Report |

Phases 6–9 **loop**: each new credential/host updates the graph and may re-trigger
discovery and re-prioritization before the next move.

## Universal TTP template
Every TTP in the library (`docs/03`, `06`–`10`) is written in this exact structure:

- **TTP** — human name.
- **ATT&CK Mapping** — Technique ID, Sub-technique ID, Technique name.
- **Objective** — what the adversary achieves.
- **Preconditions** — what must already exist.
- **Required Access** — external / compromised workstation / valid creds / local admin
  / domain user / domain admin / server / VPN / cloud creds.
- **Primary Tools** / **Alternative Tools** / **Native / LOLBin options**.
- **Execution Workflow** — numbered, least-impact first.
- **Decision Tree** — `IF / THEN / ELSE / FALLBACK / STOP / ESCALATE`.
- **Validation** — how you know it actually worked.
- **Evidence** — timestamps, command output, hosts, users, hashes, URLs, screenshots.
- **Detection Opportunities** — what defenders may observe.
- **SOC Telemetry** — ideal log sources/events.
- **Cleanup** — how to restore original state.
- **Risk** — LOW / MEDIUM / HIGH / CRITICAL + why.
- **Next Step** — where the output routes in the graph.

## Reading the decision-tree grammar
- `IF <observation> THEN <action>` — conditional branch.
- `ELSE / FALLBACK` — alternate when the branch fails.
- `STOP` — hard stop (safety/scope) — do not proceed.
- `ESCALATE` — requires operator/client approval before proceeding.
- `VALIDATE` — confirm the result before treating it as true.
- `DOCUMENT` — write evidence now.
