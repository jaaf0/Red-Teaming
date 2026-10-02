# 33 — Automation Architecture & Tool-Execution Standard

Automation **discovers and proposes** the next action; it never auto-exploits every host.
High-risk actions always require explicit operator confirmation.

## Modular layout
```
redteam-framework/
  config/   scope.yaml  exclusions.yaml  rules.yaml
  modules/
    recon/        discovery/     enumeration/
    web/  smb/  ad/  windows/  linux/  cloud/  c2/
    attack_paths/ validation/    evidence/      reporting/
  orchestrator/   # safety controller + pipeline + attack-graph state
  output/
    logs/  reports/  evidence/
```

## Data flow
```
scope → recon → discovery → enumeration → attack-path engine → (operator decision) → validation → evidence → reporting
```
Each module consumes structured JSON from the previous stage and emits structured JSON +
evidence records. The attack-path engine merges results into the graph and surfaces ranked
candidate actions (`docs/21`) for the operator.

## Tool-execution standard (every module MUST implement)
- **Scope validation** — check target ∈ scope ∉ exclusions (fail-closed).
- **Input validation** — sanitize/normalize inputs; reject malformed targets.
- **Exclusion checking** — exclusions override inclusions, always.
- **Rate limiting** — honor `max_scan_rate_pps` and per-account attempt caps.
- **Timeout** + **retry** (bounded, backoff) — don't hang or hammer.
- **Error handling** — fail safe; never proceed on ambiguous scope.
- **Logging** — append-only action log.
- **JSON output** — machine-readable results for the next stage.
- **Evidence storage** — write the evidence record (`docs/23`) before acting.
- **Dry-run mode** — print intended actions without executing (default for new modules).
- **Kill switch** — abort if `rules.yaml` kill-switch file is present.

## Orchestrator rules
- Run the Global Safety Controller before dispatching any module action.
- **Propose, don't execute** high-risk steps: anything in `require_approval_for`, anything
  disruptive, anything state-changing. Queue them for operator confirmation.
- Never fan an exploit across all discovered hosts. One target, one validated step, then
  re-evaluate.
- Maintain the attack-graph state and re-prioritize after every result.

## Example automation flows (discover → propose, human validates)
```
Flow 1 (web):  nmap → parse XML → identify HTTP → httpx → identify tech → nuclei
               → potential finding → [OPERATOR] Burp/manual validation → evidence
               → attack-path engine → operator decision
Flow 2 (AD):   nmap → 445 → SMB enum → NetExec → auth info → LDAP → BloodHound
               → attack graph → potential privilege path → [OPERATOR] manual validation → evidence
Flow 3 (host): Windows host → local enum → privilege indicators → credential exposure
               → AD discovery → attack graph → lateral candidate → [OPERATOR] controlled validation
```
In every flow the automation stops at `[OPERATOR]` for confirmation before any
exploit/state-changing/approval-gated step; discovery and read-only enumeration may run
automatically within rate limits.
