# 00 — Executive Overview & Operating Assumptions

## Executive overview
This framework operationalizes **threat-informed defense**: it drives authorized
offensive operations while simultaneously producing the detection, telemetry, and
evidence artifacts a blue team and SOC need to improve. It is built on **MITRE
ATT&CK** as the common language, **adversary emulation** as the method, and
**purple-team validation** as the feedback loop.

It is not a single linear attack. It is a **decision engine**: a library of TTPs,
scenario playbooks, decision trees, and a "what-do-I-do-next" matrix, bound together
by a safety controller and an evidence pipeline. The operator forms a hypothesis,
validates the smallest safe proof, records evidence, updates the attack graph, and
selects the next path.

## Who uses it
Red team operators, adversary-emulation specialists, purple-team engineers, and
detection engineers working an **authorized** engagement with a signed scope.

## Operating assumptions
- **Authorization is explicit and documented.** No scope file (`config/scope.yaml`)
  loaded and validated ⇒ no action.
- **Scope can change.** Re-validate before every action; exclusions always win.
- **The environment changes after every action.** Treat each result as new input.
- **Prove, don't abuse.** For sensitive capabilities, demonstrate the minimum proof
  and stop. Use synthetic/canary data for anything resembling sensitive data.
- **Detection is a deliverable, not a side effect.** Every TTP records expected vs.
  observed telemetry so gaps become findings.
- **Least-impact first.** Prefer read-only enumeration and native tooling over noisy
  or state-changing actions; escalate only with cause and (where required) approval.

## What "success" means
A documented, reproducible attack path to an objective **and** a detection-coverage
map (DETECTED / PARTIALLY DETECTED / NOT DETECTED) for every technique used, with
evidence and cleanup recorded for each step.

## Core loop
```
          ┌──────────────────────────────────────────────┐
          v                                              │
  Recon → Discover → Hypothesize → Validate (min proof) → Evidence
          │                                              │
          └── Update attack graph → Prioritize paths ────┘
                         │
                         └── Select next path → (loop) → Objective → Cleanup → Report
```
