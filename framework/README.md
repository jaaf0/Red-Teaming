# Advanced Red Team / Adversary Emulation Master Framework

A practical, tool-driven operating manual and **decision engine** for authorized
red team, adversary-emulation, and purple-team engagements. It is organized so
you can answer two questions at any moment:

1. **"I discovered X — what do I do next?"** → `docs/27-what-do-i-do-next.md` plus the
   per-TTP decision trees and the master decision tree (`docs/19-decision-trees.md`).
2. **"I want to simulate scenario Y — what phases, TTPs, tools, decisions, evidence,
   and detection opportunities apply?"** → `docs/05-scenario-library.md`.

> This framework is written for engagements with **explicit written authorization**
> over a **defined scope**. It is threat-informed-defense oriented: every offensive
> action is paired with detection opportunities, expected telemetry, evidence
> requirements, and cleanup. It documents techniques at a methodology/operator level
> and deliberately **does not ship weaponized exploit payloads, destructive code, or
> detection-evasion tooling for malicious use**. Sensitive techniques (credential
> dumping, memory access, impact) are described as *controlled proof-of-capability*
> with explicit stop conditions.

## How to read this

The framework is non-linear by design. Real operations are a loop:

```
Recon → Discover → Hypothesize → Validate → Update attack graph → Select next path → Validate → Objective → Cleanup
```

Every stage emits **structured results** (see `docs/23-evidence-collection.md`) that feed
the next stage and the attack graph. Never execute one giant linear chain.

## Document map (matches requested output format)

| # | Document | Purpose |
|---|----------|---------|
| 00 | `docs/00-executive-overview.md` | Executive overview + operating assumptions |
| 01 | `docs/01-rules-of-engagement.md` | ROE + Global Safety Controller |
| 02 | `docs/02-master-methodology.md` | 15-phase operational lifecycle + TTP template |
| 03 | `docs/03-ttp-library.md` | TTP library (recon → impact) |
| 04 | `docs/04-tool-matrix.md` | Toolchain mapping & selection rationale |
| 05 | `docs/05-scenario-library.md` | 18 scenario playbooks |
| 06 | `docs/06-windows-linux-ad-playbooks.md` | Host & AD playbooks (incl. AD CS) |
| 07 | `docs/07-web-api-cloud-playbooks.md` | Web/API & cloud playbooks |
| 08 | `docs/08-c2-and-caldera.md` | C2 methodology + CALDERA emulation profiles |
| 09 | `docs/09-credential-lateral-evasion.md` | Credential access, lateral movement, defense evasion |
| 10 | `docs/10-collection-exfil-impact.md` | Collection, exfiltration sim, impact sim |
| 11 | `docs/11-purple-team-and-telemetry.md` | Purple team loop, SOC telemetry matrix, Wazuh/SIEM |
| 12 | `docs/12-phase-tools-and-commands.md` | Per-phase tools + example commands reference |
| 13 | `docs/13-defense-evasion-techniques.md` | Defense-evasion detection-coverage catalog |
| 19 | `docs/19-decision-trees.md` | Master attack decision tree |
| 20 | `docs/20-attack-graphs.md` | Mermaid attack graphs |
| 21 | `docs/21-prioritization.md` | Objective attack-path prioritization |
| 23 | `docs/23-evidence-collection.md` | Evidence schema + attack log |
| 27 | `docs/27-what-do-i-do-next.md` | "What I found → next action" engine |
| 30 | `docs/30-daily-workflow.md` | Daily operating rhythm |
| 32 | `docs/32-scenario-generator.md` | Parameterized scenario generator |
| 33 | `docs/33-automation-architecture.md` | Modular automation + tool execution standard |
| 99 | `docs/99-reporting-cleanup-checklist.md` | Reporting, cleanup, final master checklist |

Configuration templates live in `config/` (`scope.yaml`, `exclusions.yaml`, `rules.yaml`).

## Non-negotiables

- No action without a scope + authorization check (Global Safety Controller, `docs/01`).
- Synthetic / canary data for all sensitive-data, exfiltration, and impact demonstrations.
- No uncontrolled credential spraying, no auto-propagation, no destructive payloads.
- Every action produces evidence; every change has a cleanup entry.
