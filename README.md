# Red-Teaming

This repository contains the **Advanced Red Team / Adversary Emulation Master Framework** —
a practical, tool-driven operating manual and decision engine for **authorized** red-team,
adversary-emulation, and purple-team engagements.

➡️ Start here: [`framework/README.md`](framework/README.md)

New operators should read the guided, phase-by-phase walkthrough first:
[`framework/docs/14-step-by-step-walkthrough.md`](framework/docs/14-step-by-step-walkthrough.md).

## Layout
- `framework/README.md` — index of the whole framework.
- `framework/config/` — scope / exclusions / rules templates (the safety controller inputs).
- `framework/docs/` — methodology, TTP library, scenario playbooks, per-phase tools &
  commands, decision trees, attack graphs, purple-team telemetry, evidence, reporting.

## Scope & intent
The framework is written for engagements with **explicit written authorization** over a
**defined scope**. It is threat-informed-defense oriented: every offensive action is paired
with detection opportunities, expected telemetry, evidence requirements, and cleanup.
Sensitive techniques are described as controlled proof-of-capability with explicit stop
conditions; it ships no weaponized payloads or destructive code.
