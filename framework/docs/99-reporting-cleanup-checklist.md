# 99 — Reporting, Cleanup & Final Master Checklist

## Reporting
Deliver two linked views: the **attack narrative** (how an objective was reached) and the
**detection-coverage map** (what the SOC saw). Structure:
1. **Executive summary** — objectives, outcomes, business risk, top themes (no jargon).
2. **Scope & authorization** — what was in/out, window, constraints.
3. **Methodology** — phases actually used (reference this framework).
4. **Attack paths** — per objective: the graph, steps, evidence, ATT&CK IDs.
5. **Findings** — each with: description, affected assets, ATT&CK mapping, risk rating +
   rationale, reproduction (redacted), evidence refs, remediation.
6. **Detection & response coverage** — per technique DETECTED / PARTIAL / NOT DETECTED with
   log-source/alert notes and gap analysis (`docs/11`); factual, no overall "best/worst".
7. **Remediation roadmap** — prioritized, actionable, mapped to findings.
8. **Appendices** — attack log, ATT&CK heatmap, tool list, evidence index, canary IDs.

Secrets: reference by account/strength; never print plaintext in the report body.

## Cleanup (verified, nothing left behind)
- [ ] Every `cleanup_required: true` evidence record has a matching completed cleanup record.
- [ ] All dropped tools/binaries/scripts removed from every touched host.
- [ ] All webshells / uploaded files / markers removed (web + hosts).
- [ ] All created services/scheduled tasks/cron/systemd units deleted.
- [ ] All ACL / group / object / GPO changes reverted.
- [ ] All test certificates revoked (AD CS); all created cloud keys/roles revoked.
- [ ] All C2 agents killed; listeners/redirectors torn down.
- [ ] All synthetic/canary files decrypted/removed; exfil staging deleted at source + dest.
- [ ] All sessions/tickets closed/purged; no persistence remains (verify, don't assume).
- [ ] Logs **not** tampered with (we never delete defender logs).
- [ ] Client notified of anything that could not be fully cleaned (with details).

## Final master checklist (engagement lifecycle)
- [ ] **Phase 0** signed authorization + scope/exclusions/rules YAML loaded & validated.
- [ ] Egress IPs registered; abort contact + kill switch agreed.
- [ ] **Recon → Surface mapping** completed within rate limits; asset inventory produced.
- [ ] **Initial access** achieved or documented as not achievable (valid outcome).
- [ ] **Foothold** stabilized; situational awareness captured.
- [ ] **C2** (if emulating) deployed on in-scope hosts; IoCs documented.
- [ ] **Discovery** feeding the attack graph continuously.
- [ ] **PrivEsc / Credential Access** — least-impact first; approval gates honored; no spraying.
- [ ] **Lateral movement** — validated, no auto-spread; graph updated each hop.
- [ ] **Objective discovery** — HVAs mapped; theoretical paths noted, not auto-exploited.
- [ ] **Controlled objective simulation** — synthetic/canary only; stopped at proof.
- [ ] **Detection validation** — coverage map complete (DETECTED/PARTIAL/NOT).
- [ ] **Evidence** — every action recorded; artifacts hashed and indexed.
- [ ] **Cleanup** — full checklist above completed and verified.
- [ ] **Reporting** — narrative + coverage delivered; remediation roadmap included.
- [ ] **Debrief** — purple-team readout; detection gaps handed to detection engineering.

## Golden rules (never violate)
1. No action without a passing Global Safety Controller check.
2. Synthetic/canary data for all sensitive-data, exfil, and impact work.
3. No uncontrolled credential attacks, no lockouts, no auto-propagation.
4. No destructive payloads; impact is simulated and reversible.
5. Never disable security controls or tamper with evidence/logs without explicit authorization.
6. Prove, don't abuse — minimum demonstration, then STOP, DOCUMENT, and clean up.
