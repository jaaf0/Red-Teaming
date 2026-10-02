# 13 — Defense Evasion: Detection-Coverage Catalog

In this framework, evasion is exercised **only to measure detection coverage** during
authorized purple-team work — never to actually blind defenders. This document is the
measurement catalog; the technique entries and their safe-validation table live in
`docs/09.3`, and the indicator lists each C2 produces live in `docs/08.3`. Use this page to
turn those into a coverage assessment.

**Hard rules (never violate):**
- Never disable, uninstall, downgrade, or tamper with EDR/AV/logging without explicit
  written authorization; never delete or alter defender logs.
- Anything that would leave a security control degraded (driver/BYOVD scenarios, API
  unhooking, agent tampering) is ESCALATE-only, demonstrated as a minimal
  proof-of-capability in a lab/approved host, then immediately restored. The deliverable is
  always the detection outcome, never a persistently weakened control.

## Technique families to assess (pointers, not how-to)
Covered in `docs/09.3` with their safe/benign validation and expected telemetry:
- Process/command masquerading (T1036) and command-line obfuscation (T1027).
- Living-off-the-land / signed-binary execution (T1218) and alternate launchers.
- Timestomp **simulation** (T1070.006) on throwaway test files.
- Log-visibility testing and control-response testing (does the control alert / block?).

For C2 traffic-shaping indicators (jitter, sleep, protocol choice) see `docs/08.3` — assess
those as network-detection coverage.

## Measurement method (per technique)
1. **Coordinate** with the SOC (validation mode) and pick one technique from `docs/09.3`.
2. **Run the benign variant** only (e.g. invoke a signed LOLBin on a benign action, run a
   renamed benign binary, set a test file's timestamp, run an EICAR-style AV test string).
3. **Observe every stage** of the purple pipeline (`docs/11`): endpoint log → SIEM event →
   EDR event → alert → investigable?
4. **Classify** coverage: DETECTED / PARTIALLY DETECTED / NOT DETECTED (`docs/11`).
5. If a gap: hand the indicators (process lineage, command-line, file-metadata change,
   network pattern) to detection engineering; tune/build the detection; **re-run** and
   re-classify.
6. **DOCUMENT** the before/after in the coverage map; restore any test-file attributes.

## Coverage-record schema
```json
{
  "technique": "signed-binary proxy execution",
  "technique_id": "T1218",
  "benign_validation": "<benign invocation used>",
  "endpoint_log": true,
  "siem_event": true,
  "edr_event": false,
  "alert_fired": false,
  "investigable": true,
  "coverage_verdict": "PARTIALLY DETECTED",
  "gap_notes": "process-create logged but no behavioral alert on LOLBin child chain",
  "remediation": "add detection for <parent>-><lolbin> with network egress within N s"
}
```

## Reporting
Aggregate the coverage records into the detection section of the report (`docs/99`):
factual per-technique coverage and gap analysis — no overall "best/worst" rating. The point
is a prioritized list of detection improvements, each tied to a reproducible indicator.
