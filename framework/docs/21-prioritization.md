# 21 — Attack-Path Prioritization (objective, not "best")

Do not rank paths as "best/worst." Score each candidate path on the factors below, then
explain the trade-offs so the operator chooses with intent. Prefer paths that are
**reliable + reversible + low-impact** for validation, escalating only with cause.

## Factors (score each 1–5; lower = more favorable unless noted)
| Factor | Meaning | Favorable |
|---|---|---|
| Prerequisite count | How many conditions must already hold | fewer |
| Required privilege | Privilege needed to start | lower |
| Exposure | How reachable the entry is | depends on goal |
| Complexity | Steps / skill / fragility | lower |
| Detection likelihood | Chance SOC observes it | depends on goal (purple: higher is useful) |
| Potential impact | Blast radius if it goes wrong | lower for validation |
| Reversibility | Can state be fully restored? | higher reversibility favored |
| Authorization requirement | Does it need extra approval? | fewer gates = faster, but gates exist for a reason |

## Scoring record (per candidate)
```json
{
  "path_id": "P-001",
  "description": "Kerberoast SVC_sql -> offline crack -> admin on SQL01 -> HVA",
  "prerequisites": ["valid domain user","reachable DC","SPN present"],
  "required_privilege": "domain user",
  "scores": {"prereq":2,"privilege":1,"exposure":3,"complexity":2,
             "detection":3,"impact":2,"reversibility":5,"authz":1},
  "tradeoffs": "Low privilege + high reversibility (offline crack, no AD change); moderate detection via TGS anomalies; success depends on weak SPN password.",
  "recommendation": "Validate first: least invasive, fully reversible, no approval gate."
}
```

## How to use
1. Enumerate all candidate edges from the attack graph.
2. Score each.
3. **Default ordering**: validate the most reliable + reversible + lowest-impact path with
   the fewest approval gates first; keep higher-impact / approval-gated paths as fallbacks.
4. For **purple-team** goals, deliberately include high-detection-likelihood paths — the
   point is to test detection, so "noisy" can be the right choice.
5. Present the ranked trade-offs to the operator; the human makes the call. Record the
   chosen path and *why* in the attack log.
