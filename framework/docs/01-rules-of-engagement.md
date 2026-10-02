# 01 — Rules of Engagement & Global Safety Controller

## Phase 0 artifacts (must exist before Phase 1)
- Signed authorization / SOW referencing the scope.
- `config/scope.yaml`, `config/exclusions.yaml`, `config/rules.yaml` filled in.
- Operator egress IPs registered; emergency client contact + abort procedure agreed.
- Agreed stop conditions, handling of accidental out-of-scope discovery, and data
  handling (synthetic-only; what to do if real sensitive data is encountered).

## Global Safety Controller (run before EVERY action)
Ordered checks — fail-closed (any failure blocks the action):

1. **Scope match** — target ∈ `in_scope` (domains/cidrs/hosts/cloud/apps)?
2. **Exclusion check** — target ∉ `exclusions` (exclusions override inclusions)?
3. **Authorization window** — current time ∈ engagement window?
4. **Technique authorized** — is the technique in `require_approval_for`? If yes,
   STOP and obtain explicit operator/client approval, recorded.
5. **Disruptive check** — could this cause outage, lockout, data change? If disruptive
   and `allowed_disruptive: false` ⇒ block.
6. **Rate limit** — within scan-rate and per-account attempt caps?
7. **Record** — write the evidence record (`docs/23`) *before* acting.
8. **Kill switch** — if `/var/run/redteam.STOP` exists ⇒ halt.

## Never (hard rules)
- Attack out-of-scope infrastructure.
- Destroy or permanently modify data/systems without explicit authorization.
- Deploy uncontrolled ransomware or any destructive payload.
- Cause uncontrolled denial of service.
- Disable EDR/AV/logging or any security control without explicit authorization.
- Delete or tamper with evidence or logs.
- Perform uncontrolled credential attacks / password spraying / cause lockouts.
- Auto-propagate across the environment.
- Exfiltrate real sensitive data when synthetic data can prove the point.

## Sensitive techniques → controlled proof-of-capability
For credential dumping, memory credential access, persistence, impact, and
exfiltration: obtain approval, perform the **minimum** demonstration (e.g. prove read
access to a canary, retrieve one controlled secret, encrypt one synthetic file),
capture evidence, then stop and clean up. Never run these broadly or automatically.

## Accidental out-of-scope / real-sensitive-data discovery
STOP the action, do not pivot further, record what happened and where, notify the
client contact, and follow the agreed handling procedure. Do not copy or retain real
sensitive data.
