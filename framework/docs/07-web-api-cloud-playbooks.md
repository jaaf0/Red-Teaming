# 07 — Web / API & Cloud Playbooks

Authorized testing only. Prefer non-destructive proof; ESCALATE before any state change or
anything that could reach production data. Use synthetic data for any data demonstration.

---

## 7.1 Web application playbook

### Phase W1 — Application & endpoint discovery
- **Tools**: httpx, Burp Suite (spider/crawl), ffuf/feroxbuster (content discovery),
  Katana. Collect: routes, params, auth flows, JS-referenced endpoints, hidden dirs.
- **Decision tree**: IF SPA/JS-heavy THEN parse JS for API routes; IF classic app THEN
  content-discovery wordlists; map auth boundaries before testing.

### Phase W2 — Authentication testing
- Session handling, password reset, MFA enforcement, JWT handling, SSO flows, default/weak
  credentials (single attempt per account — no spraying).
- **Decision tree**: IF JWT THEN inspect alg/claims (none-alg, weak secret — validate
  offline); IF reset flow THEN check token predictability; ELSE move to authz.

### Phase W3 — Authorization testing (IDOR / BOLA / privilege)
- Horizontal (other users' objects) and vertical (role) checks with two test accounts.
- **Decision tree**: IF object IDs enumerable THEN test access to a **test account's** object
  (never a real user's data); IF role-bypass THEN demonstrate on test role; DOCUMENT.

### Phase W4 — Injection classes
- SQLi, NoSQLi, command injection, template (SSTI), LDAP, XXE, deserialization, header/host.
- **Decision tree**: IF candidate THEN confirm with a **safe, non-destructive** proof (e.g.
  boolean/time-based read, `version()`), never `DROP`/write; IF RCE-class confirmed THEN
  minimal command (`id`/`whoami`) → web-to-host pivot (W8). ESCALATE before anything
  writing to a DB.

### Phase W5 — File handling
- Upload (webshell/polyglot), path traversal, LFI/RFI, arbitrary read/write.
- **Decision tree**: IF upload executes THEN drop a uniquely-named benign marker → confirm
  exec → DOCUMENT → remove it immediately. Never leave a shell in place.

### Phase W6 — Server-side vulns & exposed secrets
- SSRF, request smuggling, exposed `.git`/backups/config, API keys in responses/JS.
- **Decision tree**: IF exposed secret THEN validate minimally (W7/cloud) + ESCALATE.

### Phase W7 — SSRF → cloud metadata (where authorized)
- **Decision tree**: IF SSRF confirmed THEN first read a benign internal endpoint to prove
  reach; IF cloud metadata endpoint reachable THEN read a **non-secret** field to confirm;
  STOP and ESCALATE before retrieving credentials/role tokens. DOCUMENT the SSRF reach and
  the metadata exposure as the finding — credential retrieval is a separate approved step.

### Phase W8 — Web-to-host pivot & internal service discovery
- From confirmed exec or SSRF reach: identify host context, internal subnets, reachable
  services → feed internal discovery (`docs/06`). Controlled, minimal.
- **Branches recap**: {SSRF→metadata→cloud} | {upload→exec→host} | {authz bypass→data} |
  {exposed secret→valid account→Scenario 4}.
- **Telemetry (all web phases)**: WAF alerts, app error logs, anomalous params, egress from
  web host, cloud metadata access logs. **Evidence**: requests/responses (redacted),
  payloads, screenshots. **Cleanup**: remove uploads/markers, revert test data.

---

## 7.2 API playbook
- Enumerate endpoints (spec files: swagger/openapi, GraphQL introspection), authn/authz
  per endpoint, mass assignment, rate-limit/BOLA/BFLA, excessive data exposure, injection.
- **Decision tree**: IF GraphQL introspection enabled THEN map schema → test field-level
  authz; IF REST THEN BOLA/BFLA with two test accounts; DOCUMENT; ESCALATE for writes.

---

## 7.3 Cloud playbook (read-only first)
Covers AWS/Azure/GCP conceptually. Prefer least-privilege, read-only enumeration; ESCALATE
before any write/role change.

### C-1 Discovery
- Exposed object storage (public buckets/blobs), exposed metadata, public snapshots/images,
  misconfigured IAM, exposed functions/endpoints. Tools: cloud_enum, provider CLIs (read),
  ScoutSuite/Prowler/CloudSploit for config review.

### C-2 Credential / identity handling
- IF cloud creds obtained (via SSRF metadata, exposed secret, etc., approved) THEN enumerate
  effective permissions read-only (`get-caller-identity`, IAM simulate, role listing) →
  determine blast radius → DOCUMENT. Do not create persistence; if proving persistence is in
  scope, create a short-lived artifact and **revoke immediately**.

### C-3 Decision tree
- IF public storage with sensitive-looking data THEN prove *list/read access* against a
  **canary** object or metadata, not real data; IF over-privileged role THEN map what it
  could reach (simulate-policy), present path, validate only the approved move.
- **Telemetry**: CloudTrail / Azure Activity / GCP Audit logs — API calls, AssumeRole,
  storage access, IAM changes, metadata access. **Evidence**: API responses (redacted),
  permission maps. **Cleanup**: delete any created keys/roles/resources; confirm revocation.
