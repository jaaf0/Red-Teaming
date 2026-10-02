# 32 — Scenario Generator

Specify the situation; the framework generates candidate attack paths, required TTPs,
tools, a decision tree, expected telemetry, evidence requirements, and stop conditions.

## Input template
```yaml
scenario:
  starting_position: ""   # external | web_app | workstation | valid_creds | low_priv_dc_user | win_server | linux_shell | vpn_creds | cloud_creds
  target: ""              # objective asset / data
  credentials: ""         # none | user | service_acct | local_admin | domain_admin | cloud
  network_access: ""      # internet | vpn | internal_segment | dmz
  known_hosts: []         # inventory you already have
  known_services: []      # e.g. [445,3389,ldap,https]
  security_controls: []   # e.g. [edr, siem_wazuh, dlp, segmentation, mfa]
  objective: ""           # e.g. reach_tier0 | access_crownjewels | prove_exfil | validate_detection
```

## Generation algorithm
1. **Map starting_position → entry scenario** (`docs/05`): external→S1/S2, web_app→S2,
   workstation→S3, valid_creds→S4, low_priv_dc_user→S5, win_server→S7, linux_shell→S8,
   vpn_creds→S12, cloud_creds→`docs/07.3`.
2. **Derive candidate paths** by walking `docs/19` from that entry to `objective`, using
   `known_services`/`known_hosts` to prune branches (e.g. no 445 ⇒ drop SMB-lateral edges).
3. **Select TTPs** per path from `docs/03`/`06`–`10`; attach tools from `docs/04`.
4. **Fold in security_controls**: edr⇒prefer native/LOLBin + purple coordination;
   mfa⇒deprioritize credential-replay paths; segmentation⇒add segmentation-discovery step;
   siem_wazuh⇒attach expected telemetry (`docs/11`); dlp⇒canary-only exfil.
5. **Build the decision tree** by stitching the per-TTP trees along each path.
6. **Attach expected telemetry** (`docs/11`), **evidence requirements** (`docs/23`), and
   **stop conditions** (scope/exclusions + approval gates + objective-proof stop).
7. **Prioritize paths** objectively (`docs/21`) and present trade-offs — operator chooses.

## Worked example
**Input**: starting=workstation, creds=user, access=internal_segment, services=[445,ldap,88],
controls=[edr,siem_wazuh], objective=reach_tier0.
**Output (abridged)**:
- Entry: Scenario 3 → AD branch (Scenario 5).
- Candidate paths:
  - P1 Kerberoast → offline crack → admin host → BloodHound path to DA. (reliable, reversible)
  - P2 Local privesc → cred access (approval) → lateral → DA edge.
  - P3 ACL/delegation edge → controlled validation (ESCALATE).
- TTPs: T1087/T1069 (discovery), T1558.003 (roast), T1550/T1021 (lateral), approval-gated
  T1003 if needed.
- Tools: SharpHound/BloodHound, Impacket, hashcat (offline), NetExec; native enum (EDR present).
- Telemetry: LDAP recon burst, TGS anomalies, lateral auth (logon type 3), process-create.
- Evidence: BloodHound ZIP, ticket meta, cracked-account note, auth proofs.
- Stop: no spraying; offline crack only; ESCALATE before dumping/DCSync; stop at Tier-0 proof.
- Recommendation: validate P1 first (lowest privilege, fully reversible, no approval gate).
