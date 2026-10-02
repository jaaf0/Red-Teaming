# 19 — Master Attack Decision Tree

Every leaf answers "what do I do next?" and routes to a scenario/playbook/TTP. Pair this
with the granular `docs/27` lookup. Run the Global Safety Controller (`docs/01`) at every
branch; any scope/exclusion failure is a hard STOP.

```
START
│
├── Do I have a foothold already?
│   ├── NO  → EXTERNAL branch
│   └── YES → INTERNAL branch
│
├── EXTERNAL
│   ├── Web exposed?
│   │   ├── YES → Web/API assessment (Scenario 2, docs/07)
│   │   │         ├── RCE/upload exec? → web-to-host pivot → INTERNAL
│   │   │         ├── SSRF? → metadata/cloud (ESCALATE) → CLOUD branch
│   │   │         ├── authz/authn bypass? → data access (test data) → DOCUMENT
│   │   │         └── exposed secret? → valid-account validation (Scenario 4)
│   │   └── NO ↓
│   ├── VPN gateway exposed?
│   │   ├── YES → VPN assessment (Scenario 12)
│   │   │         ├── creds provided? → auth → segmentation discovery → INTERNAL
│   │   │         └── no creds → report exposure, continue recon
│   │   └── NO ↓
│   ├── Remote services exposed (RDP/SSH/SMB/mgmt UI)?
│   │   ├── YES → exposed-service branch (C3)
│   │   │         ├── default/weak creds (single try)? → foothold → INTERNAL
│   │   │         └── none → DOCUMENT exposure, continue
│   │   └── NO ↓
│   ├── OSINT creds / exposed repo secrets?
│   │   ├── YES → valid-account validation (Scenario 4) [no spraying]
│   │   └── NO ↓
│   └── Continue recon / report "no external foothold" (valid outcome)
│
└── INTERNAL (have access as some principal)
    ├── What OS is the foothold?
    │   ├── WINDOWS → Windows enumeration (docs/06.1)
    │   │     ├── Local admin already?
    │   │     │     ├── YES → Credential Access (approval) / Lateral / Persistence(authz)
    │   │     │     └── NO  → privesc candidates → validate least-risk first
    │   │     └── Domain-joined?
    │   │           ├── YES → AD branch
    │   │           └── NO  → local-only: creds/lateral to other hosts
    │   ├── LINUX → Linux enumeration (docs/06.2)
    │   │     ├── root? → Credential Access / Lateral / Persistence(authz)
    │   │     └── not root → sudo/SUID/caps/cron/docker candidates → validate
    │   └── OTHER (appliance/container) → container/appliance enum → pivot
    │
    ├── AD branch (domain context)
    │   ├── Collect with SharpHound/bloodhound-python → BloodHound
    │   ├── Path to Tier-0 exists?
    │   │     ├── Kerberoastable SPN? → request → crack OFFLINE → Scenario 4
    │   │     ├── AS-REP roastable? → request → crack OFFLINE
    │   │     ├── Dangerous ACL/delegation? → controlled validation (revert) ESCALATE
    │   │     ├── DCSync rights? → ESCALATE → single test-acct replication proof
    │   │     └── Local admin via session/relay? → Lateral Movement
    │   └── AD CS present? → Scenario 6 (Certipy find → classify → controlled validation)
    │
    ├── After any new creds/host → RE-ENTER Discovery → UPDATE graph → PRIORITIZE (docs/21)
    │
    └── Objective reachable?
          ├── YES → Objective Discovery → Controlled Objective Simulation (docs/10) → STOP at proof
          └── NO  → pick next-best edge from graph; if none → report paths + gaps
```

### Cross-cutting guards at every branch
- `STOP` if target fails scope/exclusion or action is disruptive without approval.
- `ESCALATE` for credential dumping, memory access, persistence, impact, exfil, DCSync,
  anything production-affecting.
- `VALIDATE` before recording success; `DOCUMENT` evidence immediately; update the graph.
