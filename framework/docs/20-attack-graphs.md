# 20 — Attack Graphs (Mermaid)

Rendered attack graphs for each major path. Each decision node routes per `docs/19`/`docs/27`.

## External attack
```mermaid
flowchart TD
  A[External recon] --> B[Surface discovery]
  B --> C{Exposed?}
  C -->|Web| D[Web/API assessment]
  C -->|VPN| E[VPN assessment]
  C -->|Remote svc| F[Exposed-service check]
  C -->|OSINT creds| G[Valid-account validation]
  D --> H{Foothold?}
  E --> H
  F --> H
  G --> H
  H -->|Yes| I[Internal access]
  H -->|No| B
  I --> J[Internal discovery]
```

## Web-to-internal
```mermaid
flowchart TD
  A[App discovery] --> B[Authn/Authz testing]
  B --> C{Injection/upload/SSRF?}
  C -->|RCE/upload| D[Exec on web host]
  C -->|SSRF| E[Reach internal/metadata]
  C -->|Secret exposed| F[Valid account]
  D --> G[Web-to-host pivot]
  E --> H{Cloud metadata?}
  H -->|Yes ESCALATE| I[Cloud creds]
  G --> J[Internal service discovery]
  F --> J
  I --> J
```

## Windows-to-AD
```mermaid
flowchart TD
  A[Workstation access] --> B[Local enum]
  B --> C{Local admin?}
  C -->|Yes| D[Cred access / lateral]
  C -->|No| E[Privesc candidates]
  E --> F{Validated?}
  F -->|Yes| D
  F -->|No| G[SharpHound collect]
  D --> G
  G --> H[BloodHound path analysis]
  H --> I{Tier-0 edge?}
  I -->|Kerberoast/ACL/DCSync| J[Controlled validation]
  I -->|No| K[Next-best edge]
  J --> L[Privileged account]
  K --> H
```

## Low-privilege-to-domain-admin-style path
```mermaid
flowchart TD
  A[Low-priv domain user] --> B[AD collection]
  B --> C[Graph shortest path to Tier-0]
  C --> D{Edge type?}
  D -->|SPN| E[Kerberoast -> offline crack]
  D -->|AS-REP| F[AS-REP roast -> offline crack]
  D -->|ACL/Deleg| G[Controlled ACL validation + revert ESCALATE]
  D -->|Session/Relay| H[Lateral movement]
  E --> I[Re-collect + re-prioritize]
  F --> I
  G --> I
  H --> I
  I --> J{Objective reached?}
  J -->|No| C
  J -->|Yes| K[Controlled objective simulation]
```

## Linux-to-server
```mermaid
flowchart TD
  A[Low-priv shell] --> B[linPEAS / native enum]
  B --> C{Privesc vector?}
  C -->|sudo/SUID/cap| D[Controlled validation]
  C -->|docker/k8s| E[Host-access PoC]
  C -->|none| F[Creds/keys harvest]
  D --> G[root]
  E --> G
  F --> H[Lateral via SSH/keys]
  G --> H
  H --> I[Target server]
```

## VPN-to-internal
```mermaid
flowchart TD
  A[VPN creds] --> B[Authenticate]
  B --> C[Segmentation discovery]
  C --> D{Reaches Tier-0 directly?}
  D -->|Yes| E[Finding: segmentation gap]
  D -->|No| F[Map reachable segments]
  E --> G[Internal discovery]
  F --> G
  G --> H[Service enum -> cred validation -> lateral]
```

## Credential-based lateral movement
```mermaid
flowchart TD
  A[Obtain creds/hash] --> B[Where am I admin? NetExec/BloodHound]
  B --> C{Admin on high-value host?}
  C -->|Yes| D[Authenticate via most-reliable method]
  C -->|No| E[Pick next reachable host]
  D --> F[Minimal confirm command]
  F --> G[Re-enter discovery on new host]
  E --> B
  G --> H{Objective?}
  H -->|No| B
  H -->|Yes| I[Objective simulation]
```

## C2 operation
```mermaid
flowchart TD
  A[Foothold] --> B[Listener/redirector]
  B --> C[Agent check-in]
  C --> D[ATT&CK-mapped actions]
  D --> E[Discovery]
  E --> F[Lateral movement]
  F --> G[Objective]
  D --> H[Telemetry -> detection validation]
  G --> I[Cleanup: kill agents, tear down]
```

## Data exfiltration simulation
```mermaid
flowchart TD
  A[Locate data] --> B[Use canary/synthetic only]
  B --> C[Stage + compress]
  C --> D{Channel}
  D -->|HTTPS| E[Transfer marked canary]
  D -->|DNS| E
  D -->|Cloud/SFTP| E
  E --> F[Check DLP/proxy/DNS detection]
  F --> G[Document detected/partial/not]
  G --> H[Cleanup: delete staged + record IDs]
```

## Purple-team loop
```mermaid
flowchart TD
  A[Pick technique] --> B[Notify SOC - validation mode]
  B --> C[Execute safe variant]
  C --> D[Observe log/SIEM/EDR/alert stages]
  D --> E{Coverage?}
  E -->|Detected| F[Document + move on]
  E -->|Partial/None| G[Hand indicators to detection eng]
  G --> H[Tune/build detection]
  H --> I[Re-run]
  I --> D
```
