# 27 — "What Do I Do Next?" Engine

Lookup table: **What I found → Meaning → Immediate action → Tool → If success → If failure.**
Every row obeys the Global Safety Controller; sensitive rows are approval-gated. Pair with
`docs/19` (branches) and `docs/21` (which path first).

| What I found | Meaning | Immediate action (least-impact) | Tool | If success | If failure |
|---|---|---|---|---|---|
| Open 445 (SMB) | File/AD service, lateral potential | Enum shares/null session/sig | NetExec, smbclient | map shares/users → BloodHound | try LDAP/other ports |
| Open 3389 (RDP) | Remote GUI access | Note; test ONE cred if available | NetExec rdp, client | session (logon type 10) | WinRM/SMB instead |
| Open 5985 (WinRM HTTP) | Remote exec channel | Validate creds | NetExec winrm, evil-winrm | remote shell | try 5986/SMB |
| Open 5986 (WinRM HTTPS) | Encrypted WinRM | Validate creds over TLS | evil-winrm -S | remote shell | SMB/WMI |
| LDAP (389/636) | Directory readable | Enum users/groups/policy | ldapsearch, NetExec | ingest to BloodHound | authenticated LDAP |
| Kerberos (88) | AD KDC present | Enum SPNs/AS-REP (DU) | Impacket | roastable accts → offline crack | enum only |
| Domain Controller found | Tier-0 identity hub | Do NOT attack directly; collect | SharpHound/BH | path analysis to DA | enumerate reachable edges |
| Valid domain account | Foothold identity | Map blast radius (no DA assumption) | NetExec, BloodHound | where admin? sessions? | enumerate reachable data |
| Local admin (host) | Host-level control | Cred access (approval) / lateral / persist(authz) | Impacket, NetExec | pivot to new hosts | enumerate more |
| Service account (SPN) | Often over-privileged | Kerberoast → crack OFFLINE | GetUserSPNs, hashcat | admin rights? lateral | AS-REP / other SPNs |
| SPN discovered | Roastable candidate | Request ticket | Impacket | offline crack | next SPN |
| Interesting ACL (GenericAll/WriteDACL) | Takeover edge | Validate on TEST object, revert ESCALATE | BloodHound, PowerView | controlled grant → path | next edge |
| Writable service (weak ACL) | Local privesc | DOCUMENT; reversible demo then revert | PowerUp | local admin | next vector |
| Scheduled task weakness | Local privesc/persist | Demonstrate, then revert | native, PowerUp | higher priv | next vector |
| SUID/SGID binary | Linux privesc | Check GTFOBins-style abuse | linPEAS | root PoC | capabilities/sudo |
| Sudo privilege (`sudo -l`) | Linux privesc | Validate documented technique | native | root | SUID/cron/docker |
| Docker socket writable | Container→host | Controlled host-access PoC, STOP before persist | docker CLI | host access | k8s / other |
| SSH key found | Reusable auth | One auth to reachable host | ssh | lateral foothold | enumerate more keys |
| API token found | Service access | One minimal authorized call ESCALATE | curl/CLI | scope of token | other secrets |
| Cloud credential | Cloud access | Read-only identity/permission enum | cloud CLI | blast radius map | another creds source |
| Web login page | Auth surface | Authn/authz tests, single-try creds | Burp | session/bypass | injection/content disc |
| File upload | Potential exec | Upload benign marker, confirm, remove | Burp | web-to-host pivot | path traversal/LFI |
| SSRF candidate | Internal reach | Prove benign internal reach first | Burp | metadata (ESCALATE) | other server-side |
| Database exposed | Data/exec surface | Enum schema; read seeded test row | NetExec, client | creds/data path | auth brute (NO) → stop |
| VPN gateway | Network entry | Auth with provided creds | VPN client | segmentation discovery | report exposure |
| Open SMB null session | Info leak | Enumerate users/shares | rpcclient, NetExec | user list → roast/spray-guarded | authenticated enum |
| Trust relationship | Cross-domain path | Map trust direction/type | nltest, BH | theoretical path (approved) | intra-domain path |
| AD CS CA found | Cert-based privesc maybe | Certipy find → classify | Certipy | controlled validation (Scenario 6) | record "present, no misconfig" |
| EDR detected | Monitored host | Prefer native/LOLBin; coordinate purple | — | quiet progress + telemetry notes | choose less-monitored path |
| No telemetry (expected but absent) | Detection gap (a FINDING) | DOCUMENT; check log source→agent→rule | SIEM/Wazuh | report gap | verify action logged at all |
| C2 established | Managed control | Run ATT&CK-mapped actions + record IoCs | Caldera/Sliver | discovery/lateral | re-stage channel |
| High-value asset discovered | Objective candidate | Map theoretical path; do NOT auto-exploit | BloodHound | prioritize (docs/21) → validate chosen | note + continue |
| Exposed `.git`/backup/config | Source/secret leak | Download read-only; scan for secrets | git-dumper, trufflehog | valid account/keys | other exposures |
| Mgmt UI (Jenkins/iLO/etc.) | Admin surface | Default/weak auth single-try | browser, NetExec | foothold | other services |
| Writable PATH / cron (Linux) | Privesc/persist | Benign marker, confirm, remove | native | root | other vectors |
| Kerberos AS-REP (no preauth) | Roastable | Request AS-REP, crack OFFLINE | GetNPUsers | account recovered | next account |
| DCSync rights on principal | Tier-0 capability | ESCALATE; single test-acct replication proof | secretsdump (approval) | capability proven, STOP | report rights only |

### Using the engine
1. Observe a fact (from recon/discovery). 2. Find the row. 3. Run the **least-impact**
immediate action with the safety controller. 4. On success, DOCUMENT + update the graph +
re-prioritize. 5. On failure, take the "If failure" branch or return to the graph for the
next-best edge. Never iterate an action across all hosts automatically — propose, then act.
