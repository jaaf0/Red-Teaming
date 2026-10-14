# scripts/ — Custom PowerShell toolkit

Our own, dependency-free PowerShell for the **safe, read-only, evidence-producing** parts of
an engagement. No community modules (no PowerView/PowerUp/Atomic) — everything here uses
built-in cmdlets, CIM, and native .NET LDAP. Every script is scope-gated and emits structured
evidence (`docs/23`).

| Script | Phase (docs/14) | ATT&CK | What it does | Writes? |
|---|---|---|---|---|
| `RTSafety.psm1` | all | — | Global Safety Controller: scope/exclusion check, approval gate, JSON evidence logger | evidence only |
| `Invoke-HostRecon.ps1` | 4, 6 | T1082/T1033/T1057/T1016/T1518.001 | Local host/user/priv/service/network/security-product inventory | JSON report only |
| `Invoke-DomainRecon.ps1` | 6 | T1087.002/T1069.002/T1018/T1482 | Read-only AD users/groups/computers/OUs/trusts via native LDAP; flags Kerberoast/AS-REP candidates | JSON report only |
| `Invoke-ShareScan.ps1` | 6, 10 | T1135/T1083 | Read-only SMB share discovery + read-access test across in-scope hosts | JSON report only |
| `Invoke-HostSurvey.ps1` | 4, 6 | T1082/T1518.001/T1033/T1012 | Host situational-awareness survey (our *Seatbelt* equivalent): OS/patches, UAC, PS-logging posture, AV/EDR, firewall, autoruns, tasks | JSON report only |
| `Invoke-PrivEscAudit.ps1` | 6 | T1543.003/T1574/T1548.002/T1552 | Local priv-esc **misconfig audit** (our *winPEAS* equivalent): unquoted/writable services, AlwaysInstallElevated, writable PATH, dangerous privileges. Reports, never exploits | JSON report only |
| `Invoke-CredExposureAudit.ps1` | 6, 9 | T1003/T1552/T1558/T1550 (defensive) | **Credential-exposure audit** (the *Mimikatz* counterpart): detects WDigest cleartext, LSASS-not-PPL, no Credential Guard, autologon password, cached-logon surface. **No LSASS/SAM access, no secret read** | JSON report only |
| `Invoke-AdEnum.ps1` | 6 | T1087.002/T1069.002/T1482/T1207 | Deep AD enumeration (our *PowerView* equivalent): delegation (unconstrained/constrained/RBCD), risky ACLs, GPOs, password policy, roastable accounts — identify only | JSON report only |
| `Invoke-AdGraphCollect.ps1` | 6 | T1087.002/T1069.002/T1482 | AD graph collector (our *SharpHound* equivalent): read-only nodes+edges (MemberOf, ACL control, delegation) for offline analysis | JSON graph only |
| `Analyze-AdGraph.ps1` | 6 | — (offline) | *BloodHound*-style **offline** attack-path analysis over the collected graph (shortest path to Domain Admins). No network, no AD | JSON report only |
| `Invoke-SmbEnum.ps1` | 6 | T1135/T1018/T1021.002 | SMB security-posture enum (the *NetExec* **enumeration** subset): 445 reach, null-session, anon shares, SMBv1/signing. **No spraying, no exec, no dumping** | JSON report only |
| `Invoke-LateralRecon.ps1` | 6 | T1046/T1021/T1135 | Read-only lateral-movement exposure recon: remote-admin port reach + current-token admin-share access. No creds supplied | JSON report only |
| `Invoke-EgressRecon.ps1` | 10 | TA0010/T1046 | Read-only outbound egress-path reachability to an operator-controlled test collector. Moves no data | JSON report only |
| `Invoke-ImpactMarker.ps1` | 11 | T1486 (sim) | **Benign** impact sim: drops harmless marker files in an `RT-Sandbox` dir for detection testing; `-Cleanup` removes them | sandbox markers only (reversible) |

### Custom-tool equivalents (why these exist)
Clients often ask for "the tools you ran." These are our own, auditable, **read-only** stand-ins
for the usual offensive utilities, safe to hand over as an engagement deliverable:
`Invoke-HostSurvey` ≈ Seatbelt, `Invoke-PrivEscAudit` ≈ winPEAS, `Invoke-AdEnum` ≈ PowerView,
`Invoke-AdGraphCollect`/`Analyze-AdGraph` ≈ SharpHound/BloodHound, `Invoke-SmbEnum` ≈ the NetExec
*enumeration* subset, and `Invoke-CredExposureAudit` is the **defensive** counterpart to Mimikatz —
it reports *where* credential theft would succeed so the client can remediate, without ever
touching LSASS/SAM or reading a secret.

## Usage
```powershell
# from framework/scripts/
Import-Module .\RTSafety.psm1 -Force          # loaded automatically by each script too

.\Invoke-HostRecon.ps1 -OutFile host.json
.\Invoke-DomainRecon.ps1 -Domain corp.example.com -OutFile domain.json
.\Invoke-ShareScan.ps1 -Targets dc01,fs01 -ListTopLevel -OutFile shares.json

# custom read-only tool equivalents:
.\Invoke-HostSurvey.ps1 -OutFile hostsurvey.json                 # Seatbelt-style
.\Invoke-PrivEscAudit.ps1 -OutFile privesc.json                  # winPEAS-style (reports, never exploits)
.\Invoke-CredExposureAudit.ps1 -OutFile credexposure.json        # Mimikatz counterpart (audit only)
.\Invoke-AdEnum.ps1 -Domain corp.example.com -OutFile adenum.json          # PowerView-style
.\Invoke-AdGraphCollect.ps1 -Domain corp.example.com -OutFile adgraph.json # SharpHound-style
.\Analyze-AdGraph.ps1 -GraphFile adgraph.json                              # BloodHound-style (offline)
.\Invoke-SmbEnum.ps1 -Targets dc01,fs01 -OutFile smbenum.json    # NetExec enumeration subset
.\Invoke-LateralRecon.ps1 -Targets (Get-Content hosts.txt) -OutFile lateral.json
.\Invoke-EgressRecon.ps1 -Collector test-collector.redteam.lab -OutFile egress.json

# impact sim is approval-gated and sandbox-only:
.\Invoke-ImpactMarker.ps1 -SandboxDir C:\RT-Sandbox -Count 50 -ApprovalRef ENG-2026-001
.\Invoke-ImpactMarker.ps1 -SandboxDir C:\RT-Sandbox -Cleanup
```
Evidence is appended to `output/evidence/<date>/attacklog.jsonl` (one JSON record per action,
matching the `docs/23` schema), ready for the report.

## Scope control
All scripts read `../config/scope.yaml` and `../config/exclusions.yaml`. A target must be
**in scope and not excluded** or the action is skipped (fail-closed). Fill those files in
before running anything.

## Deliberately NOT in this toolkit
Weaponized offensive code is **not** hand-rolled here, by design:
- credential dumping / LSASS or SAM access,
- Kerberoast/AS-REP ticket extraction + cracking,
- exploitation, lateral-movement execution, AMSI/EDR evasion,
- real encryption / deletion / service-disruption.

For those approval-gated steps, use established, authorized, signed tooling (e.g. Impacket for
Kerberos ticket requests, run offline cracking with hashcat) under your ROE — see `docs/08`,
`docs/09`, and the per-scenario tables in `docs/15`. These discovery scripts identify the
*candidates and reach*; the sensitive action is a separate, explicitly-approved step.
