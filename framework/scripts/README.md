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
| `Invoke-ImpactMarker.ps1` | 11 | T1486 (sim) | **Benign** impact sim: drops harmless marker files in an `RT-Sandbox` dir for detection testing; `-Cleanup` removes them | sandbox markers only (reversible) |

## Usage
```powershell
# from framework/scripts/
Import-Module .\RTSafety.psm1 -Force          # loaded automatically by each script too

.\Invoke-HostRecon.ps1 -OutFile host.json
.\Invoke-DomainRecon.ps1 -Domain corp.example.com -OutFile domain.json
.\Invoke-ShareScan.ps1 -Targets dc01,fs01 -ListTopLevel -OutFile shares.json

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
