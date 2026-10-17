# 16 — Engagement Runbook: from kickoff to client handover

An end-to-end, ordered procedure for running an **authorized** engagement with this framework and the
custom scripts in `scripts/`. Every script is read-only and scope-gated. Anything sensitive
(credential dumping, ticket attacks, exploitation, impact) stays an approval-gated step done with
established tooling under your ROE (`docs/01`, `docs/08`, `docs/09`), not with these scripts.

Conventions: run from `framework/scripts/` in PowerShell 7 (Windows PowerShell 5.1 also works for most scripts).
Evidence is appended automatically to `output/evidence/<date>/attacklog.jsonl`.

---

## Phase 0 — Authorization and setup (before touching anything)

| # | Step | How |
|---|---|---|
| 0.1 | Get signed authorization (SOW + ROE) and a named client contact with an emergency stop number | `docs/01` |
| 0.2 | Fill the scope: engagement id, window, operators, in-scope domains/CIDRs/hosts | `config/scope.yaml` |
| 0.3 | Fill the exclusions: OT/ICS, medical, fragile hosts, hard stops | `config/exclusions.yaml` |
| 0.4 | Confirm constraints: `allowed_disruptive: false`, `synthetic_data_only: true`, approval list | `config/scope.yaml` |
| 0.5 | Validate the toolkit on a lab host before using it on the client | `Invoke-Pester -Path ../tests` (expect 18 passing) |
| 0.6 | Agree evidence handling: where reports are stored, who can read them, retention and destruction date | `docs/23`, `docs/99` |

Gate: nothing runs until 0.1–0.4 are complete. The scripts fail closed: a target that is not in scope, or is excluded, is skipped.

## Phase 1 — Baseline and situational awareness (from the foothold or assessment host)

Run on the host you were given access to (or a client-provided assessment workstation).

```powershell
.\Invoke-HostSurvey.ps1        -OutFile out\hostsurvey.json     # Seatbelt-style posture
.\Invoke-HostRecon.ps1         -OutFile out\host.json           # inventory, services, network, security products
.\Invoke-PrivEscAudit.ps1      -OutFile out\privesc.json        # winPEAS-style misconfigs (reported, not exploited)
.\Invoke-CredExposureAudit.ps1 -OutFile out\credexposure.json   # where credential theft would succeed
```
Read the outputs for: AV/EDR present, PowerShell logging posture, UAC and local admin membership,
writable service paths, WDigest / LSASS protection / Credential Guard state, stored-credential surfaces.
Record notable items in the engagement log.

## Phase 2 — Active Directory discovery (domain-joined foothold)

```powershell
.\Invoke-DomainRecon.ps1    -Domain corp.example.com -OutFile out\domain.json     # users/groups/computers/trusts
.\Invoke-AdEnum.ps1         -Domain corp.example.com -OutFile out\adenum.json     # delegation, risky ACLs, GPOs, policy
.\Invoke-AdGraphCollect.ps1 -Domain corp.example.com -OutFile out\adgraph.json    # nodes + edges
.\Analyze-AdGraph.ps1       -GraphFile out\adgraph.json -OutFile out\paths.json   # OFFLINE shortest paths to Domain Admins
```
Expect a burst of LDAP queries: tell the client SOC beforehand if the exercise is not blind. Analyze the graph offline; the analysis touches nothing.

## Phase 3 — Identity-infrastructure audits

```powershell
.\Invoke-AdcsAudit.ps1       -Domain corp.example.com -OutFile out\adcs.json      # certificate template misconfigurations
.\Invoke-SysvolAudit.ps1     -Domain corp.example.com -OutFile out\sysvol.json    # GPP cpassword presence, writable SYSVOL scripts
.\Invoke-KerberosPosture.ps1 -Domain corp.example.com -OutFile out\kerberos.json  # SPNs, enc types, krbtgt age, trusts
```
These read configuration only: no certificates are requested, no tickets requested, no password values read or decoded.

## Phase 4 — Network exposure (in-scope hosts only)

```powershell
.\Invoke-SmbEnum.ps1     -Targets dc01,fs01 -OutFile out\smb.json        # null session, SMBv1, signing, anonymous shares
.\Invoke-ShareScan.ps1   -Targets dc01,fs01 -ListTopLevel -OutFile out\shares.json
.\Invoke-LateralRecon.ps1 -Targets (Get-Content hosts.txt) -OutFile out\lateral.json   # reachable admin ports, token admin-share access
.\Invoke-EgressRecon.ps1 -Collector test-collector.<your-lab-domain> -OutFile out\egress.json
```
`-Collector` must be an endpoint **you** control and that is listed in scope. Egress recon proves which outbound channels are open and moves no engagement data.
Linux hosts: copy and run `scripts/linux/Invoke-LinuxAudit.sh` (report-only), then collect its JSON.

## Phase 5 — Consolidate and prioritize

```powershell
.\Invoke-AllChecks.ps1 -Domain corp.example.com -OutDir .\rt-report
```
Produces `rt-report\report.json` and `report.md`: one severity-ranked list across the audits, with a per-step status. Then:

1. Review Critical and High findings first; validate each manually before it enters the report.
2. Use `out\paths.json` (graph paths) with `docs/21` to rank the attack paths by impact and likelihood.
3. Choose which findings need **proof of exploitability**. Each proof is a separate approval-gated action (Phase 6).

## Phase 6 — Approval-gated validation (separate from the scripts)

For each finding the client wants proven:

1. Write a one-page change request: technique, target, expected impact, stop condition, rollback, evidence to capture. Use `docs/02` (TTP template).
2. Get written approval referencing the ticket (`-ApprovalRef` for any gated script, e.g. `Invoke-ImpactMarker.ps1`).
3. Execute with established, authorized tooling under ROE (`docs/08`, `docs/09`), at the agreed time, with the client contact reachable.
4. Capture evidence immediately, then clean up (`docs/99`).
5. Benign impact simulation (detection testing only): `.\Invoke-ImpactMarker.ps1 -SandboxDir C:\RT-Sandbox -Count 50 -ApprovalRef ENG-2026-001`, then `-Cleanup`.

Stop immediately and call the client contact if: a production service degrades, an out-of-scope system is touched, or sensitive real data is exposed.

## Phase 7 — Purple-team debrief and detection scoring

1. Sit with the blue team. For each technique you exercised, list the detection rule that should have fired (`docs/11`, `docs/13`).
2. Put expectations in `expected.csv` (`Technique,Rule`); put rules the SOC confirmed fired in `observed.csv` (`Rule`).
3. Score:
   ```powershell
   .\Measure-DetectionCoverage.ps1 -ExpectedCsv expected.csv -ObservedCsv observed.csv -OutFile out\coverage.json
   ```
4. Gaps and partials become detection-engineering tasks in the report.

## Phase 8 — Reporting and handover

| # | Step | Notes |
|---|---|---|
| 8.1 | Executive summary: objectives met or not, top risks, business impact | plain language, no tool output |
| 8.2 | Findings: id, severity, evidence, ATT&CK technique, **remediation** | from `report.json`, plus validated proofs |
| 8.3 | Attack-path narrative with the graph | from `paths.json` |
| 8.4 | Detection coverage table | from `coverage.json` |
| 8.5 | Appendix: scripts used, versions, exact commands | `attacklog.jsonl` is the audit trail |
| 8.6 | Deliver the toolkit if contracted | hand over `scripts/` and `tests/` plus the README; it is read-only and auditable |
| 8.7 | Retest plan | re-run `Invoke-AllChecks.ps1` after fixes and diff `report.json` |

## Phase 9 — Cleanup and closure

1. Remove anything you created: sandbox markers (`-Cleanup`), temp files, copied scripts, test accounts or tasks from approved validation.
2. Confirm cleanup with the client contact and record it in the log.
3. Securely archive evidence per the retention agreement; destroy working copies on the agreed date.
4. Hold the debrief and agree on the retest date. Close the engagement in the log.

---

### Quick reference: which script answers which question

| Question | Script |
|---|---|
| How hardened is this host? | `Invoke-HostSurvey`, `Invoke-PrivEscAudit` |
| Would credential theft succeed here? | `Invoke-CredExposureAudit` |
| What does AD allow an attacker to abuse? | `Invoke-AdEnum`, `Invoke-AdGraphCollect` + `Analyze-AdGraph` |
| Is the PKI or SYSVOL exposed? | `Invoke-AdcsAudit`, `Invoke-SysvolAudit` |
| Are Kerberos accounts and trusts weak? | `Invoke-KerberosPosture` |
| What can reach what over the network? | `Invoke-SmbEnum`, `Invoke-LateralRecon`, `Invoke-ShareScan` |
| Can data leave the network? | `Invoke-EgressRecon` |
| Linux exposure? | `linux/Invoke-LinuxAudit.sh` |
| Everything in one report? | `Invoke-AllChecks` |
| Did the SOC see it? | `Measure-DetectionCoverage` |
