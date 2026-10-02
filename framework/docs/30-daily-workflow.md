# 30 — Daily Red Team Workflow

A practical operating rhythm that keeps the loop (recon → validate → graph → next path)
disciplined and evidence-complete.

## Morning (plan)
1. **Review scope** — re-read `config/scope.yaml` + `exclusions.yaml`; confirm the window
   is open and your egress IPs are still registered.
2. **Review previous findings** — read yesterday's attack log + evidence.
3. **Review attack graph** — current nodes/edges, owned principals, open candidate paths.
4. **Select today's objective** — one primary objective + 1–2 fallback paths.
5. **Verify authorization** — confirm any approval-gated techniques planned for today are
   actually approved (persistence, dumping, impact, exfil).
6. **Define stop conditions** — explicit, written, for today's activities.

## During operation (execute the loop)
For each action:
- Run the **Global Safety Controller** (`docs/01`).
- Write the **intent** evidence record (`docs/23`) before acting.
- Execute the least-impact action; **monitor telemetry** as you go (purple runs: confirm
  with SOC).
- **VALIDATE** the result; complete the evidence record.
- **Update the attack graph**; **re-prioritize** (`docs/21`).
- **Decide the next branch** via `docs/27`/`docs/19` — do not auto-chain.
- Honor the kill switch and client-abort contact at all times.

## End of day (close out)
1. **Cleanup** — process every `cleanup_required: true` record; remove tools/files/markers;
   revert services/tasks/ACLs; decrypt/remove synthetic files; kill agents/sessions.
2. **Verify no persistence remains** — confirm each persistence/change is reverted.
3. **Export evidence** — snapshot the day's evidence dir; hash artifacts.
4. **Update timeline** — complete the attack log.
5. **Update ATT&CK mapping** — techniques used today + coverage verdicts.
6. **Prepare next-day plan** — top candidate paths, blockers, approvals to request.

## Weekly / engagement checkpoints
- Reconcile every open `cleanup_required` item.
- Confirm detection-coverage map is current for purple engagements.
- Re-validate scope if the environment or authorization changed.
