# 08 — C2 Methodology & CALDERA Adversary Emulation

C2 is used here for **adversary emulation and detection validation**, not stealth for its
own sake. Deploy agents only on in-scope hosts; coordinate with the blue team for
purple-team runs. Document indicators so detections can be built.

---

## 8.1 C2 platform comparison

| Platform | Best for | Notes |
|---|---|---|
| **MITRE Caldera** | ATT&CK-mapped, repeatable emulation + detection validation | Open-source, ability/adversary profiles, telemetry-friendly |
| **Sliver** | Flexible operator C2, cross-platform implants | Good default for red-team ops; mTLS/HTTP/DNS/WireGuard |
| **Mythic** | Modular multi-agent C2, team ops | Containerized, many profiles |
| **Havoc** | Modern open-source operator C2 | — |
| **Cobalt Strike** | Mature commercial C2 | **Licensed only**; license check before use |
| **Approved custom agents** | Bespoke emulation needs | Must meet tool-execution standard (`docs/33`) |

## 8.2 Generic C2 lifecycle (any platform)
```
Architecture → Listener → Agent/Implant → Check-in → Command execution →
Discovery → Lateral movement → Cleanup
```
- **Architecture**: redirector(s) → team server → operator console. Scope redirector
  domains/IPs; register with blue team for purple runs.
- **Listener**: choose protocol (HTTPS / DNS / mTLS) to match the emulated adversary and
  the detection you want to test.
- **Agent/implant**: deploy to in-scope foothold only.
- **Check-in**: set realistic jitter/sleep for the emulated actor.
- **Command execution / discovery / lateral**: run ATT&CK-mapped actions; each maps to a
  TTP-library entry with its telemetry.
- **Cleanup**: kill agents, remove staged files, tear down listeners/redirectors, revoke
  any certs, confirm no persistence remains.

## 8.3 Indicators each C2 produces (give these to detection engineering)
- **Network**: beacon periodicity + jitter, consistent request sizes, long-lived sessions,
  uncommon JA3/TLS fingerprints, traffic to newly-registered/categorized domains.
- **Process**: implant process lineage, injected threads, unusual parent-child chains,
  spawned LOLBins.
- **DNS**: high query volume, long/high-entropy labels, TXT-heavy traffic (DNS C2).
- **HTTP/S**: fixed URIs/user-agents, uncommon headers, POST-heavy small responses.
- **Authentication**: new-host logons following agent check-in, service/task creation.
- **Endpoint**: file drops in temp/staging dirs, scheduled tasks/services, AMSI/script logs.

---

## 8.4 CALDERA workflow (Scenario 17)

### Install & configure
1. Deploy Caldera on an in-scope operator host (Docker or source).
2. Configure users, API key, and a scoped `red` group; restrict server exposure.
3. Register redirector/listener as needed; align `config` with ROE.

### Agent deployment
4. Deploy the Sandcat/agent to authorized target hosts only (one-liner stager in the UI).
5. Confirm check-in; place agents into **groups** by host role (workstations, servers, DCs).

### Build & run an operation
6. Choose/compose an **adversary profile** (ordered ability set).
7. **Ability selection**: pick abilities mapped to the ATT&CK techniques you want to
   validate; disable anything destructive; set fact sources.
8. **Operation setup**: pick adversary, group, planner (e.g. atomic/batch), obfuscator,
   jitter, and **auto-close/limits**; enable fact collection.
9. Execute; watch step results and collected facts.
10. **Telemetry collection**: correlate each ability's timestamp with SIEM/EDR events.
11. **ATT&CK mapping**: Caldera tags each ability — export the technique list.
12. **Detection validation**: mark each technique DETECTED / PARTIAL / NOT (`docs/11`).
13. **Cleanup**: run Caldera's cleanup commands (each ability's reverse action), kill
    agents, remove staged files, confirm host state restored.

### Operation profiles
- **Profile A — Discovery**: host/user/network/domain enumeration abilities only (LOW
  risk). Goal: baseline discovery detection.
- **Profile B — Credential Access Simulation**: safe credential-access abilities (e.g.
  credential-in-file discovery, Kerberoast request) — approval for anything touching LSA;
  prefer proof-of-capability abilities.
- **Profile C — Lateral Movement Simulation**: SMB/WMI/WinRM movement between two approved
  hosts with test creds.
- **Profile D — Full Windows AD Attack Path**: chained discovery → credential → lateral →
  objective across an approved AD lab segment; map the whole path to ATT&CK.
- **Profile E — Purple Team Detection Validation**: run A–D with the SOC watching; after
  each ability, confirm the expected alert fired; feed gaps to detection engineering.

- **Decision tree**: start with Profile A → confirm telemetry baseline → add B/C once
  detection for A is understood → D only in an approved lab/segment → E whenever the SOC is
  engaged. Never run D broadly in production without explicit approval.
