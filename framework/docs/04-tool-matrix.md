# 04 — Tool Matrix & Selection Rationale

Do **not** blindly chain tools. Each is selected because its output is the next tool's
input, or because it answers a specific decision-point question. "Native" favors
living-off-the-land (quietest, often least likely to trip EDR). Tools marked **(approval)**
require explicit authorization; **(authz)** require being explicitly in scope.

| Phase | Primary | Alternative | Native / LOLBin | Input | Output | Next tool / why |
|---|---|---|---|---|---|---|
| Recon (passive) | subfinder, amass | crt.sh, Censys | whois, dig | domains | subdomains/IPs | dnsx (resolve) |
| Resolve | dnsx | massdns | nslookup | subdomains | live hosts | naabu |
| Port sweep | naabu, RustScan | masscan **(approval)** | /dev/tcp, Test-NetConnection | hosts | open ports | nmap |
| Service enum | nmap -sV -sC | — | — | ports | services/versions | httpx or service playbook |
| Web probe | httpx | WhatWeb | curl | web ports | live URLs, tech | nuclei / Burp |
| Vuln check | nuclei (validated) | Nessus, OpenVAS | — | URLs/hosts | candidate findings | manual validation (Burp) |
| Web test | Burp Suite | ZAP | — | URLs | confirmed issues | evidence/attack-path |
| Content disc. | ffuf | feroxbuster, gobuster | — | base URL | endpoints | Burp |
| SMB enum | NetExec | smbclient, rpcclient | `net view` | 445 hosts | shares/users/auth | ldapsearch / BloodHound |
| LDAP enum | ldapsearch, NetExec --users | windapsearch | `dsquery`, AD cmdlets | DC | directory data | BloodHound ingest |
| AD graph | BloodHound + SharpHound/bloodhound-python | — | — | AD data | attack paths | path analysis |
| Kerberos | Impacket (GetUserSPNs/GetNPUsers) | Rubeus **(authz)** | `setspn` | DU creds | tickets (offline crack) | hashcat (offline) |
| Auth/exec | NetExec, Impacket (wmiexec/psexec) | evil-winrm | WinRM, PsExec | creds | remote exec | discovery on new host |
| Linux privesc enum | linPEAS | LinEnum | `sudo -l`, `find` | shell | privesc candidates | manual validation |
| Windows privesc enum | WinPEAS, PowerUp | Seatbelt | `whoami /priv` | shell | privesc candidates | manual validation |
| Cred crack (offline) | hashcat | john | — | hashes | passwords | lateral movement |
| Responder **(approval)** | Responder | — | — | network | hashes (poisoning) | **noisy, explicit authz only** |
| AD CS | Certipy **(authz)** | — | `certutil` | DU creds | template misconfig | controlled validation |
| C2 | Caldera, Sliver | Mythic, Havoc, Cobalt Strike (licensed) | — | foothold | managed agent | discovery/lateral |
| Traffic analysis | Wireshark, tcpdump | — | — | iface | pcap | evidence |
| Vuln mgmt | Nessus, OpenVAS | — | — | hosts | vuln report | prioritization |
| SIEM/detect | Wazuh, Elastic | Splunk | OS logs | telemetry | detection map | purple-team report |
| Case mgmt | TheHive + Cortex | — | — | alerts | investigations | purple-team report |

## Selection rationale (why, not just what)
- **naabu before nmap**: fast TCP discovery narrows nmap's deep `-sV -sC` to only open
  ports → less noise, faster, lower chance of tripping volumetric IDS.
- **httpx before nuclei**: confirm which ports are really HTTP(S) and capture tech/titles
  so nuclei runs targeted templates, not the whole set against everything.
- **nuclei is a *candidate* generator, not proof**: always manual-validate in Burp before
  recording a finding (avoids false positives and blind mass exploitation).
- **NetExec as the SMB/LDAP/WinRM swiss-army**: single tool to validate creds and
  enumerate across protocols; feeds BloodHound and tells you *where* creds are admin.
- **BloodHound is the brain**: it turns raw AD data into **paths**; you query it before
  choosing a lateral/priv move so you move with intent, not noise.
- **Offline cracking (hashcat/john)**: keeps credential attacks *off* the target network —
  no lockouts, minimal auth-log noise.
- **Responder is opt-in only**: poisoning is disruptive and broad; never default-on.
- **Caldera vs Sliver**: Caldera for ATT&CK-mapped, repeatable *emulation + detection
  validation*; Sliver/Mythic for flexible operator C2. Choose by goal (see `docs/08`).
