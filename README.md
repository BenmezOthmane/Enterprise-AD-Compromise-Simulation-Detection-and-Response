## Enterprise AD Compromise Simulation & Detection

## Project Overview
  This project simulates a **realistic Active Directory compromise** — from initial network reconnaissance to full Domain Admin takeover — while simultaneously building a **detection engineering layer** on top of Wazuh SIEM.
Every attack is mapped to **MITRE ATT&CK**, detected via **custom Wazuh rules**, and documented with a full attack timeline. The environment also integrates **Azure Entra ID** for hybrid cloud visibility and an **automated offsite backup** pipeline.

## Objectives
| # | Area | Goal |
|---|---|---|
| 1 | **Infrastructure** | Deploy a segmented network environment using pfSense with isolated attacker and corporate zones |
| 2 | **Offense** | Execute common AD attack vectors: LLMNR Poisoning, Kerberoasting, Pass-the-Hash, Privilege Escalation |
| 3 | **Analysis** | Deep-dive into Windows Event Logs and Sysmon to identify attacker footprints |
| 4 | **Defense** | Engineer custom Wazuh detection rules, decoders, and automated response actions |
| 5 | **Hybrid Visibility** | Integrate Azure cloud and on-premise logging into a unified monitoring dashboard |

## Architecture Diagram
```
                          ┌────────────────────────┐
                          │      pfSense FW        │
                          │ (VLAN/Static Routing)  │
                          └─────┬────────────┬─────┘
                                │            │
   ┌────────────────────────────▼──┐  ┌──────▼─────────────────────┐
   │      LAN CORPORATE ZONE       │  │     LAN ATTACKER ZONE      │
   │      (Internal Network)       │  │     (Untrusted Network)    │
   │                               │  │                            │
   │  ┌─────────────────────────┐  │  │  ┌──────────────────────┐  │
   │  │   Windows Server 2022   │  │  │  │      Kali Linux      │  │
   │  │   (Domain Controller)   │  │  │  │    (Threat Actor)    │  │
   │  │       SOC.local         │  │  │  └──────────────────────┘  │
   │  └────────────┬────────────┘  │  └────────────────────────────┘
   │               │               │
   │  ┌────────────▼────────────┐  │           ┌────────────────────┐
   │  │    Windows 10 Pro       │  │           │    HYBRID CLOUD    │
   │  │    (Domain Joined)      │◄─┼──────────►│   Azure Entra ID   │
   │  └────────────┬────────────┘  │           │    (Monitoring)    │
   │               │               │           └────────────────────┘
   │  ┌────────────▼────────────┐  │
   │  │     Ubuntu Server       │  │           ┌────────────────────┐
   │  │  ┌─────────────────┐    │  │           │   EXTERNAL DATA    │
   │  │  │  Wazuh (Docker) │◄───┼──┼──────────►│  OFFSITE BACKUP    │
   │  │  ├─────────────────┤    │  │           └────────────────────┘
   │  │  │ Automated Backup│    │  │
   │  │  └─────────────────┘    │  │
   │  └─────────────────────────┘  │
   └───────────────────────────────┘
```
| Machine | OS | Role |
|---|---|---|
| DC01 | Windows Server 2022 | Domain Controller — SOC.local |
| WORKSTATION01 | Windows 10 Pro | Domain-joined Victim Endpoint |
| SIEM01 | Ubuntu Server | Wazuh SIEM + Backup (Docker) |
| ATTACKER | Kali Linux | Red Team / Threat Actor |
| FIREWALL | pfSense | Network Segmentation & Routing |

---

## Attack Simulation (Planned)
  ### Phase 1 — Reconnaissance & Initial Access
  - **Technique:** LLMNR/NBT-NS Poisoning
  - **Tool:** Responder
  - **Goal:** Capture NTLMv2 hashes from broadcast traffic without touching the DC
  - **MITRE:** [T1557.001](https://attack.mitre.org/techniques/T1557/001/)

  ### Phase 2 — Credential Access
  - **Technique:** Kerberoasting
  - **Tool:** Impacket `GetUserSPNs.py`, Rubeus
  - **Goal:** Extract TGS tickets for service accounts → offline cracking
  - **MITRE:** [T1558.003](https://attack.mitre.org/techniques/T1558/003/)

  ### Phase 3 — Lateral Movement
  - **Technique:** Pass-the-Hash
  - **Tool:** CrackMapExec, Impacket `psexec.py`
  - **Goal:** Authenticate to other machines using NTLM hash — no plaintext password needed
  - **MITRE:** [T1550.002](https://attack.mitre.org/techniques/T1550/002/)

  ### Phase 4 — Privilege Escalation → Domain Admin
  - **Tool:** BloodHound, SharpHound, PowerView
  - **Goal:** Map AD misconfigurations and escalate privileges to Domain Admin
  - **MITRE:** [T1078.002](https://attack.mitre.org/techniques/T1078/002/)

  ## Detection Engineering (Planned)
Each attack phase will have a corresponding **custom Wazuh rule** with MITRE mapping.

| Attack | Log Source | Key Indicator | MITRE |
|---|---|---|---|
| LLMNR Poisoning | Network / pfSense | UDP 5355/137 anomalies, unexpected outbound NTLMv2 | T1557.001 |
| Kerberoasting | Windows Security Log | Event ID **4769** — RC4/DES encryption requested | T1558.003 |
| Pass-the-Hash | Windows Security Log | Event ID **4624** — Logon Type 9 from unusual source | T1550.002 |
| Privilege Escalation | Windows Security Log | Event ID **4728** — Member added to privileged group | T1078.002 |

> Custom Wazuh rules will be added to [`/detection-rules/`](./detection-rules/) as the project progresses.

---

## Response (Planned)
  - **Alerting:** Real-time notifications triggered on critical AD security group changes
  - **Host Isolation:** Automated containment of compromised endpoints via Wazuh active response agents
  - **Escalation:** Alert severity tiers mapped to response runbooks

## Hardening (Planned)
These will be validated and documented after each attack simulation:

- Disable legacy protocols (LLMNR/NetBIOS) via **Group Policy (GPO)**
- Implement **Group Managed Service Accounts (gMSA)** with auto-rotating complex passwords
- Enforce a **Tiered Administration Model** to prevent credential reuse across tiers
- Enable **Protected Users Security Group** for privileged accounts
- Require **AES-only Kerberos encryption** — disable RC4/DES

---

## Tools

**Red Team**

| Tool | Purpose |
|---|---|
| Responder | LLMNR/NBT-NS Poisoning |
| Impacket | PtH, Kerberoasting, remote execution |
| CrackMapExec | Lateral movement & AD enumeration |
| BloodHound + SharpHound | AD attack path discovery |
| Rubeus | Kerberos ticket abuse |
| Hashcat | Offline hash cracking |

**Blue Team**

| Tool | Purpose |
|---|---|
| Wazuh (Docker) | SIEM, XDR, active response |
| pfSense | Firewall, VLAN segmentation |
| Sysmon | Deep Windows endpoint telemetry |
| Azure Entra ID | Hybrid cloud identity monitoring |
| Wireshark | Network traffic analysis |

---

## MITRE ATT&CK Mapping

| Tactic | Technique | ID |
|---|---|---|
| Credential Access | LLMNR/NBT-NS Poisoning and SMB Relay | T1557.001 |
| Credential Access | Kerberoasting | T1558.003 |
| Lateral Movement | Pass the Hash | T1550.002 |
| Privilege Escalation | Valid Accounts: Domain Accounts | T1078.002 |

---

## Project Status

- [x] Lab environment setup & network segmentation
- [x] Wazuh deployment and agent configuration
- [x] Sysmon deployment on Windows machines
- [x] Phase 1 — LLMNR Poisoning simulation + detection rule
- [x] Phase 2 — Kerberoasting simulation + detection rule
- [x] Phase 3 — Pass-the-Hash simulation + detection rule
- [x] Phase 4 — Privilege Escalation simulation + detection rule
- [ ] Azure Entra ID integration
- [ ] Automated offsite backup pipeline
- [ ] Full compromise report

---

## Legal Disclaimer

> This project is conducted entirely within a **self-owned, isolated lab environment** for educational and professional development purposes only.  
> All techniques demonstrated are used strictly for **understanding and improving defensive security**.  
> Do **not** reproduce any of these techniques on systems you do not own or have explicit written authorization to test.

---

## Author

**Othmane Benmezian**  
Cybersecurity | Adversary Simulation . Blue Team · Detection Engineering · Incident Response

---

*"Offense informs defense. You can't detect what you don't understand."*
