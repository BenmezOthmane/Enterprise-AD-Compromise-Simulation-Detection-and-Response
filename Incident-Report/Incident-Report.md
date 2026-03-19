# Incident Report — Enterprise AD Compromise
**Classification:** CRITICAL  
**Date:** March 2026  
**Prepared by:** Othmane Benmezian  
**Environment:** SOC.local — Windows Server 2022 AD Lab  
**Status:** Resolved  

---

## Executive Summary

A full Active Directory compromise was simulated across 4 attack phases,
starting from an unauthenticated attacker on the network segment
and ending with complete Domain Admin access and credential dumping
of all 28 domain accounts including Administrator and krbtgt.

Every phase was detected by Wazuh SIEM with custom detection rules
mapped to MITRE ATT&CK framework. Detection rate: 4/4 — 100%.

---

## Environment

| Component | Details |
|---|---|
| Domain | SOC.local |
| Domain Controller | DC01 — Windows Server 2022 (10.0.0.10) |
| Victim Endpoint | WORKSTATION01 — Windows 10 Pro (10.0.0.30) |
| Attacker | Kali Linux (10.0.0.99) |
| SIEM | Wazuh 4.9.0 (Docker/Ubuntu 10.0.0.20) |
| Network | Corporate_Network + Attacker_Zone (pfSense) |

---

## Attack Chain
```
Initial Access
└── LLMNR Poisoning (T1557.001)
    └── Credential Access
        └── Kerberoasting (T1558.003)
            └── Lateral Movement
                └── Pass-the-Hash (T1550.002)
                    └── Privilege Escalation
                        └── DCSync (T1003.006)
                            └── DOMAIN COMPROMISED
```

---

## Attack Phases

### Phase 1 — LLMNR/NBT-NS Poisoning
- **Technique:** T1557.001
- **Tool:** Responder
- **Target:** WORKSTATION01
- **Result:** NTLMv2 hash captured and cracked → testuser:Password123
- **Detection:** Wazuh Rule 100001 — Event ID 4648
- **Severity:** HIGH

### Phase 2 — Kerberoasting
- **Technique:** T1558.003
- **Tool:** Rubeus v2.2.0
- **Target:** svc-mssql service account
- **Result:** TGS ticket extracted and cracked → svc-mssql:Password1
- **Detection:** Wazuh Rule 100010 — Event ID 4769 RC4 (0x17)
- **Severity:** HIGH

### Phase 3 — Pass-the-Hash
- **Technique:** T1550.002
- **Tool:** CrackMapExec, Impacket smbclient.py
- **Target:** WORKSTATION01, DC01
- **Result:** ADMIN$, C$, IPC$ accessed via NTLM hash
- **Detection:** Wazuh Rule 92652 — Event ID 4624 NTLM
- **Active Response:** firewall-drop configured
- **Severity:** CRITICAL

### Phase 4 — Privilege Escalation via DCSync
- **Technique:** T1003.006, T1078.002
- **Tool:** BloodHound CE, dacledit.py, secretsdump.py
- **Target:** DC01
- **Result:** All 28 domain hashes dumped including Administrator and krbtgt
- **Detection:** Wazuh Rule 100031 — Event ID 4662 — fired 53 times
- **Severity:** CRITICAL

---

## Affected Accounts

| Account | Type | Status |
|---|---|---|
| testuser | Domain User | ✅ Password123 cracked |
| svc-mssql | Service Account | ✅ Password1 cracked |
| Administrator | Domain Admin | ✅ Hash dumped |
| krbtgt | Kerberos Account | ✅ Hash dumped |
| User1–User20 | Domain Users | ✅ Hashes dumped |
| DC-022$ | Computer Account | ✅ Hash dumped |

---

## Detection Summary

| Rule ID | Level | Technique | Event ID | Detected |
|---|---|---|---|---|
| 100001 | 10 | T1557.001 — LLMNR Poisoning | 4648 | ✅ |
| 100010 | 14 | T1558.003 — Kerberoasting | 4769 | ✅ |
| 92652 | 6 | T1550.002 — Pass-the-Hash | 4624 | ✅ |
| 100031 | 15 | T1003.006 — DCSync | 4662 | ✅ 53x |

**Detection Rate: 4/4 — 100%** ✅

---

## Impact Assessment

| Asset | Impact |
|---|---|
| Domain Controller | CRITICAL — Full compromise |
| All domain accounts | CRITICAL — 28 hashes exposed |
| krbtgt account | CRITICAL — Golden Ticket attack possible |
| WORKSTATION01 | HIGH — Lateral movement achieved |
| Active Directory | CRITICAL — DCSync performed |

---

## Root Cause Analysis

| Vulnerability | Impact |
|---|---|
| LLMNR enabled by default | Initial credential theft |
| Weak service account password (Password1) | Kerberoasting success in seconds |
| NTLM authentication enabled | Pass-the-Hash lateral movement |
| WriteDACL misconfiguration on domain object | Full domain compromise |
| No privileged account monitoring | Late detection |

---

## Immediate Response Actions
```powershell
# 1. Disable compromised accounts
Disable-ADAccount -Identity svc-mssql
Disable-ADAccount -Identity testuser

# 2. Rotate krbtgt password (twice, 10 hours apart)
Set-ADAccountPassword -Identity krbtgt `
  -NewPassword (ConvertTo-SecureString "NewP@ssw0rd2026!" -AsPlainText -Force) `
  -Reset

# 3. Revoke DCSync rights
# Run: dacledit.py -action remove -rights DCSync -principal svc-mssql

# 4. Disable LLMNR via GPO
# Computer Configuration → Administrative Templates →
# Network → DNS Client → Turn off multicast name resolution → Enabled

# 5. Reset all exposed passwords
# Reset all 20+ domain user passwords immediately
```

---

## Recommendations

| Priority | Action |
|---|---|
| CRITICAL | Disable LLMNR and NBT-NS domain-wide |
| CRITICAL | Remove WriteDACL from all service accounts |
| CRITICAL | Rotate krbtgt password immediately |
| CRITICAL | Enforce strong passwords for service accounts (25+ chars) |
| HIGH | Enforce AES-only Kerberos — disable RC4 |
| HIGH | Implement LAPS for local admin accounts |
| HIGH | Deploy Protected Users Security Group |
| HIGH | Disable NTLM authentication domain-wide |
| HIGH | Regular BloodHound ACL audits |
| MEDIUM | Enable Windows Defender Credential Guard |
| MEDIUM | Implement tiered administration model |

---

## Lessons Learned

1. **Default configurations are dangerous** — LLMNR enabled by default
   led directly to credential theft with zero exploitation.

2. **Service accounts need strong passwords** — RC4 encryption
   made Kerberoasting trivial and offline cracking instant.

3. **ACL misconfigurations are critical** — A single WriteDACL
   on the domain object led to full domain compromise.

4. **Detection works** — Wazuh detected every phase with
   custom rules mapped to MITRE ATT&CK framework.

5. **Active Response needs careful design** — firewall-drop
   is not always the right response. DCSync logs on DC01,
   not on the attacker — blocking DC01 would be catastrophic.

---

## Evidence

| File | Description |
|---|---|
| `Evidence/Screenshots/phase1-llmnr-hash-captured.png` | NTLMv2 hash captured |
| `Evidence/Screenshots/phase1-hash-cracked.png` | Hash cracked → Password123 |
| `Evidence/Screenshots/phase1-wazuh-alert-100001.png` | Wazuh rule 100001 triggered |
| `Evidence/Screenshots/phase2-rubeus-kerberoast.png` | TGS ticket extracted |
| `Evidence/Screenshots/phase2-tgs-cracked.png` | Hash cracked → Password1 |
| `Evidence/Screenshots/phase2-wazuh-alert-100010.png` | Wazuh rule 100010 triggered |
| `Evidence/Screenshots/phase3-crackmapexec.png` | PtH confirmed on DC01 |
| `Evidence/Screenshots/phase3-smbclient-shares.png` | SMB lateral movement |
| `Evidence/Screenshots/phase3-wazuh-pth-detected.png` | Wazuh detection T1550.002 |
| `Evidence/Screenshots/phase4-dacledit-success.png` | DCSync rights granted |
| `Evidence/Screenshots/phase4-dcsync-success.png` | All 28 hashes dumped |
| `Evidence/Screenshots/phase4-wazuh-rule100031.png` | CRITICAL detection — 53x |