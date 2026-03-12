# Threat Model — Enterprise AD Compromise Simulation

**Version:** 1.0  
**Date:** March 2026  
**Author:** Othmane Benmezian  
**Environment:** SOC.local — Windows Server 2022 AD Lab  

---

## 1. Scope

This threat model covers the SOC.local Active Directory environment
consisting of one Domain Controller, one workstation, one SIEM, and
one attacker machine simulating an insider or network-adjacent threat.

---

## 2. Assets

| Asset | Type | Value | Location |
|---|---|---|---|
| DC01 | Domain Controller | CRITICAL | 10.0.0.10 |
| NTDS.dit | AD Credentials Database | CRITICAL | DC01 |
| krbtgt account | Kerberos Root Account | CRITICAL | DC01 |
| Administrator account | Domain Admin | CRITICAL | DC01 |
| WORKSTATION01 | Endpoint | HIGH | 10.0.0.30 |
| Service Accounts (svc-mssql) | Privileged Account | HIGH | SOC.local |
| Domain User Accounts (User1-20) | User Accounts | MEDIUM | SOC.local |
| SIEM01 | Security Monitoring | HIGH | 10.0.0.20 |

---

## 3. Threat Actors

| Actor | Type | Motivation | Capability |
|---|---|---|---|
| External Attacker | Network-adjacent | Data theft, ransomware | HIGH |
| Malicious Insider | Domain user | Privilege abuse | MEDIUM |
| Compromised Account | Credential theft | Lateral movement | HIGH |
| APT Group | Advanced persistent | Espionage | VERY HIGH |

---

## 4. Attack Vectors

### 4.1 LLMNR/NBT-NS Poisoning
```
Entry Point:    Corporate network segment
Prerequisite:   None — unauthenticated
Technique:      T1557.001
Impact:         Credential theft
Likelihood:     HIGH — LLMNR enabled by default
```

### 4.2 Kerberoasting
```
Entry Point:    Any domain-authenticated user
Prerequisite:   Valid domain credentials
Technique:      T1558.003
Impact:         Service account compromise
Likelihood:     HIGH — RC4 enabled, weak passwords
```

### 4.3 Pass-the-Hash
```
Entry Point:    Attacker with NTLM hash
Prerequisite:   Compromised service account hash
Technique:      T1550.002
Impact:         Lateral movement to workstations
Likelihood:     HIGH — NTLM authentication enabled
```

### 4.4 DCSync via ACL Abuse
```
Entry Point:    Compromised service account
Prerequisite:   WriteDACL on domain object
Technique:      T1003.006 + T1078.002
Impact:         Full domain compromise
Likelihood:     MEDIUM — Requires misconfiguration
```

---

## 5. Risk Matrix

| Threat | Likelihood | Impact | Risk Level |
|---|---|---|---|
| LLMNR Poisoning | HIGH | HIGH | 🔴 CRITICAL |
| Kerberoasting | HIGH | HIGH | 🔴 CRITICAL |
| Pass-the-Hash | HIGH | CRITICAL | 🔴 CRITICAL |
| DCSync | MEDIUM | CRITICAL | 🔴 CRITICAL |
| Golden Ticket | LOW | CRITICAL | 🟠 HIGH |
| Brute Force | MEDIUM | MEDIUM | 🟡 MEDIUM |
| Phishing | HIGH | MEDIUM | 🟠 HIGH |

---

## 6. MITRE ATT&CK Coverage

| Tactic | Technique | Covered |
|---|---|---|
| Initial Access | T1557.001 LLMNR Poisoning | ✅ Phase 1 |
| Credential Access | T1558.003 Kerberoasting | ✅ Phase 2 |
| Lateral Movement | T1550.002 Pass-the-Hash | ✅ Phase 3 |
| Privilege Escalation | T1078.002 Domain Accounts | ✅ Phase 4 |
| Credential Dumping | T1003.006 DCSync | ✅ Phase 4 |
| Defense Evasion | T1484.001 ACL Modification | ✅ Phase 4 |

---

## 7. Security Controls

### Existing Controls
| Control | Status | Effectiveness |
|---|---|---|
| Wazuh SIEM | ✅ Active | HIGH |
| Sysmon | ✅ Active | HIGH |
| pfSense Firewall | ✅ Active | MEDIUM |
| Custom Detection Rules | ✅ Active | HIGH |
| Active Response | ✅ Configured | MEDIUM |

### Missing Controls
| Control | Priority | Mitigates |
|---|---|---|
| Disable LLMNR via GPO | CRITICAL | T1557.001 |
| Enforce AES-only Kerberos | CRITICAL | T1558.003 |
| Disable NTLM | HIGH | T1550.002 |
| Remove WriteDACL from service accounts | CRITICAL | T1003.006 |
| Implement gMSA | HIGH | T1558.003 |
| Deploy LAPS | HIGH | T1550.002 |
| Enable Protected Users Group | HIGH | Multiple |
| Tiered Administration Model | HIGH | Multiple |

---

## 8. Assumptions

- Attacker has physical or network access to the corporate segment
- No EDR solution deployed on endpoints
- Default Windows configurations in place
- Service accounts have weak passwords
- No privileged access workstations (PAW) deployed
- LLMNR and NBT-NS enabled by default

---

## 9. Out of Scope

- Physical security attacks
- Social engineering / phishing
- Zero-day exploits
- Cloud infrastructure attacks
- External perimeter attacks

---

## 10. Conclusion

The SOC.local environment contains multiple critical misconfigurations
that allow a network-adjacent attacker to escalate from zero credentials
to full Domain Admin.

All attack phases were successfully detected by Wazuh using custom
rules mapped to MITRE ATT&CK. However, detection alone is insufficient
without the missing security controls listed above.

**Overall Risk Rating: 🔴 CRITICAL**
