# Response Runbook — Pass-the-Hash
**Technique:** T1550.002  
**Severity:** CRITICAL  
**Detection:** Wazuh Rule 100020 — Event ID 4624 NTLM Logon Type 3  

---

## Trigger Conditions
- Wazuh Rule 100020 fires
- Event ID 4624 — NTLM Logon Type 3 from unexpected source
- SMB authentication from non-domain IP
- Wazuh Rule 100021 — Repeated NTLM logons (CRITICAL)

---

## Immediate Actions (0-15 minutes)

### Step 1 — Identify attacker IP
```
Wazuh Dashboard → Discover →
rule.id: 100020 →
Check data.win.eventdata.ipAddress
```

### Step 2 — Identify compromised account
```
Check data.win.eventdata.targetUserName
Check data.win.eventdata.workstationName
```

### Step 3 — Block attacker IP immediately
```powershell
# On compromised host
New-NetFirewallRule -DisplayName "Block PtH Attacker" `
  -Direction Inbound `
  -RemoteAddress <ATTACKER_IP> `
  -Action Block
```

---

## Investigation (15-60 minutes)

### Step 4 — Check accessed resources
```powershell
# Find all SMB access from attacker
Get-WinEvent -LogName Security -FilterXPath `
"*[System[EventID=5140]]" -MaxEvents 50 |
Select TimeCreated, Message
```

### Step 5 — Check for persistence
```powershell
# Look for new accounts or group changes
Get-WinEvent -LogName Security -FilterXPath `
"*[System[EventID=4720 or EventID=4728]]" -MaxEvents 20 |
Select TimeCreated, Message
```

### Step 6 — Determine hash source
```
Trace back to Phase 2 — which account hash was used?
Check if Kerberoasting preceded this event
Review Event ID 4769 logs
```

---

## Containment

### Step 7 — Disable compromised account
```powershell
Disable-ADAccount -Identity svc-mssql
Write-Host "Account disabled" -ForegroundColor Red
```

### Step 8 — Reset password
```powershell
Set-ADAccountPassword -Identity svc-mssql `
  -NewPassword (ConvertTo-SecureString "NewR@nd0mP@ss2026!" -AsPlainText -Force) `
  -Reset
```

### Step 9 — Enable Protected Users
```powershell
# Add to Protected Users group — prevents NTLM auth
Add-ADGroupMember -Identity "Protected Users" `
  -Members svc-mssql
```

---

## Recovery

### Step 10 — Deploy LAPS
```powershell
# Install LAPS on all workstations
Install-Module -Name LAPS
Set-LAPSADSchema
```

### Step 11 — Disable NTLM where possible
```
Group Policy →
Computer Configuration →
Windows Settings → Security Settings →
Local Policies → Security Options →
Network security: Restrict NTLM → Deny All
```

---

## Post-Incident

| Action | Owner | Deadline |
|---|---|---|
| Disable compromised account | AD Admin | Immediate |
| Block attacker IP | SOC | Immediate |
| Reset all exposed hashes | AD Admin | 1 hour |
| Deploy LAPS | AD Admin | 1 week |
| Disable NTLM domain-wide | AD Admin | 48 hours |
| Enable Credential Guard | AD Admin | 1 week |
| Review all SMB access logs | SOC | 24 hours |

---

## Detection Validation
```powershell
# Verify Protected Users membership
Get-ADGroupMember "Protected Users" |
Select Name
# Expected: svc-mssql listed
```
