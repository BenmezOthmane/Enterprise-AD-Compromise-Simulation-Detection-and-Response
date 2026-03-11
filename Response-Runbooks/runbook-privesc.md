# Response Runbook — Privilege Escalation via DCSync
**Technique:** T1003.006, T1078.002  
**Severity:** CRITICAL  
**Detection:** Wazuh Rule 100031 — Event ID 4662  

---

## Trigger Conditions
- Wazuh Rule 100031 fires — level 15 CRITICAL
- Event ID 4662 — Replication Extended Rights on domain object
- GUID: 1131f6aa-9c07-11d1-f79f-00c04fc2dcd2 detected
- Non-DC account performing replication

---

## Immediate Actions (0-15 minutes)

### Step 1 — Confirm DCSync activity
```
Wazuh Dashboard → Discover →
rule.id: 100031 →
Check data.win.eventdata.subjectUserName
Check data.win.eventdata.properties
```

### Step 2 — Identify compromised account
```powershell
# On DC01 — find who performed replication
Get-WinEvent -LogName Security -FilterXPath `
"*[System[EventID=4662]]" -MaxEvents 10 |
Select TimeCreated, Message
```

### Step 3 — Disable compromised account IMMEDIATELY
```powershell
# This is the most critical step
Disable-ADAccount -Identity svc-mssql
Write-Host "CRITICAL: svc-mssql disabled" -ForegroundColor Red
```

---

## Investigation (15-60 minutes)

### Step 4 — Assess blast radius
```powershell
# Check all accounts whose hashes were exposed
Get-ADUser -Filter * -Properties PasswordLastSet |
Select Name, SamAccountName, PasswordLastSet |
Sort PasswordLastSet
```

### Step 5 — Check for WriteDACL abuse
```powershell
# Audit ACLs on domain object
$acl = Get-Acl "AD:DC=SOC,DC=local"
$acl.Access | Where-Object {
    $_.ActiveDirectoryRights -match "ExtendedRight"
} | Select IdentityReference, ActiveDirectoryRights
```

### Step 6 — Check BloodHound for attack path
```bash
# Re-run BloodHound to map current state
bloodhound-python -u Administrator -p 'PASSWORD' \
  -d SOC.local -ns 10.0.0.10 -c ACL
```

### Step 7 — Check for Golden Ticket usage
```powershell
# Look for anomalous Kerberos tickets
Get-WinEvent -LogName Security -FilterXPath `
"*[System[EventID=4768 or EventID=4769]]" -MaxEvents 50 |
Select TimeCreated, Message
```

---

## Containment

### Step 8 — Revoke DCSync rights
```bash
# From Kali — remove DCSync DACL
python3 dacledit.py \
  -action remove \
  -rights DCSync \
  -principal svc-mssql \
  -target-dn "DC=SOC,DC=local" \
  -dc-ip 10.0.0.10 \
  'SOC.local/Administrator:PASSWORD'
```

### Step 9 — Rotate krbtgt password TWICE
```powershell
# First rotation
Set-ADAccountPassword -Identity krbtgt `
  -NewPassword (ConvertTo-SecureString "Kr5tgt@2026!First" -AsPlainText -Force) `
  -Reset

Write-Host "Wait 10 hours before second rotation" -ForegroundColor Yellow

# Second rotation (10 hours later)
Set-ADAccountPassword -Identity krbtgt `
  -NewPassword (ConvertTo-SecureString "Kr5tgt@2026!Second" -AsPlainText -Force) `
  -Reset
```

### Step 10 — Reset Administrator password
```powershell
Set-ADAccountPassword -Identity Administrator `
  -NewPassword (ConvertTo-SecureString "Adm1n@NewP@ss2026!" -AsPlainText -Force) `
  -Reset
```

---

## Recovery

### Step 11 — Reset all exposed account passwords
```powershell
# Reset all domain user passwords
$users = Get-ADUser -Filter * -Properties SamAccountName
foreach ($user in $users) {
    $newPassword = ConvertTo-SecureString `
      "TempP@ss$(Get-Random)!" -AsPlainText -Force
    Set-ADAccountPassword -Identity $user.SamAccountName `
      -NewPassword $newPassword -Reset
    Set-ADUser -Identity $user.SamAccountName `
      -ChangePasswordAtLogon $true
}
Write-Host "All passwords reset" -ForegroundColor Green
```

### Step 12 — Audit all ACLs via BloodHound
```bash
# Full ACL audit
bloodhound-python -u Administrator -p 'PASSWORD' \
  -d SOC.local -ns 10.0.0.10 -c ALL
```

---

## Post-Incident

| Action | Owner | Deadline |
|---|---|---|
| Disable compromised account | AD Admin | IMMEDIATE |
| Rotate krbtgt (×2) | AD Admin | IMMEDIATE + 10hrs |
| Reset Administrator password | AD Admin | IMMEDIATE |
| Revoke DCSync DACL rights | AD Admin | 1 hour |
| Reset all domain passwords | AD Admin | 24 hours |
| Full BloodHound ACL audit | Security Team | 48 hours |
| Implement tiered admin model | AD Admin | 1 week |
| Deploy PAW workstations | AD Admin | 1 month |

---

## Why firewall-drop Does Not Apply

DCSync Event 4662 is logged on DC01 — not on the attacker machine.
Blocking DC01 via firewall-drop would isolate the Domain Controller.

**Correct response:** Disable account + Rotate krbtgt (see steps above)

---

## Detection Validation
```powershell
# Verify DCSync rights are removed
$acl = Get-Acl "AD:DC=SOC,DC=local"
$acl.Access | Where-Object {
    $_.IdentityReference -match "svc-mssql" -and
    $_.ActiveDirectoryRights -match "ExtendedRight"
}
# Expected: No results
```