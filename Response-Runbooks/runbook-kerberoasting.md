# Response Runbook — Kerberoasting
**Technique:** T1558.003  
**Severity:** HIGH  
**Detection:** Wazuh Rule 100010 — Event ID 4769 RC4  

---

## Trigger Conditions
- Wazuh Rule 100010 fires
- Event ID 4769 — Kerberos TGS request with RC4 encryption (0x17)
- Multiple TGS requests from single user in short timeframe

---

## Immediate Actions (0-15 minutes)

### Step 1 — Identify the source
```powershell
# On DC01 — find who requested RC4 tickets
Get-WinEvent -LogName Security -FilterXPath `
"*[System[EventID=4769]]" -MaxEvents 20 |
Select TimeCreated, Message
```

### Step 2 — Identify targeted service accounts
```
Wazuh Dashboard → Discover →
data.win.system.eventID: 4769 →
data.win.eventdata.ticketEncryptionType: 0x17 →
Check data.win.eventdata.serviceName
```

### Step 3 — Check if hash was cracked
```
Assess password strength of targeted service accounts
Assume hash is cracked if password age > 90 days
or password complexity is low
```

---

## Investigation (15-60 minutes)

### Step 4 — Find all Kerberoastable accounts
```powershell
# On DC01
Get-ADUser -Filter {ServicePrincipalName -ne "$null"} `
  -Properties ServicePrincipalName, PasswordLastSet, PasswordNeverExpires |
  Select Name, ServicePrincipalName, PasswordLastSet, PasswordNeverExpires
```

### Step 5 — Check for lateral movement
```powershell
# Look for suspicious logons after the TGS request
Get-WinEvent -LogName Security -FilterXPath `
"*[System[EventID=4624]]" -MaxEvents 50 |
Select TimeCreated, Message
```

---

## Containment

### Step 6 — Reset service account password immediately
```powershell
Set-ADAccountPassword -Identity svc-mssql `
  -NewPassword (ConvertTo-SecureString "R@nd0mP@ssw0rd2026!#$" -AsPlainText -Force) `
  -Reset
```

### Step 7 — Enforce AES encryption
```powershell
# Disable RC4 for service account
Set-ADUser -Identity svc-mssql `
  -KerberosEncryptionType AES256
```

---

## Recovery

### Step 8 — Migrate to gMSA
```powershell
# Create Group Managed Service Account
New-ADServiceAccount -Name "gmsa-mssql" `
  -DNSHostName "gmsa-mssql.SOC.local" `
  -PrincipalsAllowedToRetrieveManagedPassword "Domain Computers"

# Install on target server
Install-ADServiceAccount -Identity "gmsa-mssql"
```

### Step 9 — Audit all SPNs
```powershell
# Find all accounts with SPNs
Get-ADObject -Filter {ServicePrincipalName -ne "$null"} `
  -Properties ServicePrincipalName |
  Select Name, ServicePrincipalName
```

---

## Post-Incident

| Action | Owner | Deadline |
|---|---|---|
| Reset all service account passwords | AD Admin | Immediate |
| Migrate to gMSA | AD Admin | 1 week |
| Enforce AES-only Kerberos | AD Admin | 48 hours |
| Audit all SPNs | AD Admin | 24 hours |
| Monitor Event ID 4769 RC4 | SOC | Ongoing |

---

## Detection Validation
```powershell
# Verify RC4 is disabled for service account
Get-ADUser svc-mssql -Properties KerberosEncryptionType |
Select KerberosEncryptionType
# Expected: AES256
```