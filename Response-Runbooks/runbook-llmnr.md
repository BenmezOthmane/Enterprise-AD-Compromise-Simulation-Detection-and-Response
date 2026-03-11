# Response Runbook — LLMNR/NBT-NS Poisoning
**Technique:** T1557.001  
**Severity:** HIGH  
**Detection:** Wazuh Rule 100001 — Event ID 4648  

---

## Trigger Conditions
- Wazuh Rule 100001 fires
- Event ID 4648 — Explicit credential use to unknown host
- NTLM authentication from unexpected source IP

---

## Immediate Actions (0-15 minutes)

### Step 1 — Identify the victim
```powershell
# On DC01 — find who triggered the alert
Get-WinEvent -LogName Security -FilterXPath `
"*[System[EventID=4648]]" -MaxEvents 20 |
Select TimeCreated, Message
```

### Step 2 — Identify the attacker IP
```
Wazuh Dashboard → Discover →
data.win.system.eventID: 4648 →
Check source IP in alert
```

### Step 3 — Isolate if needed
```powershell
# Block attacker IP on DC01 firewall
New-NetFirewallRule -DisplayName "Block Attacker" `
  -Direction Inbound `
  -RemoteAddress <ATTACKER_IP> `
  -Action Block
```

---

## Investigation (15-60 minutes)

### Step 4 — Check for captured hashes
```
Look for repeated 4648 events from same user
Check if NTLM authentication succeeded (Event 4624)
```

### Step 5 — Determine scope
```powershell
# Check all recent NTLM authentications
Get-WinEvent -LogName Security -FilterXPath `
"*[System[EventID=4624] and EventData[Data[@Name='AuthenticationPackageName']='NTLM']]" `
-MaxEvents 50
```

---

## Containment

### Step 6 — Disable LLMNR via GPO
```
Group Policy Management →
Computer Configuration →
Administrative Templates →
Network → DNS Client →
Turn off multicast name resolution → Enabled
```

### Step 7 — Disable NBT-NS
```powershell
# On all workstations
$regkey = "HKLM:SYSTEM\CurrentControlSet\services\NetBT\Parameters\Interfaces"
Get-ChildItem $regkey | ForEach-Object {
    Set-ItemProperty -Path "$regkey\$($_.PSChildName)" `
    -Name NetbiosOptions -Value 2
}
```

---

## Recovery

### Step 8 — Reset compromised account password
```powershell
Set-ADAccountPassword -Identity <USERNAME> `
  -NewPassword (ConvertTo-SecureString "NewP@ssw0rd!" -AsPlainText -Force) `
  -Reset
```

### Step 9 — Force re-authentication
```powershell
# Invalidate existing sessions
Invoke-Command -ComputerName WORKSTATION01 {
    query session
    logoff <SESSION_ID>
}
```

---

## Post-Incident

| Action | Owner | Deadline |
|---|---|---|
| Disable LLMNR domain-wide | AD Admin | Immediate |
| Disable NBT-NS on all hosts | AD Admin | 24 hours |
| Enable SMB Signing | AD Admin | 48 hours |
| Security awareness training | HR/Security | 1 week |
| Review all NTLM authentications | SOC | 24 hours |

---

## Detection Validation
```powershell
# Verify LLMNR is disabled
Get-ItemProperty `
"HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" `
-Name EnableMulticast
# Expected: 0
```
