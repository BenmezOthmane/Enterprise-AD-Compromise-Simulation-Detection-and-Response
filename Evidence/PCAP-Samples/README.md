# PCAP Samples

> PCAP files are stored locally and excluded from version control
> for security reasons (.gitignore: *.pcap).

## Captured Traffic

| File | Size | Phase | Content |
|---|---|---|---|
| phase1-llmnr.pcap | 8.7MB | Phase 1 | LLMNR broadcast + NTLMv2 challenge/response |
| phase2-kerberoast.pcap | 1.8MB | Phase 2 | Kerberos TGS-REQ/REP with RC4 encryption |
| phase3-pth.pcap | 142KB | Phase 3 | SMB NTLM authentication via hash |
| phase4-dcsync.pcap | 21MB | Phase 4 | DRSUAPI replication traffic + Kerberos |

## How to Analyze
```bash
# Open with Wireshark
wireshark phase1-llmnr.pcap

# Filter LLMNR traffic
udp.port == 5355

# Filter Kerberos traffic
kerberos

# Filter SMB traffic
smb2

# Filter DCSync (DRSUAPI)
drsuapi
```

## Collection Method
All PCAP files captured using tcpdump on Kali Linux attacker machine
during live attack execution against the SOC.local lab environment.