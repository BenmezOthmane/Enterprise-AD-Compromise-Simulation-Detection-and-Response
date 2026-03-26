# Azure Integration

## Overview
Wazuh alerts forwarded to Microsoft Sentinel via Logstash pipeline.
900+ security alerts successfully ingested into cloud SIEM.

## Components
| File | Description |
|---|---|
| `sentinel-connector.md` | Sentinel + Logstash pipeline setup |
| `entra-id-setup.md` | Azure Entra ID + App Registration |

## Status
| Component | Status |
|---|---|
| Log Analytics Workspace | ✅ Active — West Europe |
| Microsoft Sentinel | ✅ Active (Free Trial until 15 Apr 2026) |
| App Registration | ✅ wazuh-sentinel-app configured |
| Data Collection Endpoint | ✅ wazuh-endpoint deployed |
| Data Collection Rule | ✅ wazuh-dcr active |
| Logstash Pipeline | ✅ Running — forwarding alerts to Sentinel |
| Wazuh Alerts in Sentinel | ✅ 900+ alerts ingested — WazuhAlerts_CL_CL |