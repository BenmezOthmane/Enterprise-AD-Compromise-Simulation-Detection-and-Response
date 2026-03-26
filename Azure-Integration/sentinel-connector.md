# Azure Sentinel Integration

## Overview
Microsoft Sentinel configured as cloud SIEM to receive Wazuh alerts
for centralized threat monitoring and correlation.
900+ Wazuh alerts successfully ingested via Logstash pipeline.

## Architecture
```
Wazuh Manager (Docker/Ubuntu)
        ↓
alerts.json (Docker Volume)
        ↓
Logstash 8.x (Ubuntu — root service)
        ↓
Azure Data Collection Endpoint (wazuh-endpoint)
        ↓
Data Collection Rule (wazuh-dcr)
        ↓
Microsoft Sentinel — WazuhAlerts_CL_CL table
```

## Azure Components
| Component | Name | Details |
|---|---|---|
| Resource Group | RG-SOC-Lab | West Europe |
| Log Analytics Workspace | RG-SOC-Lab | Free Trial — 10GB/day |
| Microsoft Sentinel | RG-SOC-Lab | Active until 15 Apr 2026 |
| App Registration | wazuh-sentinel-app | Single tenant |
| Data Collection Endpoint | wazuh-endpoint | West Europe |
| Data Collection Rule | wazuh-dcr | immutableId: dcr-1e9dc08698d54bf0b4d2ce5783a3182e |

## App Registration Details
| Field | Value |
|---|---|
| Display name | wazuh-sentinel-app |
| API Permission | Log Analytics API — Data.Read |
| IAM Role (Workspace) | Log Analytics Data Reader |
| IAM Role (DCR) | Monitoring Metrics Publisher |
| Client Secret | Configured (expires 3/15/2027) |

## Logstash Configuration
```ruby
input {
  file {
    path => "/var/lib/docker/volumes/single-node_wazuh_logs/_data/alerts/alerts.json"
    codec => "json"
    start_position => "beginning"
    sincedb_path => "/dev/null"
  }
}

filter {
  mutate {
    add_field => { "TimeGenerated" => "%{@timestamp}" }
  }
}

output {
  microsoft-sentinel-log-analytics-logstash-output-plugin {
    client_app_Id => "<APP_CLIENT_ID>"
    client_app_secret => "<CLIENT_SECRET>"
    tenant_id => "<TENANT_ID>"
    data_collection_endpoint => "https://wazuh-endpoint-f5jk.westeurope-1.ingest.monitor.azure.com"
    dcr_immutable_id => "dcr-1e9dc08698d54bf0b4d2ce5783a3182e"
    dcr_stream_name => "Custom-WazuhAlerts_CL_CL"
  }
}
```

## Result
```
Successfully posted 58 logs into DCR stream ✅
Successfully posted 90 logs into DCR stream ✅
Successfully posted 144 logs into DCR stream ✅
Total: 900+ Wazuh alerts ingested into Microsoft Sentinel
```

## Sentinel Query
```kusto
WazuhAlerts_CL_CL
| order by TimeGenerated desc
| take 10
```

## Evidence
| File | Description |
|---|---|
| `Evidence/Screenshots/sentinel-dashboard.png` | Sentinel Dashboard |
| `Evidence/Screenshots/azure-app-registration.png` | App Registration |
| `Evidence/Screenshots/azure-api-permissions.png` | API Permissions granted |
| `Evidence/Screenshots/azure-client-secret.png` | Client Secret configured |
| `Evidence/Screenshots/sentinel-wazuh-alerts.png` | Wazuh alerts live in Sentinel |