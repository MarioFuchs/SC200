# Module 1 - Mitigate Threads mit Defender XDR

## Introduction
```
POST https://graph.microsoft.com/v1.0/security/runHuntingQuery
{
  "Query": "DeviceProcessEvents | where InitiatingProcessFileName =~ \"powershell.exe\" | project Timestamp, FileName, InitiatingProcessFileName | order by Timestamp desc | limit 2"
}
```

## Mitigate Incidents
* Detect and respond to modern attacks with unified SIEM and XDR capabilities. [Guided Demo Link](https://mslearn.cloudguides.com/en-us/guides/Detect%20and%20respond%20to%20modern%20attacks%20with%20unified%20SIEM%20and%20XDR%20capabilities)
* Incident Management [Video](https://www.microsoft.com/en-us/videoplayer/embed/RE4Bzwz)
* Investigate Incidents [Guided Demo Link](https://aka.ms/M365Defender-InteractiveGuide)
* Investigate Alerts [Video](https://www.microsoft.com/en-us/videoplayer/embed/RE4yiO5?rel=0&postJsllMsg=true)
* Automated Investigations [Guided Demo Link](https://www.microsoft.com/videoplayer/embed/RE4bOeh)
* Advanced Hunting [Video](https://www.microsoft.com/en-us/videoplayer/embed/RE4bGqo?rel=0&postJsllMsg=true)
* Investigate and remediate threats with Microsoft Defender for Endpoint [Interactive Guide](https://aka.ms/MSDE-IG)
* Threat Analytics [Video](https://www.microsoft.com/en-us/videoplayer/embed/RWwJfU)
* Defender Office 365 [Guided Demo](https://aka.ms/MSDO-IG)

## Defender for Identity
* Investigate and respond to attacks with Microsoft Defender for Identity [Interactive Guide](https://mslearn.cloudguides.com/guides/Investigate%20and%20respond%20to%20attacks%20with%20Microsoft%20Defender%20for%20Identity)
* Interactive Guide [Guided Demo](https://aka.ms/MSDefenderforIdentity-IG)

## Defender for Cloud Apps
* Interactive Guide [Guided Demo](https://aka.ms/DetectThreats-ManageAlerts-MCAS_InteractiveGuide)

# Module 2 - Security Copilot
[Start-Page https://securitycopilot.Microsoft.com](https://securitycopilot.Microsoft.com)

# Module 3 - Purview
## Compliance Solutions
* Insider Risk Management [Guided Demo Link](https://mslearn.cloudguides.com/guides/Minimize%20internal%20risks%20with%20insider%20risk%20management%20in%20Microsoft%20365)
## Purview Audit
Enable in Portal
```
Search-UnifiedAuditLog
```

# Module 4 - Defender for Endpoint
## Protect Against Threads
* Microsoft Defender for Endpoint – Architecture [Video](https://www.microsoft.com/videoplayer/embed/RE4vnC4?rel=0&postJsllMsg=true)
* Incident Investigation [Video](https://www.microsoft.com/en-us/videoplayer/embed/RE4qLUV?rel=0&postJsllMsg=true)
## Deployment
* Onboarding Clients [Video](https://www.microsoft.com/en-us/videoplayer/embed/RE4bGqr?rel=0&postJsllMsg=true)
* RBAC [Video](https://www.microsoft.com/en-us/videoplayer/embed/RE4bJ2a?rel=0&postJsllMsg=true)
## Windows Security Enhancements
* Attack Surface Reducation [Video](https://www.microsoft.com/en-us/videoplayer/embed/RE4woug?postJsllMsg=true)
## Device Investigations
* Defender EDR Mode [Video](https://www.microsoft.com/en-us/videoplayer/embed/RE4HjW2?rel=0&postJsllMsg=true)
* [Discover Devices](https://www.youtube.com/watch?v=TCDxICrZQa8)
* [Assess and Onboard Unmanaged Devices](https://www.microsoft.com/en-us/videoplayer/embed/RE4RwQz?postJsllMsg=true) - NOT UPDATED
* Live Response [Video](https://www.microsoft.com/en-us/videoplayer/embed/RE4qLUW?rel=0&postJsllMsg=true)
* Deep Analysis [Video](https://www.microsoft.com/en-us/videoplayer/embed/RE4aAYy?rel=0&postJsllMsg=true)
## Automation
* Microsoft Defender for Endpoint: Conditional access [Video](https://www.microsoft.com/en-us/videoplayer/embed/RE4byD1?rel=0&postJsllMsg=true)
* Unified IoCs [Video](https://www.microsoft.com/en-us/videoplayer/embed/RE4qLVw?rel=0&postJsllMsg=true)
## Vulnerability Management
* Threat and vulnerability management: discovery & remediation [Video](https://www.microsoft.com/videoplayer/embed/RE4qLVs?rel=0)
* Threat and Vulnerability Management [Interactive Guide](https://aka.ms/MSDE_TVM_IG)

# Module 5 - Defender for Cloud
## Plan cloud workload protections
* [Guided Demo](https://mslearn.cloudguides.com/guides/Protect%20your%20hybrid%20cloud%20with%20Azure%20Security%20Center)

# Module 6 - KQL
* [KQL quick reference](https://docs.microsoft.com/en-us/azure/data-explorer/kql-quick-reference)
* Search & Where
```
search in (SecurityEvent,App*) "PowerShell"

SecurityEvent
| where TimeGenerated > ago(1h)

SecurityEvent
| where TimeGenerated > ago(1h) and EventID == "4624"

SecurityEvent
| where TimeGenerated > ago(1h)
| where EventID == 4624
| where AccountType =~ "user"

SecurityEvent | where EventID in (4624, 4625)
```
* Variablen
```
let timeOffset = 1h;
let discardEventId = 4688;
SecurityEvent
| where TimeGenerated > ago(timeOffset*2) and TimeGenerated < ago(timeOffset)
| where EventID != discardEventId


let LowActivityAccounts =
    SecurityEvent 
    | summarize cnt = count() by Account 
    | where cnt < 1000;
LowActivityAccounts | where Account contains "sql"
```
* Extend
```
SecurityAlert
| where TimeGenerated > ago(7d)
| extend severityOrder = case (
    AlertSeverity == "High", 3,
    AlertSeverity == "Medium", 2, 
    AlertSeverity == "Low", 1,
    AlertSeverity == "Informational", 0,
    -1)
```
* Order by
```
SecurityEvent
| where TimeGenerated > ago(1h) 
| where ProcessName != "" and Process != ""
| extend StartDir =  substring(ProcessName,0, string_size(ProcessName)-string_size(Process))
| order by StartDir desc, Process asc
```



