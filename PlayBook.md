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
* [Sizing Tool https://aka.ms/mdi/sizingtool](https://aka.ms/mdi/sizingtool)
* [WalkThru](https://jeffreyappel.nl/how-to-implement-defender-for-identity-and-configure-all-prerequisites/)
* [MDI Readyness Script](https://github.com/microsoft/Microsoft-Defender-for-Identity/tree/main/Test-MdiReadiness)

### Attack Scripts
**Malicious request of Data Protection API (DPAPI) master key**
```
mimikatz # privilege::debug
mimikatz # lsadump::backupkeys /system:adatumt01.net /export 
```

## Defender for Cloud Apps
* Interactive Guide [Guided Demo](https://aka.ms/DetectThreats-ManageAlerts-MCAS_InteractiveGuide)

# Module 2 - Security Copilot
* [Start-Page https://securitycopilot.Microsoft.com](https://securitycopilot.Microsoft.com)
* Provision Capacity - Step 1 [Simulation](https://app.highlights.guide/start/6d7270b9-7187-456a-ac16-97bc227d5c27?token=045faae1-1078-4eac-bf56-e12472eddaf9&link=1&azure-portal=true)
* Provision Capacity - Step 2 [Simulation](https://app.highlights.guide/start/6d7270b9-7187-456a-ac16-97bc227d5c27?token=045faae1-1078-4eac-bf56-e12472eddaf9&link=1&azure-portal=true)
* Explore Standalone Experience [Simulation](https://app.highlights.guide/start/7608581a-ee3a-4fe0-be03-309a58b78c60?token=045faae1-1078-4eac-bf56-e12472eddaf9&azure-portal=true)
* Explore Embedded Experience [Simulation](https://app.highlights.guide/start/be8a91c3-3979-4048-ad38-fd38deaf7117?token=045faae1-1078-4eac-bf56-e12472eddaf9&azure-portal=true)
* [Use Cases](https://learn.microsoft.com/en-us/training/modules/security-copilot-exercises/)

## Enable Unified Auditing
```
Install-Module ExchangeOnlineManagement
Connect-ExchangeOnline
Get-AdminAuditLogConfig | Format-List UnifiedAuditLogIngestionEnabled
Enable-OrganizationCustomization (optional)
Set-AdminAuditLogConfig -UnifiedAuditLogIngestionEnabled $true
```
Enable Purview Audit Logs in Portal

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

## Event Logging
Application and Services Logs > Microsoft > Windows > SENSE > Operational  
Application and Services Logs > Microsoft > Windows > Windows-Defender > Operational  
Application and Services Logs > Microsoft > Windows > CodeIntegrity > Operational

## ASR Rules
```
Get-MpPreference | Format-List *Attack*
```
## Tools
* [MDE Cient Analyzer](https://learn.microsoft.com/en-us/defender-endpoint/overview-client-analyzer)
```
mpruncmd.exe -getfiles
```
### Attack Samples
**Download EICAR Test File**
```
Invoke-WebRequest -Uri https://secure.eicar.org/eicar.com -OutFile testfile.com
```
```
Invoke-WebRequest -Uri https://github.com/gentilkiwi/mimikatz/releases/download/2.2.0-20220919/mimikatz_trunk.zip -OutFile mimikatz.zip
```

# Module 5 - Defender for Cloud
## Plan cloud workload protections
* [Guided Demo](https://mslearn.cloudguides.com/guides/Protect%20your%20hybrid%20cloud%20with%20Azure%20Security%20Center)
## Device Onboarding
* [Agent Overview und Logfiles](https://learn.microsoft.com/de-de/azure/azure-arc/servers/agent-overview)
* [Install Agent https://aka.ms/AzureConnectedMachineAgent](https://aka.ms/AzureConnectedMachineAgent)
* Connect Machine
```
azcmagent connect --subscription-id "Production" --resource-group "HybridServers" --location "eastus"
```
* Show Agent Status
```
azcmagent show
```

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
# Module 7 - Sentinel
* Detect and respond to modern attacks with unified SIEM and XDR capabilities [Interactive Guide](https://aka.ms/AzureSentinel_SOC_InteractiveGuide)
* [Azure Lighthouse explained](https://sec.ch9.ms/ch9/a775/eefb5ef1-305b-47b2-9ab8-97270549a775/ask-for-azure-lighthouse_high.mp4)

# Module 8 - Connect Logs to Sentinel
* Discover Devices [Video](https://www.youtube.com/watch?v=TCDxICrZQa8)
* Assess and Onboard unmanaged devices [Video](https://www.microsoft.com/en-us/videoplayer/embed/RE4RwQz?postJsllMsg=true)
* Connect Defender XDR [Simulation](https://app.highlights.guide/start/1c894b46-4b0a-40cb-b0f0-1e1c86c615f3?token=16d48b6c-eace-4a1f-8050-098d29d23a89)
* [Custom Event Log Collector Rules](https://learn.microsoft.com/en-us/azure/azure-monitor/vm/data-collection-windows-events#filter-events-using-xpath-queries)


