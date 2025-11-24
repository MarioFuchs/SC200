# Mod 1

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
* 
