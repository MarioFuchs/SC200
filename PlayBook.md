# Mod 1

```
POST https://graph.microsoft.com/v1.0/security/runHuntingQuery
{
  "Query": "DeviceProcessEvents | where InitiatingProcessFileName =~ \"powershell.exe\" | project Timestamp, FileName, InitiatingProcessFileName | order by Timestamp desc | limit 2"
}
```
Detect and respond to modern attacks with unified SIEM and XDR capabilities
Guided Demo Link(https://mslearn.cloudguides.com/en-us/guides/Detect%20and%20respond%20to%20modern%20attacks%20with%20unified%20SIEM%20and%20XDR%20capabilities)
