# Mod 1

```
POST https://graph.microsoft.com/v1.0/security/runHuntingQuery
{
  "Query": "DeviceProcessEvents | where InitiatingProcessFileName =~ \"powershell.exe\" | project Timestamp, FileName, InitiatingProcessFileName | order by Timestamp desc | limit 2"
}
```
