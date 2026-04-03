\# KQL Starter Queries (Dell BIOS + Secure Boot)



These queries assume your LogType is:



`Pilot\_Dell\_Device\_Properties`



So the table name becomes:



`Pilot\_Dell\_Device\_Properties\_CL`



\---



\## 1) Latest record per device (dedupe)



> Use this if the script runs hourly/daily. It keeps only the newest record per device.



```kusto

Pilot\_Dell\_Device\_Properties\_CL

| summarize arg\_max(TimeGenerated, \*) by Hostname\_s

| project

&#x20;   TimeGenerated,

&#x20;   Hostname\_s,

&#x20;   SystemSKU\_s,

&#x20;   InstalledBiosVersion\_s,

&#x20;   AvailableBiosVersion\_s,

&#x20;   BiosStatus\_s,

&#x20;   SecureBoot\_s,

&#x20;   Result\_s,

&#x20;   SourcesTried\_s,

&#x20;   LatestSource\_s

| order by Hostname\_s asc



