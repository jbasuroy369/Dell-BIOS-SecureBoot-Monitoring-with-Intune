\# Deployment Guide (Intune Remediations → Log Analytics)



This guide walks you through deploying the script as an \*\*Intune Remediation\*\* (report-only) and validating ingestion into a Log Analytics custom table.



\---



\## 1) Prerequisites



\### Intune Remediations

\- Remediations (formerly Proactive Remediations) run scripts via the Intune Management Extension (IME) and use exit codes to decide whether remediation executes.

\- This repo is \*\*report-only\*\* and always exits `0` by design.



\### Log Analytics workspace

You need:

\- Log Analytics Workspace \*\*Workspace ID\*\* (Customer ID)

\- Log Analytics Workspace \*\*Primary or Secondary key\*\* (Shared Key)



The script sends data using the \*\*Log Analytics HTTP Data Collector API\*\*, which supports JSON ingestion and optional headers like `time-generated-field`.



⚠️ This approach embeds LAW shared keys in the script, meaning the secret exists on endpoints; Microsoft explicitly advises not to include sensitive info in Remediations scripts. Also, Microsoft is pushing migration away from the legacy Data Collector API toward the Log Ingestion API (DCR/RBAC). For now, the script uses legacy Data Collector API; candidate for migration to Log Ingestion API when device-auth patterns are approved.



\*\*Security:\*\* The Shared Key is a secret. Remediation scripts are cached locally on devices; avoid embedding secrets where possible and never commit them to Git.

\---



\## 2) Configure the script



Open `src/Dell\_Device\_Properties.ps1` and set:



\- `$customerId = "<WORKSPACE\_ID>"`

\- `$sharedKey  = "<SHARED\_KEY>"`

\- `$logType    = "Pilot\_Dell\_Device\_Properties"`



Optional:

\- `$TimeStampField = ""`  

If you set this to a property name in the JSON payload (for example `TimestampUTC`), the Data Collector API can use that field as `TimeGenerated`. If not specified, ingestion time is used.



> \*\*Tip:\*\* The script sends payload as a JSON array for consistency with batching format. \[3](https://www.youtube.com/watch?v=aNixxPW1auw)



\---



\## 3) Create the Remediation in Intune



In Intune admin center:

1\. Go to \*\*Devices → Scripts and remediations → Remediations\*\*

2\. \*\*Create\*\* a new script package

3\. Upload the script as the \*\*Detection script\*\*

&#x20;  - Remediation script can be a no-op (or omitted if your tenant UI allows)

4\. Recommended settings:

&#x20;  - Run this script using the logged-on credentials: \*\*No\*\*

&#x20;  - Run script in 64-bit PowerShell: \*\*Yes\*\*

&#x20;  - Enforce script signature check: \*\*No\*\* (unless you sign your scripts)

5\. Assign to a device group and set schedule (Hourly or Daily)



Remediations use exit code `1` to trigger remediation execution; since this is report-only, the script always exits `0`. \[1](https://simonvedder.com/sending-custom-logs-to-log-analytics-via-http/)



\---



\## 4) Validate on a test device



\### Verify script reached the device

Remediation scripts are cached locally (helpful for testing):

\- `C:\\Windows\\IMECache\\HealthScripts\\<ScriptGUID>\\DetectionScript.ps1` \[2](https://www.powershellgallery.com/packages/OSD/21.11.1.1/Content/Public%5CCatalog%5CGet-CatalogDellSystem.ps1)



\### Verify IME logs

Check:

\- `C:\\ProgramData\\Microsoft\\IntuneManagementExtension\\Logs\\IntuneManagementExtension.log` \[2](https://www.powershellgallery.com/packages/OSD/21.11.1.1/Content/Public%5CCatalog%5CGet-CatalogDellSystem.ps1)



Look for:

\- Script execution entries

\- Any HTTP upload failures (400/403/429/5xx) printed by the script



\---



\## 5) Validate ingestion in Log Analytics



In your workspace → Logs:

\- Find the table: `<LogType>\_CL` (example: `Pilot\_Dell\_Device\_Properties\_CL`)

\- Run the starter queries in `docs/kql.md`.



\---



\## 6) Operational notes (fleet-scale)



\### TLS 1.2

Azure Monitor Logs APIs should use TLS 1.2+ for data-in-transit. The script forces TLS 1.2 in-session for Windows PowerShell 5.1 reliability. \[4](https://github.com/PandaXass/azure-logs-api-webhook)\[5](https://www.youtube.com/watch?v=gN0-zZBGUK0)



\### Retrying transient failures

The script retries transient errors (timeouts, 429 throttling, and 5xx) and fails fast on permanent errors (400/401/403) so misconfiguration remains obvious.



\### Dedupe pattern

If you run hourly, you will get multiple rows per device per day. Use `arg\_max(TimeGenerated, \*) by Hostname\_s` to evaluate the latest record per device (see KQL doc).



