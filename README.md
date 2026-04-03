\# Dell BIOS + Secure Boot Inventory (Intune Remediations → Log Analytics)



A \*\*report-only\*\* Intune Remediation script that inventories:

\- \*\*Installed BIOS version\*\*

\- \*\*Latest/available BIOS version\*\* (prefers Dell Command Update feed logic; falls back to Dell catalogs)

\- \*\*BIOS status\*\*: `Up to date` / `Update available` / `Unknown`

\- \*\*Secure Boot status\*\*: `Enabled` / `Disabled` / `Unsupported`



It then uploads \*\*one record per run\*\* into a \*\*single Log Analytics custom table\*\*, using \*\*Lenovo-aligned field names\*\* (`InstalledBiosVersion`, `AvailableBiosVersion`, `BiosStatus`, `SecureBoot`) so you can build unified OEM workbooks.



> \*\*Important:\*\* This is \*not\* an official Dell script. Use at your own risk.



\---



\## Why this exists



Intune can schedule scripts (Remediations) reliably, but it doesn’t give you a native “BIOS currency + Secure Boot posture” view with OEM feed alignment out-of-the-box. This script fills that gap by using the same catalog discovery logic typically used by Dell Command Update (DCU feed chain) and emitting consistent telemetry into Log Analytics.



\---



\## Repository structure



\- `src/`  

&#x20; Latest supported script (recommended for deployment)

\- `builds/`  

&#x20; Historical builds (v1.0.0 → v4.4) for reference and audit trails

\- `docs/`  

&#x20; Deployment guide and KQL starter queries



\---



\## Data model (single table)



\### Matched devices

\- `Hostname`

\- `SystemSKU`

\- `InstalledBiosVersion`

\- `AvailableBiosVersion`

\- `BiosStatus` (`Up to date` / `Update available`)

\- `SecureBoot` (`Enabled` / `Disabled` / `Unsupported`)

\- `LatestSource` (`DCUFeed` / `FallbackCatalog`)

\- `TimestampUTC`



\### No catalog match

\- `Result` = `NoCatalogMatch`

\- `SourcesTried` (e.g. `DCUFeed,FallbackCatalog`)

\- `AvailableBiosVersion` = `Unavailable`

\- `BiosStatus` = `Unknown`



\---



\## Deployment (TL;DR)



1\. Create an Intune Remediation package with the script from `src/`.

2\. Run as \*\*SYSTEM\*\*, 64-bit PowerShell.

3\. Schedule hourly/daily.

4\. Query Log Analytics with `arg\_max()` to dedupe (see `docs/kql.md`).



Remediations run detection/remediation logic based on exit codes, so this project is explicitly \*\*report-only\*\* and always exits `0` to avoid triggering remediation actions. \[1](https://simonvedder.com/sending-custom-logs-to-log-analytics-via-http/)



\---



\## Security notice (read this)



⚠️ This script uses the \*\*Log Analytics HTTP Data Collector API\*\* which requires a Workspace ID and Shared Key. That Shared Key is a secret. For now, the script embeds LAW shared keys in the script, meaning the secret exists on endpoints; Microsoft explicitly advises not to include sensitive info in Remediations scripts. Also, Microsoft is pushing migration away from the legacy Data Collector API toward the Log Ingestion API (DCR/RBAC). For now, the script uses legacy Data Collector API; candidate for migration to Log Ingestion API when device-auth patterns are approved.





Intune Remediation scripts are cached locally on devices (IME cache) in cleartext, so \*\*do not commit real keys to GitHub\*\*, and understand the security implications of placing ingestion keys on endpoints.



Microsoft also recommends securing data in transit using \*\*TLS 1.2+\*\* when sending/querying data to Azure Monitor Logs APIs. This script forces TLS 1.2 in-session for reliability with Windows PowerShell 5.1.



\---



\## Troubleshooting



\- Check script execution and errors in:

&#x20; `C:\\ProgramData\\Microsoft\\IntuneManagementExtension\\Logs\\IntuneManagementExtension.log` \[2](https://www.powershellgallery.com/packages/OSD/21.11.1.1/Content/Public%5CCatalog%5CGet-CatalogDellSystem.ps1)

\- Cached remediation scripts are stored under:

&#x20; `C:\\Windows\\IMECache\\HealthScripts\\...` (useful for local testing and debugging). \[2](https://www.powershellgallery.com/packages/OSD/21.11.1.1/Content/Public%5CCatalog%5CGet-CatalogDellSystem.ps1)



\---


\## Disclaimer



This project is provided \*\*as-is\*\* with no warranties. Test in a lab/pilot ring before broad deployment.



