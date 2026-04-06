Dell BIOS & Secure Boot Monitoring with IntuneA production-grade Intune Remediation solution designed to monitor Dell BIOS currency and Secure Boot status across an enterprise fleet. This tool bridges the gap between local device states and Azure Log Analytics, providing high-fidelity reporting without requiring a local installation of Dell Command | Update (DCU).

🚀 Key Features
    
    Zero Dependency: Operates independently of the Dell Command | Update client by parsing Dell's CatalogIndexPC and GroupManifest directly via HTTPS.
    Intelligent Matching: Advanced SKU matching logic that handles leading-zero numeric IDs (e.g., 0816 vs 816) while preserving hex-based IDs.
    Tri-State Compliance Logic: Reports BIOS status as Up to date, Update available, or Ahead of catalog (identifying factory-fresh firmware not yet in public feeds).
    Enterprise Hardening: Includes TLS 1.2 session hardening and exponential backoff retry logic (Invoke-WebRequestWithRetry) for resilient data transmission.
    Schema Parity: Outputs a standardized JSON schema compatible with Lenovo and HP reporting equivalents.
    
🛠️ PrerequisitesBefore deploying the script, ensure the following requirements are met: 

    License: Requires Microsoft Entra ID P1/P2 and Intune Suite/Plan 1.
    Log Analytics: An active Azure Log Analytics Workspace (LAW).
    Permissions: The script runs in the SYSTEM context on endpoints.
    Connectivity: Endpoints must reach downloads.dell.com and your LAW ODS endpoint.

📦 Deployment Instructions

    1. Azure Log Analytics Setup
    
           Create a Log Analytics Workspace in the Azure Portal.
           Navigate to Agents management and note your Workspace ID and Primary Key.
           (Optional) Create a Custom Log named Pilot_Dell_Device_Properties.
    
    2. Script Configuration
    
           Open v4.6.0_Dell_Device_Properties.ps1 and update the following variables:
           $customerId = "YOUR_WORKSPACE_ID"
           $sharedKey  = "YOUR_SHARED_KEY"
           $logType    = "Pilot_Dell_Device_Properties"
    
    4. Intune Remediation Upload
    
           Go to the Microsoft Intune Admin Center > Devices > Scripts and remediations.
           Create a new Remediation:
               Detection Script: Use the provided .ps1 (This script acts as a "Report-Only" tool, so it always exits 0).
               Remediation Script: Leave blank (unless you wish to trigger a BIOS update in a future version).
           Run as 64-bit: Yes.Enforce Script Signature Check: No (unless you have signed the script).

📊 Data Schema (JSON)

The script posts a JSON object to Log Analytics with the following structure:
        {
            "Hostname": "WS-DELL-01",
            "SystemSKU": "0816",
            "InstalledBiosVersion": "1.5.0",
            "AvailableBiosVersion": "1.7.1",
            "BiosStatus": "Update available",
            "SecureBoot": "Enabled",
            "Result": "OK",
            "SourcesTried": "DCUFeed,FallbackCatalog",
            "LatestSource": "DCUFeed",
            "TimestampUTC": "2026-03-25T14:30:00Z"
        }

🔍 Troubleshooting & Testing

The latest build (v4.6.0) includes a Dry Run mode for safe testing.

    Local Test: Run .\v4.6.0_Dell_Device_Properties.ps1 -DryRun. This will skip the Azure upload and print the record to your console.Log Files: The script generates a local log at $env:ProgramData\PilotDell_BIOS_SB_Cache\run.log with detailed INFO/WARN/ERROR levels.

📜 Version History
    v4.6.0: Added DryRun mode, hardware overrides, and structured logging.
    v4.5.0: Introduced "Ahead of catalog" state and leading-zero SKU matching.
    v4.3.0: Switched to DCU Feed (CatalogIndexPC) as primary source.
    v1.0.0: Initial baseline release.

🤝 Contributing

Contributions are welcome! Please open an issue or submit a pull request if you have suggestions for the "Universal Connector" logic or enhanced Azure Workbooks.

Disclaimer: This script is provided "as is" without warranty. Always test in a pilot group before broad production deployment.
