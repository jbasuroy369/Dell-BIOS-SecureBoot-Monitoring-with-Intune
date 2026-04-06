Changelog: Dell Device Properties (Log Analytics Reporting)
All notable changes to the Dell_Device_Properties.ps1 script for Intune Remediations and Log Analytics reporting are documented below.

[v4.6.0] - Latest Stable
Added
Debugging & Testing Tools: Added -DryRun switch to skip Log Analytics POST and print the record directly to the console.

Hardware Overrides: Added -OverrideManufacturer and -OverrideSKU parameters for cross-hardware testing/validation.

Enhanced Logging: Implemented structured Write-Log function for run.log with defined INFO, WARN, and ERROR levels.

Transcript Support: Added -FullTranscript switch to capture a standard PowerShell transcript.

Fixed
CAB Extraction: Swapped priority to expand.exe as primary and Shell.Application as fallback for better compatibility.

Async Race Condition: Replaced fixed Start-Sleep with a dynamic wait loop for Shell.Application extraction.

Logic Refinement: Standardized version comparison to be strictly numeric-segment based; removed string-based fallbacks.

[v4.5.0]
Added
Tri-State BIOS Status: Introduced "Ahead of catalog" state to identify machines with factory BIOS not yet in public XML feeds.

Leading-Zero Tolerance: Implemented a new matching logic for numeric SKUs (e.g., matching 0816 to 816) while ensuring Hex-based IDs (like 0A68) remain untouched.

Schema Parity: Added Result and SourcesTried fields to the JSON payload for better alignment with Lenovo/HP reporting schemas.

[v4.4.0]
Fixed
Cleanup Logic: Extraction folders are now explicitly cleared before re-expansion to prevent stale XML files from being selected.

Cast Consistency: Fixed issues where Axx numeric casts were being dropped during comparison.

[v4.3.0]
Added
Resilience: Implemented Invoke-WebRequestWithRetry with exponential backoff for all web calls.

Priority Logic: Script now explicitly prefers the DCU Feed (CatalogIndexPC -> GroupManifest) to avoid heavy catalog downloads.

[v4.2.0]
Added
Security: Added TLS 1.2 session hardening to ensure compatibility with modern endpoints and Windows PowerShell 5.1.

[v4.1.0]
Fixed
Comparison Engine: Rewrote Compare-DellBiosVersion to handle complex versioning (Axx numeric, dotted [version], and multi-segment numeric fallbacks).

[v4.0.0]
Changed
API Optimization: Payload is now sent as a JSON array to better support Log Analytics data ingestion requirements.

Headers: Conditional logic added for the time-generated-field header to prevent empty header errors.

[v3.0.0]
Added
Namespace Safety: Migrated to namespace-safe XPath queries (local-name()) and explicit [xml] typing to handle variations in Dell XML schemas.

SKU Matching: Refined SKU identification specifically using systemID nodes.

[v2.0.0]
Changed
Stability: Implemented Set-StrictMode and ErrorActionPreference = 'Stop' for better error flow control.

Structure: Modularized functions for signature building and data posting.

[v1.0.0] - Baseline
Added
Core Functionality: Initial release reporting InstalledBiosVersion, AvailableBiosVersion, BiosStatus, and SecureBoot to Log Analytics.

Reporting: Basic logic to report NoCatalogMatch when a device SKU is not found in public feeds.
