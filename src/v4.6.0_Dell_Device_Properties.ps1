<#
.SYNOPSIS
  Dell BIOS currency + Secure Boot -> Log Analytics (Lenovo-aligned schema)

.DESCRIPTION
  Report-only Intune Remediation script build: v4.6
  - Always exits 0
  - Fields: InstalledBiosVersion, AvailableBiosVersion, BiosStatus, SecureBoot
  - Schema parity: Result + SourcesTried included for both success and NoCatalogMatch

  Changes from v4.6:
      * Added -DryRun switch: skips Log Analytics POST, prints record to console
      * Added -OverrideManufacturer / -OverrideSKU params for cross-hardware testing
      * Added structured Write-Log transcript (run.log) with INFO / WARN / ERROR levels
      * Optional full Start-Transcript capture toggled via -FullTranscript switch
      * Manufacturer exit now prints reason instead of silently quitting

  Changes from v4.5 (carried from v4.6):
      * expand.exe is primary CAB extraction; Shell.Application is fallback
      * Removed 24-hour CAB cache: always downloads fresh CAB on every run
      * Fixed FallbackCatalog BIOS filter: $isBios flag pattern (no false-negative drops)
      * Fixed version comparison: string fallback removed; numeric-segment loop is definitive
      * Shell.Application async race fixed: wait loop replaces fixed Sleep fence
      * Per-source try/catch ensures $sourcesTried is always accurate
      * Write-Verbose traces on all silent $null returns in DCUFeed

.PARAMETER DryRun
  When set, the Log Analytics POST is skipped and the record is printed to the console.
  Safe to use on any hardware including non-Dell devices.

.PARAMETER OverrideManufacturer
  Overrides the detected manufacturer string. Use "Dell Inc." to force Dell code path
  on non-Dell hardware during testing.

.PARAMETER OverrideSKU
  Overrides the detected SystemSKUNumber. Use a known Dell SKU (e.g. "0816") to test
  catalog lookups from any machine.

.PARAMETER FullTranscript
  When set, Start-Transcript is enabled and the full PowerShell session is captured
  to transcript.log alongside run.log. Intended for deep troubleshooting only.

.NOTES
  Replace <WORKSPACE_ID> and <SHARED_KEY>.
  Shared key should ideally be retrieved at runtime from Key Vault / managed identity
  rather than stored plaintext in the script body.

.EXAMPLE
  # Dry run on any device — no Dell SKU needed, no LA POST
  .\Dell_BIOS_SecureBoot_v4.7.ps1 -DryRun

.EXAMPLE
  # Simulate a specific Dell SKU end-to-end (catalog lookup runs, LA POST skipped)
  .\Dell_BIOS_SecureBoot_v4.7.ps1 -DryRun -OverrideManufacturer "Dell Inc." -OverrideSKU "0816"

.EXAMPLE
  # Full live run with deep transcript capture enabled
  .\Dell_BIOS_SecureBoot_v4.7.ps1 -FullTranscript
#>

param(
    [switch]$DryRun,
    [string]$OverrideManufacturer = '',
    [string]$OverrideSKU          = '',
    [switch]$FullTranscript
)

Set-StrictMode -Version 2.0
$ProgressPreference    = 'SilentlyContinue'
$ConfirmPreference     = 'None'
$ErrorActionPreference = 'Stop'

# TLS 1.2 hardening for WinPS 5.1
try {
    $cur = [Net.ServicePointManager]::SecurityProtocol
    [Net.ServicePointManager]::SecurityProtocol = $cur -bor [Net.SecurityProtocolType]::Tls12
} catch { }

$Global:WebRetryMaxAttempts      = 3
$Global:WebRetryBaseDelaySeconds = 2
$Global:WebRetryMaxDelaySeconds  = 20

# ==============================================================================
# Logging
# Structured per-run log at $env:ProgramData\PilotDell_BIOS_SB_Cache\run.log
# Each run overwrites the previous log for a clean per-execution record.
# ==============================================================================
$script:LogPath = Join-Path $env:ProgramData 'PilotDell_BIOS_SB_Cache\run.log'

function Write-Log {
    param(
        [Parameter(Mandatory=$true)][string]$Message,
        [ValidateSet('INFO','WARN','ERROR')][string]$Level = 'INFO'
    )
    $entry = "[{0}] [{1}] {2}" -f `
        (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'), $Level, $Message

    # Ensure the log directory exists before first write
    $logDir = Split-Path $script:LogPath -Parent
    if (-not (Test-Path $logDir)) {
        New-Item -ItemType Directory -Path $logDir -Force | Out-Null
    }

    Add-Content -Path $script:LogPath -Value $entry -Encoding UTF8

    # Mirror to stdout so Intune captures it in remediation output
    Write-Output $entry
}

function Initialize-Log {
    # Clear the previous run's log for a clean per-execution record
    $logDir = Split-Path $script:LogPath -Parent
    if (-not (Test-Path $logDir)) {
        New-Item -ItemType Directory -Path $logDir -Force | Out-Null
    }
    if (Test-Path $script:LogPath) { Remove-Item $script:LogPath -Force -ErrorAction SilentlyContinue }

    Write-Log "================================================================"
    Write-Log "Dell BIOS / SecureBoot Remediation Script v4.7"
    Write-Log "Host       : $env:COMPUTERNAME"
    Write-Log "User       : $env:USERNAME"
    Write-Log "RunMode    : $(if ($DryRun) { 'DRY RUN (no LA POST)' } else { 'LIVE' })"
    Write-Log "StartedUTC : $((Get-Date).ToUniversalTime().ToString('o'))"
    Write-Log "================================================================"
}

# ==============================================================================
# Web request helper with exponential back-off retry
# ==============================================================================
function Invoke-WebRequestWithRetry {
    param(
        [Parameter(Mandatory=$true)][string]$Uri,
        [Parameter(Mandatory=$false)][ValidateSet('GET','POST','PUT','DELETE','HEAD','PATCH')][string]$Method = 'GET',
        [Parameter(Mandatory=$false)][hashtable]$Headers,
        [Parameter(Mandatory=$false)][string]$ContentType,
        [Parameter(Mandatory=$false)][object]$Body,
        [Parameter(Mandatory=$false)][string]$OutFile,
        [Parameter(Mandatory=$false)][int]$TimeoutSec      = 60,
        [Parameter(Mandatory=$false)][int]$MaxAttempts      = $Global:WebRetryMaxAttempts,
        [Parameter(Mandatory=$false)][int]$BaseDelaySeconds = $Global:WebRetryBaseDelaySeconds,
        [Parameter(Mandatory=$false)][int]$MaxDelaySeconds  = $Global:WebRetryMaxDelaySeconds
    )

    $attempt = 0
    while ($attempt -lt $MaxAttempts) {
        $attempt++
        try {
            $iwrParams = @{
                Uri             = $Uri
                Method          = $Method
                UseBasicParsing = $true
                TimeoutSec      = $TimeoutSec
                ErrorAction     = 'Stop'
            }
            if ($Headers)        { $iwrParams.Headers     = $Headers }
            if ($ContentType)    { $iwrParams.ContentType = $ContentType }
            if ($Body -ne $null) { $iwrParams.Body        = $Body }
            if ($OutFile)        { $iwrParams.OutFile      = $OutFile }

            return Invoke-WebRequest @iwrParams
        } catch {
            $statusCode = $null
            $retryAfter = $null

            try {
                $webResp = $_.Exception.Response
                if ($webResp -and $webResp.StatusCode) { $statusCode = [int]$webResp.StatusCode }
                if ($webResp -and $webResp.Headers -and $webResp.Headers['Retry-After']) {
                    [int]$tmp = 0
                    if ([int]::TryParse($webResp.Headers['Retry-After'], [ref]$tmp)) { $retryAfter = $tmp }
                }
            } catch { }

            $transient = $false
            if ($statusCode -ne $null) {
                if ($statusCode -eq 408 -or $statusCode -eq 429 -or
                    ($statusCode -ge 500 -and $statusCode -le 599)) { $transient = $true }
            } else {
                $transient = $true
            }

            if (-not $transient -or $attempt -ge $MaxAttempts) { throw }

            if ($retryAfter -ne $null -and $retryAfter -gt 0) {
                $delay = [Math]::Min($retryAfter, $MaxDelaySeconds)
            } else {
                $delayBase = [Math]::Min(($BaseDelaySeconds * [Math]::Pow(2, ($attempt - 1))), $MaxDelaySeconds)
                $delay     = $delayBase + (Get-Random -Minimum 0 -Maximum 2)
            }
            Write-Log "Web request attempt $attempt failed (HTTP $statusCode). Retrying in ${delay}s..." -Level 'WARN'
            Start-Sleep -Seconds $delay
        }
    }
}

# ==============================================================================
# Log Analytics Settings  —  REPLACE PLACEHOLDERS
# ==============================================================================
$customerId     = "Your Log Analytics Workspace ID Here"
$sharedKey      = "Your Shared Key Here"
$logType        = "Your Log Analytics Workspace Table Name Here"
$TimeStampField = ""

function Build-Signature {
    param(
        [Parameter(Mandatory=$true)][string]$CustomerId,
        [Parameter(Mandatory=$true)][string]$SharedKey,
        [Parameter(Mandatory=$true)][string]$Date,
        [Parameter(Mandatory=$true)][int]$ContentLength,
        [Parameter(Mandatory=$true)][string]$Method,
        [Parameter(Mandatory=$true)][string]$ContentType,
        [Parameter(Mandatory=$true)][string]$Resource
    )

    $xHeaders    = "x-ms-date:$Date"
    $strToHash   = "$Method`n$ContentLength`n$ContentType`n$xHeaders`n$Resource"
    $bytesToHash = [Text.Encoding]::UTF8.GetBytes($strToHash)
    $keyBytes    = [Convert]::FromBase64String($SharedKey)

    $hmac     = New-Object System.Security.Cryptography.HMACSHA256
    $hmac.Key = $keyBytes
    $hash     = $hmac.ComputeHash($bytesToHash)

    "SharedKey $CustomerId`:$([Convert]::ToBase64String($hash))"
}

function Post-LogAnalyticsData {
    param(
        [Parameter(Mandatory=$true)][string]$CustomerId,
        [Parameter(Mandatory=$true)][string]$SharedKey,
        [Parameter(Mandatory=$true)][byte[]]$BodyBytes,
        [Parameter(Mandatory=$true)][string]$LogType,
        [Parameter(Mandatory=$false)][string]$TimeStampField
    )

    $method      = "POST"
    $contentType = "application/json"
    $resource    = "/api/logs"
    $rfc1123date = [DateTime]::UtcNow.ToString("r")

    $signature = Build-Signature -CustomerId $CustomerId -SharedKey $SharedKey `
        -Date $rfc1123date -ContentLength $BodyBytes.Length `
        -Method $method -ContentType $contentType -Resource $resource

    $uri = "https://{0}.ods.opinsights.azure.com{1}?api-version=2016-04-01" -f $CustomerId, $resource

    $headers = @{
        "Authorization"  = $signature
        "Log-Type"       = $LogType
        "x-ms-date"      = $rfc1123date
        "Content-Length" = $BodyBytes.Length
    }
    if (-not [string]::IsNullOrWhiteSpace($TimeStampField)) {
        $headers["time-generated-field"] = $TimeStampField
    }

    try {
        $resp = Invoke-WebRequestWithRetry -Uri $uri -Method $method -ContentType $contentType `
            -Headers $headers -Body $BodyBytes
        return [pscustomobject]@{
            StatusCode        = $resp.StatusCode
            StatusDescription = $resp.StatusDescription
            Error             = $null
            ResponseBody      = $null
        }
    } catch {
        $statusCode = $null; $statusDesc = $null; $respBody = $null
        $msg = $_.Exception.Message
        try {
            $webResp = $_.Exception.Response
            if ($webResp -and $webResp.StatusCode) {
                $statusCode = [int]$webResp.StatusCode
                $statusDesc = $webResp.StatusDescription
            }
            if ($webResp -and $webResp.GetResponseStream) {
                $sr = New-Object System.IO.StreamReader($webResp.GetResponseStream())
                $respBody = $sr.ReadToEnd()
                $sr.Close()
            }
        } catch { }
        return [pscustomobject]@{
            StatusCode        = $statusCode
            StatusDescription = $statusDesc
            Error             = $msg
            ResponseBody      = $respBody
        }
    }
}

# ==============================================================================
# Device info helpers
# ==============================================================================
function Get-DeviceInfo {
    $cs   = Get-CimInstance -ClassName Win32_ComputerSystem
    $bios = Get-CimInstance -ClassName Win32_BIOS
    [pscustomobject]@{
        Hostname             = $env:COMPUTERNAME
        Manufacturer         = ($cs.Manufacturer      | Out-String).Trim()
        SystemSKU            = ($cs.SystemSKUNumber    | Out-String).Trim()
        InstalledBiosVersion = ($bios.SMBIOSBIOSVersion | Out-String).Trim()
    }
}

function Get-SecureBootStatus {
    try {
        $sb = Confirm-SecureBootUEFI -ErrorAction Stop
        if ($sb) { return "Enabled" } else { return "Disabled" }
    } catch {
        return "Unsupported"
    }
}

# ==============================================================================
# CAB extraction
# expand.exe is primary (synchronous, reliable for CAB).
# Shell.Application is fallback with async wait loop (no fixed Sleep race).
# ==============================================================================
function Expand-CabToFolder {
    param(
        [Parameter(Mandatory=$true)][string]$CabPath,
        [Parameter(Mandatory=$true)][string]$DestinationFolder
    )

    if (Test-Path $DestinationFolder) {
        Remove-Item $DestinationFolder -Recurse -Force -ErrorAction SilentlyContinue
    }
    New-Item -ItemType Directory -Path $DestinationFolder -Force | Out-Null

    $expandExe = "$env:SystemRoot\System32\expand.exe"
    $expandOk  = $false

    if (Test-Path $expandExe) {
        try {
            Write-Log "Extracting CAB via expand.exe: $(Split-Path $CabPath -Leaf)"
            $proc = Start-Process -FilePath $expandExe `
                -ArgumentList "`"$CabPath`"", "-F:*", "`"$DestinationFolder`"" `
                -Wait -PassThru -NoNewWindow -ErrorAction Stop
            if ($proc.ExitCode -eq 0) {
                $expandOk = $true
                Write-Log "expand.exe extraction succeeded (exit 0)"
            } else {
                Write-Log "expand.exe exited with code $($proc.ExitCode) — falling back to Shell.Application" -Level 'WARN'
            }
        } catch {
            Write-Log "expand.exe threw: $($_.Exception.Message) — falling back to Shell.Application" -Level 'WARN'
        }
    } else {
        Write-Log "expand.exe not found — falling back to Shell.Application" -Level 'WARN'
    }

    if (-not $expandOk) {
        Write-Log "Extracting CAB via Shell.Application: $(Split-Path $CabPath -Leaf)"
        $shell  = New-Object -ComObject Shell.Application
        $source = $shell.NameSpace($CabPath)
        $dest   = $shell.NameSpace($DestinationFolder)
        $dest.CopyHere($source.Items(), 0x10)

        # Shell.Application is async — poll for file presence rather than sleeping
        $timeout = 60; $elapsed = 0
        while ($elapsed -lt $timeout) {
            $items = Get-ChildItem -Path $DestinationFolder -Recurse -ErrorAction SilentlyContinue |
                     Where-Object { -not $_.PSIsContainer }
            if ($items) {
                Write-Log "Shell.Application extraction complete after ${elapsed}s"
                break
            }
            Start-Sleep -Seconds 1
            $elapsed++
        }
        if ($elapsed -ge $timeout) {
            Write-Log "Shell.Application extraction timed out after ${timeout}s" -Level 'WARN'
        }
    }
}

# ==============================================================================
# CAB download + XML extraction
# No 24-hour cache: always downloads a fresh CAB on every run.
# Minimum size guard catches partial/corrupt downloads.
# ==============================================================================
function Get-XmlFromCabUrl {
    param(
        [Parameter(Mandatory=$true)][string]$Url,
        [Parameter(Mandatory=$true)][string]$CacheDir
    )

    $cabName      = Split-Path $Url -Leaf
    $cabPath      = Join-Path $CacheDir $cabName
    $extractDir   = Join-Path $CacheDir ([IO.Path]::GetFileNameWithoutExtension($cabName))
    $sentinelPath = "$cabPath.done"

    Write-Log "Downloading (fresh): $cabName"

    # Always remove existing CAB + sentinel for a clean download
    Remove-Item $cabPath      -Force -ErrorAction SilentlyContinue
    Remove-Item $sentinelPath -Force -ErrorAction SilentlyContinue

    Invoke-WebRequestWithRetry -Uri $Url -OutFile $cabPath | Out-Null

    # Guard against partial/corrupt downloads
    if (-not (Test-Path $cabPath) -or (Get-Item $cabPath).Length -lt 1024) {
        throw "CAB download appears incomplete or corrupt: $cabPath"
    }

    Write-Log "Downloaded $cabName ($([Math]::Round((Get-Item $cabPath).Length / 1KB, 1)) KB)"

    # Mark download complete
    Set-Content -Path $sentinelPath -Value (Get-Date).ToString('o') -Encoding UTF8

    Expand-CabToFolder -CabPath $cabPath -DestinationFolder $extractDir

    $xmlFile = Get-ChildItem -Path $extractDir -Filter "*.xml" -Recurse -ErrorAction SilentlyContinue |
               Select-Object -First 1

    if (-not $xmlFile) {
        $literalPath = Join-Path $extractDir ($cabName.Replace(".cab", ".xml"))
        if (Test-Path $literalPath) { return $literalPath }
        throw "Extraction failed for $cabName. Destination '$extractDir' exists but no XML found."
    }

    Write-Log "XML ready: $($xmlFile.Name)"
    return $xmlFile.FullName
}

function Get-FirstNonEmptyText {
    param(
        [Parameter(Mandatory=$true)][System.Xml.XmlDocument]$Doc,
        [Parameter(Mandatory=$false)][System.Xml.XmlNode]$ContextNode,
        [Parameter(Mandatory=$true)][string[]]$XPaths
    )
    foreach ($xp in $XPaths) {
        $node = if ($ContextNode) { $ContextNode.SelectSingleNode($xp) } else { $Doc.SelectSingleNode($xp) }
        if ($node) {
            $val = if ($node.NodeType -eq [System.Xml.XmlNodeType]::Attribute) { $node.Value } else { $node.InnerText }
            if ($val -and $val.Trim()) { return $val.Trim() }
        }
    }
    return $null
}

# ==============================================================================
# Version comparison
# [version] cast as fast-path for clean dotted-numerics only.
# Numeric-segment loop is the definitive fallback — handles 1.9 vs 1.10 correctly.
# String fallback removed entirely.
# ==============================================================================
function Compare-DellBiosVersion {
    param([string]$Current, [string]$Latest)

    # Axx numeric compare  (e.g. A12 vs A14)
    if ($Current -match '^A(\d+)$' -and $Latest -match '^A(\d+)$') {
        $c = [int]($Current -replace '^A', '')
        $l = [int]($Latest  -replace '^A', '')
        return $c.CompareTo($l)
    }

    # Fast-path: both strings are clean M.N[.P[.Q]] dotted-numerics
    if ($Current -match '^\d+(\.\d+){1,3}$' -and $Latest -match '^\d+(\.\d+){1,3}$') {
        try { return ([version]$Current).CompareTo([version]$Latest) } catch { }
    }

    # Definitive fallback: numeric-segment loop
    $cNums = [Regex]::Matches($Current, '\d+') | ForEach-Object { [int]$_.Value }
    $lNums = [Regex]::Matches($Latest,  '\d+') | ForEach-Object { [int]$_.Value }

    if ($cNums.Count -gt 0 -and $lNums.Count -gt 0) {
        $len = [Math]::Max($cNums.Count, $lNums.Count)
        for ($i = 0; $i -lt $len; $i++) {
            $cv = if ($i -lt $cNums.Count) { $cNums[$i] } else { 0 }
            $lv = if ($i -lt $lNums.Count) { $lNums[$i] } else { 0 }
            if ($cv -ne $lv) { return $cv.CompareTo($lv) }
        }
        return 0
    }

    # Last resort: identical strings only
    return if ($Current -eq $Latest) { 0 } else { -1 }
}

function Get-DellSystemIdCandidates {
    param([Parameter(Mandatory=$true)][string]$SystemSKU)

    $list = New-Object System.Collections.Generic.List[string]
    $s = $SystemSKU.Trim()
    if ($s) { $list.Add($s) | Out-Null }

    # Strip leading zeros only for pure-numeric SKUs (e.g. 0816 -> 816).
    # Avoids corrupting hex-like IDs such as 0A68.
    if ($s -match '^\d+$') {
        $trimmed = $s.TrimStart('0')
        if ([string]::IsNullOrWhiteSpace($trimmed)) { $trimmed = '0' }
        if ($trimmed -ne $s) { $list.Add($trimmed) | Out-Null }
    }

    return ($list | Select-Object -Unique)
}

# ==============================================================================
# DCUFeed source  (CatalogIndexPC + per-SKU GroupManifest)
# ==============================================================================
function Get-LatestBiosFromDCUFeed {
    param(
        [Parameter(Mandatory=$true)][string]$SystemSKU,
        [Parameter(Mandatory=$true)][string]$CacheRoot
    )

    $skuCandidates = Get-DellSystemIdCandidates -SystemSKU $SystemSKU
    Write-Log "DCUFeed: SKU candidates — $($skuCandidates -join ', ')"

    $indexXmlPath = Get-XmlFromCabUrl -Url "https://downloads.dell.com/catalog/CatalogIndexPC.cab" -CacheDir $CacheRoot
    [xml]$indexXml = Get-Content -Path $indexXmlPath -Encoding UTF8

    $groupNodes = $indexXml.SelectNodes("//*[local-name()='GroupManifest']")
    if (-not $groupNodes) {
        Write-Log "DCUFeed: No GroupManifest nodes found in CatalogIndexPC" -Level 'WARN'
        return $null
    }

    Write-Log "DCUFeed: Scanning $($groupNodes.Count) GroupManifest entries for SKU match"

    $matchedGroup = $null
    foreach ($gm in $groupNodes) {
        $sysIds = $gm.SelectNodes(".//*[local-name()='systemID']")
        foreach ($id in $sysIds) {
            if ($id -and $id.InnerText -and ($skuCandidates -contains $id.InnerText.Trim())) {
                $matchedGroup = $gm
                break
            }
        }
        if ($matchedGroup) { break }
    }

    if (-not $matchedGroup) {
        Write-Log "DCUFeed: No GroupManifest matched SKU candidates: $($skuCandidates -join ', ')" -Level 'WARN'
        return $null
    }

    Write-Log "DCUFeed: Matched GroupManifest for SKU"

    $relPath = $null
    $miNode  = $matchedGroup.SelectSingleNode(".//*[local-name()='ManifestInformation']")
    if ($miNode) {
        $pNode = $miNode.SelectSingleNode(".//*[local-name()='path']")
        if ($pNode -and $pNode.InnerText)  { $relPath = $pNode.InnerText.Trim() }
        elseif ($miNode.Attributes['path']) { $relPath = $miNode.Attributes['path'].Value }
    }

    if (-not $relPath) {
        Write-Log "DCUFeed: ManifestInformation path not found (possible schema change)" -Level 'WARN'
        return $null
    }

    $skuCabUrl  = "https://downloads.dell.com/$relPath"
    Write-Log "DCUFeed: Fetching SKU manifest from $skuCabUrl"

    $skuXmlPath = Get-XmlFromCabUrl -Url $skuCabUrl -CacheDir $CacheRoot
    [xml]$skuXml = Get-Content -Path $skuXmlPath -Encoding UTF8

    $components = $skuXml.SelectNodes("//*[local-name()='SoftwareComponent']")
    if (-not $components) {
        Write-Log "DCUFeed: No SoftwareComponent nodes found in SKU manifest" -Level 'WARN'
        return $null
    }

    Write-Log "DCUFeed: Scanning $($components.Count) components for BIOS entries"

    $candidates = New-Object System.Collections.Generic.List[object]
    foreach ($c in $components) {
        $componentType = Get-FirstNonEmptyText -Doc $skuXml -ContextNode $c -XPaths @(
            ".//*[local-name()='ComponentType']/*[local-name()='value']",
            ".//*[local-name()='componentType']",
            ".//*[local-name()='Category']/*[local-name()='value']",
            ".//*[local-name()='category']"
        )
        $nameDesc = Get-FirstNonEmptyText -Doc $skuXml -ContextNode $c -XPaths @(
            ".//*[local-name()='Name']",
            ".//*[local-name()='Description']"
        )

        $isBios = ($componentType -and $componentType -match 'BIOS') -or
                  ($nameDesc      -and $nameDesc      -match 'BIOS')
        if (-not $isBios) { continue }

        $ver = Get-FirstNonEmptyText -Doc $skuXml -ContextNode $c -XPaths @(
            ".//*[local-name()='version']",
            ".//*[local-name()='dellVersion']",
            ".//@version"
        )
        $dt = Get-FirstNonEmptyText -Doc $skuXml -ContextNode $c -XPaths @(
            ".//*[local-name()='releaseDate']",
            ".//*[local-name()='dateTime']"
        )

        if ($ver) {
            Write-Log "DCUFeed: BIOS candidate found — Version: $ver | Date: $dt"
            $candidates.Add([pscustomobject]@{ Version=$ver; Date=$dt }) | Out-Null
        }
    }

    if ($candidates.Count -eq 0) {
        Write-Log "DCUFeed: No BIOS components found in SKU manifest" -Level 'WARN'
        return $null
    }

    $dated = $candidates | ForEach-Object {
        $parsed = $null
        if ($_.Date) { try { $parsed = [datetime]$_.Date } catch { } }
        [pscustomobject]@{ Version=$_.Version; DateParsed=$parsed }
    }

    $result = ($dated | Sort-Object -Property DateParsed -Descending | Select-Object -First 1).Version
    Write-Log "DCUFeed: Latest BIOS resolved — $result"
    return $result
}

# ==============================================================================
# Fallback catalog source  (DellSDPCatalogPC / CatalogPC)
# $isBios flag pattern: checks attribute, ComponentType child, Name/Description.
# No false-negative drops when 'type' attribute is absent.
# ==============================================================================
function Get-LatestBiosFromFallbackCatalog {
    param(
        [Parameter(Mandatory=$true)][string]$SystemSKU,
        [Parameter(Mandatory=$true)][string]$CacheRoot
    )

    $skuCandidates = Get-DellSystemIdCandidates -SystemSKU $SystemSKU
    Write-Log "FallbackCatalog: SKU candidates — $($skuCandidates -join ', ')"

    $urls = @(
        "https://downloads.dell.com/catalog/DellSDPCatalogPC.cab",
        "https://downloads.dell.com/catalog/CatalogPC.cab"
    )

    foreach ($u in $urls) {
        $cabName = Split-Path $u -Leaf
        Write-Log "FallbackCatalog: Trying $cabName"
        try {
            $xmlPath = Get-XmlFromCabUrl -Url $u -CacheDir $CacheRoot
            [xml]$doc = Get-Content -Path $xmlPath -Encoding UTF8

            $components = $doc.SelectNodes('//*[local-name()="SoftwareComponent"]')
            if (-not $components) {
                Write-Log "FallbackCatalog: No SoftwareComponent nodes in $cabName" -Level 'WARN'
                continue
            }

            Write-Log "FallbackCatalog: Scanning $($components.Count) components in $cabName"
            $biosMatches = New-Object System.Collections.Generic.List[object]

            foreach ($c in $components) {
                # SKU match
                $skuHit = $false
                $sysIds = $c.SelectNodes('.//*[local-name()="systemID"]')
                foreach ($id in $sysIds) {
                    if ($id -and $id.InnerText -and ($skuCandidates -contains $id.InnerText.Trim())) {
                        $skuHit = $true
                        break
                    }
                }
                if (-not $skuHit) { continue }

                # BIOS filter: check all three surfaces before deciding to skip
                $isBios = $false

                $typeAttr = $c.GetAttribute("type")
                if ($typeAttr -and $typeAttr -match 'BIOS') { $isBios = $true }

                if (-not $isBios) {
                    $ctNode = $c.SelectSingleNode('.//*[local-name()="ComponentType"]/*[local-name()="value"]')
                    if ($ctNode -and $ctNode.InnerText -match 'BIOS') { $isBios = $true }
                }

                if (-not $isBios) {
                    $nameNode = $c.SelectSingleNode('.//*[local-name()="Name"]')
                    $descNode = $c.SelectSingleNode('.//*[local-name()="Description"]')
                    if (($nameNode -and $nameNode.InnerText -match 'BIOS') -or
                        ($descNode -and $descNode.InnerText -match 'BIOS')) {
                        $isBios = $true
                    }
                }

                if (-not $isBios) { continue }

                # Extract version
                $verNode = $c.SelectSingleNode('.//*[local-name()="version"]')
                if (-not $verNode) { $verNode = $c.SelectSingleNode('.//@version') }

                $dtNode = $c.SelectSingleNode('.//*[local-name()="releaseDate"]')
                if (-not $dtNode) { $dtNode = $c.SelectSingleNode('.//*[local-name()="dateTime"]') }

                $ver = $null
                if ($verNode) {
                    $ver = if ($verNode.NodeType -eq [System.Xml.XmlNodeType]::Attribute) {
                        $verNode.Value
                    } else {
                        $verNode.InnerText
                    }
                }

                $dt = if ($dtNode) { $dtNode.InnerText } else { $null }

                if ($ver) {
                    Write-Log "FallbackCatalog: BIOS candidate found — Version: $ver | Date: $dt"
                    $biosMatches.Add([pscustomobject]@{ Version=$ver.Trim(); Date=$dt }) | Out-Null
                }
            }

            if ($biosMatches.Count -gt 0) {
                $dated = $biosMatches | ForEach-Object {
                    $parsed = $null
                    if ($_.Date) { try { $parsed = [datetime]$_.Date } catch { } }
                    [pscustomobject]@{ Version=$_.Version; DateParsed=$parsed }
                }
                $result = ($dated | Sort-Object -Property DateParsed -Descending | Select-Object -First 1).Version
                Write-Log "FallbackCatalog: Latest BIOS resolved from $cabName — $result"
                return $result
            }

            Write-Log "FallbackCatalog: No matching BIOS entries in $cabName" -Level 'WARN'
        } catch {
            Write-Log "FallbackCatalog: Error processing '$cabName' — $($_.Exception.Message)" -Level 'ERROR'
            continue
        }
    }

    return $null
}

# ==============================================================================
# Main execution
# ==============================================================================
try {
    # Initialise structured log (clears previous run)
    Initialize-Log

    # Optional full session transcript for deep troubleshooting
    $transcriptPath = Join-Path $env:ProgramData 'PilotDell_BIOS_SB_Cache\transcript.log'
    if ($FullTranscript) {
        Start-Transcript -Path $transcriptPath -Force | Out-Null
        Write-Log "Full transcript enabled: $transcriptPath"
    }

    $cacheRoot = Join-Path $env:ProgramData 'PilotDell_BIOS_SB_Cache'
    New-Item -ItemType Directory -Path $cacheRoot -Force | Out-Null

    # Collect device info
    $dev = Get-DeviceInfo
    Write-Log "Manufacturer     : $($dev.Manufacturer)"
    Write-Log "SystemSKU        : $($dev.SystemSKU)"
    Write-Log "InstalledBIOS    : $($dev.InstalledBiosVersion)"

    # Apply dry-run overrides if provided
    if ($OverrideManufacturer) {
        Write-Log "OverrideManufacturer applied: '$($dev.Manufacturer)' -> '$OverrideManufacturer'" -Level 'WARN'
        $dev.Manufacturer = $OverrideManufacturer
    }
    if ($OverrideSKU) {
        Write-Log "OverrideSKU applied: '$($dev.SystemSKU)' -> '$OverrideSKU'" -Level 'WARN'
        $dev.SystemSKU = $OverrideSKU
    }

    # Manufacturer gate
    if ($dev.Manufacturer -notmatch 'Dell') {
        Write-Log "Not a Dell device (Manufacturer: '$($dev.Manufacturer)') — exiting without action." -Level 'WARN'
        Write-Log "Tip: use -DryRun -OverrideManufacturer 'Dell Inc.' -OverrideSKU '<SKU>' to test on this device."
        if ($FullTranscript) { Stop-Transcript | Out-Null }
        exit 0
    }

    $secureBoot = Get-SecureBootStatus
    Write-Log "SecureBoot       : $secureBoot"

    $sourcesTried = @()
    $latest       = $null
    $latestSource = $null

    # --- Source 1: DCUFeed ---
    $sourcesTried += 'DCUFeed'
    Write-Log "--- Trying source: DCUFeed ---"
    try {
        $latest = Get-LatestBiosFromDCUFeed -SystemSKU $dev.SystemSKU -CacheRoot $cacheRoot
        if ($latest) {
            $latestSource = 'DCUFeed'
            Write-Log "DCUFeed succeeded: $latest"
        } else {
            Write-Log "DCUFeed returned no result" -Level 'WARN'
        }
    } catch {
        Write-Log "DCUFeed threw an exception: $($_.Exception.Message)" -Level 'ERROR'
    }

    # --- Source 2: FallbackCatalog ---
    if (-not $latest) {
        $sourcesTried += 'FallbackCatalog'
        Write-Log "--- Trying source: FallbackCatalog ---"
        try {
            $latest = Get-LatestBiosFromFallbackCatalog -SystemSKU $dev.SystemSKU -CacheRoot $cacheRoot
            if ($latest) {
                $latestSource = 'FallbackCatalog'
                Write-Log "FallbackCatalog succeeded: $latest"
            } else {
                Write-Log "FallbackCatalog returned no result" -Level 'WARN'
            }
        } catch {
            Write-Log "FallbackCatalog threw an exception: $($_.Exception.Message)" -Level 'ERROR'
        }
    }

    # Build record
    if (-not $latest) {
        Write-Log "No BIOS version found from any source" -Level 'WARN'
        $record = [pscustomobject]@{
            Hostname             = $dev.Hostname
            SystemSKU            = $dev.SystemSKU
            InstalledBiosVersion = $dev.InstalledBiosVersion
            AvailableBiosVersion = 'Unavailable'
            BiosStatus           = 'Unknown'
            SecureBoot           = $secureBoot
            Result               = 'NoCatalogMatch'
            SourcesTried         = ($sourcesTried -join ',')
            LatestSource         = $latestSource
            TimestampUTC         = (Get-Date).ToUniversalTime().ToString('o')
        }
    } else {
        $cmp = Compare-DellBiosVersion -Current $dev.InstalledBiosVersion -Latest $latest
        Write-Log "Version comparison — Installed: $($dev.InstalledBiosVersion) | Available: $latest | cmp: $cmp"

        $biosStatus = if     ($cmp -eq 0) { 'Up to date'       }
                      elseif ($cmp -lt 0) { 'Update available' }
                      else                { 'Ahead of catalog'  }

        $record = [pscustomobject]@{
            Hostname             = $dev.Hostname
            SystemSKU            = $dev.SystemSKU
            InstalledBiosVersion = $dev.InstalledBiosVersion
            AvailableBiosVersion = $latest
            BiosStatus           = $biosStatus
            SecureBoot           = $secureBoot
            Result               = 'OK'
            SourcesTried         = ($sourcesTried -join ',')
            LatestSource         = $latestSource
            TimestampUTC         = (Get-Date).ToUniversalTime().ToString('o')
        }
    }

    Write-Log "--- Record Summary ---"
    Write-Log "BiosStatus   : $($record.BiosStatus)"
    Write-Log "Result       : $($record.Result)"
    Write-Log "SourcesTried : $($record.SourcesTried)"
    Write-Log "LatestSource : $($record.LatestSource)"
    Write-Log "SecureBoot   : $($record.SecureBoot)"

    # Post to Log Analytics — or print record and skip if DryRun
    if ($DryRun) {
        Write-Log "DRY RUN — Log Analytics POST skipped. Full record below:" -Level 'WARN'
        Write-Output ""
        Write-Output "===== DRY RUN RECORD ====="
        $record | Format-List | Out-String | Write-Output
        Write-Output "=========================="
    } else {
        $json = @($record) | ConvertTo-Json -Compress
        Write-Log "Posting to Log Analytics workspace: $customerId"
        $resp = Post-LogAnalyticsData -CustomerId $customerId -SharedKey $sharedKey `
            -BodyBytes ([Text.Encoding]::UTF8.GetBytes($json)) `
            -LogType $logType -TimeStampField $TimeStampField

        if ($resp.StatusCode -eq 200) {
            Write-Log "Log Analytics POST succeeded (HTTP 200)"
        } else {
            $extra = if ($resp.ResponseBody) { " | Response: $($resp.ResponseBody)" } else { '' }
            Write-Log ("Log Analytics POST failed. HTTP: {0} {1}. Error: {2}.{3}" -f `
                $resp.StatusCode, $resp.StatusDescription, $resp.Error, $extra) -Level 'ERROR'
        }
    }

    Write-Log "Script completed successfully"

} catch {
    Write-Log "Unhandled script error: $($_.Exception.Message)" -Level 'ERROR'
} finally {
    if ($FullTranscript) {
        try { Stop-Transcript | Out-Null } catch { }
    }
}

exit 0
