<#
.SYNOPSIS
  Dell BIOS currency + Secure Boot -> Log Analytics (Lenovo-aligned schema)

.DESCRIPTION
  Report-only Intune Remediation script build: v4.5
  - Always exits 0
  - Fields: InstalledBiosVersion, AvailableBiosVersion, BiosStatus, SecureBoot
  - Schema parity: Result + SourcesTried included for both success and NoCatalogMatch
  - Improvements:
      * Always try DCUFeed (CatalogIndexPC + GroupManifest) first (no DCU dependency)
      * Leading-zero tolerant match for numeric SKUs (e.g., 0816 <-> 816) without breaking hex IDs
      * BiosStatus tri-state: Up to date / Update available / Ahead of catalog

.NOTES
  Replace <WORKSPACE_ID> and <SHARED_KEY>.
#>

Set-StrictMode -Version 2.0
$ProgressPreference = 'SilentlyContinue'
$ConfirmPreference  = 'None'
$ErrorActionPreference = 'Stop'

# TLS 1.2 hardening for WinPS 5.1
try {
    $cur = [Net.ServicePointManager]::SecurityProtocol
    [Net.ServicePointManager]::SecurityProtocol = $cur -bor [Net.SecurityProtocolType]::Tls12
} catch { }

$Global:WebRetryMaxAttempts        = 3
$Global:WebRetryBaseDelaySeconds   = 2
$Global:WebRetryMaxDelaySeconds    = 20

function Invoke-WebRequestWithRetry {
    param(
        [Parameter(Mandatory=$true)][string]$Uri,
        [Parameter(Mandatory=$false)][ValidateSet('GET','POST','PUT','DELETE','HEAD','PATCH')][string]$Method = 'GET',
        [Parameter(Mandatory=$false)][hashtable]$Headers,
        [Parameter(Mandatory=$false)][string]$ContentType,
        [Parameter(Mandatory=$false)][object]$Body,
        [Parameter(Mandatory=$false)][string]$OutFile,
        [Parameter(Mandatory=$false)][int]$TimeoutSec = 60,
        [Parameter(Mandatory=$false)][int]$MaxAttempts = $Global:WebRetryMaxAttempts,
        [Parameter(Mandatory=$false)][int]$BaseDelaySeconds = $Global:WebRetryBaseDelaySeconds,
        [Parameter(Mandatory=$false)][int]$MaxDelaySeconds  = $Global:WebRetryMaxDelaySeconds
    )

    $attempt = 0
    while ($attempt -lt $MaxAttempts) {
        $attempt++
        try {
            $iwrParams = @{
                Uri            = $Uri
                Method         = $Method
                UseBasicParsing= $true
                TimeoutSec     = $TimeoutSec
                ErrorAction    = 'Stop'
            }
            if ($Headers)     { $iwrParams.Headers     = $Headers }
            if ($ContentType) { $iwrParams.ContentType = $ContentType }
            if ($Body -ne $null) { $iwrParams.Body     = $Body }
            if ($OutFile)     { $iwrParams.OutFile     = $OutFile }

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
                if ($statusCode -eq 408 -or $statusCode -eq 429 -or ($statusCode -ge 500 -and $statusCode -le 599)) { $transient = $true }
            } else {
                $transient = $true
            }

            if (-not $transient -or $attempt -ge $MaxAttempts) { throw }

            if ($retryAfter -ne $null -and $retryAfter -gt 0) {
                $delay = [Math]::Min($retryAfter, $MaxDelaySeconds)
            } else {
                $delayBase = [Math]::Min(($BaseDelaySeconds * [Math]::Pow(2, ($attempt - 1))), $MaxDelaySeconds)
                $delay = $delayBase + (Get-Random -Minimum 0 -Maximum 2)
            }
            Start-Sleep -Seconds $delay
        }
    }
}

# ==== Log Analytics Settings (REPLACE PLACEHOLDERS) ====
$customerId = "Your Log Analytics Workspace ID Here"
$sharedKey  = "Your Shared Key Here"
$logType    = "Your Log Analytcis Workspace Table Name Here"
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

    $xHeaders = "x-ms-date:$Date"
    $stringToHash = "$Method`n$ContentLength`n$ContentType`n$xHeaders`n$Resource"
    $bytesToHash = [Text.Encoding]::UTF8.GetBytes($stringToHash)
    $keyBytes = [Convert]::FromBase64String($SharedKey)

    $hmac = New-Object System.Security.Cryptography.HMACSHA256
    $hmac.Key = $keyBytes
    $hash = $hmac.ComputeHash($bytesToHash)
    $encodedHash = [Convert]::ToBase64String($hash)

    "SharedKey $CustomerId`:$encodedHash"
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

    $signature = Build-Signature -CustomerId $CustomerId -SharedKey $SharedKey -Date $rfc1123date `
        -ContentLength $BodyBytes.Length -Method $method -ContentType $contentType -Resource $resource

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
        $resp = Invoke-WebRequestWithRetry -Uri $uri -Method $method -ContentType $contentType -Headers $headers -Body $BodyBytes
        return [pscustomobject]@{ StatusCode = $resp.StatusCode; StatusDescription = $resp.StatusDescription; Error = $null; ResponseBody = $null }
    } catch {
        $statusCode = $null
        $statusDesc = $null
        $respBody   = $null
        $msg        = $_.Exception.Message

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

        return [pscustomobject]@{ StatusCode = $statusCode; StatusDescription = $statusDesc; Error = $msg; ResponseBody = $respBody }
    }
}

function Get-DeviceInfo {
    $cs   = Get-CimInstance -ClassName Win32_ComputerSystem
    $bios = Get-CimInstance -ClassName Win32_BIOS

    [pscustomobject]@{
        Hostname             = $env:COMPUTERNAME
        Manufacturer         = ($cs.Manufacturer | Out-String).Trim()
        SystemSKU            = ($cs.SystemSKUNumber | Out-String).Trim()
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

function Get-DCUInfo {
    $paths = @(
        "$env:ProgramFiles\Dell\CommandUpdate\dcu-cli.exe",
        "$env:ProgramFiles(x86)\Dell\CommandUpdate\dcu-cli.exe"
    )
    foreach ($p in $paths) {
        if ($p -and (Test-Path $p)) {
            return [pscustomobject]@{ Present = $true; CliVersion = (Get-Item $p).VersionInfo.FileVersion }
        }
    }
    return [pscustomobject]@{ Present = $false; CliVersion = $null }
}

function Expand-CabToFolder {
    param(
        [Parameter(Mandatory=$true)][string]$CabPath,
        [Parameter(Mandatory=$true)][string]$DestinationFolder
    )
    
    # Ensure destination exists and is empty
    if (Test-Path $DestinationFolder) { 
        Remove-Item $DestinationFolder -Recurse -Force -ErrorAction SilentlyContinue 
    }
    New-Item -ItemType Directory -Path $DestinationFolder -Force | Out-Null

    try {
        # Using Shell.Application for CAB files (Native Windows, no external EXE dependency)
        $shell = New-Object -ComObject Shell.Application
        $source = $shell.NameSpace($CabPath)
        $dest = $shell.NameSpace($DestinationFolder)
        $dest.CopyHere($source.Items(), 0x10) # 0x10 = Respond "Yes to All" to any dialogs
        
        # Give the I/O a moment to finalize
        Start-Sleep -Seconds 2
    }
    catch {
        # Fallback to Expand.exe if COM fails for any reason
        & "$env:SystemRoot\System32\expand.exe" "$CabPath" -F:* "$DestinationFolder" | Out-Null
        Start-Sleep -Seconds 2
    }
}

function Get-XmlFromCabUrl {
    param(
        [Parameter(Mandatory=$true)][string]$Url,
        [Parameter(Mandatory=$true)][string]$CacheDir
    )

    $cabName = Split-Path $Url -Leaf
    $cabPath = Join-Path $CacheDir $cabName
    $extractDir = Join-Path $CacheDir ([IO.Path]::GetFileNameWithoutExtension($cabName))

    # Download handling
    if (!(Test-Path $cabPath) -or ((Get-Date) - (Get-Item $cabPath).LastWriteTime).TotalHours -gt 24) {
        Remove-Item $cabPath -Force -ErrorAction SilentlyContinue
        Invoke-WebRequestWithRetry -Uri $Url -OutFile $cabPath | Out-Null
    }

    # Extract
    Expand-CabToFolder -CabPath $cabPath -DestinationFolder $extractDir

    # Search specifically for the XML
    $xmlFile = Get-ChildItem -Path $extractDir -Filter "*.xml" -Recurse | Select-Object -First 1
    
    if (-not $xmlFile) {
        # Last ditch effort: If Get-ChildItem failed, check if the file exists using a literal path
        $literalPath = Join-Path $extractDir ($cabName.Replace(".cab", ".xml"))
        if (Test-Path $literalPath) {
            return $literalPath
        }
        throw "Extraction failed for $cabName. Destination $extractDir exists but XML is missing."
    }

    return $xmlFile.FullName
}

function Get-FirstNonEmptyText {
    param(
        [Parameter(Mandatory=$true)][System.Xml.XmlDocument]$Doc,
        [Parameter(Mandatory=$false)][System.Xml.XmlNode]$ContextNode,
        [Parameter(Mandatory=$true)][string[]]$XPaths
    )
    foreach ($xp in $XPaths) {
        $node = $null
        if ($ContextNode) { $node = $ContextNode.SelectSingleNode($xp) } else { $node = $Doc.SelectSingleNode($xp) }
        if ($node) {
            if ($node.NodeType -eq [System.Xml.XmlNodeType]::Attribute) {
                if ($node.Value -and $node.Value.Trim()) { return $node.Value.Trim() }
            } else {
                if ($node.InnerText -and $node.InnerText.Trim()) { return $node.InnerText.Trim() }
            }
        }
    }
    return $null
}

function Compare-DellBiosVersion {
    param([string]$Current, [string]$Latest)

    # Axx numeric compare
    if ($Current -match '^A(\d+)$' -and $Latest -match '^A(\d+)$') {
        $c = [int]($Current -replace '^A','')
        $l = [int]($Latest  -replace '^A','')
        return $c.CompareTo($l)
    }

    # Dotted version compare when possible
    try { return ([version]$Current).CompareTo([version]$Latest) } catch { }

    # Numeric segment compare fallback
    $cNums = [Regex]::Matches($Current,'\d+') | ForEach-Object { [int]$_.Value }
    $lNums = [Regex]::Matches($Latest ,'\d+') | ForEach-Object { [int]$_.Value }

    if ($cNums.Count -gt 0 -and $lNums.Count -gt 0) {
        $len = [Math]::Max($cNums.Count, $lNums.Count)
        for ($i=0; $i -lt $len; $i++) {
            $cv = if ($i -lt $cNums.Count) { $cNums[$i] } else { 0 }
            $lv = if ($i -lt $lNums.Count) { $lNums[$i] } else { 0 }
            if ($cv -ne $lv) { return $cv.CompareTo($lv) }
        }
        return 0
    }

    return [string]::Compare($Current, $Latest, $true)
}

function Get-DellSystemIdCandidates {
    param([Parameter(Mandatory=$true)][string]$SystemSKU)

    $list = New-Object System.Collections.Generic.List[string]
    $s = $SystemSKU.Trim()

    if ($s) { $list.Add($s) | Out-Null }

    # Only add a no-leading-zeros candidate if SKU is numeric-only (e.g., 0816 -> 816).
    # Avoid breaking hex-like IDs such as 0A68.
    if ($s -match '^\d+$') {
        $trimmed = $s.TrimStart('0')
        if ([string]::IsNullOrWhiteSpace($trimmed)) { $trimmed = '0' }
        if ($trimmed -ne $s) { $list.Add($trimmed) | Out-Null }
    }

    return ($list | Select-Object -Unique)
}

function Get-LatestBiosFromDCUFeed {
    param(
        [Parameter(Mandatory=$true)][string]$SystemSKU,
        [Parameter(Mandatory=$true)][string]$CacheRoot
    )

    $skuCandidates = Get-DellSystemIdCandidates -SystemSKU $SystemSKU

    $indexXmlPath = Get-XmlFromCabUrl -Url "https://downloads.dell.com/catalog/CatalogIndexPC.cab" -CacheDir $CacheRoot
    [xml]$indexXml = Get-Content -Path $indexXmlPath -Encoding UTF8

    $groupNodes = $indexXml.SelectNodes("//*[local-name()='GroupManifest']")
    if (-not $groupNodes) { return $null }

    $matchedGroup = $null
    foreach ($gm in $groupNodes) {
        $sysIds = $gm.SelectNodes(".//*[local-name()='systemID']")
        foreach ($id in $sysIds) {
            if ($id -and $id.InnerText) {
                $idVal = $id.InnerText.Trim()
                if ($skuCandidates -contains $idVal) { $matchedGroup = $gm; break }
            }
        }
        if ($matchedGroup) { break }
    }
    if (-not $matchedGroup) { return $null }

    $relPath = $null
    $miNode = $matchedGroup.SelectSingleNode(".//*[local-name()='ManifestInformation']")
    if ($miNode) {
        $pNode = $miNode.SelectSingleNode(".//*[local-name()='path']")
        if ($pNode -and $pNode.InnerText) { $relPath = $pNode.InnerText.Trim() }
        elseif ($miNode.Attributes['path']) { $relPath = $miNode.Attributes['path'].Value }
    }
    if (-not $relPath) { return $null }

    $skuCabUrl  = "https://downloads.dell.com/$relPath"
    $skuXmlPath = Get-XmlFromCabUrl -Url $skuCabUrl -CacheDir $CacheRoot
    [xml]$skuXml = Get-Content -Path $skuXmlPath -Encoding UTF8

    $components = $skuXml.SelectNodes("//*[local-name()='SoftwareComponent']")
    if (-not $components) { return $null }

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

        $isBios = $false
        if ($componentType -and ($componentType -match 'BIOS')) { $isBios = $true }
        elseif ($nameDesc -and ($nameDesc -match 'BIOS')) { $isBios = $true }
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

        if ($ver) { $candidates.Add([pscustomobject]@{ Version=$ver; Date=$dt }) | Out-Null }
    }

    if ($candidates.Count -eq 0) { return $null }

    $dated = foreach ($x in $candidates) {
        $parsed = $null
        if ($x.Date) { try { $parsed = [datetime]$x.Date } catch { $parsed = $null } }
        [pscustomobject]@{ Version=$x.Version; DateParsed=$parsed }
    }

    return ($dated | Sort-Object -Property DateParsed -Descending | Select-Object -First 1).Version
}

function Get-LatestBiosFromFallbackCatalog {
    param(
        [Parameter(Mandatory=$true)][string]$SystemSKU,
        [Parameter(Mandatory=$true)][string]$CacheRoot
    )

    $skuCandidates = Get-DellSystemIdCandidates -SystemSKU $SystemSKU

    $urls = @(
        "https://downloads.dell.com/catalog/DellSDPCatalogPC.cab",
        "https://downloads.dell.com/catalog/CatalogPC.cab"
    )

    foreach ($u in $urls) {
        try {
            $xmlPath = Get-XmlFromCabUrl -Url $u -CacheDir $CacheRoot
            [xml]$doc = Get-Content -Path $xmlPath -Encoding UTF8

            $components = $doc.SelectNodes('//*[local-name()="SoftwareComponent"]')
            if (-not $components) { continue }

            $biosMatches = New-Object System.Collections.Generic.List[object]

            foreach ($c in $components) {
                $skuHit = $false
                $sysIds = $c.SelectNodes('.//*[local-name()="systemID"]')
                foreach ($id in $sysIds) {
                    if ($id -and $id.InnerText) {
                        $idVal = $id.InnerText.Trim()
                        if ($skuCandidates -contains $idVal) { $skuHit = $true; break }
                    }
                }
                if (-not $skuHit) { continue }

                # BIOS-ish filter (simple)
                $componentType = $c.GetAttribute("type")
                if (-not $componentType -or ($componentType -notmatch 'BIOS')) {
                    $componentType = $c.SelectSingleNode('.//*[local-name()="ComponentType"]/*[local-name()="value"]')
                    if ($componentType -and $componentType.InnerText) {
                        if ($componentType.InnerText -notmatch 'BIOS') { continue }
                    } else {
                        continue
                    }
                }

                $verNode = $c.SelectSingleNode('.//*[local-name()="version"]')
                if (-not $verNode) { $verNode = $c.SelectSingleNode('.//@version') }

                $dtNode  = $c.SelectSingleNode('.//*[local-name()="releaseDate"]')
                if (-not $dtNode) { $dtNode = $c.SelectSingleNode('.//*[local-name()="dateTime"]') }

                $ver = $null
                if ($verNode) {
                    if ($verNode.NodeType -eq [System.Xml.XmlNodeType]::Attribute) { $ver = $verNode.Value }
                    else { $ver = $verNode.InnerText }
                }

                $dt = $null
                if ($dtNode) { $dt = $dtNode.InnerText }

                if ($ver) { $biosMatches.Add([pscustomobject]@{ Version=$ver.Trim(); Date=$dt }) | Out-Null }
            }

            if ($biosMatches.Count -gt 0) {
                $dated = foreach ($x in $biosMatches) {
                    $parsed = $null
                    if ($x.Date) { try { $parsed = [datetime]$x.Date } catch { $parsed = $null } }
                    [pscustomobject]@{ Version=$x.Version; DateParsed=$parsed }
                }
                return ($dated | Sort-Object -Property DateParsed -Descending | Select-Object -First 1).Version
            }
        } catch {
            continue
        }
    }

    return $null
}

try {
    $cacheRoot = Join-Path $env:ProgramData 'PilotDell_BIOS_SB_Cache'
    New-Item -ItemType Directory -Path $cacheRoot -Force | Out-Null

    $dev = Get-DeviceInfo
    if ($dev.Manufacturer -notmatch 'Dell') { exit 0 }

    $secureBoot = Get-SecureBootStatus
    $dcu = Get-DCUInfo

    $sourcesTried = @()
    $latest = $null
    $latestSource = $null

    # v4.4.1: Always try DCUFeed (CatalogIndexPC + GroupManifest) first
    $sourcesTried += 'DCUFeed'
    $latest = Get-LatestBiosFromDCUFeed -SystemSKU $dev.SystemSKU -CacheRoot $cacheRoot
    if ($latest) { $latestSource = 'DCUFeed' }

    if (-not $latest) {
        $sourcesTried += 'FallbackCatalog'
        $latest = Get-LatestBiosFromFallbackCatalog -SystemSKU $dev.SystemSKU -CacheRoot $cacheRoot
        if ($latest) { $latestSource = 'FallbackCatalog' }
    }

    if (-not $latest) {
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

        $biosStatus = if ($cmp -eq 0) {
            'Up to date'
        } elseif ($cmp -lt 0) {
            'Update available'
        } else {
            'Ahead of catalog'
        }

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

    $json = @($record) | ConvertTo-Json -Compress
    $resp = Post-LogAnalyticsData -CustomerId $customerId -SharedKey $sharedKey -BodyBytes ([Text.Encoding]::UTF8.GetBytes($json)) -LogType $logType -TimeStampField $TimeStampField

    if ($resp.StatusCode -eq 200) {
        Write-Output 'Data sent to Log Analytics'
    } else {
        $extra = ''
        if ($resp.ResponseBody) { $extra = " Response: $($resp.ResponseBody)" }
        Write-Output ("Failed to send data to Log Analytics. HTTP: {0} {1}. Error: {2}.{3}" -f $resp.StatusCode, $resp.StatusDescription, $resp.Error, $extra)
    }

} catch {
    Write-Output ('Dell BIOS/SecureBoot script error: ' + $_.Exception.Message)
}

exit 0
