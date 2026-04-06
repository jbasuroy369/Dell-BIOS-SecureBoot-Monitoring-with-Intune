<#
.SYNOPSIS
  Dell BIOS currency + Secure Boot â†' Log Analytics (Lenovo-aligned schema)

.DESCRIPTION
  Report-only Intune Remediation script build: v4.4
  - Always exits 0
  - Fields: InstalledBiosVersion, AvailableBiosVersion, BiosStatus, SecureBoot
  - If no catalog match: Result=NoCatalogMatch, SourcesTried, AvailableBiosVersion=Unavailable, BiosStatus=Unknown

.NOTES
  Replace <WORKSPACE_ID> and <SHARED_KEY>.
  Fixes: Axx numeric cast retained; extraction folder cleared before re-expansion to avoid stale XML selection; includes TLS+retry+DCU feed and fallback.
#>

Set-StrictMode -Version 2.0
$ProgressPreference='SilentlyContinue'
$ConfirmPreference='None'
$ErrorActionPreference='Stop'


# TLS 1.2 hardening for WinPS 5.1
try {
    $cur = [Net.ServicePointManager]::SecurityProtocol
    [Net.ServicePointManager]::SecurityProtocol = $cur -bor [Net.SecurityProtocolType]::Tls12
} catch { }

$Global:WebRetryMaxAttempts = 3
$Global:WebRetryBaseDelaySeconds = 2
$Global:WebRetryMaxDelaySeconds = 20

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
            $iwrParams = @{ Uri=$Uri; Method=$Method; UseBasicParsing=$true; TimeoutSec=$TimeoutSec; ErrorAction='Stop' }
            if ($Headers) { $iwrParams.Headers = $Headers }
            if ($ContentType) { $iwrParams.ContentType = $ContentType }
            if ($Body -ne $null) { $iwrParams.Body = $Body }
            if ($OutFile) { $iwrParams.OutFile = $OutFile }
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

$customerId = "788c2c19-91da-4b3f-b914-2bd9fde766e9"
$sharedKey  = "EyB5XRlDHRn8eLPSu+yIlkOR3/rNxjIlm2mSyR98WeXqHJlmRAMqWDaOuwhDr3LL1DtHXQuuPtTX+dYhS5pm6g=="
$logType    = "Pilot_Dell_Device_Properties"
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

        $method = "POST"
        $contentType = "application/json"
        $resource = "/api/logs"
        $rfc1123date = [DateTime]::UtcNow.ToString("r")

        $signature = Build-Signature -CustomerId $CustomerId -SharedKey $SharedKey -Date $rfc1123date `
            -ContentLength $BodyBytes.Length -Method $method -ContentType $contentType -Resource $resource

        #$uri = "https://$CustomerId.ods.opinsights.azure.com{$resource}?api-version=2016-04-01"
        $uri = "https://{0}.ods.opinsights.azure.com{1}?api-version=2016-04-01" -f $CustomerId, $resource


$headers = @{
    "Authorization" = $signature
    "Log-Type"      = $LogType
    "x-ms-date"     = $rfc1123date
    "Content-Length"= $BodyBytes.Length
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
            $respBody = $null
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
            return [pscustomobject]@{ StatusCode = $statusCode; StatusDescription = $statusDesc; Error = $msg; ResponseBody = $respBody }
        }
    }

function Get-DeviceInfo {
        $cs = Get-CimInstance -ClassName Win32_ComputerSystem
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
        New-Item -ItemType Directory -Path $DestinationFolder -Force | Out-Null
        & "$env:SystemRoot\System32\expand.exe" -F:* "$CabPath" "$DestinationFolder" | Out-Null
    }

    function Get-XmlFromCabUrl {
        param(
            [Parameter(Mandatory=$true)][string]$Url,
            [Parameter(Mandatory=$true)][string]$CacheDir
        )

        New-Item -ItemType Directory -Path $CacheDir -Force | Out-Null
        $cabName = Split-Path $Url -Leaf
        $cabPath = Join-Path $CacheDir $cabName

        # 24h CAB cache
        if (Test-Path $cabPath) {
            $ageHrs = ((Get-Date) - (Get-Item $cabPath).LastWriteTime).TotalHours
            if ($ageHrs -gt 24) {
                Remove-Item $cabPath -Force -ErrorAction SilentlyContinue
            }
        }

        if (-not (Test-Path $cabPath)) {
            Invoke-WebRequestWithRetry -Uri $Url -OutFile $cabPath | Out-Null
        }

        $extractDir = Join-Path $CacheDir ([IO.Path]::GetFileNameWithoutExtension($cabName))

if (Test-Path $extractDir) {
    Remove-Item $extractDir -Recurse -Force -ErrorAction SilentlyContinue
}
        Expand-CabToFolder -CabPath $cabPath -DestinationFolder $extractDir

        $xml = Get-ChildItem -Path $extractDir -Filter *.xml -Recurse | Select-Object -First 1
        if (-not $xml) { throw "No XML found after expanding $Url" }
        return $xml.FullName
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
    try { return ([version]$Current).CompareTo([version]$Latest) } catch {}

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

    return [string]::Compare($Current,$Latest,$true)
}

function Get-LatestBiosFromDCUFeed {
    param(
        [Parameter(Mandatory=$true)][string]$SystemSKU,
        [Parameter(Mandatory=$true)][string]$CacheRoot
    )

    $indexXmlPath = Get-XmlFromCabUrl -Url "https://downloads.dell.com/catalog/CatalogIndexPC.cab" -CacheDir $CacheRoot
    [xml]$indexXml = Get-Content -Path $indexXmlPath -Encoding UTF8

    $groupNodes = $indexXml.SelectNodes("//*[local-name()='GroupManifest']")
    if (-not $groupNodes) { return $null }

    $matchedGroup = $null
    foreach ($gm in $groupNodes) {
        $sysIds = $gm.SelectNodes(".//*[local-name()='systemID']")
        foreach ($id in $sysIds) {
            if ($id -and $id.InnerText -and ($id.InnerText.Trim() -eq $SystemSKU)) { $matchedGroup = $gm; break }
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

        $urls = @("https://downloads.dell.com/catalog/DellSDPCatalogPC.cab","https://downloads.dell.com/catalog/CatalogPC.cab")

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
    if ($id -and $id.InnerText -and ($id.InnerText.Trim() -eq $SystemSKU)) { $skuHit = $true; break }
}
                    if (-not $skuHit) { continue }

                    # BIOS-ish filter (simple)
                    $componentType = $c.GetAttribute("type")
                    if (-not $componentType -or ($componentType -notmatch 'BIOS')) {
                        # try child node hints (namespace safe via local-name)
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

if ($dcu.Present) {
    $sourcesTried += 'DCUFeed'
    $latest = Get-LatestBiosFromDCUFeed -SystemSKU $dev.SystemSKU -CacheRoot $cacheRoot
    if ($latest) { $latestSource = 'DCUFeed' }
}

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
                TimestampUTC         = (Get-Date).ToUniversalTime().ToString('o')
            }
        } else {
            $cmp = Compare-DellBiosVersion -Current $dev.InstalledBiosVersion -Latest $latest
            $biosStatus = if ($cmp -eq 0) { 'Up to date' } else { 'Update available' }

            $record = [pscustomobject]@{
                Hostname             = $dev.Hostname
                SystemSKU            = $dev.SystemSKU
                InstalledBiosVersion = $dev.InstalledBiosVersion
                AvailableBiosVersion = $latest
                BiosStatus           = $biosStatus
                SecureBoot           = $secureBoot
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


