<#
.SYNOPSIS
  Dell BIOS currency + Secure Boot → Log Analytics (Lenovo-aligned schema)

.DESCRIPTION
  Report-only Intune Remediation script build: v2.0.0
  - Always exits 0
  - Fields: InstalledBiosVersion, AvailableBiosVersion, BiosStatus, SecureBoot
  - If no catalog match: Result=NoCatalogMatch, SourcesTried, AvailableBiosVersion=Unavailable, BiosStatus=Unknown

.NOTES
  Replace <WORKSPACE_ID> and <SHARED_KEY>.
  PS 5.1-safe structure with clearer error flow; still not namespace-safe; still greedy SKU matching.
#>

Set-StrictMode -Version 2.0
$ProgressPreference='SilentlyContinue'
$ConfirmPreference='None'
$ErrorActionPreference='Stop'

$customerId = "<WORKSPACE_ID>"
$sharedKey  = "<SHARED_KEY>"
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

        $uri = "https://$CustomerId.ods.opinsights.azure.com$resource?api-version=2016-04-01"


$headers = @{
    "Authorization" = $signature
    "Log-Type"      = $LogType
    "x-ms-date"     = $rfc1123date
}

if (-not [string]::IsNullOrWhiteSpace($TimeStampField)) {
    $headers["time-generated-field"] = $TimeStampField
}

        try {
            $resp = Invoke-WebRequest -Uri $uri -Method $method -ContentType $contentType -Headers $headers -Body $BodyBytes -UseBasicParsing -ErrorAction Stop
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
        Invoke-WebRequest -Uri $Url -UseBasicParsing -OutFile $cabPath -ErrorAction Stop | Out-Null
    }

    $extractDir = Join-Path $CacheDir ([IO.Path]::GetFileNameWithoutExtension($cabName))

    Expand-CabToFolder -CabPath $cabPath -DestinationFolder $extractDir

    $xml = Get-ChildItem -Path $extractDir -Filter *.xml -Recurse | Select-Object -First 1
    if (-not $xml) { throw "No XML found after expanding $Url" }
    return $xml.FullName
}

function Compare-DellBiosVersion {
    param([string]$Current, [string]$Latest)
    if ($Current -match '^A(\d+)$' -and $Latest -match '^A(\d+)$') {
        $c = ($Current -replace '^A','')
        $l = ($Latest  -replace '^A','')
        return $c.CompareTo($l)
    }
    try { return ([version]$Current).CompareTo([version]$Latest) } catch { return [string]::Compare($Current,$Latest,$true) }
}

function Get-LatestBiosFromFallbackCatalog {
    param(
        [Parameter(Mandatory=$true)][string]$SystemSKU,
        [Parameter(Mandatory=$true)][string]$CacheRoot
    )

    $urls = @("https://downloads.dell.com/catalog/CatalogPC.cab")

    foreach ($u in $urls) {
        try {
            $xmlPath = Get-XmlFromCabUrl -Url $u -CacheDir $CacheRoot
            [xml]$doc = Get-Content -Path $xmlPath -Encoding UTF8

            $components = $doc.SelectNodes("//SoftwareComponent")
            if (-not $components) { continue }

            $biosMatches = New-Object System.Collections.Generic.List[object]

            foreach ($c in $components) {
                $skuHit = $false
                if ($c.OuterXml -match [regex]::Escape($SystemSKU)) { $skuHit = $true }
                if (-not $skuHit) { continue }

                # BIOS-ish filter (simple)
                $componentType = $c.GetAttribute("type")
                if (-not $componentType -or ($componentType -notmatch 'BIOS')) {
                    # try child node hints (namespace safe via local-name)
                    $componentType = $c.SelectSingleNode(".//*[local-name()='ComponentType']/*[local-name()='value']")
                    if ($componentType -and $componentType.InnerText) {
                        if ($componentType.InnerText -notmatch 'BIOS') { continue }
                    } else {
                        continue
                    }
                }

                $verNode = $c.SelectSingleNode(".//*[local-name()='version']")
                if (-not $verNode) { $verNode = $c.SelectSingleNode(".//@version") }
                $dtNode  = $c.SelectSingleNode(".//*[local-name()='releaseDate']")
                if (-not $dtNode) { $dtNode = $c.SelectSingleNode(".//*[local-name()='dateTime']") }

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



$sourcesTried = @('FallbackCatalog')
$latestSource = 'FallbackCatalog'
$latest = Get-LatestBiosFromFallbackCatalog -SystemSKU $dev.SystemSKU -CacheRoot $cacheRoot

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

        $json = $record | ConvertTo-Json -Compress
        $resp = Post-LogAnalyticsData -CustomerId $customerId -SharedKey $sharedKey -BodyBytes ([Text.Encoding]::UTF8.GetBytes($json)) -LogType $logType -TimeStampField $TimeStampField
        if ($resp.StatusCode -eq 200) {
            Write-Output 'Data sent to Log Analytics'
        } else {
            $extra = ''
            if ($resp.ResponseBody) { $extra = " Response: $($resp.ResponseBody)" }
            Write-Output ("Failed to send data to Log Analytics. HTTP: 0 1. Error: 2.3" -f $resp.StatusCode, $resp.StatusDescription, $resp.Error, $extra)
        }

    } catch {
        Write-Output ('Dell BIOS/SecureBoot script error: ' + $_.Exception.Message)
    }

    exit 0
