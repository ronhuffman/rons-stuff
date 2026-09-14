# Run this on your Windows laptop, not on the Pico.
# Uses only Windows/.NET; no Python installation or extra modules are needed.
[CmdletBinding()]
param(
    [string]$PicoAddress = '',
    [string]$Firmware = '',
    [string]$ConfigFile = '',
    [ValidateRange(1, 65535)][int]$Port = 80,
    [switch]$StatusOnly,
    [switch]$ConfirmOnly
)

$ErrorActionPreference = 'Stop'
# Windows PowerShell may evaluate parameter defaults before PSScriptRoot is set.
# Resolve adjacent files inside the script body, not inside param().
$packageDirectory = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $Firmware) { $Firmware = Join-Path $packageDirectory 'washer_a.py' }
if (-not $ConfigFile) { $ConfigFile = Join-Path $packageDirectory 'pico_config.json' }
$parsedAddress = $null
if (-not [Net.IPAddress]::TryParse($PicoAddress, [ref]$parsedAddress) -or
    $parsedAddress.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork) {
    throw 'Use a numeric IPv4 address, without http:// or a path.'
}
$octets = $parsedAddress.GetAddressBytes()
$privateAddress = ($octets[0] -eq 10) -or
    ($octets[0] -eq 192 -and $octets[1] -eq 168) -or
    ($octets[0] -eq 172 -and $octets[1] -ge 16 -and $octets[1] -le 31) -or
    ($octets[0] -eq 127)
if (-not $privateAddress) { throw 'Updates are restricted to a private LAN (or local test address).' }
$baseUrl = 'http://{0}:{1}' -f $PicoAddress, $Port
$updateToken = $null
$expectedDeviceId = $null

function Send-PicoRequest {
    param([string]$Method, [string]$Path, [byte[]]$Body = @(), [string]$Digest = '', [string]$ConfirmDigest = '')
    $request = [Net.HttpWebRequest]::Create($baseUrl + $Path)
    $request.Method = $Method
    $request.Proxy = $null
    $request.AllowAutoRedirect = $false
    $request.KeepAlive = $false
    $request.Timeout = if ($Method -eq 'PUT') { 65000 } else { 5000 }
    $request.ReadWriteTimeout = $request.Timeout
    $request.ServicePoint.Expect100Continue = $false
    if ($Method -ne 'GET') {
        $request.Headers['Authorization'] = 'Bearer ' + $updateToken
        $request.Headers['X-Device-Type'] = 'washer'
        $request.Headers['X-Device-ID'] = $expectedDeviceId
        $request.ContentType = 'application/octet-stream'
        $request.ContentLength = $Body.Length
    }
    if ($Digest) { $request.Headers['X-SHA256'] = $Digest }
    if ($ConfirmDigest) { $request.Headers['X-Confirm-SHA256'] = $ConfirmDigest }
    if ($Body.Length -gt 0) {
        $stream = $request.GetRequestStream()
        try { $stream.Write($Body, 0, $Body.Length) } finally { $stream.Dispose() }
    }
    try {
        $response = $request.GetResponse()
    } catch [Net.WebException] {
        if ($_.Exception.Response) {
            $errorResponse = $_.Exception.Response
            $reader = [IO.StreamReader]::new($errorResponse.GetResponseStream())
            try { $detail = $reader.ReadToEnd() } finally { $reader.Dispose(); $errorResponse.Dispose() }
            throw ('Pico refused the request: ' + $detail)
        }
        throw 'Could not reach the Pico. Check its address and that this laptop is on the same LAN.'
    }
    $reader = [IO.StreamReader]::new($response.GetResponseStream())
    try { $text = $reader.ReadToEnd() } finally { $reader.Dispose(); $response.Dispose() }
    return ($text | ConvertFrom-Json)
}

$before = Send-PicoRequest -Method GET -Path '/status'
if ($before.device_type -ne 'washer') {
    throw 'This endpoint is not the upgraded washer application. Do not send washer code to the dryer or to an unverified device.'
}
if ($StatusOnly) {
    $before | Format-List
    return
}
if ($before.boot_api -ne 1) { throw 'This Pico does not report the expected A/B update launcher API.' }
$privateConfig = Get-Content -LiteralPath $ConfigFile -Raw | ConvertFrom-Json
$updateToken = $privateConfig.UPDATE_TOKEN
if (-not $updateToken -or $updateToken.Length -lt 32) { throw 'Private configuration is missing a secure update token.' }
$expectedDeviceId = $privateConfig.DEVICE_ID
if ($privateConfig.DEVICE_TYPE -ne 'washer' -or -not $expectedDeviceId -or $expectedDeviceId -ne $before.device_id) {
    throw 'Private configuration does not match this washer device. Check the address and use its own configuration file.'
}
$firmwarePath = (Resolve-Path -LiteralPath $Firmware).Path
if ([IO.Path]::GetExtension($firmwarePath) -ne '.py') { throw 'Select the new washer application .py file, not main.py or a ZIP.' }
$payload = [IO.File]::ReadAllBytes($firmwarePath)
if ($payload.Length -lt 1000 -or $payload.Length -gt 120000) { throw 'Application must be 1,000 to 120,000 bytes.' }
$strictUtf8 = [Text.UTF8Encoding]::new($false, $true)
$sourceText = $strictUtf8.GetString($payload)
if ($sourceText -notmatch '(?m)^BOOT_API = 1\s*$' -or $sourceText -notmatch '(?m)^def run\(context\):' -or
    $sourceText -notmatch '(?m)^DEVICE_TYPE = "washer"\s*$') {
    throw 'This is not a compatible washer application. Do not send the small main.py launcher.'
}
$sha = [Security.Cryptography.SHA256]::Create()
try { $digest = ([BitConverter]::ToString($sha.ComputeHash($payload))).Replace('-', '').ToLowerInvariant() }
finally { $sha.Dispose() }
$versionMatch = [regex]::Match($sourceText, '(?m)^VERSION = "([^"]+)"\s*$')
if (-not $versionMatch.Success) { throw 'Application must declare its VERSION.' }
$expectedVersion = $versionMatch.Groups[1].Value

if ($ConfirmOnly) {
    if (-not $before.trial) { throw 'The Pico is not running a trial update.' }
    if ($before.running_sha256 -ne $digest -or $before.version -ne $expectedVersion) {
        throw 'The running trial does not match the selected application file. Do not confirm unknown code.'
    }
    $result = Send-PicoRequest -Method POST -Path '/update/confirm' -ConfirmDigest $digest
    $verified = Send-PicoRequest -Method GET -Path '/status'
    if (-not $result.confirmed -or $verified.trial -or $verified.running_sha256 -ne $digest -or
        $verified.device_id -ne $expectedDeviceId -or $verified.slot -ne $before.slot) {
        throw 'Could not independently verify confirmation.'
    }
    Write-Host ('SUCCESS: confirmed matching washer application in slot ' + $verified.slot)
    return
}
if (-not $before.update_allowed) {
    throw 'Update is not allowed yet. Washer must be READY with fresh zero/standby power for 30 seconds, no pending bulb reset, and a confirmed boot. Do not update during a cycle.'
}
$expectedSlot = if ($before.slot -eq 'a') { 'b' } elseif ($before.slot -eq 'b') { 'a' } else { throw 'Invalid running slot.' }
Write-Host ('Uploading {0:N0} bytes to {1}; running version is {2}.' -f $payload.Length, $PicoAddress, $before.version)
$accepted = Send-PicoRequest -Method PUT -Path '/update' -Body $payload -Digest $digest
if ($accepted.sha256 -ne $digest -or -not $accepted.confirmation_required -or $accepted.staged -ne $expectedSlot -or
    $accepted.device_type -ne 'washer' -or $accepted.device_id -ne $expectedDeviceId) {
    throw 'Unexpected staging reply. Do not assume the update succeeded; inspect /status.'
}
Write-Host 'Upload verified. Waiting for the trial version to reboot and pass its 60-second startup check...'
Write-Host 'Leave this window open. Without confirmation, the Pico rolls back after about three minutes.'
$timer = [Diagnostics.Stopwatch]::StartNew()
$sawTrial = $false
while ($timer.Elapsed.TotalSeconds -lt 200) {
    Start-Sleep -Seconds 3
    try { $current = Send-PicoRequest -Method GET -Path '/status' } catch { continue }
    if ($current.device_type -ne 'washer' -or $current.device_id -ne $expectedDeviceId) {
        throw 'The endpoint device identity changed while updating. No further confirmation will be sent.'
    }
    $matchingApplication = $current.running_sha256 -eq $digest -and $current.slot -eq $accepted.staged -and $current.version -eq $expectedVersion
    if ($matchingApplication -and $current.trial) { $sawTrial = $true }
    if ($matchingApplication -and $current.trial -and $current.boot_age_seconds -ge 60 -and
        $current.confirmation_allowed -and $current.shelly_online -and $current.wifi_connected) {
        try { $confirmation = Send-PicoRequest -Method POST -Path '/update/confirm' -ConfirmDigest $digest } catch { continue }
        if (-not $confirmation.confirmed) { continue }
        $verified = Send-PicoRequest -Method GET -Path '/status'
        if ($verified.running_sha256 -eq $digest -and $verified.slot -eq $accepted.staged -and -not $verified.trial -and
            $verified.device_type -eq 'washer' -and $verified.device_id -eq $expectedDeviceId -and $verified.version -eq $expectedVersion) {
            Write-Host ('SUCCESS: version {0}, slot {1}, confirmed over Wi-Fi.' -f $verified.version, $verified.slot)
            return
        }
    }
    # A lost confirmation reply is recoverable: verify committed hash and slot.
    if ($matchingApplication -and -not $current.trial) {
        Write-Host ('SUCCESS: version {0}, slot {1}, already confirmed.' -f $current.version, $current.slot)
        return
    }
    if (($sawTrial -or $timer.Elapsed.TotalSeconds -gt 30) -and
        -not $current.trial -and $current.slot -eq $before.slot) {
        throw 'The new application did not stay running; the Pico is back on the previous slot. Inspect /status and last_crash. The update was NOT confirmed.'
    }
}
throw 'No confirmed success was observed. The trial should roll back if unconfirmed; check /status. Do not assume either success or recovery without checking.'
