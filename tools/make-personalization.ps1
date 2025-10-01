param(
    [Parameter(Mandatory=$true)][string]$CardId,
    [string]$CardsRoot = "./secrets/cards",
    [string]$OutDir = "./out"
)

if ($CardId.Length -ne 16) { throw "CardId must be 8 bytes hex (16 hex chars)" }

$cardDir = Join-Path $CardsRoot $CardId
if (-not (Test-Path $cardDir)) { throw "Card folder not found: $cardDir" }

$masterHex = (Get-Content (Join-Path $cardDir 'master_auth_key.hex') -Raw).Trim()
$sessionHex = (Get-Content (Join-Path $cardDir 'session_key.hex') -Raw).Trim()

# Optional server pubkey
$serverPubHexPath = Join-Path (Split-Path $CardsRoot -Parent) 'server_pub_raw.hex'
$serverPubHex = $(if (Test-Path $serverPubHexPath) { (Get-Content $serverPubHexPath -Raw).Trim() } else { '' })

function Make-TLV([byte]$tag, [byte[]]$value) {
    $len = [byte]$value.Length
    $bytes = New-Object byte[] (2 + $value.Length)
    $bytes[0] = $tag
    $bytes[1] = $len
    [Array]::Copy($value, 0, $bytes, 2, $value.Length)
    $bytes
}

function HexToBytes($hex) {
    if ($hex -eq $null -or $hex -eq '') { return @() }
    -split ($hex -replace '..','& ') | Where-Object { $_ -ne '' } | ForEach-Object { [Convert]::ToByte($_,16) }
}

$cardIdBytes = HexToBytes $CardId
$tlvInit = Make-TLV 0x5A $cardIdBytes

$keyBlocks = @()
if ($masterHex -ne '') { $keyBlocks += Make-TLV 0x81 (HexToBytes $masterHex) }
if ($sessionHex -ne '') { $keyBlocks += Make-TLV 0x82 (HexToBytes $sessionHex) }
if ($serverPubHex -ne '') { $keyBlocks += Make-TLV 0x91 (HexToBytes $serverPubHex) }

function BytesToHex([byte[]]$b) { ($b | ForEach-Object { $_.ToString('X2') }) -join '' }

$payloadInitHex = BytesToHex $tlvInit
$payloadKeysHex = BytesToHex ([byte[]]::Concat($keyBlocks))

function Build-APDU($cla,$ins,$p1,$p2,$payloadHex) {
    $hdr = '{0:X2}{1:X2}{2:X2}{3:X2}' -f $cla,$ins,$p1,$p2
    if ($payloadHex -eq '' -or $payloadHex -eq $null) { return $hdr + '00' }
    $len = ([int]($payloadHex.Length/2))
    $Lc = '{0:X2}' -f $len
    return $hdr + $Lc + $payloadHex + '00'
}

$selectAID = '00A4040009A00000006203010C0600'
$apduInit  = Build-APDU 0x80 0x01 0x00 0x00 $payloadInitHex
$apduKeys  = Build-APDU 0x80 0x06 0x00 0x00 $payloadKeysHex

if (-not (Test-Path $OutDir)) { New-Item -ItemType Directory -Force -Path $OutDir | Out-Null }
$outCardDir = Join-Path $OutDir $CardId
if (-not (Test-Path $outCardDir)) { New-Item -ItemType Directory -Force -Path $outCardDir | Out-Null }

$scriptPath = Join-Path $outCardDir 'personalize.apdu'
@(
    $selectAID
    $apduInit
    $apduKeys
) | Set-Content -Path $scriptPath -NoNewline

Write-Host "APDU script generated:" $scriptPath

