param(
    [Parameter(Mandatory=$true)][string]$CardId,
    [string]$OutDir = "./secrets/cards",
    [int]$KeyBytes = 32,
    [string]$DbPath = "./card_keys.db",
    [string]$ServerPubHexPath = "./secrets/server_pub_raw.hex"
)

if ($CardId.Length -ne 16) { throw "CardId must be 8 bytes hex (16 hex chars)" }
if (-not (Test-Path $OutDir)) { New-Item -ItemType Directory -Force -Path $OutDir | Out-Null }

$cardDir = Join-Path $OutDir $CardId
if (-not (Test-Path $cardDir)) { New-Item -ItemType Directory -Force -Path $cardDir | Out-Null }

function New-RandomHex([int]$len) {
    $b = New-Object byte[] $len
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $rng.GetBytes($b)
    ($b | ForEach-Object { $_.ToString('X2') }) -join ''
}

$masterHex = New-RandomHex $KeyBytes
$sessionHex = New-RandomHex $KeyBytes

Set-Content -Path (Join-Path $cardDir 'master_auth_key.hex') -Value $masterHex -NoNewline
Set-Content -Path (Join-Path $cardDir 'session_key.hex') -Value $sessionHex -NoNewline

$serverPubHex = ''
if (Test-Path $ServerPubHexPath) { $serverPubHex = (Get-Content $ServerPubHexPath -Raw).Trim() }

$uid = $CardId

$profile = [ordered]@{
    card_id = $CardId
    uid = $uid
    master_auth_key_hex = $masterHex
    session_key_hex = $sessionHex
    server_pubkey_hex = $serverPubHex
}

$json = $profile | ConvertTo-Json -Depth 4
Set-Content -Path (Join-Path $cardDir 'card_profile.json') -Value $json

# Upsert into TSV DB
if (-not (Test-Path $DbPath)) {
    Set-Content -Path $DbPath -Value "card_id	uid	master_auth_key_hex	session_key_hex	server_pubkey_hex" -NoNewline
}

$lines = Get-Content $DbPath
$header = $lines | Select-Object -First 1
$rest = @()
if ($lines.Count -gt 1) { $rest = $lines | Select-Object -Skip 1 }
$rest = $rest | Where-Object { -not ($_ -match "^$CardId\t") }
$newLine = "$CardId`t$uid`t$masterHex`t$sessionHex`t$serverPubHex"
$outLines = @($header) + $rest + $newLine
Set-Content -Path $DbPath -Value $outLines

Write-Host "Generated keys and profile in" $cardDir

