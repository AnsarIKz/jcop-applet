param(
    [string]$OutDir = "./secrets"
)

if (-not (Test-Path $OutDir)) { New-Item -ItemType Directory -Force -Path $OutDir | Out-Null }

$privPem = Join-Path $OutDir "server_key.pem"
$pubPem  = Join-Path $OutDir "server_pub.pem"
$pubHex  = Join-Path $OutDir "server_pub_raw.hex"

# Requires OpenSSL in PATH
& openssl ecparam -genkey -name prime256v1 -noout -out $privPem | Out-Null
& openssl ec -in $privPem -pubout -out $pubPem | Out-Null

# Export compressed public key (33 bytes) and save as hex
$compressed = & openssl ec -in $privPem -pubout -conv_form compressed -outform DER 2>$null |
    ForEach-Object { $_ }

if (-not $compressed) {
    Write-Error "OpenSSL not found or failed to generate key"
    exit 1
}

# The DER public key structure ends with the ECPoint OCTET STRING; extract last 33 bytes
$bytes = [byte[]]$compressed
if ($bytes.Length -lt 33) { Write-Error "Unexpected DER length"; exit 1 }
$last33 = $bytes[-33..-1]
$hex = ($last33 | ForEach-Object { $_.ToString('X2') }) -join ''
Set-Content -Path $pubHex -Value $hex -NoNewline

Write-Host "Generated:" $privPem, $pubPem, $pubHex



