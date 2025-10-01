#!/usr/bin/env bash
set -euo pipefail

OUT_DIR=${1:-./secrets}
mkdir -p "$OUT_DIR"

PRIV_PEM="$OUT_DIR/server_key.pem"
PUB_PEM="$OUT_DIR/server_pub.pem"
PUB_HEX="$OUT_DIR/server_pub_raw.hex"

# Requires openssl
openssl ecparam -genkey -name prime256v1 -noout -out "$PRIV_PEM"
openssl ec -in "$PRIV_PEM" -pubout -out "$PUB_PEM"

# Get compressed public key (33 bytes) as DER, then extract last 33 bytes and hex-encode
openssl ec -in "$PRIV_PEM" -pubout -conv_form compressed -outform DER \
  | tail -c 33 \
  | od -An -v -t x1 \
  | tr -d ' \n' \
  > "$PUB_HEX"

echo "Generated: $PRIV_PEM $PUB_PEM $PUB_HEX"

