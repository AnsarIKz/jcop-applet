#!/usr/bin/env bash
set -euo pipefail

if [ $# -lt 1 ]; then
  echo "Usage: $0 <CARD_ID_HEX_16> [OUT_DIR=./secrets/cards] [DB_PATH=./card_keys.db] [SERVER_PUB_HEX=./secrets/server_pub_raw.hex]" >&2
  exit 1
fi

CARD_ID="$1"        # 16 hex chars (8 bytes)
OUT_DIR="${2:-./secrets/cards}"
DB_PATH="${3:-./card_keys.db}"
SERVER_PUB_HEX_PATH="${4:-./secrets/server_pub_raw.hex}"

if [ ${#CARD_ID} -ne 16 ]; then
  echo "CardId must be 8 bytes hex (16 hex chars)" >&2
  exit 1
fi

CARD_DIR="$OUT_DIR/$CARD_ID"
mkdir -p "$CARD_DIR"

# 32-byte random hex
rand_hex() {
  # tries /dev/urandom; fallback to openssl
  if command -v hexdump >/dev/null 2>&1; then
    head -c "$1" /dev/urandom | hexdump -v -e '/1 "%02X"'
  else
    openssl rand -hex "$1" | tr '[:lower:]' '[:upper:]'
  fi
}

MASTER_HEX=$(rand_hex 32)
SESSION_HEX=$(rand_hex 32)

printf "%s" "$MASTER_HEX" > "$CARD_DIR/master_auth_key.hex"
printf "%s" "$SESSION_HEX" > "$CARD_DIR/session_key.hex"

SERVER_PUB_HEX=""
if [ -f "$SERVER_PUB_HEX_PATH" ]; then
  SERVER_PUB_HEX=$(tr -d '\n\r' < "$SERVER_PUB_HEX_PATH")
fi

cat > "$CARD_DIR/card_profile.json" <<JSON
{
  "card_id": "$CARD_ID",
  "uid": "$CARD_ID",
  "master_auth_key_hex": "$MASTER_HEX",
  "session_key_hex": "$SESSION_HEX",
  "server_pubkey_hex": "$SERVER_PUB_HEX"
}
JSON

# Upsert TSV DB
if [ ! -f "$DB_PATH" ]; then
  printf "card_id\tuid\tmaster_auth_key_hex\tsession_key_hex\tserver_pubkey_hex" > "$DB_PATH"
fi

TMP_DB=$(mktemp)
grep -v "^$CARD_ID\t" "$DB_PATH" > "$TMP_DB" || true
printf "\n%s\t%s\t%s\t%s\t%s" "$CARD_ID" "$CARD_ID" "$MASTER_HEX" "$SESSION_HEX" "$SERVER_PUB_HEX" >> "$TMP_DB"
mv "$TMP_DB" "$DB_PATH"

echo "Generated keys and profile in $CARD_DIR"

