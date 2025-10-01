#!/usr/bin/env bash
set -euo pipefail

if [ $# -lt 1 ]; then
  echo "Usage: $0 <CARD_ID_HEX_16> [CARDS_ROOT=./secrets/cards] [OUT_DIR=./out]" >&2
  exit 1
fi

CARD_ID="$1"
CARDS_ROOT="${2:-./secrets/cards}"
OUT_DIR="${3:-./out}"

if [ ${#CARD_ID} -ne 16 ]; then
  echo "CardId must be 8 bytes hex (16 hex chars)" >&2
  exit 1
fi

CARD_DIR="$CARDS_ROOT/$CARD_ID"
if [ ! -d "$CARD_DIR" ]; then
  echo "Card folder not found: $CARD_DIR" >&2
  exit 1
fi

MASTER_HEX=$(tr -d '\n\r' < "$CARD_DIR/master_auth_key.hex")
SESSION_HEX=$(tr -d '\n\r' < "$CARD_DIR/session_key.hex")

SERVER_PUB_HEX=""
SERVER_PUB_HEX_PATH="$(dirname "$CARDS_ROOT")/server_pub_raw.hex"
if [ -f "$SERVER_PUB_HEX_PATH" ]; then
  SERVER_PUB_HEX=$(tr -d '\n\r' < "$SERVER_PUB_HEX_PATH")
fi

hex_to_bytes() {
  # input hex, output raw bytes to stdout
  echo -n "$1" | sed 's/../& /g' | xargs -n1 printf "\\x%s"
}

bytes_to_hex() {
  od -An -v -t x1 | tr -d ' \n' | tr '[:lower:]' '[:upper:]'
}

make_tlv() {
  local tag=$1
  local val_hex=$2
  local val_bytes
  val_bytes=$(hex_to_bytes "$val_hex")
  local len
  len=$(printf "%02X" $(echo -n "$val_bytes" | wc -c))
  printf "%02X%s%s" "$tag" "$len" "$val_hex"
}

CARD_ID_TLV=$(make_tlv 0x5A "$CARD_ID")
KEYS_HEX=""
if [ -n "$MASTER_HEX" ]; then KEYS_HEX+=$(make_tlv 0x81 "$MASTER_HEX"); fi
if [ -n "$SESSION_HEX" ]; then KEYS_HEX+=$(make_tlv 0x82 "$SESSION_HEX"); fi
if [ -n "$SERVER_PUB_HEX" ]; then KEYS_HEX+=$(make_tlv 0x91 "$SERVER_PUB_HEX"); fi

build_apdu() {
  local cla=$1 ins=$2 p1=$3 p2=$4 payload_hex=${5:-}
  local hdr
  hdr=$(printf "%02X%02X%02X%02X" "$cla" "$ins" "$p1" "$p2")
  if [ -z "$payload_hex" ]; then echo -n "${hdr}00"; return; fi
  local len
  len=$(printf "%02X" $(( ${#payload_hex} / 2 )))
  echo -n "${hdr}${len}${payload_hex}00"
}

SELECT_AID="00A4040009A00000006203010C0600"
APDU_INIT=$(build_apdu 0x80 0x01 0x00 0x00 "$CARD_ID_TLV")
APDU_KEYS=$(build_apdu 0x80 0x06 0x00 0x00 "$KEYS_HEX")

mkdir -p "$OUT_DIR/$CARD_ID"
SCRIPT_PATH="$OUT_DIR/$CARD_ID/personalize.apdu"
{
  echo -n "$SELECT_AID\n$APDU_INIT\n$APDU_KEYS"
} > "$SCRIPT_PATH"

echo "APDU script generated: $SCRIPT_PATH"

