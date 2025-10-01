#!/usr/bin/env bash
set -euo pipefail

GP_JAR=${1:-./tools/gp.jar}
CAP_PATH=${2:-}
KEY_HEX=${3:-404142434445464748494A4B4C4D4E4F}
INSTANCE_AID=${4:-A00000006203010C06}

if [ ! -f "$GP_JAR" ]; then
  echo "GlobalPlatformPro jar not found: $GP_JAR" >&2
  echo "Download: https://github.com/martinpaljak/GlobalPlatformPro/releases" >&2
  exit 1
fi

if [ -z "${CAP_PATH}" ]; then
  # pick first cap under ./build
  CAP_PATH=$(find ./build -type f -name '*.cap' | head -n1 || true)
fi

if [ -z "$CAP_PATH" ] || [ ! -f "$CAP_PATH" ]; then
  echo "CAP not found. Run 'ant convert' first." >&2
  exit 1
fi

echo "Installing CAP: $CAP_PATH with AID $INSTANCE_AID"
set -x
java -jar "$GP_JAR" -key "$KEY_HEX" -install "$CAP_PATH" -default -create "$INSTANCE_AID"
set +x
echo "Install completed"

