#!/usr/bin/env bash
# AgentMint receipt verification -- pure bash, openssl, jq, sha256sum/shasum.
#
# Step 1 :: openssl pkeyutl verifies the Ed25519 signature over the canonical
#           receipt bytes using only the customer-held public key. This proves
#           the receipt has not been altered since the agent signed it.
#
# Step 2 :: SHA-256 of the payload file is compared to the payload_sha256
#           field inside the receipt. This proves the action payload matches
#           what the receipt claims, without putting PHI on the wire.
#
# Step 3 :: We declare the receipt verified offline. No AgentMint binary, no
#           network call, no vendor on the line.
#
# Exits non-zero on any failure. Requires openssl 3.0+ and jq.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PUB="$ROOT/keys/public.pem"
RCPT="$ROOT/receipts/00001.json"
SIG="$ROOT/receipts/00001.json.sig"
PAYLOAD="$ROOT/receipts/00001.json.payload"

require() {
  command -v "$1" >/dev/null 2>&1 || { echo "ERROR: '$1' not found on PATH"; exit 10; }
}
require openssl
require jq

if command -v sha256sum >/dev/null 2>&1; then
  HASH_CMD=(sha256sum)
elif command -v shasum >/dev/null 2>&1; then
  HASH_CMD=(shasum -a 256)
else
  echo "ERROR: need sha256sum or shasum"; exit 10
fi

OSSL_VER="$(openssl version | awk '{print $2}')"
case "$OSSL_VER" in
  3.*) ;;
  *) echo "ERROR: openssl $OSSL_VER detected; need 3.0 or newer for Ed25519 -rawin"; exit 11 ;;
esac

echo "-- Step 1 :: verify Ed25519 signature --"
if openssl pkeyutl -verify \
    -pubin -inkey "$PUB" \
    -rawin -in "$RCPT" \
    -sigfile "$SIG"; then
  echo "  OK signature valid"
else
  echo "  FAIL signature INVALID"
  exit 1
fi

echo
echo "-- Step 2 :: payload hash matches receipt claim --"
CLAIMED="$(jq -r '.payload_sha256' "$RCPT")"
ACTUAL="$("${HASH_CMD[@]}" "$PAYLOAD" | awk '{print $1}')"
if [ "$CLAIMED" = "$ACTUAL" ]; then
  echo "  OK payload SHA-256 matches: ${ACTUAL:0:16}..."
else
  echo "  FAIL mismatch"
  echo "    claimed: $CLAIMED"
  echo "    actual:  $ACTUAL"
  exit 2
fi

echo
echo "-- Step 3 :: result --"
echo "  OK Receipt verifies offline. No AgentMint binary required."
