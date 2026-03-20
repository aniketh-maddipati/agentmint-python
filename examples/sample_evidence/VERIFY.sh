#!/bin/bash
# AgentMint Evidence Verification — RFC 3161 Timestamps
# Requires: openssl
# For Ed25519 signatures: python3 verify_sigs.py

set -euo pipefail
cd "$(dirname "$0")"

VERIFIED=0
FAILED=0
FLAGGED=0
TOTAL=0

echo "── Receipt 24aa2837 ──"
echo "  Action:    read:reports:quarterly"
echo "  Agent:     demo-agent"
echo "  In Policy: True"
echo "  Observed:  2026-03-20T16:09:09.444164+00:00"
if openssl ts -verify \
    -in "receipts/24aa2837-cef3-4a4c-b16f-ad1545becf26.tsr" \
    -queryfile "receipts/24aa2837-cef3-4a4c-b16f-ad1545becf26.tsq" \
    -CAfile "freetsa_cacert.pem" \
    -untrusted "freetsa_tsa.crt" \
    > /dev/null 2>&1; then
  echo "  Timestamp: ✓ verified"
  VERIFIED=$((VERIFIED + 1))
else
  echo "  Timestamp: ✗ FAILED"
  FAILED=$((FAILED + 1))
fi
TOTAL=$((TOTAL + 1))
echo ""
echo "── Receipt e93c0bec ──"
echo "  Action:    read:reports:summary"
echo "  Agent:     demo-agent"
echo "  In Policy: True"
echo "  Observed:  2026-03-20T16:09:09.823448+00:00"
if openssl ts -verify \
    -in "receipts/e93c0bec-fb43-4a8d-9790-f950815baab0.tsr" \
    -queryfile "receipts/e93c0bec-fb43-4a8d-9790-f950815baab0.tsq" \
    -CAfile "freetsa_cacert.pem" \
    -untrusted "freetsa_tsa.crt" \
    > /dev/null 2>&1; then
  echo "  Timestamp: ✓ verified"
  VERIFIED=$((VERIFIED + 1))
else
  echo "  Timestamp: ✗ FAILED"
  FAILED=$((FAILED + 1))
fi
TOTAL=$((TOTAL + 1))
echo ""
echo "── Receipt c7ea0e82 ──"
echo "  Action:    delete:reports:quarterly"
echo "  Agent:     demo-agent"
echo "  In Policy: False"
echo "  Observed:  2026-03-20T16:09:10.191176+00:00"
echo "  ⚠ FLAGGED: matched checkpoint delete:*"
FLAGGED=$((FLAGGED + 1))
if openssl ts -verify \
    -in "receipts/c7ea0e82-df2c-477f-b4d8-9712c6a2ad44.tsr" \
    -queryfile "receipts/c7ea0e82-df2c-477f-b4d8-9712c6a2ad44.tsq" \
    -CAfile "freetsa_cacert.pem" \
    -untrusted "freetsa_tsa.crt" \
    > /dev/null 2>&1; then
  echo "  Timestamp: ✓ verified"
  VERIFIED=$((VERIFIED + 1))
else
  echo "  Timestamp: ✗ FAILED"
  FAILED=$((FAILED + 1))
fi
TOTAL=$((TOTAL + 1))
echo ""
echo "── Receipt b5dd9e47 ──"
echo "  Action:    read:secrets:credentials"
echo "  Agent:     demo-agent"
echo "  In Policy: False"
echo "  Observed:  2026-03-20T16:09:10.529517+00:00"
echo "  ⚠ FLAGGED: no scope pattern matched"
FLAGGED=$((FLAGGED + 1))
if openssl ts -verify \
    -in "receipts/b5dd9e47-374f-4ab1-b7dd-3de5e13dfaed.tsr" \
    -queryfile "receipts/b5dd9e47-374f-4ab1-b7dd-3de5e13dfaed.tsq" \
    -CAfile "freetsa_cacert.pem" \
    -untrusted "freetsa_tsa.crt" \
    > /dev/null 2>&1; then
  echo "  Timestamp: ✓ verified"
  VERIFIED=$((VERIFIED + 1))
else
  echo "  Timestamp: ✗ FAILED"
  FAILED=$((FAILED + 1))
fi
TOTAL=$((TOTAL + 1))
echo ""
echo "════════════════════════════════════════"
echo "  Timestamps: $VERIFIED / $TOTAL verified"
echo "  Failures:   $FAILED"
echo "  Flagged:    $FLAGGED out-of-policy"
echo "  Signatures: run python3 verify_sigs.py"
echo "════════════════════════════════════════"

[ "$FAILED" -gt 0 ] && exit 1
exit 0
