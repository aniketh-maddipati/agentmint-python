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

echo "── Receipt f45894e5 ──"
echo "  Action:    read:reports:quarterly"
echo "  Agent:     demo-agent"
echo "  In Policy: True"
echo "  Observed:  2026-03-18T18:20:16.159727+00:00"
if openssl ts -verify \
    -in "receipts/f45894e5-a562-4c59-977d-994c6b04acb2.tsr" \
    -queryfile "receipts/f45894e5-a562-4c59-977d-994c6b04acb2.tsq" \
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
echo "── Receipt c9fda809 ──"
echo "  Action:    read:reports:summary"
echo "  Agent:     demo-agent"
echo "  In Policy: True"
echo "  Observed:  2026-03-18T18:20:16.488537+00:00"
if openssl ts -verify \
    -in "receipts/c9fda809-61a9-4ba7-af57-89b1faf119b9.tsr" \
    -queryfile "receipts/c9fda809-61a9-4ba7-af57-89b1faf119b9.tsq" \
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
echo "── Receipt b2c5a871 ──"
echo "  Action:    delete:reports:quarterly"
echo "  Agent:     demo-agent"
echo "  In Policy: False"
echo "  Observed:  2026-03-18T18:20:16.842817+00:00"
echo "  ⚠ FLAGGED: matched checkpoint delete:*"
FLAGGED=$((FLAGGED + 1))
if openssl ts -verify \
    -in "receipts/b2c5a871-8265-487e-9442-b7d0b0034b9a.tsr" \
    -queryfile "receipts/b2c5a871-8265-487e-9442-b7d0b0034b9a.tsq" \
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
echo "── Receipt 4cc2202f ──"
echo "  Action:    read:secrets:credentials"
echo "  Agent:     demo-agent"
echo "  In Policy: False"
echo "  Observed:  2026-03-18T18:20:17.172223+00:00"
echo "  ⚠ FLAGGED: no scope pattern matched"
FLAGGED=$((FLAGGED + 1))
if openssl ts -verify \
    -in "receipts/4cc2202f-6912-4140-8a3a-c20e06f88dd3.tsr" \
    -queryfile "receipts/4cc2202f-6912-4140-8a3a-c20e06f88dd3.tsq" \
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
