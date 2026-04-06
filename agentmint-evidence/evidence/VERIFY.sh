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

echo "── Receipt ebde8c3d ──"
echo "  Action:    ehr:read:patient"
echo "  Agent:     clinical-ops"
echo "  In Policy: True"
echo "  Observed:  2026-04-06T18:15:42.507721+00:00"
if openssl ts -verify \
    -in "receipts/ebde8c3d-bab7-41fa-b42f-7328fe08088e.tsr" \
    -queryfile "receipts/ebde8c3d-bab7-41fa-b42f-7328fe08088e.tsq" \
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
echo "── Receipt 36bc818a ──"
echo "  Action:    billing:charge:payment"
echo "  Agent:     clinical-ops"
echo "  In Policy: True"
echo "  Observed:  2026-04-06T18:15:42.822095+00:00"
if openssl ts -verify \
    -in "receipts/36bc818a-e461-4bfc-90d7-968f45240272.tsr" \
    -queryfile "receipts/36bc818a-e461-4bfc-90d7-968f45240272.tsq" \
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
echo "── Receipt 8bc74258 ──"
echo "  Action:    shield:blocked:notify:send:message"
echo "  Agent:     clinical-ops"
echo "  In Policy: False"
echo "  Observed:  2026-04-06T18:15:43.132627+00:00"
echo "  ⚠ FLAGGED: no scope pattern matched"
FLAGGED=$((FLAGGED + 1))
if openssl ts -verify \
    -in "receipts/8bc74258-7905-4a47-aeb2-dd629736c35f.tsr" \
    -queryfile "receipts/8bc74258-7905-4a47-aeb2-dd629736c35f.tsq" \
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
echo "── Receipt 46883077 ──"
echo "  Action:    audit:query:log"
echo "  Agent:     clinical-ops"
echo "  In Policy: True"
echo "  Observed:  2026-04-06T18:15:43.439085+00:00"
if openssl ts -verify \
    -in "receipts/46883077-ecec-4781-bdad-53d03558527e.tsr" \
    -queryfile "receipts/46883077-ecec-4781-bdad-53d03558527e.tsq" \
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
