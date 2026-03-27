#!/usr/bin/env python3
"""
Verify AgentMint receipt chain from receipts.json.

Checks SHA-256 hash chain integrity and prints a human-readable trace.
No AgentMint installation needed.

For full Ed25519 signature verification, use the evidence export
package (notary.export_evidence) which includes public_key.pem
and verify_sigs.py.

    python verify_receipts.py
"""

import hashlib
import json
import sys
from pathlib import Path


def canonical(d: dict) -> bytes:
    return json.dumps(d, sort_keys=True, separators=(",", ":")).encode()


def main():
    path = Path("receipts.json")
    if not path.exists():
        print("No receipts.json found. Run demo.py first.")
        sys.exit(1)

    receipts = json.loads(path.read_text())
    print(f"\nVerifying {len(receipts)} receipts…\n")

    chain_ok = True
    prev_hash = None

    for i, receipt in enumerate(receipts):
        sig_hex = receipt.get("signature", "")
        signable = {k: v for k, v in receipt.items() if k not in ("signature", "timestamp")}

        # Chain integrity
        receipt_prev = receipt.get("previous_receipt_hash")
        chain_match = receipt_prev == prev_hash
        if not chain_match:
            chain_ok = False

        # Compute hash for next link
        prev_hash = hashlib.sha256(canonical({**signable, "signature": sig_hex})).hexdigest()

        # Display
        rid = receipt.get("id", "")[:8]
        action = receipt.get("action", "?")
        tag = "in policy" if receipt.get("in_policy") else "VIOLATION"
        chain_mark = "✓" if chain_match else "✗ BREAK"

        print(f"  [{i+1}] {rid}  {action}  ({tag})  chain:{chain_mark}")

    print(f"\n{'─' * 50}")
    print(f"  Receipts: {len(receipts)}")
    print(f"  Chain:    {'✓ intact' if chain_ok else '✗ BROKEN'}")
    print(f"{'─' * 50}\n")

    sys.exit(0 if chain_ok else 1)


if __name__ == "__main__":
    main()