#!/bin/bash
# apply_patches.sh — Run from agentmint-python-main root (demo-for-bil branch)
# Applies all session patches: shield 25, demo section 12, verify_all.py, CHEAT_SHEET.md


echo "Applying patches..."

# ─────────────────────────────────────────────
# 1. SHIELD: system_role_tag warn → block
# ─────────────────────────────────────────────
sed -i.bak 's/("system_role_tag", "structural", "warn",/("system_role_tag", "structural", "block",/' agentmint/shield.py
echo "  ✓ shield.py: system_role_tag → block"

# ─────────────────────────────────────────────
# 2. SHIELD: add 4 new patterns before closing ]
# ─────────────────────────────────────────────
python3 -c "
import re

with open('agentmint/shield.py', 'r') as f:
    content = f.read()

# Find the markdown_link_injection pattern line + closing bracket
old = '''    (\"markdown_link_injection\", \"structural\", \"warn\",
     r\"!\\[.*?\\]\\((?:javascript|data|vbscript):\"),
]'''

new = '''    (\"markdown_link_injection\", \"structural\", \"warn\",
     r\"!\\[.*?\\]\\((?:javascript|data|vbscript):\"),

    # Markdown image data exfiltration — image URL smuggles PII
    (\"markdown_image_exfil\", \"structural\", \"block\",
     r\"!\\[.*?\\]\\(https?://[^\\s)]*(?:ssn|password|secret|token|key|credit)[^\\s)]*\\)\"),

    # Tool output containing instruction-like preamble
    (\"output_instruction\", \"injection\", \"warn\",
     r\"(?i)(?:IMPORTANT|URGENT|NOTE|UPDATE)\\s*:\\s*(?:ignore|forget|override|send|forward)\"),

    # Bulk PII request in output — social engineering via tool response
    (\"bulk_pii_request\", \"injection\", \"warn\",
     r\"(?i)(?:include|provide|output|list)\\s+(?:all\\s+)?(?:customer|user|patient|employee)\\s+\"
     r\"(?:data|details|records|information|accounts|names|emails|numbers)\"),

    # Non-ASCII lookalike in Latin context (Cyrillic substitution)
    (\"homoglyph_latin_mix\", \"encoding\", \"warn\",
     r\"[\\u0400-\\u04ff][\\x20-\\x7e]{2,}[\\u0400-\\u04ff]\"),
]'''

if old not in content:
    if 'markdown_image_exfil' in content:
        print('  (shield patterns already applied)')
    else:
        raise RuntimeError('Could not find shield.py anchor text')
else:
    content = content.replace(old, new, 1)
    with open('agentmint/shield.py', 'w') as f:
        f.write(content)
"
echo "  ✓ shield.py: +4 patterns (markdown_image_exfil, output_instruction, bulk_pii_request, homoglyph_latin_mix)"
rm -f agentmint/shield.py.bak

# ─────────────────────────────────────────────
# 3. DEMO: update section 12 (shipped today / building this week)
# ─────────────────────────────────────────────
python3 -c "
with open('demo_for_bil.py', 'r') as f:
    content = f.read()

old = '''  Shield:             21 regex patterns today \u2014 PII, secrets, injection, encoding
                      output scanning is unique \u2014 no other framework does this
                      {Y}honest gaps: non-English injection, semantic attacks, base64{X}

  OTVP:               receipt.evidence.infrastructure_trust.assessment_hash
                      same Ed25519, same SHA-256, same SPKI PEM, same RFC 3161

  {B}What I'm building this week:{X}

  1. verify_all.py    \u2014 single command replaces VERIFY.sh + verify_sigs.py
                        workpaper-ready output, exception-first, one verdict
                        auditors asked for this \u2014 they don't want two scripts

  2. NHI Authority    \u2014 guided questionnaire mode (Mode B)
     Mode B             \"which agents touch production?\" \"max \$ per action?\"
                        answers \u2192 plan JSON \u2192 ops lead reviews and signs

  3. Shield \u2192 30      \u2014 promote system_role_tag to block, add markdown image
     patterns           exfil, non-ASCII normalization (rogue_agent_demo gaps)

  4. agentmint init   \u2014 outputs draft plan.json alongside scan report
     \u2192 plan draft       ops lead reviews the plan, signs it, that's the authority'''

new = '''  Shield:             25 regex patterns \u2014 PII, secrets, injection, encoding, structural
                      output scanning is unique \u2014 no other framework does this
                      {Y}honest gaps: non-English injection, semantic attacks, base64{X}

  OTVP:               receipt.evidence.infrastructure_trust.assessment_hash
                      same Ed25519, same SHA-256, same SPKI PEM, same RFC 3161

  {B}Shipped today:{X}

  1. verify_all.py    \u2014 single command, workpaper-ready, exception-first
                        replaces VERIFY.sh + verify_sigs.py
                        now bundled into every evidence package

  2. Shield 22\u219225     \u2014 system_role_tag promoted to block
     patterns           + markdown image exfil, output instruction,
                        bulk PII request, homoglyph detection

  {B}Building this week:{X}

  1. NHI Authority    \u2014 guided questionnaire mode (Mode B)
     Mode B             \"which agents touch production?\" \"max \$ per action?\"
                        answers \u2192 plan JSON \u2192 ops lead reviews and signs

  2. agentmint init   \u2014 outputs draft plan.json alongside scan report
     \u2192 plan draft       ops lead reviews the plan, signs it, that's the authority

  3. Shield \u2192 30+     \u2014 non-ASCII normalization before scan,
     patterns           base64 decode-and-rescan, URL extraction from markdown'''

if old not in content:
    if 'Shipped today' in content:
        print('  (demo section 12 already applied)')
    else:
        raise RuntimeError('Could not find demo section 12 anchor text')
else:
    content = content.replace(old, new, 1)
    with open('demo_for_bil.py', 'w') as f:
        f.write(content)
"
echo "  ✓ demo_for_bil.py: section 12 updated (shipped today + building this week)"

# ─────────────────────────────────────────────
# 4. VERIFY_ALL.PY — new file at project root
# ─────────────────────────────────────────────
if [ -f verify_all.py ]; then
    echo "  ⚠ verify_all.py already exists — skipping (delete first to recreate)"
else
cat > verify_all.py << 'PYEOF'
#!/usr/bin/env python3
"""
verify_all.py — Single-command evidence verification.

Replaces VERIFY.sh + verify_sigs.py with one script, one verdict.
Workpaper-ready output. Exception-first reporting.

Place this inside an unzipped evidence package and run:
    python3 verify_all.py

Requires: pip install pynacl
No AgentMint software or account needed.
"""

import base64
import hashlib
import json
import sys
from pathlib import Path

try:
    from nacl.signing import VerifyKey
    from nacl.exceptions import BadSignatureError
except ImportError:
    print("Requires: pip install pynacl")
    sys.exit(1)


def canonical(d):
    return json.dumps(d, sort_keys=True, separators=(",", ":")).encode()


def load_pem_public_key(path):
    lines = path.read_text().strip().split("\n")
    b64 = "".join(lines[1:-1])
    der = base64.b64decode(b64)
    return VerifyKey(der[12:])  # SPKI prefix is 12 bytes


def main():
    here = Path(__file__).parent

    # ── Load public key ───────────────────────────────
    pk_path = here / "public_key.pem"
    if not pk_path.exists():
        print("ERROR: public_key.pem not found")
        sys.exit(1)
    vk = load_pem_public_key(pk_path)
    key_id = hashlib.sha256(bytes(vk)).hexdigest()[:16]

    # ── Load plan ─────────────────────────────────────
    plan_path = here / "plan.json"
    plan = json.loads(plan_path.read_text()) if plan_path.exists() else None

    # ── Load receipts ─────────────────────────────────
    receipts_dir = here / "receipts"
    if not receipts_dir.exists():
        print("ERROR: receipts/ directory not found")
        sys.exit(1)

    receipt_files = sorted(receipts_dir.glob("*.json"))
    if not receipt_files:
        print("ERROR: no receipt JSON files found")
        sys.exit(1)

    # ── Verify ────────────────────────────────────────
    results = []
    exceptions = []
    chain_hashes = []

    print()
    print("  AGENTMINT EVIDENCE VERIFICATION")
    print("  ================================")
    print()

    # Verify plan signature
    if plan:
        sig = bytes.fromhex(plan["signature"])
        signable = {k: v for k, v in plan.items() if k != "signature"}
        try:
            vk.verify(canonical(signable), sig)
            plan_ok = True
        except BadSignatureError:
            plan_ok = False
        status = "OK" if plan_ok else "FAILED"
        print(f"  Plan {plan.get('id', '?')[:8]}  signature: {status}")
        print(f"    user:       {plan.get('user', '?')}")
        print(f"    scope:      {len(plan.get('scope', []))} tools")
        print(f"    delegates:  {plan.get('delegates_to', [])}")
        print(f"    TTL:        {plan.get('issued_at', '?')} → {plan.get('expires_at', '?')}")
        if not plan_ok:
            exceptions.append(("plan", plan.get("id", "?")[:8], "SIGNATURE INVALID"))
        print()

    # Verify each receipt
    for rfile in receipt_files:
        receipt = json.loads(rfile.read_text())
        rid = receipt.get("id", "?")[:8]
        action = receipt.get("action", "?")
        agent = receipt.get("agent", "?")
        in_policy = receipt.get("in_policy", None)
        policy_reason = receipt.get("policy_reason", "")

        # Signature check
        sig = bytes.fromhex(receipt["signature"])
        signable = {k: v for k, v in receipt.items()
                    if k not in ("signature", "timestamp")}
        try:
            vk.verify(canonical(signable), sig)
            sig_ok = True
        except BadSignatureError:
            sig_ok = False

        # Evidence hash check
        evidence = receipt.get("evidence", {})
        evidence_hash = receipt.get("evidence_hash_sha512", "")
        recomputed = hashlib.sha512(canonical(evidence)).hexdigest()
        hash_ok = recomputed == evidence_hash

        # Chain hash (collect for chain verification)
        chain_hashes.append({
            "id": receipt.get("id"),
            "previous_receipt_hash": receipt.get("previous_receipt_hash"),
            "signed_payload": canonical({**signable, "signature": receipt["signature"]}),
        })

        # Key ID check
        receipt_key_id = receipt.get("key_id", "")
        key_match = receipt_key_id == key_id

        # Record result
        row = {
            "id": rid, "action": action, "agent": agent,
            "in_policy": in_policy, "sig_ok": sig_ok,
            "hash_ok": hash_ok, "key_match": key_match,
        }
        results.append(row)

        if not in_policy:
            exceptions.append((rid, action, f"OUT OF POLICY: {policy_reason}"))
        if not sig_ok:
            exceptions.append((rid, action, "SIGNATURE INVALID"))
        if not hash_ok:
            exceptions.append((rid, action, "EVIDENCE HASH MISMATCH"))
        if not key_match:
            exceptions.append((rid, action, f"KEY MISMATCH: {receipt_key_id} != {key_id}"))

    # Chain verification
    chain_valid = True
    chain_break = None
    prev_hash = None
    for i, ch in enumerate(chain_hashes):
        if ch["previous_receipt_hash"] != prev_hash:
            chain_valid = False
            chain_break = i
            break
        prev_hash = hashlib.sha256(ch["signed_payload"]).hexdigest()

    if not chain_valid:
        exceptions.append(("chain", f"index {chain_break}", "CHAIN INTEGRITY BROKEN"))

    # ── EXCEPTIONS (first) ────────────────────────────
    if exceptions:
        print("  EXCEPTIONS")
        print("  ----------")
        for src, detail, msg in exceptions:
            print(f"  ✗  {src:<10s} {detail:<34s} {msg}")
        print()

    # ── RECEIPT TABLE (workpaper-ready) ───────────────
    print(f"  {'ID':<10s} {'Action':<32s} {'Agent':<14s} {'Policy':<10s} {'Sig':<6s} {'Hash':<6s} {'Key':<6s}")
    print(f"  {'─'*10} {'─'*32} {'─'*14} {'─'*10} {'─'*6} {'─'*6} {'─'*6}")
    for r in results:
        policy = "ALLOW" if r["in_policy"] else "DENY"
        sig = "OK" if r["sig_ok"] else "FAIL"
        hsh = "OK" if r["hash_ok"] else "FAIL"
        key = "OK" if r["key_match"] else "FAIL"
        print(f"  {r['id']:<10s} {r['action']:<32s} {r['agent']:<14s} {policy:<10s} {sig:<6s} {hsh:<6s} {key:<6s}")

    # ── SUMMARY ───────────────────────────────────────
    total = len(results)
    sig_pass = sum(1 for r in results if r["sig_ok"])
    hash_pass = sum(1 for r in results if r["hash_ok"])
    key_pass = sum(1 for r in results if r["key_match"])
    policy_deny = sum(1 for r in results if not r["in_policy"])

    print()
    print(f"  SUMMARY")
    print(f"  -------")
    print(f"  Receipts:    {total}")
    print(f"  Signatures:  {sig_pass}/{total} valid")
    print(f"  Hashes:      {hash_pass}/{total} valid")
    print(f"  Key IDs:     {key_pass}/{total} match public_key.pem")
    print(f"  Chain:       {'INTACT' if chain_valid else 'BROKEN at index ' + str(chain_break)}")
    print(f"  Policy:      {total - policy_deny} allowed, {policy_deny} denied")
    print(f"  Exceptions:  {len(exceptions)}")
    print()

    # ── VERDICT ───────────────────────────────────────
    all_ok = sig_pass == total and hash_pass == total and key_pass == total and chain_valid
    if all_ok and not any(e[2].startswith("SIGNATURE") or e[2].startswith("EVIDENCE") or e[2].startswith("CHAIN") for e in exceptions):
        print(f"  VERDICT: PASS — all signatures valid, chain intact, hashes match")
    else:
        print(f"  VERDICT: FAIL — see exceptions above")

    print()
    print(f"  key_id:      {key_id}")
    print(f"  verified_by: verify_all.py (pynacl + hashlib, no vendor software)")
    print()

    sys.exit(0 if all_ok else 1)


if __name__ == "__main__":
    main()
PYEOF
    chmod +x verify_all.py
    echo "  ✓ verify_all.py created"
fi

# ─────────────────────────────────────────────
# 5. CHEAT_SHEET.md — new file at project root
# ─────────────────────────────────────────────
if [ -f CHEAT_SHEET.md ]; then
    echo "  ⚠ CHEAT_SHEET.md already exists — skipping (delete first to recreate)"
else
cat > CHEAT_SHEET.md << 'MDEOF'
# MEETING CHEAT SHEET — Bil Demo
# Read once. Keep open on a second screen during the call.

## PRE-CALL (5 min before)

```bash
cd ~/path/to/agentmint-python-main
rm -rf demo-evidence/
python3 demo_for_bil.py > /dev/null 2>&1   # warm run, creates demo-evidence/
rm -rf demo-evidence/                       # clean for live run
```

Open terminal. Dark background. Font size 16+. Screen share ready.

---

## THE CALL

### Opening (0:00)
SAY: "Since last time I shipped the full pipeline. Let me run it."

```bash
python3 demo_for_bil.py
```

Don't touch keyboard. Let it run (~1 second).

### Section 1-2: Key Management + Discovery (0:01-0:03)
SAY: "This is the key model — ephemeral or persistent, standard Ed25519.
The init scan found 9 tools in the OpenAI CS demo, classified by operation type."

Let scroll. Don't read the output to him.

### Section 3: NHI Authority (0:03-0:05) ← PAUSE HERE
SAY: "This is new since last time. The scan classifies every tool — read, write,
delete, exec — and drafts a plan. Reads auto-allow. Writes need review.
Deletes and exec get checkpoints for human approval.
The signed plan is the agent's authority. No plan, no access."

Point at the plan JSON on screen. Let him read the scope and checkpoints.

### Section 4: Enforce (0:05-0:08) ← PAUSE ON SCENARIO B
SAY on A: "Clean booking. All steps pass. Receipt signed."

SAY on B: "Watch this. Tool is authorized. Inputs clean. But the output
has AWS credentials — compromised dependency. Output scan blocks it.
That credential never reaches the LLM. This is the LiteLLM pattern."

SAY on C: "Cancel flight hits a checkpoint. Plan says pause for human
approval. In production that's a webhook."

SAY on D: "Injection in customer message. Input scan catches it."

### Section 5: Receipt Internals (0:08-0:10)
SAY: "Full receipt. Every field. I verified the signature manually
with nacl — not through our API."

Point at evidence_hash, previous_receipt_hash, plan_signature.

### Section 6-7: Chain + OTVP (0:10-0:12)
SAY: "Hash chain. Any tampering breaks it. The OTVP assessment hash
is in every receipt — same crypto model you built."

### Section 8: Evidence Export (0:12-0:13)
SAY: "Self-contained zip. verify_all.py is new — single command,
workpaper-ready output, exception-first. Replaces the two-script
workflow. Built it based on auditor feedback."

### Section 9: Delegation (0:13-0:14)
SAY: "Parent delegates to child. Scope is intersection — child
can never exceed parent."

### Section 10: Tamper Proof (0:14-0:16)
SAY: "Three tamper tests. Modify a field — signature breaks.
Reorder receipts — chain breaks. Delete one — chain breaks."

### Section 11: Key Derivation (0:16-0:17)
SAY: "key_id is deterministic — SHA-256 of the public key.
Anyone with the PEM can verify this. No trust in us needed."

### Section 12: This Week + Ask (0:17-0:20)
SAY: "That's the verification checklist for your partners.
Here's what I shipped today and what's next this week."

Point at the "shipped today" and "building this week" on screen.

---

## HIS QUESTIONS + YOUR ANSWERS

**"Walk me through what happens on a tool call."**
Rate limit → scope check → checkpoint → input scan → execute → output
scan → sign receipt. Every outcome — allow and deny — gets a receipt.

**"What's the plan vs the receipt?"**
Plan is immutable, signed, has a TTL. Defines scope, checkpoints,
delegates. Receipt is proof of what happened against that plan.
Plan signature is carried into every receipt.

**"Why linear chain not Merkle?"**
Linear is correct for sequential per-session verification. Merkle is
better for proof-of-inclusion at scale — O(log n) vs O(n). That's
where it goes. I'd like your input on tree construction since you
built that for OTVP.

**"How is this different from Oasis?"**
Oasis governs access — which systems an agent can reach. They do JIT
permissions. They don't scan tool call content and don't produce
vendor-independent evidence. We govern actions — what actually
happened, signed and verifiable with openssl. Different layer.
We'd integrate, not replace.

**"Regex is too weak."**
You're right, regex is the floor. It catches the known patterns — AWS
keys, JWTs, injection keywords, data exfil URLs. That's what hit
LiteLLM. It won't catch semantic attacks. The architecture is
pluggable — same pipeline, same receipts, swap the scanner.

**"What do I install on day one?"**
pip install agentmint. Run agentmint init against the codebase.
Scans every tool call across OpenAI SDK, LangGraph, CrewAI, MCP.
Define a plan. Every tool call gets scanned and receipted.
Day one you have an evidence package.

**"What if the signing key is compromised?"**
Key is 32 bytes, 0600 permissions. If compromised, attacker can sign
fake receipts. Mitigation: RFC 3161 timestamps prove when real
receipts were signed. Evidence package snapshots the public key.
Key rotation = new key, re-sign plans, old receipts verify against
old key. HSM support is on the roadmap.

**"Can I verify without your software?"**
Yes. verify_all.py needs only pynacl + hashlib. VERIFY.sh needs only
openssl. Public key is in the zip. No account, no vendor, no lock-in.

**"What properties does your evidence guarantee?"**
Five: portability (survives vendor failure), provenance (policy_hash
proves which rules were active), non-repudiation (Ed25519 + RFC 3161),
chain of custody (SHA-256 hash chain), independent verification
(anyone with the public key).

**"What would make this land with a SOC 2 auditor?"**
verify_all.py — one command, one verdict, exception-first table they
copy into their workpaper. That's what they asked for. Built it today.

---

## THE ASK (0:25-0:30)

Wait for a natural pause. Then:

"I have two questions. First — does the plan receipt model map to how
you've seen NHI governance work in practice?"

Let him answer. Then:

"Second — I'm looking for a team shipping agents to production whose
CISO is asking how they prove what the agents did. That's the person.
Anyone in your circle fit that?"

If he offers to connect you to Oasis/Danny Brickman:
"That makes sense — Oasis grants access, AgentMint produces the
receipt trail for what happened with that access."

---

## IF HE GOES QUIET
Point at section 12 on screen. "Those questions at the bottom —
that's what I'm trying to figure out this week."
MDEOF
    echo "  ✓ CHEAT_SHEET.md created"
fi

# ─────────────────────────────────────────────
# 6. CLEANUP — remove stale root copies
# ─────────────────────────────────────────────
for f in display.py display_updated.py main.py; do
    if [ -f "$f" ] && [ -f "agentmint/cli/$f" ]; then
        if diff -q "$f" "agentmint/cli/$f" > /dev/null 2>&1; then
            rm "$f"
            echo "  ✓ removed stale root $f (identical to cli/$f)"
        fi
    fi
done
rm -rf demo-evidence/
echo "  ✓ cleaned demo-evidence/"

# ─────────────────────────────────────────────
# VERIFY
# ─────────────────────────────────────────────
echo ""
echo "Verifying..."
PATTERN_COUNT=$(grep -c '^\s\+("' agentmint/shield.py)
echo "  Shield patterns: $PATTERN_COUNT (expect 25)"

python3 -c "import py_compile; py_compile.compile('verify_all.py', doraise=True)" && echo "  verify_all.py: syntax OK"
python3 -c "import py_compile; py_compile.compile('demo_for_bil.py', doraise=True)" && echo "  demo_for_bil.py: syntax OK"

echo ""
echo "Done. Now run:"
echo "  pytest"
echo "  python3 demo_for_bil.py"
echo "  rm -rf demo-evidence/"
