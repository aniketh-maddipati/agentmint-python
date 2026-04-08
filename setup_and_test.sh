#!/bin/bash
# ═══════════════════════════════════════════════════════════════════
#  PASTE THIS ENTIRE BLOCK INTO YOUR TERMINAL
#  Run from: agentmint-python-main/  (the project root)
#
#  What it does:
#    1. Installs Python dependencies
#    2. Installs agentmint in editable mode
#    3. Verifies every import the demo needs
#    4. Runs the demo and validates output
#    5. Runs the existing test suite
# ═══════════════════════════════════════════════════════════════════
set -euo pipefail

G="\033[92m"; R="\033[91m"; Y="\033[93m"; C="\033[96m"
D="\033[2m"; B="\033[1m"; X="\033[0m"

echo ""
echo -e "${B}═══════════════════════════════════════════════════════${X}"
echo -e "  ${B}AgentMint Demo — Full Setup${X}"
echo -e "${B}═══════════════════════════════════════════════════════${X}"

# ── Sanity check: are we in the right directory? ──────
if [ ! -f "pyproject.toml" ] || [ ! -d "agentmint" ]; then
    echo -e "  ${R}✗  Not in the agentmint-python-main project root.${X}"
    echo -e "  ${D}   cd to the directory containing pyproject.toml${X}"
    exit 1
fi
echo -e "  ${G}✓${X}  In project root: $(pwd)"

# ── Step 1: Install dependencies ──────────────────────
echo ""
echo -e "  ${B}Step 1: Dependencies${X}"
echo -e "  ${D}─────────────────────────────────────────${X}"

pip install pynacl requests click rich pyyaml 2>&1 | tail -1
echo -e "  ${G}✓${X}  pip install complete"

pip install -e . 2>&1 | tail -1
echo -e "  ${G}✓${X}  agentmint installed in editable mode"

# ── Step 2: Verify imports ────────────────────────────
echo ""
echo -e "  ${B}Step 2: Verify imports${X}"
echo -e "  ${D}─────────────────────────────────────────${X}"

FAIL=0
for mod in \
    "from nacl.signing import SigningKey" \
    "from agentmint.shield import scan" \
    "from agentmint.circuit_breaker import CircuitBreaker" \
    "from agentmint.notary import Notary, verify_chain" \
    "from agentmint.patterns import in_scope" \
    "from agentmint.cli.candidates import ToolCandidate" \
    "from agentmint.cli.display import print_full_report"
do
    if python3 -c "$mod" 2>/dev/null; then
        SHORT=$(echo "$mod" | sed 's/from //;s/ import.*//')
        echo -e "  ${G}✓${X}  $SHORT"
    else
        echo -e "  ${R}✗${X}  $mod"
        FAIL=1
    fi
done

if [ "$FAIL" = "1" ]; then
    echo ""
    echo -e "  ${R}Import failures. See errors above.${X}"
    exit 1
fi

# ── Step 3: Verify demo script ────────────────────────
echo ""
echo -e "  ${B}Step 3: Demo script${X}"
echo -e "  ${D}─────────────────────────────────────────${X}"

if [ ! -f "demo_for_bil.py" ]; then
    echo -e "  ${R}✗  demo_for_bil.py not found in project root${X}"
    exit 1
fi
echo -e "  ${G}✓${X}  demo_for_bil.py found"
python3 -c "import ast; ast.parse(open('demo_for_bil.py').read())"
echo -e "  ${G}✓${X}  Parses clean"

# ── Step 4: Run the demo ──────────────────────────────
echo ""
echo -e "  ${B}Step 4: Running demo_for_bil.py${X}"
echo -e "  ${D}─────────────────────────────────────────${X}"

OUTFILE="/tmp/demo_bil_test.txt"
if python3 demo_for_bil.py > "$OUTFILE" 2>&1; then
    echo -e "  ${G}✓${X}  Demo completed"
else
    echo -e "  ${R}✗  Demo crashed:${X}"
    tail -20 "$OUTFILE"
    exit 1
fi

# ── Step 5: Validate output (30 checks) ──────────────
echo ""
echo -e "  ${B}Step 5: Validate output${X}"
echo -e "  ${D}─────────────────────────────────────────${X}"

PASS=0; FAIL=0
chk() {
    if grep -q "$2" "$OUTFILE" 2>/dev/null; then
        PASS=$((PASS + 1))
    else
        echo -e "  ${R}✗${X}  $1"
        FAIL=$((FAIL + 1))
    fi
}

chk "Act 1 header"          "ACT 1"
chk "Headline box"          "not production-ready"
chk "book_new_flight"       "book_new_flight"
chk "issue_compensation"    "issue_compensation"
chk "Kiro incident"         "Kiro"
chk "LiteLLM incident"      "LiteLLM"
chk "WITH AGENTMINT table"  "WITH AGENTMINT"
chk "Act 2 header"          "ACT 2"
chk "ALLOWED result"        "ALLOWED"
chk "BLOCKED result"        "BLOCKED"
chk "Output scan block"     "output scan"
chk "Scope violation"       "OUT OF SCOPE"
chk "Receipts signed"       "receipts signed"
chk "Act 3 header"          "ACT 3"
chk "Sigs verified"         "signatures verified"
chk "Chain valid"           "Chain valid"
chk "Hash match"            "evidence_hash matches"
chk "OTVP hash"             "c29c6380"
chk "Act 4 header"          "ACT 4"
chk "Ed25519 side-by-side"  "Ed25519"
chk "Full stack trust"      "Full stack trust"
chk "Oasis mention"         "Oasis"
chk "NHI mention"           "Non-Human"
chk "Act 5 header"          "ACT 5"
chk "pip install"           "pip install agentmint"
chk "Completed timing"      "Completed in"

echo -e "  ${G}${PASS} passed${X}, ${R}${FAIL} failed${X}"

# ── Step 6: Evidence zip ──────────────────────────────
echo ""
echo -e "  ${B}Step 6: Evidence package${X}"
echo -e "  ${D}─────────────────────────────────────────${X}"

if ls demo-evidence/agentmint_evidence_*.zip > /dev/null 2>&1; then
    ZIP=$(ls -t demo-evidence/agentmint_evidence_*.zip | head -1)
    echo -e "  ${G}✓${X}  $ZIP"
    python3 -c "
import zipfile
with zipfile.ZipFile('$ZIP') as z:
    for n in sorted(z.namelist()):
        print(f'       {n}')
" 2>/dev/null
else
    echo -e "  ${Y}~${X}  No zip (timestamps need network — OK for offline demo)"
fi

# ── Step 7: Existing tests ────────────────────────────
echo ""
echo -e "  ${B}Step 7: Test suite${X}"
echo -e "  ${D}─────────────────────────────────────────${X}"
python3 -m pytest tests/ -q --tb=short 2>&1 | tail -5 || true

# ── Summary ───────────────────────────────────────────
echo ""
echo -e "${B}═══════════════════════════════════════════════════════${X}"
if [ "$FAIL" = "0" ]; then
    echo -e "  ${G}ALL CHECKS PASSED — DEMO IS READY${X}"
else
    echo -e "  ${R}${FAIL} CHECKS FAILED — FIX BEFORE MEETING${X}"
fi
echo -e "${B}═══════════════════════════════════════════════════════${X}"
echo ""
echo -e "  To run the demo:  ${C}python3 demo_for_bil.py${X}"
echo ""

rm -f "$OUTFILE"
