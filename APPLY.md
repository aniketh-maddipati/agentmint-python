# How to Apply These Changes

## What's in this zip

All files with improvements 4.1–4.7 applied, plus new tests, documentation,
and the adapted Bil demo.

## Step-by-step

### 1. Extract into your repo (overwrite existing files)

```bash
cd agentmint-python
unzip -o /path/to/agentmint_improvements.zip
```

### 2. Fix docs/index.html title (bug 3.8)

```bash
bash docs/fix_title.sh
```

Or manually change in `docs/index.html`:
- Title: "AI Agent Identity Gateway" → "Independent Notary for AI Agent Actions"
- Badge: "AI Agent Identity" → "Independent Notary"

### 3. Run tests

```bash
pytest tests/ -v
```

Expected: all tests pass. New test count should be ~90+ (was 76).

New tests added:
- `test_patterns.py` — 9 tests for unified pattern matcher (4.3)
- `test_notary.py::TestPlanSignatureInReceipt` — 4 tests (4.4)
- `test_notary.py::TestReceiptChain::test_per_plan_chain_isolation` — 1 test (4.2)
- `test_notary.py::TestNotaryKeyStore` — 3 tests (4.1)
- `test_notary.py::TestVerifyChain` — 4 tests (4.6)
- `test_notary.py::TestEvidencePackage::test_index_has_chain_root` — 1 test (4.7)

### 4. Regenerate sample evidence

```bash
python examples/generate_sample_evidence.py
```

### 5. Run the quickstart

```bash
python examples/quickstart.py
```

### 6. Run the Bil demo

```bash
export ANTHROPIC_API_KEY=...
export ELEVENLABS_API_KEY=...
python examples/elevenlabs_gatekeeper_demo.py
```

### 7. Verify the evidence package

```bash
cd evidence_output && unzip -o agentmint_evidence_*.zip
bash VERIFY.sh
python3 verify_sigs.py
```

## Files changed

| File | Change |
|------|--------|
| `agentmint/patterns.py` | **NEW** — unified pattern matcher (4.3) |
| `agentmint/core.py` | Updated imports to use `patterns.py` |
| `agentmint/notary.py` | All improvements: 4.1, 4.2, 4.4, 4.5, 4.6, 4.7 |
| `tests/test_patterns.py` | **NEW** — pattern matcher tests |
| `tests/test_notary.py` | Updated with new improvement tests |
| `tests/test_core.py` | Unchanged |
| `LIMITS.md` | **NEW** — architectural limits |
| `IMPROVEMENTS.md` | **NEW** — what was built |
| `examples/elevenlabs_gatekeeper_demo.py` | Adapted for Bil demo |
| `docs/fix_title.sh` | **NEW** — fixes index.html title |

## Files NOT changed (keep your originals)

- `agentmint/__init__.py`
- `agentmint/errors.py`
- `agentmint/types.py`
- `agentmint/console.py`
- `agentmint/decorator.py`
- `agentmint/keystore.py`
- `agentmint/timestamp.py`
- `docs/index.html` (apply fix_title.sh separately)
- All other example files
- `mcp_server/`
- `README.md`
- `pyproject.toml`
