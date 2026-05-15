# AGENTS.md

Guidance for AI coding agents and human contributors working in this repository.

## Project role

AgentMint is the reference producer/runtime for AERF receipts.

This repository focuses on:

- Runtime enforcement for AI-agent tool calls.
- Signed evidence receipts.
- Scope enforcement and delegation.
- Evidence export and verification workflows.
- Content scanning and runtime protections.
- Framework integrations and developer ergonomics.

AERF itself lives in the separate `aerf-spec/aerf` repository.

Keep the separation clear:

- AgentMint produces and operationalizes receipts.
- AERF defines the portable receipt format and verifier semantics.
- Runtime convenience must not silently violate the AERF contract.

## Architecture expectations

Core properties that should remain true:

- Receipts are independently verifiable.
- Verification must not require AgentMint infrastructure.
- Signed evidence should be deterministic and auditable.
- Enforcement failures should fail closed by default.
- Delegated scope must never exceed parent scope.
- Evidence export should remain simple and inspectable.

Prefer transparent and auditable code paths over hidden automation.

## Key areas

- `agentmint/notary.py` — receipt creation, signing, chaining, export.
- `agentmint/shield.py` — content scanning and injection detection.
- `agentmint/circuit_breaker.py` — runaway-agent protection.
- `agentmint/cli/` — CLI tooling and codebase scanning.
- `agentmint/demo/` — healthcare and other demonstrations.
- `tests/` — behavioral and regression coverage.

If repository structure changes, update this file.

## Development rules

- Maintain Python 3.8+ compatibility unless the project version policy changes.
- Avoid introducing heavyweight dependencies unless clearly justified.
- Keep cryptographic and verification paths easy to audit.
- Do not log secrets, raw credentials, auth tokens, or regulated customer data.
- Never commit private signing keys or real PHI/PII.
- Do not weaken enforcement semantics to improve demos or benchmarks.
- Preserve backward compatibility for public APIs where practical, especially:
  - `Notary`
  - `create_plan`
  - `notarise`
  - delegation APIs
  - evidence export flows
  - CLI commands

## Validation

Run the relevant checks before committing:

```bash
python -m pytest
```

Also validate packaging and CLI behavior when touching distribution or command code:

```bash
pip install -e .
agentmint --help
```

Run the demo flows after changes affecting receipts, delegation, scanning, export, or enforcement:

```bash
python -m agentmint.demo.healthcare
```

If receipt structure changes, verify compatibility against the AERF specification repository.

## AERF compatibility

When changing receipt fields, signatures, canonicalization, chaining behavior, timestamps, or export structure:

1. Check compatibility with `aerf-spec/aerf`.
2. Update example artifacts if needed.
3. Document intentional divergences clearly.
4. Avoid shipping undocumented wire-format changes.

If AgentMint temporarily diverges from the draft spec, document the gap explicitly in:

- `README.md`
- `CHANGELOG.md`
- open issues
- migration notes

## CLI and scanner guidance

The scanner and initialization tools should optimize for:

- low false negatives for unprotected tool calls
- understandable output
- safe defaults
- minimal destructive behavior

Never auto-modify user code without an explicit opt-in flag.

Generated config and quickstart files should be readable and conservative.

## Documentation style

- Use concrete operational language.
- Prefer runnable examples.
- Keep examples copy-pasteable.
- Clearly label aspirational roadmap items versus shipping functionality.
- Be precise about security guarantees and current limitations.

Do not claim:

- formal certification
- guaranteed compliance
- perfect prompt-injection detection
- impossible-to-bypass enforcement

## Performance guidance

AgentMint is intended for hot runtime paths.

When modifying notarisation or verification flows:

- avoid unnecessary allocations
- avoid network dependencies in core runtime paths
- benchmark before adding expensive scanning or serialization logic
- preserve low-latency shadow-mode usage

## Safe editing checklist

Before opening a PR or committing directly, confirm:

- [ ] Tests pass.
- [ ] Public APIs remain stable or are documented.
- [ ] Receipt verification still works.
- [ ] Evidence export still verifies offline.
- [ ] No secrets or regulated data were committed.
- [ ] README examples still run.
- [ ] AERF compatibility impact is understood and documented.
