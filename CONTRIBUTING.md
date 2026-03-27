# Contributing to AgentMint

AgentMint is early-stage and actively developed. Contributions are welcome — whether that's a bug fix, a new pattern for the shield, a framework integration, or a docs improvement.

## Getting started

```bash
git clone https://github.com/aniketh-maddipati/agentmint-python.git
cd agentmint-python
uv sync
uv run pytest tests/ -v
```

All 184 tests should pass. If they don't, open an issue.

## What we're looking for

- **Framework integrations** — MCP, CrewAI, OpenAI Agents SDK, LangChain, AutoGen. Working examples that show AgentMint plugged into a real agent loop.
- **Shield patterns** — New regex patterns for the content scanner. If you've seen a prompt injection or data exfiltration technique in the wild that the shield misses, submit it.
- **Bug reports** — Especially around scope intersection edge cases, receipt chain integrity, and concurrent access.
- **Documentation** — Clearer explanations, better examples, typo fixes. All useful.
- **Performance** — Benchmarks, profiling, or optimisations. AgentMint is currently single-threaded (see [LIMITS.md](LIMITS.md)).

## How to contribute

1. **Check existing issues** before starting work. If there's no issue for what you want to do, open one first so we can discuss the approach.
2. **Fork and branch** from `main`. Use a descriptive branch name (`feat/crewai-integration`, `fix/scope-intersection-edge-case`).
3. **Write tests.** If you're adding a feature, add tests. If you're fixing a bug, add a test that reproduces it.
4. **Run the full suite** before opening a PR:
   ```bash
   uv run pytest tests/ -v
   ```
5. **Open a pull request** against `main`. Describe what changed and why. Link the issue.

## Code style

- Python 3.10+.
- Type hints on public APIs.
- Docstrings on public classes and functions.
- No additional dependencies without discussion — AgentMint ships with two (`pynacl`, `requests`) and we intend to keep it minimal.

## Commit messages

Use conventional commits:

```
feat: add CrewAI integration example
fix: scope intersection fails with empty parent scope
docs: clarify checkpoint gate behaviour in README
test: add receipt chain tamper detection tests
chore: update CI to test Python 3.12
```

## Pull request guidelines

- One logical change per PR. Don't bundle unrelated fixes.
- Keep PRs reviewable — under 400 lines of diff when possible.
- If your change affects the public API, update the README.
- If your change affects security behaviour (shield patterns, scope enforcement, receipt signing), call that out explicitly in the PR description.

## Reporting bugs

Open an issue with:

- What you expected to happen
- What actually happened
- A minimal code snippet that reproduces it
- Python version and OS

## Security vulnerabilities

**Do not open a public issue for security vulnerabilities.** See [SECURITY.md](SECURITY.md) for responsible disclosure instructions.

## License

By contributing, you agree that your contributions will be licensed under the [MIT License](LICENSE).