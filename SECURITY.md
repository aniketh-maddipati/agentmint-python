# Security Policy

AgentMint is a security library. We take vulnerabilities in our own code seriously.

## Supported versions

| Version | Supported |
| ------- | --------- |
| 0.1.x   | ✅        |

## Reporting a vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Email **security@agent-mint.dev** with:

- Description of the vulnerability
- Steps to reproduce
- Impact assessment (what an attacker could achieve)
- Suggested fix, if you have one

You'll receive an acknowledgement within 48 hours. We aim to provide a substantive response (confirmed/not confirmed, timeline for fix) within 5 business days.

## What qualifies

We're especially interested in:

- **Receipt forgery or tampering** — any way to produce a receipt that passes `verify_receipt()` without the original signing key, or to modify a receipt without detection.
- **Hash chain breaks** — ways to insert, remove, or reorder receipts without breaking the chain verification.
- **Scope escalation** — a delegate gaining permissions beyond what the parent plan grants, including through scope intersection edge cases.
- **Shield bypasses** — prompt injection, data exfiltration, or secret patterns that evade the content scanner. Include the exact input that bypasses detection.
- **Circuit breaker evasion** — ways to exceed rate limits without triggering the breaker.
- **Timing or side-channel attacks** — information leakage through timing differences in scope checks or receipt verification.

## What doesn't qualify

- **Known limitations documented in [LIMITS.md](LIMITS.md)** — regex-based scanning won't catch novel semantic attacks, agent identity is asserted not proven, no behavioural baselines. These are documented boundaries, not vulnerabilities.
- Denial of service through resource exhaustion (AgentMint runs in-process; if you can call it, you already have process access).
- Issues that require physical access to the machine.

## Disclosure timeline

- **Day 0** — Report received, acknowledgement sent.
- **Day 5** — Initial assessment shared with reporter.
- **Day 30** — Target for fix in a new release. If we need more time, we'll tell you why.
- **Day 90** — Public disclosure. We won't ask you to wait longer than 90 days.

If we confirm a vulnerability, the reporter will be credited in the release notes (unless they prefer to remain anonymous).

## PGP key

If you'd like to encrypt your report, request our PGP public key by emailing security@agent-mint.dev with the subject line `PGP key request`.