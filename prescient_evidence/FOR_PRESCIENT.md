# AgentMint Evidence Package — Prescient

    bash VERIFY.sh

Six signed receipts, two plans, one checkpoint block, one supervisor
amendment. WORKPAPER_TEMPLATE.md has the assessment procedure (~30 min).

---

## Where we are

We built a standard evidence format for AIUC-1 agent assessments —
signed receipts mapped to D003 and E015 controls. This package is
a working implementation against a healthcare claims scenario.

The three-file sequence (receipt 004, plan-002, receipt 005) shows
D003.4 human-approval enforced and verified cryptographically. The
rest covers authorization, rate limits, tool call logging, and chain
integrity.

We know the standard well enough to have built this. We do not know
what your assessors would need different, and we would rather hear
that from you than guess.

---

## What we are asking for

A call to walk through the package together. We want to hear what
works, what does not, and what your team would need to actually use
this on an engagement.

If it holds up, the pilot is straightforward: we provide the evidence
format on your first AIUC-1 client, your team runs the assessment,
we build the workpaper together.

Every company that integrates AgentMint produces this format and
needs an assessor. That pipeline flows to whoever validates it.

---

## What is in here

D003/E015 coverage only. No adversarial testing (B001). No log
storage (E015.2). Timestamps available, not in this demo. This
is one piece, not the full picture.
