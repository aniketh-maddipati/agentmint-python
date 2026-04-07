# AgentMint Evidence Package — Decrypt Compliance

    bash VERIFY.sh            # timestamps — pure openssl
    python3 verify_sigs.py    # Ed25519 signatures — needs pynacl

Six signed receipts, two plans, one checkpoint block, one supervisor
amendment. WORKPAPER_TEMPLATE.md has the assessment procedure (~30 min).

---

## What this is

A sample evidence package for AI agent tool calls, mapped to controls
you already test: SOC 2 CC6/CC7/CC8, ISO 42001 A.6/A.7/A.8, and AIUC-1
D003/E015. The scenario is a healthcare claims agent — reads patient data,
checks insurance, submits claims, gets blocked on an appeal (checkpoint),
then re-authorized under a narrower policy by a human supervisor.

Each receipt is an Ed25519-signed JSON recording one agent action. The
chain uses SHA-256 hashes linking each receipt to its predecessor. RFC 3161
timestamps from FreeTSA anchor the timeline independently.

---

## Why this matters for your AI clients

When you audit a SaaS company that deploys AI agents, you need evidence
that agent actions were authorized, bounded, logged, and monitored. Today
that evidence doesn't exist in a structured format. Clients give you
application logs (mutable), screenshots (point-in-time), or nothing.

This package is what "good" looks like — structured, signed, chained,
independently verifiable. Every receipt maps to controls you already have
in your workpapers.

---

## Multi-framework coverage (one evidence artifact)

Your blog post on ISO 42001 / SOC 2 overlap described how "security
controls that protect customer data can also support responsible AI use."
This evidence format is built around that same principle — one receipt
satisfies controls across frameworks simultaneously.

| Receipt field | SOC 2 | ISO 42001 | AIUC-1 |
|---|---|---|---|
| `action` + `in_policy` | CC6.1 Logical Access | A.6.2.8 Event Logging | E015 Log activity |
| `previous_receipt_hash` | CC7.2 Monitoring | Clause 9.1 Evaluation | E015.3 Integrity |
| `policy_hash` + `plan_signature` | CC8.1 Change Mgmt | A.6.2.3 Verification | D003.1 Authorization |
| checkpoint block (receipt 004) | CC7.2 Anomaly Detection | A.8.3 Human Oversight | D003.4 Approval |
| `signature` (Ed25519) | CC7.2 Tamper Evidence | Clause 7.5 Doc Integrity | E015.3 Integrity |
| `evidence_hash_sha512` | PI1.1 Processing Defined | A.7.4 Data Provenance | — |
| `session_trajectory` | CC7.3 Event Analysis | A.6.2.6 Op Monitoring | — |

---

## The critical sequence — human-in-the-loop (3 files, 10 min)

This is the part that matters most. Three files demonstrate that a
high-risk action was blocked, a human supervisor reviewed and narrowed
the policy, and the action was re-authorized under the amended plan:

    004-appeal-blocked.json   in_policy: false, output: null
    plan-002.json             narrower scope, parent_plan_id → plan-001
    005-appeal-approved.json  in_policy: true, new plan_id, new policy_hash

Cross-references your team checks:

    plan-001.id == receipt-004.plan_id       blocked under original
    plan-001.id == plan-002.parent_plan_id   amendment traces back
    plan-002.id == receipt-005.plan_id       re-approved under amendment
    plan-002.scope ⊆ plan-001.scope          narrowed, not widened

Maps to: SOC 2 CC6.1 (authorization), CC7.2 (anomaly detected and
escalated), ISO 42001 A.8.3 (human oversight), AIUC-1 D003.4.

---

## What we're asking

A call to walk through this together. Specifically:

1. **Does this format work as-is in your current SOC 2 / ISO 42001
   workpapers?** What would your team (Lyndie, Julian) need different
   to actually use it during fieldwork?

2. **What's missing?** We know we don't cover E015.2 (log storage),
   B001 (adversarial testing), or deployment-level controls. What
   else would you need from a client who handed you this?

3. **Would you use the WORKPAPER_TEMPLATE.md?** It's a draft. We'd
   rather build the real version with your team on a pilot engagement.

If the evidence holds up, the pilot is simple: on your next AI-heavy
client, we instrument one agent workflow, deliver a pre-filled evidence
pack + test procedure, your team runs it alongside their current method.
If it doesn't save review time, we stop.

Every company that integrates AgentMint produces this exact format and
will need an auditor who knows how to assess it. That pipeline flows to
whoever validates it first.

---

## What's not in here

- E015.2: Log storage config (S3, retention, access controls) — deployment-level
- B001: Adversarial testing evidence — separate control
- RFC 3161 timestamps: Available in production; this demo may or may not
  have them depending on FreeTSA availability at generation time
- Agent co-signing: Dual-key option exists but not in this demo
- Output data: `output_hash` commits to outputs without storing raw data;
  raw outputs stored separately by the client

---

*Built by Aniketh Maddipati · github.com/aniketh-maddipati/agentmint-python*
*Contributing to OWASP Agentic AI Security Initiative with Ken Huang*
*Robin Joseph (Uproot Security) and Danny Manimbo are mutual connections*
