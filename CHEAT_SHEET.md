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
