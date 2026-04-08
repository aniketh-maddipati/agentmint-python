# WALKTHROUGH — Speaker Notes for Bil Meeting
# Read this once. Don't bring it to the meeting.

## SETUP (before he arrives)
- Terminal open, dark background, LARGE font (he's reading from across a table)
- demo_for_bil.py in project root, tested, runs clean
- Have run it once already so demo-evidence/ exists
- Clean the demo-evidence/ dir right before: `rm -rf demo-evidence/`

## OPENING LINE
"Last time I showed you the evidence package. Since then I shipped
the full pipeline. One command, start to finish."

Run:  `python3 demo_for_bil.py`

Don't touch the keyboard until it finishes (~10 seconds).

---

## ACT 1: DISCOVERY — what to say

HE SEES: The agentmint init report. 9 tools from the OpenAI CS demo.
Headline box: "7 of 9 tools are not production-ready." Per-tool exposure
with incident references. Enforcement preview table.

SAY:
"This is agentmint init. Point it at any Python agent codebase — it
finds every tool, classifies the risk, shows you what's missing.
This is OpenAI's official customer service demo. 9 tools. 7 dangerous.
Zero controls."

[Let him read the headline box. Don't rush.]

"Those incidents are real. Kiro deleted production — no scope limits.
LiteLLM got 500K machines through a supply chain attack in tool outputs.
Claude Code burned $400 with no rate limit."

WHY HE CARES: First thing a CISO asks is "what do we have?" This
answers it in 10 seconds for any agent codebase.

---

## ACT 2: ENFORCE — what to say

HE SEES: 5 scenarios. Each shows the pipeline steps with ✓ or ✗.
1 allowed, 4 blocked. 5 signed receipts.

### Scenario 1 (clean booking — ALLOWED)
"Normal flight booking. Everything passes. Receipt signed."

### Scenario 2 (supply chain — BLOCKED) ← THE MONEY SHOT
"Now watch this one. The tool is authorized. Inputs are clean.
Agent calls get_flight_status — comes back with flight data.
But look at the output. AWS credentials. A compromised dependency
is exfiltrating secrets in the API response.

This is exactly what hit LiteLLM three weeks ago. Mercor, Meta, Cisco
all affected. Every other framework — LangChain, CrewAI, OpenAI's own
SDK — passes that output straight to the LLM. The LLM now has AWS keys
in its context window.

AgentMint scans the output. Blocks it. Signs a receipt proving it blocked
it and why. The dangerous data never reaches the LLM."

### Scenario 3 (scope — BLOCKED)
"Agent tries to issue a refund. Not in its scope. Blocked before execution."

### Scenario 4 (injection — BLOCKED)
"Customer sends a malicious message. LLM puts it in the email body.
Input scan catches the injection pattern."

### Scenario 5 (secret leak — BLOCKED)
"LLM hallucinates and includes AWS credentials in an email. Blocked."

---

## ACT 3: EVIDENCE — what to say

HE SEES: Signature verification on every receipt. Chain verification.
Evidence hash spot-check. OTVP cross-reference. Evidence export.

SAY:
"Every one of those decisions — the allow AND the four blocks —
is Ed25519 signed and SHA-256 hash-chained. I just verified every
signature and the chain integrity inline.

Look at the OTVP cross-reference. That assessment hash in the receipt —
that's from your evidence package. Same hash. Every receipt carries it.

An auditor opens the zip, runs bash VERIFY.sh, and confirms timestamps
with openssl. Runs verify_sigs.py and confirms signatures with pynacl.
No vendor software. No account. No trust required."

---

## ACT 4: BRIDGE — what to say

HE SEES: Side-by-side table (AgentMint vs OTVP). Same crypto.
Three-layer stack diagram. NHI framing with Oasis.

SAY:
"Same signing algorithm. Same hash chain model. Same verification
tools. Same zero vendor lock-in. Different layer.

OTVP answers: is this infrastructure trustworthy?
AgentMint answers: did this agent act within policy?
The assessment hash in the receipt is the bridge between them."

[Then the NHI positioning:]

"You've seen what Craft did with Oasis — $120M for NHI access governance.
Oasis answers 'what systems can this agent reach?'
AgentMint answers 'what did this agent actually do with that access?'

Oasis grants it. AgentMint proves what happened. OTVP verifies the
infrastructure underneath. Three layers, same crypto model."

---

## ACT 5: CLOSE — what to say

HE SEES: Production-readiness table for all 9 tools. Summary list.
"pip install agentmint → agentmint init . → ship with receipts"

SAY:
"That's the full pipeline. Discovery, enforcement, evidence, verification.
One pip install. Runs offline. No API keys. Every decision signed."

---

## THE ASK

Pause. Let him process. Then:

"If you were deploying agents tomorrow and your board asked how you
govern them, would you use this?"

[Let him answer. Then:]

"Who in your network is in that situation right now?"

THAT'S THE ASK. One warm intro to a CISO deploying agents.

If he offers more, the second ask:
"Oasis governs access, AgentMint governs actions. Would you
connect me to Danny Brickman? The integration story is obvious."

---

## LANDMINES TO AVOID
- Don't say "we're competing with Onyx/Oasis" — you're complementary
- Don't ask for investment — ask for an intro
- Don't demo enforce_demo.py separately — demo_for_bil.py covers it
- Don't explain the code — explain what the output proves
- If he asks about ML/PromptGuard tier — "regex is the floor, ML is
  the paid tier, same pipeline, same receipts"
- If he asks about MCP — "agentmint init already detects MCP tools,
  same enforcement pipeline"
