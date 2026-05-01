# Control mappings

## HIPAA Security Rule

| Citation | Control Name | What AgentMint Provides |
|---|---|---|
| §164.312(b) | Audit Controls | Each agent action emits a signed receipt persisted to a customer-controlled store, producing the immutable audit record the rule requires. |
| §164.312(c)(1) | Integrity | Ed25519 signature over the canonical receipt detects any post-hoc alteration of the action record. |
| §164.312(d) | Person or Entity Authentication | The receipt cryptographically binds the action to a named agent identity verifiable against a customer-held public key. |
| §164.316(b)(2)(i) | Time Limit | Receipts are append-only and retained on customer infrastructure for as long as the customer requires; AgentMint does not delete or expire them. |

## HITRUST CSF v11

| Control ID | Control Name | What AgentMint Provides |
|---|---|---|
| 09.aa | Audit Logging | Tool call to signed receipt is the logging primitive; coverage is one decorator wide and applies uniformly across agent frameworks. |
| 09.ac | Protection of Log Information | Signature plus customer-held private key make tampering cryptographically detectable and prevent unilateral vendor edits. |
| 09.ad | Administrator and Operator Logs | Privileged service-account actions sign with the same primitive as user-facing actions; no separate log channel to bypass. |
| 06.i | Information System Audit Considerations | Auditors verify receipts offline using openssl alone, with no dependency on AgentMint or the vendor running the agent. |

Mappings shown above are the controls most directly relevant to AI agent action evidence. Full HITRUST CSF v11 mapping available on request.
