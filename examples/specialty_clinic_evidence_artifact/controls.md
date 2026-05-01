# Control mappings

> **Scope.** This artifact directly demonstrates §164.312(c)(1) Integrity,
> §164.312(d) Authentication, HITRUST 09.ac Log Protection, and HITRUST
> 06.i Audit Considerations. The other controls are *enabled* by the
> primitive when deployed across an agent's tool calls, not proven by a
> single-receipt demo. Cells tagged *(deployment)* are the latter.

## HIPAA Security Rule

| Citation | Control Name | What this primitive enables |
|---|---|---|
| §164.312(b) | Audit Controls | *(deployment)* Every agent action emits a signed receipt persisted to a customer-controlled store; this artifact demonstrates the per-action primitive, not full system coverage. |
| §164.312(c)(1) | Integrity | Ed25519 signature over the canonical receipt detects any post-hoc alteration of the action record. |
| §164.312(d) | Person or Entity Authentication | Each receipt is signed by a customer-held key issued per agent; agent identity binding to that key is operational, not yet cryptographic. |

## HITRUST CSF v11

| Control ID | Control Name | What this primitive enables |
|---|---|---|
| 09.aa | Audit Logging | *(deployment)* Tool call to signed receipt is the logging primitive; production library wraps tool calls via decorator. This demo shows the primitive, not the wrapping. |
| 09.ac | Protection of Log Information | Signature plus customer-held private key make tampering cryptographically detectable and prevent unilateral vendor edits. |
| 09.ad | Administrator and Operator Logs | *(deployment)* The receipt primitive is identity-agnostic; admin and service-account actions sign through the same path as user-facing actions. |
| 06.i | Information System Audit Considerations | Auditors verify receipts offline using openssl alone, with no dependency on AgentMint or the vendor running the agent. |

Mappings shown above are the controls most directly relevant to AI agent action evidence. Retention (§164.316(b)(2)(i)) is a storage architecture decision and is not demonstrated by this artifact. Full deployment-scope mapping is in the main repo.
