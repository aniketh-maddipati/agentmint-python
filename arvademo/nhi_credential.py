"""
NHI Credential for AML Screening Agent.

Production: OIDC client credentials flow -> SPIFFE/SVID workload attestation.
This file: static reference for demo. Same structure, same fields, same semantics.
The plan scope is always a strict subset of scope_grants.
"""

from __future__ import annotations

import hashlib
import json


# -- Credential ---------------------------------------------------------------

NHI_CREDENTIAL: dict = {
    "credential_type": "static_jwt_reference",
    "issuer": "https://idp.demo-bank.com",
    "subject": "aml-screening-agent-v3@agents.demo-bank.com",
    "owner": "compliance-ops@demo-bank.com",
    "client_id": "agt_aml_screening_prod_4k7z",
    "scope_grants": [
        "comply_advantage:alerts:read",
        "comply_advantage:alerts:update:status",
        "entity:web_presence:read",
        "entity:adverse_media:read",
        "entity:incorporation_docs:read",
        "entity:ownership_structure:read",
        "ofac:sdnlist:read:via_integration",
        "internal:customer:read:own_alerts",
        "internal:case_management:write:recommendation",
        "internal:audit_log:write",
    ],
    "excluded_by_credential": [
        "fincen:314b:read",
        "fincen:sar:read",
        "ofac:sdnlist:read:direct",
        "internal:customer:read:cross_customer",
        "internal:customer:read:full_transaction_history",
        "comply_advantage:alerts:close:autonomous",
        "internal:case_management:write:disposition:final",
        "internal:employee:read",
        "swift:messages:read",
        "correspondent_bank:accounts:read",
    ],
    "regulatory_context": {
        "ofac_compliance": True,
        "bsa_aml": True,
        "fincen_314b_excluded": True,
        "human_in_loop_required_for_disposition": True,
    },
    "upgrade_path": "OIDC client credentials -> SPIFFE/SVID workload attestation",
}


# -- Plan configuration -------------------------------------------------------

PLAN_SCOPE: list[str] = list(NHI_CREDENTIAL["scope_grants"])

PLAN_CHECKPOINTS: list[str] = [
    "comply_advantage:alerts:update:status",
    "internal:case_management:write:recommendation",
]

PLAN_RATE_LIMITS: dict[str, str] = {
    "comply_advantage:alerts:read": "20/60s",
    "entity:web_presence:read": "15/60s",
    "ofac:sdnlist:read:via_integration": "5/60s",
}

SUBAGENT_SCOPE: list[str] = [
    "entity:web_presence:read",
    "entity:adverse_media:read",
    "entity:incorporation_docs:read",
    "entity:ownership_structure:read",
]

AGENT_NAME = "aml-screening-agent-v3"


# -- Credential hash ----------------------------------------------------------

def get_credential_hash() -> str:
    """SHA-256 of canonical credential JSON. Deterministic, portable."""
    canonical = json.dumps(NHI_CREDENTIAL, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()
