"""Generate sample evidence with real Ed25519 signatures and RFC 3161 timestamps."""

import shutil
import zipfile
from pathlib import Path

from agentmint.notary import Notary, NotaryError

SAMPLE_DIR = Path(__file__).parent / "sample_evidence"

DIM = "\033[2m"
RST = "\033[0m"
GRN = "\033[92m"
RED = "\033[91m"
CYN = "\033[96m"
YLW = "\033[93m"
BLD = "\033[1m"

CONTENT_COMMITMENT = {
    "hash_algorithm": "SHA-512",
    "content_excluded": True,
    "verification": "hash original data with SHA-512, compare to evidence_hash_sha512",
}

ACTIONS = [
    {
        "action": "read:reports:quarterly",
        "evidence": {
            "request": {
                "method": "GET",
                "resource": "/api/reports/quarterly",
                "intent": "read quarterly financial report",
            },
            "response": {
                "outcome": "success",
                "status_code": 200,
                "bytes": 4096,
                "content_type": "application/json",
            },
            "delegation": {
                "delegated_by": "security-team@example.com",
                "delegation_depth": 1,
                "scope_pattern_evaluated": "read:reports:*",
                "scope_verdict": "match",
            },
            "compliance": {
                "controls_exercised": {
                    "AIUC-1:E015": "agent action logged with signature and timestamp",
                    "AIUC-1:D003": "tool call evaluated against scope restriction",
                },
                "eu_ai_act": "Article 12(2)(c) — monitoring of AI system operation",
                "iso_42001": "Clause 9 — performance evaluation evidence",
            },
            "content_commitment": CONTENT_COMMITMENT,
        },
        "label": "in policy",
    },
    {
        "action": "read:reports:summary",
        "evidence": {
            "request": {
                "method": "GET",
                "resource": "/api/reports/summary",
                "intent": "read report summary",
            },
            "response": {
                "outcome": "success",
                "status_code": 200,
                "bytes": 2048,
                "content_type": "application/json",
            },
            "delegation": {
                "delegated_by": "security-team@example.com",
                "delegation_depth": 1,
                "scope_pattern_evaluated": "read:reports:*",
                "scope_verdict": "match",
            },
            "compliance": {
                "controls_exercised": {
                    "AIUC-1:E015": "agent action logged with signature and timestamp",
                    "AIUC-1:D003": "tool call evaluated against scope restriction",
                },
                "eu_ai_act": "Article 12(2)(c) — monitoring of AI system operation",
                "iso_42001": "Clause 9 — performance evaluation evidence",
            },
            "content_commitment": CONTENT_COMMITMENT,
        },
        "label": "in policy",
    },
    {
        "action": "delete:reports:quarterly",
        "evidence": {
            "request": {
                "method": "DELETE",
                "resource": "/api/reports/quarterly",
                "intent": "delete quarterly report",
            },
            "response": {
                "outcome": "blocked",
                "reason": "checkpoint_requires_human_approval",
            },
            "delegation": {
                "delegated_by": "security-team@example.com",
                "delegation_depth": 1,
                "checkpoint_pattern_matched": "delete:*",
                "scope_verdict": "checkpoint",
                "escalation_required": True,
            },
            "compliance": {
                "controls_exercised": {
                    "AIUC-1:E015": "agent action logged with signature and timestamp",
                    "AIUC-1:D003": "unauthorized tool call blocked before execution",
                    "AIUC-1:E010": "acceptable use policy enforced — checkpoint violation",
                    "AIUC-1:B001": "adversarial robustness — scope boundary tested",
                },
                "eu_ai_act": "Article 12(2)(a) — risk situation identified and recorded",
                "iso_42001": "Clause 8 — AI risk treatment evidence",
            },
            "content_commitment": CONTENT_COMMITMENT,
        },
        "label": "violation (checkpoint)",
    },
    {
        "action": "read:secrets:credentials",
        "evidence": {
            "request": {
                "method": "GET",
                "resource": "/api/secrets/credentials",
                "intent": "read credentials",
            },
            "response": {
                "outcome": "blocked",
                "reason": "action_not_in_scope",
            },
            "delegation": {
                "delegated_by": "security-team@example.com",
                "delegation_depth": 1,
                "scope_pattern_evaluated": "read:reports:*",
                "scope_verdict": "miss",
            },
            "compliance": {
                "controls_exercised": {
                    "AIUC-1:E015": "agent action logged with signature and timestamp",
                    "AIUC-1:D003": "unauthorized tool call blocked before execution",
                },
                "eu_ai_act": "Article 12(2)(a) — risk situation identified and recorded",
                "iso_42001": "Clause 8 — AI risk treatment evidence",
            },
            "content_commitment": CONTENT_COMMITMENT,
        },
        "label": "violation (out of scope)",
    },
]


def main() -> None:
    print(f"\n{BLD}Generating sample evidence...{RST}\n")

    notary = Notary()
    plan = notary.create_plan(
        user="security-team@example.com",
        action="demo",
        scope=["read:reports:*"],
        checkpoints=["delete:*"],
        delegates_to=["demo-agent"],
        ttl_seconds=3600,
    )

    print(f"  {DIM}Plan:{RST} {plan.user} \u2192 demo-agent")
    print(f"  {DIM}Scope:{RST} {', '.join(plan.scope)}")
    print(f"  {DIM}Checkpoints:{RST} {', '.join(plan.checkpoints)}")
    print(f"  {DIM}Signature:{RST} {plan.signature[:32]}...\n")

    in_count = 0
    out_count = 0
    ts_count = 0
    timestamps_ok = True

    for entry in ACTIONS:
        try:
            receipt = notary.notarise(
                action=entry["action"],
                agent="demo-agent",
                plan=plan,
                evidence=entry["evidence"],
                enable_timestamp=True,
            )
            ts_count += 1
        except NotaryError:
            timestamps_ok = False
            receipt = notary.notarise(
                action=entry["action"],
                agent="demo-agent",
                plan=plan,
                evidence=entry["evidence"],
                enable_timestamp=False,
            )

        if receipt.in_policy:
            print(f"  {GRN}\u2713{RST} {entry['action']:<30s} {DIM}\u2014 {entry['label']}{RST}")
            in_count += 1
        else:
            print(f"  {RED}\u2717{RST} {entry['action']:<30s} {DIM}\u2014 {entry['label']}{RST}")
            out_count += 1

    if not timestamps_ok:
        print(f"\n  {YLW}\u26a0 FreeTSA unreachable \u2014 receipts signed without timestamps{RST}")

    # Export zip to temp, then unzip into sample_evidence/
    tmp_dir = SAMPLE_DIR.parent / ".sample_evidence_tmp"
    tmp_dir.mkdir(parents=True, exist_ok=True)

    try:
        zip_path = notary.export_evidence(tmp_dir)

        # Preserve README.md before cleaning
        readme_content = None
        if SAMPLE_DIR.exists():
            readme = SAMPLE_DIR / "README.md"
            if readme.exists():
                readme_content = readme.read_text()
            shutil.rmtree(SAMPLE_DIR)

        SAMPLE_DIR.mkdir(parents=True, exist_ok=True)

        with zipfile.ZipFile(zip_path) as zf:
            zf.extractall(SAMPLE_DIR)

        if readme_content is not None:
            (SAMPLE_DIR / "README.md").write_text(readme_content)

        # Ensure VERIFY.sh is executable (zipfile.extractall doesn't preserve this)
        verify_sh = SAMPLE_DIR / "VERIFY.sh"
        if verify_sh.exists():
            verify_sh.chmod(0o755)
    finally:
        if tmp_dir.exists():
            shutil.rmtree(tmp_dir)

    total = in_count + out_count
    rel = SAMPLE_DIR.relative_to(Path(__file__).parent.parent)
    print(f"\n{BLD}Exported to {rel}/{RST}")
    print(f"  {total} receipts | {GRN}{in_count} in-policy{RST} | {RED}{out_count} violations{RST}")
    if ts_count:
        print(f"  {CYN}{ts_count} RFC 3161 timestamps{RST} from FreeTSA")
    print(f"\n  {DIM}Verify:{RST} cd {rel} && bash VERIFY.sh\n")


if __name__ == "__main__":
    main()
