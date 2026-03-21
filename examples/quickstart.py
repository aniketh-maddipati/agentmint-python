#!/usr/bin/env python3
"""
AgentMint Quickstart — See the full receipt lifecycle in your terminal.

No API keys required. Real Ed25519 signatures. Real RFC 3161 timestamps.
Optional: set ANTHROPIC_API_KEY and/or ELEVENLABS_API_KEY for live API calls.

Run:
    pip install -e .
    python examples/quickstart.py
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import tempfile
import time
import zipfile
from pathlib import Path

from agentmint.notary import Notary, NotaryError

# ── ANSI helpers (no external deps) ────────────────────────

NO_COLOR = os.environ.get("NO_COLOR", "") != ""


class C:
    """ANSI color codes. Respects NO_COLOR standard."""
    G = "" if NO_COLOR else "\033[92m"   # green
    R = "" if NO_COLOR else "\033[91m"   # red
    Y = "" if NO_COLOR else "\033[93m"   # yellow
    B = "" if NO_COLOR else "\033[94m"   # blue
    M = "" if NO_COLOR else "\033[95m"   # magenta
    CN = "" if NO_COLOR else "\033[96m"  # cyan
    W = "" if NO_COLOR else "\033[97m"   # white/bright
    D = "" if NO_COLOR else "\033[2m"    # dim
    BD = "" if NO_COLOR else "\033[1m"   # bold
    X = "" if NO_COLOR else "\033[0m"    # reset
    UL = "" if NO_COLOR else "\033[4m"   # underline


def banner(text: str) -> None:
    w = 58
    print(f"\n  {C.CN}{'━' * w}{C.X}")
    print(f"  {C.BD}{C.W}{text.center(w)}{C.X}")
    print(f"  {C.CN}{'━' * w}{C.X}\n")


def step(num: int, title: str) -> None:
    print(f"\n  {C.CN}{C.BD}[{num}]{C.X} {C.W}{C.BD}{title}{C.X}\n")


def label(key: str, val: str, indent: int = 6) -> None:
    pad = " " * indent
    print(f"{pad}{C.D}{key}:{C.X} {val}")


def ok(msg: str) -> None:
    print(f"      {C.G}✓{C.X} {msg}")


def fail(msg: str) -> None:
    print(f"      {C.R}✗{C.X} {msg}")


def warn(msg: str) -> None:
    print(f"      {C.Y}!{C.X} {msg}")


def dim(msg: str) -> None:
    print(f"      {C.D}{msg}{C.X}")


def link(name: str, url: str) -> None:
    # OSC 8 hyperlink — works in most modern terminals
    if NO_COLOR:
        print(f"      {name}: {url}")
    else:
        print(f"      {name}: \033]8;;{url}\033\\{C.UL}{C.B}{url}{C.X}\033]8;;\033\\")


def box(lines: list[str], color: str = C.D, title: str = "") -> None:
    """Draw a box around lines of text."""
    max_w = max(len(line.replace("\033[92m", "").replace("\033[91m", "").replace("\033[93m", "")
                       .replace("\033[94m", "").replace("\033[95m", "").replace("\033[96m", "")
                       .replace("\033[97m", "").replace("\033[2m", "").replace("\033[1m", "")
                       .replace("\033[0m", "").replace("\033[4m", ""))
                 for line in lines) if lines else 40
    w = max(max_w + 2, 50)
    # Strip ANSI from title for width calculation
    title_clean = title
    for code in ["\033[92m", "\033[91m", "\033[93m", "\033[94m", "\033[95m",
                 "\033[96m", "\033[97m", "\033[2m", "\033[1m", "\033[0m", "\033[4m"]:
        title_clean = title_clean.replace(code, "")
    t = f" {title} " if title else ""
    t_clean = f" {title_clean} " if title_clean else ""
    left = (w - len(t_clean)) // 2
    right = w - len(t_clean) - left
    print(f"      {color}┌{'─' * left}{t}{'─' * right}┐{C.X}")
    for line in lines:
        # Calculate visible length (strip ANSI)
        visible = line
        for code in ["\033[92m", "\033[91m", "\033[93m", "\033[94m", "\033[95m",
                     "\033[96m", "\033[97m", "\033[2m", "\033[1m", "\033[0m", "\033[4m"]:
            visible = visible.replace(code, "")
        pad = w - len(visible)
        print(f"      {color}│{C.X} {line}{' ' * max(0, pad - 1)}{color}│{C.X}")
    print(f"      {color}└{'─' * w}┘{C.X}")


def json_block(data: dict, annotations: dict[str, str] | None = None, indent: int = 6) -> None:
    """Print JSON with optional inline annotations."""
    pad = " " * indent
    raw = json.dumps(data, indent=2, sort_keys=False)
    for line in raw.split("\n"):
        note = ""
        if annotations:
            for key, comment in annotations.items():
                if f'"{key}"' in line:
                    note = f"  {C.D}← {comment}{C.X}"
                    break
        print(f"{pad}{C.CN}{line}{C.X}{note}")


def spinner_line(msg: str) -> None:
    """Print a status line that can be overwritten."""
    sys.stdout.write(f"      {C.Y}⧗{C.X} {msg}...")
    sys.stdout.flush()


def spinner_done(msg: str) -> None:
    """Overwrite spinner with done message."""
    sys.stdout.write(f"\r      {C.G}✓{C.X} {msg}              \n")
    sys.stdout.flush()


def pause(s: float = 0.3) -> None:
    time.sleep(s)


# ── Main ───────────────────────────────────────────────────

def main() -> None:
    banner("AgentMint Quickstart")

    # ── Detect API keys ────────────────────────────────────
    anthropic_key = os.environ.get("ANTHROPIC_API_KEY")
    elevenlabs_key = os.environ.get("ELEVENLABS_API_KEY")
    has_live = bool(anthropic_key or elevenlabs_key)

    if has_live:
        apis = []
        if anthropic_key:
            apis.append(f"{C.G}Anthropic{C.X}")
        if elevenlabs_key:
            apis.append(f"{C.G}ElevenLabs{C.X}")
        print(f"      API keys detected: {', '.join(apis)}")
        if not anthropic_key:
            dim("No ANTHROPIC_API_KEY — will simulate read action")
        if not elevenlabs_key:
            dim("No ELEVENLABS_API_KEY — will simulate violation action")
    else:
        print(f"      Running with {C.W}simulated actions{C.X}.")
        print(f"      Receipts are real: Ed25519 signed, RFC 3161 timestamped.\n")
        print(f"      Want live API calls? Set environment variables:")
        link("Anthropic", "https://console.anthropic.com/settings/keys")
        link("ElevenLabs", "https://elevenlabs.io/app/settings/api-keys")

    pause(0.4)

    # ══════════════════════════════════════════════════════════
    step(1, "Create a Scoped Plan")
    # ══════════════════════════════════════════════════════════

    dim("A human or policy engine defines what the agent is allowed to do.\n")

    notary = Notary()

    plan = notary.create_plan(
        user="security-team@example.com",
        action="agent-operations",
        scope=["read:reports:*", "tts:standard:*"],
        checkpoints=["read:secrets:*", "tts:clone:*"],
        delegates_to=["demo-agent"],
        ttl_seconds=600,
    )

    box([
        f"{C.W}Plan {plan.id[:8]}{C.X}",
        f"",
        f"{C.D}Authorized by:{C.X}  {C.W}security-team@example.com{C.X}",
        f"{C.D}Delegates to:{C.X}   {C.CN}demo-agent{C.X}",
        f"{C.D}TTL:{C.X}             600 seconds",
        f"",
        f"{C.G}✓ allow{C.X}  read:reports:*     {C.D}(any report){C.X}",
        f"{C.G}✓ allow{C.X}  tts:standard:*     {C.D}(standard TTS){C.X}",
        f"{C.Y}⚠ block{C.X}  read:secrets:*     {C.D}(needs human approval){C.X}",
        f"{C.Y}⚠ block{C.X}  tts:clone:*        {C.D}(needs human approval){C.X}",
        f"",
        f"{C.D}Signature: {plan.signature[:40]}...{C.X}",
    ], color=C.CN, title=f"{C.CN} PLAN {C.X}")

    ok("Plan signed with Ed25519")
    pause(0.5)

    # ══════════════════════════════════════════════════════════
    step(2, "Action 1 — In-Policy Read")
    # ══════════════════════════════════════════════════════════

    action_1 = "read:reports:quarterly"
    evidence_1: dict = {}
    live_1 = False

    print(f"      {C.D}Pre-action — what the agent wants to do:{C.X}\n")
    box([
        f"{C.D}agent:{C.X}    {C.CN}demo-agent{C.X}",
        f"{C.D}action:{C.X}   {C.CN}{action_1}{C.X}",
        f"{C.D}scope:{C.X}    read:reports:*  →  {C.G}MATCH{C.X}",
    ], color=C.B, title=f"{C.B} REQUEST {C.X}")

    pause(0.3)

    # Execute (real or simulated)
    if anthropic_key:
        try:
            from anthropic import Anthropic

            spinner_line("Calling Claude API")
            client = Anthropic()
            t0 = time.time()
            response = client.messages.create(
                model="claude-sonnet-4-20250514",
                max_tokens=100,
                messages=[{"role": "user", "content": "Summarize in one sentence: Q4 revenue was $4.2M, up 15% YoY, driven by enterprise expansion."}],
            )
            elapsed = time.time() - t0
            summary = response.content[0].text
            spinner_done(f"Claude responded ({elapsed:.1f}s)")

            evidence_1 = {
                "source": "anthropic",
                "model": "claude-sonnet-4-20250514",
                "action": "summarize quarterly report",
                "tokens_in": response.usage.input_tokens,
                "tokens_out": response.usage.output_tokens,
                "result_preview": summary[:120],
            }
            live_1 = True
        except Exception as e:
            warn(f"Anthropic call failed: {e}")
            dim("Falling back to simulated action")
            anthropic_key = None

    if not live_1:
        evidence_1 = {
            "source": "simulated",
            "method": "GET",
            "resource": "/api/reports/quarterly",
            "status_code": 200,
            "bytes_returned": 4096,
            "content_type": "application/json",
        }

    print(f"\n      {C.D}Post-action — what happened:{C.X}\n")
    box([
        *[f"{C.D}{k}:{C.X}  {C.W}{v}{C.X}" for k, v in evidence_1.items()],
    ], color=C.G, title=f"{C.G} RESULT {C.X}")

    pause(0.3)

    # Sign the receipt
    print(f"\n      {C.D}Signing receipt...{C.X}\n")

    evidence_bytes = json.dumps(evidence_1, sort_keys=True, separators=(",", ":")).encode()
    evidence_hash = hashlib.sha512(evidence_bytes).hexdigest()

    dim(f"1. Evidence → SHA-512 → {evidence_hash[:40]}...")

    ts_enabled = True
    spinner_line("2. Requesting RFC 3161 timestamp from FreeTSA")
    t0 = time.time()

    try:
        receipt_1 = notary.notarise(
            action=action_1,
            agent="demo-agent",
            plan=plan,
            evidence=evidence_1,
            enable_timestamp=True,
        )
        elapsed = time.time() - t0
        spinner_done(f"2. Timestamp received from FreeTSA ({elapsed:.1f}s)")
    except NotaryError:
        ts_enabled = False
        receipt_1 = notary.notarise(
            action=action_1,
            agent="demo-agent",
            plan=plan,
            evidence=evidence_1,
            enable_timestamp=False,
        )
        elapsed = time.time() - t0
        warn(f"2. FreeTSA unreachable — signed without timestamp ({elapsed:.1f}s)")

    ok(f"3. Ed25519 signature: {receipt_1.signature[:40]}...")
    dim(f"4. Chain hash: None (first receipt in chain)")

    pause(0.3)

    # Show the receipt
    print(f"\n      {C.BD}{C.G}Receipt 1 — IN POLICY{C.X}\n")
    json_block(receipt_1.to_dict(), annotations={
        "plan_id": "links to the human-approved plan above",
        "agent": "who acted",
        "action": "what they did",
        "in_policy": "was it authorized? YES",
        "policy_reason": "which scope pattern matched",
        "evidence_hash_sha512": "SHA-512 of evidence — tamper detection",
        "signature": "Ed25519 — covers every field above",
        "tsa_url": "independent third-party time authority",
        "previous_receipt_hash": "chain link (first in chain)",
    })

    pause(0.5)

    # ══════════════════════════════════════════════════════════
    step(3, "Action 2 — Policy Violation")
    # ══════════════════════════════════════════════════════════

    action_2 = "tts:clone:ceo_voice" if elevenlabs_key else "read:secrets:credentials"
    evidence_2: dict = {}
    checkpoint_pattern = "tts:clone:*" if elevenlabs_key else "read:secrets:*"

    print(f"      {C.D}Pre-action — agent attempts a checkpointed action:{C.X}\n")
    box([
        f"{C.D}agent:{C.X}    {C.CN}demo-agent{C.X}",
        f"{C.D}action:{C.X}   {C.R}{action_2}{C.X}",
        f"{C.D}scope:{C.X}    {checkpoint_pattern}  →  {C.R}CHECKPOINT{C.X}",
        f"",
        f"{C.Y}Requires human approval — not granted{C.X}",
    ], color=C.R, title=f"{C.R} BLOCKED {C.X}")

    pause(0.3)

    if elevenlabs_key:
        evidence_2 = {
            "source": "elevenlabs",
            "attempted_action": "voice_clone",
            "voice_id": "ceo_voice_001",
            "result": "blocked_by_checkpoint",
            "reason": "voice cloning requires human re-approval",
        }
    else:
        evidence_2 = {
            "source": "simulated",
            "method": "GET",
            "resource": "/api/secrets/credentials",
            "result": "blocked_by_checkpoint",
            "reason": "secrets access requires human re-approval",
        }

    print(f"\n      {C.D}Violation recorded as evidence:{C.X}\n")
    box([
        *[f"{C.D}{k}:{C.X}  {C.W}{v}{C.X}" for k, v in evidence_2.items()],
    ], color=C.R, title=f"{C.R} VIOLATION EVIDENCE {C.X}")

    pause(0.3)

    print(f"\n      {C.D}Signing violation receipt...{C.X}\n")
    spinner_line("Requesting RFC 3161 timestamp from FreeTSA")
    t0 = time.time()

    try:
        receipt_2 = notary.notarise(
            action=action_2,
            agent="demo-agent",
            plan=plan,
            evidence=evidence_2,
            enable_timestamp=ts_enabled,
        )
        elapsed = time.time() - t0
        if ts_enabled:
            spinner_done(f"Timestamp received ({elapsed:.1f}s)")
        else:
            spinner_done(f"Signed without timestamp ({elapsed:.1f}s)")
    except NotaryError:
        receipt_2 = notary.notarise(
            action=action_2,
            agent="demo-agent",
            plan=plan,
            evidence=evidence_2,
            enable_timestamp=False,
        )
        elapsed = time.time() - t0
        warn(f"FreeTSA unreachable ({elapsed:.1f}s)")

    ok(f"Ed25519 signature: {receipt_2.signature[:40]}...")
    if receipt_2.previous_receipt_hash:
        ok(f"Chain hash: {receipt_2.previous_receipt_hash[:40]}...")
        dim("↑ SHA-256 of Receipt 1 — delete or reorder any receipt, chain breaks")

    print(f"\n      {C.BD}{C.R}Receipt 2 — VIOLATION{C.X}\n")
    json_block(receipt_2.to_dict(), annotations={
        "in_policy": "was it authorized? NO",
        "policy_reason": "which checkpoint pattern matched",
        "previous_receipt_hash": "SHA-256 of receipt 1 — chain intact",
        "signature": "Ed25519 — violations are signed too",
    })

    pause(0.5)

    # ══════════════════════════════════════════════════════════
    step(4, "Export Evidence Package")
    # ══════════════════════════════════════════════════════════

    output_dir = Path("./evidence_output")
    try:
        zip_path = notary.export_evidence(output_dir)
    except NotaryError as e:
        fail(f"Export failed: {e}")
        sys.exit(1)

    ok(f"Exported: {C.W}{zip_path}{C.X}\n")

    with zipfile.ZipFile(zip_path) as zf:
        names = sorted(zf.namelist())
        purpose_map = {
            "plan.json": "the human-approved plan",
            "receipt_index.json": "table of contents — start here",
            "public_key.pem": "Ed25519 public key for independent verification",
            "VERIFY.sh": "verify timestamps (pure OpenSSL)",
            "verify_sigs.py": "verify Ed25519 signatures (pynacl)",
            "freetsa_cacert.pem": "FreeTSA root CA certificate",
            "freetsa_tsa.crt": "FreeTSA TSA certificate",
        }
        file_lines = []
        for name in names:
            size = zf.getinfo(name).file_size
            purpose = purpose_map.get(name, "")
            if name.startswith("receipts/") and name.endswith(".json"):
                purpose = "signed receipt"
            elif name.startswith("receipts/") and name.endswith(".tsr"):
                purpose = "RFC 3161 timestamp token"
            elif name.startswith("receipts/") and name.endswith(".tsq"):
                purpose = "timestamp query"
            file_lines.append(f"{C.CN}{name:<50}{C.X}  {C.D}{purpose}{C.X}")

        box(file_lines, color=C.CN, title=f"{C.CN} EVIDENCE ZIP {C.X}")

    pause(0.5)

    # ══════════════════════════════════════════════════════════
    step(5, "Verify — No AgentMint Software Needed")
    # ══════════════════════════════════════════════════════════

    dim("An auditor receives the zip. They extract it and run two commands.")
    dim("No AgentMint installation. No account. No network connection needed.\n")

    # Extract to temp dir for verification
    verify_dir = Path(tempfile.mkdtemp(prefix="agentmint_verify_"))
    with zipfile.ZipFile(zip_path) as zf:
        zf.extractall(verify_dir)
    verify_sh = verify_dir / "VERIFY.sh"
    if verify_sh.exists():
        verify_sh.chmod(0o755)

    # Run VERIFY.sh (timestamps)
    print(f"      {C.W}$ bash VERIFY.sh{C.X}\n")
    try:
        result = subprocess.run(
            ["bash", str(verify_sh)],
            capture_output=True,
            text=True,
            timeout=30,
            cwd=str(verify_dir),
        )
        for line in result.stdout.strip().split("\n"):
            stripped = line.strip()
            if not stripped:
                continue
            if "✓" in stripped:
                print(f"        {C.G}{stripped}{C.X}")
            elif "✗" in stripped or "FAILED" in stripped:
                print(f"        {C.R}{stripped}{C.X}")
            elif "═" in stripped:
                print(f"        {C.W}{stripped}{C.X}")
            elif "⚠" in stripped or "FLAGGED" in stripped:
                print(f"        {C.Y}{stripped}{C.X}")
            elif "──" in stripped:
                print(f"        {C.D}{stripped}{C.X}")
            else:
                print(f"        {stripped}")

        print()
        if result.returncode == 0:
            ok(f"All timestamps verified with OpenSSL")
        else:
            fail("Some timestamps failed verification")
    except FileNotFoundError:
        warn("OpenSSL not found — skipping timestamp verification")
        dim("Install OpenSSL to verify: brew install openssl (macOS) / apt install openssl (Linux)")
    except subprocess.TimeoutExpired:
        warn("Verification timed out")

    print()

    # Run verify_sigs.py (signatures)
    verify_sigs = verify_dir / "verify_sigs.py"
    if verify_sigs.exists():
        print(f"      {C.W}$ python3 verify_sigs.py{C.X}\n")
        try:
            result = subprocess.run(
                [sys.executable, str(verify_sigs)],
                capture_output=True,
                text=True,
                timeout=10,
                cwd=str(verify_dir),
            )
            for line in result.stdout.strip().split("\n"):
                stripped = line.strip()
                if not stripped:
                    continue
                if "✓" in stripped:
                    print(f"        {C.G}{stripped}{C.X}")
                elif "✗" in stripped or "FAILED" in stripped:
                    print(f"        {C.R}{stripped}{C.X}")
                else:
                    print(f"        {stripped}")

            print()
            if result.returncode == 0:
                ok("All signatures verified with pynacl")
            else:
                fail("Some signatures failed verification")
        except Exception as e:
            warn(f"Signature verification error: {e}")

    # Cleanup temp dir
    import shutil
    shutil.rmtree(verify_dir, ignore_errors=True)

    pause(0.3)

    # ══════════════════════════════════════════════════════════
    step(6, "Summary")
    # ══════════════════════════════════════════════════════════

    in_count = sum(1 for r in [receipt_1, receipt_2] if r.in_policy)
    out_count = 2 - in_count
    ts_count = sum(1 for r in [receipt_1, receipt_2] if r.timestamp_result)

    box([
        f"",
        f"  {C.W}Receipts:{C.X}      2 total  {C.G}{in_count} in-policy{C.X}  {C.R}{out_count} violation{C.X}",
        f"  {C.W}Signatures:{C.X}    Ed25519 (private key never left this machine)",
        f"  {C.W}Timestamps:{C.X}    {ts_count} via FreeTSA (independent third party)",
        f"  {C.W}Chain:{C.X}         Receipt 2 → SHA-256(Receipt 1)",
        f"",
        f"  {C.W}Evidence:{C.X}      {zip_path}",
        f"  {C.W}Verify:{C.X}        unzip *.zip && bash VERIFY.sh",
        f"",
        f"  {C.D}No AgentMint software needed to verify.{C.X}",
        f"  {C.D}Just OpenSSL + Python.{C.X}",
        f"",
    ], color=C.CN, title=f"{C.CN} RESULTS {C.X}")

    # ══════════════════════════════════════════════════════════

    print(f"\n  {C.CN}{'━' * 58}{C.X}")
    print(f"\n      {C.W}{C.BD}Want receipts for YOUR agent?{C.X}\n")
    print(f"      You bring the agent. I instrument it, map your actions")
    print(f"      to receipts, and hand you an evidence package your")
    print(f"      buyer's security team can verify independently.\n")
    link("Book 15 min", "https://calendar.app.google/pT1Sz8EUtqowWABi8")
    link("Email", "mailto:anikethcov@gmail.com")
    link("GitHub", "https://github.com/aniketh-maddipati/agentmint-python")
    print(f"\n  {C.CN}{'━' * 58}{C.X}\n")


if __name__ == "__main__":
    main()