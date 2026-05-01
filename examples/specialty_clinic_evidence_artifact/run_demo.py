#!/usr/bin/env python3
"""
AgentMint :: specialty-clinic admin agent evidence demo.

Generates an Ed25519 keypair, constructs a sample prior-authorization payload
(no PHI), produces a signed receipt referencing the payload only by SHA-256,
then verifies the receipt offline using openssl as a subprocess.
"""
from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

ROOT = Path(__file__).parent
KEYS = ROOT / "keys"
RECEIPTS = ROOT / "receipts"
SALT = "agentmint-demo-v1"

console = Console()


def header(n: int, title: str) -> None:
    console.print()
    console.rule(f"[bold cyan]Phase {n} :: {title}[/bold cyan]")


def ok(msg: str) -> None:
    console.print(f"  [green]\u2713[/green] {msg}")


def fail(msg: str) -> None:
    console.print(f"  [red]\u2717[/red] {msg}")


def canonical(obj: dict) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def hashed_subject_ref(raw_id: str) -> str:
    return sha256_hex((SALT + raw_id).encode("utf-8"))


def reset_dirs() -> None:
    for d in (KEYS, RECEIPTS):
        if d.exists():
            shutil.rmtree(d)
        d.mkdir()


def phase_1() -> Ed25519PrivateKey:
    header(1, "Generate Ed25519 keypair")
    reset_dirs()
    private = Ed25519PrivateKey.generate()
    public = private.public_key()

    (KEYS / "private.pem").write_bytes(
        private.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    (KEYS / "public.pem").write_bytes(
        public.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    ok("Wrote keys/private.pem and keys/public.pem")
    console.print(
        Panel(
            "Customer holds the key, vendor never sees it.\n"
            "In production, the private key lives on customer infrastructure;\n"
            "AgentMint signs with a per-engagement key the customer issues.",
            title="[bold]Trust model[/bold]",
            border_style="cyan",
        )
    )
    return private


def phase_2() -> str:
    header(2, "Construct payload :: hash with SHA-256")
    payload = {
        "action": "prior_authorization_submission",
        "payer": {"name": "EXAMPLE_PAYER", "npi": "0000000001"},
        "ordering_provider_npi": "1234567890",
        "subject_ref": hashed_subject_ref("DEMO-PATIENT-001"),
        "service": {
            "cpt": "99213",
            "icd10": "Z00.00",
            "date_of_service": "2026-05-15",
        },
        "submitted_at": datetime.now(timezone.utc).isoformat(),
        "human_in_the_loop": {"reviewer_role": "front_desk", "approved": True},
    }
    canon = canonical(payload)
    digest = sha256_hex(canon)
    (RECEIPTS / "00001.json.payload").write_bytes(canon)
    ok(f"Action: {payload['action']}")
    ok(f"Subject ref (hashed, no PHI): {payload['subject_ref'][:16]}...")
    ok(f"Payload SHA-256: {digest[:16]}...")
    console.print(
        Panel(
            "Receipt will reference this payload by SHA-256 only.\n"
            "No PHI is written to the receipt itself.",
            title="[bold]No PHI on the wire[/bold]",
            border_style="cyan",
        )
    )
    return digest


def phase_3(private: Ed25519PrivateKey, payload_digest: str) -> None:
    header(3, "Build receipt :: sign with Ed25519")
    receipt = {
        "receipt_id": "00001",
        "version": "1.0",
        "action": "prior_authorization_submission",
        "agent_id": "specialty-clinic-pa-agent-v1",
        "subject_ref": hashed_subject_ref("DEMO-PATIENT-001"),
        "payload_sha256": payload_digest,
        "previous_receipt_hash": "GENESIS",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "signature_alg": "ed25519",
        "public_key_id": "agentmint_demo_pub_v1",
    }
    canon_receipt = canonical(receipt)
    signature = private.sign(canon_receipt)
    (RECEIPTS / "00001.json").write_bytes(canon_receipt)
    (RECEIPTS / "00001.json.sig").write_bytes(signature)
    ok("Wrote receipts/00001.json (canonical bytes)")
    ok("Wrote receipts/00001.json.sig (raw 64-byte Ed25519 signature)")
    ok("Wrote receipts/00001.json.payload (canonical payload bytes)")
    console.print(
        Panel(
            json.dumps(receipt, indent=2),
            title="[bold]Receipt -- no PHI, only a hash[/bold]",
            border_style="cyan",
        )
    )


def phase_4() -> None:
    header(4, "Verify offline with openssl")
    cmd = [
        "openssl", "pkeyutl", "-verify",
        "-pubin", "-inkey", "keys/public.pem",
        "-rawin", "-in", "receipts/00001.json",
        "-sigfile", "receipts/00001.json.sig",
    ]
    console.print(f"[dim]$ {' '.join(cmd)}[/dim]")
    try:
        result = subprocess.run(cmd, cwd=str(ROOT), capture_output=True, text=True, timeout=10)
    except FileNotFoundError:
        fail("openssl not found on PATH")
        sys.exit(1)
    if result.returncode == 0:
        out = (result.stdout + result.stderr).strip() or "Signature Verified Successfully"
        ok(out)
        ok("Receipt verifies offline. No AgentMint binary required.")
    else:
        fail(f"openssl returned {result.returncode}")
        console.print(result.stdout)
        console.print(result.stderr)
        sys.exit(2)


def control_table() -> None:
    table = Table(title="Control mappings (summary)", show_lines=False)
    table.add_column("Framework", style="cyan", no_wrap=True)
    table.add_column("Citation", style="bold")
    table.add_column("What this receipt provides")
    table.add_row("HIPAA", "\u00a7164.312(b)", "Audit controls -- per-action signed record (deployment)")
    table.add_row("HIPAA", "\u00a7164.312(c)(1)", "Integrity -- tamper detection via signature")
    table.add_row("HIPAA", "\u00a7164.312(d)", "Authentication -- action signed by customer-held key")
    table.add_row("HITRUST", "09.aa", "Audit logging primitive (deployment wraps via decorator)")
    table.add_row("HITRUST", "09.ac", "Log protection -- customer-held key prevents edits")
    table.add_row("HITRUST", "09.ad", "Admin/operator logs use same primitive (deployment)")
    table.add_row("HITRUST", "06.i", "Offline auditor verification with openssl alone")
    console.print()
    console.print(table)
    console.print("[dim]Full mappings: controls.md[/dim]")


def main() -> None:
    console.print(
        Panel(
            Text(
                "AgentMint :: specialty-clinic admin agent evidence demo",
                style="bold",
                justify="center",
            ),
            border_style="cyan",
        )
    )
    private = phase_1()
    digest = phase_2()
    phase_3(private, digest)
    phase_4()
    control_table()
    console.print()
    console.print("[bold green]Receipt verified end-to-end.[/bold green]")


if __name__ == "__main__":
    main()
