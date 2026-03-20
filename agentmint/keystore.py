"""Ed25519 key persistence — generate on first run, load thereafter."""

from __future__ import annotations
import base64
import os
from pathlib import Path
from nacl.signing import SigningKey, VerifyKey


DEFAULT_KEY_DIR = Path(".agentmint")
PRIVATE_KEY_FILE = "signing_key.bin"
PUBLIC_KEY_FILE = "public_key.pem"

# Ed25519 SPKI prefix (RFC 8410): 302a300506032b6570032100
_SPKI_PREFIX = bytes.fromhex("302a300506032b6570032100")


def pem_wrap(raw_public_key: bytes, label: str = "PUBLIC KEY") -> str:
    """Wrap a raw Ed25519 public key in SPKI PEM format (RFC 8410).

    The result is directly usable with:
        openssl pkeyutl -verify -pubin -inkey public_key.pem ...

    Args:
        raw_public_key: 32-byte Ed25519 public key.
        label: PEM label (default: PUBLIC KEY).

    Returns:
        PEM-encoded string.
    """
    der = _SPKI_PREFIX + raw_public_key
    b64 = base64.b64encode(der).decode()
    lines = [b64[i:i + 64] for i in range(0, len(b64), 64)]
    return f"-----BEGIN {label}-----\n" + "\n".join(lines) + f"\n-----END {label}-----\n"


class KeyStore:
    """Load or generate an Ed25519 keypair with disk persistence."""

    def __init__(self, key_dir: str | Path | None = None):
        self._dir = Path(key_dir) if key_dir else DEFAULT_KEY_DIR
        self._sk: SigningKey
        self._vk: VerifyKey
        self._load_or_generate()

    def _load_or_generate(self) -> None:
        sk_path = self._dir / PRIVATE_KEY_FILE
        pk_path = self._dir / PUBLIC_KEY_FILE

        if sk_path.exists():
            raw = sk_path.read_bytes()
            self._sk = SigningKey(raw)
            self._vk = self._sk.verify_key
        else:
            self._sk = SigningKey.generate()
            self._vk = self._sk.verify_key
            self._dir.mkdir(parents=True, exist_ok=True)
            # Write private key — owner-only permissions
            sk_path.write_bytes(bytes(self._sk))
            os.chmod(sk_path, 0o600)
            # Write PEM public key for OpenSSL verification
            pk_path.write_text(pem_wrap(bytes(self._vk)))
            os.chmod(pk_path, 0o644)

    @property
    def signing_key(self) -> SigningKey:
        return self._sk

    @property
    def verify_key(self) -> VerifyKey:
        return self._vk

    @property
    def public_key_pem(self) -> str:
        """PEM-encoded public key string (SPKI format, RFC 8410)."""
        return pem_wrap(bytes(self._vk))

    @property
    def public_key_pem_path(self) -> Path:
        return self._dir / PUBLIC_KEY_FILE

    @property
    def key_dir(self) -> Path:
        return self._dir
