"""
RFC 3161 trusted timestamping via FreeTSA.org.

Produces independently verifiable timestamp tokens proving that
a piece of data existed at a specific point in time. Used by the
AgentMint notary to anchor signed evidence receipts to wall-clock
time without requiring trust in AgentMint itself.

The timestamp authority (FreeTSA.org) is an independent third party.
Anyone can verify the resulting tokens with a single OpenSSL command:

    openssl ts -verify \\
        -in receipt.tsr \\
        -queryfile receipt.tsq \\
        -CAfile freetsa_cacert.pem \\
        -untrusted freetsa_tsa.crt

No AgentMint software, account, or API key is needed to verify.

References:
    RFC 3161 — Internet X.509 PKI Time-Stamp Protocol
    https://tools.ietf.org/html/rfc3161

    FreeTSA — Free Trusted Timestamping Authority
    https://freetsa.org
"""

from __future__ import annotations

import hashlib
import struct
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Final

import requests

__all__ = [
    "TimestampError",
    "TimestampResult",
    "timestamp",
    "fetch_ca_certs",
    "verify",
]


# ── Configuration ──────────────────────────────────────────

FREETSA_TSR_URL: Final[str] = "https://freetsa.org/tsr"
FREETSA_CACERT_URL: Final[str] = "https://freetsa.org/files/cacert.pem"
FREETSA_TSA_CERT_URL: Final[str] = "https://freetsa.org/files/tsa.crt"

HTTP_TIMEOUT_SECONDS: Final[int] = 30
MAX_RETRIES: Final[int] = 3
RETRY_BACKOFF_SECONDS: Final[float] = 1.0
MAX_DATA_BYTES: Final[int] = 10 * 1024 * 1024  # 10 MB
MIN_TSR_BYTES: Final[int] = 64  # sanity check on TSA response


# ── Errors ─────────────────────────────────────────────────

class TimestampError(Exception):
    """Raised when any part of the timestamping process fails.

    The message always includes what went wrong and what to try next.
    """
    pass


# ── Result ─────────────────────────────────────────────────

@dataclass(frozen=True)
class TimestampResult:
    """Immutable result of an RFC 3161 timestamp operation.

    Attributes:
        tsq: Raw DER-encoded timestamp query (request sent to TSA).
        tsr: Raw DER-encoded timestamp response (token from TSA).
        digest_hex: Hex-encoded SHA-512 digest of the original data.
        tsa_url: URL of the timestamp authority that issued the token.
    """
    tsq: bytes
    tsr: bytes
    digest_hex: str
    tsa_url: str

    def save(self, directory: Path, prefix: str = "receipt") -> tuple[Path, Path]:
        """Write TSQ and TSR files to disk for independent verification.

        Args:
            directory: Target directory (created if it does not exist).
            prefix: Filename prefix. Produces {prefix}.tsq and {prefix}.tsr.

        Returns:
            Tuple of (tsq_path, tsr_path).
        """
        directory.mkdir(parents=True, exist_ok=True)
        tsq_path = directory / f"{prefix}.tsq"
        tsr_path = directory / f"{prefix}.tsr"
        tsq_path.write_bytes(self.tsq)
        tsr_path.write_bytes(self.tsr)
        return tsq_path, tsr_path


# ── Public API ─────────────────────────────────────────────

def timestamp(data: bytes, url: str | None = None) -> TimestampResult:
    """Timestamp arbitrary data via FreeTSA.

    Builds an RFC 3161 timestamp query from a SHA-512 digest of the
    input data, submits it to FreeTSA, and returns both the query
    and response tokens for independent verification.

    AgentMint never needs to be running for verification. The TSQ and
    TSR files plus the FreeTSA CA certificates are fully self-contained.

    Args:
        data: Bytes to timestamp (typically a JSON-serialized signed receipt).
              Must be non-empty and under 10 MB.

    Returns:
        TimestampResult containing TSQ bytes, TSR bytes, digest, and TSA URL.

    Raises:
        TimestampError: If input is invalid, TSQ construction fails,
            or the TSA is unreachable after retries.
    """
    _validate_data(data)

    digest = hashlib.sha512(data).digest()
    digest_hex = digest.hex()

    tsa_url = url or FREETSA_TSR_URL
    tsq = _build_tsq(digest)
    tsr = _submit_tsq_with_retry(tsq, tsa_url=tsa_url)

    return TimestampResult(
        tsq=tsq,
        tsr=tsr,
        digest_hex=digest_hex,
        tsa_url=tsa_url,
    )


def fetch_ca_certs(directory: Path) -> tuple[Path, Path]:
    """Download FreeTSA CA certificates for offline verification.

    Downloads once, then serves from cache. Both files are needed
    for the OpenSSL verification command.

    Args:
        directory: Where to store the certificates.

    Returns:
        Tuple of (cacert_path, tsa_cert_path).

    Raises:
        TimestampError: If either certificate cannot be downloaded.
    """
    directory.mkdir(parents=True, exist_ok=True)

    cacert_path = directory / "freetsa_cacert.pem"
    tsa_cert_path = directory / "freetsa_tsa.crt"

    _download_if_missing(cacert_path, FREETSA_CACERT_URL, "CA certificate")
    _download_if_missing(tsa_cert_path, FREETSA_TSA_CERT_URL, "TSA certificate")

    return cacert_path, tsa_cert_path


def verify(
    tsq_path: Path,
    tsr_path: Path,
    cacert_path: Path,
    tsa_cert_path: Path,
) -> tuple[bool, str]:
    """Verify a timestamp token using the OpenSSL CLI.

    This function exists as a convenience for demos. Its real purpose
    is to show that anyone can run this exact command independently,
    without any AgentMint software installed.

    The equivalent manual command is:
        openssl ts -verify -in {tsr} -queryfile {tsq} \\
            -CAfile {cacert} -untrusted {tsa_cert}

    Args:
        tsq_path: Path to the .tsq file (timestamp query).
        tsr_path: Path to the .tsr file (timestamp response).
        cacert_path: Path to the FreeTSA CA certificate.
        tsa_cert_path: Path to the FreeTSA TSA certificate.

    Returns:
        Tuple of (success: bool, output: str).

    Raises:
        TimestampError: If any input file is missing or OpenSSL is
            not available on the system.
    """
    for path, label in [
        (tsq_path, "timestamp query (.tsq)"),
        (tsr_path, "timestamp response (.tsr)"),
        (cacert_path, "CA certificate"),
        (tsa_cert_path, "TSA certificate"),
    ]:
        if not path.exists():
            raise TimestampError(
                f"missing {label}: {path}\n"
                f"  Ensure you have saved the timestamp result and fetched CA certs."
            )

    try:
        result = subprocess.run(
            [
                "openssl", "ts", "-verify",
                "-in", str(tsr_path),
                "-queryfile", str(tsq_path),
                "-CAfile", str(cacert_path),
                "-untrusted", str(tsa_cert_path),
            ],
            capture_output=True,
            text=True,
            timeout=10,
        )
    except FileNotFoundError:
        raise TimestampError(
            "openssl not found on PATH\n"
            "  Install OpenSSL to verify timestamps independently."
        )
    except subprocess.TimeoutExpired:
        raise TimestampError("openssl verification timed out after 10 seconds")

    output = (result.stdout.strip() + " " + result.stderr.strip()).strip()
    success = "Verification: OK" in output
    return success, output


# ── Input validation ───────────────────────────────────────

def _validate_data(data: bytes) -> None:
    """Validate input data before timestamping."""
    if not isinstance(data, bytes):
        raise TimestampError(
            f"data must be bytes, got {type(data).__name__}\n"
            f"  If you have a string, encode it: data.encode('utf-8')"
        )
    if len(data) == 0:
        raise TimestampError("data must not be empty — nothing to timestamp")
    if len(data) > MAX_DATA_BYTES:
        raise TimestampError(
            f"data is {len(data):,} bytes, maximum is {MAX_DATA_BYTES:,}\n"
            f"  Timestamp a hash of the data instead of the data itself."
        )


# ── HTTP helpers ───────────────────────────────────────────

def _submit_tsq_with_retry(tsq: bytes, tsa_url: str = FREETSA_TSR_URL) -> bytes:
    """Submit a timestamp query to FreeTSA with retry on transient failures."""
    last_error = None

    for attempt in range(1, MAX_RETRIES + 1):
        try:
            return _submit_tsq(tsq, tsa_url=tsa_url)
        except TimestampError:
            raise
        except requests.exceptions.ConnectionError as e:
            last_error = e
            if attempt < MAX_RETRIES:
                time.sleep(RETRY_BACKOFF_SECONDS * attempt)
        except requests.exceptions.Timeout as e:
            last_error = e
            if attempt < MAX_RETRIES:
                time.sleep(RETRY_BACKOFF_SECONDS * attempt)

    raise TimestampError(
        f"FreeTSA unreachable after {MAX_RETRIES} attempts\n"
        f"  Last error: {last_error}\n"
        f"  Check your internet connection or try again later."
    )


def _submit_tsq(tsq: bytes, tsa_url: str = FREETSA_TSR_URL) -> bytes:
    """Submit a single timestamp query to FreeTSA."""
    resp = requests.post(
        tsa_url,
        data=tsq,
        headers={"Content-Type": "application/timestamp-query"},
        timeout=HTTP_TIMEOUT_SECONDS,
    )

    if resp.status_code == 403:
        raise TimestampError(
            "FreeTSA returned 403 Forbidden\n"
            "  This usually means the timestamp query is malformed."
        )

    resp.raise_for_status()

    if len(resp.content) < MIN_TSR_BYTES:
        raise TimestampError(
            f"FreeTSA returned only {len(resp.content)} bytes (expected >= {MIN_TSR_BYTES})\n"
            f"  The response may be an error page, not a timestamp token."
        )

    return resp.content


def _download_if_missing(path: Path, url: str, label: str) -> None:
    """Download a file if it doesn't already exist on disk."""
    if path.exists():
        return
    try:
        resp = requests.get(url, timeout=HTTP_TIMEOUT_SECONDS)
        resp.raise_for_status()
        path.write_bytes(resp.content)
    except Exception as e:
        raise TimestampError(
            f"failed to download {label} from {url}\n"
            f"  Error: {e}\n"
            f"  You can download it manually: curl -o {path} {url}"
        )


# ── ASN.1 DER encoding (RFC 3161 §2.4.1) ─────────────────
#
# A TimeStampReq is a small ASN.1 structure. We build it by hand
# rather than pulling in a large ASN.1 library. The structure is:
#
#   TimeStampReq ::= SEQUENCE {
#       version          INTEGER              -- always 1
#       messageImprint   MessageImprint       -- hash of our data
#       certReq          BOOLEAN              -- TRUE (include cert in response)
#   }
#
#   MessageImprint ::= SEQUENCE {
#       hashAlgorithm    AlgorithmIdentifier  -- SHA-512
#       hashedMessage    OCTET STRING         -- the 64-byte digest
#   }
#
#   AlgorithmIdentifier ::= SEQUENCE {
#       algorithm        OBJECT IDENTIFIER    -- 2.16.840.1.101.3.4.2.3 (SHA-512)
#       parameters       NULL
#   }
#
# In DER bytes, the full encoded request is approximately 100 bytes.
#

# OID 2.16.840.1.101.3.4.2.3 = SHA-512
_SHA512_OID: Final[bytes] = b"\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x03"
_ASN1_NULL: Final[bytes] = b"\x05\x00"


def _der_length(length: int) -> bytes:
    """Encode a length value in DER format.

    DER uses a compact variable-length encoding:
        0-127:    single byte
        128-255:  0x81 + one byte
        256+:     0x82 + two bytes (big-endian)
    """
    if length < 0:
        raise ValueError(f"DER length cannot be negative: {length}")
    if length < 0x80:
        return struct.pack("B", length)
    if length < 0x100:
        return b"\x81" + struct.pack("B", length)
    if length < 0x10000:
        return b"\x82" + struct.pack(">H", length)
    raise ValueError(f"DER length too large for timestamp query: {length}")


def _der_tag(tag: int, contents: bytes) -> bytes:
    """Wrap contents with a DER tag and length."""
    return struct.pack("B", tag) + _der_length(len(contents)) + contents


def _der_sequence(contents: bytes) -> bytes:
    """DER SEQUENCE (tag 0x30)."""
    return _der_tag(0x30, contents)


def _der_integer(value: int) -> bytes:
    """DER INTEGER for small non-negative values."""
    if value < 0 or value > 0xFFFF:
        raise ValueError(f"integer out of range for timestamp query: {value}")
    if value < 0x80:
        return b"\x02\x01" + struct.pack("B", value)
    if value < 0x100:
        return b"\x02\x02\x00" + struct.pack("B", value)
    return b"\x02\x03\x00" + struct.pack(">H", value)


def _der_octet_string(data: bytes) -> bytes:
    """DER OCTET STRING (tag 0x04)."""
    return _der_tag(0x04, data)


def _der_boolean_true() -> bytes:
    """DER BOOLEAN TRUE."""
    return b"\x01\x01\xff"


def _build_tsq(digest: bytes) -> bytes:
    """Build an RFC 3161 TimeStampReq from a SHA-512 digest.

    Args:
        digest: Exactly 64 bytes (SHA-512 output).

    Returns:
        DER-encoded TimeStampReq ready to send to a TSA.

    Raises:
        TimestampError: If the digest is not exactly 64 bytes.
    """
    if len(digest) != 64:
        raise TimestampError(
            f"SHA-512 digest must be exactly 64 bytes, got {len(digest)}\n"
            f"  Use hashlib.sha512(data).digest() to produce the correct input."
        )

    algorithm_id = _der_sequence(_SHA512_OID + _ASN1_NULL)
    message_imprint = _der_sequence(algorithm_id + _der_octet_string(digest))
    version = _der_integer(1)
    cert_req = _der_boolean_true()

    return _der_sequence(version + message_imprint + cert_req)
