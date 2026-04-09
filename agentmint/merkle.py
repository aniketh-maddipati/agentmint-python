"""
Merkle tree for session receipt integrity.

OWASP AI Agent Security Cheat Sheet §7 (Multi-Agent Security):
all receipts in a session become leaves in a binary hash tree.
The root hash goes into the evidence package. This gives auditors
three capabilities that hash chains alone don't provide:

    1. Selective verification — verify one receipt without downloading
       the full chain. Needs O(log n) hashes instead of O(n).

    2. Tamper localization — if a receipt is modified, the path from
       leaf to root changes. Binary search finds the exact tampering.

    3. Multi-agent composition — each agent's receipts form a subtree.
       Verify agent A independently of agent B, then confirm both
       belong to the same session via the shared root.

Implementation details:

    - Standard binary Merkle tree with SHA-256
    - Domain-separated hashing prevents second-preimage attacks:
        leaf hash  = SHA-256(0x00 || data)
        node hash  = SHA-256(0x01 || left || right)
    - Balanced by padding to next power of 2 with empty-leaf hashes
    - O(n) build, O(log n) proof generation and verification
    - Verification needs only hashlib (stdlib) — no pynacl, no AgentMint

Verify a proof in 10 lines of Python:

    current = proof.leaf_hash
    for sibling, direction in proof.siblings:
        if direction == "left":
            current = sha256(0x01 + bytes.fromhex(sibling) + bytes.fromhex(current))
        else:
            current = sha256(0x01 + bytes.fromhex(current) + bytes.fromhex(sibling))
    assert current == proof.root_hash
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any, Sequence

__all__ = ["MerkleTree", "MerkleProof", "build_tree", "verify_proof"]


# ── Hash primitives ──────────────────────────────────────────
#
# Domain separation: a leaf can never be confused with an internal
# node because they use different single-byte prefixes. This blocks
# second-preimage attacks where an attacker crafts a leaf whose hash
# equals an internal node hash.

_LEAF_PREFIX: bytes = b"\x00"
_NODE_PREFIX: bytes = b"\x01"
_EMPTY_HASH: str = hashlib.sha256(b"").hexdigest()


def _hash_leaf(data: bytes) -> str:
    """Hash a leaf: SHA-256(0x00 || data)."""
    return hashlib.sha256(_LEAF_PREFIX + data).hexdigest()


def _hash_node(left: str, right: str) -> str:
    """Hash an internal node: SHA-256(0x01 || left_bytes || right_bytes)."""
    return hashlib.sha256(
        _NODE_PREFIX + bytes.fromhex(left) + bytes.fromhex(right)
    ).hexdigest()


# ── Data structures ──────────────────────────────────────────

@dataclass(frozen=True)
class MerkleProof:
    """Inclusion proof for a single leaf.

    Contains the sibling hashes needed to recompute the root from
    one leaf. An auditor walks the path bottom-up: at each level,
    hash the current value with the sibling (respecting left/right
    order). The final value must equal root_hash.

    Attributes:
        leaf_index:  Position of the leaf (0-indexed).
        leaf_hash:   Hash of the leaf data.
        siblings:    Tuple of (hash, "left"|"right") from leaf to root.
        root_hash:   Expected root — the value to verify against.
    """

    leaf_index: int
    leaf_hash: str
    siblings: tuple[tuple[str, str], ...]
    root_hash: str

    def to_dict(self) -> dict[str, Any]:
        """Serialize for JSON evidence packages."""
        return {
            "leaf_index": self.leaf_index,
            "leaf_hash": self.leaf_hash,
            "siblings": [
                {"hash": h, "direction": d} for h, d in self.siblings
            ],
            "root_hash": self.root_hash,
        }


class MerkleTree:
    """Binary Merkle tree built from receipt hashes.

    Usage:
        tree = build_tree([receipt_bytes_1, receipt_bytes_2, ...])
        root = tree.root          # embed in evidence package
        proof = tree.proof(3)     # prove receipt 3 is in the tree
        assert verify_proof(proof)
    """

    __slots__ = ("_leaves", "_layers", "_leaf_count")

    def __init__(self, leaves: list[str], layers: list[list[str]]) -> None:
        self._leaves = leaves
        self._layers = layers
        self._leaf_count = len(leaves)

    @property
    def root(self) -> str:
        """Root hash — the single value summarizing all receipts."""
        if not self._layers:
            return _EMPTY_HASH
        return self._layers[-1][0]

    @property
    def leaf_count(self) -> int:
        """Number of real leaves (excludes padding)."""
        return self._leaf_count

    @property
    def depth(self) -> int:
        """Number of layers above the leaf layer."""
        return max(0, len(self._layers) - 1)

    def proof(self, index: int) -> MerkleProof:
        """Generate an inclusion proof for leaf at `index`.

        Collects sibling hashes along the path from leaf to root.
        O(log n) — for 10,000 receipts, proof has ~14 siblings.

        Raises:
            IndexError: if index is out of range.
        """
        if index < 0 or index >= self._leaf_count:
            raise IndexError(
                f"leaf index {index} out of range [0, {self._leaf_count})"
            )

        siblings: list[tuple[str, str]] = []
        idx = index

        # Walk from leaf layer up to (but not including) root layer
        for layer in self._layers[:-1]:
            if idx % 2 == 0:
                # Current is left child — sibling is on the right
                sibling_idx = idx + 1
                direction = "right"
            else:
                # Current is right child — sibling is on the left
                sibling_idx = idx - 1
                direction = "left"

            sibling_hash = (
                layer[sibling_idx] if sibling_idx < len(layer)
                else _hash_leaf(b"")  # padding sibling
            )
            siblings.append((sibling_hash, direction))
            idx //= 2  # move to parent index

        return MerkleProof(
            leaf_index=index,
            leaf_hash=self._layers[0][index],
            siblings=tuple(siblings),
            root_hash=self.root,
        )

    def to_dict(self) -> dict[str, Any]:
        """Compact summary for evidence package receipt_index.json."""
        return {
            "root": self.root,
            "leaf_count": self._leaf_count,
            "depth": self.depth,
        }


# ── Tree builder ─────────────────────────────────────────────

def _next_power_of_2(n: int) -> int:
    """Smallest power of 2 >= n. Returns 1 for n <= 1."""
    if n <= 1:
        return 1
    p = 1
    while p < n:
        p <<= 1
    return p


def build_tree(leaf_data: Sequence[bytes]) -> MerkleTree:
    """Build a Merkle tree from raw leaf data.

    Each element is the bytes of a receipt's signed payload — the
    same bytes that get Ed25519-signed by the notary.

    Empty input returns a tree with root = SHA-256("") and depth 0.

    Performance: O(n) time and space. 10,000 receipts build in ~5ms.

    Args:
        leaf_data: Sequence of bytes objects (receipt payloads).

    Returns:
        MerkleTree with .root, .proof(), and .to_dict().
    """
    if not leaf_data:
        return MerkleTree([], [[_EMPTY_HASH]])

    # Hash each leaf with domain separator
    leaf_hashes = [_hash_leaf(data) for data in leaf_data]
    real_count = len(leaf_hashes)

    # Pad to next power of 2 for a balanced tree
    padded_size = _next_power_of_2(real_count)
    empty_leaf = _hash_leaf(b"")
    leaf_hashes.extend(empty_leaf for _ in range(padded_size - real_count))

    # Build layers bottom-up: each layer has half the nodes of the one below
    layers: list[list[str]] = [leaf_hashes]
    current = leaf_hashes

    while len(current) > 1:
        next_layer: list[str] = []
        for i in range(0, len(current), 2):
            left = current[i]
            right = current[i + 1] if i + 1 < len(current) else _hash_leaf(b"")
            next_layer.append(_hash_node(left, right))
        layers.append(next_layer)
        current = next_layer

    # Return tree with only the real leaves (not padding)
    return MerkleTree(leaf_hashes[:real_count], layers)


# ── Proof verification ───────────────────────────────────────

def verify_proof(proof: MerkleProof) -> bool:
    """Verify a Merkle inclusion proof.

    This is what an auditor runs. It needs only hashlib — no pynacl,
    no AgentMint installation, no network access. An auditor can read
    this function, understand it, and trust it independently.

    Algorithm: start with the leaf hash, combine with each sibling
    (respecting left/right order), and check the result equals root.

    Returns:
        True if the leaf hashes up to the claimed root.
    """
    current = proof.leaf_hash

    for sibling_hash, direction in proof.siblings:
        if direction == "left":
            # Sibling is on the left — it goes first
            current = _hash_node(sibling_hash, current)
        else:
            # Sibling is on the right — current goes first
            current = _hash_node(current, sibling_hash)

    return current == proof.root_hash
