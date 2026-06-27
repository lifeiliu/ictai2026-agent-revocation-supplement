"""Shared helpers for E16 framework trace replay."""

from __future__ import annotations

import hashlib
import json
import sys
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from revocation.crypto import KeyPair, sha256_hex  # noqa: E402

EXP_DIR = Path(__file__).resolve().parent
TRACE_DIR = EXP_DIR / "traces"
RAW_TRACE_PATH = TRACE_DIR / "langgraph_raw.jsonl"
NORMALIZED_TRACE_PATH = TRACE_DIR / "normalized_events.jsonl"
PUBLIC_KEYS_PATH = TRACE_DIR / "public_keys.json"
RESULTS_PATH = EXP_DIR / "e16_results.json"
EPOCH_ID = "e16-framework-replay"

DEFAULT_PERMISSION = {
    "tenant": "tenant-a",
    "resource": "documents",
    "action": "read",
    "constraints": [],
}


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def stable_hash(value: Any) -> str:
    return sha256_hex(canonical_bytes(value))


def deterministic_keypair(label: str) -> KeyPair:
    """Return a reproducible Ed25519 keypair for artifact replay.

    These are experiment keys, not secrets. Deterministic keys keep signatures
    reproducible across anonymous artifact rebuilds.
    """

    seed = hashlib.sha256(f"signed-edge-revocation:e16:{label}".encode()).digest()
    private = Ed25519PrivateKey.from_private_bytes(seed)
    public = private.public_key()
    public_bytes = public.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return KeyPair(private=private, public=public, key_id=sha256_hex(public_bytes)[:16])


def edge_identifier(parent: str, child: str, permission: dict[str, Any]) -> str:
    return stable_hash(
        {
            "epoch_id": EPOCH_ID,
            "parent": parent,
            "child": child,
            "permission": permission,
        }
    )[:24]


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    rows = []
    with path.open() as handle:
        for line in handle:
            stripped = line.strip()
            if stripped:
                rows.append(json.loads(stripped))
    return rows


def write_jsonl(path: Path, rows: Iterable[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w") as handle:
        for row in rows:
            handle.write(json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n")


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")

