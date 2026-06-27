"""RevocationEnvelope — minimal signed evidence for verifier-independent revocation.

Minimum schema per paper-a-plan.md §3.1:
  { target_id, target_type, revoked_at, issuer_key_id, signature }

No transparency log, no M-of-N — those belong to Paper B.
Signature covers canonical JSON of all fields except signature itself.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from typing import Literal

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .crypto import KeyPair, sign, verify

TargetType = Literal["deployer", "chain", "edge", "segment"]


@dataclass(frozen=True)
class RevocationEnvelope:
    target_id: str
    target_type: TargetType
    revoked_at: float     # Unix timestamp (seconds)
    epoch_id: str
    issuer_key_id: str
    signature: str        # Ed25519 hex; empty string before signing

    def _signable_bytes(self) -> bytes:
        payload = {
            "target_id": self.target_id,
            "target_type": self.target_type,
            "revoked_at": self.revoked_at,
            "epoch_id": self.epoch_id,
            "issuer_key_id": self.issuer_key_id,
        }
        return json.dumps(payload, sort_keys=True).encode()


def create_envelope(
    target_id: str,
    target_type: TargetType,
    keypair: KeyPair,
    *,
    revoked_at: float | None = None,
    epoch_id: str = "epoch-0",
) -> RevocationEnvelope:
    ts = revoked_at if revoked_at is not None else time.time()
    unsigned = RevocationEnvelope(
        target_id=target_id,
        target_type=target_type,
        revoked_at=ts,
        epoch_id=epoch_id,
        issuer_key_id=keypair.key_id,
        signature="",
    )
    sig = sign(keypair.private, unsigned._signable_bytes())
    return RevocationEnvelope(
        target_id=target_id,
        target_type=target_type,
        revoked_at=ts,
        epoch_id=epoch_id,
        issuer_key_id=keypair.key_id,
        signature=sig,
    )


def verify_envelope(envelope: RevocationEnvelope, public_key: Ed25519PublicKey) -> bool:
    """Return True iff the envelope's signature is valid under public_key."""
    check = RevocationEnvelope(
        target_id=envelope.target_id,
        target_type=envelope.target_type,
        revoked_at=envelope.revoked_at,
        epoch_id=envelope.epoch_id,
        issuer_key_id=envelope.issuer_key_id,
        signature="",
    )
    return verify(public_key, check._signable_bytes(), envelope.signature)
