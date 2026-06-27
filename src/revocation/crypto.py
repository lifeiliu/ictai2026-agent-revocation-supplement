"""Ed25519 cryptographic primitives for the signed revocation artifact."""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


@dataclass(frozen=True)
class KeyPair:
    private: Ed25519PrivateKey
    public: Ed25519PublicKey
    key_id: str

    @property
    def public_bytes(self) -> bytes:
        return self.public.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )


def generate_keypair() -> KeyPair:
    private = Ed25519PrivateKey.generate()
    public = private.public_key()
    pub_raw = public.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    kid = sha256_hex(pub_raw)[:16]
    return KeyPair(private=private, public=public, key_id=kid)


def sign(private: Ed25519PrivateKey, data: bytes) -> str:
    return private.sign(data).hex()


def verify(public: Ed25519PublicKey, data: bytes, signature_hex: str) -> bool:
    try:
        public.verify(bytes.fromhex(signature_hex), data)
        return True
    except (InvalidSignature, ValueError):
        return False
