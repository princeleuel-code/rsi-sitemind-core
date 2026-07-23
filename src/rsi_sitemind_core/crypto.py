from __future__ import annotations

import base64
from dataclasses import dataclass, field
from typing import Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .canonical import canonical_bytes


@dataclass(frozen=True)
class Ed25519Keypair:
    key_id: str
    _private: Ed25519PrivateKey = field(repr=False)

    @classmethod
    def generate(cls, key_id: str) -> "Ed25519Keypair":
        if not key_id.strip():
            raise ValueError("key_id is required")
        return cls(key_id=key_id, _private=Ed25519PrivateKey.generate())

    def sign(self, payload: object) -> str:
        return base64.b64encode(self._private.sign(canonical_bytes(payload))).decode("ascii")

    def public_bytes_b64(self) -> str:
        raw = self._private.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        return base64.b64encode(raw).decode("ascii")


class PublicKeyRegistry:
    def __init__(self, keys: Mapping[str, str] | None = None):
        self._keys: dict[str, Ed25519PublicKey] = {}
        for key_id, raw_b64 in (keys or {}).items():
            self.add(key_id, raw_b64)

    def add(self, key_id: str, raw_b64: str) -> None:
        raw = base64.b64decode(raw_b64, validate=True)
        self._keys[key_id] = Ed25519PublicKey.from_public_bytes(raw)

    def verify(self, key_id: str, payload: object, signature_b64: str) -> bool:
        key = self._keys.get(key_id)
        if key is None:
            return False
        try:
            signature = base64.b64decode(signature_b64, validate=True)
            key.verify(signature, canonical_bytes(payload))
            return True
        except (InvalidSignature, ValueError, TypeError):
            return False
