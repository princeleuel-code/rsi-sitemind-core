from __future__ import annotations

import dataclasses
from dataclasses import replace

from .canonical import sha256_hex
from .crypto import Ed25519Keypair, PublicKeyRegistry
from .models import ExecutionReceipt


class ReceiptLedger:
    """Tenant/site-scoped append-only receipt chain.

    External anchoring is still required to detect a full rewrite by a compromised signer.
    `checkpoint()` returns a hash suitable for an independent transparency log or KMS-backed anchor.
    """

    def __init__(self, signer: Ed25519Keypair, keys: PublicKeyRegistry):
        self.signer = signer
        self.keys = keys
        self._receipts: list[ExecutionReceipt] = []
        self._used_idempotency: set[str] = set()

    @property
    def used_idempotency_keys(self) -> set[str]:
        return set(self._used_idempotency)

    def append(self, receipt: ExecutionReceipt) -> ExecutionReceipt:
        if not receipt.idempotency_key.strip():
            raise ValueError("idempotency key required")
        if receipt.idempotency_key in self._used_idempotency:
            raise ValueError("idempotency replay")
        previous = self._receipts[-1].receipt_hash if self._receipts else "GENESIS"
        candidate = replace(receipt, previous_receipt_hash=previous, key_id=self.signer.key_id, signature="", receipt_hash="")
        digest = sha256_hex(candidate.unsigned_payload())
        candidate = replace(candidate, receipt_hash=digest)
        signature = self.signer.sign(candidate.unsigned_payload())
        signed = replace(candidate, signature=signature)
        self._receipts.append(signed)
        self._used_idempotency.add(signed.idempotency_key)
        return signed

    def checkpoint(self) -> str:
        return sha256_hex([r.unsigned_payload() | {"signature": r.signature} for r in self._receipts])

    def verify(self, *, expected_checkpoint: str | None = None) -> tuple[bool, tuple[str, ...]]:
        errors: list[str] = []
        previous = "GENESIS"
        seen: set[str] = set()
        scope = None
        for index, receipt in enumerate(self._receipts):
            if receipt.idempotency_key in seen:
                errors.append(f"duplicate_idempotency:{index}")
            seen.add(receipt.idempotency_key)
            current_scope = (receipt.tenant_id, receipt.business_id, receipt.site_id)
            if scope is None:
                scope = current_scope
            elif scope != current_scope:
                errors.append(f"cross_scope_receipt:{index}")
            if receipt.previous_receipt_hash != previous:
                errors.append(f"chain_break:{index}")
            unsigned_without_hash = receipt.unsigned_payload().copy()
            unsigned_without_hash["receipt_hash"] = ""
            expected_hash = sha256_hex(unsigned_without_hash)
            if receipt.receipt_hash != expected_hash:
                errors.append(f"receipt_hash_invalid:{index}")
            if not self.keys.verify(receipt.key_id, receipt.unsigned_payload(), receipt.signature):
                errors.append(f"signature_invalid:{index}")
            previous = receipt.receipt_hash
        if expected_checkpoint is not None and self.checkpoint() != expected_checkpoint:
            errors.append("checkpoint_mismatch")
        return (not errors, tuple(errors))

    def snapshot(self) -> tuple[ExecutionReceipt, ...]:
        return tuple(self._receipts)
