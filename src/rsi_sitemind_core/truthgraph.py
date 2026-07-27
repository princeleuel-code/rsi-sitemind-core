from __future__ import annotations

import datetime as dt
import enum
from dataclasses import dataclass, replace

from .canonical import sha256_hex
from .ledger import ReceiptLedger
from .models import ExecutionReceipt

UTC = dt.timezone.utc


def _parse_time(value: str) -> dt.datetime:
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    parsed = dt.datetime.fromisoformat(normalized)
    if parsed.tzinfo is None:
        raise ValueError("timezone-aware timestamp required")
    return parsed.astimezone(UTC)


class TruthState(str, enum.Enum):
    PLANNED = "PLANNED"
    ATTEMPTED = "ATTEMPTED"
    PARTIAL = "PARTIAL"
    COMPLETED_UNVERIFIED = "COMPLETED_UNVERIFIED"
    VERIFIED = "VERIFIED"
    FAILED = "FAILED"
    ROLLED_BACK = "ROLLED_BACK"
    SUPERSEDED = "SUPERSEDED"


@dataclass(frozen=True)
class TruthNode:
    node_id: str
    project: str
    claim: str
    state: TruthState
    evidence_references: tuple[str, ...] = ()
    supersedes: tuple[str, ...] = ()
    superseded_by: tuple[str, ...] = ()
    tenant_id: str = ""
    business_id: str = ""
    site_id: str = ""
    mission_id: str = ""
    action_contract_id: str = ""
    claim_digest: str = ""

    def __post_init__(self) -> None:
        if not self.node_id.strip() or not self.project.strip() or not self.claim.strip():
            raise ValueError("truth node identity, project and claim are required")
        if self.claim_digest and len(self.claim_digest) != 64:
            raise ValueError("claim_digest must be sha256 hex")


@dataclass(frozen=True)
class TruthVerificationBundle:
    receipt: ExecutionReceipt
    ledger: ReceiptLedger
    expected_checkpoint: str
    external_anchor_reference: str
    evidence_references: tuple[str, ...]
    evidence_created_at: str
    maximum_age_seconds: int
    observed_content_digest: str
    postconditions_met: bool
    evidence_resolved: bool
    authorization_revoked: bool = False


@dataclass(frozen=True)
class TruthVerificationDecision:
    allowed: bool
    reasons: tuple[str, ...]


class SignedTruthVerifier:
    def verify(self, node: TruthNode, bundle: TruthVerificationBundle, *, now: dt.datetime | None = None) -> TruthVerificationDecision:
        reasons: list[str] = []
        receipt = bundle.receipt
        now = (now or dt.datetime.now(UTC)).astimezone(UTC)
        ledger_ok, ledger_errors = bundle.ledger.verify(expected_checkpoint=bundle.expected_checkpoint)
        if not ledger_ok:
            reasons.extend(f"ledger:{error}" for error in ledger_errors)
        snapshot = bundle.ledger.snapshot()
        exact = [item for item in snapshot if item.receipt_id == receipt.receipt_id]
        if len(exact) != 1 or exact[0] != receipt:
            reasons.append("receipt_not_in_verified_ledger")
        if receipt.status != "SUCCEEDED":
            reasons.append("receipt_not_successful")
        if not receipt.signature or not receipt.key_id:
            reasons.append("receipt_unsigned")
        if not bundle.external_anchor_reference.strip():
            reasons.append("external_anchor_missing")
        if bundle.authorization_revoked:
            reasons.append("authorization_revoked")
        if not bundle.postconditions_met:
            reasons.append("postconditions_unmet")
        if not bundle.evidence_resolved:
            reasons.append("evidence_unresolved")
        if bundle.maximum_age_seconds <= 0:
            reasons.append("freshness_policy_invalid")
        else:
            try:
                age = (now - _parse_time(bundle.evidence_created_at)).total_seconds()
                if age < 0 or age > bundle.maximum_age_seconds:
                    reasons.append("evidence_stale")
            except (ValueError, TypeError, OverflowError):
                reasons.append("evidence_timestamp_invalid")
        scope_pairs = (
            ("tenant", node.tenant_id, receipt.tenant_id),
            ("business", node.business_id, receipt.business_id),
            ("site", node.site_id, receipt.site_id),
            ("mission", node.mission_id, receipt.mission_id),
            ("action_contract", node.action_contract_id, receipt.action_contract_id),
        )
        for label, expected, observed in scope_pairs:
            if not expected or expected != observed:
                reasons.append(f"{label}_scope_mismatch")
        if not node.claim_digest or node.claim_digest != bundle.observed_content_digest:
            reasons.append("content_digest_mismatch")
        if len(bundle.observed_content_digest) != 64:
            reasons.append("content_digest_invalid")
        refs = tuple(dict.fromkeys(bundle.evidence_references))
        if not refs:
            reasons.append("evidence_missing")
        if node.node_id in refs or receipt.receipt_id == node.node_id:
            reasons.append("circular_evidence")
        if any(ref.startswith("generated-report:") and ref.endswith(node.node_id) for ref in refs):
            reasons.append("self_verifying_report")
        idempotencies = [item.idempotency_key for item in snapshot]
        if not receipt.idempotency_key or idempotencies.count(receipt.idempotency_key) != 1:
            reasons.append("idempotency_not_unique")
        return TruthVerificationDecision(not reasons, tuple(sorted(set(reasons))))


class TruthGraph:
    TRANSITIONS = {
        TruthState.PLANNED: {TruthState.ATTEMPTED, TruthState.FAILED, TruthState.SUPERSEDED},
        TruthState.ATTEMPTED: {TruthState.PARTIAL, TruthState.COMPLETED_UNVERIFIED, TruthState.FAILED},
        TruthState.PARTIAL: {TruthState.ATTEMPTED, TruthState.COMPLETED_UNVERIFIED, TruthState.FAILED},
        TruthState.COMPLETED_UNVERIFIED: {TruthState.VERIFIED, TruthState.ATTEMPTED, TruthState.FAILED},
        TruthState.VERIFIED: {TruthState.ROLLED_BACK, TruthState.SUPERSEDED},
        TruthState.FAILED: {TruthState.ATTEMPTED, TruthState.SUPERSEDED},
        TruthState.ROLLED_BACK: {TruthState.ATTEMPTED, TruthState.SUPERSEDED},
        TruthState.SUPERSEDED: set(),
    }

    def __init__(self, verifier: SignedTruthVerifier | None = None) -> None:
        self._nodes: dict[str, TruthNode] = {}
        self.verifier = verifier or SignedTruthVerifier()

    def add(self, node: TruthNode) -> None:
        if node.node_id in self._nodes:
            raise ValueError("truth node id must be unique")
        if node.state == TruthState.VERIFIED:
            raise PermissionError("verified truth must enter through a signed verification transition")
        self._nodes[node.node_id] = node

    def get(self, node_id: str) -> TruthNode:
        return self._nodes[node_id]

    def transition(self, node_id: str, target: TruthState, *, evidence_references: tuple[str, ...] = (), verification_bundle: TruthVerificationBundle | None = None, now: dt.datetime | None = None) -> TruthNode:
        node = self._nodes[node_id]
        if target not in self.TRANSITIONS[node.state]:
            raise PermissionError("invalid truth-state transition")
        evidence = tuple(sorted(set(node.evidence_references) | set(evidence_references)))
        if target == TruthState.VERIFIED:
            if verification_bundle is None:
                raise PermissionError("verified truth requires a signed verification bundle")
            decision = self.verifier.verify(node, verification_bundle, now=now)
            if not decision.allowed:
                raise PermissionError("truth verification denied: " + ",".join(decision.reasons))
            evidence = tuple(sorted(set(evidence) | set(verification_bundle.evidence_references) | {verification_bundle.receipt.receipt_id, verification_bundle.expected_checkpoint, verification_bundle.external_anchor_reference}))
        updated = replace(node, state=target, evidence_references=evidence)
        self._nodes[node_id] = updated
        return updated

    def supersede(self, old_id: str, replacement: TruthNode) -> TruthNode:
        old = self._nodes[old_id]
        if old.state != TruthState.VERIFIED:
            raise PermissionError("only verified truth can be superseded")
        if old_id not in replacement.supersedes:
            replacement = replace(replacement, supersedes=tuple(sorted(set(replacement.supersedes) | {old_id})))
        self.add(replacement)
        self._nodes[old_id] = replace(old, state=TruthState.SUPERSEDED, superseded_by=(replacement.node_id,))
        return replacement


def claim_digest(claim: str, payload: object) -> str:
    return sha256_hex({"claim": claim, "payload": payload})
