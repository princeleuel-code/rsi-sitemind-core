import sys
from dataclasses import replace
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

from rsi_sitemind_core import (
    CandidateEvolution, DomainOnboardingService, Ed25519Keypair, ExecutionReceipt,
    PromotionCourt, PromotionState, PublicKeyRegistry, ReceiptLedger,
)


def test_domain_requires_verification():
    service = DomainOnboardingService()
    twin = service.begin(tenant_id="t1", business_id="b1", site_id="s1", domain="https://Example.com/path")
    assert twin.domain == "example.com"
    assert not service.can_manage(twin)
    token = service.issue_challenge(twin, "DNS_TXT")
    verified = service.verify(twin, "DNS_TXT", token)
    assert service.can_manage(verified)
    assert verified.management_mode == "AUTHORIZED_READ_ONLY"


def test_ledger_chain_and_checkpoint():
    signer = Ed25519Keypair.generate("receipt-test")
    keys = PublicKeyRegistry({signer.key_id: signer.public_bytes_b64()})
    ledger = ReceiptLedger(signer, keys)
    base = dict(
        tenant_id="t1", business_id="b1", site_id="s1", mission_id="m1",
        action_contract_id="a1", status="SUCCEEDED", started_at="2026-07-23T15:00:00Z",
        completed_at="2026-07-23T15:01:00Z", external_state_before_hash="before",
        external_state_after_hash="after", result_hash="result",
    )
    ledger.append(ExecutionReceipt(receipt_id="r1", idempotency_key="i1", **base))
    ledger.append(ExecutionReceipt(receipt_id="r2", idempotency_key="i2", **base))
    checkpoint = ledger.checkpoint()
    ok, errors = ledger.verify(expected_checkpoint=checkpoint)
    assert ok, errors


def test_promotion_requires_all_gates():
    court = PromotionCourt()
    candidate = CandidateEvolution(
        candidate_id="c1", candidate_type="CandidateSkill", source_identity="sha256:x",
        proposed_change_hash="sha256:y", required_gates=("schema", "adversarial"),
        passed_gates=("schema", "adversarial"),
    )
    candidate = court.advance(candidate, PromotionState.VALIDATED)
    candidate = court.advance(candidate, PromotionState.SHADOW, receipt="shadow-r")
    candidate = court.advance(candidate, PromotionState.CANARY, receipt="canary-r")
    candidate = court.advance(candidate, PromotionState.PROMOTED, receipt="promotion-r")
    assert candidate.state == PromotionState.PROMOTED


def test_checkpoint_detects_post_hoc_mutation():
    signer = Ed25519Keypair.generate("tamper-test")
    keys = PublicKeyRegistry({signer.key_id: signer.public_bytes_b64()})
    ledger = ReceiptLedger(signer, keys)
    receipt = ledger.append(ExecutionReceipt(
        receipt_id="r", tenant_id="t", business_id="b", site_id="s", mission_id="m",
        action_contract_id="a", idempotency_key="i", status="SUCCEEDED",
        started_at="2026-07-23T15:00:00Z", completed_at="2026-07-23T15:01:00Z",
        external_state_before_hash="before", external_state_after_hash="after", result_hash="result",
    ))
    checkpoint=ledger.checkpoint()
    ledger._receipts[0]=replace(receipt,status="FAILED")
    ok, errors=ledger.verify(expected_checkpoint=checkpoint)
    assert not ok
    assert any(e.startswith("signature_invalid") for e in errors)
    assert "checkpoint_mismatch" in errors
