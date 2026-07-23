import datetime as dt
import sys
from dataclasses import replace
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

from rsi_sitemind_core import ActionContract, AuthorizationGrant, Ed25519Keypair, PublicKeyRegistry, RSIGovernor, WorkerCapability

NOW = dt.datetime(2026, 7, 23, 16, 0, tzinfo=dt.timezone.utc)
START = "2026-07-23T15:00:00Z"
END = "2026-07-23T17:00:00Z"


def signed(record, signer):
    prepared = replace(record, key_id=signer.key_id, signature="")
    return replace(prepared, signature=signer.sign(prepared.unsigned_payload()))


def fixture():
    signer = Ed25519Keypair.generate("governor-test")
    keys = PublicKeyRegistry({signer.key_id: signer.public_bytes_b64()})
    governor = RSIGovernor(keys)
    auth = signed(AuthorizationGrant(
        authorization_id="auth-1", tenant_id="tenant-a", business_id="biz-a", site_id="site-a",
        actor_id="owner-a", allowed_action_types=("publish_cms_draft",),
        allowed_resources=("cms://site-a/drafts",), maximum_financial_exposure=100,
        valid_from=START, valid_until=END,
    ), signer)
    cap = signed(WorkerCapability(
        capability_id="cap-1", tenant_id="tenant-a", business_id="biz-a", site_id="site-a",
        mission_id="mission-a", worker_id="worker-a", worker_role="content",
        permitted_action_types=("publish_cms_draft",), permitted_resources=("cms://site-a/drafts",),
        maximum_financial_exposure=50, maximum_runtime_seconds=600, maximum_calls=10,
        valid_from=START, valid_until=END,
    ), signer)
    action = signed(ActionContract(
        action_contract_id="action-1", tenant_id="tenant-a", business_id="biz-a", site_id="site-a",
        mission_id="mission-a", actor_id="owner-a", worker_id="worker-a",
        action_type="publish_cms_draft", authorization_id="auth-1", capability_id="cap-1",
        resource="cms://site-a/drafts", financial_exposure=0, valid_from=START, valid_until=END,
        evidence_references=("claim-1",), expected_result={"draft": True},
        preconditions=("ownership_verified",), postconditions=("draft_exists",),
        idempotency_key="idem-1", reversible=True, rollback_contract={"action":"delete_draft"},
        model_version="test", prompt_version="test",
    ), signer)
    return signer, governor, auth, cap, action


def test_valid_action_allowed():
    _, governor, auth, cap, action = fixture()
    decision = governor.validate_action(action, auth, cap, now=NOW)
    assert decision.allowed, decision.reasons


def test_cross_tenant_denied():
    signer, governor, auth, cap, action = fixture()
    action = signed(replace(action, tenant_id="tenant-b", signature=""), signer)
    decision = governor.validate_action(action, auth, cap, now=NOW)
    assert not decision.allowed and "tenant_id_mismatch" in decision.reasons


def test_expired_authorization_denied():
    signer, governor, auth, cap, action = fixture()
    auth = signed(replace(auth, valid_from="2026-07-23T13:00:00Z", valid_until="2026-07-23T14:00:00Z", signature=""), signer)
    decision = governor.validate_action(action, auth, cap, now=NOW)
    assert not decision.allowed and "authorization_outside_validity" in decision.reasons


def test_negative_spend_denied():
    signer, governor, auth, cap, action = fixture()
    action = signed(replace(action, financial_exposure=-1, signature=""), signer)
    decision = governor.validate_action(action, auth, cap, now=NOW)
    assert not decision.allowed and "financial_exposure_invalid" in decision.reasons


def test_replay_denied():
    _, governor, auth, cap, action = fixture()
    decision = governor.validate_action(action, auth, cap, now=NOW, used_idempotency_keys={"idem-1"})
    assert not decision.allowed and "idempotency_replay" in decision.reasons


def test_tampered_signature_denied():
    _, governor, auth, cap, action = fixture()
    action = replace(action, resource="cms://site-a/other")
    decision = governor.validate_action(action, auth, cap, now=NOW)
    assert not decision.allowed and "action_signature_invalid" in decision.reasons


def test_malformed_timestamp_denied_without_crash():
    signer, governor, auth, cap, action = fixture()
    action = signed(replace(action, valid_until="not-a-time", idempotency_key="bad-time", signature=""), signer)
    decision = governor.validate_action(action, auth, cap, now=NOW)
    assert not decision.allowed and "timestamp_invalid" in decision.reasons


def test_revoked_and_policy_conflict_denied():
    signer, governor, auth, cap, action = fixture()
    auth = signed(replace(auth, revoked=True, signature=""), signer)
    action = signed(replace(action, idempotency_key="revoked", permitted_side_effects=("publish",), prohibited_side_effects=("publish",), signature=""), signer)
    decision = governor.validate_action(action, auth, cap, now=NOW)
    assert not decision.allowed
    assert "authorization_revoked" in decision.reasons
    assert "side_effect_policy_conflict" in decision.reasons


def test_missing_evidence_and_rollback_denied():
    signer, governor, auth, cap, action = fixture()
    action = signed(replace(action, idempotency_key="missing", evidence_references=(), rollback_contract={}, signature=""), signer)
    decision = governor.validate_action(action, auth, cap, now=NOW)
    assert not decision.allowed
    assert "evidence_missing" in decision.reasons
    assert "rollback_contract_missing" in decision.reasons


def test_invalid_worker_budgets_denied():
    signer, governor, auth, cap, action = fixture()
    cap = signed(replace(cap, maximum_runtime_seconds=0, maximum_calls=0, signature=""), signer)
    action = signed(replace(action, idempotency_key="worker-budget", signature=""), signer)
    decision = governor.validate_action(action, auth, cap, now=NOW)
    assert not decision.allowed
    assert "runtime_budget_invalid" in decision.reasons
    assert "call_budget_invalid" in decision.reasons
