from __future__ import annotations

import dataclasses
import datetime as dt
import enum
from dataclasses import dataclass, field, replace
from typing import Any


class EpistemicState(str, enum.Enum):
    OBSERVED = "OBSERVED"
    CALCULATED = "CALCULATED"
    CORROBORATED = "CORROBORATED"
    INFERRED = "INFERRED"
    DISPUTED = "DISPUTED"
    STALE = "STALE"
    UNKNOWN = "UNKNOWN"


class PromotionState(str, enum.Enum):
    PROPOSED = "PROPOSED"
    VALIDATED = "VALIDATED"
    SHADOW = "SHADOW"
    CANARY = "CANARY"
    PROMOTED = "PROMOTED"
    REJECTED = "REJECTED"
    ROLLED_BACK = "ROLLED_BACK"


@dataclass(frozen=True)
class SignedRecord:
    key_id: str = ""
    signature: str = ""

    def unsigned_payload(self) -> dict[str, Any]:
        data = dataclasses.asdict(self)
        data.pop("signature", None)
        return data

    def with_signature(self, key_id: str, signature: str) -> "SignedRecord":
        return replace(self, key_id=key_id, signature=signature)


@dataclass(frozen=True)
class AuthorizationGrant(SignedRecord):
    authorization_id: str = ""
    tenant_id: str = ""
    business_id: str = ""
    site_id: str = ""
    actor_id: str = ""
    allowed_action_types: tuple[str, ...] = ()
    allowed_resources: tuple[str, ...] = ()
    maximum_financial_exposure: float = 0.0
    valid_from: str = ""
    valid_until: str = ""
    allow_irreversible: bool = False
    policy_version: str = "rsi-policy-v1"
    revoked: bool = False


@dataclass(frozen=True)
class WorkerCapability(SignedRecord):
    capability_id: str = ""
    tenant_id: str = ""
    business_id: str = ""
    site_id: str = ""
    mission_id: str = ""
    worker_id: str = ""
    worker_role: str = ""
    permitted_action_types: tuple[str, ...] = ()
    permitted_resources: tuple[str, ...] = ()
    prohibited_actions: tuple[str, ...] = ()
    maximum_financial_exposure: float = 0.0
    maximum_runtime_seconds: int = 0
    maximum_calls: int = 0
    valid_from: str = ""
    valid_until: str = ""
    delegation_depth: int = 0
    maximum_delegation_depth: int = 1
    sensitivity: str = "internal"
    revoked: bool = False


@dataclass(frozen=True)
class ActionContract(SignedRecord):
    action_contract_id: str = ""
    tenant_id: str = ""
    business_id: str = ""
    site_id: str = ""
    mission_id: str = ""
    actor_id: str = ""
    worker_id: str = ""
    action_type: str = ""
    authorization_id: str = ""
    capability_id: str = ""
    resource: str = ""
    financial_exposure: float = 0.0
    valid_from: str = ""
    valid_until: str = ""
    evidence_references: tuple[str, ...] = ()
    expected_result: dict[str, Any] = field(default_factory=dict)
    permitted_side_effects: tuple[str, ...] = ()
    prohibited_side_effects: tuple[str, ...] = ()
    preconditions: tuple[str, ...] = ()
    postconditions: tuple[str, ...] = ()
    idempotency_key: str = ""
    reversible: bool = True
    rollback_contract: dict[str, Any] = field(default_factory=dict)
    policy_version: str = "rsi-policy-v1"
    model_version: str = ""
    prompt_version: str = ""
    receipt_parent: str = "GENESIS"


@dataclass(frozen=True)
class ExecutionReceipt(SignedRecord):
    receipt_id: str = ""
    tenant_id: str = ""
    business_id: str = ""
    site_id: str = ""
    mission_id: str = ""
    action_contract_id: str = ""
    idempotency_key: str = ""
    status: str = ""
    started_at: str = ""
    completed_at: str = ""
    external_state_before_hash: str = ""
    external_state_after_hash: str = ""
    result_hash: str = ""
    previous_receipt_hash: str = "GENESIS"
    receipt_hash: str = ""
    error_code: str = ""


@dataclass(frozen=True)
class MissionContract(SignedRecord):
    mission_id: str = ""
    tenant_id: str = ""
    business_id: str = ""
    site_id: str = ""
    requesting_actor_id: str = ""
    question: str = ""
    supported_decision: str = ""
    allowed_source_classes: tuple[str, ...] = ()
    prohibited_operations: tuple[str, ...] = ()
    required_freshness_seconds: int = 0
    required_confidence_class: str = ""
    time_horizon: str = ""
    maximum_runtime_seconds: int = 0
    maximum_model_cost: float = 0.0
    completion_conditions: tuple[str, ...] = ()
    escalation_conditions: tuple[str, ...] = ()
    valid_from: str = ""
    valid_until: str = ""


@dataclass(frozen=True)
class DomainTwin:
    tenant_id: str
    business_id: str
    site_id: str
    domain: str
    ownership_status: str = "UNVERIFIED"
    management_mode: str = "PUBLIC_ANALYSIS"
    verification_method: str = ""
    verification_receipt_id: str = ""
    business_type: str = "UNKNOWN"
    products_services: tuple[str, ...] = ()
    geographies: tuple[str, ...] = ()
    connectors: tuple[str, ...] = ()
    evidence_references: tuple[str, ...] = ()
    unknowns: tuple[str, ...] = ()
    rollback_state: str = "EMPTY"


@dataclass(frozen=True)
class CandidateEvolution(SignedRecord):
    candidate_id: str = ""
    candidate_type: str = ""
    source_identity: str = ""
    proposed_change_hash: str = ""
    tenant_scope: str = "PLATFORM"
    state: PromotionState = PromotionState.PROPOSED
    required_gates: tuple[str, ...] = ()
    passed_gates: tuple[str, ...] = ()
    failed_gates: tuple[str, ...] = ()
    shadow_receipt: str = ""
    canary_receipt: str = ""
    promotion_receipt: str = ""
    rollback_reference: str = ""
