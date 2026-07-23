from __future__ import annotations

import datetime as dt
from dataclasses import dataclass

from .crypto import PublicKeyRegistry
from .models import ActionContract, AuthorizationGrant, WorkerCapability


@dataclass(frozen=True)
class GovernanceDecision:
    allowed: bool
    code: str
    reasons: tuple[str, ...]


class RSIGovernor:
    READ_ONLY_ACTIONS = frozenset({
        "public_crawl", "query_evidence", "read_analytics", "read_search_console",
        "read_cms", "read_ads", "read_revenue", "generate_proposal",
    })

    def __init__(self, keys: PublicKeyRegistry, policy_version: str = "rsi-policy-v1"):
        self.keys = keys
        self.policy_version = policy_version

    @staticmethod
    def _parse_time(value: str) -> dt.datetime:
        if not isinstance(value, str) or not value.strip():
            raise ValueError("timestamp is required")
        normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
        parsed = dt.datetime.fromisoformat(normalized)
        if parsed.tzinfo is None:
            raise ValueError("timezone-aware timestamp required")
        return parsed.astimezone(dt.timezone.utc)

    def validate_action(
        self,
        action: ActionContract,
        authorization: AuthorizationGrant,
        capability: WorkerCapability,
        *,
        now: dt.datetime | None = None,
        used_idempotency_keys: set[str] | None = None,
    ) -> GovernanceDecision:
        reasons: list[str] = []
        now = (now or dt.datetime.now(dt.timezone.utc)).astimezone(dt.timezone.utc)

        for record, name in ((authorization, "authorization"), (capability, "capability"), (action, "action")):
            if not record.key_id or not record.signature:
                reasons.append(f"{name}_unsigned")
            elif not self.keys.verify(record.key_id, record.unsigned_payload(), record.signature):
                reasons.append(f"{name}_signature_invalid")

        if authorization.revoked:
            reasons.append("authorization_revoked")
        if capability.revoked:
            reasons.append("capability_revoked")

        identity_fields = ("tenant_id", "business_id", "site_id")
        for field in identity_fields:
            values = {getattr(action, field), getattr(authorization, field), getattr(capability, field)}
            if "" in values or len(values) != 1:
                reasons.append(f"{field}_mismatch")

        if action.authorization_id != authorization.authorization_id:
            reasons.append("authorization_id_mismatch")
        if action.capability_id != capability.capability_id:
            reasons.append("capability_id_mismatch")
        if action.actor_id != authorization.actor_id:
            reasons.append("actor_id_mismatch")
        if action.worker_id != capability.worker_id:
            reasons.append("worker_id_mismatch")
        if action.mission_id != capability.mission_id:
            reasons.append("mission_id_mismatch")

        try:
            windows = [
                (self._parse_time(authorization.valid_from), self._parse_time(authorization.valid_until), "authorization"),
                (self._parse_time(capability.valid_from), self._parse_time(capability.valid_until), "capability"),
                (self._parse_time(action.valid_from), self._parse_time(action.valid_until), "action"),
            ]
            for start, end, name in windows:
                if end <= start:
                    reasons.append(f"{name}_window_invalid")
                elif not (start <= now <= end):
                    reasons.append(f"{name}_outside_validity")
        except (ValueError, TypeError, OverflowError):
            reasons.append("timestamp_invalid")

        if not action.action_type:
            reasons.append("action_type_missing")
        if action.action_type not in authorization.allowed_action_types:
            reasons.append("action_not_authorized")
        if action.action_type not in capability.permitted_action_types:
            reasons.append("action_not_permitted_for_worker")
        if action.action_type in capability.prohibited_actions:
            reasons.append("action_explicitly_prohibited")

        if not action.resource:
            reasons.append("resource_missing")
        if action.resource not in authorization.allowed_resources:
            reasons.append("resource_not_authorized")
        if action.resource not in capability.permitted_resources:
            reasons.append("resource_not_permitted_for_worker")

        exposures = (
            action.financial_exposure,
            authorization.maximum_financial_exposure,
            capability.maximum_financial_exposure,
        )
        if any(not isinstance(v, (int, float)) or isinstance(v, bool) or v < 0 for v in exposures):
            reasons.append("financial_exposure_invalid")
        elif action.financial_exposure > min(authorization.maximum_financial_exposure, capability.maximum_financial_exposure):
            reasons.append("financial_exposure_exceeds_cap")

        if capability.delegation_depth < 0 or capability.maximum_delegation_depth < 0:
            reasons.append("delegation_depth_invalid")
        elif capability.delegation_depth > capability.maximum_delegation_depth:
            reasons.append("delegation_depth_exceeded")

        if capability.maximum_runtime_seconds <= 0:
            reasons.append("runtime_budget_invalid")
        if capability.maximum_calls <= 0:
            reasons.append("call_budget_invalid")

        if not action.idempotency_key.strip():
            reasons.append("idempotency_key_missing")
        elif used_idempotency_keys is not None and action.idempotency_key in used_idempotency_keys:
            reasons.append("idempotency_replay")

        consequential = action.action_type not in self.READ_ONLY_ACTIONS
        if consequential and not action.evidence_references:
            reasons.append("evidence_missing")
        if consequential and not action.preconditions:
            reasons.append("preconditions_missing")
        if consequential and not action.postconditions:
            reasons.append("postconditions_missing")
        if consequential and not action.reversible and not authorization.allow_irreversible:
            reasons.append("irreversible_action_not_authorized")
        if consequential and action.reversible and not action.rollback_contract:
            reasons.append("rollback_contract_missing")

        overlap = set(action.permitted_side_effects) & set(action.prohibited_side_effects)
        if overlap:
            reasons.append("side_effect_policy_conflict")

        if action.policy_version != self.policy_version or authorization.policy_version != self.policy_version:
            reasons.append("policy_version_mismatch")

        reasons = sorted(set(reasons))
        return GovernanceDecision(not reasons, "ALLOW" if not reasons else "DENY", tuple(reasons))
