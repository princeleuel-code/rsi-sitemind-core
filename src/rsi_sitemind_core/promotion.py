from __future__ import annotations

from dataclasses import replace

from .models import CandidateEvolution, PromotionState


class PromotionCourt:
    ORDER = (
        PromotionState.PROPOSED,
        PromotionState.VALIDATED,
        PromotionState.SHADOW,
        PromotionState.CANARY,
        PromotionState.PROMOTED,
    )

    def advance(self, candidate: CandidateEvolution, target: PromotionState, *, receipt: str = "") -> CandidateEvolution:
        if candidate.state in {PromotionState.REJECTED, PromotionState.ROLLED_BACK}:
            raise ValueError("terminal candidate cannot advance")
        if target not in self.ORDER:
            raise ValueError("use reject or rollback for terminal transitions")
        current_index = self.ORDER.index(candidate.state)
        target_index = self.ORDER.index(target)
        if target_index != current_index + 1:
            raise ValueError("candidate must advance exactly one stage")
        missing = set(candidate.required_gates) - set(candidate.passed_gates)
        if target == PromotionState.PROMOTED and missing:
            raise PermissionError(f"promotion gates missing: {sorted(missing)}")
        updates = {"state": target}
        if target == PromotionState.SHADOW:
            updates["shadow_receipt"] = receipt
        elif target == PromotionState.CANARY:
            updates["canary_receipt"] = receipt
        elif target == PromotionState.PROMOTED:
            updates["promotion_receipt"] = receipt
        return replace(candidate, **updates)

    @staticmethod
    def reject(candidate: CandidateEvolution, failed_gate: str) -> CandidateEvolution:
        failures = tuple(sorted(set(candidate.failed_gates) | {failed_gate}))
        return replace(candidate, state=PromotionState.REJECTED, failed_gates=failures)

    @staticmethod
    def rollback(candidate: CandidateEvolution, rollback_reference: str) -> CandidateEvolution:
        if candidate.state != PromotionState.PROMOTED:
            raise ValueError("only promoted candidates can be rolled back")
        if not rollback_reference:
            raise ValueError("rollback reference required")
        return replace(candidate, state=PromotionState.ROLLED_BACK, rollback_reference=rollback_reference)
