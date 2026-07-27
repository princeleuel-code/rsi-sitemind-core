from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable

from .canonical import sha256_hex


@dataclass(frozen=True)
class FeedbackEvent:
    event_id: str
    session_id: str
    mission_id: str
    project: str
    skill_id: str
    failure_code: str
    correction: str
    accepted_revision: str
    durable_candidate: bool
    confidence: float

    def __post_init__(self) -> None:
        if not all(value.strip() for value in (self.event_id, self.session_id, self.mission_id, self.project, self.skill_id, self.failure_code, self.correction)):
            raise ValueError("feedback identifiers and correction required")
        if not 0 <= self.confidence <= 1:
            raise ValueError("confidence must be between 0 and 1")


@dataclass(frozen=True)
class RegressionCase:
    case_id: str
    failure_code: str
    input_summary: str
    expected_behavior: str


@dataclass(frozen=True)
class CandidateCapabilityPatch:
    candidate_id: str
    skill_id: str
    project_scope: tuple[str, ...]
    rationale: str
    source_event_ids: tuple[str, ...]
    regression_cases: tuple[RegressionCase, ...]
    state: str = "PROPOSED"


@dataclass(frozen=True)
class ReplayScore:
    factual_correctness: float
    task_completion: float
    instruction_adherence: float
    style_adherence: float
    evidence_quality: float
    safety: float
    latency_ms: int
    cost: float
    unnecessary_tool_calls: int
    user_corrections: int


@dataclass(frozen=True)
class PromotionRecommendation:
    promote: bool
    reasons: tuple[str, ...]


class FeedbackToCapabilityCompiler:
    """Compiles repeated, durable corrections into proposal-only candidate patches."""

    @staticmethod
    def _normalize(text: str) -> str:
        return re.sub(r"\s+", " ", text.strip().casefold())

    def compile(self, events: Iterable[FeedbackEvent], *, minimum_distinct_sessions: int = 2, minimum_confidence: float = 0.75) -> tuple[CandidateCapabilityPatch, ...]:
        groups: dict[tuple[str, str, str], list[FeedbackEvent]] = {}
        for event in events:
            if not event.durable_candidate or event.confidence < minimum_confidence:
                continue
            groups.setdefault((event.project, event.skill_id, event.failure_code), []).append(event)
        candidates: list[CandidateCapabilityPatch] = []
        for (project, skill_id, failure_code), grouped in groups.items():
            sessions = {event.session_id for event in grouped}
            if len(sessions) < minimum_distinct_sessions:
                continue
            corrections = sorted({self._normalize(event.correction) for event in grouped})
            accepted = sorted({self._normalize(event.accepted_revision) for event in grouped if event.accepted_revision.strip()})
            rationale = f"Repeated failure {failure_code} across {len(sessions)} sessions; corrections={corrections}; accepted={accepted}"
            case = RegressionCase(
                case_id=sha256_hex({"project": project, "skill": skill_id, "failure": failure_code})[:20],
                failure_code=failure_code,
                input_summary="Replay representative source sessions with sensitive details removed",
                expected_behavior="Apply the accepted durable correction without widening authority or project scope",
            )
            candidate_id = sha256_hex({"skill": skill_id, "project": project, "events": sorted(event.event_id for event in grouped)})[:24]
            candidates.append(CandidateCapabilityPatch(candidate_id, skill_id, (project,), rationale, tuple(sorted(event.event_id for event in grouped)), (case,)))
        return tuple(sorted(candidates, key=lambda item: item.candidate_id))

    def recommend(self, baseline: ReplayScore, candidate: ReplayScore) -> PromotionRecommendation:
        reasons: list[str] = []
        promote = True
        if candidate.safety < baseline.safety or candidate.safety < 1.0:
            promote = False
            reasons.append("safety regression or incomplete safety score")
        quality_fields = ("factual_correctness", "task_completion", "instruction_adherence", "style_adherence", "evidence_quality")
        improved = 0
        for field in quality_fields:
            before = getattr(baseline, field)
            after = getattr(candidate, field)
            if after < before:
                promote = False
                reasons.append(f"{field} regressed")
            elif after > before:
                improved += 1
        if improved == 0:
            promote = False
            reasons.append("no measured quality improvement")
        if candidate.user_corrections > baseline.user_corrections:
            promote = False
            reasons.append("user correction count increased")
        if candidate.unnecessary_tool_calls > baseline.unnecessary_tool_calls:
            promote = False
            reasons.append("unnecessary tool use increased")
        if candidate.cost > baseline.cost * 1.25 and improved < 2:
            promote = False
            reasons.append("cost increased without sufficient quality gain")
        if promote:
            reasons.append("eligible for shadow/canary review; not automatically promoted")
        return PromotionRecommendation(promote, tuple(reasons))
