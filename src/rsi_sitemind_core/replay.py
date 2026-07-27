from __future__ import annotations

import enum
from dataclasses import dataclass
from typing import Iterable

from .feedback import FeedbackEvent


class FeedbackCategory(str, enum.Enum):
    DURABLE_DIRECTIVE = "DURABLE_DIRECTIVE"
    REPEATED_CORRECTION = "REPEATED_CORRECTION"
    ACCEPTED_REVISION = "ACCEPTED_REVISION"
    TEMPORARY_INSTRUCTION = "TEMPORARY_INSTRUCTION"
    EMOTIONAL_REACTION = "EMOTIONAL_REACTION"
    PROJECT_PREFERENCE = "PROJECT_PREFERENCE"
    UNIVERSAL_SAFETY_RULE = "UNIVERSAL_SAFETY_RULE"


@dataclass(frozen=True)
class RedactedFeedbackRecord:
    event: FeedbackEvent
    category: FeedbackCategory
    redacted: bool
    authorization_reference: str
    source_excerpt_hash: str


@dataclass(frozen=True)
class ReplayCorpusValidation:
    valid: bool
    reasons: tuple[str, ...]
    accepted_event_ids: tuple[str, ...]


class AuthorizedReplayCorpus:
    """Validates authorization, redaction, scope and durability before replay."""

    def validate(self, records: Iterable[RedactedFeedbackRecord]) -> ReplayCorpusValidation:
        reasons: list[str] = []
        accepted: list[str] = []
        seen: set[str] = set()
        for record in records:
            event = record.event
            if event.event_id in seen:
                reasons.append(f"duplicate_event:{event.event_id}")
                continue
            seen.add(event.event_id)
            if not record.redacted:
                reasons.append(f"not_redacted:{event.event_id}")
                continue
            if not record.authorization_reference.strip():
                reasons.append(f"authorization_missing:{event.event_id}")
                continue
            if len(record.source_excerpt_hash) != 64:
                reasons.append(f"source_hash_invalid:{event.event_id}")
                continue
            if record.category in {FeedbackCategory.TEMPORARY_INSTRUCTION, FeedbackCategory.EMOTIONAL_REACTION} and event.durable_candidate:
                reasons.append(f"non_durable_category_marked_durable:{event.event_id}")
                continue
            if record.category == FeedbackCategory.UNIVERSAL_SAFETY_RULE and event.project != "*":
                reasons.append(f"universal_rule_scope_invalid:{event.event_id}")
                continue
            accepted.append(event.event_id)
        return ReplayCorpusValidation(not reasons, tuple(sorted(reasons)), tuple(sorted(accepted)))
