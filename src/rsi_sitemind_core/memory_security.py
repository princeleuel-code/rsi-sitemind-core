from __future__ import annotations

import enum
import re
import unicodedata
from dataclasses import dataclass


class InputTrustClass(str, enum.Enum):
    OWNER_DIRECTIVE = "OWNER_DIRECTIVE"
    AUTHORIZED_INTERNAL = "AUTHORIZED_INTERNAL"
    RETRIEVED_UNTRUSTED = "RETRIEVED_UNTRUSTED"
    CUSTOMER_PRIVATE = "CUSTOMER_PRIVATE"
    GENERATED_ARTIFACT = "GENERATED_ARTIFACT"


class IngestionOutcome(str, enum.Enum):
    ALLOW = "ALLOW"
    QUARANTINE = "QUARANTINE"
    HUMAN_REVIEW = "HUMAN_REVIEW"
    DENY = "DENY"


@dataclass(frozen=True)
class MemoryIngestionRequest:
    source_project: str
    target_project: str
    target_scope: str
    content: str
    trust_class: InputTrustClass
    durable_candidate: bool
    requested_tools: tuple[str, ...] = ()
    citations: tuple[str, ...] = ()
    temporary: bool = False
    maximum_bytes: int = 250_000


@dataclass(frozen=True)
class MemoryIngestionDecision:
    outcome: IngestionOutcome
    reasons: tuple[str, ...]


class MemoryIngestionPolicy:
    INJECTION_PATTERNS = (
        re.compile(r"(?i)ignore\s+(?:all\s+)?previous\s+instructions"),
        re.compile(r"(?i)system\s+prompt"),
        re.compile(r"(?i)(?:reveal|exfiltrate|print)\s+(?:the\s+)?(?:secret|credential|token|password)"),
        re.compile(r"(?i)(?:grant|elevate|bypass)\s+(?:my\s+)?(?:authority|permissions?|governor)"),
    )
    ELEVATED_TOOLS = frozenset({"production-deploy", "send-external", "spend-money", "secret-manager-write", "launch-gate-open"})

    def decide(self, request: MemoryIngestionRequest) -> MemoryIngestionDecision:
        reasons: list[str] = []
        raw = request.content.encode("utf-8", errors="strict")
        if len(raw) > request.maximum_bytes:
            return MemoryIngestionDecision(IngestionOutcome.DENY, ("payload_too_large",))
        if unicodedata.normalize("NFKC", request.content) != request.content:
            reasons.append("unicode_requires_normalization")
        if any(unicodedata.category(ch) in {"Cf", "Cs"} for ch in request.content):
            reasons.append("unicode_control_character")
        if any(pattern.search(request.content) for pattern in self.INJECTION_PATTERNS):
            reasons.append("prompt_injection_detected")
        if request.source_project != request.target_project and request.target_scope not in {"platform-public", "cross-project-approved"}:
            reasons.append("cross_project_memory_write")
        if request.temporary and request.durable_candidate:
            reasons.append("temporary_feedback_cannot_be_durable")
        if request.trust_class == InputTrustClass.CUSTOMER_PRIVATE and request.target_scope.startswith("platform"):
            reasons.append("customer_private_platform_generalization")
        if set(request.requested_tools) & self.ELEVATED_TOOLS:
            reasons.append("memory_requests_elevated_tools")
        if any(citation.startswith("fabricated:") or not citation.strip() for citation in request.citations):
            reasons.append("citation_unresolved_or_fabricated")
        if "cross_project_memory_write" in reasons or "customer_private_platform_generalization" in reasons:
            outcome = IngestionOutcome.DENY
        elif "prompt_injection_detected" in reasons or "memory_requests_elevated_tools" in reasons or "unicode_control_character" in reasons:
            outcome = IngestionOutcome.QUARANTINE
        elif reasons:
            outcome = IngestionOutcome.HUMAN_REVIEW
        elif request.trust_class in {InputTrustClass.RETRIEVED_UNTRUSTED, InputTrustClass.GENERATED_ARTIFACT}:
            outcome = IngestionOutcome.HUMAN_REVIEW
            reasons.append("untrusted_source_requires_review")
        else:
            outcome = IngestionOutcome.ALLOW
        return MemoryIngestionDecision(outcome, tuple(sorted(set(reasons))))
