from __future__ import annotations

import datetime as dt
import enum
import re
import uuid
from dataclasses import dataclass, replace
from typing import Any, Iterable, Mapping

from .canonical import sha256_hex

UTC = dt.timezone.utc


def _parse_time(value: str) -> dt.datetime:
    if not isinstance(value, str) or not value.strip():
        raise ValueError("timezone-aware timestamp required")
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    parsed = dt.datetime.fromisoformat(normalized)
    if parsed.tzinfo is None:
        raise ValueError("timezone-aware timestamp required")
    return parsed.astimezone(UTC)


def _nonblank(values: Iterable[str], label: str) -> None:
    if any(not isinstance(v, str) or not v.strip() for v in values):
        raise ValueError(f"{label} values must be non-empty strings")


class AutonomyLevel(enum.IntEnum):
    OBSERVE = 0
    RECOMMEND = 1
    DRAFT = 2
    REVERSIBLE_INTERNAL = 3
    APPROVED_EXTERNAL = 4
    POLICY_BOUNDED = 5


class MissionStatus(str, enum.Enum):
    PLANNED = "PLANNED"
    ACTIVE = "ACTIVE"
    BLOCKED = "BLOCKED"
    PARTIAL = "PARTIAL"
    COMPLETED_UNVERIFIED = "COMPLETED_UNVERIFIED"
    VERIFIED = "VERIFIED"
    FAILED = "FAILED"
    ROLLED_BACK = "ROLLED_BACK"
    SUPERSEDED = "SUPERSEDED"


class MemoryStatus(str, enum.Enum):
    ACTIVE = "ACTIVE"
    DISPUTED = "DISPUTED"
    STALE = "STALE"
    SUPERSEDED = "SUPERSEDED"
    ARCHIVED = "ARCHIVED"


class HeartbeatKind(str, enum.Enum):
    MORNING_INTELLIGENCE = "MORNING_INTELLIGENCE"
    MIDDAY_EXECUTION = "MIDDAY_EXECUTION"
    EVENING_VERIFICATION = "EVENING_VERIFICATION"
    CONDITION_WATCH = "CONDITION_WATCH"


class HeartbeatRunStatus(str, enum.Enum):
    RUNNING = "RUNNING"
    PAUSED = "PAUSED"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


@dataclass(frozen=True)
class EvidenceReference:
    ref_id: str
    kind: str
    digest: str
    source: str
    created_at: str

    def __post_init__(self) -> None:
        _nonblank((self.ref_id, self.kind, self.digest, self.source), "evidence")
        _parse_time(self.created_at)
        if not re.fullmatch(r"[a-fA-F0-9]{64}", self.digest):
            raise ValueError("evidence digest must be sha256 hex")


@dataclass(frozen=True)
class DurableMemory:
    object_id: str
    object_type: str
    project: str
    scope: str
    claim_key: str
    payload: Mapping[str, Any]
    source: str
    author: str
    created_at: str
    last_verified_at: str
    confidence: float
    status: MemoryStatus = MemoryStatus.ACTIVE
    sensitivity: str = "internal"
    evidence_references: tuple[str, ...] = ()
    supersedes: tuple[str, ...] = ()
    superseded_by: tuple[str, ...] = ()
    review_after: str = ""
    allowed_consumers: tuple[str, ...] = ()
    retrieval_tags: tuple[str, ...] = ()
    truthgraph_node_id: str = ""

    def __post_init__(self) -> None:
        _nonblank((self.object_id, self.object_type, self.project, self.scope, self.claim_key, self.source, self.author), "memory")
        _parse_time(self.created_at)
        _parse_time(self.last_verified_at)
        if self.review_after:
            _parse_time(self.review_after)
        if not 0 <= self.confidence <= 1:
            raise ValueError("confidence must be between 0 and 1")

    @property
    def payload_hash(self) -> str:
        return sha256_hex({"claim_key": self.claim_key, "payload": dict(self.payload)})


@dataclass(frozen=True)
class MemoryWriteResult:
    outcome: str
    object_id: str
    conflicting_ids: tuple[str, ...] = ()
    duplicate_of: str = ""


class MemoryRegistry:
    """Fail-closed durable-memory registry with explicit contradiction and supersession handling."""

    def __init__(self) -> None:
        self._records: dict[str, DurableMemory] = {}

    def get(self, object_id: str) -> DurableMemory:
        return self._records[object_id]

    def snapshot(self) -> tuple[DurableMemory, ...]:
        return tuple(sorted(self._records.values(), key=lambda item: item.object_id))

    def register(self, memory: DurableMemory) -> MemoryWriteResult:
        existing = self._records.get(memory.object_id)
        if existing:
            if existing == memory:
                return MemoryWriteResult("UNCHANGED", memory.object_id, duplicate_of=existing.object_id)
            raise ValueError("memory object_id already exists with different content")
        for candidate in self._records.values():
            if candidate.status == MemoryStatus.ACTIVE and candidate.project == memory.project and candidate.scope == memory.scope and candidate.claim_key == memory.claim_key:
                if candidate.payload_hash == memory.payload_hash:
                    return MemoryWriteResult("DUPLICATE", memory.object_id, duplicate_of=candidate.object_id)
                self._records[candidate.object_id] = replace(candidate, status=MemoryStatus.DISPUTED)
                self._records[memory.object_id] = replace(memory, status=MemoryStatus.DISPUTED)
                return MemoryWriteResult("CONTRADICTION", memory.object_id, conflicting_ids=(candidate.object_id, memory.object_id))
        self._records[memory.object_id] = memory
        return MemoryWriteResult("REGISTERED", memory.object_id)

    def supersede(self, old_id: str, replacement: DurableMemory) -> MemoryWriteResult:
        old = self._records.get(old_id)
        if old is None:
            raise KeyError(old_id)
        if replacement.object_id == old_id:
            raise ValueError("replacement must use a new object_id")
        if old_id not in replacement.supersedes:
            replacement = replace(replacement, supersedes=tuple(sorted(set(replacement.supersedes) | {old_id})))
        outcome = self.register(replacement)
        if outcome.outcome not in {"REGISTERED", "DUPLICATE"}:
            raise ValueError("replacement must resolve rather than create a contradiction")
        replacement_id = outcome.duplicate_of or replacement.object_id
        self._records[old_id] = replace(old, status=MemoryStatus.SUPERSEDED, superseded_by=(replacement_id,))
        return MemoryWriteResult("SUPERSEDED", replacement_id)

    def stale(self, as_of: dt.datetime) -> tuple[DurableMemory, ...]:
        if as_of.tzinfo is None:
            raise ValueError("as_of must be timezone-aware")
        stale = [memory for memory in self._records.values() if memory.review_after and memory.status == MemoryStatus.ACTIVE and _parse_time(memory.review_after) <= as_of.astimezone(UTC)]
        return tuple(sorted(stale, key=lambda item: item.object_id))


@dataclass(frozen=True)
class MissionWorkspace:
    mission_id: str
    title: str
    owner: str
    project: str
    objective: str
    status: MissionStatus
    priority: int
    autonomy_level: AutonomyLevel
    allowed_tools: tuple[str, ...]
    allowed_data_sources: tuple[str, ...]
    blocked_actions: tuple[str, ...]
    dependencies: tuple[str, ...]
    success_criteria: tuple[str, ...]
    verification_method: tuple[str, ...]
    rollback_method: tuple[str, ...]
    last_heartbeat: str = ""
    next_review: str = ""
    canonical_paths: tuple[str, ...] = ()
    receipt_references: tuple[str, ...] = ()
    originating_reference: str = ""

    REQUIRED_FILES = ("GOAL.md", "PLAN.md", "WORKLOG.md", "RECEIPTS.md", "DECISIONS.md", "RISKS.md", "OPEN_GAPS.md", "ROLLBACK.md")

    def __post_init__(self) -> None:
        _nonblank((self.mission_id, self.title, self.owner, self.project, self.objective), "mission")
        if not 0 <= self.priority <= 100:
            raise ValueError("priority must be between 0 and 100")
        if not self.success_criteria:
            raise ValueError("mission requires success criteria")
        if not self.verification_method:
            raise ValueError("mission requires verification method")
        if self.last_heartbeat:
            _parse_time(self.last_heartbeat)
        if self.next_review:
            _parse_time(self.next_review)


class MissionRegistry:
    TRANSITIONS = {
        MissionStatus.PLANNED: frozenset({MissionStatus.ACTIVE, MissionStatus.BLOCKED, MissionStatus.SUPERSEDED}),
        MissionStatus.ACTIVE: frozenset({MissionStatus.BLOCKED, MissionStatus.PARTIAL, MissionStatus.COMPLETED_UNVERIFIED, MissionStatus.FAILED}),
        MissionStatus.BLOCKED: frozenset({MissionStatus.ACTIVE, MissionStatus.FAILED, MissionStatus.SUPERSEDED}),
        MissionStatus.PARTIAL: frozenset({MissionStatus.ACTIVE, MissionStatus.BLOCKED, MissionStatus.COMPLETED_UNVERIFIED, MissionStatus.FAILED}),
        MissionStatus.COMPLETED_UNVERIFIED: frozenset({MissionStatus.VERIFIED, MissionStatus.ACTIVE, MissionStatus.FAILED}),
        MissionStatus.VERIFIED: frozenset({MissionStatus.ROLLED_BACK, MissionStatus.SUPERSEDED}),
        MissionStatus.FAILED: frozenset({MissionStatus.ACTIVE, MissionStatus.SUPERSEDED}),
        MissionStatus.ROLLED_BACK: frozenset({MissionStatus.ACTIVE, MissionStatus.SUPERSEDED}),
        MissionStatus.SUPERSEDED: frozenset(),
    }

    def __init__(self) -> None:
        self._missions: dict[str, MissionWorkspace] = {}

    def create(self, mission: MissionWorkspace) -> None:
        if mission.mission_id in self._missions:
            raise ValueError("mission_id must be unique")
        self._missions[mission.mission_id] = mission

    def get(self, mission_id: str) -> MissionWorkspace:
        return self._missions[mission_id]

    def transition(self, mission_id: str, target: MissionStatus, *, receipt_references: tuple[str, ...] = ()) -> MissionWorkspace:
        current = self.get(mission_id)
        if target not in self.TRANSITIONS[current.status]:
            raise PermissionError(f"invalid mission transition {current.status.value}->{target.value}")
        receipts = tuple(sorted(set(current.receipt_references) | set(receipt_references)))
        if target == MissionStatus.VERIFIED and not receipts:
            raise PermissionError("verified status requires at least one receipt")
        updated = replace(current, status=target, receipt_references=receipts)
        self._missions[mission_id] = updated
        return updated

    def open_missions(self) -> tuple[MissionWorkspace, ...]:
        terminal = {MissionStatus.VERIFIED, MissionStatus.FAILED, MissionStatus.ROLLED_BACK, MissionStatus.SUPERSEDED}
        return tuple(sorted((m for m in self._missions.values() if m.status not in terminal), key=lambda m: (-m.priority, m.mission_id)))


@dataclass(frozen=True)
class HeartbeatSpec:
    heartbeat_id: str
    kind: HeartbeatKind
    project: str
    max_autonomy_level: AutonomyLevel
    steps: tuple[str, ...]
    condition: str = ""

    def __post_init__(self) -> None:
        _nonblank((self.heartbeat_id, self.project), "heartbeat")
        if not self.steps:
            raise ValueError("heartbeat requires steps")
        if self.kind == HeartbeatKind.CONDITION_WATCH and not self.condition.strip():
            raise ValueError("condition watch requires a condition")


@dataclass(frozen=True)
class HeartbeatRun:
    run_id: str
    heartbeat_id: str
    idempotency_key: str
    scheduled_for: str
    status: HeartbeatRunStatus
    completed_steps: tuple[str, ...] = ()
    checkpoint_hash: str = ""
    receipt_references: tuple[str, ...] = ()
    error: str = ""


class HeartbeatGovernor:
    """Idempotent, resumable heartbeat state machine. It never executes tools itself."""

    def __init__(self) -> None:
        self._specs: dict[str, HeartbeatSpec] = {}
        self._runs: dict[str, HeartbeatRun] = {}
        self._by_idempotency: dict[str, str] = {}

    def register(self, spec: HeartbeatSpec) -> None:
        if spec.heartbeat_id in self._specs:
            raise ValueError("heartbeat_id must be unique")
        self._specs[spec.heartbeat_id] = spec

    def start(self, heartbeat_id: str, scheduled_for: str, idempotency_key: str) -> HeartbeatRun:
        _parse_time(scheduled_for)
        if not idempotency_key.strip():
            raise ValueError("idempotency_key required")
        existing_id = self._by_idempotency.get(idempotency_key)
        if existing_id:
            return self._runs[existing_id]
        if heartbeat_id not in self._specs:
            raise KeyError(heartbeat_id)
        run_id = str(uuid.uuid4())
        run = HeartbeatRun(run_id, heartbeat_id, idempotency_key, scheduled_for, HeartbeatRunStatus.RUNNING)
        self._runs[run_id] = run
        self._by_idempotency[idempotency_key] = run_id
        return run

    def checkpoint(self, run_id: str, step: str, state: Mapping[str, Any]) -> HeartbeatRun:
        run = self._runs[run_id]
        spec = self._specs[run.heartbeat_id]
        if run.status not in {HeartbeatRunStatus.RUNNING, HeartbeatRunStatus.PAUSED}:
            raise PermissionError("only active heartbeat runs can checkpoint")
        if step not in spec.steps:
            raise ValueError("step is not part of heartbeat spec")
        completed = tuple(dict.fromkeys((*run.completed_steps, step)))
        updated = replace(run, status=HeartbeatRunStatus.RUNNING, completed_steps=completed, checkpoint_hash=sha256_hex(state))
        self._runs[run_id] = updated
        return updated

    def pause(self, run_id: str) -> HeartbeatRun:
        run = self._runs[run_id]
        if run.status != HeartbeatRunStatus.RUNNING:
            raise PermissionError("only running heartbeat can pause")
        updated = replace(run, status=HeartbeatRunStatus.PAUSED)
        self._runs[run_id] = updated
        return updated

    def resume(self, run_id: str) -> HeartbeatRun:
        run = self._runs[run_id]
        if run.status != HeartbeatRunStatus.PAUSED:
            raise PermissionError("only paused heartbeat can resume")
        updated = replace(run, status=HeartbeatRunStatus.RUNNING)
        self._runs[run_id] = updated
        return updated

    def complete(self, run_id: str, receipt_references: tuple[str, ...]) -> HeartbeatRun:
        run = self._runs[run_id]
        spec = self._specs[run.heartbeat_id]
        missing = tuple(step for step in spec.steps if step not in run.completed_steps)
        if missing:
            raise PermissionError(f"heartbeat steps incomplete: {missing}")
        if not receipt_references:
            raise PermissionError("heartbeat completion requires receipts")
        updated = replace(run, status=HeartbeatRunStatus.COMPLETED, receipt_references=tuple(sorted(set(receipt_references))))
        self._runs[run_id] = updated
        return updated


@dataclass(frozen=True)
class SkillSpec:
    skill_id: str
    version: str
    purpose: str
    project_scope: tuple[str, ...]
    trigger_conditions: tuple[str, ...]
    non_trigger_conditions: tuple[str, ...]
    required_inputs: tuple[str, ...]
    expected_outputs: tuple[str, ...]
    supported_providers: tuple[str, ...]
    required_tools: tuple[str, ...]
    read_permissions: tuple[str, ...]
    write_permissions: tuple[str, ...]
    confirmation_requirements: tuple[str, ...]
    prohibited_actions: tuple[str, ...]
    evaluation_suite: tuple[str, ...]
    known_failure_modes: tuple[str, ...]
    rollback_version: str
    last_validated_at: str
    owning_maintainer: str
    maximum_autonomy: AutonomyLevel = AutonomyLevel.DRAFT

    def __post_init__(self) -> None:
        _nonblank((self.skill_id, self.version, self.purpose, self.owning_maintainer), "skill")
        if not re.fullmatch(r"\d+\.\d+\.\d+", self.version):
            raise ValueError("skill version must be semantic x.y.z")
        _parse_time(self.last_validated_at)
        if not self.trigger_conditions:
            raise ValueError("skill requires trigger conditions")
        if not self.evaluation_suite:
            raise ValueError("skill requires evaluation suite")


@dataclass(frozen=True)
class SkillUsage:
    skill_id: str
    version: str
    mission_id: str
    invoked_at: str
    successful: bool
    user_corrections: int = 0
    cost: float = 0.0
    latency_ms: int = 0


@dataclass(frozen=True)
class SkillHygieneFinding:
    code: str
    skill_ids: tuple[str, ...]
    evidence: str
    recommendation: str
    risk: str


class SkillRegistry:
    def __init__(self) -> None:
        self._skills: dict[tuple[str, str], SkillSpec] = {}
        self._active: dict[str, str] = {}
        self._usage: list[SkillUsage] = []

    @staticmethod
    def _version_key(version: str) -> tuple[int, int, int]:
        parts = tuple(int(part) for part in version.split("."))
        return parts[0], parts[1], parts[2]

    def register(self, skill: SkillSpec, *, activate: bool = False) -> None:
        key = (skill.skill_id, skill.version)
        if key in self._skills:
            raise ValueError("skill version already registered")
        self._skills[key] = skill
        if activate:
            current = self._active.get(skill.skill_id)
            if current and self._version_key(skill.version) <= self._version_key(current):
                raise ValueError("active skill version must increase")
            self._active[skill.skill_id] = skill.version

    def active(self, skill_id: str) -> SkillSpec:
        return self._skills[(skill_id, self._active[skill_id])]

    def route(self, *, project: str, signals: Iterable[str], available_tools: Iterable[str], requested_autonomy: AutonomyLevel) -> tuple[SkillSpec, ...]:
        signal_set = {s.casefold() for s in signals}
        tools = set(available_tools)
        routed = []
        for skill_id, version in self._active.items():
            skill = self._skills[(skill_id, version)]
            triggers = {t.casefold() for t in skill.trigger_conditions}
            non_triggers = {t.casefold() for t in skill.non_trigger_conditions}
            if project not in skill.project_scope and "*" not in skill.project_scope:
                continue
            if not (triggers & signal_set) or (non_triggers & signal_set):
                continue
            if not set(skill.required_tools).issubset(tools):
                continue
            if requested_autonomy > skill.maximum_autonomy:
                continue
            routed.append(skill)
        return tuple(sorted(routed, key=lambda item: item.skill_id))

    def record_usage(self, usage: SkillUsage) -> None:
        if (usage.skill_id, usage.version) not in self._skills:
            raise KeyError((usage.skill_id, usage.version))
        _parse_time(usage.invoked_at)
        if usage.user_corrections < 0 or usage.cost < 0 or usage.latency_ms < 0:
            raise ValueError("usage metrics cannot be negative")
        self._usage.append(usage)

    def hygiene(self, *, min_usage: int = 1, correction_rate_threshold: float = 0.4) -> tuple[SkillHygieneFinding, ...]:
        findings = []
        for skill_id, version in self._active.items():
            records = [u for u in self._usage if u.skill_id == skill_id and u.version == version]
            if len(records) < min_usage:
                findings.append(SkillHygieneFinding("UNUSED_OR_RARE", (skill_id,), f"usage_count={len(records)}", "review; archive only after criticality check", "deleting rare recovery skills can remove safety capability"))
            if records:
                corrected = sum(1 for item in records if item.user_corrections > 0)
                rate = corrected / len(records)
                if rate >= correction_rate_threshold:
                    findings.append(SkillHygieneFinding("HIGH_CORRECTION_RATE", (skill_id,), f"correction_rate={rate:.3f}", "rewrite and replay historical cases before promotion", "current behavior repeatedly misses user intent"))
        active = [self._skills[(sid, version)] for sid, version in self._active.items()]
        for index, left in enumerate(active):
            for right in active[index + 1:]:
                overlap = set(left.trigger_conditions) & set(right.trigger_conditions)
                if overlap and set(left.project_scope) & set(right.project_scope):
                    findings.append(SkillHygieneFinding("OVERLAPPING_TRIGGERS", tuple(sorted((left.skill_id, right.skill_id))), f"shared_triggers={sorted(overlap)}", "differentiate non-trigger rules or consolidate only if permissions match", "ambiguous routing can select the wrong authority surface"))
        return tuple(findings)
