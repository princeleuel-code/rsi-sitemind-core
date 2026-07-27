import datetime as dt
from dataclasses import replace

import pytest

from rsi_sitemind_core.work_os import (
    AutonomyLevel, DurableMemory, HeartbeatGovernor, HeartbeatKind, HeartbeatRunStatus,
    HeartbeatSpec, MemoryRegistry, MemoryStatus, MissionRegistry, MissionStatus,
    MissionWorkspace, SkillRegistry, SkillSpec, SkillUsage,
)

NOW = "2026-07-26T20:00:00Z"


def memory(object_id="mem-1", payload=None, **changes):
    base = DurableMemory(
        object_id=object_id, object_type="decision", project="CANA", scope="platform",
        claim_key="provider-law", payload=payload or {"neutral": True}, source="user-directive",
        author="user", created_at=NOW, last_verified_at=NOW, confidence=1.0,
        review_after="2027-01-01T00:00:00Z", allowed_consumers=("Hermes",),
    )
    return replace(base, **changes)


def mission(status=MissionStatus.PLANNED):
    return MissionWorkspace(
        mission_id="mission-1", title="Build vault", owner="Hermes", project="CANA",
        objective="Create a verified canonical vault", status=status, priority=90,
        autonomy_level=AutonomyLevel.DRAFT, allowed_tools=("filesystem",),
        allowed_data_sources=("repository",), blocked_actions=("production_deploy",), dependencies=(),
        success_criteria=("required directories exist",), verification_method=("vault validator passes",),
        rollback_method=("delete candidate branch",), next_review="2026-07-27T09:00:00Z",
    )


def skill(skill_id="evidence-verifier", triggers=("verify",), non_triggers=("medical",)):
    return SkillSpec(
        skill_id=skill_id, version="1.0.0", purpose="verify claims", project_scope=("CANA",),
        trigger_conditions=triggers, non_trigger_conditions=non_triggers,
        required_inputs=("claim",), expected_outputs=("receipt",), supported_providers=("*",),
        required_tools=("evidence-store",), read_permissions=("receipts",), write_permissions=("candidate-reports",),
        confirmation_requirements=("external-write",), prohibited_actions=("self-promote",),
        evaluation_suite=("evidence-gate",), known_failure_modes=("missing-source",), rollback_version="0.9.0",
        last_validated_at=NOW, owning_maintainer="CANA", maximum_autonomy=AutonomyLevel.DRAFT,
    )


def test_memory_duplicate_contradiction_and_supersession_are_explicit():
    registry = MemoryRegistry()
    assert registry.register(memory()).outcome == "REGISTERED"
    duplicate = registry.register(memory("mem-2"))
    assert duplicate.outcome == "DUPLICATE" and duplicate.duplicate_of == "mem-1"
    conflict = registry.register(memory("mem-3", {"neutral": False}))
    assert conflict.outcome == "CONTRADICTION"
    assert registry.get("mem-1").status == MemoryStatus.DISPUTED
    assert registry.get("mem-3").status == MemoryStatus.DISPUTED


def test_memory_stale_detection_requires_explicit_review_date():
    registry = MemoryRegistry()
    registry.register(memory(review_after="2026-07-26T19:00:00Z"))
    stale = registry.stale(dt.datetime(2026, 7, 26, 20, tzinfo=dt.timezone.utc))
    assert [item.object_id for item in stale] == ["mem-1"]


def test_mission_cannot_be_verified_without_receipt():
    registry = MissionRegistry()
    registry.create(mission())
    registry.transition("mission-1", MissionStatus.ACTIVE)
    registry.transition("mission-1", MissionStatus.COMPLETED_UNVERIFIED)
    with pytest.raises(PermissionError):
        registry.transition("mission-1", MissionStatus.VERIFIED)
    verified = registry.transition("mission-1", MissionStatus.VERIFIED, receipt_references=("receipt-1",))
    assert verified.status == MissionStatus.VERIFIED


def test_heartbeat_is_idempotent_resumable_and_receipt_gated():
    spec = HeartbeatSpec("morning", HeartbeatKind.MORNING_INTELLIGENCE, "CANA", AutonomyLevel.OBSERVE, ("inspect", "rank"))
    governor = HeartbeatGovernor()
    governor.register(spec)
    first = governor.start("morning", NOW, "morning:2026-07-26")
    replay = governor.start("morning", NOW, "morning:2026-07-26")
    assert first.run_id == replay.run_id
    first = governor.checkpoint(first.run_id, "inspect", {"open": 3})
    paused = governor.pause(first.run_id)
    assert paused.status == HeartbeatRunStatus.PAUSED
    governor.resume(first.run_id)
    governor.checkpoint(first.run_id, "rank", {"priority": ["mission-1"]})
    with pytest.raises(PermissionError):
        governor.complete(first.run_id, ())
    completed = governor.complete(first.run_id, ("receipt-heartbeat",))
    assert completed.status == HeartbeatRunStatus.COMPLETED


def test_skill_router_enforces_scope_tools_non_triggers_and_autonomy():
    registry = SkillRegistry()
    registry.register(skill(), activate=True)
    routed = registry.route(project="CANA", signals=("verify",), available_tools=("evidence-store",), requested_autonomy=AutonomyLevel.DRAFT)
    assert [item.skill_id for item in routed] == ["evidence-verifier"]
    assert not registry.route(project="CANA", signals=("verify", "medical"), available_tools=("evidence-store",), requested_autonomy=AutonomyLevel.DRAFT)
    assert not registry.route(project="CANA", signals=("verify",), available_tools=(), requested_autonomy=AutonomyLevel.DRAFT)
    assert not registry.route(project="CANA", signals=("verify",), available_tools=("evidence-store",), requested_autonomy=AutonomyLevel.APPROVED_EXTERNAL)


def test_skill_hygiene_detects_overlap_and_correction_pressure():
    registry = SkillRegistry()
    registry.register(skill(), activate=True)
    registry.register(replace(skill("claim-checker"), version="1.0.0"), activate=True)
    registry.record_usage(SkillUsage("evidence-verifier", "1.0.0", "m1", NOW, False, user_corrections=1))
    findings = registry.hygiene(min_usage=1, correction_rate_threshold=0.5)
    codes = {finding.code for finding in findings}
    assert "HIGH_CORRECTION_RATE" in codes
    assert "OVERLAPPING_TRIGGERS" in codes
