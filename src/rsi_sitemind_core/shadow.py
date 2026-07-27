from __future__ import annotations

import time
from dataclasses import asdict, dataclass
from typing import Any, Mapping

from .canonical import sha256_hex
from .work_os import AutonomyLevel, HeartbeatGovernor, HeartbeatSpec


@dataclass(frozen=True)
class ShadowSource:
    source_id: str
    freshness_seconds: int
    digest: str


@dataclass(frozen=True)
class ShadowHeartbeatReceipt:
    receipt_id: str
    heartbeat_id: str
    project: str
    scheduled_window: str
    idempotency_key: str
    source_inventory: tuple[ShadowSource, ...]
    completed_steps: tuple[str, ...]
    checkpoint_hashes: tuple[str, ...]
    interruption_resumed: bool
    ranked_findings: tuple[str, ...]
    false_positives: int
    false_negatives: int
    missing_evidence: tuple[str, ...]
    suggested_actions: tuple[str, ...]
    cost: float
    latency_ms: int
    autonomy_level: int
    write_actions: tuple[str, ...]
    status: str


class ReadOnlyShadowHeartbeatRunner:
    """Deterministic heartbeat rehearsal over caller-supplied snapshots only."""

    def __init__(self, governor: HeartbeatGovernor):
        self.governor = governor
        self._receipts_by_key: dict[str, ShadowHeartbeatReceipt] = {}

    def run(self, spec: HeartbeatSpec, *, scheduled_window: str, sources: tuple[ShadowSource, ...], snapshot: Mapping[str, Any], findings: tuple[str, ...] = (), missing_evidence: tuple[str, ...] = (), suggested_actions: tuple[str, ...] = (), false_positives: int = 0, false_negatives: int = 0, simulate_interruption: bool = False, cost: float = 0.0) -> ShadowHeartbeatReceipt:
        if spec.max_autonomy_level != AutonomyLevel.OBSERVE:
            raise PermissionError("shadow heartbeat must be OBSERVE-only")
        if false_positives < 0 or false_negatives < 0 or cost < 0:
            raise ValueError("shadow metrics cannot be negative")
        start = time.perf_counter()
        key = sha256_hex({"heartbeat": spec.heartbeat_id, "project": spec.project, "window": scheduled_window})
        existing = self._receipts_by_key.get(key)
        if existing is not None:
            return existing
        run = self.governor.start(spec.heartbeat_id, scheduled_window, key)
        checkpoints: list[str] = []
        for index, step in enumerate(spec.steps):
            if simulate_interruption and index == 1:
                self.governor.pause(run.run_id)
                self.governor.resume(run.run_id)
            state = {"step": step, "snapshot_digest": sha256_hex(dict(snapshot)), "sources": [asdict(source) for source in sources]}
            run = self.governor.checkpoint(run.run_id, step, state)
            checkpoints.append(run.checkpoint_hash)
        provisional_id = sha256_hex({"run": run.run_id, "key": key, "checkpoints": checkpoints})
        run = self.governor.complete(run.run_id, (provisional_id,))
        receipt = ShadowHeartbeatReceipt(provisional_id, spec.heartbeat_id, spec.project, scheduled_window, key, sources, run.completed_steps, tuple(checkpoints), simulate_interruption, findings, false_positives, false_negatives, missing_evidence, suggested_actions, cost, max(0, int((time.perf_counter() - start) * 1000)), int(spec.max_autonomy_level), (), run.status.value)
        self._receipts_by_key[key] = receipt
        return receipt
