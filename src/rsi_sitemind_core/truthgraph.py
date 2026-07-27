from __future__ import annotations

import enum
from dataclasses import dataclass, replace


class TruthState(str, enum.Enum):
    PLANNED = "PLANNED"
    ATTEMPTED = "ATTEMPTED"
    PARTIAL = "PARTIAL"
    COMPLETED_UNVERIFIED = "COMPLETED_UNVERIFIED"
    VERIFIED = "VERIFIED"
    FAILED = "FAILED"
    ROLLED_BACK = "ROLLED_BACK"
    SUPERSEDED = "SUPERSEDED"


@dataclass(frozen=True)
class TruthNode:
    node_id: str
    project: str
    claim: str
    state: TruthState
    evidence_references: tuple[str, ...] = ()
    supersedes: tuple[str, ...] = ()
    superseded_by: tuple[str, ...] = ()


class TruthGraph:
    TRANSITIONS = {
        TruthState.PLANNED: {TruthState.ATTEMPTED, TruthState.FAILED, TruthState.SUPERSEDED},
        TruthState.ATTEMPTED: {TruthState.PARTIAL, TruthState.COMPLETED_UNVERIFIED, TruthState.FAILED},
        TruthState.PARTIAL: {TruthState.ATTEMPTED, TruthState.COMPLETED_UNVERIFIED, TruthState.FAILED},
        TruthState.COMPLETED_UNVERIFIED: {TruthState.VERIFIED, TruthState.ATTEMPTED, TruthState.FAILED},
        TruthState.VERIFIED: {TruthState.ROLLED_BACK, TruthState.SUPERSEDED},
        TruthState.FAILED: {TruthState.ATTEMPTED, TruthState.SUPERSEDED},
        TruthState.ROLLED_BACK: {TruthState.ATTEMPTED, TruthState.SUPERSEDED},
        TruthState.SUPERSEDED: set(),
    }

    def __init__(self) -> None:
        self._nodes: dict[str, TruthNode] = {}

    def add(self, node: TruthNode) -> None:
        if node.node_id in self._nodes:
            raise ValueError("truth node id must be unique")
        if node.state == TruthState.VERIFIED and not node.evidence_references:
            raise PermissionError("verified truth requires evidence")
        self._nodes[node.node_id] = node

    def transition(self, node_id: str, target: TruthState, *, evidence_references: tuple[str, ...] = ()) -> TruthNode:
        node = self._nodes[node_id]
        if target not in self.TRANSITIONS[node.state]:
            raise PermissionError("invalid truth-state transition")
        evidence = tuple(sorted(set(node.evidence_references) | set(evidence_references)))
        if target == TruthState.VERIFIED and not evidence:
            raise PermissionError("verified truth requires evidence")
        updated = replace(node, state=target, evidence_references=evidence)
        self._nodes[node_id] = updated
        return updated

    def supersede(self, old_id: str, replacement: TruthNode) -> TruthNode:
        old = self._nodes[old_id]
        if old.state != TruthState.VERIFIED:
            raise PermissionError("only verified truth can be superseded")
        if old_id not in replacement.supersedes:
            replacement = replace(replacement, supersedes=tuple(sorted(set(replacement.supersedes) | {old_id})))
        self.add(replacement)
        self._nodes[old_id] = replace(old, state=TruthState.SUPERSEDED, superseded_by=(replacement.node_id,))
        return replacement
