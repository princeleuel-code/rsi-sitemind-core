from __future__ import annotations
from dataclasses import dataclass, field
from pathlib import PurePosixPath

@dataclass(frozen=True)
class CapabilityRecord:
    capability_id: str
    upstream_components: tuple[str, ...]
    rsi_use_case: str
    required_authorities: tuple[str, ...]
    prohibited_authorities: tuple[str, ...]
    required_tests: tuple[str, ...]
    security_classification: str = "HIGH"

@dataclass(frozen=True)
class UpgradeAnalysis:
    upstream_sha: str
    changed_paths: tuple[str, ...]
    affected_subsystems: tuple[str, ...]
    required_gates: tuple[str, ...]
    risk_flags: tuple[str, ...]

class CapabilityRegistry:
    def __init__(self):
        self._records: dict[str, CapabilityRecord] = {}
    def register(self, record: CapabilityRecord) -> None:
        if not record.capability_id or record.capability_id in self._records:
            raise ValueError("capability id must be unique")
        self._records[record.capability_id]=record
    def affected(self, changed_paths: tuple[str, ...]) -> tuple[CapabilityRecord, ...]:
        out=[]
        for record in self._records.values():
            if any(any(path.startswith(prefix) for prefix in record.upstream_components) for path in changed_paths):
                out.append(record)
        return tuple(sorted(out,key=lambda r:r.capability_id))

class UpstreamChangeAnalyzer:
    MAP={
        "agent/":"agent_loop", "run_agent.py":"agent_loop", "tools/":"tools",
        "gateway/":"gateway", "cron/":"scheduler", "plugins/memory/":"memory",
        "skills/":"skills", "hermes_cli/":"cli_config", "acp_adapter/":"acp",
        "tests/":"tests", "website/docs/user-guide/security":"security_docs",
    }
    BASE_GATES=("upstream_tests","rsi_contracts","tenant_isolation","authority_bypass","receipt_integrity")
    HIGH_RISK={"tools","gateway","scheduler","memory","skills","agent_loop","cli_config"}
    def analyze(self, upstream_sha: str, changed_paths: tuple[str, ...]) -> UpgradeAnalysis:
        if len(upstream_sha)!=40 or any(c not in '0123456789abcdef' for c in upstream_sha.lower()):
            raise ValueError("exact 40-character upstream SHA required")
        subsystems=set()
        for raw in changed_paths:
            path=str(PurePosixPath(raw))
            for prefix,name in self.MAP.items():
                if path==prefix or path.startswith(prefix): subsystems.add(name)
        gates=set(self.BASE_GATES)
        flags=set()
        if subsystems & self.HIGH_RISK:
            gates.update(("memory_skill_poisoning","shadow_runtime","canary","rollback"))
            flags.add("HIGH_RISK_RUNTIME_CHANGE")
        if "tools" in subsystems:
            gates.update(("connector_contracts","credential_flow","egress_control"))
        if "gateway" in subsystems or "memory" in subsystems:
            gates.add("cross_channel_privacy")
        if not changed_paths:
            flags.add("EMPTY_CHANGESET")
        return UpgradeAnalysis(upstream_sha,tuple(sorted(changed_paths)),tuple(sorted(subsystems)),tuple(sorted(gates)),tuple(sorted(flags)))

class CompatibilityGraph:
    def __init__(self):
        self._edges: dict[str,set[str]]={}
    def bind(self, component: str, contract_test: str) -> None:
        if not component or not contract_test: raise ValueError("component and test required")
        self._edges.setdefault(component,set()).add(contract_test)
    def required_tests(self, subsystems: tuple[str,...]) -> tuple[str,...]:
        tests=set()
        for subsystem in subsystems: tests.update(self._edges.get(subsystem,set()))
        return tuple(sorted(tests))
