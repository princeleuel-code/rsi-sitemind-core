from __future__ import annotations
import datetime as dt
import enum
from dataclasses import dataclass, replace
from .models import DomainTwin

class DomainMode(str, enum.Enum):
    PUBLIC_ANALYSIS="PUBLIC_ANALYSIS"
    AUTHORIZED_READ_ONLY="AUTHORIZED_READ_ONLY"
    PROPOSAL_ONLY="PROPOSAL_ONLY"
    DRAFT_EXECUTION="DRAFT_EXECUTION"
    BOUNDED_PRODUCTION="BOUNDED_PRODUCTION"
    REVOKED="REVOKED"

@dataclass(frozen=True)
class DomainRuntimeState:
    twin: DomainTwin
    mode: DomainMode
    next_run_at: str
    last_run_at: str=""
    paused: bool=False
    emergency_revoked: bool=False

class DomainManagementRuntime:
    TRANSITIONS={
        DomainMode.PUBLIC_ANALYSIS:{DomainMode.AUTHORIZED_READ_ONLY,DomainMode.REVOKED},
        DomainMode.AUTHORIZED_READ_ONLY:{DomainMode.PROPOSAL_ONLY,DomainMode.REVOKED},
        DomainMode.PROPOSAL_ONLY:{DomainMode.DRAFT_EXECUTION,DomainMode.AUTHORIZED_READ_ONLY,DomainMode.REVOKED},
        DomainMode.DRAFT_EXECUTION:{DomainMode.BOUNDED_PRODUCTION,DomainMode.PROPOSAL_ONLY,DomainMode.REVOKED},
        DomainMode.BOUNDED_PRODUCTION:{DomainMode.DRAFT_EXECUTION,DomainMode.REVOKED},
        DomainMode.REVOKED:set(),
    }
    CYCLE=("DISCOVER","MODEL","OBSERVE","VERIFY","DIAGNOSE","PRIORITIZE","PROPOSE","CHALLENGE","GOVERN","EXECUTE","VERIFY_EXTERNAL_STATE","MEASURE","ATTRIBUTE","LEARN","PROMOTE_OR_ROLL_BACK")
    @staticmethod
    def _parse(value:str)->dt.datetime:
        v=value[:-1]+'+00:00' if value.endswith('Z') else value
        parsed=dt.datetime.fromisoformat(v)
        if parsed.tzinfo is None: raise ValueError("timezone required")
        return parsed.astimezone(dt.timezone.utc)
    def transition(self,state:DomainRuntimeState,target:DomainMode)->DomainRuntimeState:
        if target not in self.TRANSITIONS[state.mode]: raise PermissionError("invalid domain mode transition")
        if target not in {DomainMode.PUBLIC_ANALYSIS,DomainMode.REVOKED} and state.twin.ownership_status!='VERIFIED':
            raise PermissionError("verified ownership required")
        return replace(state,mode=target,emergency_revoked=(target==DomainMode.REVOKED),paused=(target==DomainMode.REVOKED))
    def due(self,state:DomainRuntimeState,now:dt.datetime)->bool:
        if state.paused or state.emergency_revoked or state.mode==DomainMode.REVOKED: return False
        return now.astimezone(dt.timezone.utc)>=self._parse(state.next_run_at)
    def cycle_plan(self,state:DomainRuntimeState)->tuple[str,...]:
        if state.mode==DomainMode.PUBLIC_ANALYSIS:
            return self.CYCLE[:7]
        if state.mode==DomainMode.AUTHORIZED_READ_ONLY:
            return self.CYCLE[:8]
        if state.mode==DomainMode.PROPOSAL_ONLY:
            return self.CYCLE[:9]
        return self.CYCLE
