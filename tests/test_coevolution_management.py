import datetime as dt, sys
from dataclasses import replace
from pathlib import Path
sys.path.insert(0,str(Path(__file__).parents[1]/'src'))
from rsi_sitemind_core import CapabilityRecord, CapabilityRegistry, CompatibilityGraph, DomainManagementRuntime, DomainMode, DomainOnboardingService, DomainRuntimeState, UpstreamChangeAnalyzer

def test_upstream_analyzer_adds_high_risk_gates():
    a=UpstreamChangeAnalyzer().analyze('a'*40,('tools/terminal_tool.py','plugins/memory/provider.py'))
    assert 'authority_bypass' in a.required_gates
    assert 'memory_skill_poisoning' in a.required_gates
    assert 'credential_flow' in a.required_gates
    assert 'HIGH_RISK_RUNTIME_CHANGE' in a.risk_flags

def test_capability_registry_and_graph():
    r=CapabilityRegistry();r.register(CapabilityRecord('delegation',('tools/delegate_tool.py',),'parallel workers',('spawn',),('grant_authority',),('test_depth',)))
    assert r.affected(('tools/delegate_tool.py',))[0].capability_id=='delegation'
    g=CompatibilityGraph();g.bind('tools','test_governed_proxy');assert g.required_tests(('tools',))==('test_governed_proxy',)

def test_domain_runtime_never_promotes_unverified_domain():
    svc=DomainOnboardingService(); twin=svc.begin(tenant_id='t',business_id='b',site_id='s',domain='example.com')
    state=DomainRuntimeState(twin,DomainMode.PUBLIC_ANALYSIS,'2026-07-23T16:00:00Z')
    runtime=DomainManagementRuntime()
    try: runtime.transition(state,DomainMode.AUTHORIZED_READ_ONLY)
    except PermissionError: pass
    else: raise AssertionError('unverified domain promoted')
    token=svc.issue_challenge(twin,'DNS_TXT'); verified=svc.verify(twin,'DNS_TXT',token)
    state=replace(state,twin=verified)
    state=runtime.transition(state,DomainMode.AUTHORIZED_READ_ONLY)
    assert state.mode==DomainMode.AUTHORIZED_READ_ONLY
    assert runtime.due(state,dt.datetime(2026,7,23,16,1,tzinfo=dt.timezone.utc))
    assert 'EXECUTE' not in runtime.cycle_plan(state)
