import pytest

from rsi_sitemind_core.feedback import FeedbackEvent, FeedbackToCapabilityCompiler, ReplayScore
from rsi_sitemind_core.routing import ModelEndpoint, ProviderNeutralRouter, RouteRequest
from rsi_sitemind_core.truthgraph import TruthGraph, TruthNode, TruthState


def test_provider_router_is_policy_driven_and_returns_fallbacks():
    router = ProviderNeutralRouter()
    router.register(ModelEndpoint("provider-b", "model-2", ("research",), ("internal",), 200000, 4.0, 900))
    router.register(ModelEndpoint("provider-a", "model-1", ("research", "code"), ("internal",), 150000, 3.0, 1000))
    decision = router.route(RouteRequest(("research",), "internal", 100000, 5.0, 1200))
    assert decision.primary.provider_id == "provider-a"
    assert decision.fallbacks[0].provider_id == "provider-b"


def test_provider_router_fails_closed_when_privacy_policy_cannot_be_met():
    router = ProviderNeutralRouter()
    router.register(ModelEndpoint("provider-a", "model-1", ("research",), ("public",), 100000, 1.0, 500))
    with pytest.raises(LookupError):
        router.route(RouteRequest(("research",), "restricted", 1000, 2.0, 1000))


def event(event_id, session_id):
    return FeedbackEvent(event_id, session_id, "mission-1", "ORDERWEEDDC", "brand-voice", "UNWANTED_LIGHT_GREEN", "Use the approved dark green rather than light green", "Applied approved dark green", True, 0.95)


def test_feedback_compiler_requires_repetition_and_never_auto_promotes():
    compiler = FeedbackToCapabilityCompiler()
    assert compiler.compile((event("e1", "s1"),)) == ()
    candidates = compiler.compile((event("e1", "s1"), event("e2", "s2")))
    assert len(candidates) == 1
    assert candidates[0].state == "PROPOSED"
    assert candidates[0].project_scope == ("ORDERWEEDDC",)


def test_replay_recommendation_rejects_safety_regression():
    compiler = FeedbackToCapabilityCompiler()
    baseline = ReplayScore(.8, .8, .8, .8, .8, 1.0, 1000, 1.0, 1, 1)
    candidate = ReplayScore(.9, .9, .9, .9, .9, .9, 900, .9, 0, 0)
    recommendation = compiler.recommend(baseline, candidate)
    assert not recommendation.promote
    assert any("safety" in reason for reason in recommendation.reasons)


def test_truthgraph_refuses_all_legacy_unbound_verified_claims():
    graph = TruthGraph()
    with pytest.raises(PermissionError):
        graph.add(TruthNode("node-0", "CANA", "system deployed", TruthState.VERIFIED))
    graph.add(TruthNode("node-1", "CANA", "module planned", TruthState.PLANNED))
    graph.transition("node-1", TruthState.ATTEMPTED)
    graph.transition("node-1", TruthState.COMPLETED_UNVERIFIED)
    with pytest.raises(PermissionError):
        graph.transition("node-1", TruthState.VERIFIED, evidence_references=("commit-sha", "test-report"))
