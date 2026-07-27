from __future__ import annotations

from dataclasses import dataclass, replace


@dataclass(frozen=True)
class ModelEndpoint:
    provider_id: str
    model_id: str
    capabilities: tuple[str, ...]
    privacy_classes: tuple[str, ...]
    maximum_context_tokens: int
    estimated_cost_per_million_tokens: float
    p95_latency_ms: int
    enabled: bool = True
    available: bool = True
    authenticated: bool = True
    rate_limited: bool = False
    revoked: bool = False
    emergency_disabled: bool = False
    data_regions: tuple[str, ...] = ("global",)
    response_contract_valid: bool = True
    stream_healthy: bool = True
    capability_evidence_refs: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.provider_id.strip() or not self.model_id.strip():
            raise ValueError("provider_id and model_id required")
        if self.maximum_context_tokens <= 0 or self.estimated_cost_per_million_tokens < 0 or self.p95_latency_ms <= 0:
            raise ValueError("invalid endpoint limits")
        if not self.data_regions:
            raise ValueError("at least one data region required")


@dataclass(frozen=True)
class RouteRequest:
    required_capabilities: tuple[str, ...]
    privacy_class: str
    minimum_context_tokens: int
    maximum_cost_per_million_tokens: float
    maximum_latency_ms: int
    excluded_providers: tuple[str, ...] = ()
    allowed_data_regions: tuple[str, ...] = ("global",)
    require_validated_response_contract: bool = True
    require_healthy_streaming: bool = True

    def __post_init__(self) -> None:
        if self.minimum_context_tokens <= 0 or self.maximum_cost_per_million_tokens < 0 or self.maximum_latency_ms <= 0:
            raise ValueError("invalid route policy")
        if not self.privacy_class.strip() or not self.allowed_data_regions:
            raise ValueError("privacy class and data regions required")


@dataclass(frozen=True)
class RouteDecision:
    primary: ModelEndpoint
    fallbacks: tuple[ModelEndpoint, ...]
    reasons: tuple[str, ...]
    capability_evidence: tuple[str, ...] = ()


class ProviderNeutralRouter:
    """Deterministic hard-policy routing; provider names are only final stable tie-breakers."""

    def __init__(self) -> None:
        self._endpoints: dict[tuple[str, str], ModelEndpoint] = {}

    def register(self, endpoint: ModelEndpoint) -> None:
        key = (endpoint.provider_id, endpoint.model_id)
        if key in self._endpoints:
            raise ValueError("endpoint already registered")
        self._endpoints[key] = endpoint

    def update_operational_state(self, provider_id: str, model_id: str, **changes: object) -> ModelEndpoint:
        key = (provider_id, model_id)
        endpoint = self._endpoints[key]
        allowed = {"enabled", "available", "authenticated", "rate_limited", "revoked", "emergency_disabled", "response_contract_valid", "stream_healthy"}
        if set(changes) - allowed:
            raise ValueError("only operational state may be updated")
        updated = replace(endpoint, **changes)
        self._endpoints[key] = updated
        return updated

    def route(self, request: RouteRequest) -> RouteDecision:
        required = set(request.required_capabilities)
        excluded = set(request.excluded_providers)
        regions = set(request.allowed_data_regions)
        eligible = []
        for endpoint in self._endpoints.values():
            if not endpoint.enabled or not endpoint.available or not endpoint.authenticated:
                continue
            if endpoint.rate_limited or endpoint.revoked or endpoint.emergency_disabled:
                continue
            if endpoint.provider_id in excluded:
                continue
            if not required.issubset(set(endpoint.capabilities)):
                continue
            if request.privacy_class not in endpoint.privacy_classes:
                continue
            if endpoint.maximum_context_tokens < request.minimum_context_tokens:
                continue
            if endpoint.estimated_cost_per_million_tokens > request.maximum_cost_per_million_tokens:
                continue
            if endpoint.p95_latency_ms > request.maximum_latency_ms:
                continue
            if not (regions & set(endpoint.data_regions)):
                continue
            if request.require_validated_response_contract and not endpoint.response_contract_valid:
                continue
            if request.require_healthy_streaming and not endpoint.stream_healthy:
                continue
            eligible.append(endpoint)
        if not eligible:
            raise LookupError("no endpoint satisfies capability, privacy, region, context, cost, latency, health and revocation policy")
        eligible.sort(key=lambda item: (
            item.estimated_cost_per_million_tokens,
            item.p95_latency_ms,
            -item.maximum_context_tokens,
            item.provider_id,
            item.model_id,
        ))
        evidence = tuple(sorted({ref for endpoint in eligible for ref in endpoint.capability_evidence_refs}))
        return RouteDecision(
            eligible[0], tuple(eligible[1:]),
            ("all hard policies satisfied", "ordered by cost, latency, context, then stable identifiers only"),
            evidence,
        )
