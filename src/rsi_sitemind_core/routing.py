from __future__ import annotations

from dataclasses import dataclass


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

    def __post_init__(self) -> None:
        if not self.provider_id.strip() or not self.model_id.strip():
            raise ValueError("provider_id and model_id required")
        if self.maximum_context_tokens <= 0 or self.estimated_cost_per_million_tokens < 0 or self.p95_latency_ms <= 0:
            raise ValueError("invalid endpoint limits")


@dataclass(frozen=True)
class RouteRequest:
    required_capabilities: tuple[str, ...]
    privacy_class: str
    minimum_context_tokens: int
    maximum_cost_per_million_tokens: float
    maximum_latency_ms: int
    excluded_providers: tuple[str, ...] = ()


@dataclass(frozen=True)
class RouteDecision:
    primary: ModelEndpoint
    fallbacks: tuple[ModelEndpoint, ...]
    reasons: tuple[str, ...]


class ProviderNeutralRouter:
    """Deterministic provider-neutral routing. Provider names carry no built-in preference."""

    def __init__(self) -> None:
        self._endpoints: dict[tuple[str, str], ModelEndpoint] = {}

    def register(self, endpoint: ModelEndpoint) -> None:
        key = (endpoint.provider_id, endpoint.model_id)
        if key in self._endpoints:
            raise ValueError("endpoint already registered")
        self._endpoints[key] = endpoint

    def route(self, request: RouteRequest) -> RouteDecision:
        required = set(request.required_capabilities)
        excluded = set(request.excluded_providers)
        eligible = [
            endpoint for endpoint in self._endpoints.values()
            if endpoint.enabled
            and endpoint.provider_id not in excluded
            and required.issubset(set(endpoint.capabilities))
            and request.privacy_class in endpoint.privacy_classes
            and endpoint.maximum_context_tokens >= request.minimum_context_tokens
            and endpoint.estimated_cost_per_million_tokens <= request.maximum_cost_per_million_tokens
            and endpoint.p95_latency_ms <= request.maximum_latency_ms
        ]
        if not eligible:
            raise LookupError("no endpoint satisfies capability, privacy, context, cost, and latency policy")
        eligible.sort(key=lambda item: (item.estimated_cost_per_million_tokens, item.p95_latency_ms, -item.maximum_context_tokens, item.provider_id, item.model_id))
        return RouteDecision(eligible[0], tuple(eligible[1:]), ("all hard policies satisfied", "ordered by cost, latency, context, stable identifier"))
