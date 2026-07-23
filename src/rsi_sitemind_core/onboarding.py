from __future__ import annotations

import hashlib
import re
import secrets
from dataclasses import replace
from urllib.parse import urlparse

from .models import DomainTwin


class DomainOnboardingService:
    SUPPORTED_METHODS = frozenset({
        "DNS_TXT", "HTML_FILE", "CMS_OAUTH", "CMS_PLUGIN", "GITHUB_APP",
        "SEARCH_CONSOLE", "ANALYTICS", "ADS", "REVENUE_SYSTEM", "SIGNED_OWNER_RECEIPT",
    })

    def __init__(self):
        self._challenges: dict[tuple[str, str], str] = {}

    @staticmethod
    def normalize_domain(value: str) -> str:
        raw = value.strip().lower()
        parsed = urlparse(raw if "://" in raw else f"https://{raw}")
        host = (parsed.hostname or "").rstrip(".")
        if not host or len(host) > 253 or not re.fullmatch(r"[a-z0-9.-]+", host):
            raise ValueError("invalid domain")
        if ".." in host or host.startswith("-") or host.endswith("-"):
            raise ValueError("invalid domain")
        return host

    def begin(self, *, tenant_id: str, business_id: str, site_id: str, domain: str) -> DomainTwin:
        if not all(x.strip() for x in (tenant_id, business_id, site_id)):
            raise ValueError("tenant, business and site identifiers are required")
        return DomainTwin(
            tenant_id=tenant_id,
            business_id=business_id,
            site_id=site_id,
            domain=self.normalize_domain(domain),
            ownership_status="UNVERIFIED",
            management_mode="PUBLIC_ANALYSIS",
            unknowns=("ownership_not_verified", "authorized_connectors_unknown"),
        )

    def issue_challenge(self, twin: DomainTwin, method: str) -> str:
        if method not in self.SUPPORTED_METHODS:
            raise ValueError("unsupported verification method")
        token = f"rsi-verify={secrets.token_urlsafe(24)}"
        self._challenges[(twin.site_id, method)] = token
        return token

    def verify(self, twin: DomainTwin, method: str, observed_token: str) -> DomainTwin:
        expected = self._challenges.get((twin.site_id, method))
        if expected is None or not secrets.compare_digest(expected, observed_token):
            raise PermissionError("ownership verification failed")
        receipt = hashlib.sha256(f"{twin.tenant_id}:{twin.site_id}:{method}:{expected}".encode()).hexdigest()
        self._challenges.pop((twin.site_id, method), None)
        return replace(
            twin,
            ownership_status="VERIFIED",
            management_mode="AUTHORIZED_READ_ONLY",
            verification_method=method,
            verification_receipt_id=receipt,
            unknowns=tuple(u for u in twin.unknowns if u != "ownership_not_verified"),
        )

    @staticmethod
    def can_manage(twin: DomainTwin) -> bool:
        return twin.ownership_status == "VERIFIED" and twin.management_mode != "PUBLIC_ANALYSIS"
