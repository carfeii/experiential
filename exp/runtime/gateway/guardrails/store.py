"""Resolve platform and identity policies through one scoped policy store."""

from __future__ import annotations

from collections.abc import Iterable
from typing import Protocol

from exp.runtime.gateway.contracts import IdentityId, OrganizationId
from exp.runtime.gateway.guardrails.contracts import GuardrailPolicy


class GuardrailPolicyStore(Protocol):
    """Resolve a frozen ordered policy set for authenticated authority."""

    def policies_for(
        self, organization_id: OrganizationId, identity_id: IdentityId
    ) -> tuple[GuardrailPolicy, ...]:
        """Return every applicable policy, with authenticated decision metadata."""
        ...


class MappingGuardrailStore:
    """Operator-owned scope resolution; identity assignments cannot replace global checks."""

    def __init__(self, policies: Iterable[GuardrailPolicy] = ()) -> None:
        """Index global policies and one assignment per identity, rejecting duplicates."""
        self._platform: list[GuardrailPolicy] = []
        self._identities: dict[tuple[str, str], GuardrailPolicy] = {}
        ids: set[str] = set()
        for policy in policies:
            if policy.policy_id in ids:
                raise ValueError("guardrail policy IDs must be unique")
            ids.add(policy.policy_id)
            if policy.organization_id is None or policy.identity_id is None:
                self._platform.append(policy)
                continue
            key = (policy.organization_id, policy.identity_id)
            if key in self._identities:
                raise ValueError("guardrail policies must be unique per organization and identity")
            self._identities[key] = policy

    def policies_for(
        self, organization_id: OrganizationId, identity_id: IdentityId
    ) -> tuple[GuardrailPolicy, ...]:
        """Apply platform policies first, followed by this identity's optional policy."""
        assigned = self._identities.get((organization_id, identity_id))
        return tuple(p.bind(organization_id, identity_id) for p in self._platform) + (
            () if assigned is None else (assigned,)
        )
