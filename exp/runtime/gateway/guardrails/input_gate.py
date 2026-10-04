"""Overlap mandatory input inspection with generation, never with response release."""

from __future__ import annotations

import json
import time
from concurrent.futures import Future
from dataclasses import dataclass
from typing import TYPE_CHECKING

from exp.common.core.artifacts import JsonObject
from exp.runtime.gateway.contracts import (
    AuthorizationSnapshot,
    GatewayEvent,
    GatewayFailure,
    GatewayFailureClass,
    GatewayRequest,
)
from exp.runtime.gateway.guardrails.bounded import start_on_native_loop
from exp.runtime.gateway.guardrails.contracts import GuardrailPolicy, GuardrailRejected

if TYPE_CHECKING:
    from exp.runtime.gateway.guardrails.enforcement import GuardrailEngine
    from exp.runtime.gateway.native_execution import InflightRequest


def discard_input_gate(entry: InflightRequest | None) -> None:
    """Cancel inspection after removing its request from the accounting registry."""
    if entry is not None and entry.input_guardrail_gate is not None:
        entry.input_guardrail_gate.cancel()


def can_overlap_input(engine: GuardrailEngine | None, request: GatewayRequest) -> bool:
    """Permit ordinary text/function generation, keeping hosted actions behind inspection."""
    return (
        engine is not None
        and engine.mandatory_policy is not None
        and engine.mandatory_policy.input_execution == "parallel"
        and not request.provider_native_tools
        and not request.provider_server_tools
        and request.web_search is None
        and request.tool_search is None
        and request.service_tier is None
    )


def denied_input_failure(failure: GatewayFailure | None = None) -> GatewayFailure:
    """Mark trusted input denials for zero customer settlement, retaining provider usage."""
    failure = failure or GatewayFailure(
        failure_class=GatewayFailureClass.UNAVAILABLE,
        safe_message="Content inspection is unavailable. Retry later.",
    )
    return failure.model_copy(
        update={"safe_details": {**failure.safe_details, "input_guardrail_denied": True}}
    )


@dataclass
class InputGuardrailGate:
    """One immutable input decision owned by one admitted request.

    Attributes:
        future: Shared-engine inspect task on the existing callback loop.
        deadline_monotonic: Original request deadline; no poll renews it.
    """

    future: Future[None]
    deadline_monotonic: float

    def decision(self) -> JsonObject:
        """Poll without blocking a bridge worker or logging inspected content."""
        if not self.future.done() and time.monotonic() >= self.deadline_monotonic:
            self.future.cancel()
        if not self.future.done():
            return {"action": "pending"}
        try:
            self.future.result()
        except GuardrailRejected as exc:
            failure = denied_input_failure(exc.failure)
        except Exception:  # noqa: BLE001 - classifier details never leave the engine.
            failure = denied_input_failure()
        else:
            return {"action": "allow"}
        return {"action": "error", "failure": failure.model_dump(mode="json")}

    def settlement_failure(self) -> GatewayFailure | None:
        """Fail unapproved work closed, including a disconnect before classification."""
        decision = self.decision()
        if decision["action"] == "allow":
            return None
        if decision["action"] == "pending":
            self.future.cancel()
            return denied_input_failure()
        return GatewayFailure.model_validate(decision["failure"])

    def cancel(self) -> None:
        """Cancel request-owned inspection when no consumer can use its verdict."""
        self.future.cancel()


async def _inspect_subjects(
    engine: GuardrailEngine,
    policy: GuardrailPolicy,
    subjects: tuple[GatewayRequest, ...],
    deadline_monotonic: float,
) -> None:
    """Check original intent, customer rewrites, and recovered continuation plaintext."""
    inspected: list[GatewayRequest] = []
    for subject in subjects:
        if subject not in inspected:
            await engine.enforce_input(
                policy=policy, request=subject, deadline_monotonic=deadline_monotonic
            )
            inspected.append(subject)


def start_input_gate(
    engine: GuardrailEngine,
    authorization: AuthorizationSnapshot,
    subjects: tuple[GatewayRequest, ...],
    deadline_monotonic: float,
) -> InputGuardrailGate:
    """Freeze policy authority and start the existing bounded engine before dispatch."""
    mandatory = engine.mandatory_policy
    if mandatory is None or mandatory.input_execution != "parallel":
        raise ValueError("parallel input inspection requires an operator-owned parallel policy")
    policy = mandatory.bind(authorization.organization_id, authorization.identity_id)
    return InputGuardrailGate(
        future=start_on_native_loop(
            _inspect_subjects(engine, policy, subjects, deadline_monotonic)
        ),
        deadline_monotonic=deadline_monotonic,
    )


def gate_status(gate: InputGuardrailGate | None) -> str:
    """Serialize a content-free decision, failing closed on a missing request."""
    decision: JsonObject = (
        {"action": "error", "failure": denied_input_failure().model_dump(mode="json")}
        if gate is None
        else gate.decision()
    )
    return json.dumps(decision)


def settle_input_gate(
    gate: InputGuardrailGate | None,
    terminal: GatewayEvent,
    failure: GatewayFailure | None,
) -> tuple[GatewayEvent, GatewayFailure | None]:
    """Keep provider meters but never charge or complete unapproved generation."""
    denied = None if gate is None else gate.settlement_failure()
    if denied is None:
        return terminal, failure
    return terminal, denied
