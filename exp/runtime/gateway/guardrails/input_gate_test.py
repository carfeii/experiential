"""Tests for request-owned parallel input inspection."""

from __future__ import annotations

import time
from concurrent.futures import Future

import pytest
from pydantic import ValidationError

from exp.runtime.gateway.contracts import (
    GatewayApiSurface,
    GatewayEvent,
    GatewayEventKind,
    GatewayFailure,
    GatewayFailureClass,
    GatewayMessage,
    GatewayRequest,
    GatewayUsage,
)
from exp.runtime.gateway.guardrails.contracts import GuardrailCheckStage, MandatoryGuardrailPolicy
from exp.runtime.gateway.guardrails.input_gate import (
    InputGuardrailGate,
    can_overlap_input,
    settle_input_gate,
    start_input_gate,
)
from exp.runtime.gateway.guardrails.native_test import _authorization
from exp.runtime.gateway.tests.parallel_input_guardrails_test import _Classifier, _engine
from exp.runtime.gateway.tool_contracts import GatewayProviderNativeTool


def _request(text: str) -> GatewayRequest:
    """Create a complete, normalized conversation subject."""
    return GatewayRequest(
        surface=GatewayApiSurface.CHAT_COMPLETIONS,
        messages=(GatewayMessage(role="user", content=text),),
    )


def test_parallel_policy_rejects_output_checks() -> None:
    """A host cannot accidentally turn parallel input mode into output buffering."""
    policy = _engine(_Classifier("allow")).mandatory_policy
    assert policy is not None
    payload = policy.model_dump(mode="python")
    payload["checks"] = (policy.checks[0].model_copy(update={"stage": GuardrailCheckStage.OUTPUT}),)
    with pytest.raises(ValidationError, match="input-only"):
        MandatoryGuardrailPolicy.model_validate(payload)


@pytest.mark.parametrize("kind", ["provider_native", "provider_server", "tier"])
def test_remote_actions_and_tiered_requests_require_pre_dispatch_inspection(kind: str) -> None:
    """Provider-executed actions and unresolved tier pricing cannot speculate."""
    engine = _engine(_Classifier("allow"))
    request = _request("fixture")
    assert can_overlap_input(engine, request)
    if kind == "provider_native":
        request = request.model_copy(
            update={
                "provider_native_tools": (
                    GatewayProviderNativeTool(index=0, tool={"type": "web_search"}),
                )
            }
        )
    elif kind == "provider_server":
        request = request.model_copy(
            update={"provider_server_tools": ({"type": "web_search", "name": "web_search"},)}
        )
    else:
        request = request.model_copy(update={"service_tier": "priority"})
    assert not can_overlap_input(engine, request)
    assert not can_overlap_input(None, _request("fixture"))


def test_original_rewritten_and_expanded_inputs_share_one_frozen_policy() -> None:
    """Inspect every changed context while avoiding repeated inspection of identical copies."""
    classifier = _Classifier("allow")
    classifier.release.set()
    original, rewritten = _request("original intent"), _request("rewritten context")
    expanded = _request("expanded plaintext continuation")
    gate = start_input_gate(
        _engine(classifier),
        _authorization(),
        (original, rewritten, rewritten.model_copy(), expanded),
        time.monotonic() + 3,
    )
    gate.future.result(timeout=2)
    assert gate.decision() == {"action": "allow"}
    assert classifier.requests == [original, rewritten, expanded]


def test_request_decisions_are_not_shared() -> None:
    """Approving one request cannot release a different request's pending generation."""
    first, second = _Classifier("allow"), _Classifier("allow")
    first.release.set()
    gate_a = start_input_gate(
        _engine(first),
        _authorization(),
        (_request("same text"),),
        time.monotonic() + 3,
    )
    gate_b = start_input_gate(
        _engine(second),
        _authorization().model_copy(update={"organization_id": "other-tenant"}),
        (_request("same text"),),
        time.monotonic() + 3,
    )
    try:
        gate_a.future.result(timeout=2)
        assert gate_a.decision() == {"action": "allow"}
        assert gate_b.decision() == {"action": "pending"}
    finally:
        gate_b.cancel()
    assert gate_b.decision()["action"] == "error"


def test_disconnect_before_approval_keeps_meter_evidence_and_cancels_inspection() -> None:
    """Unapproved cancellation settles as a denial without erasing estimated provider usage."""
    future: Future[None] = Future()
    gate = InputGuardrailGate(future, time.monotonic() + 3)
    failure = GatewayFailure(
        failure_class=GatewayFailureClass.CANCELLED, safe_message="Client disconnected."
    )
    terminal = GatewayEvent(
        kind=GatewayEventKind.FAILED,
        sequence_number=0,
        failure=failure,
        usage=GatewayUsage(input_tokens=80, output_tokens=3),
        usage_incomplete_due_to_disconnect=True,
        usage_estimated=True,
    )
    result, denied = settle_input_gate(gate, terminal, failure)
    assert result is terminal
    assert result.usage_estimated and result.failure is failure
    assert denied is not None
    assert denied.failure_class is GatewayFailureClass.UNAVAILABLE
    assert denied.safe_details["input_guardrail_denied"] is True
    assert future.cancelled()


def test_expired_pending_inspection_cannot_release_output() -> None:
    """An expired deadline fails closed without renewing the request budget."""
    future: Future[None] = Future()
    gate = InputGuardrailGate(future, time.monotonic() - 1)
    assert gate.decision()["action"] == "error"
    assert future.cancelled()
