"""Native callbacks for the shared request-owned guardrail session."""

from __future__ import annotations

import importlib
import json
from collections.abc import Sequence
from typing import TYPE_CHECKING, Protocol, cast

from exp.common.core.artifacts import JsonObject
from exp.runtime.gateway.contracts import GatewayRequest
from exp.runtime.gateway.guardrails.contracts import (
    GuardrailAction,
    GuardrailCompletion,
    GuardrailRejected,
    GuardrailToolCall,
    OutputGuardrailMode,
)
from exp.runtime.gateway.guardrails.session import GuardrailSession, denied_input_failure

if TYPE_CHECKING:
    from exp.runtime.gateway.guardrails.enforcement import GuardrailEngine
    from exp.runtime.gateway.native_accounting import NativeAttemptAccounting


def validate_guardrail_engine(engine: GuardrailEngine | None) -> None:
    """Require the coordinated native guardrail contract before serving guarded traffic."""
    if engine is None:
        return
    native = importlib.import_module("exp_gateway_native")
    if getattr(native, "GUARDRAIL_CONTRACT_VERSION", None) != 3:
        raise ValueError(
            "guardrails require native GUARDRAIL_CONTRACT_VERSION=3; "
            "install the coordinated native package"
        )


def native_output_mode(
    session: GuardrailSession | None,
    request: GatewayRequest,
    *,
    image_output: bool = False,
    wire_route: Sequence[JsonObject] = (),
) -> OutputGuardrailMode:
    """Choose one output execution strategy for the entire frozen policy set."""
    if session is None:
        return OutputGuardrailMode.OFF
    return session.output_mode(
        request,
        reasoning=upstream_requests_reasoning(wire_route),
        images=image_output or any(wire.get("image_output") is True for wire in wire_route),
    )


def parse_output_payload(data: JsonObject) -> GuardrailCompletion:
    """Decode one native output-inspection payload.

    Args:
        data: JSON object with ``text``, ``refusal``, and ``tool_calls``.

    Returns:
        The normalized completion presented to the output chain.
    """
    raw_calls = data.get("tool_calls", [])
    calls: list[GuardrailToolCall] = []
    if isinstance(raw_calls, list):
        for item in raw_calls:
            if not isinstance(item, dict):
                continue
            call_id = item.get("call_id") or item.get("id")
            name = item.get("name")
            arguments = item.get("arguments") or item.get("raw_arguments") or ""
            if isinstance(call_id, str) and isinstance(name, str) and isinstance(arguments, str):
                calls.append(GuardrailToolCall(call_id=call_id, name=name, arguments=arguments))
    raw_context = data.get("context", [])
    if not isinstance(raw_context, list) or any(not isinstance(item, str) for item in raw_context):
        raise GuardrailRejected(denied_input_failure())
    return GuardrailCompletion(
        text=str(data.get("text") or ""),
        refusal=bool(data.get("refusal")),
        tool_calls=tuple(calls),
        context=tuple(str(item) for item in raw_context),
    )


def encode_output_decision(
    *,
    action: str,
    replacement_text: str | None = None,
    failure: JsonObject | None = None,
) -> str:
    """Encode a release decision with sanitized failure metadata."""
    payload: JsonObject = {"action": action}
    if replacement_text is not None:
        payload["replacement_text"] = replacement_text
    if failure is not None:
        payload["failure"] = failure
    return json.dumps(payload, separators=(",", ":"))


def enforce_native_output_segment(session: GuardrailSession | None, argument: str) -> str:
    """Apply the session's deterministic streaming strategy before releasing bytes."""
    data = cast(JsonObject, json.loads(argument))
    try:
        if session is None:
            raise GuardrailRejected(denied_input_failure())
        value = data.get("settled_bytes")
        segment = session.release_output_segment(
            pending=str(data.get("pending") or ""),
            final=bool(data.get("final")),
            settled_bytes=value if isinstance(value, int) else 0,
        )
    except GuardrailRejected as exc:
        return encode_output_decision(
            action=str(exc.failure.safe_details.get("action", "error")),
            failure=exc.failure.model_dump(mode="json"),
        )
    return json.dumps(
        {
            "action": "allow",
            "release": segment.release,
            "pending": segment.pending,
            "flagged": segment.flagged,
        }
    )


def enforce_native_output(session: GuardrailSession | None, argument: str) -> str:
    """Apply every scoped policy to the same buffered completion before releasing it."""
    try:
        if session is None:
            raise GuardrailRejected(denied_input_failure())
        completion = parse_output_payload(cast(JsonObject, json.loads(argument)))
        result = session.inspect_output(completion)
    except GuardrailRejected as exc:
        return encode_output_decision(
            action=str(exc.failure.safe_details.get("action", "error")),
            failure=exc.failure.model_dump(mode="json"),
        )
    if result != completion:
        return encode_output_decision(
            action=GuardrailAction.MODIFY.value, replacement_text=result.text
        )
    return encode_output_decision(action=GuardrailAction.ALLOW.value)


def upstream_requests_reasoning(wire_route: Sequence[JsonObject]) -> bool:
    """Return whether any rung's built payload asks for readable reasoning.

    Reasoning display defaults add an OpenAI ``reasoning.summary`` or an
    Anthropic ``thinking.display`` the caller never sent; a streamed output
    chain must then buffer, because it cannot judge or redact reasoning.

    Args:
        wire_route: The admission's ordered wire entries.

    Returns:
        ``True`` when a payload carries a summary or a thinking display.
    """
    for wire in wire_route:
        payload = wire.get("upstream_payload")
        if not isinstance(payload, dict):
            continue
        reasoning = payload.get("reasoning")
        thinking = payload.get("thinking")
        if (isinstance(reasoning, dict) and "summary" in reasoning) or (
            isinstance(thinking, dict) and "display" in thinking
        ):
            return True
    return False


class _GuardrailPlane(Protocol):
    """Accounting is the sole owner of each admitted request's session."""

    _accounting: NativeAttemptAccounting


class NativeGuardrailsMixin:
    """Resolve native operations to one frozen session, independent of policy scope."""

    def guardrail_input_status(self: _GuardrailPlane, argument: str) -> str:
        """Poll approval without tying up a bridge worker or authorizing a closed request."""
        request_id = str(json.loads(argument).get("request_id") or "")
        entry = self._accounting.entry(request_id)
        if entry is None:
            return '{"action":"closed"}'
        decision = (
            {"action": "error", "failure": denied_input_failure().model_dump(mode="json")}
            if entry.guardrails is None
            else entry.guardrails.input_decision()
        )
        return (
            json.dumps(decision)
            if self._accounting.entry(request_id) is entry
            else '{"action":"closed"}'
        )

    def enforce_output_segment(self: _GuardrailPlane, argument: str) -> str:
        """Release one deterministic segment through the admitted session."""
        entry = self._accounting.entry(str(json.loads(argument).get("request_id") or ""))
        return enforce_native_output_segment(None if entry is None else entry.guardrails, argument)

    def enforce_output(self: _GuardrailPlane, argument: str) -> str:
        """Inspect one complete output through the admitted session."""
        entry = self._accounting.entry(str(json.loads(argument).get("request_id") or ""))
        return enforce_native_output(None if entry is None else entry.guardrails, argument)
