"""Paid admission work survives a failed terminal write without a synthetic model attempt."""

from __future__ import annotations

import threading
from unittest.mock import patch

import pytest

from exp.runtime.gateway.contracts import (
    AuthorizationSnapshot,
    GatewayFailure,
    GatewayFailureClass,
)
from exp.runtime.gateway.native_accounting_errors import NativeBridgeError
from exp.runtime.gateway.native_accounting_test import _RecordingLedger, _registry
from exp.runtime.gateway.native_request_settlement import RequestSettlements


def test_pre_dispatch_search_meter_is_retried_by_the_accounting_sweep() -> None:
    """Block further paid work until the original verdict and exact meter commit."""
    accounting, ledger, entry = _registry()
    ledger.fail_request_finishes = 2
    failure = GatewayFailure(
        failure_class=GatewayFailureClass.GUARDRAIL,
        safe_message="blocked",
        safe_details={"input_guardrail_denied": True},
    )
    assert not accounting.finish_request_quietly(
        entry.authorization,
        failure,
        web_search_requests=1,
    )
    assert not accounting.accounting_healthy
    with pytest.raises(NativeBridgeError, match="accounting is recovering"):
        accounting.request_settlements.require_clear()
    accounting.sweep_expired()
    assert not accounting.accounting_healthy
    accounting.sweep_expired()
    assert accounting.accounting_healthy
    accounting.request_settlements.require_clear()
    accounting.sweep_expired()
    assert ledger.finished_requests == [failure]
    assert ledger.request_search_meters == [1]
    assert ledger.started == []


def test_ledger_without_unattempted_search_contract_is_rejected_at_startup() -> None:
    """A host must support the hard cutover before the gateway can spend on a search."""
    ledger = _RecordingLedger()

    def incomplete_contract(
        *,
        authorization: AuthorizationSnapshot,
        failure: GatewayFailure,
        certify_no_effects: bool = False,
    ) -> bool:
        """Expose an incomplete ledger signature without allowing a write."""
        raise AssertionError("startup validation must not execute the ledger")

    with patch.object(ledger, "finish_request", incomplete_contract):
        with pytest.raises(ValueError, match="persist unattempted search expense"):
            RequestSettlements(ledger)


def test_normal_in_progress_terminal_write_does_not_block_unrelated_admission() -> None:
    """Only failed writes close admission; a normal commit may still be in flight."""
    accounting, ledger, entry = _registry()
    entered, release = threading.Event(), threading.Event()
    calls: list[int] = []

    def commit(
        *,
        authorization: AuthorizationSnapshot,
        failure: GatewayFailure,
        certify_no_effects: bool = False,
        web_search_requests: int = 0,
    ) -> bool:
        """Hold a successful terminal write open while another request checks admission."""
        calls.append(1)
        entered.set()
        assert release.wait(3)
        return True

    failure = GatewayFailure(failure_class=GatewayFailureClass.GUARDRAIL, safe_message="blocked")
    results: list[bool] = []
    worker = threading.Thread(
        target=lambda: results.append(
            accounting.finish_request_quietly(entry.authorization, failure)
        )
    )
    with patch.object(ledger, "finish_request", commit):
        worker.start()
        try:
            assert entered.wait(3)
            assert accounting.accounting_healthy
            accounting.request_settlements.require_clear()
            accounting.request_settlements.retry(16)
            assert calls == [1]
        finally:
            release.set()
            worker.join(3)
    assert not worker.is_alive()
    assert results == [True]
