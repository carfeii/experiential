//! Withhold the first outward event while the shared engine checks the input.

use std::sync::Arc;
use std::time::{Duration, Instant};

use serde::Deserialize;
use serde_json::json;
use tokio::sync::OnceCell;

use crate::bridge::Bridge;
use crate::encode::compact_json;
use crate::errors::{Failure, FailureClass};
use crate::relay::{collection_public_error, remaining};
use crate::settlement::AttemptGuard;
use crate::waterfall::{acquire_attempt, WaterfallContext, Won};

/// One cached decision shared by response release and every attempt settlement.
pub(crate) struct InputGate {
    request_id: String,
    deadline: Instant,
    decision: OnceCell<Result<(), Failure>>,
}

#[derive(Deserialize)]
struct Decision {
    action: String,
    failure: Option<Failure>,
}

fn unavailable() -> Failure {
    Failure::new(
        FailureClass::Unavailable,
        "Content inspection is unavailable. Retry later.",
    )
}

impl InputGate {
    pub(crate) async fn wait(&self, bridge: &Bridge) -> Result<(), Failure> {
        self.decision
            .get_or_init(|| async {
                // Each callback is a nonblocking poll. No classifier can occupy
                // all bridge workers and prevent provider dispatch/settlement.
                let argument = compact_json(&json!({"request_id": self.request_id}));
                let mut delay_ms = 1;
                loop {
                    let response = tokio::time::timeout(
                        remaining(self.deadline),
                        bridge.call("guardrail_input_status", argument.clone()),
                    )
                    .await
                    .map_err(|_| unavailable())?
                    .map_err(|_| unavailable())?;
                    let decision: Decision =
                        serde_json::from_str(&response).map_err(|_| unavailable())?;
                    match decision.action.as_str() {
                        "allow" => return Ok(()),
                        "error" => return Err(decision.failure.unwrap_or_else(unavailable)),
                        "pending" if Instant::now() < self.deadline => {
                            tokio::time::sleep(
                                Duration::from_millis(delay_ms).min(remaining(self.deadline)),
                            )
                            .await;
                            delay_ms = (delay_ms * 2).min(10);
                        }
                        _ => return Err(unavailable()),
                    }
                }
            })
            .await
            .clone()
    }
}

/// Generate and inspect concurrently, withholding all protocol/replay/capture output.
pub(crate) async fn acquire_guarded_attempt(
    ctx: &WaterfallContext<'_>,
    guard: &mut AttemptGuard,
    enabled: bool,
) -> Won {
    if !enabled {
        return acquire_attempt(ctx, guard).await;
    }
    let gate = Arc::new(InputGate {
        request_id: ctx.request_id.to_owned(),
        deadline: ctx.deadline,
        decision: OnceCell::new(),
    });
    guard.input_gate = Some(gate.clone());
    let outcome = {
        let acquire = acquire_attempt(ctx, guard);
        tokio::pin!(acquire);
        tokio::select! {
            biased;
            decision = gate.wait(ctx.bridge) => match decision {
                Ok(()) => Ok(acquire.await),
                Err(failure) => Err(failure),
            },
            won = &mut acquire => match gate.wait(ctx.bridge).await {
                Ok(()) => Ok(won),
                Err(failure) => Err(failure),
            },
        }
    };
    match outcome {
        Ok(won) => won,
        Err(failure) => {
            // Dropping acquire/the committed relay closes upstream immediately.
            // The guard retains witnessed usage for our cost, while the host
            // applies the input verdict to customer settlement.
            guard
                .settle("failed", None, &[], Some(&failure), true)
                .await;
            guard.abandon(&failure).await;
            Won::Failed(collection_public_error(&failure.boundary()))
        }
    }
}
