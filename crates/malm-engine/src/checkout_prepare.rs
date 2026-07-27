use malm_types::{CheckoutRequestV1, PreparedDeploymentV1};

use crate::{Engine, EngineError, lifecycle_prepare, prepared_store};

pub(super) fn prepare(
    engine: &Engine,
    request: &CheckoutRequestV1,
) -> Result<PreparedDeploymentV1, EngineError> {
    let committer = engine
        .committer_v1()
        .map_err(|error| prepared_store::commit_error(engine, error))?;
    let (current_digest, current, desired) = committer
        .inspect_checkout_generations_v1(request.namespace(), request.target_generation())
        .map_err(|error| prepared_store::commit_error(engine, error))?;

    lifecycle_prepare::checkout(
        engine,
        &current_digest,
        &current,
        request.target_generation(),
        &desired,
    )
}
