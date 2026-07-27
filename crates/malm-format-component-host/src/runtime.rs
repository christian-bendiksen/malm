use wasmtime::{ResourceLimiter, Store};

use crate::{FormatComponentInvocationError, GuestTrapCodeV1, bindings};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RuntimeLimits {
    pub(crate) transform_fuel: u64,
    pub(crate) max_aggregate_memory_bytes: usize,
    pub(crate) max_table_elements: usize,
    pub(crate) max_instances: usize,
    pub(crate) max_tables: usize,
    pub(crate) max_memories: usize,
    pub(crate) max_hostcall_bytes: usize,
    pub(crate) max_wasm_stack_bytes: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ResourceLimitKind {
    Fuel,
    Memory,
    Table,
    StoreCount,
    GuestToHostTransfer,
}

#[derive(Debug)]
pub(crate) enum RuntimeCallError {
    ResourceLimit(ResourceLimitKind),
    Invocation(FormatComponentInvocationError),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum GrowFailureKind {
    Memory,
    Table,
}

pub(crate) struct InvocationState {
    limiter: InvocationLimiter,
}

struct InvocationLimiter {
    limits: RuntimeLimits,
    charged_memory_bytes: usize,
    hit: Option<ResourceLimitKind>,
    grow_failed: Option<GrowFailureKind>,
}

impl InvocationLimiter {
    const fn new(limits: RuntimeLimits) -> Self {
        Self {
            limits,
            charged_memory_bytes: 0,
            hit: None,
            grow_failed: None,
        }
    }
}

impl ResourceLimiter for InvocationLimiter {
    fn memory_growing(
        &mut self,
        current: usize,
        desired: usize,
        maximum: Option<usize>,
    ) -> wasmtime::Result<bool> {
        if maximum.is_some_and(|maximum| desired > maximum) {
            return Ok(false);
        }
        let growth = desired.saturating_sub(current);
        let Some(charged) = self.charged_memory_bytes.checked_add(growth) else {
            self.hit = Some(ResourceLimitKind::Memory);
            return Err(wasmtime::Error::msg(
                "deterministic format-component aggregate memory limit exceeded",
            ));
        };
        if charged > self.limits.max_aggregate_memory_bytes {
            self.hit = Some(ResourceLimitKind::Memory);
            return Err(wasmtime::Error::msg(
                "deterministic format-component aggregate memory limit exceeded",
            ));
        }
        // Charge approved growth even if Wasmtime later fails to allocate it.
        self.charged_memory_bytes = charged;
        Ok(true)
    }

    fn table_growing(
        &mut self,
        _current: usize,
        desired: usize,
        maximum: Option<usize>,
    ) -> wasmtime::Result<bool> {
        if maximum.is_some_and(|maximum| desired > maximum) {
            return Ok(false);
        }
        if desired > self.limits.max_table_elements {
            self.hit = Some(ResourceLimitKind::Table);
            return Err(wasmtime::Error::msg(
                "deterministic format-component table limit exceeded",
            ));
        }
        Ok(true)
    }

    fn memory_grow_failed(&mut self, error: wasmtime::Error) -> wasmtime::Result<()> {
        self.grow_failed = Some(GrowFailureKind::Memory);
        Err(error)
    }

    fn table_grow_failed(&mut self, error: wasmtime::Error) -> wasmtime::Result<()> {
        self.grow_failed = Some(GrowFailureKind::Table);
        Err(error)
    }

    fn instances(&self) -> usize {
        self.limits.max_instances
    }

    fn tables(&self) -> usize {
        self.limits.max_tables
    }

    fn memories(&self) -> usize {
        self.limits.max_memories
    }
}

/// Invokes the transform export with an explicit fuel budget.
///
/// Production callers pass `limits.transform_fuel`; tests may use a smaller budget.
pub(crate) fn transform(
    pre: &bindings::MalmFormatComponentPre<InvocationState>,
    request: &bindings::TransformRequestV1,
    limits: RuntimeLimits,
    fuel: u64,
    epoch_deadline_ticks: u64,
) -> Result<Result<bindings::TransformResponseV1, bindings::TransformFailureV1>, RuntimeCallError> {
    invoke(
        pre,
        limits,
        fuel,
        epoch_deadline_ticks,
        |component, store| component.call_transform(store, request),
    )
}

fn invoke<T>(
    pre: &bindings::MalmFormatComponentPre<InvocationState>,
    limits: RuntimeLimits,
    fuel: u64,
    epoch_deadline_ticks: u64,
    call: impl FnOnce(
        &bindings::MalmFormatComponent,
        &mut Store<InvocationState>,
    ) -> wasmtime::Result<T>,
) -> Result<T, RuntimeCallError> {
    let mut store = new_store(pre, limits, fuel, epoch_deadline_ticks)?;
    let component = pre
        .instantiate(&mut store)
        .map_err(|error| classify_error(error, &store, false))?;
    call(&component, &mut store).map_err(|error| classify_error(error, &store, true))
}

fn new_store(
    pre: &bindings::MalmFormatComponentPre<InvocationState>,
    limits: RuntimeLimits,
    fuel: u64,
    epoch_deadline_ticks: u64,
) -> Result<Store<InvocationState>, RuntimeCallError> {
    let mut store = Store::new(
        pre.engine(),
        InvocationState {
            limiter: InvocationLimiter::new(limits),
        },
    );
    store.limiter(|state| &mut state.limiter);
    store.set_hostcall_fuel(limits.max_hostcall_bytes);
    store.set_epoch_deadline(epoch_deadline_ticks);
    store.epoch_deadline_trap();
    store.set_fuel(fuel).map_err(|error| {
        RuntimeCallError::Invocation(FormatComponentInvocationError::RuntimeFailure {
            reason: error.root_cause().to_string(),
        })
    })?;
    Ok(store)
}

#[cfg(test)]
pub(crate) fn force_epoch_cancellation(
    pre: &bindings::MalmFormatComponentPre<InvocationState>,
    request: &bindings::TransformRequestV1,
    limits: RuntimeLimits,
) -> RuntimeCallError {
    let mut store =
        new_store(pre, limits, u64::MAX, 1).expect("fixed test store configuration is valid");
    let component = pre
        .instantiate(&mut store)
        .expect("valid fixture instantiates before cancellation");
    pre.engine().increment_epoch();
    let error = component
        .call_transform(&mut store, request)
        .expect_err("expired epoch must cancel the call");
    classify_error(error, &store, true)
}

fn classify_error(
    error: wasmtime::Error,
    store: &Store<InvocationState>,
    during_call: bool,
) -> RuntimeCallError {
    if let Some(kind) = store.data().limiter.hit {
        return RuntimeCallError::ResourceLimit(kind);
    }
    if let Some(kind) = store.data().limiter.grow_failed {
        let resource = match kind {
            GrowFailureKind::Memory => "memory",
            GrowFailureKind::Table => "table",
        };
        return RuntimeCallError::Invocation(FormatComponentInvocationError::RuntimeFailure {
            reason: format!("format component {resource} growth failed after approval"),
        });
    }
    if let Some(trap) = error.downcast_ref::<wasmtime::Trap>() {
        return match trap {
            wasmtime::Trap::OutOfFuel => RuntimeCallError::ResourceLimit(ResourceLimitKind::Fuel),
            wasmtime::Trap::Interrupt => RuntimeCallError::Invocation(
                FormatComponentInvocationError::InfrastructureCancellation,
            ),
            trap => RuntimeCallError::Invocation(FormatComponentInvocationError::GuestTrap {
                trap: guest_trap_code(trap),
            }),
        };
    }

    let reason = error.root_cause().to_string();
    if reason
        == "too much data is being copied between the host and the guest: fuel allocated for hostcalls has been exhausted"
    {
        return RuntimeCallError::ResourceLimit(ResourceLimitKind::GuestToHostTransfer);
    }
    if reason.starts_with("resource limit exceeded:") {
        return RuntimeCallError::ResourceLimit(ResourceLimitKind::StoreCount);
    }
    if during_call {
        RuntimeCallError::Invocation(FormatComponentInvocationError::MalformedOutput { reason })
    } else {
        RuntimeCallError::Invocation(FormatComponentInvocationError::RuntimeFailure { reason })
    }
}

/// Maps Wasmtime traps to the mirrored [`GuestTrapCodeV1`] variant list.
const fn guest_trap_code(trap: &wasmtime::Trap) -> GuestTrapCodeV1 {
    match trap {
        wasmtime::Trap::StackOverflow => GuestTrapCodeV1::StackOverflow,
        wasmtime::Trap::MemoryOutOfBounds => GuestTrapCodeV1::MemoryOutOfBounds,
        wasmtime::Trap::HeapMisaligned => GuestTrapCodeV1::HeapMisaligned,
        wasmtime::Trap::TableOutOfBounds => GuestTrapCodeV1::TableOutOfBounds,
        wasmtime::Trap::IndirectCallToNull => GuestTrapCodeV1::IndirectCallToNull,
        wasmtime::Trap::BadSignature => GuestTrapCodeV1::BadSignature,
        wasmtime::Trap::IntegerOverflow => GuestTrapCodeV1::IntegerOverflow,
        wasmtime::Trap::IntegerDivisionByZero => GuestTrapCodeV1::IntegerDivisionByZero,
        wasmtime::Trap::BadConversionToInteger => GuestTrapCodeV1::BadConversionToInteger,
        wasmtime::Trap::UnreachableCodeReached => GuestTrapCodeV1::Unreachable,
        wasmtime::Trap::AlwaysTrapAdapter => GuestTrapCodeV1::AlwaysTrapAdapter,
        wasmtime::Trap::AtomicWaitNonSharedMemory => GuestTrapCodeV1::AtomicWaitNonSharedMemory,
        wasmtime::Trap::NullReference => GuestTrapCodeV1::NullReference,
        wasmtime::Trap::ArrayOutOfBounds => GuestTrapCodeV1::ArrayOutOfBounds,
        wasmtime::Trap::AllocationTooLarge => GuestTrapCodeV1::AllocationTooLarge,
        wasmtime::Trap::CastFailure => GuestTrapCodeV1::CastFailure,
        wasmtime::Trap::CannotEnterComponent => GuestTrapCodeV1::CannotEnterComponent,
        _ => GuestTrapCodeV1::Other,
    }
}

#[cfg(test)]
mod tests {
    use super::{InvocationLimiter, ResourceLimitKind, RuntimeLimits};
    use wasmtime::ResourceLimiter;

    fn limits(max_aggregate_memory_bytes: usize) -> RuntimeLimits {
        RuntimeLimits {
            transform_fuel: 1,
            max_aggregate_memory_bytes,
            max_table_elements: 1,
            max_instances: 1,
            max_tables: 1,
            max_memories: 2,
            max_hostcall_bytes: 1,
            max_wasm_stack_bytes: 1,
        }
    }

    #[test]
    fn individually_legal_memories_share_one_invocation_budget() {
        let mut limiter = InvocationLimiter::new(limits(100));
        assert!(limiter.memory_growing(0, 60, None).unwrap());
        assert!(limiter.memory_growing(0, 60, None).is_err());
        assert_eq!(limiter.hit, Some(ResourceLimitKind::Memory));
    }

    #[test]
    fn approved_growth_remains_charged_after_a_runtime_failure() {
        let mut limiter = InvocationLimiter::new(limits(100));
        assert!(limiter.memory_growing(0, 60, None).unwrap());
        assert!(
            limiter
                .memory_grow_failed(wasmtime::Error::msg("allocation failed"))
                .is_err()
        );
        assert!(limiter.memory_growing(0, 41, None).is_err());
        assert_eq!(limiter.charged_memory_bytes, 60);
    }
}
