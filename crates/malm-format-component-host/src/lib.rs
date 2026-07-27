//! Admits and invokes capability-free format components deterministically.

#![forbid(unsafe_code)]

use std::{fmt, sync::Mutex};

use malm_config as config_api;
use malm_format_component_api as component_api;
use malm_types::Digest;
use wasmparser::{Parser, Validator, WasmFeatures, WasmFeaturesInflated};
use wasmtime::{
    Config, Engine, Strategy,
    component::{Component, Linker},
};

mod bindings;
mod conversion;
mod runtime;
mod watchdog;

/// Identifies the v1 component admission profile implemented by this crate.
pub const COMPONENT_PROFILE_V1: &str = "malm-format-component-admission/v1";

/// Identifies the v1 deterministic execution profile implemented by this crate.
pub const EXECUTION_PROFILE_V1: &str = "malm-format-component-execution/v1";

/// Largest WebAssembly component accepted for admission, in bytes.
pub const MAX_COMPONENT_BYTES: usize = 16 * 1024 * 1024;

const WASMTIME_VERSION: &str = "36.0.12";
const WASMTIME_FEATURES: &str = "component-model,cranelift,runtime,std";
const WASMPARSER_VERSION: &str = "0.236.1";
const FORMAT_COMPONENT_WORLD: &str = "malm:format-component/malm-format-component@1.0.0";
const COMPILER_STRATEGY: &str = "cranelift";
const GROWTH_FAILURE_POLICY: &str = "trap-after-approved-growth/v1";

#[derive(Clone, Debug, Eq, PartialEq)]
struct ContractLimitsV1 {
    canonical_document_bytes: usize,
    options: usize,
    resources: usize,
    resource_bytes: usize,
    total_resource_bytes: usize,
    output_bytes: usize,
    diagnostics: usize,
    diagnostic_bytes: usize,
    diagnostic_notes: usize,
    total_diagnostic_bytes: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ExecutionProfileV1 {
    execution_profile: &'static str,
    component_profile: &'static str,
    wasmtime_version: &'static str,
    wasmtime_features: &'static str,
    wasmparser_version: &'static str,
    format_component_world: &'static str,
    wit_digest: Digest,
    compiler_strategy: &'static str,
    consume_fuel: bool,
    epoch_interruption: bool,
    canonical_nans: bool,
    relaxed_simd_deterministic: bool,
    growth_failure_policy: &'static str,
    wasm_features: WasmFeatures,
    max_component_bytes: usize,
    contract_limits: ContractLimitsV1,
    runtime_limits: runtime::RuntimeLimits,
}

/// A host limited to deterministic format-component admission and invocation.
pub struct FormatComponentHost {
    engine: Engine,
    watchdog: watchdog::WatchdogConfig,
    profile: ExecutionProfileV1,
    profile_digest: Digest,
    /// Admissions cached by verified digest. Compilation depends only on the
    /// exact component bytes and fixed engine configuration, so reuse preserves
    /// the execution profile. Each digest has one shared initialization slot:
    /// the first caller compiles while concurrent callers wait. Entries are
    /// retained in first-in-first-out order.
    #[allow(clippy::type_complexity)]
    admitted: Mutex<
        Vec<(
            Digest,
            std::sync::Arc<Mutex<Option<AdmittedFormatComponent>>>,
        )>,
    >,
}

impl FormatComponentHost {
    /// Creates a host with a private deterministic Wasmtime engine and watchdog.
    pub fn new() -> Result<Self, HostInitializationError> {
        Self::with_watchdog_and_cache(watchdog::WatchdogConfig::PRODUCTION, None)
    }

    /// Creates the host with a persistent compilation cache directory.
    ///
    /// The cache stores Wasmtime-serialized machine code keyed by component
    /// content and the complete compiler configuration. It changes compilation
    /// work, not execution results or the execution profile identity. If the
    /// directory is unusable, the host silently falls back to per-process
    /// compilation.
    pub fn with_compile_cache(
        cache_dir: &std::path::Path,
    ) -> Result<Self, HostInitializationError> {
        Self::with_watchdog_and_cache(watchdog::WatchdogConfig::PRODUCTION, Some(cache_dir))
    }

    fn with_watchdog_and_cache(
        watchdog: watchdog::WatchdogConfig,
        cache_dir: Option<&std::path::Path>,
    ) -> Result<Self, HostInitializationError> {
        let profile = current_execution_profile_v1();
        let profile_digest = profile_digest(&profile);
        let engine =
            deterministic_engine(&profile, cache_dir).map_err(HostInitializationError::new)?;
        watchdog::start(&engine, watchdog.tick_interval).map_err(|error| {
            HostInitializationError::new(wasmtime::Error::msg(format!(
                "failed to start epoch watchdog: {error}"
            )))
        })?;
        Ok(Self {
            engine,
            watchdog,
            profile,
            profile_digest,
            admitted: Mutex::new(Vec::new()),
        })
    }

    /// Returns the exact execution profile digest without invoking a component.
    #[must_use]
    pub const fn execution_profile_digest(&self) -> &Digest {
        &self.profile_digest
    }

    /// Admits an exact authorized component with no imports.
    ///
    /// A previously admitted component may reuse its digest-verified compilation.
    pub fn admit_component(
        &self,
        authorization: &component_api::FormatComponentAuthorizationV1,
        expected_digest: &Digest,
        bytes: &[u8],
    ) -> Result<AdmittedFormatComponent, ComponentAdmissionError> {
        if !authorization.permits(expected_digest) {
            return Err(ComponentAdmissionError::UnauthorizedDigest {
                digest: expected_digest.clone(),
            });
        }
        enforce_component_size(bytes.len(), self.profile.max_component_bytes)?;
        let bytes = bytes.to_vec();
        let bytes = bytes.as_slice();
        let actual_digest = Digest::sha256(bytes);
        if &actual_digest != expected_digest {
            return Err(ComponentAdmissionError::DigestMismatch {
                expected: expected_digest.clone(),
                actual: actual_digest,
            });
        }
        let slot = {
            let mut cache = self
                .admitted
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if let Some((_, slot)) = cache.iter().find(|(digest, _)| digest == &actual_digest) {
                std::sync::Arc::clone(slot)
            } else {
                if cache.len() >= MAX_CACHED_ADMISSIONS {
                    cache.remove(0);
                }
                let slot = std::sync::Arc::new(Mutex::new(None));
                cache.push((actual_digest.clone(), std::sync::Arc::clone(&slot)));
                slot
            }
        };
        let mut slot = slot
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(admitted) = slot.as_ref() {
            return Ok(admitted.clone());
        }
        if Parser::is_core_wasm(bytes) {
            return Err(ComponentAdmissionError::CoreModule);
        }
        if !Parser::is_component(bytes) {
            return Err(ComponentAdmissionError::InvalidComponent {
                reason: "input does not have a WebAssembly component binary header".to_owned(),
            });
        }
        Validator::new_with_features(self.profile.wasm_features)
            .validate_all(bytes)
            .map_err(|error| ComponentAdmissionError::InvalidComponent {
                reason: error.to_string(),
            })?;
        let component = Component::from_binary(&self.engine, bytes).map_err(|error| {
            ComponentAdmissionError::CompilationFailed {
                reason: error.to_string(),
            }
        })?;
        let import_count = component.component_type().imports(&self.engine).len();
        if import_count != 0 {
            return Err(ComponentAdmissionError::ImportsNotAllowed {
                count: u32::try_from(import_count).unwrap_or(u32::MAX),
            });
        }
        let linker = Linker::<runtime::InvocationState>::new(&self.engine);
        let instance_pre = linker
            .instantiate_pre(&component)
            .map_err(interface_mismatch)?;
        let pre =
            bindings::MalmFormatComponentPre::new(instance_pre).map_err(interface_mismatch)?;
        let admitted = AdmittedFormatComponent {
            pre,
            digest: actual_digest,
            byte_len: bytes.len(),
            epoch_deadline_ticks: self.watchdog.deadline_ticks,
            profile: self.profile.clone(),
            profile_digest: self.profile_digest.clone(),
        };
        *slot = Some(admitted.clone());
        Ok(admitted)
    }
}

impl fmt::Debug for FormatComponentHost {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FormatComponentHost")
            .field("component_profile", &COMPONENT_PROFILE_V1)
            .field("execution_profile_digest", &self.profile_digest)
            .finish_non_exhaustive()
    }
}

/// Retains a small FIFO of compiled admissions; deployments usually bind only
/// one or two components.
const MAX_CACHED_ADMISSIONS: usize = 8;

/// A digest-verified `format-component/v1` binary compiled by this host.
#[derive(Clone)]
pub struct AdmittedFormatComponent {
    pre: bindings::MalmFormatComponentPre<runtime::InvocationState>,
    digest: Digest,
    byte_len: usize,
    epoch_deadline_ticks: u64,
    profile: ExecutionProfileV1,
    profile_digest: Digest,
}

impl AdmittedFormatComponent {
    #[must_use]
    pub const fn digest(&self) -> &Digest {
        &self.digest
    }

    #[must_use]
    pub const fn byte_len(&self) -> usize {
        self.byte_len
    }

    #[must_use]
    pub const fn component_profile(&self) -> &'static str {
        COMPONENT_PROFILE_V1
    }

    #[must_use]
    pub const fn execution_profile_digest(&self) -> &Digest {
        &self.profile_digest
    }

    /// Invokes the component's transform export in a fresh, bounded store.
    pub fn transform(
        &self,
        request: &config_api::TransformRequestV1,
    ) -> Result<
        Result<config_api::TransformResponseV1, config_api::TransformFailureV1>,
        FormatComponentInvocationError,
    > {
        request
            .validate()
            .map_err(|error| FormatComponentInvocationError::InvalidRequest {
                reason: error.to_string(),
            })?;
        let binding_request = conversion::to_binding_request(request);
        let result = match runtime::transform(
            &self.pre,
            &binding_request,
            self.profile.runtime_limits,
            self.profile.runtime_limits.transform_fuel,
            self.epoch_deadline_ticks,
        ) {
            Ok(result) => result,
            Err(runtime::RuntimeCallError::ResourceLimit(kind)) => {
                return Ok(Err(resource_limit_failure(kind)));
            }
            Err(runtime::RuntimeCallError::Invocation(error)) => return Err(error),
        };
        match result {
            Ok(response) => conversion::from_binding_response(response, request)
                .map(Ok)
                .map_err(malformed_output),
            Err(failure) => conversion::from_binding_failure(failure, request)
                .map(Err)
                .map_err(malformed_output),
        }
    }
}

impl fmt::Debug for AdmittedFormatComponent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AdmittedFormatComponent")
            .field("digest", &self.digest)
            .field("byte_len", &self.byte_len)
            .field("component_profile", &COMPONENT_PROFILE_V1)
            .field("execution_profile_digest", &self.profile_digest)
            .finish_non_exhaustive()
    }
}

/// An error while creating the fixed deterministic runtime configuration.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
#[error("failed to initialize deterministic format-component host: {reason}")]
pub struct HostInitializationError {
    reason: String,
}

impl HostInitializationError {
    fn new(error: wasmtime::Error) -> Self {
        Self {
            reason: error.to_string(),
        }
    }

    #[must_use]
    pub fn reason(&self) -> &str {
        &self.reason
    }
}

/// An error while admitting a component to the deterministic host.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
#[non_exhaustive]
pub enum ComponentAdmissionError {
    #[error("component contains {actual} bytes; limit is {limit}")]
    InputTooLarge { limit: usize, actual: usize },
    #[error("component digest mismatch: expected {expected}, computed {actual}")]
    DigestMismatch { expected: Digest, actual: Digest },
    #[error("input is a core module, not a component")]
    CoreModule,
    #[error("invalid component: {reason}")]
    InvalidComponent { reason: String },
    #[error("component declares {count} root imports; none are allowed")]
    ImportsNotAllowed { count: u32 },
    #[error("component does not implement format-component/v1: {reason}")]
    InterfaceMismatch { reason: String },
    #[error("component digest {digest} is not authorized")]
    UnauthorizedDigest { digest: Digest },
    #[error("component compilation failed: {reason}")]
    CompilationFailed { reason: String },
}

/// Stable codes for WebAssembly traps raised by a guest.
///
/// `runtime::guest_trap_code` mirrors these variants and their order. Both
/// lists remain handwritten so the crate's public API is literal and auditable
/// in source. The `format_component_host_public_api_is_exact_and_runtime_opaque`
/// dependency-boundary gate rejects macro-generated public items. Update both
/// lists together.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum GuestTrapCodeV1 {
    StackOverflow,
    MemoryOutOfBounds,
    HeapMisaligned,
    TableOutOfBounds,
    IndirectCallToNull,
    BadSignature,
    IntegerOverflow,
    IntegerDivisionByZero,
    BadConversionToInteger,
    Unreachable,
    AlwaysTrapAdapter,
    AtomicWaitNonSharedMemory,
    NullReference,
    ArrayOutOfBounds,
    AllocationTooLarge,
    CastFailure,
    CannotEnterComponent,
    Other,
}

/// An invocation error outside a valid, bounded semantic transform response.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
#[non_exhaustive]
pub enum FormatComponentInvocationError {
    #[error("invalid transform request: {reason}")]
    InvalidRequest { reason: String },
    #[error("malformed format-component output: {reason}")]
    MalformedOutput { reason: String },
    #[error("format component trapped: {trap:?}")]
    GuestTrap { trap: GuestTrapCodeV1 },
    #[error("format-component runtime failure: {reason}")]
    RuntimeFailure { reason: String },
    #[error("format-component invocation cancelled by infrastructure")]
    InfrastructureCancellation,
}

/// Computes a digest covering every fixed semantic setting in the v1 execution profile.
#[must_use]
pub fn execution_profile_digest_v1() -> Digest {
    profile_digest(&current_execution_profile_v1())
}

fn profile_digest(profile: &ExecutionProfileV1) -> Digest {
    let ExecutionProfileV1 {
        execution_profile,
        component_profile,
        wasmtime_version,
        wasmtime_features,
        wasmparser_version,
        format_component_world,
        wit_digest,
        compiler_strategy,
        consume_fuel,
        epoch_interruption,
        canonical_nans,
        relaxed_simd_deterministic,
        growth_failure_policy,
        wasm_features,
        max_component_bytes,
        contract_limits,
        runtime_limits,
    } = profile;
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"malm-format-component-execution-profile\0");
    for (name, value) in [
        ("execution-profile", *execution_profile),
        ("component-profile", *component_profile),
        ("wasmtime-version", *wasmtime_version),
        ("wasmtime-features", *wasmtime_features),
        ("wasmparser-version", *wasmparser_version),
        ("format-component-world", *format_component_world),
        ("wit-digest", wit_digest.as_str()),
        ("compiler-strategy", *compiler_strategy),
    ] {
        profile_text(&mut bytes, name, value);
    }
    for (name, value) in [
        ("consume-fuel", *consume_fuel),
        ("epoch-interruption", *epoch_interruption),
        ("canonical-nans", *canonical_nans),
        ("relaxed-simd-deterministic", *relaxed_simd_deterministic),
    ] {
        profile_bool(&mut bytes, name, value);
    }
    profile_text(&mut bytes, "growth-failure-policy", growth_failure_policy);
    profile_u64(&mut bytes, "wasm-features", wasm_features.bits());
    profile_usize(&mut bytes, "max-component-bytes", *max_component_bytes);

    let ContractLimitsV1 {
        canonical_document_bytes,
        options,
        resources,
        resource_bytes,
        total_resource_bytes,
        output_bytes,
        diagnostics,
        diagnostic_bytes,
        diagnostic_notes,
        total_diagnostic_bytes,
    } = contract_limits;
    for (name, value) in [
        (
            "contract.canonical-document-bytes",
            *canonical_document_bytes,
        ),
        ("contract.options", *options),
        ("contract.resources", *resources),
        ("contract.resource-bytes", *resource_bytes),
        ("contract.total-resource-bytes", *total_resource_bytes),
        ("contract.output-bytes", *output_bytes),
        ("contract.diagnostics", *diagnostics),
        ("contract.diagnostic-bytes", *diagnostic_bytes),
        ("contract.diagnostic-notes", *diagnostic_notes),
        ("contract.total-diagnostic-bytes", *total_diagnostic_bytes),
    ] {
        profile_usize(&mut bytes, name, value);
    }

    let runtime::RuntimeLimits {
        transform_fuel,
        max_aggregate_memory_bytes,
        max_table_elements,
        max_instances,
        max_tables,
        max_memories,
        max_hostcall_bytes,
        max_wasm_stack_bytes,
    } = runtime_limits;
    profile_u64(&mut bytes, "runtime.transform-fuel", *transform_fuel);
    for (name, value) in [
        (
            "runtime.max-aggregate-memory-bytes",
            *max_aggregate_memory_bytes,
        ),
        ("runtime.max-table-elements", *max_table_elements),
        ("runtime.max-instances", *max_instances),
        ("runtime.max-tables", *max_tables),
        ("runtime.max-memories", *max_memories),
        ("runtime.max-hostcall-bytes", *max_hostcall_bytes),
        ("runtime.max-wasm-stack-bytes", *max_wasm_stack_bytes),
    ] {
        profile_usize(&mut bytes, name, value);
    }
    Digest::sha256(bytes)
}

fn profile_text(bytes: &mut Vec<u8>, name: &str, value: &str) {
    profile_field(bytes, name, value.as_bytes());
}

fn profile_bool(bytes: &mut Vec<u8>, name: &str, value: bool) {
    profile_field(bytes, name, &[u8::from(value)]);
}

fn profile_usize(bytes: &mut Vec<u8>, name: &str, value: usize) {
    profile_u64(
        bytes,
        name,
        u64::try_from(value).expect("supported hosts use at most 64-bit usize"),
    );
}

fn profile_u64(bytes: &mut Vec<u8>, name: &str, value: u64) {
    profile_field(bytes, name, &value.to_be_bytes());
}

fn profile_field(bytes: &mut Vec<u8>, name: &str, value: &[u8]) {
    bytes.extend_from_slice(
        &u64::try_from(name.len())
            .expect("profile field names fit in u64")
            .to_be_bytes(),
    );
    bytes.extend_from_slice(name.as_bytes());
    bytes.extend_from_slice(
        &u64::try_from(value.len())
            .expect("profile field values fit in u64")
            .to_be_bytes(),
    );
    bytes.extend_from_slice(value);
}

fn malformed_output(error: conversion::ConversionError) -> FormatComponentInvocationError {
    FormatComponentInvocationError::MalformedOutput {
        reason: error.to_string(),
    }
}

fn resource_limit_failure(kind: runtime::ResourceLimitKind) -> config_api::TransformFailureV1 {
    let message = match kind {
        runtime::ResourceLimitKind::Fuel => "format-component execution fuel exhausted",
        runtime::ResourceLimitKind::Memory => "format-component memory limit exceeded",
        runtime::ResourceLimitKind::Table => "format-component table limit exceeded",
        runtime::ResourceLimitKind::StoreCount => {
            "format-component instance resource limit exceeded"
        }
        runtime::ResourceLimitKind::GuestToHostTransfer => {
            "format-component guest-to-host transfer limit exceeded"
        }
    };
    config_api::TransformFailureV1::new(
        config_api::TransformFailureKindV1::ResourceLimit,
        message,
        Vec::new(),
    )
    .expect("fixed resource-limit failure is bounded")
}

fn interface_mismatch(error: wasmtime::Error) -> ComponentAdmissionError {
    ComponentAdmissionError::InterfaceMismatch {
        reason: error.root_cause().to_string(),
    }
}

fn enforce_component_size(actual: usize, limit: usize) -> Result<(), ComponentAdmissionError> {
    if actual > limit {
        return Err(ComponentAdmissionError::InputTooLarge { limit, actual });
    }
    Ok(())
}

fn current_execution_profile_v1() -> ExecutionProfileV1 {
    ExecutionProfileV1 {
        execution_profile: EXECUTION_PROFILE_V1,
        component_profile: COMPONENT_PROFILE_V1,
        wasmtime_version: WASMTIME_VERSION,
        wasmtime_features: WASMTIME_FEATURES,
        wasmparser_version: WASMPARSER_VERSION,
        format_component_world: FORMAT_COMPONENT_WORLD,
        wit_digest: Digest::sha256(component_api::WIT_SOURCE),
        compiler_strategy: COMPILER_STRATEGY,
        consume_fuel: true,
        epoch_interruption: true,
        canonical_nans: true,
        relaxed_simd_deterministic: true,
        growth_failure_policy: GROWTH_FAILURE_POLICY,
        wasm_features: wasm_features_v1(),
        max_component_bytes: MAX_COMPONENT_BYTES,
        contract_limits: ContractLimitsV1 {
            canonical_document_bytes: config_api::MAX_CANONICAL_TYPED_DOCUMENT_BYTES,
            options: config_api::MAX_TRANSFORM_OPTIONS,
            resources: config_api::MAX_TRANSFORM_RESOURCES,
            resource_bytes: config_api::MAX_TRANSFORM_RESOURCE_BYTES,
            total_resource_bytes: config_api::MAX_TRANSFORM_TOTAL_RESOURCE_BYTES,
            output_bytes: config_api::MAX_TRANSFORM_OUTPUT_BYTES,
            diagnostics: config_api::MAX_RICH_DIAGNOSTICS,
            diagnostic_bytes: config_api::MAX_RICH_DIAGNOSTIC_BYTES,
            diagnostic_notes: config_api::MAX_RICH_DIAGNOSTIC_NOTES,
            total_diagnostic_bytes: config_api::MAX_RICH_TOTAL_DIAGNOSTIC_BYTES,
        },
        runtime_limits: runtime::RuntimeLimits {
            transform_fuel: 100_000_000,
            max_aggregate_memory_bytes: 512 * 1024 * 1024,
            max_table_elements: 100_000,
            max_instances: 64,
            max_tables: 32,
            max_memories: 8,
            max_hostcall_bytes: 128 * 1024 * 1024,
            max_wasm_stack_bytes: 512 * 1024,
        },
    }
}

fn wasm_features_v1() -> WasmFeatures {
    WasmFeatures::from_inflated(WasmFeaturesInflated {
        mutable_global: true,
        saturating_float_to_int: true,
        sign_extension: true,
        reference_types: true,
        multi_value: true,
        bulk_memory: true,
        simd: true,
        relaxed_simd: false,
        threads: false,
        shared_everything_threads: false,
        tail_call: false,
        floats: true,
        multi_memory: false,
        exceptions: false,
        memory64: false,
        extended_const: false,
        component_model: true,
        function_references: false,
        memory_control: false,
        gc: false,
        custom_page_sizes: false,
        legacy_exceptions: false,
        gc_types: false,
        stack_switching: false,
        wide_arithmetic: false,
        cm_values: false,
        cm_nested_names: false,
        cm_async: false,
        cm_async_stackful: false,
        cm_async_builtins: false,
        cm_error_context: false,
        cm_fixed_size_list: false,
        cm_gc: false,
        call_indirect_overlong: true,
        bulk_memory_opt: true,
    })
}

fn deterministic_engine(
    profile: &ExecutionProfileV1,
    cache_dir: Option<&std::path::Path>,
) -> Result<Engine, wasmtime::Error> {
    let features = profile.wasm_features;
    let mut config = Config::new();
    if let Some(directory) = cache_dir {
        let mut cache_config = wasmtime::CacheConfig::new();
        cache_config.with_directory(directory);
        if let Ok(cache) = wasmtime::Cache::new(cache_config) {
            config.cache(Some(cache));
        }
    }
    config
        .strategy(Strategy::Cranelift)
        .consume_fuel(profile.consume_fuel)
        .epoch_interruption(profile.epoch_interruption)
        .max_wasm_stack(profile.runtime_limits.max_wasm_stack_bytes)
        .cranelift_nan_canonicalization(profile.canonical_nans)
        .relaxed_simd_deterministic(profile.relaxed_simd_deterministic)
        .wasm_component_model(features.contains(WasmFeatures::COMPONENT_MODEL))
        .wasm_tail_call(features.contains(WasmFeatures::TAIL_CALL))
        .wasm_custom_page_sizes(features.contains(WasmFeatures::CUSTOM_PAGE_SIZES))
        .wasm_shared_everything_threads(features.contains(WasmFeatures::SHARED_EVERYTHING_THREADS))
        .wasm_wide_arithmetic(features.contains(WasmFeatures::WIDE_ARITHMETIC))
        .wasm_simd(features.contains(WasmFeatures::SIMD))
        .wasm_relaxed_simd(features.contains(WasmFeatures::RELAXED_SIMD))
        .wasm_bulk_memory(features.contains(WasmFeatures::BULK_MEMORY))
        .wasm_multi_value(features.contains(WasmFeatures::MULTI_VALUE))
        .wasm_multi_memory(features.contains(WasmFeatures::MULTI_MEMORY))
        .wasm_memory64(features.contains(WasmFeatures::MEMORY64))
        .wasm_extended_const(features.contains(WasmFeatures::EXTENDED_CONST))
        .wasm_stack_switching(features.contains(WasmFeatures::STACK_SWITCHING))
        .wasm_component_model_error_context(features.contains(WasmFeatures::CM_ERROR_CONTEXT))
        .wasm_component_model_gc(features.contains(WasmFeatures::CM_GC))
        .wasm_exceptions(features.contains(WasmFeatures::EXCEPTIONS));
    Engine::new(&config)
}

#[cfg(test)]
mod tests;
