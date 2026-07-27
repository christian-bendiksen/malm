use std::collections::BTreeMap;
use std::fmt;

use crate::rich::{
    CanonicalTypedDocumentV1, CapturedConfigDocumentV1, CapturedDocumentIdV1,
    CapturedDocumentSetV1, CapturedSourceIdentityV1, EvaluationFrameV1, FragmentDeclarationV1,
    IncludeProvenanceV1, PatchOperationV1, ProvenanceOperationV1, ProvenanceRecordV1,
    RichConditionV1, RichDiagnosticLocationV1, RichDiagnosticSeverityV1, RichDiagnosticV1,
    RichDocumentBodyV1, RichExpressionV1, RichKeyV1, RichNameV1, RichStatementV1, RichValuePathV1,
    SourceLocationV1, SourceRangeV1, TypedValueDataV1, TypedValueKindV1, TypedValueV1,
    VariableDeclarationV1, VariableSourceV1, canonical_diagnostics,
};
use crate::{
    MAX_RICH_COLLECTION_ITEMS, MAX_RICH_EVALUATION_STEPS, MAX_RICH_FRAGMENTS,
    MAX_RICH_INCLUDE_DEPTH, MAX_RICH_LOOP_ITERATIONS, MAX_RICH_PROVENANCE_RECORDS,
    MAX_RICH_STATEMENTS, MAX_RICH_TOTAL_LOOP_ITERATIONS, MAX_RICH_VARIABLES,
};

/// A named variable after assignment, defaults, optionality, and type checking.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolvedVariableV1 {
    value: TypedValueV1,
    provenance: Vec<ProvenanceRecordV1>,
}

impl ResolvedVariableV1 {
    #[must_use]
    pub const fn value(&self) -> &TypedValueV1 {
        &self.value
    }
    #[must_use]
    pub fn provenance(&self) -> &[ProvenanceRecordV1] {
        &self.provenance
    }
}

/// A successful deterministic evaluation of a captured include closure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RichEvaluationV1 {
    document: CanonicalTypedDocumentV1,
    variables: BTreeMap<RichNameV1, ResolvedVariableV1>,
    includes: Vec<IncludeProvenanceV1>,
    diagnostics: Vec<RichDiagnosticV1>,
}

impl RichEvaluationV1 {
    #[must_use]
    pub const fn document(&self) -> &CanonicalTypedDocumentV1 {
        &self.document
    }
    #[must_use]
    pub const fn variables(&self) -> &BTreeMap<RichNameV1, ResolvedVariableV1> {
        &self.variables
    }
    #[must_use]
    pub fn includes(&self) -> &[IncludeProvenanceV1] {
        &self.includes
    }
    #[must_use]
    pub fn diagnostics(&self) -> &[RichDiagnosticV1] {
        &self.diagnostics
    }
}

/// Bounded deterministic diagnostics from an unsuccessful rich evaluation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RichEvaluationErrorV1 {
    diagnostics: Vec<RichDiagnosticV1>,
}

impl RichEvaluationErrorV1 {
    pub(crate) fn one(diagnostic: RichDiagnosticV1) -> Self {
        Self {
            diagnostics: canonical_diagnostics(vec![diagnostic])
                .expect("internal diagnostics always satisfy fixed bounds"),
        }
    }
}

impl RichEvaluationErrorV1 {
    #[must_use]
    pub fn diagnostics(&self) -> &[RichDiagnosticV1] {
        &self.diagnostics
    }
}

impl fmt::Display for RichEvaluationErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let diagnostic = self
            .diagnostics
            .first()
            .expect("evaluation failures contain a diagnostic");
        write!(
            formatter,
            "rich config evaluation failed [{}]: {}",
            diagnostic.code(),
            diagnostic.message()
        )
    }
}

impl std::error::Error for RichEvaluationErrorV1 {}

/// Evaluates an entry document using only the supplied finite documents and values.
pub fn evaluate_rich_config_v1(
    documents: &CapturedDocumentSetV1,
    entry: &CapturedDocumentIdV1,
    supplied: &BTreeMap<RichNameV1, TypedValueV1>,
) -> Result<RichEvaluationV1, RichEvaluationErrorV1> {
    evaluate_rich_config_with_statements_v1(documents, entry, supplied, Vec::new())
}

pub(crate) fn evaluate_rich_config_with_statements_v1(
    documents: &CapturedDocumentSetV1,
    entry: &CapturedDocumentIdV1,
    supplied: &BTreeMap<RichNameV1, TypedValueV1>,
    additional_statements: Vec<LocatedRichStatementV1>,
) -> Result<RichEvaluationV1, RichEvaluationErrorV1> {
    let mut graph = resolve_include_graph(documents, entry)?;
    for statement in &additional_statements {
        let document = documents
            .documents
            .get(&statement.document)
            .ok_or_else(|| {
                RichEvaluationErrorV1::one(diagnostic(
                    "unknown-statement-document",
                    format!(
                        "additional statement references uncaptured document {}",
                        statement.document
                    ),
                    None,
                    Vec::new(),
                ))
            })?;
        validate_statement_ranges(
            document,
            std::slice::from_ref(&statement.statement),
            1,
            &mut graph.preflight.statements,
            &mut graph.preflight.expression_nodes,
        )?;
    }
    let mut declarations = collect_program(documents, &graph.order)?;
    declarations.statements.extend(additional_statements);
    let mut evaluator = Evaluator::new(declarations.variables, declarations.fragments, supplied);
    evaluator.resolve_all_variables()?;
    for statement in declarations.statements {
        evaluator.execute_statements(
            &statement.document,
            std::slice::from_ref(&statement.statement),
            &BTreeMap::new(),
        )?;
    }

    let root = TypedValueV1::record(evaluator.root).map_err(|error| {
        RichEvaluationErrorV1::one(diagnostic(
            "invalid-result",
            error.to_string(),
            None,
            Vec::new(),
        ))
    })?;
    let source_documents = graph
        .order
        .iter()
        .map(|id| {
            let document = documents
                .documents
                .get(id)
                .expect("resolved graph nodes remain captured");
            (
                id.clone(),
                CapturedSourceIdentityV1::new(
                    document.digest().clone(),
                    u64::try_from(document.bytes().len()).unwrap_or(u64::MAX),
                )
                .expect("captured document byte length was validated at construction"),
            )
        })
        .collect();
    let document = CanonicalTypedDocumentV1::evaluated(
        root,
        source_documents,
        graph.includes.clone(),
        evaluator.document_provenance,
    )
    .map_err(|error| {
        RichEvaluationErrorV1::one(diagnostic(
            "invalid-result",
            error.to_string(),
            None,
            Vec::new(),
        ))
    })?;
    let diagnostics = canonical_diagnostics(Vec::new())
        .expect("an empty diagnostic sequence always satisfies bounds");
    Ok(RichEvaluationV1 {
        document,
        variables: evaluator.resolved,
        includes: graph.includes,
        diagnostics,
    })
}

impl CapturedDocumentSetV1 {
    pub fn evaluate(
        &self,
        entry: &CapturedDocumentIdV1,
        supplied: &BTreeMap<RichNameV1, TypedValueV1>,
    ) -> Result<RichEvaluationV1, RichEvaluationErrorV1> {
        evaluate_rich_config_v1(self, entry, supplied)
    }
}

struct ResolvedGraph {
    order: Vec<CapturedDocumentIdV1>,
    includes: Vec<IncludeProvenanceV1>,
    preflight: PreflightBudget,
}

pub(crate) fn reachable_rich_document_order_v1(
    documents: &CapturedDocumentSetV1,
    entry: &CapturedDocumentIdV1,
) -> Result<Vec<CapturedDocumentIdV1>, RichEvaluationErrorV1> {
    resolve_include_graph(documents, entry).map(|graph| graph.order)
}

fn resolve_include_graph(
    documents: &CapturedDocumentSetV1,
    entry: &CapturedDocumentIdV1,
) -> Result<ResolvedGraph, RichEvaluationErrorV1> {
    if entry.authority() != documents.authorities.root() {
        return Err(RichEvaluationErrorV1::one(diagnostic(
            "forged-entry-authority",
            format!("entry document {entry} does not belong to the locked root authority"),
            None,
            Vec::new(),
        )));
    }
    if !documents.documents.contains_key(entry) {
        return Err(RichEvaluationErrorV1::one(diagnostic(
            "missing-entry-document",
            format!("entry document {entry} was not captured"),
            None,
            Vec::new(),
        )));
    }
    let mut states = BTreeMap::new();
    let mut stack = Vec::new();
    let mut order = Vec::new();
    let mut includes = Vec::new();
    let mut preflight = PreflightBudget::default();
    visit_document(
        documents,
        entry,
        &mut states,
        &mut stack,
        &mut order,
        &mut includes,
        &mut preflight,
    )?;
    if order.len() != documents.documents.len() {
        let unreachable = documents
            .documents
            .keys()
            .find(|id| !states.contains_key(*id))
            .expect("different counts imply one document was not visited");
        return Err(RichEvaluationErrorV1::one(diagnostic(
            "unreachable-captured-document",
            format!("captured document {unreachable} is not reachable from entry {entry}"),
            None,
            Vec::new(),
        )));
    }
    Ok(ResolvedGraph {
        order,
        includes,
        preflight,
    })
}

fn visit_document(
    documents: &CapturedDocumentSetV1,
    id: &CapturedDocumentIdV1,
    states: &mut BTreeMap<CapturedDocumentIdV1, u8>,
    stack: &mut Vec<CapturedDocumentIdV1>,
    order: &mut Vec<CapturedDocumentIdV1>,
    includes: &mut Vec<IncludeProvenanceV1>,
    preflight: &mut PreflightBudget,
) -> Result<(), RichEvaluationErrorV1> {
    match states.get(id).copied() {
        Some(2) => return Ok(()),
        Some(1) => {
            let cycle_start = stack
                .iter()
                .position(|candidate| candidate == id)
                .unwrap_or(0);
            let mut cycle = stack[cycle_start..]
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>();
            cycle.push(id.to_string());
            return Err(RichEvaluationErrorV1::one(diagnostic(
                "include-cycle",
                format!("include graph contains a cycle at {id}"),
                None,
                vec![format!("cycle: {}", cycle.join(" -> "))],
            )));
        }
        _ => {}
    }
    if stack.len() >= MAX_RICH_INCLUDE_DEPTH {
        return Err(RichEvaluationErrorV1::one(diagnostic(
            "include-depth-limit",
            format!("include depth exceeds {MAX_RICH_INCLUDE_DEPTH}"),
            None,
            Vec::new(),
        )));
    }
    states.insert(id.clone(), 1);
    stack.push(id.clone());
    let document = documents
        .documents
        .get(id)
        .expect("the entry and every traversed target were checked");
    validate_document_ranges(document, preflight)?;
    for include in document.includes() {
        let location = SourceLocationV1::new(id.clone(), include.range());
        let Some(target) = documents.documents.get(include.target()) else {
            return Err(RichEvaluationErrorV1::one(diagnostic(
                "missing-include",
                format!("included document {} was not captured", include.target()),
                Some(RichDiagnosticLocationV1::Source(location)),
                Vec::new(),
            )));
        };
        includes.push(IncludeProvenanceV1::new(
            location,
            include.target().clone(),
            target.digest().clone(),
            include.dependency().cloned(),
            include.kind().clone(),
        ));
        visit_document(
            documents,
            include.target(),
            states,
            stack,
            order,
            includes,
            preflight,
        )?;
    }
    stack.pop();
    states.insert(id.clone(), 2);
    order.push(id.clone());
    Ok(())
}

#[derive(Default)]
struct PreflightBudget {
    statements: usize,
    expression_nodes: usize,
}

fn validate_document_ranges(
    document: &CapturedConfigDocumentV1,
    budget: &mut PreflightBudget,
) -> Result<(), RichEvaluationErrorV1> {
    for include in document.includes() {
        validate_range(document, include.range())?;
    }
    for variable in document.body().variables.values() {
        validate_range(document, variable.range)?;
        match &variable.source {
            VariableSourceV1::Input {
                default: Some(default),
                ..
            }
            | VariableSourceV1::Computed(default) => validate_expression_shape(
                document,
                default,
                variable.range,
                1,
                &mut budget.expression_nodes,
            )?,
            VariableSourceV1::Input { default: None, .. } => {}
        }
    }
    for fragment in document.body().fragments.values() {
        validate_range(document, fragment.range)?;
        validate_statement_ranges(
            document,
            &fragment.statements,
            1,
            &mut budget.statements,
            &mut budget.expression_nodes,
        )?;
    }
    validate_statement_ranges(
        document,
        &document.body().statements,
        1,
        &mut budget.statements,
        &mut budget.expression_nodes,
    )
}

fn validate_statement_ranges(
    document: &CapturedConfigDocumentV1,
    statements: &[RichStatementV1],
    depth: usize,
    count: &mut usize,
    expression_nodes: &mut usize,
) -> Result<(), RichEvaluationErrorV1> {
    if depth > crate::MAX_RICH_VALUE_DEPTH {
        return Err(RichEvaluationErrorV1::one(diagnostic(
            "statement-depth-limit",
            format!("statement nesting exceeds {}", crate::MAX_RICH_VALUE_DEPTH),
            None,
            Vec::new(),
        )));
    }
    *count = count.saturating_add(statements.len());
    if *count > MAX_RICH_STATEMENTS {
        return Err(RichEvaluationErrorV1::one(diagnostic(
            "statement-limit",
            format!("statement count exceeds {MAX_RICH_STATEMENTS}"),
            None,
            Vec::new(),
        )));
    }
    for statement in statements {
        match statement {
            RichStatementV1::Emit { range, .. }
            | RichStatementV1::Compose { range, .. }
            | RichStatementV1::Conditional { range, .. }
            | RichStatementV1::ForEach { range, .. }
            | RichStatementV1::Range { range, .. } => validate_range(document, *range)?,
            RichStatementV1::Patch(patch) => {
                *count = count.saturating_add(patch.steps.len());
                if *count > MAX_RICH_STATEMENTS {
                    return Err(RichEvaluationErrorV1::one(diagnostic(
                        "statement-limit",
                        format!("statement and patch count exceeds {MAX_RICH_STATEMENTS}"),
                        None,
                        Vec::new(),
                    )));
                }
                for step in &patch.steps {
                    validate_range(document, step.range)?;
                    validate_patch_shape(document, &step.operation, step.range, expression_nodes)?;
                }
            }
        }
        match statement {
            RichStatementV1::Emit { value, range, .. } => {
                validate_expression_shape(document, value, *range, 1, expression_nodes)?;
            }
            RichStatementV1::Conditional {
                condition, range, ..
            } => {
                validate_condition_shape(document, condition, *range, 1, expression_nodes)?;
            }
            RichStatementV1::ForEach {
                iterable, range, ..
            } => {
                validate_expression_shape(document, iterable, *range, 1, expression_nodes)?;
            }
            RichStatementV1::Patch(_)
            | RichStatementV1::Compose { .. }
            | RichStatementV1::Range { .. } => {}
        }
        match statement {
            RichStatementV1::Conditional {
                then_statements,
                else_statements,
                ..
            } => {
                validate_statement_ranges(
                    document,
                    then_statements,
                    depth + 1,
                    count,
                    expression_nodes,
                )?;
                validate_statement_ranges(
                    document,
                    else_statements,
                    depth + 1,
                    count,
                    expression_nodes,
                )?;
            }
            RichStatementV1::ForEach { statements, .. }
            | RichStatementV1::Range { statements, .. } => {
                validate_statement_ranges(
                    document,
                    statements,
                    depth + 1,
                    count,
                    expression_nodes,
                )?;
            }
            RichStatementV1::Emit { .. }
            | RichStatementV1::Patch(_)
            | RichStatementV1::Compose { .. } => {}
        }
    }
    Ok(())
}

fn validate_patch_shape(
    document: &CapturedConfigDocumentV1,
    operation: &PatchOperationV1,
    range: SourceRangeV1,
    expression_nodes: &mut usize,
) -> Result<(), RichEvaluationErrorV1> {
    match operation {
        PatchOperationV1::Set { value, .. } | PatchOperationV1::ListAppend { value, .. } => {
            validate_expression_shape(document, value, range, 1, expression_nodes)
        }
        PatchOperationV1::CollectionInsert { key, value, .. }
        | PatchOperationV1::CollectionReplace { key, value, .. } => {
            validate_expression_shape(document, key, range, 1, expression_nodes)?;
            validate_expression_shape(document, value, range, 1, expression_nodes)
        }
        PatchOperationV1::CollectionRemove { key, .. } => {
            validate_expression_shape(document, key, range, 1, expression_nodes)
        }
        PatchOperationV1::CollectionReplaceAll { values, .. } => {
            if values.len() > MAX_RICH_COLLECTION_ITEMS {
                return Err(preflight_error(
                    document,
                    range,
                    "expression-collection-limit",
                    format!(
                        "collection replacement has more than {MAX_RICH_COLLECTION_ITEMS} items"
                    ),
                ));
            }
            for value in values.values() {
                validate_expression_shape(document, value, range, 1, expression_nodes)?;
            }
            Ok(())
        }
        PatchOperationV1::Unset { .. } => Ok(()),
    }
}

fn validate_expression_shape(
    document: &CapturedConfigDocumentV1,
    expression: &RichExpressionV1,
    range: SourceRangeV1,
    depth: usize,
    nodes: &mut usize,
) -> Result<(), RichEvaluationErrorV1> {
    if depth > crate::MAX_RICH_VALUE_DEPTH {
        return Err(preflight_error(
            document,
            range,
            "expression-depth-limit",
            format!("expression nesting exceeds {}", crate::MAX_RICH_VALUE_DEPTH),
        ));
    }
    *nodes = nodes.saturating_add(1);
    if *nodes > MAX_RICH_EVALUATION_STEPS {
        return Err(preflight_error(
            document,
            range,
            "expression-node-limit",
            format!("expression node count exceeds {MAX_RICH_EVALUATION_STEPS}"),
        ));
    }
    match expression {
        RichExpressionV1::Literal(value) => value.validate().map_err(|error| {
            preflight_error(document, range, "invalid-literal-value", error.to_string())
        }),
        RichExpressionV1::Variable(_) => Ok(()),
        RichExpressionV1::List(values) => {
            if values.len() > MAX_RICH_COLLECTION_ITEMS {
                return Err(preflight_error(
                    document,
                    range,
                    "expression-collection-limit",
                    format!("list expression has more than {MAX_RICH_COLLECTION_ITEMS} items"),
                ));
            }
            for value in values {
                validate_expression_shape(document, value, range, depth + 1, nodes)?;
            }
            Ok(())
        }
        RichExpressionV1::Record(values) | RichExpressionV1::Collection(values) => {
            if values.len() > MAX_RICH_COLLECTION_ITEMS {
                return Err(preflight_error(
                    document,
                    range,
                    "expression-collection-limit",
                    format!("map expression has more than {MAX_RICH_COLLECTION_ITEMS} items"),
                ));
            }
            for value in values.values() {
                validate_expression_shape(document, value, range, depth + 1, nodes)?;
            }
            Ok(())
        }
        RichExpressionV1::Select { value, .. } => {
            validate_expression_shape(document, value, range, depth + 1, nodes)
        }
        RichExpressionV1::Conditional {
            condition,
            then_value,
            else_value,
        } => {
            validate_condition_shape(document, condition, range, depth + 1, nodes)?;
            validate_expression_shape(document, then_value, range, depth + 1, nodes)?;
            validate_expression_shape(document, else_value, range, depth + 1, nodes)
        }
    }
}

fn validate_condition_shape(
    document: &CapturedConfigDocumentV1,
    condition: &RichConditionV1,
    range: SourceRangeV1,
    depth: usize,
    nodes: &mut usize,
) -> Result<(), RichEvaluationErrorV1> {
    if depth > crate::MAX_RICH_VALUE_DEPTH {
        return Err(preflight_error(
            document,
            range,
            "expression-depth-limit",
            format!("condition nesting exceeds {}", crate::MAX_RICH_VALUE_DEPTH),
        ));
    }
    *nodes = nodes.saturating_add(1);
    if *nodes > MAX_RICH_EVALUATION_STEPS {
        return Err(preflight_error(
            document,
            range,
            "expression-node-limit",
            format!("expression node count exceeds {MAX_RICH_EVALUATION_STEPS}"),
        ));
    }
    match condition {
        RichConditionV1::Boolean(value) | RichConditionV1::IsSet(value) => {
            validate_expression_shape(document, value, range, depth + 1, nodes)
        }
        RichConditionV1::Equal { left, right, .. } => {
            validate_expression_shape(document, left, range, depth + 1, nodes)?;
            validate_expression_shape(document, right, range, depth + 1, nodes)
        }
        RichConditionV1::Not(condition) => {
            validate_condition_shape(document, condition, range, depth + 1, nodes)
        }
        RichConditionV1::All(conditions) | RichConditionV1::Any(conditions) => {
            if conditions.len() > MAX_RICH_COLLECTION_ITEMS {
                return Err(preflight_error(
                    document,
                    range,
                    "condition-term-limit",
                    format!("condition has more than {MAX_RICH_COLLECTION_ITEMS} terms"),
                ));
            }
            for condition in conditions {
                validate_condition_shape(document, condition, range, depth + 1, nodes)?;
            }
            Ok(())
        }
    }
}

fn preflight_error(
    document: &CapturedConfigDocumentV1,
    range: SourceRangeV1,
    code: &str,
    message: impl Into<String>,
) -> RichEvaluationErrorV1 {
    RichEvaluationErrorV1::one(diagnostic(
        code,
        message,
        Some(RichDiagnosticLocationV1::Source(SourceLocationV1::new(
            document.id().clone(),
            range,
        ))),
        Vec::new(),
    ))
}

fn validate_range(
    document: &CapturedConfigDocumentV1,
    range: SourceRangeV1,
) -> Result<(), RichEvaluationErrorV1> {
    if usize::try_from(range.end()).unwrap_or(usize::MAX) > document.bytes().len() {
        let location = SourceLocationV1::new(document.id().clone(), range);
        return Err(RichEvaluationErrorV1::one(diagnostic(
            "invalid-source-range",
            format!(
                "source range {}..{} exceeds the {} captured bytes",
                range.start(),
                range.end(),
                document.bytes().len()
            ),
            Some(RichDiagnosticLocationV1::Source(location)),
            Vec::new(),
        )));
    }
    Ok(())
}

#[derive(Clone)]
struct LocatedVariable {
    document: CapturedDocumentIdV1,
    declaration: VariableDeclarationV1,
}

#[derive(Clone)]
struct LocatedFragment {
    document: CapturedDocumentIdV1,
    declaration: FragmentDeclarationV1,
}

pub(crate) struct LocatedRichStatementV1 {
    pub(crate) document: CapturedDocumentIdV1,
    pub(crate) statement: RichStatementV1,
}

struct CollectedProgram {
    variables: BTreeMap<RichNameV1, LocatedVariable>,
    fragments: BTreeMap<RichNameV1, LocatedFragment>,
    statements: Vec<LocatedRichStatementV1>,
}

fn collect_program(
    documents: &CapturedDocumentSetV1,
    order: &[CapturedDocumentIdV1],
) -> Result<CollectedProgram, RichEvaluationErrorV1> {
    let mut variables = BTreeMap::new();
    let mut fragments = BTreeMap::new();
    let mut statements = Vec::new();
    for id in order {
        let document = documents
            .documents
            .get(id)
            .expect("resolved graph nodes remain captured");
        collect_variables(id, document.body(), &mut variables)?;
        collect_fragments(id, document.body(), &mut fragments)?;
        statements.extend(document.body().statements.iter().cloned().map(|statement| {
            LocatedRichStatementV1 {
                document: id.clone(),
                statement,
            }
        }));
    }
    if variables.len() > MAX_RICH_VARIABLES {
        return Err(RichEvaluationErrorV1::one(diagnostic(
            "variable-limit",
            format!("variable count exceeds {MAX_RICH_VARIABLES}"),
            None,
            Vec::new(),
        )));
    }
    if fragments.len() > MAX_RICH_FRAGMENTS {
        return Err(RichEvaluationErrorV1::one(diagnostic(
            "fragment-limit",
            format!("fragment count exceeds {MAX_RICH_FRAGMENTS}"),
            None,
            Vec::new(),
        )));
    }
    Ok(CollectedProgram {
        variables,
        fragments,
        statements,
    })
}

fn collect_variables(
    id: &CapturedDocumentIdV1,
    body: &RichDocumentBodyV1,
    variables: &mut BTreeMap<RichNameV1, LocatedVariable>,
) -> Result<(), RichEvaluationErrorV1> {
    for (name, declaration) in &body.variables {
        if let Some(previous) = variables.get(name) {
            return Err(RichEvaluationErrorV1::one(diagnostic(
                "duplicate-variable",
                format!("variable {name} is declared more than once"),
                Some(RichDiagnosticLocationV1::Source(SourceLocationV1::new(
                    id.clone(),
                    declaration.range,
                ))),
                vec![format!("first declared in {}", previous.document)],
            )));
        }
        if variables.len() >= MAX_RICH_VARIABLES {
            return Err(RichEvaluationErrorV1::one(diagnostic(
                "variable-limit",
                format!("variable count exceeds {MAX_RICH_VARIABLES}"),
                Some(RichDiagnosticLocationV1::Source(SourceLocationV1::new(
                    id.clone(),
                    declaration.range,
                ))),
                Vec::new(),
            )));
        }
        variables.insert(
            name.clone(),
            LocatedVariable {
                document: id.clone(),
                declaration: declaration.clone(),
            },
        );
    }
    Ok(())
}

fn collect_fragments(
    id: &CapturedDocumentIdV1,
    body: &RichDocumentBodyV1,
    fragments: &mut BTreeMap<RichNameV1, LocatedFragment>,
) -> Result<(), RichEvaluationErrorV1> {
    for (name, declaration) in &body.fragments {
        if let Some(previous) = fragments.get(name) {
            return Err(RichEvaluationErrorV1::one(diagnostic(
                "duplicate-fragment",
                format!("fragment {name} is declared more than once"),
                Some(RichDiagnosticLocationV1::Source(SourceLocationV1::new(
                    id.clone(),
                    declaration.range,
                ))),
                vec![format!("first declared in {}", previous.document)],
            )));
        }
        if fragments.len() >= MAX_RICH_FRAGMENTS {
            return Err(RichEvaluationErrorV1::one(diagnostic(
                "fragment-limit",
                format!("fragment count exceeds {MAX_RICH_FRAGMENTS}"),
                Some(RichDiagnosticLocationV1::Source(SourceLocationV1::new(
                    id.clone(),
                    declaration.range,
                ))),
                Vec::new(),
            )));
        }
        fragments.insert(
            name.clone(),
            LocatedFragment {
                document: id.clone(),
                declaration: declaration.clone(),
            },
        );
    }
    Ok(())
}

struct Evaluator<'a> {
    variables: BTreeMap<RichNameV1, LocatedVariable>,
    fragments: BTreeMap<RichNameV1, LocatedFragment>,
    supplied: &'a BTreeMap<RichNameV1, TypedValueV1>,
    states: BTreeMap<RichNameV1, u8>,
    variable_stack: Vec<RichNameV1>,
    fragment_stack: Vec<RichNameV1>,
    resolved: BTreeMap<RichNameV1, ResolvedVariableV1>,
    root: BTreeMap<RichKeyV1, TypedValueV1>,
    document_provenance: BTreeMap<RichValuePathV1, Vec<ProvenanceRecordV1>>,
    frames: Vec<EvaluationFrameV1>,
    sequence: u64,
    steps: usize,
    loop_iterations: usize,
}

impl<'a> Evaluator<'a> {
    fn new(
        variables: BTreeMap<RichNameV1, LocatedVariable>,
        fragments: BTreeMap<RichNameV1, LocatedFragment>,
        supplied: &'a BTreeMap<RichNameV1, TypedValueV1>,
    ) -> Self {
        Self {
            variables,
            fragments,
            supplied,
            states: BTreeMap::new(),
            variable_stack: Vec::new(),
            fragment_stack: Vec::new(),
            resolved: BTreeMap::new(),
            root: BTreeMap::new(),
            document_provenance: BTreeMap::new(),
            frames: Vec::new(),
            sequence: 0,
            steps: 0,
            loop_iterations: 0,
        }
    }

    fn resolve_all_variables(&mut self) -> Result<(), RichEvaluationErrorV1> {
        for (name, value) in self.supplied {
            let Some(declaration) = self.variables.get(name) else {
                return Err(RichEvaluationErrorV1::one(diagnostic(
                    "unknown-supplied-variable",
                    format!("no input variable named {name} is declared"),
                    None,
                    Vec::new(),
                )));
            };
            if matches!(
                declaration.declaration.source,
                VariableSourceV1::Computed(_)
            ) {
                return Err(RichEvaluationErrorV1::one(diagnostic(
                    "computed-variable-supplied",
                    format!("computed variable {name} cannot be supplied"),
                    Some(RichDiagnosticLocationV1::Source(SourceLocationV1::new(
                        declaration.document.clone(),
                        declaration.declaration.range,
                    ))),
                    Vec::new(),
                )));
            }
            value.validate().map_err(|error| {
                RichEvaluationErrorV1::one(diagnostic(
                    "invalid-supplied-value",
                    format!("supplied variable {name}: {error}"),
                    None,
                    Vec::new(),
                ))
            })?;
        }
        let names = self.variables.keys().cloned().collect::<Vec<_>>();
        for name in names {
            self.resolve_variable(&name)?;
        }
        Ok(())
    }

    fn resolve_variable(
        &mut self,
        name: &RichNameV1,
    ) -> Result<TypedValueV1, RichEvaluationErrorV1> {
        if let Some(resolved) = self.resolved.get(name) {
            return Ok(resolved.value.clone());
        }
        if self.states.get(name) == Some(&1) {
            let start = self
                .variable_stack
                .iter()
                .position(|candidate| candidate == name)
                .unwrap_or(0);
            let mut cycle = self.variable_stack[start..]
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>();
            cycle.push(name.to_string());
            return Err(RichEvaluationErrorV1::one(diagnostic(
                "variable-cycle",
                format!("variable references form a cycle at {name}"),
                None,
                vec![format!("cycle: {}", cycle.join(" -> "))],
            )));
        }
        let located = self.variables.get(name).cloned().ok_or_else(|| {
            RichEvaluationErrorV1::one(diagnostic(
                "unknown-variable",
                format!("unknown variable {name}"),
                None,
                Vec::new(),
            ))
        })?;
        self.states.insert(name.clone(), 1);
        self.variable_stack.push(name.clone());
        let location = SourceLocationV1::new(located.document.clone(), located.declaration.range);
        let (raw, operation) = match &located.declaration.source {
            VariableSourceV1::Computed(expression) => (
                self.eval_expression(expression, &BTreeMap::new(), &location)?,
                ProvenanceOperationV1::VariableComputed,
            ),
            VariableSourceV1::Input { optional, default } => {
                if let Some(value) = self.supplied.get(name) {
                    (value.clone(), ProvenanceOperationV1::VariableSupplied)
                } else if let Some(default) = default {
                    (
                        self.eval_expression(default, &BTreeMap::new(), &location)?,
                        ProvenanceOperationV1::VariableDefault,
                    )
                } else if *optional {
                    (
                        TypedValueV1::null(),
                        ProvenanceOperationV1::VariableOptionalAbsent,
                    )
                } else {
                    return Err(RichEvaluationErrorV1::one(diagnostic(
                        "missing-required-variable",
                        format!("required variable {name} was not supplied"),
                        Some(RichDiagnosticLocationV1::Source(location)),
                        Vec::new(),
                    )));
                }
            }
        };
        let optional = matches!(
            located.declaration.source,
            VariableSourceV1::Input { optional: true, .. }
        );
        let value = located
            .declaration
            .value_type
            .resolve_optional(&raw, optional)
            .map_err(|error| {
                RichEvaluationErrorV1::one(diagnostic(
                    "variable-type-mismatch",
                    format!("variable {name}: {error}"),
                    Some(RichDiagnosticLocationV1::Source(location.clone())),
                    Vec::new(),
                ))
            })?;
        let record = self.provenance_record(location, operation);
        self.variable_stack.pop();
        self.states.insert(name.clone(), 2);
        self.resolved.insert(
            name.clone(),
            ResolvedVariableV1 {
                value: value.clone(),
                provenance: vec![record],
            },
        );
        Ok(value)
    }

    fn eval_expression(
        &mut self,
        expression: &RichExpressionV1,
        locals: &BTreeMap<RichNameV1, TypedValueV1>,
        location: &SourceLocationV1,
    ) -> Result<TypedValueV1, RichEvaluationErrorV1> {
        self.charge(location)?;
        match expression {
            RichExpressionV1::Literal(value) => Ok(value.clone()),
            RichExpressionV1::Variable(name) => locals
                .get(name)
                .cloned()
                .map(Ok)
                .unwrap_or_else(|| self.resolve_variable(name)),
            RichExpressionV1::List(expressions) => {
                if expressions.len() > MAX_RICH_COLLECTION_ITEMS {
                    return Err(self.limit_error(
                        "expression-collection-limit",
                        "list expression",
                        MAX_RICH_COLLECTION_ITEMS,
                        location,
                    ));
                }
                let values = expressions
                    .iter()
                    .map(|expression| self.eval_expression(expression, locals, location))
                    .collect::<Result<Vec<_>, _>>()?;
                TypedValueV1::list(values).map_err(|error| self.value_error(error, location))
            }
            RichExpressionV1::Record(expressions) => {
                self.eval_map(expressions, locals, location, TypedValueV1::record)
            }
            RichExpressionV1::Collection(expressions) => {
                self.eval_map(expressions, locals, location, TypedValueV1::collection)
            }
            RichExpressionV1::Select { value, key } => {
                let value = self.eval_expression(value, locals, location)?;
                match &value.0 {
                    TypedValueDataV1::Record(values) | TypedValueDataV1::Collection(values) => {
                        values.get(key).cloned().ok_or_else(|| {
                            RichEvaluationErrorV1::one(diagnostic(
                                "missing-selected-key",
                                format!("value has no key {key:?}"),
                                Some(RichDiagnosticLocationV1::Source(location.clone())),
                                Vec::new(),
                            ))
                        })
                    }
                    _ => Err(RichEvaluationErrorV1::one(diagnostic(
                        "invalid-selection",
                        format!("cannot select a key from {}", value.kind().as_str()),
                        Some(RichDiagnosticLocationV1::Source(location.clone())),
                        Vec::new(),
                    ))),
                }
            }
            RichExpressionV1::Conditional {
                condition,
                then_value,
                else_value,
            } => {
                if self.eval_condition(condition, locals, location)? {
                    self.eval_expression(then_value, locals, location)
                } else {
                    self.eval_expression(else_value, locals, location)
                }
            }
        }
    }

    fn eval_map(
        &mut self,
        expressions: &BTreeMap<RichKeyV1, RichExpressionV1>,
        locals: &BTreeMap<RichNameV1, TypedValueV1>,
        location: &SourceLocationV1,
        construct: impl FnOnce(
            BTreeMap<RichKeyV1, TypedValueV1>,
        ) -> Result<TypedValueV1, crate::RichConfigErrorV1>,
    ) -> Result<TypedValueV1, RichEvaluationErrorV1> {
        if expressions.len() > MAX_RICH_COLLECTION_ITEMS {
            return Err(self.limit_error(
                "expression-collection-limit",
                "map expression",
                MAX_RICH_COLLECTION_ITEMS,
                location,
            ));
        }
        let mut values = BTreeMap::new();
        for (key, expression) in expressions {
            values.insert(
                key.clone(),
                self.eval_expression(expression, locals, location)?,
            );
        }
        construct(values).map_err(|error| self.value_error(error, location))
    }

    fn eval_condition(
        &mut self,
        condition: &RichConditionV1,
        locals: &BTreeMap<RichNameV1, TypedValueV1>,
        location: &SourceLocationV1,
    ) -> Result<bool, RichEvaluationErrorV1> {
        self.charge(location)?;
        match condition {
            RichConditionV1::Boolean(expression) => {
                let value = self.eval_expression(expression, locals, location)?;
                value.as_bool().ok_or_else(|| {
                    RichEvaluationErrorV1::one(diagnostic(
                        "condition-type-mismatch",
                        format!(
                            "boolean condition found {} instead of bool",
                            value.kind().as_str()
                        ),
                        Some(RichDiagnosticLocationV1::Source(location.clone())),
                        Vec::new(),
                    ))
                })
            }
            RichConditionV1::IsSet(expression) => self
                .eval_expression(expression, locals, location)
                .map(|value| value.kind() != TypedValueKindV1::Null),
            RichConditionV1::Equal {
                left,
                right,
                negated,
            } => {
                let equal = self.eval_expression(left, locals, location)?
                    == self.eval_expression(right, locals, location)?;
                Ok(if *negated { !equal } else { equal })
            }
            RichConditionV1::Not(condition) => self
                .eval_condition(condition, locals, location)
                .map(|value| !value),
            RichConditionV1::All(conditions) => {
                if conditions.len() > MAX_RICH_COLLECTION_ITEMS {
                    return Err(self.limit_error(
                        "condition-term-limit",
                        "condition terms",
                        MAX_RICH_COLLECTION_ITEMS,
                        location,
                    ));
                }
                for condition in conditions {
                    if !self.eval_condition(condition, locals, location)? {
                        return Ok(false);
                    }
                }
                Ok(true)
            }
            RichConditionV1::Any(conditions) => {
                if conditions.len() > MAX_RICH_COLLECTION_ITEMS {
                    return Err(self.limit_error(
                        "condition-term-limit",
                        "condition terms",
                        MAX_RICH_COLLECTION_ITEMS,
                        location,
                    ));
                }
                for condition in conditions {
                    if self.eval_condition(condition, locals, location)? {
                        return Ok(true);
                    }
                }
                Ok(false)
            }
        }
    }

    fn execute_statements(
        &mut self,
        document: &CapturedDocumentIdV1,
        statements: &[RichStatementV1],
        locals: &BTreeMap<RichNameV1, TypedValueV1>,
    ) -> Result<(), RichEvaluationErrorV1> {
        for statement in statements {
            let range = statement_range(statement);
            let location = SourceLocationV1::new(document.clone(), range);
            self.charge(&location)?;
            match statement {
                RichStatementV1::Emit { key, value, .. } => {
                    if self.root.contains_key(key) {
                        return Err(RichEvaluationErrorV1::one(diagnostic(
                            "duplicate-document-key",
                            format!("document root key {key:?} was emitted more than once"),
                            Some(RichDiagnosticLocationV1::Source(location)),
                            Vec::new(),
                        )));
                    }
                    let value = self.eval_expression(value, locals, &location)?;
                    self.root.insert(key.clone(), value);
                    self.add_document_provenance(
                        RichValuePathV1::root(key.clone()),
                        location,
                        ProvenanceOperationV1::Emit,
                    )?;
                }
                RichStatementV1::Patch(patch) => {
                    for (index, step) in patch.steps.iter().enumerate() {
                        let location = SourceLocationV1::new(document.clone(), step.range);
                        self.charge(&location)?;
                        self.apply_patch(
                            &step.operation,
                            u32::try_from(index).unwrap_or(u32::MAX),
                            locals,
                            location,
                        )?;
                    }
                }
                RichStatementV1::Compose {
                    fragment, range, ..
                } => {
                    let fragment_location = SourceLocationV1::new(document.clone(), *range);
                    self.compose_fragment(fragment, locals, fragment_location)?;
                }
                RichStatementV1::Conditional {
                    condition,
                    then_statements,
                    else_statements,
                    ..
                } => {
                    let then_branch = self.eval_condition(condition, locals, &location)?;
                    self.frames
                        .push(EvaluationFrameV1::Conditional { then_branch });
                    let selected = if then_branch {
                        then_statements
                    } else {
                        else_statements
                    };
                    self.execute_statements(document, selected, locals)?;
                    self.frames.pop();
                }
                RichStatementV1::ForEach {
                    value_binding,
                    key_binding,
                    iterable,
                    statements,
                    ..
                } => {
                    if key_binding.as_ref() == Some(value_binding) {
                        return Err(RichEvaluationErrorV1::one(diagnostic(
                            "duplicate-loop-binding",
                            format!("loop uses {value_binding} for both key and value"),
                            Some(RichDiagnosticLocationV1::Source(location)),
                            Vec::new(),
                        )));
                    }
                    let iterable = self.eval_expression(iterable, locals, &location)?;
                    let items = loop_items(iterable, &location)?;
                    self.charge_loop(items.len(), &location)?;
                    for (iteration, (key, value)) in items.into_iter().enumerate() {
                        let mut iteration_locals = locals.clone();
                        if iteration_locals.contains_key(value_binding)
                            || key_binding
                                .as_ref()
                                .is_some_and(|name| iteration_locals.contains_key(name))
                        {
                            return Err(RichEvaluationErrorV1::one(diagnostic(
                                "shadowed-loop-binding",
                                "nested loops must use distinct binding names",
                                Some(RichDiagnosticLocationV1::Source(location.clone())),
                                Vec::new(),
                            )));
                        }
                        iteration_locals.insert(value_binding.clone(), value);
                        if let Some(binding) = key_binding {
                            iteration_locals.insert(binding.clone(), key);
                        }
                        self.frames.push(EvaluationFrameV1::Loop {
                            binding: value_binding.clone(),
                            iteration: u32::try_from(iteration).unwrap_or(u32::MAX),
                        });
                        self.execute_statements(document, statements, &iteration_locals)?;
                        self.frames.pop();
                    }
                }
                RichStatementV1::Range {
                    binding,
                    from,
                    through,
                    statements,
                    ..
                } => {
                    if through < from {
                        return Err(RichEvaluationErrorV1::one(diagnostic(
                            "invalid-range-loop",
                            format!("range loop start {from} exceeds end {through}"),
                            Some(RichDiagnosticLocationV1::Source(location)),
                            Vec::new(),
                        )));
                    }
                    let count_i128 = i128::from(*through) - i128::from(*from) + 1;
                    let count = usize::try_from(count_i128).unwrap_or(usize::MAX);
                    self.charge_loop(count, &location)?;
                    for iteration in 0..count {
                        if locals.contains_key(binding) {
                            return Err(RichEvaluationErrorV1::one(diagnostic(
                                "shadowed-loop-binding",
                                "nested loops must use distinct binding names",
                                Some(RichDiagnosticLocationV1::Source(location.clone())),
                                Vec::new(),
                            )));
                        }
                        let value = i128::from(*from)
                            + i128::try_from(iteration).expect("usize loop count fits i128");
                        let mut iteration_locals = locals.clone();
                        iteration_locals.insert(
                            binding.clone(),
                            TypedValueV1::integer(
                                i64::try_from(value).expect("value remains between i64 endpoints"),
                            ),
                        );
                        self.frames.push(EvaluationFrameV1::Loop {
                            binding: binding.clone(),
                            iteration: u32::try_from(iteration).unwrap_or(u32::MAX),
                        });
                        self.execute_statements(document, statements, &iteration_locals)?;
                        self.frames.pop();
                    }
                }
            }
        }
        Ok(())
    }

    fn compose_fragment(
        &mut self,
        name: &RichNameV1,
        locals: &BTreeMap<RichNameV1, TypedValueV1>,
        location: SourceLocationV1,
    ) -> Result<(), RichEvaluationErrorV1> {
        if let Some(start) = self
            .fragment_stack
            .iter()
            .position(|candidate| candidate == name)
        {
            let mut cycle = self.fragment_stack[start..]
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>();
            cycle.push(name.to_string());
            return Err(RichEvaluationErrorV1::one(diagnostic(
                "fragment-cycle",
                format!("fragment composition forms a cycle at {name}"),
                Some(RichDiagnosticLocationV1::Source(location)),
                vec![format!("cycle: {}", cycle.join(" -> "))],
            )));
        }
        if self.fragment_stack.len() >= crate::MAX_RICH_VALUE_DEPTH {
            return Err(RichEvaluationErrorV1::one(diagnostic(
                "fragment-depth-limit",
                format!(
                    "fragment composition depth exceeds {}",
                    crate::MAX_RICH_VALUE_DEPTH
                ),
                Some(RichDiagnosticLocationV1::Source(location)),
                Vec::new(),
            )));
        }
        let fragment = self.fragments.get(name).cloned().ok_or_else(|| {
            RichEvaluationErrorV1::one(diagnostic(
                "unknown-fragment",
                format!("unknown fragment {name}"),
                Some(RichDiagnosticLocationV1::Source(location.clone())),
                Vec::new(),
            ))
        })?;
        self.fragment_stack.push(name.clone());
        self.frames.push(EvaluationFrameV1::Fragment(name.clone()));
        self.execute_statements(&fragment.document, &fragment.declaration.statements, locals)?;
        self.frames.pop();
        self.fragment_stack.pop();
        Ok(())
    }

    fn apply_patch(
        &mut self,
        operation: &PatchOperationV1,
        operation_index: u32,
        locals: &BTreeMap<RichNameV1, TypedValueV1>,
        location: SourceLocationV1,
    ) -> Result<(), RichEvaluationErrorV1> {
        let operation_kind = ProvenanceOperationV1::Patch {
            operation: operation_index,
        };
        match operation {
            PatchOperationV1::Set { path, value } => {
                let value = self.eval_expression(value, locals, &location)?;
                set_path(&mut self.root, path, value)
                    .map_err(|message| patch_error(message, location.clone()))?;
                self.add_document_provenance(path.clone(), location, operation_kind)
            }
            PatchOperationV1::Unset { path, optional } => {
                let removed = remove_path(&mut self.root, path)
                    .map_err(|message| patch_error(message, location.clone()))?;
                if !removed && !optional {
                    return Err(patch_error(
                        format!("cannot unset missing path {}", display_path(path)),
                        location,
                    ));
                }
                self.add_document_provenance(path.clone(), location, operation_kind)
            }
            PatchOperationV1::ListAppend { path, value } => {
                let value = self.eval_expression(value, locals, &location)?;
                let target = get_path_mut(&mut self.root, path).ok_or_else(|| {
                    patch_error(
                        format!("list path {} does not exist", display_path(path)),
                        location.clone(),
                    )
                })?;
                let values = target.as_list_mut().ok_or_else(|| {
                    patch_error(
                        format!("path {} is not a list", display_path(path)),
                        location.clone(),
                    )
                })?;
                if values.len() >= MAX_RICH_COLLECTION_ITEMS {
                    return Err(self.limit_error(
                        "patch-collection-limit",
                        "patched list items",
                        MAX_RICH_COLLECTION_ITEMS,
                        &location,
                    ));
                }
                values.push(value);
                self.add_document_provenance(path.clone(), location, operation_kind)
            }
            PatchOperationV1::CollectionInsert { path, key, value } => {
                let key = self.eval_collection_key(key, locals, &location)?;
                let value = self.eval_expression(value, locals, &location)?;
                let collection = self.collection_at_mut(path, &location)?;
                if collection.contains_key(&key) {
                    return Err(patch_error(
                        format!("collection key {key:?} already exists"),
                        location,
                    ));
                }
                if collection.len() >= MAX_RICH_COLLECTION_ITEMS {
                    return Err(self.limit_error(
                        "patch-collection-limit",
                        "patched collection items",
                        MAX_RICH_COLLECTION_ITEMS,
                        &location,
                    ));
                }
                collection.insert(key.clone(), value);
                let target = path
                    .with_suffix(key)
                    .map_err(|error| self.value_error(error, &location))?;
                self.add_document_provenance(target, location, operation_kind)
            }
            PatchOperationV1::CollectionReplace { path, key, value } => {
                let key = self.eval_collection_key(key, locals, &location)?;
                let value = self.eval_expression(value, locals, &location)?;
                let collection = self.collection_at_mut(path, &location)?;
                let Some(target_value) = collection.get_mut(&key) else {
                    return Err(patch_error(
                        format!("collection key {key:?} does not exist"),
                        location,
                    ));
                };
                *target_value = value;
                let target = path
                    .with_suffix(key)
                    .map_err(|error| self.value_error(error, &location))?;
                self.add_document_provenance(target, location, operation_kind)
            }
            PatchOperationV1::CollectionRemove {
                path,
                key,
                optional,
            } => {
                let key = self.eval_collection_key(key, locals, &location)?;
                let collection = self.collection_at_mut(path, &location)?;
                if collection.remove(&key).is_none() && !optional {
                    return Err(patch_error(
                        format!("collection key {key:?} does not exist"),
                        location,
                    ));
                }
                let target = path
                    .with_suffix(key)
                    .map_err(|error| self.value_error(error, &location))?;
                self.add_document_provenance(target, location, operation_kind)
            }
            PatchOperationV1::CollectionReplaceAll { path, values } => {
                if values.len() > MAX_RICH_COLLECTION_ITEMS {
                    return Err(self.limit_error(
                        "patch-collection-limit",
                        "replacement collection items",
                        MAX_RICH_COLLECTION_ITEMS,
                        &location,
                    ));
                }
                let mut replacement = BTreeMap::new();
                for (key, expression) in values {
                    replacement.insert(
                        key.clone(),
                        self.eval_expression(expression, locals, &location)?,
                    );
                }
                let collection = self.collection_at_mut(path, &location)?;
                *collection = replacement;
                self.document_provenance
                    .retain(|candidate, _| !path_is_strict_prefix(path, candidate));
                self.add_document_provenance(path.clone(), location, operation_kind)
            }
        }
    }

    fn eval_collection_key(
        &mut self,
        expression: &RichExpressionV1,
        locals: &BTreeMap<RichNameV1, TypedValueV1>,
        location: &SourceLocationV1,
    ) -> Result<RichKeyV1, RichEvaluationErrorV1> {
        let value = self.eval_expression(expression, locals, location)?;
        let Some(value) = value.as_string() else {
            return Err(patch_error(
                format!(
                    "collection patch key must be a string, found {}",
                    value.kind().as_str()
                ),
                location.clone(),
            ));
        };
        RichKeyV1::new(value).map_err(|error| self.value_error(error, location))
    }

    fn collection_at_mut(
        &mut self,
        path: &RichValuePathV1,
        location: &SourceLocationV1,
    ) -> Result<&mut BTreeMap<RichKeyV1, TypedValueV1>, RichEvaluationErrorV1> {
        let target = get_path_mut(&mut self.root, path).ok_or_else(|| {
            patch_error(
                format!("collection path {} does not exist", display_path(path)),
                location.clone(),
            )
        })?;
        target.as_collection_mut().ok_or_else(|| {
            patch_error(
                format!("path {} is not a collection", display_path(path)),
                location.clone(),
            )
        })
    }

    fn charge(&mut self, location: &SourceLocationV1) -> Result<(), RichEvaluationErrorV1> {
        self.steps = self.steps.saturating_add(1);
        if self.steps > MAX_RICH_EVALUATION_STEPS {
            return Err(self.limit_error(
                "evaluation-step-limit",
                "evaluation steps",
                MAX_RICH_EVALUATION_STEPS,
                location,
            ));
        }
        Ok(())
    }

    fn charge_loop(
        &mut self,
        count: usize,
        location: &SourceLocationV1,
    ) -> Result<(), RichEvaluationErrorV1> {
        if count > MAX_RICH_LOOP_ITERATIONS {
            return Err(self.limit_error(
                "loop-iteration-limit",
                "loop iterations",
                MAX_RICH_LOOP_ITERATIONS,
                location,
            ));
        }
        self.loop_iterations = self.loop_iterations.saturating_add(count);
        if self.loop_iterations > MAX_RICH_TOTAL_LOOP_ITERATIONS {
            return Err(self.limit_error(
                "total-loop-iteration-limit",
                "total loop iterations",
                MAX_RICH_TOTAL_LOOP_ITERATIONS,
                location,
            ));
        }
        Ok(())
    }

    fn provenance_record(
        &mut self,
        location: SourceLocationV1,
        operation: ProvenanceOperationV1,
    ) -> ProvenanceRecordV1 {
        let record =
            ProvenanceRecordV1::new(self.sequence, location, operation, self.frames.clone());
        self.sequence = self.sequence.saturating_add(1);
        record
    }

    fn add_document_provenance(
        &mut self,
        path: RichValuePathV1,
        location: SourceLocationV1,
        operation: ProvenanceOperationV1,
    ) -> Result<(), RichEvaluationErrorV1> {
        let count = self
            .document_provenance
            .values()
            .fold(0_usize, |total, records| {
                total.saturating_add(records.len())
            });
        if count >= MAX_RICH_PROVENANCE_RECORDS {
            return Err(self.limit_error(
                "provenance-limit",
                "provenance records",
                MAX_RICH_PROVENANCE_RECORDS,
                &location,
            ));
        }
        let record = self.provenance_record(location, operation);
        self.document_provenance
            .entry(path)
            .or_default()
            .push(record);
        Ok(())
    }

    fn limit_error(
        &self,
        code: &str,
        resource: &str,
        limit: usize,
        location: &SourceLocationV1,
    ) -> RichEvaluationErrorV1 {
        RichEvaluationErrorV1::one(diagnostic(
            code,
            format!("{resource} exceed the fixed limit {limit}"),
            Some(RichDiagnosticLocationV1::Source(location.clone())),
            Vec::new(),
        ))
    }

    fn value_error(
        &self,
        error: crate::RichConfigErrorV1,
        location: &SourceLocationV1,
    ) -> RichEvaluationErrorV1 {
        RichEvaluationErrorV1::one(diagnostic(
            "invalid-evaluated-value",
            error.to_string(),
            Some(RichDiagnosticLocationV1::Source(location.clone())),
            Vec::new(),
        ))
    }
}

fn loop_items(
    value: TypedValueV1,
    location: &SourceLocationV1,
) -> Result<Vec<(TypedValueV1, TypedValueV1)>, RichEvaluationErrorV1> {
    match value.0 {
        TypedValueDataV1::List(values) => Ok(values
            .into_iter()
            .enumerate()
            .map(|(index, value)| {
                (
                    TypedValueV1::unsigned(u64::try_from(index).unwrap_or(u64::MAX)),
                    value,
                )
            })
            .collect()),
        TypedValueDataV1::Collection(values) => values
            .into_iter()
            .map(|(key, value)| TypedValueV1::string(key.as_str()).map(|key| (key, value)))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| {
                RichEvaluationErrorV1::one(diagnostic(
                    "invalid-loop-key",
                    error.to_string(),
                    Some(RichDiagnosticLocationV1::Source(location.clone())),
                    Vec::new(),
                ))
            }),
        other => Err(RichEvaluationErrorV1::one(diagnostic(
            "loop-type-mismatch",
            format!(
                "for-each requires a list or collection, found {}",
                TypedValueV1(other).kind().as_str()
            ),
            Some(RichDiagnosticLocationV1::Source(location.clone())),
            Vec::new(),
        ))),
    }
}

fn statement_range(statement: &RichStatementV1) -> SourceRangeV1 {
    match statement {
        RichStatementV1::Emit { range, .. }
        | RichStatementV1::Compose { range, .. }
        | RichStatementV1::Conditional { range, .. }
        | RichStatementV1::ForEach { range, .. }
        | RichStatementV1::Range { range, .. } => *range,
        RichStatementV1::Patch(patch) => patch
            .steps
            .first()
            .map_or(SourceRangeV1::synthetic(), |step| step.range),
    }
}

fn get_path_mut<'a>(
    root: &'a mut BTreeMap<RichKeyV1, TypedValueV1>,
    path: &RichValuePathV1,
) -> Option<&'a mut TypedValueV1> {
    let (first, rest) = path.segments().split_first()?;
    let mut value = root.get_mut(first)?;
    for segment in rest {
        value = match &mut value.0 {
            TypedValueDataV1::Record(values) | TypedValueDataV1::Collection(values) => {
                values.get_mut(segment)?
            }
            _ => return None,
        };
    }
    Some(value)
}

fn set_path(
    root: &mut BTreeMap<RichKeyV1, TypedValueV1>,
    path: &RichValuePathV1,
    value: TypedValueV1,
) -> Result<(), String> {
    let (last, parent) = path
        .segments()
        .split_last()
        .expect("validated paths are nonempty");
    if parent.is_empty() {
        root.insert(last.clone(), value);
        return Ok(());
    }
    let parent_path =
        RichValuePathV1::new(parent.to_vec()).expect("a prefix of a validated path remains valid");
    let parent = get_path_mut(root, &parent_path)
        .ok_or_else(|| format!("patch parent {} does not exist", display_path(&parent_path)))?;
    let record = parent.as_record_mut().ok_or_else(|| {
        format!(
            "patch parent {} is not a record",
            display_path(&parent_path)
        )
    })?;
    record.insert(last.clone(), value);
    Ok(())
}

fn remove_path(
    root: &mut BTreeMap<RichKeyV1, TypedValueV1>,
    path: &RichValuePathV1,
) -> Result<bool, String> {
    let (last, parent) = path
        .segments()
        .split_last()
        .expect("validated paths are nonempty");
    if parent.is_empty() {
        return Ok(root.remove(last).is_some());
    }
    let parent_path =
        RichValuePathV1::new(parent.to_vec()).expect("a prefix of a validated path remains valid");
    let parent = get_path_mut(root, &parent_path)
        .ok_or_else(|| format!("patch parent {} does not exist", display_path(&parent_path)))?;
    let record = parent.as_record_mut().ok_or_else(|| {
        format!(
            "patch parent {} is not a record",
            display_path(&parent_path)
        )
    })?;
    Ok(record.remove(last).is_some())
}

fn path_is_strict_prefix(prefix: &RichValuePathV1, path: &RichValuePathV1) -> bool {
    prefix.segments().len() < path.segments().len()
        && path.segments().starts_with(prefix.segments())
}

fn display_path(path: &RichValuePathV1) -> String {
    path.segments()
        .iter()
        .map(RichKeyV1::as_str)
        .collect::<Vec<_>>()
        .join(".")
}

fn patch_error(message: impl Into<String>, location: SourceLocationV1) -> RichEvaluationErrorV1 {
    RichEvaluationErrorV1::one(diagnostic(
        "invalid-patch",
        message,
        Some(RichDiagnosticLocationV1::Source(location)),
        Vec::new(),
    ))
}

fn diagnostic(
    code: &str,
    message: impl Into<String>,
    primary: Option<RichDiagnosticLocationV1>,
    notes: Vec<String>,
) -> RichDiagnosticV1 {
    let message = bounded_diagnostic_text(message.into(), crate::MAX_RICH_DIAGNOSTIC_BYTES);
    let mut remaining = crate::MAX_RICH_TOTAL_DIAGNOSTIC_BYTES.saturating_sub(message.len());
    let notes = notes
        .into_iter()
        .take(crate::MAX_RICH_DIAGNOSTIC_NOTES)
        .map_while(|note| {
            if remaining == 0 {
                return None;
            }
            let note =
                bounded_diagnostic_text(note, crate::MAX_RICH_DIAGNOSTIC_BYTES.min(remaining));
            remaining = remaining.saturating_sub(note.len());
            Some(note)
        })
        .collect();
    RichDiagnosticV1::new(
        RichDiagnosticSeverityV1::Error,
        RichNameV1::new(code).expect("internal diagnostic codes are valid rich names"),
        message,
        primary,
        notes,
    )
    .expect("internal diagnostics always satisfy fixed bounds")
}

fn bounded_diagnostic_text(mut value: String, limit: usize) -> String {
    const SUFFIX: &str = "...[truncated]";
    if value.len() <= limit {
        return value;
    }
    let suffix = if limit > SUFFIX.len() { SUFFIX } else { "" };
    let mut keep = limit.saturating_sub(suffix.len());
    while !value.is_char_boundary(keep) {
        keep -= 1;
    }
    value.truncate(keep);
    value.push_str(suffix);
    value
}
