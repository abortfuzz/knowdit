use std::{
    collections::{BTreeMap, HashMap, HashSet},
    path::{Path, PathBuf},
};

use color_eyre::eyre::{ContextCompat, WrapErr, ensure};
use foundry_compilers_artifacts::ast::{
    AssignmentOperator, Block, BlockOrStatement, ContractDefinitionPart, Expression,
    ExpressionOrVariableDeclarationStatement, FunctionDefinition, ModifierDefinition, Mutability,
    SourceLocation, SourceUnitPart, Statement, StorageLocation, UnaryOperator, VariableDeclaration,
};
use knowdit_repo_model::{
    cg::{FileChunk, FileLocation},
    inheritance::{ContractInherit, InheritanceGraph},
    storage::{ContractVariable, FunctionStateVariable, StateVariable, StorageGraph},
};

use crate::{IdMaps, NodeID, SourceUnitInput};

/// Result of the storage / state-variable analysis pass. Inheritance
/// edges fall out of the same AST walk so we surface them here; the
/// `InheritanceGraph` is its own value object so callers that don't
/// care about storage (e.g. interface dispatch) can stash just that.
#[derive(Debug, Clone)]
pub struct StorageAnalysisResult {
    pub storage: StorageGraph,
    pub inheritance: InheritanceGraph,
    pub state_variable_count: usize,
    pub contract_inherit_count: usize,
    pub contract_variable_count: usize,
    pub function_state_variable_count: usize,
}

/// Run state-variable analysis over the same source units the call graph saw, reusing the
/// id maps produced by the call graph builder.
pub fn analyze_storage(
    repo_root: &Path,
    inputs: &[SourceUnitInput],
    id_maps: &IdMaps,
) -> Result<StorageAnalysisResult, color_eyre::Report> {
    let mut analyzer = StorageAnalyzer::new(repo_root, id_maps);
    for input in inputs {
        analyzer.collect_state_vars(input)?;
    }
    for input in inputs {
        analyzer.analyze_functions(input)?;
    }

    let state_variable_count = analyzer.state_variables.len();
    let contract_inherit_count = analyzer.contract_inherits.len();
    let contract_variable_count = analyzer.contract_variables.len();
    let function_state_variable_count = analyzer.function_state_variables.len();

    Ok(StorageAnalysisResult {
        storage: StorageGraph {
            state_variables: analyzer.state_variables,
            contract_variables: analyzer.contract_variables,
            function_state_variables: analyzer.function_state_variables,
        },
        inheritance: InheritanceGraph::new(analyzer.contract_inherits),
        state_variable_count,
        contract_inherit_count,
        contract_variable_count,
        function_state_variable_count,
    })
}

struct StorageAnalyzer<'a> {
    repo_root: &'a Path,
    id_maps: &'a IdMaps,
    state_variables: BTreeMap<i32, StateVariable>,
    contract_variables: Vec<ContractVariable>,
    function_state_variables: Vec<FunctionStateVariable>,
    contract_inherits: Vec<ContractInherit>,
    /// Solc state-variable NodeID → assigned project-local state variable id. State variables
    /// span all contracts; we assign ids on first sight (sorted by NodeID for stability).
    state_var_id_by_node: HashMap<NodeID, i32>,
    next_state_var_id: i32,
}

impl<'a> StorageAnalyzer<'a> {
    fn new(repo_root: &'a Path, id_maps: &'a IdMaps) -> Self {
        Self {
            repo_root,
            id_maps,
            state_variables: BTreeMap::new(),
            contract_variables: Vec::new(),
            function_state_variables: Vec::new(),
            contract_inherits: Vec::new(),
            state_var_id_by_node: HashMap::new(),
            next_state_var_id: 1,
        }
    }

    fn collect_state_vars(&mut self, input: &SourceUnitInput) -> Result<(), color_eyre::Report> {
        let source = input.source.as_str();
        let relative_file_path = self.relative_path(&input.absolute_path);

        for node in &input.source_unit.nodes {
            let SourceUnitPart::ContractDefinition(contract) = node else {
                continue;
            };
            let contract_node_id = contract.id as NodeID;
            let Some(&contract_id) = self.id_maps.contract_id_by_node.get(&contract_node_id) else {
                continue;
            };

            for spec in &contract.base_contracts {
                if let Some(parent_node_id) = base_contract_target(&spec.base_name)
                    && let Some(&parent_id) = self.id_maps.contract_id_by_node.get(&parent_node_id)
                {
                    self.contract_inherits.push(ContractInherit {
                        contract_id,
                        inherited_id: parent_id,
                    });
                }
            }

            for member in &contract.nodes {
                let ContractDefinitionPart::VariableDeclaration(var) = member else {
                    continue;
                };
                if !is_state_variable(var) {
                    continue;
                }
                let sv_node_id = var.id as NodeID;
                if self.state_var_id_by_node.contains_key(&sv_node_id) {
                    continue;
                }
                let chunk = chunk_from_src(&var.src, source).wrap_err_with(|| {
                    format!(
                        "failed to compute source range for state variable {} in {}",
                        var.name, input.absolute_path
                    )
                })?;
                let id = self.next_state_var_id;
                self.next_state_var_id += 1;
                self.state_var_id_by_node.insert(sv_node_id, id);
                self.state_variables.insert(
                    id,
                    StateVariable {
                        id,
                        name: var.name.clone(),
                        type_name: var
                            .type_descriptions
                            .type_string
                            .clone()
                            .unwrap_or_default(),
                        relative_file_path: relative_file_path.clone(),
                        loc: chunk.loc,
                        content: chunk.content,
                    },
                );
                self.contract_variables.push(ContractVariable {
                    contract_id,
                    state_variable_id: id,
                    description: None,
                });
            }
        }
        Ok(())
    }

    fn analyze_functions(&mut self, input: &SourceUnitInput) -> Result<(), color_eyre::Report> {
        for node in &input.source_unit.nodes {
            let SourceUnitPart::ContractDefinition(contract) = node else {
                continue;
            };
            for member in &contract.nodes {
                match member {
                    ContractDefinitionPart::FunctionDefinition(function) => {
                        self.analyze_function(function);
                    }
                    ContractDefinitionPart::ModifierDefinition(modifier) => {
                        self.analyze_modifier(modifier);
                    }
                    _ => {}
                }
            }
            // Free functions (top-level) are walked too, but they cannot touch contract storage.
        }
        Ok(())
    }

    fn analyze_function(&mut self, function: &FunctionDefinition) {
        let node_id = function.id as NodeID;
        let Some(&function_id) = self.id_maps.function_id_by_node.get(&node_id) else {
            return;
        };
        let (reads, writes) = {
            let mut walker = FunctionWalker::new(&self.state_var_id_by_node);
            for invocation in &function.modifiers {
                for arg in &invocation.arguments {
                    walker.walk_expression(arg, false, true);
                }
            }
            if let Some(body) = &function.body {
                walker.walk_block(body);
            }
            (walker.reads, walker.writes)
        };
        self.persist_walker_results(function_id, reads, writes);
    }

    fn analyze_modifier(&mut self, modifier: &ModifierDefinition) {
        let node_id = modifier.id as NodeID;
        let Some(&function_id) = self.id_maps.function_id_by_node.get(&node_id) else {
            return;
        };
        let (reads, writes) = {
            let mut walker = FunctionWalker::new(&self.state_var_id_by_node);
            if let Some(body) = &modifier.body {
                walker.walk_block(body);
            }
            (walker.reads, walker.writes)
        };
        self.persist_walker_results(function_id, reads, writes);
    }

    fn persist_walker_results(
        &mut self,
        function_id: i32,
        reads: HashSet<i32>,
        writes: HashSet<i32>,
    ) {
        let mut sorted_writes: Vec<i32> = writes.iter().copied().collect();
        sorted_writes.sort();
        let mut sorted_reads: Vec<i32> = reads.iter().copied().collect();
        sorted_reads.sort();
        let mut emitted: HashSet<(i32, bool)> = HashSet::new();
        for sv_id in sorted_writes {
            if emitted.insert((sv_id, true)) {
                self.function_state_variables.push(FunctionStateVariable {
                    function_id,
                    state_variable_id: sv_id,
                    is_write: true,
                    description: None,
                });
            }
        }
        for sv_id in sorted_reads {
            if emitted.insert((sv_id, false)) {
                self.function_state_variables.push(FunctionStateVariable {
                    function_id,
                    state_variable_id: sv_id,
                    is_write: false,
                    description: None,
                });
            }
        }
    }

    fn relative_path(&self, absolute_path: &str) -> PathBuf {
        let candidate = Path::new(absolute_path);
        if let Ok(stripped) = candidate.strip_prefix(self.repo_root) {
            return stripped.to_path_buf();
        }
        if let Ok(canonical_root) = self.repo_root.canonicalize()
            && let Ok(stripped) = candidate.strip_prefix(&canonical_root)
        {
            return stripped.to_path_buf();
        }
        candidate.to_path_buf()
    }
}

fn is_state_variable(var: &VariableDeclaration) -> bool {
    if !var.state_variable {
        return false;
    }
    match var.mutability {
        Some(Mutability::Constant) => false,
        _ => !var.constant,
    }
}

fn base_contract_target(
    base_name: &foundry_compilers_artifacts::ast::UserDefinedTypeNameOrIdentifierPath,
) -> Option<NodeID> {
    use foundry_compilers_artifacts::ast::UserDefinedTypeNameOrIdentifierPath::*;
    match base_name {
        UserDefinedTypeName(udt) => Some(udt.referenced_declaration),
        IdentifierPath(path) => Some(path.referenced_declaration),
    }
}

/// Per-function read/write collector. Walks the body recursively and tracks storage-pointer
/// aliases inside the function so that
///
/// ```solidity
/// User storage u = users[id];
/// u.balance = 0; // marks `users` as written
/// ```
///
/// produces the right edge.
struct FunctionWalker<'a> {
    state_var_id_by_node: &'a HashMap<NodeID, i32>,
    /// Local variable NodeID → set of state variable ids it aliases.
    aliases: HashMap<NodeID, HashSet<i32>>,
    reads: HashSet<i32>,
    writes: HashSet<i32>,
}

impl<'a> FunctionWalker<'a> {
    fn new(state_var_id_by_node: &'a HashMap<NodeID, i32>) -> Self {
        Self {
            state_var_id_by_node,
            aliases: HashMap::new(),
            reads: HashSet::new(),
            writes: HashSet::new(),
        }
    }

    fn walk_block(&mut self, block: &Block) {
        for stmt in &block.statements {
            self.walk_statement(stmt);
        }
    }

    fn walk_block_or_statement(&mut self, bos: &BlockOrStatement) {
        match bos {
            BlockOrStatement::Block(block) => self.walk_block(block),
            BlockOrStatement::Statement(stmt) => self.walk_statement(stmt),
        }
    }

    fn walk_statement(&mut self, stmt: &Statement) {
        match stmt {
            Statement::Block(block) => self.walk_block(block),
            Statement::UncheckedBlock(block) => {
                for stmt in &block.statements {
                    self.walk_statement(stmt);
                }
            }
            Statement::ExpressionStatement(es) => {
                self.walk_expression(&es.expression, false, true);
            }
            Statement::VariableDeclarationStatement(vds) => {
                if let Some(initial) = &vds.initial_value {
                    // Tuple-style multi-decl uses a TupleExpression initializer; we approximate
                    // by aliasing each Storage-located declaration to the union of state vars
                    // resolvable from the entire initializer.
                    let aliased = self.resolve_storage_alias(initial);
                    if !aliased.is_empty() {
                        for decl in vds.declarations.iter().flatten() {
                            if matches!(decl.storage_location, StorageLocation::Storage) {
                                self.aliases
                                    .entry(decl.id as NodeID)
                                    .or_default()
                                    .extend(aliased.iter().copied());
                            }
                        }
                    }
                    self.walk_expression(initial, false, true);
                }
            }
            Statement::IfStatement(s) => {
                self.walk_expression(&s.condition, false, true);
                self.walk_block_or_statement(&s.true_body);
                if let Some(false_body) = &s.false_body {
                    self.walk_block_or_statement(false_body);
                }
            }
            Statement::WhileStatement(s) => {
                self.walk_expression(&s.condition, false, true);
                self.walk_block_or_statement(&s.body);
            }
            Statement::DoWhileStatement(s) => {
                self.walk_block(&s.body);
                self.walk_expression(&s.condition, false, true);
            }
            Statement::ForStatement(s) => {
                if let Some(init) = &s.initialization_expression {
                    match init {
                        ExpressionOrVariableDeclarationStatement::ExpressionStatement(es) => {
                            self.walk_expression(&es.expression, false, true);
                        }
                        ExpressionOrVariableDeclarationStatement::VariableDeclarationStatement(
                            vds,
                        ) => {
                            self.walk_statement(&Statement::VariableDeclarationStatement(
                                vds.clone(),
                            ));
                        }
                    }
                }
                if let Some(cond) = &s.condition {
                    self.walk_expression(cond, false, true);
                }
                if let Some(loop_expr) = &s.loop_expression {
                    self.walk_expression(&loop_expr.expression, false, true);
                }
                self.walk_block_or_statement(&s.body);
            }
            Statement::Return(s) => {
                if let Some(expr) = &s.expression {
                    self.walk_expression(expr, false, true);
                }
            }
            Statement::EmitStatement(s) => {
                // emit args read state; the call expression itself is the event reference,
                // which we don't treat as a callable touch.
                for arg in &s.event_call.arguments {
                    self.walk_expression(arg, false, true);
                }
            }
            Statement::RevertStatement(s) => {
                for arg in &s.error_call.arguments {
                    self.walk_expression(arg, false, true);
                }
            }
            Statement::TryStatement(s) => {
                self.walk_expression(&s.external_call.expression, false, true);
                for arg in &s.external_call.arguments {
                    self.walk_expression(arg, false, true);
                }
                for clause in &s.clauses {
                    self.walk_block(&clause.block);
                }
            }
            Statement::PlaceholderStatement(_)
            | Statement::Break(_)
            | Statement::Continue(_)
            | Statement::InlineAssembly(_) => {}
        }
    }

    fn walk_expression(&mut self, expr: &Expression, is_write: bool, is_read: bool) {
        match expr {
            Expression::Identifier(ident) => {
                if let Some(refd) = ident.referenced_declaration {
                    self.touch(refd, is_write, is_read);
                }
            }
            Expression::MemberAccess(ma) => {
                // The member itself might *be* a state variable (e.g. `Lib.s` where `s` is a
                // public state var of a referenced contract); record both inner and the access.
                self.walk_expression(&ma.expression, is_write, is_read);
                if let Some(refd) = ma.referenced_declaration {
                    self.touch(refd, is_write, is_read);
                }
            }
            Expression::IndexAccess(ia) => {
                self.walk_expression(&ia.base_expression, is_write, is_read);
                if let Some(idx) = &ia.index_expression {
                    self.walk_expression(idx, false, true);
                }
            }
            Expression::IndexRangeAccess(ira) => {
                self.walk_expression(&ira.base_expression, is_write, is_read);
                if let Some(s) = &ira.start_expression {
                    self.walk_expression(s, false, true);
                }
                if let Some(e) = &ira.end_expression {
                    self.walk_expression(e, false, true);
                }
            }
            Expression::Assignment(asg) => {
                let compound = !matches!(asg.operator, AssignmentOperator::Assign);
                self.walk_expression(&asg.lhs, true, compound);
                self.walk_expression(&asg.rhs, false, true);
            }
            Expression::UnaryOperation(uop) => match uop.operator {
                UnaryOperator::Increment | UnaryOperator::Decrement => {
                    self.walk_expression(&uop.sub_expression, true, true);
                }
                UnaryOperator::Delete => {
                    self.walk_expression(&uop.sub_expression, true, false);
                }
                _ => self.walk_expression(&uop.sub_expression, false, true),
            },
            Expression::FunctionCall(fc) => {
                // arr.push(x) / arr.pop() mark base as written.
                if let Expression::MemberAccess(ma) = &fc.expression
                    && (ma.member_name == "push" || ma.member_name == "pop")
                {
                    self.walk_expression(&ma.expression, true, true);
                    for arg in &fc.arguments {
                        self.walk_expression(arg, false, true);
                    }
                    return;
                }
                self.walk_expression(&fc.expression, false, true);
                for arg in &fc.arguments {
                    self.walk_expression(arg, false, true);
                }
            }
            Expression::FunctionCallOptions(fco) => {
                self.walk_expression(&fco.expression, false, true);
                for opt in &fco.options {
                    self.walk_expression(opt, false, true);
                }
            }
            Expression::TupleExpression(te) => {
                for c in te.components.iter().flatten() {
                    self.walk_expression(c, is_write, is_read);
                }
            }
            Expression::BinaryOperation(bo) => {
                self.walk_expression(&bo.lhs, false, true);
                self.walk_expression(&bo.rhs, false, true);
            }
            Expression::Conditional(c) => {
                self.walk_expression(&c.condition, false, true);
                self.walk_expression(&c.true_expression, is_write, is_read);
                self.walk_expression(&c.false_expression, is_write, is_read);
            }
            Expression::NewExpression(_)
            | Expression::Literal(_)
            | Expression::ElementaryTypeNameExpression(_) => {}
        }
    }

    /// Returns the set of state-variable ids that this expression aliases, for the purpose of
    /// tracking storage pointers. Walks down through field/index access to find the base
    /// state variable or alias.
    fn resolve_storage_alias(&self, expr: &Expression) -> HashSet<i32> {
        match expr {
            Expression::Identifier(ident) => {
                if let Some(refd) = ident.referenced_declaration {
                    if let Some(&sv_id) = self.state_var_id_by_node.get(&refd) {
                        return HashSet::from([sv_id]);
                    }
                    if let Some(set) = self.aliases.get(&refd) {
                        return set.clone();
                    }
                }
                HashSet::new()
            }
            Expression::MemberAccess(ma) => self.resolve_storage_alias(&ma.expression),
            Expression::IndexAccess(ia) => self.resolve_storage_alias(&ia.base_expression),
            Expression::IndexRangeAccess(ira) => self.resolve_storage_alias(&ira.base_expression),
            Expression::Conditional(c) => {
                let mut t = self.resolve_storage_alias(&c.true_expression);
                t.extend(self.resolve_storage_alias(&c.false_expression));
                t
            }
            Expression::TupleExpression(te) => {
                let mut all = HashSet::new();
                for e in te.components.iter().flatten() {
                    all.extend(self.resolve_storage_alias(e));
                }
                all
            }
            _ => HashSet::new(),
        }
    }

    fn touch(&mut self, refd: NodeID, is_write: bool, is_read: bool) {
        if let Some(&sv_id) = self.state_var_id_by_node.get(&refd) {
            if is_write {
                self.writes.insert(sv_id);
            }
            if is_read {
                self.reads.insert(sv_id);
            }
            return;
        }
        if let Some(targets) = self.aliases.get(&refd) {
            let targets = targets.clone();
            if is_write {
                self.writes.extend(targets.iter().copied());
            }
            if is_read {
                self.reads.extend(targets.iter().copied());
            }
        }
    }
}

fn chunk_from_src(src: &SourceLocation, source: &str) -> Result<FileChunk, color_eyre::Report> {
    let offset = src
        .start
        .wrap_err("source location is missing start offset")?;
    let length = src.length.wrap_err("source location is missing length")?;
    let end = offset + length;
    ensure!(
        end <= source.len(),
        "src range {offset}..{end} exceeds source length {}",
        source.len()
    );
    ensure!(
        source.is_char_boundary(offset) && source.is_char_boundary(end),
        "src range {offset}..{end} crosses a UTF-8 boundary"
    );
    let (start_line, start_column) = byte_to_line_column(source, offset)?;
    let (end_line, end_column) = byte_to_line_column(source, end)?;
    Ok(FileChunk {
        loc: FileLocation {
            start_line,
            start_column,
            end_line,
            end_column,
        },
        content: source[offset..end].to_string(),
    })
}

fn byte_to_line_column(source: &str, byte: usize) -> Result<(usize, usize), color_eyre::Report> {
    ensure!(
        byte <= source.len(),
        "byte offset {byte} exceeds source length"
    );
    ensure!(
        source.is_char_boundary(byte),
        "byte offset {byte} is not a UTF-8 character boundary"
    );
    let mut line = 1;
    let mut column = 0usize;
    for ch in source[..byte].chars() {
        if ch == '\n' {
            line += 1;
            column = 0;
        } else {
            column += 1;
        }
    }
    Ok((line, column))
}
