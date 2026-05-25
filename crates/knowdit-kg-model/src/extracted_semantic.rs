//! Domain value types for a project-specific semantic and the functions
//! attached to it. Shared between the LLM extraction pipeline (which produces
//! these via tool calls) and the persistence layers in `knowdit-kg` and
//! `knowdit-repo-model`. Derives `JsonSchema` so the type can serve directly
//! as a tool's `ARGUMENTS` shape — no duplicate "Args" struct needed.
use schemars::JsonSchema;
use sea_orm::ActiveValue::Set;
use serde::{Deserialize, Serialize};

use crate::category::DeFiCategory;
use crate::db::{semantic_function, semantic_node};

/// One semantic interaction extracted from a project's source. Field shapes
/// match the LLM tool-call contract; persistence-only metadata (row ids,
/// etc.) is not modelled here — the database assigns those at insert time.
#[derive(Debug, Deserialize, Serialize, Clone, JsonSchema)]
pub struct ExtractedSemantic {
    /// Short canonical name (project-agnostic), e.g. "Constant Product AMM Swap".
    pub name: String,
    /// Which DeFi category this semantic belongs to.
    pub category: DeFiCategory,
    /// One-sentence formal definition.
    pub definition: String,
    /// Abstract description of user interaction, value flow, and outcome.
    pub description: String,
    /// Functions in the source that implement this semantic. At least one
    /// entry is required (validated post-deserialization by the tool).
    pub functions: Vec<ExtractedFunction>,
}

/// Function reference attached to an [`ExtractedSemantic`].
#[derive(Debug, Deserialize, Serialize, Clone, JsonSchema)]
pub struct ExtractedFunction {
    /// Function or entry-point name as it appears in the source.
    pub name: String,
    /// Containing file or module path (e.g. `src/pool/Swap.sol`).
    pub contract: String,
    /// Optional Solidity-style signature.
    pub signature: Option<String>,
}

impl ExtractedSemantic {
    /// Build an `ActiveModel` ready to insert into `semantic_node`. Functions
    /// are stored separately via [`Self::function_active_models`], and the
    /// project-provenance link MUST be written into `project_semantic` by the
    /// caller — there is no longer a scalar `project_id` column on
    /// `semantic_node`.
    pub fn to_active_model(&self) -> semantic_node::ActiveModel {
        semantic_node::ActiveModel {
            name: Set(self.name.clone()),
            category: Set(self.category),
            definition: Set(self.definition.clone()),
            description: Set(self.description.clone()),
            ..Default::default()
        }
    }

    /// Build the `semantic_function` rows that link a parent semantic node to
    /// each of its `functions`. Caller supplies the parent id obtained after
    /// inserting the semantic node.
    pub fn function_active_models(
        &self,
        semantic_node_id: i32,
    ) -> Vec<semantic_function::ActiveModel> {
        self.functions
            .iter()
            .map(|f| f.to_active_model(semantic_node_id))
            .collect()
    }

    /// Reconstruct from a stored `semantic_node` row plus its `semantic_function`
    /// children. Function `signature` is left `None` because that column is not
    /// persisted.
    pub fn from_model(
        node: semantic_node::Model,
        functions: Vec<semantic_function::Model>,
    ) -> Self {
        Self {
            name: node.name,
            category: node.category,
            definition: node.definition,
            description: node.description,
            functions: functions
                .into_iter()
                .map(ExtractedFunction::from_model)
                .collect(),
        }
    }
}

impl ExtractedFunction {
    pub fn to_active_model(&self, semantic_node_id: i32) -> semantic_function::ActiveModel {
        semantic_function::ActiveModel {
            semantic_node_id: Set(semantic_node_id),
            function_name: Set(self.name.clone()),
            contract_path: Set(self.contract.clone()),
            ..Default::default()
        }
    }

    /// Reconstruct from a stored `semantic_function` row. `signature` is left
    /// `None` because the column is not persisted.
    pub fn from_model(model: semantic_function::Model) -> Self {
        Self {
            name: model.function_name,
            contract: model.contract_path,
            signature: None,
        }
    }
}
