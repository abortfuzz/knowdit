use sea_orm::entity::prelude::*;

#[sea_orm::model]
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize, DeriveEntityModel)]
#[sea_orm(table_name = "function")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i32,
    #[sea_orm(column_type = "Text")]
    pub name: String,
    #[sea_orm(column_type = "Text")]
    pub args: String,
    #[sea_orm(column_type = "Text")]
    pub relative_file_path: String,
    pub start_line: i32,
    pub start_column: i32,
    pub end_line: i32,
    pub end_column: i32,
    #[sea_orm(column_type = "Text", nullable)]
    pub content: Option<String>,
    #[sea_orm(column_type = "Text", nullable)]
    pub description: Option<String>,

    #[sea_orm(has_many, relation_enum = "LhsCalls", via_rel = "Lhs")]
    pub lhs_calls: HasMany<super::function_call::Entity>,
    #[sea_orm(has_many, relation_enum = "RhsCalls", via_rel = "Rhs")]
    pub rhs_calls: HasMany<super::function_call::Entity>,
    #[sea_orm(has_many, via = "contract_functions")]
    pub contracts: HasMany<super::contract::Entity>,
    #[sea_orm(has_many, via = "interface_functions")]
    pub interfaces: HasMany<super::interface::Entity>,
}

impl ActiveModelBehavior for ActiveModel {}
