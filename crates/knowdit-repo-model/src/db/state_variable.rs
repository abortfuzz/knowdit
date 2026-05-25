use sea_orm::entity::prelude::*;

#[sea_orm::model]
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize, DeriveEntityModel)]
#[sea_orm(table_name = "state_variable")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i32,
    #[sea_orm(column_type = "Text", indexed)]
    pub name: String,
    #[sea_orm(column_type = "Text", column_name = "type")]
    pub type_name: String,
    #[sea_orm(column_type = "Text")]
    pub relative_file_path: String,
    pub start_line: i32,
    pub start_column: i32,
    pub end_line: i32,
    pub end_column: i32,
    #[sea_orm(column_type = "Text")]
    pub content: String,
}

impl ActiveModelBehavior for ActiveModel {}
