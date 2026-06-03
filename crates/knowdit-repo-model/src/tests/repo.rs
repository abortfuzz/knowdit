//! Smoke tests for [`RepoDatabase`] basics: project bookkeeping and
//! call-graph round-trip. Migrated out of an inline `mod tests` in
//! `src/repo.rs` so all test code for this crate lives under
//! `src/tests/`.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use knowdit_kg_model::db::project as project_model;
use knowdit_kg_model::{ExtractedFunction, ExtractedSemantic};
use sea_orm::{ActiveValue::Set, EntityTrait};

use crate::cg::{CallGraph, Contract, FileChunk, FileLocation, Function, FunctionCall, Interface};
use crate::repo::RepoDatabase;

struct TempDb {
    repo: RepoDatabase,
    path: PathBuf,
}

impl Drop for TempDb {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
        let _ = std::fs::remove_file(self.path.with_extension("sqlite3-shm"));
        let _ = std::fs::remove_file(self.path.with_extension("sqlite3-wal"));
    }
}

async fn temp_db() -> TempDb {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock should be after unix epoch")
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "knowdit-repo-db-test-{}-{unique}.sqlite3",
        std::process::id()
    ));
    let repo = RepoDatabase::open_sqlite(path.clone())
        .await
        .expect("test repo database should connect");
    TempDb { repo, path }
}

#[tokio::test]
async fn ensure_project_records_current_project_when_empty() {
    let temp = temp_db().await;
    temp.repo
        .init_schema()
        .await
        .expect("schema should initialize");

    temp.repo
        .ensure_project("current-project")
        .await
        .expect("empty project database should accept current project");

    let projects = project_model::Entity::find()
        .all(temp.repo.connection())
        .await
        .expect("project rows should load");
    assert_eq!(projects.len(), 1);
    assert_eq!(projects[0].name, "current-project");
}

#[tokio::test]
async fn ensure_project_rejects_multiple_projects() {
    let temp = temp_db().await;
    temp.repo
        .init_schema()
        .await
        .expect("schema should initialize");
    project_model::Entity::insert_many([
        project_model::ActiveModel {
            name: Set("one".to_string()),
            status: Set("completed".to_string()),
            ..Default::default()
        },
        project_model::ActiveModel {
            name: Set("two".to_string()),
            status: Set("completed".to_string()),
            ..Default::default()
        },
    ])
    .exec(temp.repo.connection())
    .await
    .expect("test projects should insert");

    let err = temp
        .repo
        .ensure_project("one")
        .await
        .expect_err("multiple projects should be rejected")
        .to_string();
    assert!(err.contains("project database contains multiple projects"));
}

fn loc(start_line: usize, start_column: usize, end_column: usize) -> FileLocation {
    FileLocation {
        start_line,
        start_column,
        end_line: start_line,
        end_column,
    }
}

fn chunk(content: &str, start_line: usize, start_column: usize, end_column: usize) -> FileChunk {
    FileChunk {
        loc: loc(start_line, start_column, end_column),
        content: content.to_string(),
    }
}

#[tokio::test]
async fn writes_and_reads_call_graph_database() {
    let temp = temp_db().await;
    temp.repo
        .init_schema()
        .await
        .expect("schema should initialize");

    let call_graph = CallGraph {
        contracts: BTreeMap::from([(
            1,
            Contract {
                id: 1,
                name: "Vault".to_string(),
                relative_file_path: PathBuf::from("src/Vault.sol"),
                chunk: chunk("contract Vault {}", 1, 0, 8),
                functions: vec![
                    Function {
                        id: 1,
                        name: "deposit".to_string(),
                        args: "uint256 amount".to_string(),
                        relative_file_path: PathBuf::from("src/Vault.sol"),
                        loc: loc(2, 4, 40),
                        content: Some("function deposit(uint256 amount) {}".to_string()),
                        calls: vec![FunctionCall {
                            id: 1,
                            from_id: 1,
                            to_id: 2,
                            description: Some("updates accounting".to_string()),
                        }],
                        description: Some("deposit entrypoint".to_string()),
                    },
                    Function {
                        id: 2,
                        name: "account".to_string(),
                        args: "uint256 amount".to_string(),
                        relative_file_path: PathBuf::from("src/Vault.sol"),
                        loc: loc(3, 4, 40),
                        content: Some("function account(uint256 amount) {}".to_string()),
                        calls: Vec::new(),
                        description: Some("accounting helper".to_string()),
                    },
                ],
                description: Some("Vault contract".to_string()),
            },
        )]),
        interfaces: BTreeMap::from([(
            10,
            Interface {
                id: 10,
                name: "IERC20".to_string(),
                relative_file_path: PathBuf::from("src/IERC20.sol"),
                chunk: chunk("interface IERC20 {}", 1, 0, 19),
                functions: vec![Function {
                    id: 10,
                    name: "transfer".to_string(),
                    args: "address to, uint256 amount".to_string(),
                    relative_file_path: PathBuf::from("src/IERC20.sol"),
                    loc: loc(2, 4, 70),
                    content: None,
                    calls: Vec::new(),
                    description: Some("interface declaration".to_string()),
                }],
                description: Some("IERC20 interface".to_string()),
            },
        )]),
    };

    temp.repo
        .write_call_graph(&call_graph)
        .await
        .expect("callgraph should write");
    temp.repo
        .replace_project_semantics(&[ExtractedSemantic {
            name: "Token Transfer".to_string(),
            category: knowdit_kg_model::category::DeFiCategory::Services,
            definition: "Moves ERC20 balances between accounts".to_string(),
            description: "Tracks project-specific token transfer semantics".to_string(),
            functions: vec![ExtractedFunction {
                name: "transfer".to_string(),
                contract: "src/IERC20.sol".to_string(),
                signature: Some("transfer(address,uint256)".to_string()),
            }],
        }])
        .await
        .expect("project semantics should write");
    let restored = temp
        .repo
        .load_call_graph()
        .await
        .expect("callgraph should read back");
    let restored_semantics = temp
        .repo
        .load_project_semantics()
        .await
        .expect("project semantics should read back");

    let contract = restored
        .contracts
        .get(&1)
        .expect("contract should be restored");
    assert_eq!(contract.relative_file_path, PathBuf::from("src/Vault.sol"));
    assert_eq!(contract.functions.len(), 2);
    assert_eq!(contract.functions[0].calls.len(), 1);
    assert_eq!(contract.functions[0].calls[0].to_id, 2);
    assert_eq!(
        contract.functions[0].calls[0].description.as_deref(),
        Some("updates accounting")
    );
    let interface = restored
        .interfaces
        .get(&10)
        .expect("interface should be restored");
    assert_eq!(interface.name, "IERC20");
    assert_eq!(interface.functions.len(), 1);
    assert_eq!(interface.functions[0].content, None);
    assert_eq!(restored_semantics.len(), 1);
    assert_eq!(restored_semantics[0].functions.len(), 1);
    assert_eq!(restored_semantics[0].functions[0].name, "transfer");
}
