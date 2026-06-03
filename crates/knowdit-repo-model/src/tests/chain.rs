//! Tests for the regen-lineage walkers on [`RepoDatabase`]:
//! `code_gen_chain_depth`, `spec_chain_depth`, and
//! `prior_incomplete_step_count`.
//!
//! Each test stands up a fresh on-disk SQLite via `temp_db`, calls
//! `init_schema`, and seeds the FK-required parent rows before any
//! child insert. FKs are enforced on the project DB so the helpers
//! that touch reflection/harness_run/code_gen also handle the chain
//! up to `project_semantic` / `specification`. `code_gen_regen` and
//! `specification_regen` themselves carry no FKs (see the doc comment
//! on those models), so the chain-depth tests can seed lineage edges
//! directly without bothering with parent rows.

use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use knowdit_kg_model::category::DeFiCategory;
use sea_orm::{ActiveValue::Set, EntityTrait};

use crate::db::{
    code_gen as code_gen_model, code_gen_regen as code_gen_regen_model,
    harness_run as harness_run_model, project_semantic as project_semantic_model,
    reflection as reflection_model, specification as specification_model,
    specification_regen as specification_regen_model,
};
use crate::repo::{CodeGenStatus, ReflectionResult, RepoDatabase, RunKind};

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
        "knowdit-chain-test-{}-{unique}.sqlite3",
        std::process::id()
    ));
    let repo = RepoDatabase::open_sqlite(path.clone())
        .await
        .expect("test repo database should connect");
    repo.init_schema().await.expect("schema should initialize");
    TempDb { repo, path }
}

async fn insert_code_gen_regen(repo: &RepoDatabase, child: i32, parent: i32) {
    code_gen_regen_model::Entity::insert(code_gen_regen_model::ActiveModel {
        child_code_gen_id: Set(child),
        parent_code_gen_id: Set(parent),
        reason: Set(format!("regen {parent} -> {child}")),
        triggered_by_reflection_id: Set(0),
    })
    .exec(repo.connection())
    .await
    .expect("code_gen_regen row should insert");
}

async fn insert_spec_regen(repo: &RepoDatabase, child: i32, parent: i32) {
    specification_regen_model::Entity::insert(specification_regen_model::ActiveModel {
        child_spec_id: Set(child),
        parent_spec_id: Set(parent),
        reason: Set(format!("spec regen {parent} -> {child}")),
        triggered_by_reflection_id: Set(0),
    })
    .exec(repo.connection())
    .await
    .expect("specification_regen row should insert");
}

// --- prior_incomplete_step_count needs the full FK chain ---

async fn insert_extract(repo: &RepoDatabase, id: i32) {
    project_semantic_model::Entity::insert(project_semantic_model::ActiveModel {
        id: Set(id),
        name: Set(format!("extract_{id}")),
        category: Set(DeFiCategory::Lending),
        definition: Set(String::new()),
        description: Set(String::new()),
        ..Default::default()
    })
    .exec(repo.connection())
    .await
    .expect("project_semantic row should insert");
}

async fn insert_spec(repo: &RepoDatabase, extract_id: i32) -> i32 {
    let res = specification_model::Entity::insert(specification_model::ActiveModel {
        semantic_id: Set(extract_id),
        finding_id: Set(1),
        specification: Set("{}".to_string()),
        ..Default::default()
    })
    .exec(repo.connection())
    .await
    .expect("specification row should insert");
    res.last_insert_id
}

async fn insert_code_gen(repo: &RepoDatabase, spec_id: i32) -> i32 {
    let res = code_gen_model::Entity::insert(code_gen_model::ActiveModel {
        spec_id: Set(spec_id),
        harness_relative_path: Set(String::new()),
        harness_source: Set(String::new()),
        status: Set(CodeGenStatus::Completed),
        final_reason: Set(String::new()),
        agent_steps: Set(0),
        ..Default::default()
    })
    .exec(repo.connection())
    .await
    .expect("code_gen row should insert");
    res.last_insert_id
}

async fn insert_harness_run(repo: &RepoDatabase, code_id: i32) -> i32 {
    let res = harness_run_model::Entity::insert(harness_run_model::ActiveModel {
        code_id: Set(code_id),
        kind: Set(RunKind::Test),
        seed: Set(None),
        runs: Set(0),
        forge_args: Set("[]".to_string()),
        exit_code: Set(0),
        stdout: Set(String::new()),
        stderr: Set(String::new()),
        duration_ms: Set(0),
        violated: Set(false),
        sequence_json: Set(None),
        ..Default::default()
    })
    .exec(repo.connection())
    .await
    .expect("harness_run row should insert");
    res.last_insert_id
}

async fn insert_reflection(
    repo: &RepoDatabase,
    run_id: i32,
    spec_id: i32,
    result: ReflectionResult,
) {
    reflection_model::Entity::insert(reflection_model::ActiveModel {
        run_id: Set(run_id),
        spec_id: Set(spec_id),
        result: Set(result),
        reason: Set(String::new()),
        ..Default::default()
    })
    .exec(repo.connection())
    .await
    .expect("reflection row should insert");
}

// =============================================================
// code_gen_chain_depth
// =============================================================

#[tokio::test]
async fn code_gen_chain_depth_zero_when_no_regen_row() {
    let temp = temp_db().await;
    let depth = temp
        .repo
        .code_gen_chain_depth(42)
        .await
        .expect("depth query should succeed");
    assert_eq!(depth, 0);
}

#[tokio::test]
async fn code_gen_chain_depth_counts_single_hop() {
    let temp = temp_db().await;
    insert_code_gen_regen(&temp.repo, 5, 4).await;

    let depth = temp.repo.code_gen_chain_depth(5).await.expect("depth");
    assert_eq!(depth, 1);
}

#[tokio::test]
async fn code_gen_chain_depth_counts_multi_hop() {
    let temp = temp_db().await;
    // 7 → 6 → 5 → 4
    insert_code_gen_regen(&temp.repo, 7, 6).await;
    insert_code_gen_regen(&temp.repo, 6, 5).await;
    insert_code_gen_regen(&temp.repo, 5, 4).await;

    assert_eq!(temp.repo.code_gen_chain_depth(7).await.unwrap(), 3);
    assert_eq!(temp.repo.code_gen_chain_depth(6).await.unwrap(), 2);
    assert_eq!(temp.repo.code_gen_chain_depth(5).await.unwrap(), 1);
    assert_eq!(temp.repo.code_gen_chain_depth(4).await.unwrap(), 0);
}

#[tokio::test]
async fn code_gen_chain_depth_independent_chains_do_not_cross() {
    let temp = temp_db().await;
    // Chain A: 10 → 9
    insert_code_gen_regen(&temp.repo, 10, 9).await;
    // Chain B: 20 → 21 → 22 (deeper, unrelated)
    insert_code_gen_regen(&temp.repo, 20, 21).await;
    insert_code_gen_regen(&temp.repo, 21, 22).await;

    assert_eq!(temp.repo.code_gen_chain_depth(10).await.unwrap(), 1);
    assert_eq!(temp.repo.code_gen_chain_depth(20).await.unwrap(), 2);
}

// =============================================================
// spec_chain_depth
// =============================================================

#[tokio::test]
async fn spec_chain_depth_zero_when_no_regen_row() {
    let temp = temp_db().await;
    let depth = temp.repo.spec_chain_depth(42).await.expect("depth");
    assert_eq!(depth, 0);
}

#[tokio::test]
async fn spec_chain_depth_counts_multi_hop() {
    let temp = temp_db().await;
    insert_spec_regen(&temp.repo, 30, 20).await;
    insert_spec_regen(&temp.repo, 20, 10).await;

    assert_eq!(temp.repo.spec_chain_depth(30).await.unwrap(), 2);
    assert_eq!(temp.repo.spec_chain_depth(20).await.unwrap(), 1);
    assert_eq!(temp.repo.spec_chain_depth(10).await.unwrap(), 0);
}

// =============================================================
// prior_incomplete_step_count
// =============================================================

#[tokio::test]
async fn prior_incomplete_step_count_zero_when_no_lineage() {
    let temp = temp_db().await;
    insert_extract(&temp.repo, 1).await;
    let spec_id = insert_spec(&temp.repo, 1).await;
    let code_id = insert_code_gen(&temp.repo, spec_id).await;
    let run_id = insert_harness_run(&temp.repo, code_id).await;
    // A reflection on the code_gen itself with IncompleteStep — but the
    // count only looks at ANCESTORS, so it should be ignored.
    insert_reflection(
        &temp.repo,
        run_id,
        spec_id,
        ReflectionResult::IncompleteStep,
    )
    .await;

    let n = temp
        .repo
        .prior_incomplete_step_count(code_id)
        .await
        .expect("count");
    assert_eq!(n, 0);
}

#[tokio::test]
async fn prior_incomplete_step_count_counts_ancestor_incomplete_step() {
    let temp = temp_db().await;
    insert_extract(&temp.repo, 1).await;
    let spec_id = insert_spec(&temp.repo, 1).await;
    let parent_code = insert_code_gen(&temp.repo, spec_id).await;
    let child_code = insert_code_gen(&temp.repo, spec_id).await;
    insert_code_gen_regen(&temp.repo, child_code, parent_code).await;
    let parent_run = insert_harness_run(&temp.repo, parent_code).await;
    insert_reflection(
        &temp.repo,
        parent_run,
        spec_id,
        ReflectionResult::IncompleteStep,
    )
    .await;

    let n = temp
        .repo
        .prior_incomplete_step_count(child_code)
        .await
        .expect("count");
    assert_eq!(n, 1);
}

#[tokio::test]
async fn prior_incomplete_step_count_ignores_non_incomplete_step_results() {
    let temp = temp_db().await;
    insert_extract(&temp.repo, 1).await;
    let spec_id = insert_spec(&temp.repo, 1).await;
    let parent_code = insert_code_gen(&temp.repo, spec_id).await;
    let child_code = insert_code_gen(&temp.repo, spec_id).await;
    insert_code_gen_regen(&temp.repo, child_code, parent_code).await;
    let parent_run = insert_harness_run(&temp.repo, parent_code).await;
    // Anything other than IncompleteStep should not count.
    insert_reflection(
        &temp.repo,
        parent_run,
        spec_id,
        ReflectionResult::ValidFinding,
    )
    .await;

    let n = temp
        .repo
        .prior_incomplete_step_count(child_code)
        .await
        .expect("count");
    assert_eq!(n, 0);
}

#[tokio::test]
async fn prior_incomplete_step_count_sums_across_deeper_lineage() {
    let temp = temp_db().await;
    insert_extract(&temp.repo, 1).await;
    let spec_id = insert_spec(&temp.repo, 1).await;
    // Lineage: grand <- middle <- leaf.
    let grand_code = insert_code_gen(&temp.repo, spec_id).await;
    let middle_code = insert_code_gen(&temp.repo, spec_id).await;
    let leaf_code = insert_code_gen(&temp.repo, spec_id).await;
    insert_code_gen_regen(&temp.repo, middle_code, grand_code).await;
    insert_code_gen_regen(&temp.repo, leaf_code, middle_code).await;
    let grand_run = insert_harness_run(&temp.repo, grand_code).await;
    let middle_run = insert_harness_run(&temp.repo, middle_code).await;
    insert_reflection(
        &temp.repo,
        grand_run,
        spec_id,
        ReflectionResult::IncompleteStep,
    )
    .await;
    insert_reflection(
        &temp.repo,
        middle_run,
        spec_id,
        ReflectionResult::IncompleteStep,
    )
    .await;

    let n = temp
        .repo
        .prior_incomplete_step_count(leaf_code)
        .await
        .expect("count");
    assert_eq!(n, 2);
}
