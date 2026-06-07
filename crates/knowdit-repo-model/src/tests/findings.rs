//! Tests for the two larger join-readers on [`RepoDatabase`] that
//! used to be raw-SQL: `load_valid_findings` and `pending_reflections`.
//! Each rewrite drives a chain of typed-entity queries instead of one
//! big SQL string, so these tests exercise both the multi-step
//! orchestration and the schema invariants it relies on (FK chain,
//! enum filtering, regen-consumption gates).

use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use knowdit_kg_model::audit_finding::FindingSeverity;
use knowdit_kg_model::category::DeFiCategory;
use sea_orm::{ActiveValue::Set, EntityTrait};

use crate::db::{
    code_gen as code_gen_model, code_gen_regen as code_gen_regen_model,
    harness_run as harness_run_model, historical_semantic as historical_semantic_model,
    project_semantic as project_semantic_model, reflection as reflection_model,
    specification as specification_model, specification_regen as specification_regen_model,
    valid_finding as valid_finding_model,
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
        "knowdit-findings-test-{}-{unique}.sqlite3",
        std::process::id()
    ));
    let repo = RepoDatabase::open_sqlite(path.clone())
        .await
        .expect("test repo database should connect");
    repo.init_schema().await.expect("schema should initialize");
    TempDb { repo, path }
}

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

async fn insert_historical(repo: &RepoDatabase, id: i32) {
    historical_semantic_model::Entity::insert(historical_semantic_model::ActiveModel {
        id: Set(id),
        name: Set(format!("hist_{id}")),
        definition: Set(String::new()),
        description: Set(String::new()),
        category: Set(DeFiCategory::Lending),
        ..Default::default()
    })
    .exec(repo.connection())
    .await
    .expect("historical_semantic row should insert");
}

async fn insert_spec(
    repo: &RepoDatabase,
    extract_id: i32,
    historical_id: i32,
    finding_id: i32,
    body: &str,
) -> i32 {
    let res = specification_model::Entity::insert(specification_model::ActiveModel {
        semantic_id: Set(extract_id),
        historical_id: Set(historical_id),
        finding_id: Set(finding_id),
        specification: Set(body.to_string()),
        ..Default::default()
    })
    .exec(repo.connection())
    .await
    .expect("specification row should insert");
    res.last_insert_id
}

async fn insert_code_gen(repo: &RepoDatabase, spec_id: i32, source: &str, path: &str) -> i32 {
    let res = code_gen_model::Entity::insert(code_gen_model::ActiveModel {
        spec_id: Set(spec_id),
        harness_relative_path: Set(path.to_string()),
        harness_source: Set(source.to_string()),
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

async fn insert_harness_run(
    repo: &RepoDatabase,
    code_id: i32,
    kind: RunKind,
    exit_code: i32,
    stdout: &str,
    sequence_json: Option<&str>,
) -> i32 {
    let res = harness_run_model::Entity::insert(harness_run_model::ActiveModel {
        code_id: Set(code_id),
        kind: Set(kind),
        seed: Set(None),
        runs: Set(0),
        forge_args: Set("[]".to_string()),
        exit_code: Set(exit_code),
        stdout: Set(stdout.to_string()),
        stderr: Set(String::new()),
        duration_ms: Set(0),
        violated: Set(false),
        sequence_json: Set(sequence_json.map(|s| s.to_string())),
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
    reason: &str,
) -> i32 {
    let res = reflection_model::Entity::insert(reflection_model::ActiveModel {
        run_id: Set(run_id),
        spec_id: Set(spec_id),
        result: Set(result),
        reason: Set(reason.to_string()),
        ..Default::default()
    })
    .exec(repo.connection())
    .await
    .expect("reflection row should insert");
    res.last_insert_id
}

async fn insert_valid_finding(
    repo: &RepoDatabase,
    reflection_id: i32,
    severity: FindingSeverity,
    reason: &str,
) {
    valid_finding_model::Entity::insert(valid_finding_model::ActiveModel {
        reflection_id: Set(reflection_id),
        severity: Set(severity),
        severity_reason: Set(reason.to_string()),
        ..Default::default()
    })
    .exec(repo.connection())
    .await
    .expect("valid_finding row should insert");
}

async fn insert_code_gen_regen_consumption(
    repo: &RepoDatabase,
    child: i32,
    parent: i32,
    reflection_id: i32,
) {
    code_gen_regen_model::Entity::insert(code_gen_regen_model::ActiveModel {
        child_code_gen_id: Set(child),
        parent_code_gen_id: Set(parent),
        reason: Set(String::new()),
        triggered_by_reflection_id: Set(reflection_id),
    })
    .exec(repo.connection())
    .await
    .expect("code_gen_regen row should insert");
}

async fn insert_spec_regen_consumption(
    repo: &RepoDatabase,
    child: i32,
    parent: i32,
    reflection_id: i32,
) {
    specification_regen_model::Entity::insert(specification_regen_model::ActiveModel {
        child_spec_id: Set(child),
        parent_spec_id: Set(parent),
        reason: Set(String::new()),
        triggered_by_reflection_id: Set(reflection_id),
    })
    .exec(repo.connection())
    .await
    .expect("specification_regen row should insert");
}

// =============================================================
// load_valid_findings
// =============================================================

#[tokio::test]
async fn load_valid_findings_empty_when_no_reflections() {
    let temp = temp_db().await;
    let findings = temp.repo.load_valid_findings().await.expect("query");
    assert!(findings.is_empty());
}

#[tokio::test]
async fn load_valid_findings_returns_joined_fields() {
    let temp = temp_db().await;
    insert_extract(&temp.repo, 1).await;
    insert_historical(&temp.repo, 1).await;
    let spec_id = insert_spec(&temp.repo, 1, 1, 7, "{\"setup\":\"x\"}").await;
    let code_id = insert_code_gen(
        &temp.repo,
        spec_id,
        "contract Harness {}",
        "test/Harness.t.sol",
    )
    .await;
    let run_id = insert_harness_run(
        &temp.repo,
        code_id,
        RunKind::Test,
        1,
        "FORGE STDOUT",
        Some("[{\"sender\":\"0x0\"}]"),
    )
    .await;
    let reflection_id = insert_reflection(
        &temp.repo,
        run_id,
        spec_id,
        ReflectionResult::ValidFinding,
        "looks legit",
    )
    .await;
    insert_valid_finding(
        &temp.repo,
        reflection_id,
        FindingSeverity::High,
        "drains funds",
    )
    .await;

    let findings = temp.repo.load_valid_findings().await.expect("query");
    assert_eq!(findings.len(), 1);
    let f = &findings[0];
    assert_eq!(f.reflection_id, reflection_id);
    assert_eq!(f.run_id, run_id);
    assert_eq!(f.spec_id, spec_id);
    assert_eq!(f.verdict_reason, "looks legit");
    assert_eq!(f.severity, "High");
    assert_eq!(f.severity_reason, "drains funds");
    assert_eq!(f.specification_json, "{\"setup\":\"x\"}");
    assert_eq!(f.harness_source, "contract Harness {}");
    assert_eq!(f.harness_relative_path, "test/Harness.t.sol");
    assert_eq!(f.run_kind, "Test");
    assert_eq!(f.run_exit_code, Some(1));
    assert!(!f.run_violated);
    assert_eq!(f.run_stdout, "FORGE STDOUT");
    assert_eq!(
        f.run_sequence_json.as_deref(),
        Some("[{\"sender\":\"0x0\"}]")
    );
}

#[tokio::test]
async fn load_valid_findings_skips_non_valid_finding_results() {
    let temp = temp_db().await;
    insert_extract(&temp.repo, 1).await;
    insert_historical(&temp.repo, 1).await;
    let spec_id = insert_spec(&temp.repo, 1, 1, 7, "{}").await;
    let code_id = insert_code_gen(&temp.repo, spec_id, "", "").await;
    let run_id = insert_harness_run(&temp.repo, code_id, RunKind::Test, 0, "", None).await;
    // A reflection with Suspect must NOT show up — even if you bend the
    // schema and write a valid_finding row alongside it (which the
    // higher-level API would never do).
    insert_reflection(&temp.repo, run_id, spec_id, ReflectionResult::Suspect, "").await;

    let findings = temp.repo.load_valid_findings().await.expect("query");
    assert!(findings.is_empty());
}

#[tokio::test]
async fn load_valid_findings_orders_by_reflection_id_ascending() {
    let temp = temp_db().await;
    insert_extract(&temp.repo, 1).await;
    insert_historical(&temp.repo, 1).await;
    let spec_id = insert_spec(&temp.repo, 1, 1, 7, "{}").await;
    let code_id = insert_code_gen(&temp.repo, spec_id, "", "").await;

    let mut reflection_ids = Vec::new();
    for i in 0..3 {
        let run_id = insert_harness_run(
            &temp.repo,
            code_id,
            RunKind::Test,
            0,
            &format!("run {i}"),
            None,
        )
        .await;
        let rid = insert_reflection(
            &temp.repo,
            run_id,
            spec_id,
            ReflectionResult::ValidFinding,
            &format!("r{i}"),
        )
        .await;
        insert_valid_finding(&temp.repo, rid, FindingSeverity::Medium, &format!("v{i}")).await;
        reflection_ids.push(rid);
    }

    let findings = temp.repo.load_valid_findings().await.expect("query");
    assert_eq!(findings.len(), 3);
    let ids: Vec<i32> = findings.iter().map(|f| f.reflection_id).collect();
    assert_eq!(ids, reflection_ids);
}

#[tokio::test]
async fn load_valid_findings_errors_when_reflection_has_no_sibling_valid_finding() {
    let temp = temp_db().await;
    insert_extract(&temp.repo, 1).await;
    insert_historical(&temp.repo, 1).await;
    let spec_id = insert_spec(&temp.repo, 1, 1, 7, "{}").await;
    let code_id = insert_code_gen(&temp.repo, spec_id, "", "").await;
    let run_id = insert_harness_run(&temp.repo, code_id, RunKind::Test, 0, "", None).await;
    // ValidFinding reflection with NO matching valid_finding row —
    // the higher-level API enforces this invariant, so the loader
    // is allowed to error rather than silently drop the row.
    insert_reflection(
        &temp.repo,
        run_id,
        spec_id,
        ReflectionResult::ValidFinding,
        "",
    )
    .await;

    let err = temp
        .repo
        .load_valid_findings()
        .await
        .expect_err("should reject ValidFinding reflection without sibling row");
    assert!(err.to_string().contains("no valid_finding row"));
}

// =============================================================
// pending_reflections
// =============================================================

#[tokio::test]
async fn pending_reflections_empty_when_db_empty() {
    let temp = temp_db().await;
    let out = temp.repo.pending_reflections().await.expect("query");
    assert!(out.is_empty());
}

#[tokio::test]
async fn pending_reflections_includes_each_regen_eligible_result() {
    let temp = temp_db().await;
    insert_extract(&temp.repo, 1).await;
    insert_historical(&temp.repo, 1).await;
    let spec_id = insert_spec(&temp.repo, 1, 1, 7, "{}").await;
    let code_id = insert_code_gen(&temp.repo, spec_id, "", "").await;

    let mut want_ids = Vec::new();
    for kind in [
        ReflectionResult::Suspect,
        ReflectionResult::IncompleteStep,
        ReflectionResult::IncompleteSpecification,
    ] {
        let run_id = insert_harness_run(&temp.repo, code_id, RunKind::Test, 0, "", None).await;
        let rid = insert_reflection(&temp.repo, run_id, spec_id, kind, &format!("{kind:?}")).await;
        want_ids.push((rid, kind));
    }

    let out = temp.repo.pending_reflections().await.expect("query");
    assert_eq!(out.len(), 3);
    for (i, (rid, kind)) in want_ids.iter().enumerate() {
        assert_eq!(out[i].reflection_id, *rid);
        assert_eq!(out[i].result, *kind);
        assert_eq!(out[i].code_id, code_id);
        assert_eq!(out[i].spec_id, spec_id);
    }
}

#[tokio::test]
async fn pending_reflections_excludes_non_regen_results() {
    let temp = temp_db().await;
    insert_extract(&temp.repo, 1).await;
    insert_historical(&temp.repo, 1).await;
    let spec_id = insert_spec(&temp.repo, 1, 1, 7, "{}").await;
    let code_id = insert_code_gen(&temp.repo, spec_id, "", "").await;

    for kind in [
        ReflectionResult::OutOfScope,
        ReflectionResult::ExpectedViolation,
        ReflectionResult::ValidFinding,
    ] {
        let run_id = insert_harness_run(&temp.repo, code_id, RunKind::Test, 0, "", None).await;
        insert_reflection(&temp.repo, run_id, spec_id, kind, "").await;
    }

    let out = temp.repo.pending_reflections().await.expect("query");
    assert!(out.is_empty());
}

#[tokio::test]
async fn pending_reflections_excludes_reflection_consumed_by_code_gen_regen() {
    let temp = temp_db().await;
    insert_extract(&temp.repo, 1).await;
    insert_historical(&temp.repo, 1).await;
    let spec_id = insert_spec(&temp.repo, 1, 1, 7, "{}").await;
    let parent_code = insert_code_gen(&temp.repo, spec_id, "", "").await;
    let child_code = insert_code_gen(&temp.repo, spec_id, "", "").await;
    let run_id = insert_harness_run(&temp.repo, parent_code, RunKind::Test, 0, "", None).await;
    let consumed_rid = insert_reflection(
        &temp.repo,
        run_id,
        spec_id,
        ReflectionResult::Suspect,
        "consumed",
    )
    .await;
    insert_code_gen_regen_consumption(&temp.repo, child_code, parent_code, consumed_rid).await;

    let still_pending_run =
        insert_harness_run(&temp.repo, parent_code, RunKind::Test, 0, "", None).await;
    let pending_rid = insert_reflection(
        &temp.repo,
        still_pending_run,
        spec_id,
        ReflectionResult::Suspect,
        "still pending",
    )
    .await;

    let out = temp.repo.pending_reflections().await.expect("query");
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].reflection_id, pending_rid);
}

#[tokio::test]
async fn pending_reflections_excludes_reflection_consumed_by_specification_regen() {
    let temp = temp_db().await;
    insert_extract(&temp.repo, 1).await;
    insert_historical(&temp.repo, 1).await;
    let parent_spec = insert_spec(&temp.repo, 1, 1, 7, "{}").await;
    let child_spec = insert_spec(&temp.repo, 1, 1, 7, "{}").await;
    let code_id = insert_code_gen(&temp.repo, parent_spec, "", "").await;
    let run_id = insert_harness_run(&temp.repo, code_id, RunKind::Test, 0, "", None).await;
    let consumed_rid = insert_reflection(
        &temp.repo,
        run_id,
        parent_spec,
        ReflectionResult::IncompleteSpecification,
        "consumed",
    )
    .await;
    insert_spec_regen_consumption(&temp.repo, child_spec, parent_spec, consumed_rid).await;

    let out = temp.repo.pending_reflections().await.expect("query");
    assert!(out.is_empty());
}

#[tokio::test]
async fn pending_reflections_includes_code_id_via_harness_run_join() {
    let temp = temp_db().await;
    insert_extract(&temp.repo, 1).await;
    insert_historical(&temp.repo, 1).await;
    let spec_id = insert_spec(&temp.repo, 1, 1, 7, "{}").await;
    let code_a = insert_code_gen(&temp.repo, spec_id, "", "a").await;
    let code_b = insert_code_gen(&temp.repo, spec_id, "", "b").await;
    let run_a = insert_harness_run(&temp.repo, code_a, RunKind::Test, 0, "", None).await;
    let run_b = insert_harness_run(&temp.repo, code_b, RunKind::Test, 0, "", None).await;
    let rid_a = insert_reflection(&temp.repo, run_a, spec_id, ReflectionResult::Suspect, "a").await;
    let rid_b = insert_reflection(
        &temp.repo,
        run_b,
        spec_id,
        ReflectionResult::IncompleteStep,
        "b",
    )
    .await;

    let out = temp.repo.pending_reflections().await.expect("query");
    assert_eq!(out.len(), 2);
    let by_id: std::collections::HashMap<i32, i32> =
        out.iter().map(|r| (r.reflection_id, r.code_id)).collect();
    assert_eq!(by_id[&rid_a], code_a);
    assert_eq!(by_id[&rid_b], code_b);
}
