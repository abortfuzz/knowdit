//! Tests for [`RepoDatabase::link_resume_state`].
//!
//! The method drives streamloop's DB-only resume policy. Each test
//! stands up a fresh on-disk SQLite, seeds the FK chain by hand, and
//! asserts the returned [`LinkResumeState`] for one
//! `(extract, historical, finding)` triple.
//!
//! State map (mirrors the doc-comment on `link_resume_state`):
//!
//! | rows in `specification` for (E, H, F) | rows in `code_gen` (for those specs) | state         |
//! |---------------------------------------|--------------------------------------|---------------|
//! | 0                                     | (n/a)                                | `NotStarted`  |
//! | ≥1                                    | 0                                    | `Partial`     |
//! | ≥1                                    | ≥1                                   | `Built`       |
//!
//! Each test covers ONE branch of the table above, plus a few scoping
//! invariants (the lookup is keyed on the full triple — sibling
//! historicals don't bleed into each other).

use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use knowdit_kg_model::category::DeFiCategory;
use sea_orm::{ActiveValue::Set, EntityTrait};

use crate::db::{
    code_gen as code_gen_model, historical_semantic as historical_semantic_model,
    project_semantic as project_semantic_model, specification as specification_model,
};
use crate::repo::{CodeGenStatus, LinkResumeState, RepoDatabase};

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
        "knowdit-link-resume-test-{}-{unique}.sqlite3",
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
) -> i32 {
    let res = specification_model::Entity::insert(specification_model::ActiveModel {
        semantic_id: Set(extract_id),
        historical_id: Set(historical_id),
        finding_id: Set(finding_id),
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

#[tokio::test]
async fn not_started_when_no_specs() {
    let temp = temp_db().await;
    insert_extract(&temp.repo, 1).await;
    insert_historical(&temp.repo, 100).await;
    let state = temp.repo.link_resume_state(1, 100, 99).await.unwrap();
    assert_eq!(state, LinkResumeState::NotStarted);
}

#[tokio::test]
async fn partial_when_specs_but_no_codegen() {
    let temp = temp_db().await;
    insert_extract(&temp.repo, 1).await;
    insert_historical(&temp.repo, 100).await;
    let s1 = insert_spec(&temp.repo, 1, 100, 7).await;
    let s2 = insert_spec(&temp.repo, 1, 100, 7).await;
    let state = temp.repo.link_resume_state(1, 100, 7).await.unwrap();
    // Both specs surface in the Partial payload, ordered by id ASC
    // (matches the loader's `.order_by_asc(Id)`).
    assert_eq!(
        state,
        LinkResumeState::Partial {
            spec_ids: vec![s1, s2]
        }
    );
}

#[tokio::test]
async fn built_when_any_spec_has_codegen() {
    let temp = temp_db().await;
    insert_extract(&temp.repo, 1).await;
    insert_historical(&temp.repo, 100).await;
    let s1 = insert_spec(&temp.repo, 1, 100, 7).await;
    let _s2 = insert_spec(&temp.repo, 1, 100, 7).await;
    // One spec out of two has a code_gen — the link is "Built" from
    // streamloop's perspective. Standalone reflect / regen will handle
    // the other.
    insert_code_gen(&temp.repo, s1).await;
    let state = temp.repo.link_resume_state(1, 100, 7).await.unwrap();
    assert_eq!(state, LinkResumeState::Built);
}

#[tokio::test]
async fn scoped_by_extract_historical_and_finding() {
    let temp = temp_db().await;
    insert_extract(&temp.repo, 1).await;
    insert_extract(&temp.repo, 2).await;
    insert_historical(&temp.repo, 100).await;
    insert_historical(&temp.repo, 200).await;
    // (extract=1, historical=100, finding=7) has specs.
    insert_spec(&temp.repo, 1, 100, 7).await;

    // Different extract id.
    assert_eq!(
        temp.repo.link_resume_state(2, 100, 7).await.unwrap(),
        LinkResumeState::NotStarted,
        "different extract id must not see specs from other extracts"
    );
    // Different finding id.
    assert_eq!(
        temp.repo.link_resume_state(1, 100, 8).await.unwrap(),
        LinkResumeState::NotStarted,
        "different finding id must not see specs from other findings"
    );
    // Different historical id — this is the new isolation we get from
    // Tier 2's (E, H, F) keying; pre-Tier 2 this would have spuriously
    // returned Partial because the (E, F) pair had specs.
    assert_eq!(
        temp.repo.link_resume_state(1, 200, 7).await.unwrap(),
        LinkResumeState::NotStarted,
        "different historical id must not see specs from other historicals"
    );
}

#[tokio::test]
async fn sibling_historicals_get_independent_states() {
    let temp = temp_db().await;
    insert_extract(&temp.repo, 1).await;
    insert_historical(&temp.repo, 100).await;
    insert_historical(&temp.repo, 200).await;
    // The fresh-run intentional fan-out: extract 1 matched to two
    // historicals, both linking to finding 7, each emits its own
    // specs. After a Ctrl-C between gen-spec and first fuzz, both
    // sets sit in `specification` with NO code_gen yet.
    let h100_specs = vec![
        insert_spec(&temp.repo, 1, 100, 7).await,
        insert_spec(&temp.repo, 1, 100, 7).await,
    ];
    let h200_specs = vec![
        insert_spec(&temp.repo, 1, 200, 7).await,
        insert_spec(&temp.repo, 1, 200, 7).await,
    ];

    // Each sibling resumes its OWN spec ids — no cross-historical
    // pollution.
    assert_eq!(
        temp.repo.link_resume_state(1, 100, 7).await.unwrap(),
        LinkResumeState::Partial {
            spec_ids: h100_specs.clone()
        }
    );
    assert_eq!(
        temp.repo.link_resume_state(1, 200, 7).await.unwrap(),
        LinkResumeState::Partial {
            spec_ids: h200_specs.clone()
        }
    );

    // If only the H=100 side gets a code_gen, ONLY that side flips to
    // Built; the H=200 side stays Partial.
    insert_code_gen(&temp.repo, h100_specs[0]).await;
    assert_eq!(
        temp.repo.link_resume_state(1, 100, 7).await.unwrap(),
        LinkResumeState::Built
    );
    assert_eq!(
        temp.repo.link_resume_state(1, 200, 7).await.unwrap(),
        LinkResumeState::Partial {
            spec_ids: h200_specs
        }
    );
}

#[tokio::test]
async fn codegen_on_unrelated_spec_does_not_count() {
    let temp = temp_db().await;
    insert_extract(&temp.repo, 1).await;
    insert_historical(&temp.repo, 100).await;
    // Spec for the link under test.
    insert_spec(&temp.repo, 1, 100, 7).await;
    // Spec for a different finding under same (E, H) — has a code_gen.
    let other = insert_spec(&temp.repo, 1, 100, 99).await;
    insert_code_gen(&temp.repo, other).await;

    // Our link (1, 100, 7) is still Partial: its OWN specs lack a code_gen.
    let state = temp.repo.link_resume_state(1, 100, 7).await.unwrap();
    match state {
        LinkResumeState::Partial { .. } => (),
        other => panic!("expected Partial, got {other:?}"),
    }
}
