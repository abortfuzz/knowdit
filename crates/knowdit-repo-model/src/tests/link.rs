//! Integration-style tests for [`RepoDatabase::load_link_for_spec`].
//!
//! Each test stands up a fresh on-disk SQLite via `temp_db`, calls
//! `init_schema`, seeds the FK-required parent rows
//! (`project_semantic` / `historical_semantic` / `historical_finding`)
//! before any `specification` / `semantic_matched` /
//! `historical_semantic_finding_link` insert, and asserts on the
//! `(SemanticMatch, semantic_finding_link::Model)` pair the loader
//! returns.

use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use knowdit_kg_model::audit_finding::FindingSeverity;
use knowdit_kg_model::category::DeFiCategory;
use knowdit_kg_model::link_strength::LinkStrength;
use sea_orm::{ActiveValue::Set, EntityTrait};

use crate::db::{
    historical_finding as historical_finding_model,
    historical_semantic as historical_semantic_model,
    historical_semantic_finding_link as historical_semantic_finding_link_model,
    project_semantic as project_semantic_model, semantic_matched as semantic_matched_model,
    specification as specification_model,
};
use crate::repo::{MatchStrength, RepoDatabase};

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
        "knowdit-load-link-test-{}-{unique}.sqlite3",
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
    .expect("project_semantic parent row should insert");
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
    .expect("historical_semantic parent row should insert");
}

async fn insert_finding(repo: &RepoDatabase, id: i32) {
    historical_finding_model::Entity::insert(historical_finding_model::ActiveModel {
        id: Set(id),
        title: Set(format!("finding_{id}")),
        severity: Set(FindingSeverity::Medium),
        root_cause: Set(String::new()),
        description: Set(String::new()),
        patterns: Set(String::new()),
        exploits: Set(String::new()),
        ..Default::default()
    })
    .exec(repo.connection())
    .await
    .expect("historical_finding parent row should insert");
}

async fn insert_spec(repo: &RepoDatabase, semantic_id: i32, finding_id: i32) -> i32 {
    let res = specification_model::Entity::insert(specification_model::ActiveModel {
        semantic_id: Set(semantic_id),
        finding_id: Set(finding_id),
        specification: Set("{}".to_string()),
        ..Default::default()
    })
    .exec(repo.connection())
    .await
    .expect("specification row should insert");
    res.last_insert_id
}

async fn insert_match(
    repo: &RepoDatabase,
    extract_id: i32,
    historical_id: i32,
    strength: MatchStrength,
    evidence: &str,
) {
    semantic_matched_model::Entity::insert(semantic_matched_model::ActiveModel {
        extract_id: Set(extract_id),
        historical_id: Set(historical_id),
        strength: Set(strength),
        evidence: Set(evidence.to_string()),
        ..Default::default()
    })
    .exec(repo.connection())
    .await
    .expect("semantic_matched row should insert");
}

async fn insert_link(
    repo: &RepoDatabase,
    historical_semantic_id: i32,
    historical_finding_id: i32,
    strength: LinkStrength,
    evidence: &str,
) {
    historical_semantic_finding_link_model::Entity::insert(
        historical_semantic_finding_link_model::ActiveModel {
            historical_semantic_id: Set(historical_semantic_id),
            historical_finding_id: Set(historical_finding_id),
            strength: Set(strength),
            evidence: Set(evidence.to_string()),
            ..Default::default()
        },
    )
    .exec(repo.connection())
    .await
    .expect("historical_semantic_finding_link row should insert");
}

#[tokio::test]
async fn returns_pair_when_chain_exists() {
    let temp = temp_db().await;
    insert_extract(&temp.repo, 101).await;
    insert_historical(&temp.repo, 555).await;
    insert_finding(&temp.repo, 7).await;
    let spec_id = insert_spec(&temp.repo, 101, 7).await;
    insert_match(&temp.repo, 101, 555, MatchStrength::High, "mapper says yes").await;
    insert_link(&temp.repo, 555, 7, LinkStrength::Medium, "linker says ok").await;

    let (m, link) = temp
        .repo
        .load_link_for_spec(spec_id)
        .await
        .expect("query should succeed")
        .expect("chain should resolve to a pair");

    assert_eq!(m.extract_id, 101);
    assert_eq!(m.historical_id, 555);
    assert_eq!(m.strength, MatchStrength::High);
    assert_eq!(m.evidence, "mapper says yes");
    assert_eq!(link.semantic_node_id, 555);
    assert_eq!(link.audit_finding_id, 7);
    assert_eq!(link.strength, LinkStrength::Medium);
    assert_eq!(link.evidence, "linker says ok");
}

#[tokio::test]
async fn returns_none_when_spec_missing() {
    let temp = temp_db().await;
    let pair = temp
        .repo
        .load_link_for_spec(9999)
        .await
        .expect("query should succeed");
    assert!(pair.is_none());
}

#[tokio::test]
async fn returns_none_when_no_match() {
    let temp = temp_db().await;
    insert_extract(&temp.repo, 101).await;
    insert_finding(&temp.repo, 7).await;
    let spec_id = insert_spec(&temp.repo, 101, 7).await;
    // No semantic_matched row at all.

    let pair = temp
        .repo
        .load_link_for_spec(spec_id)
        .await
        .expect("query should succeed");
    assert!(pair.is_none());
}

#[tokio::test]
async fn returns_none_when_match_but_no_link() {
    let temp = temp_db().await;
    insert_extract(&temp.repo, 101).await;
    insert_historical(&temp.repo, 555).await;
    insert_finding(&temp.repo, 7).await;
    let spec_id = insert_spec(&temp.repo, 101, 7).await;
    insert_match(&temp.repo, 101, 555, MatchStrength::High, "mapper says yes").await;
    // No historical_semantic_finding_link row.

    let pair = temp
        .repo
        .load_link_for_spec(spec_id)
        .await
        .expect("query should succeed");
    assert!(pair.is_none());
}

#[tokio::test]
async fn picks_strongest_match_strength_first() {
    let temp = temp_db().await;
    insert_extract(&temp.repo, 101).await;
    insert_historical(&temp.repo, 500).await;
    insert_historical(&temp.repo, 600).await;
    insert_finding(&temp.repo, 7).await;
    let spec_id = insert_spec(&temp.repo, 101, 7).await;
    // Two historicals both match the extract; both own the finding.
    // 600 has a stronger MATCH (High vs Low) — should win even
    // though its LINK is weaker.
    insert_match(&temp.repo, 101, 500, MatchStrength::Low, "weak match").await;
    insert_match(&temp.repo, 101, 600, MatchStrength::High, "strong match").await;
    insert_link(&temp.repo, 500, 7, LinkStrength::High, "strong link").await;
    insert_link(&temp.repo, 600, 7, LinkStrength::Low, "weak link").await;

    let (m, link) = temp
        .repo
        .load_link_for_spec(spec_id)
        .await
        .expect("query should succeed")
        .expect("pair");
    assert_eq!(m.historical_id, 600);
    assert_eq!(m.strength, MatchStrength::High);
    assert_eq!(link.semantic_node_id, 600);
    assert_eq!(link.strength, LinkStrength::Low);
}

#[tokio::test]
async fn breaks_match_tie_with_link_strength() {
    let temp = temp_db().await;
    insert_extract(&temp.repo, 101).await;
    insert_historical(&temp.repo, 700).await;
    insert_historical(&temp.repo, 800).await;
    insert_finding(&temp.repo, 7).await;
    let spec_id = insert_spec(&temp.repo, 101, 7).await;
    // Both matches are Medium → tied. Link strength decides:
    // historical 800 has High link, 700 has Low.
    insert_match(&temp.repo, 101, 700, MatchStrength::Medium, "med a").await;
    insert_match(&temp.repo, 101, 800, MatchStrength::Medium, "med b").await;
    insert_link(&temp.repo, 700, 7, LinkStrength::Low, "weak").await;
    insert_link(&temp.repo, 800, 7, LinkStrength::High, "strong").await;

    let (m, link) = temp
        .repo
        .load_link_for_spec(spec_id)
        .await
        .expect("query should succeed")
        .expect("pair");
    assert_eq!(m.historical_id, 800);
    assert_eq!(link.strength, LinkStrength::High);
}

#[tokio::test]
async fn breaks_full_tie_with_lowest_historical_id() {
    let temp = temp_db().await;
    insert_extract(&temp.repo, 101).await;
    insert_historical(&temp.repo, 111).await;
    insert_historical(&temp.repo, 999).await;
    insert_finding(&temp.repo, 7).await;
    let spec_id = insert_spec(&temp.repo, 101, 7).await;
    // All strengths identical → lowest historical_id wins.
    insert_match(&temp.repo, 101, 999, MatchStrength::High, "high a").await;
    insert_match(&temp.repo, 101, 111, MatchStrength::High, "high b").await;
    insert_link(&temp.repo, 999, 7, LinkStrength::High, "link a").await;
    insert_link(&temp.repo, 111, 7, LinkStrength::High, "link b").await;

    let (m, link) = temp
        .repo
        .load_link_for_spec(spec_id)
        .await
        .expect("query should succeed")
        .expect("pair");
    assert_eq!(m.historical_id, 111);
    assert_eq!(link.semantic_node_id, 111);
}

#[tokio::test]
async fn ignores_links_under_other_historicals() {
    let temp = temp_db().await;
    insert_extract(&temp.repo, 101).await;
    insert_historical(&temp.repo, 555).await;
    insert_historical(&temp.repo, 777).await;
    insert_finding(&temp.repo, 7).await;
    insert_finding(&temp.repo, 8).await;
    let spec_id = insert_spec(&temp.repo, 101, 7).await;
    insert_match(&temp.repo, 101, 555, MatchStrength::High, "matched").await;
    // 555 owns no link for finding 7 — only finding 8.
    insert_link(&temp.repo, 555, 8, LinkStrength::High, "wrong finding").await;
    // Another historical owns finding 7 but wasn't matched to this extract.
    insert_link(&temp.repo, 777, 7, LinkStrength::High, "wrong historical").await;

    let pair = temp
        .repo
        .load_link_for_spec(spec_id)
        .await
        .expect("query should succeed");
    assert!(pair.is_none());
}
