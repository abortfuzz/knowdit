//! Integration-style tests for [`RepoDatabase::load_link_for_spec`].
//!
//! Post-Tier-2 the spec row carries its `historical_id` directly, so
//! `load_link_for_spec` just reads the triple off the spec and joins
//! to `semantic_matched` + `historical_semantic_finding_link` for the
//! two strength / evidence pairs — no "pick strongest candidate"
//! heuristic. These tests cover the four boundary conditions of that
//! join: full chain present, spec missing, match missing, link
//! missing, plus the negative case where a link row exists but under
//! a *different* historical than the spec's stored one.

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

async fn insert_spec(
    repo: &RepoDatabase,
    semantic_id: i32,
    historical_id: i32,
    finding_id: i32,
) -> i32 {
    let res = specification_model::Entity::insert(specification_model::ActiveModel {
        semantic_id: Set(semantic_id),
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
    let spec_id = insert_spec(&temp.repo, 101, 555, 7).await;
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
async fn provenance_is_self_contained() {
    let temp = temp_db().await;
    // Content-rich rows so we can assert the provenance embeds the actual
    // text, not just ids.
    project_semantic_model::Entity::insert(project_semantic_model::ActiveModel {
        id: Set(101),
        name: Set("Signature-Authorized Safe Op".to_string()),
        category: Set(DeFiCategory::Services),
        definition: Set("EIP-712 signed safeCancel/safeFill".to_string()),
        description: Set("verifies a typed-data signature".to_string()),
        ..Default::default()
    })
    .exec(temp.repo.connection())
    .await
    .unwrap();
    historical_semantic_model::Entity::insert(historical_semantic_model::ActiveModel {
        id: Set(555),
        name: Set("Meta-Tx Forwarding".to_string()),
        definition: Set("signed payload includes a deadline".to_string()),
        description: Set("rejects expired signatures".to_string()),
        category: Set(DeFiCategory::Services),
        ..Default::default()
    })
    .exec(temp.repo.connection())
    .await
    .unwrap();
    historical_finding_model::Entity::insert(historical_finding_model::ActiveModel {
        id: Set(7),
        title: Set("Lack of deadline check in forwarded request".to_string()),
        severity: Set(FindingSeverity::High),
        root_cause: Set("signed request omits any expiry field".to_string()),
        description: Set("signature stays valid indefinitely".to_string()),
        patterns: Set("missing deadline in typehash".to_string()),
        exploits: Set("replay the signed op later".to_string()),
        ..Default::default()
    })
    .exec(temp.repo.connection())
    .await
    .unwrap();
    let spec_id = insert_spec(&temp.repo, 101, 555, 7).await;
    insert_match(
        &temp.repo,
        101,
        555,
        MatchStrength::High,
        "shared sig mechanism",
    )
    .await;
    insert_link(
        &temp.repo,
        555,
        7,
        LinkStrength::Medium,
        "same failure mode",
    )
    .await;

    let prov = temp
        .repo
        .load_provenance_for_spec(spec_id)
        .await
        .expect("query should succeed")
        .expect("provenance should resolve");

    // Extract: the actual project_semantic row, full content (not just an id).
    assert_eq!(prov.extract.id, 101);
    assert_eq!(prov.extract.name, "Signature-Authorized Safe Op");
    assert_eq!(prov.extract.category, DeFiCategory::Services);
    assert_eq!(
        prov.extract.definition,
        "EIP-712 signed safeCancel/safeFill"
    );
    // Mapper match edge.
    let m = prov.semantic_match.as_ref().expect("match edge present");
    assert_eq!(m.strength, MatchStrength::High);
    assert_eq!(m.evidence, "shared sig mechanism");
    // Historical semantic: the actual row.
    assert_eq!(prov.historical_semantic.id, 555);
    assert_eq!(prov.historical_semantic.name, "Meta-Tx Forwarding");
    assert_eq!(
        prov.historical_semantic.definition,
        "signed payload includes a deadline"
    );
    // KG link edge.
    let l = prov.finding_link.as_ref().expect("link edge present");
    assert_eq!(l.strength, LinkStrength::Medium);
    assert_eq!(l.evidence, "same failure mode");
    // Historical finding: the actual row, full body.
    assert_eq!(prov.historical_finding.id, 7);
    assert_eq!(
        prov.historical_finding.title,
        "Lack of deadline check in forwarded request"
    );
    assert_eq!(prov.historical_finding.severity, FindingSeverity::High);
    assert_eq!(
        prov.historical_finding.root_cause,
        "signed request omits any expiry field"
    );
    assert_eq!(
        prov.historical_finding.exploits,
        "replay the signed op later"
    );

    // Round-trips through serde (the on-disk shape) without loss, and the
    // serialized models carry NO relation-field noise (`functions`,
    // `semantic_node`, …) — `#[sea_orm::model]` strips them.
    let json = serde_json::to_string(&prov).unwrap();
    assert!(json.contains("Lack of deadline check in forwarded request"));
    assert!(!json.contains("functions"));
    assert!(!json.contains("semantic_node"));
    let back: crate::repo::FindingProvenance = serde_json::from_str(&json).unwrap();
    assert_eq!(back.historical_finding.id, 7);
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
    insert_historical(&temp.repo, 555).await;
    insert_finding(&temp.repo, 7).await;
    let spec_id = insert_spec(&temp.repo, 101, 555, 7).await;
    // No semantic_matched row.

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
    let spec_id = insert_spec(&temp.repo, 101, 555, 7).await;
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
async fn returns_exactly_the_h_recorded_on_the_spec() {
    // Post-Tier-2 sanity check: with TWO historicals matching the
    // extract and both linking to the finding, the spec row's stored
    // `historical_id` is the sole driver of which pair gets returned.
    // No "strongest of multiple candidates" heuristic involved.
    let temp = temp_db().await;
    insert_extract(&temp.repo, 101).await;
    insert_historical(&temp.repo, 500).await;
    insert_historical(&temp.repo, 600).await;
    insert_finding(&temp.repo, 7).await;
    // Spec authored under H=600.
    let spec_id = insert_spec(&temp.repo, 101, 600, 7).await;
    // Both H's have matches + links — deliberately giving H=500 the
    // stronger labels to prove the heuristic isn't being applied.
    insert_match(&temp.repo, 101, 500, MatchStrength::High, "strong h500").await;
    insert_match(&temp.repo, 101, 600, MatchStrength::Low, "weak h600").await;
    insert_link(&temp.repo, 500, 7, LinkStrength::High, "strong link 500").await;
    insert_link(&temp.repo, 600, 7, LinkStrength::Low, "weak link 600").await;

    let (m, link) = temp
        .repo
        .load_link_for_spec(spec_id)
        .await
        .expect("query should succeed")
        .expect("pair");
    assert_eq!(m.historical_id, 600, "must return the H stored on the spec");
    assert_eq!(m.strength, MatchStrength::Low);
    assert_eq!(link.semantic_node_id, 600);
    assert_eq!(link.strength, LinkStrength::Low);
}

#[tokio::test]
async fn returns_none_when_links_exist_but_not_for_specs_historical() {
    // A neighbouring historical has a link for the finding, but the
    // spec was authored under a DIFFERENT historical that has no link
    // row. Post-Tier-2 we don't cross-pollinate: returns None.
    let temp = temp_db().await;
    insert_extract(&temp.repo, 101).await;
    insert_historical(&temp.repo, 555).await;
    insert_historical(&temp.repo, 777).await;
    insert_finding(&temp.repo, 7).await;
    // Spec stored under 555.
    let spec_id = insert_spec(&temp.repo, 101, 555, 7).await;
    insert_match(&temp.repo, 101, 555, MatchStrength::High, "matched").await;
    // No link row for (555, 7) — only (777, 7).
    insert_link(&temp.repo, 777, 7, LinkStrength::High, "wrong historical").await;

    let pair = temp
        .repo
        .load_link_for_spec(spec_id)
        .await
        .expect("query should succeed");
    assert!(pair.is_none());
}
