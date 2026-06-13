//! Tests for [`crate::RepoDatabase::write_package_structure`] /
//! [`crate::RepoDatabase::load_package_structure`].
//!
//! What we cover (§0.1.D rules):
//!
//! * **Round-trip**: write → load → assert eq. Pulls in JSON-encoded
//!   sub-fields (generic_params, fields) so a serde drift in either
//!   direction surfaces immediately.
//! * **Idempotency** / **crash-safe re-run**: write twice with the
//!   same input, second write must leave the DB indistinguishable
//!   from the first. Catches missing `delete_many` clears,
//!   accidental incremental inserts, or auto-increment IDs leaking
//!   between runs.
//! * **Replacement**: write A then write B, only B's content is
//!   visible. Catches the "I only delete some rows" bug class.
//! * **Empty input**: an empty [`MovePackageStructure`] clears
//!   the prior state without erroring.
//! * **UNIQUE constraint**: duplicate `(contract_id, struct_name)`
//!   pairs must be rejected at the SQL layer.

use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use sea_orm::{ActiveValue::Set, EntityTrait};

use crate::db::{contract as contract_model, function as function_model};
use crate::move_lang::{
    MoveAbility, MoveField, MoveFunctionMetadata, MoveGenericParam, MovePackageStructure,
    MoveStruct, MoveVisibility,
};
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
        "knowdit-move-lang-test-{}-{unique}.sqlite3",
        std::process::id()
    ));
    let repo = RepoDatabase::open_sqlite(path.clone())
        .await
        .expect("test repo database should connect");
    repo.init_schema().await.expect("schema should initialize");
    TempDb { repo, path }
}

/// Insert a stub `contract` row so `move_struct.contract_id` has a
/// valid target. The Move ingest path treats contracts as modules.
async fn insert_contract(repo: &RepoDatabase, id: i32) {
    contract_model::Entity::insert(contract_model::ActiveModel {
        id: Set(id),
        name: Set(format!("module_{id}")),
        relative_file_path: Set(format!("sources/m{id}.move")),
        start_line: Set(1),
        start_column: Set(1),
        end_line: Set(1),
        end_column: Set(1),
        content: Set(String::new()),
        description: Set(None),
    })
    .exec(repo.connection())
    .await
    .expect("contract row should insert");
}

/// Insert a stub `function` row so `move_function_metadata.function_id`
/// has a valid FK target.
async fn insert_function(repo: &RepoDatabase, id: i32) {
    function_model::Entity::insert(function_model::ActiveModel {
        id: Set(id),
        name: Set(format!("fn_{id}")),
        args: Set(String::new()),
        relative_file_path: Set(format!("sources/m{id}.move")),
        start_line: Set(1),
        start_column: Set(1),
        end_line: Set(1),
        end_column: Set(1),
        content: Set(None),
        description: Set(None),
    })
    .exec(repo.connection())
    .await
    .expect("function row should insert");
}

fn sample_struct(id: i32, contract_id: i32, name: &str, abilities: &[MoveAbility]) -> MoveStruct {
    MoveStruct {
        id,
        contract_id,
        name: name.to_string(),
        abilities: abilities.to_vec(),
        generic_params: vec![MoveGenericParam {
            name: "T".to_string(),
            constraints: vec![MoveAbility::Store],
            phantom: false,
        }],
        fields: vec![
            MoveField {
                name: "id".to_string(),
                type_repr: "UID".to_string(),
            },
            MoveField {
                name: "amount".to_string(),
                type_repr: "u64".to_string(),
            },
        ],
    }
}

fn sample_function_metadata(function_id: i32, visibility: MoveVisibility) -> MoveFunctionMetadata {
    MoveFunctionMetadata {
        function_id,
        visibility,
        is_entry: matches!(visibility, MoveVisibility::Public),
        generic_params: vec![MoveGenericParam {
            name: "X".to_string(),
            constraints: vec![MoveAbility::Key, MoveAbility::Store],
            phantom: true,
        }],
    }
}

#[tokio::test]
async fn round_trip_package_structure() {
    let temp = temp_db().await;
    insert_contract(&temp.repo, 10).await;
    insert_contract(&temp.repo, 11).await;
    insert_function(&temp.repo, 100).await;
    insert_function(&temp.repo, 101).await;

    // Author abilities out-of-canonical-order on purpose; the load
    // path sorts them via `MoveAbility::canonical_order`. Compare
    // against a sorted copy so the assert documents that contract:
    // abilities are a set, not a list.
    let input = MovePackageStructure {
        structs: vec![
            sample_struct(1, 10, "Coin", &[MoveAbility::Key, MoveAbility::Store]),
            sample_struct(2, 11, "Treasury", &[MoveAbility::Store]),
        ],
        function_metadata: vec![
            sample_function_metadata(100, MoveVisibility::Public),
            sample_function_metadata(101, MoveVisibility::PublicPackage),
        ],
    };

    temp.repo
        .write_package_structure(&input)
        .await
        .expect("write should succeed");
    let loaded = temp
        .repo
        .load_package_structure()
        .await
        .expect("load should succeed");

    let mut expected = input.clone();
    for s in &mut expected.structs {
        s.abilities.sort_by_key(|a| a.canonical_order());
    }
    assert_eq!(
        loaded, expected,
        "round-trip must preserve the input modulo canonical ability ordering"
    );
}

#[tokio::test]
async fn write_package_structure_is_idempotent() {
    // Two identical writes ⇒ DB state identical to one write. Catches
    // missing `delete_many` calls or accidental incremental inserts.
    let temp = temp_db().await;
    insert_contract(&temp.repo, 10).await;
    insert_function(&temp.repo, 100).await;

    let input = MovePackageStructure {
        structs: vec![sample_struct(1, 10, "Coin", &[MoveAbility::Key])],
        function_metadata: vec![sample_function_metadata(100, MoveVisibility::Private)],
    };

    temp.repo.write_package_structure(&input).await.unwrap();
    let after_first = temp.repo.load_package_structure().await.unwrap();
    temp.repo.write_package_structure(&input).await.unwrap();
    let after_second = temp.repo.load_package_structure().await.unwrap();

    assert_eq!(after_first, after_second, "second write must be a no-op");
    assert_eq!(after_second, input);
}

#[tokio::test]
async fn write_package_structure_replaces_prior_snapshot() {
    let temp = temp_db().await;
    insert_contract(&temp.repo, 10).await;
    insert_contract(&temp.repo, 11).await;
    insert_function(&temp.repo, 100).await;
    insert_function(&temp.repo, 101).await;

    let a = MovePackageStructure {
        structs: vec![sample_struct(1, 10, "Old", &[MoveAbility::Store])],
        function_metadata: vec![sample_function_metadata(100, MoveVisibility::Public)],
    };
    let b = MovePackageStructure {
        structs: vec![sample_struct(
            2,
            11,
            "New",
            &[MoveAbility::Key, MoveAbility::Store],
        )],
        function_metadata: vec![sample_function_metadata(101, MoveVisibility::PublicFriend)],
    };

    temp.repo.write_package_structure(&a).await.unwrap();
    temp.repo.write_package_structure(&b).await.unwrap();
    let loaded = temp.repo.load_package_structure().await.unwrap();

    let mut expected = b.clone();
    for s in &mut expected.structs {
        s.abilities.sort_by_key(|a| a.canonical_order());
    }
    assert_eq!(loaded, expected, "only the latest snapshot must remain");
}

#[tokio::test]
async fn empty_package_structure_clears_existing_rows() {
    let temp = temp_db().await;
    insert_contract(&temp.repo, 10).await;
    insert_function(&temp.repo, 100).await;

    let seeded = MovePackageStructure {
        structs: vec![sample_struct(1, 10, "Coin", &[MoveAbility::Key])],
        function_metadata: vec![sample_function_metadata(100, MoveVisibility::Public)],
    };
    temp.repo.write_package_structure(&seeded).await.unwrap();

    let empty = MovePackageStructure::default();
    temp.repo.write_package_structure(&empty).await.unwrap();
    let loaded = temp.repo.load_package_structure().await.unwrap();
    assert!(loaded.structs.is_empty());
    assert!(loaded.function_metadata.is_empty());
}

#[tokio::test]
async fn function_metadata_referencing_missing_function_fails() {
    // FK from move_function_metadata.function_id → function.id.
    // The `PRAGMA foreign_keys=ON` we set in `connect` is what
    // makes this enforceable; this test is the regression catch if
    // either the pragma or the SeaORM `belongs_to` relation gets
    // dropped.
    let temp = temp_db().await;
    // Intentionally do NOT insert function 999.
    let pkg = MovePackageStructure {
        structs: vec![],
        function_metadata: vec![sample_function_metadata(999, MoveVisibility::Public)],
    };
    let err = temp
        .repo
        .write_package_structure(&pkg)
        .await
        .expect_err("function_id=999 has no parent — FK must violate");
    let causes: Vec<String> = err.chain().map(|e| e.to_string()).collect();
    assert!(
        causes
            .iter()
            .any(|s| s.contains("FOREIGN KEY") || s.contains("constraint")),
        "expected FK violation: {causes:?}"
    );
}

#[tokio::test]
async fn struct_referencing_missing_contract_fails() {
    // Same shape, different edge: move_struct.contract_id → contract.id.
    let temp = temp_db().await;
    let pkg = MovePackageStructure {
        structs: vec![sample_struct(1, 999, "Orphan", &[MoveAbility::Key])],
        function_metadata: vec![],
    };
    let err = temp
        .repo
        .write_package_structure(&pkg)
        .await
        .expect_err("contract_id=999 has no parent — FK must violate");
    let causes: Vec<String> = err.chain().map(|e| e.to_string()).collect();
    assert!(
        causes
            .iter()
            .any(|s| s.contains("FOREIGN KEY") || s.contains("constraint")),
        "expected FK violation: {causes:?}"
    );
}

#[tokio::test]
async fn package_structure_unique_index_blocks_dup_struct_name() {
    // The (contract_id, name) UNIQUE index lives in init_schema —
    // make sure it's enforced at the SQL layer, not just relied on
    // in writer logic.
    use sea_orm::DbErr;

    let temp = temp_db().await;
    insert_contract(&temp.repo, 10).await;
    let pkg = MovePackageStructure {
        structs: vec![
            sample_struct(1, 10, "Coin", &[MoveAbility::Key]),
            // Same (contract_id, name) as the first — DB should
            // reject. Different `id` so the PK doesn't collide
            // first.
            sample_struct(2, 10, "Coin", &[MoveAbility::Store]),
        ],
        function_metadata: vec![],
    };

    let err = temp
        .repo
        .write_package_structure(&pkg)
        .await
        .expect_err("duplicate (contract_id, name) must violate UNIQUE");
    let causes: Vec<String> = err.chain().map(|e| e.to_string()).collect();
    assert!(
        causes
            .iter()
            .any(|s| s.contains("UNIQUE") || s.contains("constraint")),
        "expected UNIQUE constraint error in chain: {causes:?}"
    );
    let _: Option<&DbErr> = err.chain().find_map(|c| c.downcast_ref::<DbErr>());
}

#[tokio::test]
async fn struct_ability_reverse_lookup() {
    // The whole reason abilities live in a relation table: enable
    // "find every struct with ability X" queries via JOIN /
    // direct filter, without LIKE-matching a CSV column.
    use crate::db::r#move::move_struct_ability as move_struct_ability_model;
    use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};

    let temp = temp_db().await;
    insert_contract(&temp.repo, 10).await;

    temp.repo
        .write_package_structure(&MovePackageStructure {
            structs: vec![
                sample_struct(1, 10, "Coin", &[MoveAbility::Key, MoveAbility::Store]),
                sample_struct(2, 10, "Recipe", &[MoveAbility::Copy, MoveAbility::Drop]),
                sample_struct(3, 10, "Treasury", &[MoveAbility::Key, MoveAbility::Store]),
            ],
            function_metadata: vec![],
        })
        .await
        .unwrap();

    // Pull out every key-able struct id via the secondary index on
    // `ability`. Audit prompts will use this same query shape to
    // answer "what Sui objects does this package define?".
    let key_struct_ids: std::collections::BTreeSet<i32> = move_struct_ability_model::Entity::find()
        .filter(move_struct_ability_model::Column::Ability.eq(MoveAbility::Key))
        .all(temp.repo.connection())
        .await
        .unwrap()
        .into_iter()
        .map(|row| row.struct_id)
        .collect();
    assert_eq!(
        key_struct_ids,
        std::collections::BTreeSet::from([1, 3]),
        "Coin and Treasury are the only key-able structs"
    );

    // And the inverse — Copy is on Recipe only.
    let copy_struct_ids: std::collections::BTreeSet<i32> =
        move_struct_ability_model::Entity::find()
            .filter(move_struct_ability_model::Column::Ability.eq(MoveAbility::Copy))
            .all(temp.repo.connection())
            .await
            .unwrap()
            .into_iter()
            .map(|row| row.struct_id)
            .collect();
    assert_eq!(copy_struct_ids, std::collections::BTreeSet::from([2]));
}
