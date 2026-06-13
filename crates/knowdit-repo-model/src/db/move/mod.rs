//! SeaORM entities for the Move-only side of the project DB.
//!
//! Filed under `r#move` (raw identifier — `move` is a keyword)
//! so the Move tables stay corralled together instead of mixing
//! into the larger language-neutral / Solidity-leaning entity
//! list one level up.
//!
//! Tables here:
//! * [`move_struct`] — struct definitions (one row per
//!   declaration; siblings to Solidity's `contract`).
//! * [`move_struct_ability`] — many-to-many between a struct and
//!   its abilities (`copy` / `drop` / `store` / `key`). Reverse-
//!   indexed on `ability` so audit prompts can answer
//!   "every key-able struct in this package".
//! * [`move_function_metadata`] — 1:1 side table on
//!   [`super::function`] carrying Move-only fields the shared
//!   `function` table doesn't have room for (visibility,
//!   entry-ness, generic constraints).

pub mod move_function_metadata;
pub mod move_struct;
pub mod move_struct_ability;
