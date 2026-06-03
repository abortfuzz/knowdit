//! Test suites for [`crate::repo::RepoDatabase`], grouped by the API
//! surface they cover. Each submodule stands up a fresh on-disk SQLite
//! via its own `temp_db` helper, calls `init_schema`, seeds whatever
//! FK-parent rows the test needs, then drives the method under test.

mod chain;
mod findings;
mod link;
mod repo;
