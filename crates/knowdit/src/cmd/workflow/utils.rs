//! Small shared helpers for the workflow orchestrators.

use std::path::{Path, PathBuf};

use color_eyre::eyre::{Result, WrapErr};
use serde::Serialize;

/// Serialize `value` as pretty JSON and write it to `final_path` atomically:
/// write to a sibling `*.tmp` file, then rename it over the target, so a crash
/// mid-write never leaves a half-written file behind. The parent directory must
/// already exist.
pub(crate) fn write_json_atomic<T: Serialize>(final_path: &Path, value: &T) -> Result<()> {
    let body = serde_json::to_string_pretty(value)
        .wrap_err_with(|| format!("failed to serialize JSON for {}", final_path.display()))?;
    let mut tmp = final_path.as_os_str().to_owned();
    tmp.push(".tmp");
    let tmp = PathBuf::from(tmp);
    std::fs::write(&tmp, body).wrap_err_with(|| format!("failed to write {}", tmp.display()))?;
    std::fs::rename(&tmp, final_path)
        .wrap_err_with(|| format!("failed to rename into {}", final_path.display()))?;
    Ok(())
}
