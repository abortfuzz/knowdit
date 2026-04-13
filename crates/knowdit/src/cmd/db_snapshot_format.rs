use clap::ValueEnum;
use color_eyre::eyre::{Result, eyre};
use std::path::Path;

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub enum DbSnapshotFormat {
    Sql,
    Json,
}

impl DbSnapshotFormat {
    pub fn infer_from_path(path: &Path) -> Option<Self> {
        let extension = path.extension()?.to_str()?.to_ascii_lowercase();
        match extension.as_str() {
            "sql" => Some(Self::Sql),
            "json" => Some(Self::Json),
            _ => None,
        }
    }

    pub fn resolve_output_format(path: &Path, format: Option<Self>) -> Self {
        format
            .or_else(|| Self::infer_from_path(path))
            .unwrap_or(Self::Sql)
    }

    pub fn resolve_input_format(path: &Path, format: Option<Self>) -> Result<Self> {
        format
            .or_else(|| Self::infer_from_path(path))
            .ok_or_else(|| {
                eyre!(
                    "could not infer snapshot format from {}. Use --format sql or --format json",
                    path.display()
                )
            })
    }
}

#[cfg(test)]
mod tests {
    use super::DbSnapshotFormat;
    use std::path::Path;

    #[test]
    fn infers_snapshot_format_from_supported_extensions() {
        assert_eq!(
            DbSnapshotFormat::infer_from_path(Path::new("snapshot.sql")),
            Some(DbSnapshotFormat::Sql)
        );
        assert_eq!(
            DbSnapshotFormat::infer_from_path(Path::new("snapshot.JSON")),
            Some(DbSnapshotFormat::Json)
        );
    }

    #[test]
    fn output_defaults_to_sql_when_extension_is_unknown() {
        assert_eq!(
            DbSnapshotFormat::resolve_output_format(Path::new("snapshot.unknown"), None,),
            DbSnapshotFormat::Sql
        );
    }

    #[test]
    fn input_requires_explicit_or_inferred_format() {
        let error = DbSnapshotFormat::resolve_input_format(Path::new("snapshot.unknown"), None)
            .expect_err("unknown import format should error");

        assert!(
            error
                .to_string()
                .contains("could not infer snapshot format")
        );
    }
}
