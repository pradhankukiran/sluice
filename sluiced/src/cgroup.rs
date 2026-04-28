//! Locate the cgroup v2 root that we attach `cgroup/connect4`/`connect6`
//! programs to.
//!
//! Cgroup v2 has a single unified hierarchy mounted at `/sys/fs/cgroup` on
//! every modern systemd-based distro. We confirm v2 by probing for
//! `cgroup.controllers` — that interface file only exists in the v2 root.
//!
//! Operators can override the path via `SLUICE_CGROUP_ROOT`.

use std::env;
use std::path::{Path, PathBuf};

use thiserror::Error;

const ENV_OVERRIDE: &str = "SLUICE_CGROUP_ROOT";
const DEFAULT_PATH: &str = "/sys/fs/cgroup";
const V2_PROBE_FILE: &str = "cgroup.controllers";

#[derive(Debug, Error)]
pub enum CgroupRootError {
    #[error("cgroup root {path} does not exist")]
    Missing { path: PathBuf },
    #[error(
        "cgroup root {path} is not cgroup v2 (missing {probe}). \
         sluice requires the unified cgroup v2 hierarchy."
    )]
    NotV2 { path: PathBuf, probe: &'static str },
}

/// Returns the cgroup v2 root sluice should attach to.
pub fn resolve() -> Result<PathBuf, CgroupRootError> {
    let raw = env::var(ENV_OVERRIDE).unwrap_or_else(|_| DEFAULT_PATH.to_string());
    let path = PathBuf::from(raw);
    validate(&path)?;
    Ok(path)
}

fn validate(path: &Path) -> Result<(), CgroupRootError> {
    if !path.exists() {
        return Err(CgroupRootError::Missing {
            path: path.to_path_buf(),
        });
    }
    if !path.join(V2_PROBE_FILE).exists() {
        return Err(CgroupRootError::NotV2 {
            path: path.to_path_buf(),
            probe: V2_PROBE_FILE,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_path_is_reported() {
        let err = validate(Path::new("/definitely/not/here")).unwrap_err();
        assert!(matches!(err, CgroupRootError::Missing { .. }));
    }

    #[test]
    fn directory_without_controllers_is_rejected() {
        let dir = tempdir();
        let err = validate(&dir).unwrap_err();
        assert!(matches!(err, CgroupRootError::NotV2 { .. }));
    }

    #[test]
    fn directory_with_controllers_passes() {
        let dir = tempdir();
        std::fs::write(dir.join(V2_PROBE_FILE), "").unwrap();
        validate(&dir).unwrap();
    }

    fn tempdir() -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!(
            "sluice-cgroup-test-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&p).unwrap();
        p
    }
}
