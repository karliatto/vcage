//! Heuristics for "is this path inside a cloud-sync folder?".

use std::path::{Component, Path, PathBuf};

/// Directory names (compared case-insensitively) used by sync clients.
const SYNC_DIR_NAMES: &[(&str, &str)] = &[
    ("dropbox", "Dropbox"),
    ("nextcloud", "Nextcloud"),
    ("owncloud", "ownCloud"),
    ("onedrive", "OneDrive"),
    ("google drive", "Google Drive"),
    ("googledrive", "Google Drive"),
    ("my drive", "Google Drive"),
    ("gdrive", "Google Drive"),
    ("insync", "Google Drive (Insync)"),
    ("syncthing", "Syncthing"),
];

/// Marker files that sync clients leave in the root of a synced folder, and
/// whether the marker must be a regular file. `~/.dropbox` is the Dropbox
/// client's config *directory*, so only a `.dropbox` file marks a synced root.
const MARKERS: &[(&str, &str, bool)] = &[
    (".stfolder", "Syncthing", false),
    (".dropbox", "Dropbox", true),
    (".dropbox.cache", "Dropbox", false),
    (".nextcloudsync.log", "Nextcloud", false),
    (".owncloudsync.log", "ownCloud", false),
];

/// Returns the name of the sync service `path` appears to be inside, if any.
/// `extra` are user-configured synced directories (already expanded).
pub fn detect(path: &Path, home: &Path, extra: &[PathBuf]) -> Option<String> {
    let real = resolve_existing_prefix(path);
    for candidate in [path, real.as_path()] {
        for dir in extra {
            if candidate.starts_with(dir) {
                return Some(format!("configured sync folder {}", dir.display()));
            }
        }
        for c in candidate.components() {
            if let Component::Normal(name) = c {
                let lower = name.to_string_lossy().to_lowercase();
                for (n, service) in SYNC_DIR_NAMES {
                    // Also catch "Dropbox (Personal)", "OneDrive - Contoso", ...
                    if lower == *n || lower.starts_with(&format!("{n} ")) {
                        return Some((*service).to_string());
                    }
                }
            }
        }
        // Syncthing's default folder is ~/Sync.
        if candidate.starts_with(home.join("Sync")) {
            return Some("Syncthing".into());
        }
    }
    for dir in real.ancestors() {
        for (m, service, file_only) in MARKERS {
            let p = dir.join(m);
            let found = if *file_only { p.is_file() } else { p.exists() };
            if found {
                return Some((*service).to_string());
            }
        }
        // Nextcloud/ownCloud journal databases: .sync_XXXX.db / ._sync_XXXX.db
        if let Ok(rd) = std::fs::read_dir(dir) {
            let has_journal = rd.flatten().any(|e| {
                let n = e.file_name().to_string_lossy().into_owned();
                (n.starts_with(".sync_") || n.starts_with("._sync_")) && n.ends_with(".db")
            });
            if has_journal {
                return Some("Nextcloud/ownCloud".into());
            }
        }
    }
    None
}

/// Canonicalizes the longest existing prefix of `path` (to see through
/// symlinks) and re-appends the rest.
fn resolve_existing_prefix(path: &Path) -> PathBuf {
    let mut rest = Vec::new();
    let mut cur = path;
    loop {
        if let Ok(c) = cur.canonicalize() {
            return rest.iter().rev().fold(c, |acc: PathBuf, r| acc.join(r));
        }
        match (cur.parent(), cur.file_name()) {
            (Some(p), Some(n)) => {
                rest.push(n.to_os_string());
                cur = p;
            }
            _ => return path.to_path_buf(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn d(p: &str) -> Option<String> {
        detect(Path::new(p), Path::new("/nonexistent-home"), &[])
    }

    #[test]
    fn detects_by_name() {
        assert_eq!(
            d("/nonexistent-home/Dropbox/vc").as_deref(),
            Some("Dropbox")
        );
        assert_eq!(
            d("/nonexistent-home/Dropbox (Personal)/x").as_deref(),
            Some("Dropbox")
        );
        assert_eq!(
            d("/nonexistent-home/OneDrive - Contoso/x").as_deref(),
            Some("OneDrive")
        );
        assert_eq!(
            d("/nonexistent-home/Nextcloud/a/b").as_deref(),
            Some("Nextcloud")
        );
        assert_eq!(
            d("/nonexistent-home/Google Drive/x").as_deref(),
            Some("Google Drive")
        );
        assert_eq!(d("/nonexistent-home/Sync/vc").as_deref(), Some("Syncthing"));
        assert_eq!(d("/nonexistent-home/vc/personal"), None);
        assert_eq!(d("/nonexistent-home/dropboxing/x"), None);
    }

    #[test]
    fn detects_markers_and_extra_dirs() {
        let t = tempfile::tempdir().unwrap();
        let shared = t.path().join("shared");
        std::fs::create_dir_all(shared.join("sub")).unwrap();
        std::fs::write(shared.join(".stfolder"), "").unwrap();
        let home = Path::new("/nonexistent-home");
        assert_eq!(
            detect(&shared.join("sub/not-yet"), home, &[]).as_deref(),
            Some("Syncthing")
        );
        let other = t.path().join("other");
        std::fs::create_dir_all(&other).unwrap();
        assert_eq!(detect(&other.join("mnt"), home, &[]), None);
        assert!(detect(&other.join("mnt"), home, std::slice::from_ref(&other)).is_some());
        // A symlink into a synced folder is seen through.
        let link = t.path().join("link");
        std::os::unix::fs::symlink(&shared, &link).unwrap();
        assert!(detect(&link.join("mnt"), home, &[]).is_some());
    }

    #[test]
    fn dropbox_config_dir_is_not_a_marker() {
        let t = tempfile::tempdir().unwrap();
        let home = t.path();
        // The Dropbox client keeps its config in ~/.dropbox (a directory).
        std::fs::create_dir_all(home.join(".dropbox")).unwrap();
        std::fs::create_dir_all(home.join("vc")).unwrap();
        assert_eq!(detect(&home.join("vc/personal"), home, &[]), None);
        // The synced folder's root has a .dropbox *file*.
        let synced = home.join("Box");
        std::fs::create_dir_all(&synced).unwrap();
        std::fs::write(synced.join(".dropbox"), "{}").unwrap();
        assert_eq!(
            detect(&synced.join("vc"), home, &[]).as_deref(),
            Some("Dropbox")
        );
    }
}
