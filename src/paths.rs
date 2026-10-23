//! Path helpers: `~` expansion and XDG config locations.

use std::env;
use std::ffi::OsString;
use std::path::{Path, PathBuf};

use anyhow::{bail, Result};

/// Returns `$HOME`, which must be set and absolute.
pub fn home_dir() -> Result<PathBuf> {
    match env::var_os("HOME") {
        Some(h) if Path::new(&h).is_absolute() => Ok(PathBuf::from(h)),
        _ => bail!("$HOME is not set or is not an absolute path"),
    }
}

/// Expands a leading `~` or `~/` to `home`. `~user` forms are not supported
/// and are returned unchanged (and will then be treated as relative paths).
pub fn expand_tilde_with(path: &str, home: &Path) -> PathBuf {
    if path == "~" {
        home.to_path_buf()
    } else if let Some(rest) = path.strip_prefix("~/") {
        home.join(rest)
    } else {
        PathBuf::from(path)
    }
}

/// Expands `~` using `$HOME`.
pub fn expand_tilde(path: &str) -> Result<PathBuf> {
    Ok(expand_tilde_with(path, &home_dir()?))
}

/// `$XDG_CONFIG_HOME/vcage` (if set and absolute, per the XDG spec), otherwise
/// `~/.config/vcage`.
pub fn config_dir() -> Result<PathBuf> {
    Ok(config_dir_from(
        env::var_os("XDG_CONFIG_HOME"),
        &home_dir()?,
    ))
}

fn config_dir_from(xdg_config_home: Option<OsString>, home: &Path) -> PathBuf {
    match xdg_config_home {
        Some(x) if Path::new(&x).is_absolute() => PathBuf::from(x).join("vcage"),
        _ => home.join(".config").join("vcage"),
    }
}

pub fn config_file() -> Result<PathBuf> {
    Ok(config_dir()?.join("config.toml"))
}

pub fn identities_dir() -> Result<PathBuf> {
    Ok(config_dir()?.join("identities"))
}

/// Resolves an identity reference. A bare name (no `/`, not starting with
/// `~`) means `<identities_dir>/<name>.txt`; anything else is a path.
pub fn resolve_identity(reference: &str) -> Result<PathBuf> {
    if reference.contains('/') || reference.starts_with('~') {
        expand_tilde(reference)
    } else {
        validate_name(reference, "identity")?;
        Ok(identities_dir()?.join(format!("{reference}.txt")))
    }
}

/// Vault and identity names end up in file names and TOML keys, so keep them simple.
pub fn validate_name(name: &str, what: &str) -> Result<()> {
    let ok = !name.is_empty()
        && name.len() <= 64
        && !name.starts_with('-')
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_');
    if !ok {
        bail!("invalid {what} name {name:?}: use 1-64 characters from [A-Za-z0-9_-], not starting with '-'");
    }
    Ok(())
}

/// Collapses `~` back for display and for storing in the config file.
pub fn contract_tilde(path: &Path) -> String {
    if let Ok(home) = home_dir() {
        if let Ok(rest) = path.strip_prefix(&home) {
            if rest.as_os_str().is_empty() {
                return "~".into();
            }
            return format!("~/{}", rest.display());
        }
    }
    path.display().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expands_tilde() {
        let home = Path::new("/home/alice");
        assert_eq!(expand_tilde_with("~", home), PathBuf::from("/home/alice"));
        assert_eq!(
            expand_tilde_with("~/Vaults/a.vc", home),
            PathBuf::from("/home/alice/Vaults/a.vc")
        );
        assert_eq!(expand_tilde_with("/abs/x", home), PathBuf::from("/abs/x"));
        assert_eq!(expand_tilde_with("rel/x", home), PathBuf::from("rel/x"));
        // `~user` is not expanded, and a `~` in the middle is literal.
        assert_eq!(expand_tilde_with("~bob/x", home), PathBuf::from("~bob/x"));
        assert_eq!(expand_tilde_with("/a/~/b", home), PathBuf::from("/a/~/b"));
    }

    #[test]
    fn config_dir_respects_xdg() {
        let home = Path::new("/home/alice");
        assert_eq!(
            config_dir_from(None, home),
            PathBuf::from("/home/alice/.config/vcage")
        );
        assert_eq!(
            config_dir_from(Some("/xdg".into()), home),
            PathBuf::from("/xdg/vcage")
        );
        // Relative values are invalid per the XDG spec and ignored.
        assert_eq!(
            config_dir_from(Some("rel".into()), home),
            PathBuf::from("/home/alice/.config/vcage")
        );
        assert_eq!(
            config_dir_from(Some("".into()), home),
            PathBuf::from("/home/alice/.config/vcage")
        );
    }

    #[test]
    fn validates_names() {
        assert!(validate_name("personal", "vault").is_ok());
        assert!(validate_name("work_2-b", "vault").is_ok());
        for bad in ["", "-x", "a/b", "a b", "..", "é", &"x".repeat(65)] {
            assert!(validate_name(bad, "vault").is_err(), "{bad:?}");
        }
    }
}
