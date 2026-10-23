//! `config.toml` parsing, saving and per-vault resolution with CLI overrides.

use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

use crate::paths;

#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default)]
    pub settings: Settings,
    #[serde(default)]
    pub vaults: BTreeMap<String, VaultConfig>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Settings {
    /// Warn when a mountpoint looks like it is inside a cloud-sync folder.
    #[serde(default = "default_true")]
    pub warn_cloud_sync: bool,
    /// Extra directories to treat as synced (in addition to the built-in list).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cloud_sync_dirs: Vec<String>,
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            warn_cloud_sync: true,
            cloud_sync_dirs: Vec::new(),
        }
    }
}

fn default_true() -> bool {
    true
}

/// A vault as stored in the config file (paths may contain `~`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VaultConfig {
    pub volume: String,
    pub keyfile: String,
    pub identity: String,
    pub mountpoint: String,
}

/// Per-field overrides from the command line.
#[derive(Debug, Default, Clone)]
pub struct VaultOverrides {
    pub volume: Option<String>,
    pub keyfile: Option<String>,
    pub identity: Option<String>,
    pub mountpoint: Option<String>,
}

/// A vault with every path expanded and absolute.
#[derive(Debug, Clone, PartialEq)]
pub struct Vault {
    pub name: String,
    pub volume: PathBuf,
    pub keyfile: PathBuf,
    pub identity: PathBuf,
    pub mountpoint: PathBuf,
}

impl Config {
    pub fn parse(text: &str) -> Result<Config> {
        let cfg: Config = toml::from_str(text).context("invalid config file")?;
        for name in cfg.vaults.keys() {
            paths::validate_name(name, "vault")?;
        }
        Ok(cfg)
    }

    /// Loads the config file; a missing file is an empty config.
    pub fn load_from(path: &Path) -> Result<Config> {
        match fs::read_to_string(path) {
            Ok(text) => Config::parse(&text).with_context(|| format!("reading {}", path.display())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Config::default()),
            Err(e) => Err(e).with_context(|| format!("reading {}", path.display())),
        }
    }

    pub fn load() -> Result<Config> {
        Config::load_from(&paths::config_file()?)
    }

    /// Writes the config atomically (temp file + rename), mode 0600, creating
    /// the config directory with mode 0700 if needed.
    pub fn save_to(&self, path: &Path) -> Result<()> {
        let dir = path.parent().context("config path has no parent")?;
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)
            .with_context(|| format!("creating {}", dir.display()))?;
        let text = toml::to_string_pretty(self)?;
        let tmp = dir.join(format!(".config.toml.tmp-{}", std::process::id()));
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&tmp)
            .with_context(|| format!("creating {}", tmp.display()))?;
        let res = f
            .write_all(text.as_bytes())
            .and_then(|_| f.sync_all())
            .and_then(|_| fs::rename(&tmp, path));
        if res.is_err() {
            let _ = fs::remove_file(&tmp);
        }
        res.with_context(|| format!("writing {}", path.display()))
    }

    pub fn save(&self) -> Result<()> {
        self.save_to(&paths::config_file()?)
    }

    /// Resolves a vault from the config, applying overrides. A vault that is
    /// not in the config can still be used if every field is given as a flag.
    pub fn vault(&self, name: &str, ov: &VaultOverrides) -> Result<Vault> {
        paths::validate_name(name, "vault")?;
        let stored = self.vaults.get(name);
        let field = |flag: &Option<String>, f: fn(&VaultConfig) -> &String, what: &str| match (
            flag, stored,
        ) {
            (Some(v), _) => Ok(v.clone()),
            (None, Some(s)) => Ok(f(s).clone()),
            (None, None) => bail!(
                "vault {name:?} is not in the config ({}); add it with `vcage create` \
                     or pass --{what}",
                paths::config_file()
                    .map(|p| p.display().to_string())
                    .unwrap_or_default()
            ),
        };
        let volume = field(&ov.volume, |s| &s.volume, "volume")?;
        let keyfile = field(&ov.keyfile, |s| &s.keyfile, "keyfile")?;
        let identity = field(&ov.identity, |s| &s.identity, "identity")?;
        let mountpoint = field(&ov.mountpoint, |s| &s.mountpoint, "mountpoint")?;
        Ok(Vault {
            name: name.to_string(),
            volume: absolute(paths::expand_tilde(&volume)?)?,
            keyfile: absolute(paths::expand_tilde(&keyfile)?)?,
            identity: absolute(paths::resolve_identity(&identity)?)?,
            mountpoint: absolute(paths::expand_tilde(&mountpoint)?)?,
        })
    }

    pub fn all_vaults(&self) -> Result<Vec<Vault>> {
        self.vaults
            .keys()
            .map(|n| self.vault(n, &VaultOverrides::default()))
            .collect()
    }
}

/// Makes a path absolute against the current directory, without touching the
/// filesystem (the file may not exist yet).
pub fn absolute(p: PathBuf) -> Result<PathBuf> {
    if p.is_absolute() {
        Ok(p)
    } else {
        Ok(std::env::current_dir()?.join(p))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"
[vaults.personal]
volume = "~/Vaults/personal.vc"
keyfile = "~/Vaults/personal.key.age"
identity = "~/.config/vcage/identities/trezor.txt"
mountpoint = "~/vc/personal"
"#;

    #[test]
    fn parses_sample() {
        let cfg = Config::parse(SAMPLE).unwrap();
        assert!(cfg.settings.warn_cloud_sync);
        let v = &cfg.vaults["personal"];
        assert_eq!(v.volume, "~/Vaults/personal.vc");
        assert_eq!(v.keyfile, "~/Vaults/personal.key.age");
        assert_eq!(v.identity, "~/.config/vcage/identities/trezor.txt");
        assert_eq!(v.mountpoint, "~/vc/personal");
    }

    #[test]
    fn parses_settings_and_empty() {
        assert_eq!(Config::parse("").unwrap(), Config::default());
        let cfg = Config::parse(
            "[settings]\nwarn_cloud_sync = false\ncloud_sync_dirs = [\"~/Shared\"]\n",
        )
        .unwrap();
        assert!(!cfg.settings.warn_cloud_sync);
        assert_eq!(cfg.settings.cloud_sync_dirs, vec!["~/Shared".to_string()]);
    }

    #[test]
    fn rejects_bad_configs() {
        // Missing field.
        assert!(Config::parse("[vaults.a]\nvolume = \"x\"\n").is_err());
        // Typo in a field name.
        let typo = SAMPLE.replace("mountpoint", "mountpiont");
        assert!(Config::parse(&typo).is_err());
        // Unknown top-level table.
        assert!(Config::parse("[vault.a]\n").is_err());
        // Bad vault name.
        let bad = SAMPLE.replace("[vaults.personal]", "[vaults.\"a/b\"]");
        assert!(Config::parse(&bad).is_err());
    }

    #[test]
    fn roundtrips() {
        let cfg = Config::parse(SAMPLE).unwrap();
        let text = toml::to_string_pretty(&cfg).unwrap();
        assert_eq!(Config::parse(&text).unwrap(), cfg);
    }

    #[test]
    fn save_and_load() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sub/config.toml");
        assert_eq!(Config::load_from(&path).unwrap(), Config::default());
        let cfg = Config::parse(SAMPLE).unwrap();
        cfg.save_to(&path).unwrap();
        assert_eq!(Config::load_from(&path).unwrap(), cfg);
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        // Saving again replaces the file.
        cfg.save_to(&path).unwrap();
    }

    #[test]
    fn overrides_need_all_fields_for_unknown_vault() {
        let cfg = Config::default();
        let partial = VaultOverrides {
            volume: Some("/v.vc".into()),
            ..Default::default()
        };
        assert!(cfg.vault("x", &partial).is_err());
        let full = VaultOverrides {
            volume: Some("/v.vc".into()),
            keyfile: Some("/k.age".into()),
            identity: Some("/id.txt".into()),
            mountpoint: Some("/mnt/x".into()),
        };
        let v = cfg.vault("x", &full).unwrap();
        assert_eq!(v.volume, PathBuf::from("/v.vc"));
        assert_eq!(v.identity, PathBuf::from("/id.txt"));
    }

    #[test]
    fn override_wins_over_config() {
        let cfg = Config::parse(&SAMPLE.replace('~', "/home/a")).unwrap();
        let ov = VaultOverrides {
            mountpoint: Some("/mnt/other".into()),
            ..Default::default()
        };
        let v = cfg.vault("personal", &ov).unwrap();
        assert_eq!(v.mountpoint, PathBuf::from("/mnt/other"));
        assert_eq!(v.volume, PathBuf::from("/home/a/Vaults/personal.vc"));
    }
}
