//! Locating external programs on `PATH`, with install hints for Nix users.

use std::env;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tool {
    Age,
    AgePluginTrezor,
    VeraCrypt,
    Sudo,
}

impl Tool {
    pub fn binary(self) -> &'static str {
        match self {
            Tool::Age => "age",
            Tool::AgePluginTrezor => "age-plugin-trezor",
            Tool::VeraCrypt => "veracrypt",
            Tool::Sudo => "sudo",
        }
    }

    pub fn install_hint(self) -> &'static str {
        match self {
            Tool::Age => "install the `age` Nix package (e.g. `nix shell nixpkgs#age`)",
            Tool::AgePluginTrezor => {
                "install the `trezor-agent` Nix package, which provides age-plugin-trezor \
                 (e.g. `nix shell nixpkgs#trezor-agent`)"
            }
            Tool::VeraCrypt => {
                "install the `veracrypt` Nix package; it is unfree, so set \
                 `nixpkgs.config.allowUnfree = true` (or an allowUnfreePredicate) or run \
                 `NIXPKGS_ALLOW_UNFREE=1 nix shell --impure nixpkgs#veracrypt`"
            }
            Tool::Sudo => {
                "sudo must be installed and configured by the system \
                 (on NixOS it is /run/wrappers/bin/sudo)"
            }
        }
    }
}

#[derive(Debug, Error)]
#[error("`{binary}` was not found on PATH: {hint}")]
pub struct MissingTool {
    pub binary: &'static str,
    pub hint: &'static str,
}

/// Finds `tool` on `$PATH`, returning its absolute path.
pub fn find(tool: Tool) -> Result<PathBuf, MissingTool> {
    let path = env::var_os("PATH").unwrap_or_default();
    find_in(tool.binary(), env::split_paths(&path)).ok_or(MissingTool {
        binary: tool.binary(),
        hint: tool.install_hint(),
    })
}

fn find_in(name: &str, dirs: impl Iterator<Item = PathBuf>) -> Option<PathBuf> {
    dirs.filter(|d| d.is_absolute())
        .map(|d| d.join(name))
        .find(|p| is_executable(p))
}

fn is_executable(p: &Path) -> bool {
    p.metadata()
        .map(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn finds_executables_only_in_absolute_dirs() {
        let a = tempfile::tempdir().unwrap();
        let b = tempfile::tempdir().unwrap();
        fs::write(a.path().join("age"), "").unwrap(); // not executable
        let exe = b.path().join("age");
        fs::write(&exe, "").unwrap();
        fs::set_permissions(&exe, fs::Permissions::from_mode(0o755)).unwrap();
        let dirs = vec![PathBuf::from("relative"), a.path().into(), b.path().into()];
        assert_eq!(find_in("age", dirs.into_iter()), Some(exe));
        assert_eq!(find_in("nope", vec![b.path().into()].into_iter()), None);
    }

    #[test]
    fn missing_tool_message_mentions_nix() {
        let e = MissingTool {
            binary: "veracrypt",
            hint: Tool::VeraCrypt.install_hint(),
        };
        let msg = e.to_string();
        assert!(msg.contains("veracrypt"));
        assert!(msg.contains("NIXPKGS_ALLOW_UNFREE=1"));
    }
}
