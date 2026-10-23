//! Test harness: a temporary $HOME, a real `age`/`age-keygen` (X25519, no
//! Trezor), and fake `sudo`/`veracrypt` scripts placed first on PATH.
#![allow(dead_code)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};

/// Fake `sudo`: drops the `--` and runs the command as the current user.
const FAKE_SUDO: &str = r#"#!/bin/sh
echo "sudo $*" >> "$FAKE_LOG"
[ "$1" = "--" ] && shift
exec "$@"
"#;

/// Fake `veracrypt`. Mount state is a file holding `veracrypt -l` output.
/// It copies the keyfile it is given to $FAKE_KEYCOPY so tests can inspect it
/// after vcage has wiped the original.
const FAKE_VERACRYPT: &str = r#"#!/bin/sh
echo "veracrypt $*" >> "$FAKE_LOG"
keyfile=""; mode=mount; vol=""; prev=""; last=""; second_last=""
for a in "$@"; do
  case "$a" in
    --keyfiles=*) keyfile="${a#--keyfiles=}" ;;
    -l) mode=list ;;
    -d) mode=dismount ;;
    --create) mode=create ;;
  esac
  [ "$prev" = "--create" ] && vol="$a"
  prev="$a"; second_last="$last"; last="$a"
done
case "$mode" in
  list)
    if [ -s "$FAKE_STATE" ]; then cat "$FAKE_STATE"; exit 0; fi
    echo "Error: No volumes mounted." >&2; exit 1 ;;
  dismount)
    rm -f "$FAKE_STATE"; exit 0 ;;
esac
[ -f "$keyfile" ] || { echo "fake veracrypt: keyfile missing" >&2; exit 3; }
cp "$keyfile" "$FAKE_KEYCOPY"
stat -c %a "$keyfile" > "$FAKE_KEYCOPY.mode"
if [ -n "$FAKE_BLOCK" ]; then
  touch "$FAKE_READY"
  exec sleep 30
fi
[ "${FAKE_EXIT:-0}" = 0 ] || exit "$FAKE_EXIT"
if [ "$mode" = create ]; then
  printf 'fake volume' > "$vol"
else
  echo "1: $second_last /dev/mapper/veracrypt1 $last" > "$FAKE_STATE"
fi
"#;

pub struct Env {
    pub root: tempfile::TempDir,
    pub home: PathBuf,
    pub bin: PathBuf,
    pub extra_env: Vec<(String, String)>,
}

pub fn find_tool(name: &str) -> PathBuf {
    let path = std::env::var_os("PATH").unwrap_or_default();
    std::env::split_paths(&path)
        .map(|d| d.join(name))
        .find(|p| p.is_file())
        .unwrap_or_else(|| {
            panic!("`{name}` is required for the integration tests; run them in `nix develop`")
        })
}

impl Env {
    pub fn new() -> Env {
        let root = tempfile::tempdir().unwrap();
        let home = root.path().join("home");
        let bin = root.path().join("bin");
        fs::create_dir_all(&home).unwrap();
        fs::create_dir_all(&bin).unwrap();
        for (name, body) in [("sudo", FAKE_SUDO), ("veracrypt", FAKE_VERACRYPT)] {
            let p = bin.join(name);
            fs::write(&p, body).unwrap();
            fs::set_permissions(&p, fs::Permissions::from_mode(0o755)).unwrap();
        }
        // Real age binaries, linked so a restricted PATH still finds them.
        for name in ["age", "age-keygen"] {
            std::os::unix::fs::symlink(find_tool(name), bin.join(name)).unwrap();
        }
        Env {
            root,
            home,
            bin,
            extra_env: Vec::new(),
        }
    }

    pub fn path(&self, rel: &str) -> PathBuf {
        self.root.path().join(rel)
    }

    pub fn identities(&self) -> PathBuf {
        self.home.join(".config/vcage/identities")
    }

    /// Creates an X25519 identity named `name` with age-keygen; returns its
    /// public key.
    pub fn keygen(&self, name: &str) -> String {
        let dir = self.identities();
        fs::create_dir_all(&dir).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        let path = dir.join(format!("{name}.txt"));
        let st = Command::new(self.bin.join("age-keygen"))
            .arg("-o")
            .arg(&path)
            .stderr(Stdio::null())
            .status()
            .unwrap();
        assert!(st.success());
        let text = fs::read_to_string(&path).unwrap();
        text.lines()
            .find_map(|l| l.strip_prefix("# public key: "))
            .unwrap()
            .to_string()
    }

    pub fn age_decrypt(&self, identity: &Path, file: &Path) -> Vec<u8> {
        let out = Command::new(self.bin.join("age"))
            .arg("-d")
            .arg("-i")
            .arg(identity)
            .arg(file)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        out.stdout
    }

    pub fn cmd(&self, args: &[&str]) -> Command {
        let mut c = Command::new(env!("CARGO_BIN_EXE_vcage"));
        c.args(args)
            .env_clear()
            .env("HOME", &self.home)
            .env("PATH", format!("{}:/usr/bin:/bin", self.bin.display()))
            .env("FAKE_LOG", self.path("log"))
            .env("FAKE_STATE", self.path("state"))
            .env("FAKE_KEYCOPY", self.path("keycopy"))
            .env("FAKE_READY", self.path("ready"))
            .stdin(Stdio::null());
        for (k, v) in &self.extra_env {
            c.env(k, v);
        }
        c
    }

    /// Runs vcage to completion and asserts that, whatever happened, it left
    /// no plaintext keyfile behind.
    pub fn run(&self, args: &[&str]) -> Output {
        let child = self
            .cmd(args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let pid = child.id();
        let out = child.wait_with_output().unwrap();
        let left = leftovers(pid);
        assert!(left.is_empty(), "plaintext keyfile left behind: {left:?}");
        out
    }

    pub fn spawn(&self, args: &[&str]) -> Child {
        self.cmd(args)
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap()
    }

    pub fn log(&self) -> String {
        fs::read_to_string(self.path("log")).unwrap_or_default()
    }

    pub fn keycopy(&self) -> Vec<u8> {
        fs::read(self.path("keycopy")).unwrap()
    }

    pub fn keycopy_mode(&self) -> String {
        fs::read_to_string(self.path("keycopy.mode"))
            .unwrap()
            .trim()
            .to_string()
    }
}

/// Plaintext keyfiles that process `pid` left in /dev/shm.
pub fn leftovers(pid: u32) -> Vec<PathBuf> {
    let prefix = vcage::keyfile::name_prefix(pid);
    fs::read_dir(vcage::keyfile::SHM_DIR)
        .unwrap()
        .flatten()
        .filter(|e| e.file_name().to_string_lossy().starts_with(&prefix))
        .map(|e| e.path())
        .collect()
}

pub fn stderr(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

pub fn stdout(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

#[track_caller]
pub fn assert_ok(o: &Output) {
    assert!(o.status.success(), "vcage failed:\n{}", stderr(o));
}

#[track_caller]
pub fn assert_err(o: &Output, needle: &str) {
    assert!(!o.status.success(), "vcage unexpectedly succeeded");
    assert!(
        stderr(o).contains(needle),
        "stderr does not contain {needle:?}:\n{}",
        stderr(o)
    );
}
