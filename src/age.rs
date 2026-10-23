//! age encryption/decryption of the keyfile, via the `age` binary.
//!
//! Decryption sits behind [`KeyfileDecryptor`] so it can later be replaced
//! by the `age` crate (with its `plugin` feature) running in process.

use std::fs::{File, OpenOptions};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::{bail, Context, Result};
use zeroize::Zeroizing;

use crate::bins::{self, Tool};
use crate::cleanup;
use crate::keyfile;

/// Decrypts an age-encrypted keyfile into memory.
pub trait KeyfileDecryptor {
    /// Returns the plaintext of `encrypted`. Implementations must not print,
    /// log or put the plaintext into errors.
    fn decrypt(&self, encrypted: &Path) -> Result<Zeroizing<Vec<u8>>>;
}

/// Runs `age -d -i <identity> <file>`. stdin and stderr are inherited so the
/// plugin's messages ("Please confirm ... on Trezor") reach the user; stdout
/// carries the plaintext and is read straight into a zeroizing buffer.
pub struct AgeCliDecryptor {
    pub identity: PathBuf,
}

impl KeyfileDecryptor for AgeCliDecryptor {
    fn decrypt(&self, encrypted: &Path) -> Result<Zeroizing<Vec<u8>>> {
        let age = bins::find(Tool::Age)?;
        if identity_needs_trezor_plugin(&self.identity)? {
            bins::find(Tool::AgePluginTrezor)?;
        }
        let mut cmd = Command::new(&age);
        cmd.arg("--decrypt")
            .arg("--identity")
            .arg(&self.identity)
            .arg("--")
            .arg(encrypted)
            .stdin(Stdio::inherit())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit());
        let mut child = cleanup::spawn(&mut cmd)?;
        let stdout = child.stdout.take().context("age stdout")?;
        let read = keyfile::read_bounded(stdout);
        let status = cleanup::wait(child)?;
        if !status.success() {
            bail!("age could not decrypt {} ({status})", encrypted.display());
        }
        let data = read.context("reading decrypted keyfile from age")?;
        if data.is_empty() {
            bail!("age produced an empty keyfile from {}", encrypted.display());
        }
        Ok(data)
    }
}

/// Encrypts `plaintext` to `recipients`, writing a new file at `out`
/// (refusing to overwrite). On failure the partial output is removed.
pub fn encrypt(recipients: &[String], plaintext: &Path, out: &Path) -> Result<()> {
    if recipients.is_empty() {
        bail!("no recipients");
    }
    let age = bins::find(Tool::Age)?;
    let file = create_new_private(out)?;
    let mut cmd = Command::new(&age);
    cmd.arg("--encrypt");
    for r in recipients {
        cmd.arg("--recipient").arg(r);
    }
    cmd.arg("--")
        .arg(plaintext)
        .stdin(Stdio::null())
        .stdout(Stdio::from(file))
        .stderr(Stdio::inherit());
    let res = cleanup::run(&mut cmd).and_then(|st| {
        if st.success() {
            Ok(())
        } else {
            bail!("age --encrypt failed ({st})")
        }
    });
    if res.is_err() {
        let _ = std::fs::remove_file(out);
    }
    res
}

/// Creates a new file with mode 0600, failing if anything exists at `path`.
pub fn create_new_private(path: &Path) -> Result<File> {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .with_context(|| format!("creating {} (refusing to overwrite)", path.display()))
}

/// What we can learn from an age identity file without secrets leaving it.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct IdentityInfo {
    /// Recipients from `# recipient:` / `# public key:` comments.
    pub recipients: Vec<String>,
    /// The SLIP-0017 identity string from a `# SLIP-0017:` comment.
    pub slip17: Option<String>,
    pub trezor_identities: usize,
    pub x25519_identities: usize,
}

impl IdentityInfo {
    pub fn parse(text: &str) -> IdentityInfo {
        let mut info = IdentityInfo::default();
        for line in text.lines().map(str::trim) {
            if let Some(c) = line.strip_prefix('#') {
                let c = c.trim();
                if let Some(s) = c.strip_prefix("SLIP-0017:") {
                    info.slip17 = Some(s.trim().to_string());
                } else if let Some((_, r)) = c
                    .split_once("recipient:")
                    .or_else(|| c.split_once("public key:"))
                {
                    let r = r.trim();
                    if r.starts_with("age1") && !info.recipients.iter().any(|x| x == r) {
                        info.recipients.push(r.to_string());
                    }
                }
            } else if line.starts_with("AGE-PLUGIN-TREZOR-1") {
                info.trezor_identities += 1;
            } else if line.starts_with("AGE-SECRET-KEY-1") {
                info.x25519_identities += 1;
            }
        }
        info
    }

    pub fn load(path: &Path) -> Result<IdentityInfo> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading identity file {}", path.display()))?;
        Ok(IdentityInfo::parse(&text))
    }

    /// The single recipient this identity decrypts for.
    pub fn recipient(&self, path: &Path) -> Result<&str> {
        match self.recipients.as_slice() {
            [r] => Ok(r),
            [] => bail!(
                "identity file {} has no `# recipient: age1...` comment; \
                 recreate it with `vcage init-identity`",
                path.display()
            ),
            _ => bail!(
                "identity file {} lists several recipients; use a file with exactly one identity",
                path.display()
            ),
        }
    }
}

fn identity_needs_trezor_plugin(path: &Path) -> Result<bool> {
    Ok(IdentityInfo::load(path)?.trezor_identities > 0)
}

/// Runs `age-plugin-trezor -i <identity string>` and returns its output after
/// checking that it really contains an identity. The plugin swallows device
/// errors and still exits 0, so the exit status alone means nothing.
pub fn trezor_identity(identity_string: &str) -> Result<(String, IdentityInfo)> {
    let plugin = bins::find(Tool::AgePluginTrezor)?;
    let mut cmd = Command::new(&plugin);
    cmd.arg("-i")
        .arg(identity_string)
        .stdin(Stdio::inherit())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit());
    let (status, stdout) = cleanup::run_capture(&mut cmd)?;
    if !status.success() {
        bail!("age-plugin-trezor failed ({status})");
    }
    let text = String::from_utf8(stdout).context("age-plugin-trezor output is not UTF-8")?;
    let info = IdentityInfo::parse(&text);
    if info.trezor_identities != 1 || info.recipients.len() != 1 {
        bail!(
            "age-plugin-trezor did not produce an identity. Is the Trezor connected and \
             unlocked (PIN entered), and is no other program (e.g. Trezor Suite) using it? \
             Set TREZOR_AGE_PLUGIN_LOG=/path/to/log for details"
        );
    }
    if info.slip17.as_deref() != Some(identity_string) {
        bail!("age-plugin-trezor output does not match the requested identity string");
    }
    Ok((text, info))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_trezor_identity() {
        let text = "# recipient: age1abc\n# SLIP-0017: <me@example.com>\nAGE-PLUGIN-TREZOR-1XYZ\n";
        let info = IdentityInfo::parse(text);
        assert_eq!(info.recipients, vec!["age1abc"]);
        assert_eq!(info.slip17.as_deref(), Some("<me@example.com>"));
        assert_eq!(info.trezor_identities, 1);
        assert_eq!(info.recipient(Path::new("x")).unwrap(), "age1abc");
    }

    #[test]
    fn parses_age_keygen_identity() {
        let text = "# created: 2026-01-01T00:00:00Z\n# public key: age1def\nAGE-SECRET-KEY-1QQQ\n";
        let info = IdentityInfo::parse(text);
        assert_eq!(info.recipients, vec!["age1def"]);
        assert_eq!(info.x25519_identities, 1);
        assert_eq!(info.slip17, None);
    }

    #[test]
    fn recipient_requires_exactly_one() {
        assert!(IdentityInfo::parse("AGE-SECRET-KEY-1Q\n")
            .recipient(Path::new("x"))
            .is_err());
        assert!(
            IdentityInfo::parse("# public key: age1a\n# public key: age1b\n")
                .recipient(Path::new("x"))
                .is_err()
        );
    }
}
