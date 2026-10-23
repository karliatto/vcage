//! Thin wrapper around the `veracrypt` command line.
//!
//! All interactive invocations inherit stdin/stdout/stderr so that VeraCrypt
//! itself prompts for the password; vcage never sees it.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::{bail, Context, Result};

use crate::bins::{self, Tool};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mounted {
    pub slot: u32,
    pub volume: PathBuf,
    pub device: String,
    /// `None` when VeraCrypt reports `-` (mounted without a filesystem).
    pub mountpoint: Option<PathBuf>,
}

/// Parses the output of `veracrypt --text -l`, whose lines look like
/// `1: /path/to/volume /dev/mapper/veracrypt1 /mount/point`.
/// Volume and mountpoint paths may contain spaces.
pub fn parse_list(output: &str) -> Result<Vec<Mounted>> {
    if is_no_volumes(output) {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    for line in output.lines().map(str::trim).filter(|l| !l.is_empty()) {
        let Some((slot, rest)) = line.split_once(": ") else {
            continue;
        };
        let Ok(slot) = slot.parse::<u32>() else {
            continue;
        };
        let Some(dev_at) = rest.find(" /dev/") else {
            bail!("unexpected `veracrypt -l` line: {line:?}");
        };
        let volume = &rest[..dev_at];
        let after = &rest[dev_at + 1..];
        let (device, mountpoint) = match after.split_once(' ') {
            Some((d, m)) => (d, m.trim()),
            None => (after, "-"),
        };
        out.push(Mounted {
            slot,
            volume: PathBuf::from(volume),
            device: device.to_string(),
            mountpoint: (mountpoint != "-" && !mountpoint.is_empty())
                .then(|| PathBuf::from(mountpoint)),
        });
    }
    Ok(out)
}

fn is_no_volumes(output: &str) -> bool {
    output.to_ascii_lowercase().contains("no volumes mounted")
}

/// Lists mounted VeraCrypt volumes. "No volumes mounted" is an empty list.
pub fn list() -> Result<Vec<Mounted>> {
    let vc = bins::find(Tool::VeraCrypt)?;
    let out = Command::new(&vc)
        .args(["--text", "--non-interactive", "-l"])
        .stdin(Stdio::null())
        .output()
        .with_context(|| format!("running {}", vc.display()))?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    if out.status.success() {
        return parse_list(&stdout);
    }
    if is_no_volumes(&stdout) || is_no_volumes(&stderr) {
        return Ok(Vec::new());
    }
    bail!(
        "`veracrypt --text -l` failed ({}): {}",
        out.status,
        stderr.trim()
    )
}

/// Whether `volume` appears in `mounted`, comparing canonical paths when possible.
pub fn find_mounted<'a>(mounted: &'a [Mounted], volume: &Path) -> Option<&'a Mounted> {
    let canon = |p: &Path| p.canonicalize().unwrap_or_else(|_| p.to_path_buf());
    let want = canon(volume);
    mounted.iter().find(|m| canon(&m.volume) == want)
}

fn run_interactive(mut cmd: Command, what: &str) -> Result<()> {
    let status = cmd
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .with_context(|| format!("starting {what}"))?;
    if !status.success() {
        bail!("{what} failed ({status})");
    }
    Ok(())
}

/// Builds `sudo <absolute veracrypt path> --text ...`. The absolute path is
/// used because sudo's `secure_path` usually does not include Nix profiles.
fn sudo_veracrypt() -> Result<Command> {
    let sudo = bins::find(Tool::Sudo)?;
    let vc = bins::find(Tool::VeraCrypt)?;
    let mut cmd = Command::new(sudo);
    cmd.arg("--").arg(vc).arg("--text");
    Ok(cmd)
}

pub fn create(volume: &Path, size: &str, keyfile: &Path) -> Result<()> {
    let vc = bins::find(Tool::VeraCrypt)?;
    let mut cmd = Command::new(vc);
    cmd.arg("--text")
        .arg("--create")
        .arg(volume)
        .arg(format!("--size={size}"))
        .args([
            "--volume-type=normal",
            "--encryption=AES",
            "--hash=SHA-512",
            "--filesystem=FAT",
            "--pim=0",
        ])
        .arg(keyfiles_arg(keyfile)?)
        .arg("--random-source=/dev/urandom");
    run_interactive(cmd, "veracrypt --create")
}

pub fn mount(volume: &Path, mountpoint: &Path, keyfile: &Path) -> Result<()> {
    let mut cmd = sudo_veracrypt()?;
    cmd.arg(keyfiles_arg(keyfile)?)
        .args(["--pim=0", "--protect-hidden=no"])
        .arg(volume)
        .arg(mountpoint);
    run_interactive(cmd, "sudo veracrypt (mount)")
}

pub fn dismount(volume: &Path) -> Result<()> {
    let mut cmd = sudo_veracrypt()?;
    cmd.arg("-d").arg(volume);
    run_interactive(cmd, "sudo veracrypt -d")
}

/// `--keyfiles=` takes a comma-separated list, so a path with a comma would
/// be misread. Our keyfile names never contain one, but check anyway.
fn keyfiles_arg(keyfile: &Path) -> Result<std::ffi::OsString> {
    let s = keyfile.to_str().context("keyfile path is not UTF-8")?;
    if s.contains(',') {
        bail!("keyfile path must not contain ','");
    }
    Ok(format!("--keyfiles={s}").into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_mounted_volumes() {
        let out = "1: /home/a/Vaults/personal.vc /dev/mapper/veracrypt1 /home/a/vc/personal\n\
                   2: /home/a/My Vaults/work.vc /dev/mapper/veracrypt2 /media/my mount\n\
                   3: /dev/sdb1 /dev/mapper/veracrypt3 -\n";
        let v = parse_list(out).unwrap();
        assert_eq!(v.len(), 3);
        assert_eq!(
            v[0],
            Mounted {
                slot: 1,
                volume: "/home/a/Vaults/personal.vc".into(),
                device: "/dev/mapper/veracrypt1".into(),
                mountpoint: Some("/home/a/vc/personal".into()),
            }
        );
        assert_eq!(v[1].volume, PathBuf::from("/home/a/My Vaults/work.vc"));
        assert_eq!(v[1].mountpoint, Some(PathBuf::from("/media/my mount")));
        assert_eq!(v[2].volume, PathBuf::from("/dev/sdb1"));
        assert_eq!(v[2].device, "/dev/mapper/veracrypt3");
        assert_eq!(v[2].mountpoint, None);
    }

    #[test]
    fn no_volumes_is_empty() {
        assert!(parse_list("Error: No volumes mounted.\n")
            .unwrap()
            .is_empty());
        assert!(parse_list("").unwrap().is_empty());
    }

    #[test]
    fn skips_noise_and_rejects_garbage() {
        let out = "Warning: something\n\n1: /v.vc /dev/loop0 /mnt/x\n";
        assert_eq!(parse_list(out).unwrap().len(), 1);
        assert!(parse_list("1: /v.vc nodevice\n").is_err());
    }

    #[test]
    fn finds_by_path() {
        let v = parse_list("1: /a/b.vc /dev/mapper/veracrypt1 /m\n").unwrap();
        assert!(find_mounted(&v, Path::new("/a/b.vc")).is_some());
        assert!(find_mounted(&v, Path::new("/a/c.vc")).is_none());
    }

    #[test]
    fn keyfiles_arg_rejects_commas() {
        assert!(keyfiles_arg(Path::new("/dev/shm/a,b")).is_err());
        assert_eq!(
            keyfiles_arg(Path::new("/dev/shm/k")).unwrap(),
            std::ffi::OsString::from("--keyfiles=/dev/shm/k")
        );
    }
}
