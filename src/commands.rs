//! Implementations of the `vcage` subcommands.

use std::fs;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};

use crate::age::{self, AgeCliDecryptor, IdentityInfo, KeyfileDecryptor};
use crate::bins::{self, Tool};
use crate::cloud;
use crate::config::{absolute, Config, Vault, VaultConfig, VaultOverrides};
use crate::keyfile::{self, SecretFile};
use crate::paths;
use crate::trezor;
use crate::veracrypt;

// ---------------------------------------------------------------- init-identity

pub fn init_identity(name: &str, identity_string: &str) -> Result<()> {
    paths::validate_name(name, "identity")?;
    if identity_string.trim().is_empty() || identity_string.chars().any(char::is_control) {
        bail!("the identity string must be non-empty and on a single line");
    }
    let dir = paths::identities_dir()?;
    let path = dir.join(format!("{name}.txt"));
    if fs::symlink_metadata(&path).is_ok() {
        bail!("{} already exists; refusing to overwrite", path.display());
    }
    eprintln!("Deriving the age identity on the Trezor (unlock it if asked)...");
    let (text, info) = age::trezor_identity(identity_string)?;
    mkdir_private(&dir)?;
    let mut f = age::create_new_private(&path)?;
    std::io::Write::write_all(&mut f, text.as_bytes())
        .and_then(|_| f.sync_all())
        .with_context(|| format!("writing {}", path.display()))?;

    eprintln!("Saved identity to {}", path.display());
    eprintln!("Recipient:");
    println!("{}", info.recipients[0]);
    eprintln!();
    eprintln!("IMPORTANT: write down the identity string EXACTLY as typed (case, spaces and");
    eprintln!("punctuation all matter):");
    eprintln!();
    eprintln!("    {identity_string}");
    eprintln!();
    eprintln!("This string plus your Trezor seed (and passphrase, if you use one) is the only");
    eprintln!("way to recreate this identity if the file is lost.");
    Ok(())
}

// ---------------------------------------------------------------------- create

pub struct CreateArgs {
    pub vault: String,
    pub size: String,
    pub identity: String,
    pub extra_recipients: Vec<String>,
    pub volume: Option<String>,
    pub keyfile: Option<String>,
    pub mountpoint: Option<String>,
}

pub fn create(a: CreateArgs) -> Result<()> {
    paths::validate_name(&a.vault, "vault")?;
    validate_size(&a.size)?;
    for r in &a.extra_recipients {
        validate_recipient(r)?;
    }
    let cfg = Config::load()?;
    if cfg.vaults.contains_key(&a.vault) {
        bail!("vault {:?} already exists in the config", a.vault);
    }
    let pick = |flag: &Option<String>, default: String| -> Result<PathBuf> {
        absolute(paths::expand_tilde(flag.as_deref().unwrap_or(&default))?)
    };
    let v = Vault {
        name: a.vault.clone(),
        volume: pick(&a.volume, format!("~/Vaults/{}.vc", a.vault))?,
        keyfile: pick(&a.keyfile, format!("~/Vaults/{}.key.age", a.vault))?,
        identity: absolute(paths::resolve_identity(&a.identity)?)?,
        mountpoint: pick(&a.mountpoint, format!("~/vc/{}", a.vault))?,
    };

    // Preflight: everything that can fail cheaply fails before any key exists.
    bins::find(Tool::Age)?;
    bins::find(Tool::VeraCrypt)?;
    require_file(&v.identity, "identity file")?;
    check_not_writable_by_others(&v.identity)?;
    let info = IdentityInfo::load(&v.identity)?;
    if info.trezor_identities > 0 {
        bins::find(Tool::AgePluginTrezor)?;
    }
    let mut recipients = vec![info.recipient(&v.identity)?.to_string()];
    for r in &a.extra_recipients {
        if !recipients.contains(r) {
            recipients.push(r.clone());
        }
    }
    if v.volume == v.keyfile {
        bail!("the volume and the encrypted keyfile must be different files");
    }
    for (p, what) in [(&v.volume, "volume"), (&v.keyfile, "encrypted keyfile")] {
        if fs::symlink_metadata(p).is_ok() {
            bail!(
                "{what} {} already exists; refusing to overwrite",
                p.display()
            );
        }
    }
    if let Ok(m) = fs::symlink_metadata(&v.mountpoint) {
        if !m.is_dir() {
            bail!(
                "mountpoint {} exists and is not a directory",
                v.mountpoint.display()
            );
        }
    }
    warn_cloud_sync(&cfg, &v.mountpoint)?;
    for p in [&v.volume, &v.keyfile] {
        if let Some(parent) = p.parent() {
            mkdir_private(parent)?;
        }
    }

    // 1. Random keyfile in RAM.
    let (secret, key) = SecretFile::generate()?;

    // 2. Encrypt it.
    eprintln!(
        "Encrypting the keyfile to {} recipient(s) -> {}",
        recipients.len(),
        v.keyfile.display()
    );
    age::encrypt(&recipients, secret.path(), &v.keyfile)?;
    let mut encrypted = RemoveOnDrop(Some(v.keyfile.clone()));

    // 3. Verify before creating anything that depends on it.
    eprintln!("Verifying: decrypting it again (confirm on your Trezor if asked)...");
    let decrypted = AgeCliDecryptor {
        identity: v.identity.clone(),
    }
    .decrypt(&v.keyfile)
    .context("verification decrypt failed; nothing was created")?;
    if !keyfile::ct_eq(&decrypted, &key[..]) {
        bail!("verification failed: the decrypted keyfile does not match; nothing was created");
    }
    drop(decrypted);
    drop(key);
    eprintln!("Verified. Creating the VeraCrypt volume; VeraCrypt will ask for a password.");

    // 4. Create the volume.
    if let Err(e) = veracrypt::create(&v.volume, &a.size, secret.path()) {
        if v.volume.exists() {
            eprintln!(
                "vcage: a partial volume may have been left at {}; delete it before retrying",
                v.volume.display()
            );
        }
        return Err(e);
    }
    encrypted.0 = None; // keep the encrypted keyfile from now on

    // 5. Wipe the plaintext keyfile now rather than at the end of scope.
    drop(secret);

    mkdir_private(&v.mountpoint)?;
    let entry = VaultConfig {
        volume: paths::contract_tilde(&v.volume),
        keyfile: paths::contract_tilde(&v.keyfile),
        identity: paths::contract_tilde(&v.identity),
        mountpoint: paths::contract_tilde(&v.mountpoint),
    };
    let mut cfg = Config::load()?;
    cfg.vaults.insert(v.name.clone(), entry.clone());
    if let Err(e) = cfg.save() {
        eprintln!(
            "vcage: could not save the config ({e:#}); add this to it by hand:\n\n[vaults.{}]\n{}",
            v.name,
            toml::to_string(&entry).unwrap_or_default()
        );
        return Err(e);
    }

    eprintln!();
    eprintln!(
        "Created vault {:?}. Mount it with: vcage mount {}",
        v.name, v.name
    );
    eprintln!();
    eprintln!("Back up NOW (without these the volume cannot be opened):");
    eprintln!("  - the encrypted keyfile {}", v.keyfile.display());
    eprintln!("  - your Trezor recovery seed (and passphrase, if any)");
    eprintln!("  - the exact identity string (see the `# SLIP-0017:` line in");
    eprintln!("    {})", v.identity.display());
    if recipients.len() > 1 {
        eprintln!("  - the secret key(s) for the extra recipient(s)");
    }
    eprintln!("  - the VeraCrypt password you just chose");
    Ok(())
}

/// Removes a file on drop unless disarmed (set to `None`).
struct RemoveOnDrop(Option<PathBuf>);

impl Drop for RemoveOnDrop {
    fn drop(&mut self) {
        if let Some(p) = self.0.take() {
            let _ = fs::remove_file(p);
        }
    }
}

/// VeraCrypt accepts a byte count or a number with K/M/G/T (optionally KiB...).
pub fn validate_size(size: &str) -> Result<()> {
    let digits = size.chars().take_while(char::is_ascii_digit).count();
    let (num, unit) = size.split_at(digits);
    let unit_ok = matches!(
        unit,
        "" | "K" | "M" | "G" | "T" | "KiB" | "MiB" | "GiB" | "TiB"
    );
    if num.is_empty() || !unit_ok || num.trim_start_matches('0').is_empty() {
        bail!("invalid size {size:?}; use e.g. 500M, 2G or 2GiB");
    }
    Ok(())
}

pub fn validate_recipient(r: &str) -> Result<()> {
    let ok = r.starts_with("age1")
        && r.len() > 10
        && r[4..]
            .chars()
            .all(|c| "qpzry9x8gf2tvdw0s3jn54khce6mua7l".contains(c));
    if !ok {
        bail!("invalid recipient {r:?}; expected an age1... public key");
    }
    Ok(())
}

// ----------------------------------------------------------------------- mount

pub fn mount(name: &str, ov: &VaultOverrides) -> Result<()> {
    let cfg = Config::load()?;
    let v = cfg.vault(name, ov)?;
    require_file(&v.volume, "volume")?;
    require_file(&v.keyfile, "encrypted keyfile")?;
    require_file(&v.identity, "identity file")?;
    check_not_writable_by_others(&v.identity)?;
    check_not_writable_by_others(&v.keyfile)?;
    bins::find(Tool::Sudo)?;

    let mounted = veracrypt::list()?;
    if let Some(m) = veracrypt::find_mounted(&mounted, &v.volume) {
        bail!(
            "vault {:?} is already mounted (slot {}{})",
            v.name,
            m.slot,
            m.mountpoint
                .as_ref()
                .map(|p| format!(", at {}", p.display()))
                .unwrap_or_default()
        );
    }
    match fs::symlink_metadata(&v.mountpoint) {
        Ok(m) if !m.is_dir() => {
            bail!("mountpoint {} is not a directory", v.mountpoint.display())
        }
        Ok(_) => {}
        Err(_) => mkdir_private(&v.mountpoint)?,
    }
    let canon_mp = v.mountpoint.canonicalize()?;
    if mounted.iter().any(|m| {
        m.mountpoint
            .as_ref()
            .is_some_and(|p| p.canonicalize().unwrap_or_else(|_| p.clone()) == canon_mp)
    }) {
        bail!(
            "another VeraCrypt volume is mounted at {}",
            v.mountpoint.display()
        );
    }
    warn_cloud_sync(&cfg, &v.mountpoint)?;

    eprintln!("Decrypting the keyfile (confirm on your Trezor)...");
    let plain = AgeCliDecryptor {
        identity: v.identity.clone(),
    }
    .decrypt(&v.keyfile)?;
    let secret = SecretFile::create()?;
    secret.write(&plain)?;
    drop(plain);

    veracrypt::mount(&v.volume, &v.mountpoint, secret.path())?;
    drop(secret);
    eprintln!("Mounted {:?} at {}", v.name, v.mountpoint.display());
    Ok(())
}

// --------------------------------------------------------------------- unmount

pub fn unmount(name: Option<&str>, all: bool) -> Result<()> {
    let cfg = Config::load()?;
    let mounted = veracrypt::list()?;
    let targets: Vec<Vault> = if all {
        cfg.all_vaults()?
            .into_iter()
            .filter(|v| veracrypt::find_mounted(&mounted, &v.volume).is_some())
            .collect()
    } else {
        let name = name.context("give a vault name or --all")?;
        let v = cfg.vault(name, &VaultOverrides::default())?;
        if veracrypt::find_mounted(&mounted, &v.volume).is_none() {
            bail!("vault {name:?} is not mounted");
        }
        vec![v]
    };
    if targets.is_empty() {
        eprintln!("No configured vaults are mounted.");
        return Ok(());
    }
    let mut failed = 0;
    for v in &targets {
        match veracrypt::dismount(&v.volume) {
            Ok(()) => eprintln!("Unmounted {:?}", v.name),
            Err(e) => {
                failed += 1;
                eprintln!("vcage: could not unmount {:?}: {e:#}", v.name);
            }
        }
    }
    if failed > 0 {
        bail!("{failed} vault(s) could not be unmounted");
    }
    Ok(())
}

// ------------------------------------------------------------------------ list

pub fn list() -> Result<()> {
    let cfg = Config::load()?;
    let vaults = cfg.all_vaults()?;
    let mounted = veracrypt::list()?;
    if vaults.is_empty() {
        eprintln!("No vaults configured. Create one with `vcage create`.");
    } else {
        let w = vaults
            .iter()
            .map(|v| v.name.len())
            .max()
            .unwrap_or(4)
            .max(4);
        println!(
            "{:<w$}  {:<9}  {:<30}  VOLUME",
            "NAME", "STATUS", "MOUNTPOINT"
        );
        for v in &vaults {
            let m = veracrypt::find_mounted(&mounted, &v.volume);
            let status = if m.is_some() { "mounted" } else { "unmounted" };
            let mp = m
                .and_then(|m| m.mountpoint.clone())
                .unwrap_or_else(|| v.mountpoint.clone());
            println!(
                "{:<w$}  {:<9}  {:<30}  {}",
                v.name,
                status,
                paths::contract_tilde(&mp),
                paths::contract_tilde(&v.volume)
            );
        }
    }
    let other = mounted
        .iter()
        .filter(|m| {
            !vaults
                .iter()
                .any(|v| veracrypt::find_mounted(std::slice::from_ref(m), &v.volume).is_some())
        })
        .count();
    if other > 0 {
        eprintln!("({other} other VeraCrypt volume(s) mounted, not managed by vcage)");
    }
    Ok(())
}

// ----------------------------------------------------------------------- check

#[derive(Default)]
struct Report {
    failed: usize,
    warned: usize,
}

impl Report {
    fn ok(&mut self, msg: impl AsRef<str>) {
        println!("  ok    {}", msg.as_ref());
    }
    fn warn(&mut self, msg: impl AsRef<str>) {
        self.warned += 1;
        println!("  WARN  {}", msg.as_ref());
    }
    fn fail(&mut self, msg: impl AsRef<str>) {
        self.failed += 1;
        println!("  FAIL  {}", msg.as_ref());
    }
    fn check(&mut self, r: Result<String>) {
        match r {
            Ok(m) => self.ok(m),
            Err(e) => self.fail(format!("{e:#}")),
        }
    }
}

pub fn check(use_device: bool) -> Result<()> {
    let mut r = Report::default();

    println!("Programs:");
    for t in [
        Tool::Age,
        Tool::AgePluginTrezor,
        Tool::VeraCrypt,
        Tool::Sudo,
    ] {
        r.check(
            bins::find(t)
                .map(|p| format!("{} ({})", t.binary(), p.display()))
                .map_err(Into::into),
        );
    }

    println!("RAM directory:");
    r.check(
        keyfile::is_ram_fs(&Path::new(keyfile::SHM_DIR).canonicalize()?)
            .map_err(anyhow::Error::from)
            .and_then(|tmpfs| {
                if tmpfs {
                    Ok(format!("{} is tmpfs", keyfile::SHM_DIR))
                } else {
                    bail!("{} is not tmpfs", keyfile::SHM_DIR)
                }
            }),
    );

    println!("Config:");
    let cfg_path = paths::config_file()?;
    let cfg = match Config::load_from(&cfg_path) {
        Ok(c) => {
            if cfg_path.exists() {
                check_perms(&mut r, &cfg_path, "config file");
            } else {
                r.warn(format!("{} does not exist yet", cfg_path.display()));
            }
            c
        }
        Err(e) => {
            r.fail(format!("{e:#}"));
            Config::default()
        }
    };
    let id_dir = paths::identities_dir()?;
    if id_dir.exists() {
        check_perms(&mut r, &id_dir, "identities directory");
    }

    let mounted = match veracrypt::list() {
        Ok(m) => Some(m),
        Err(e) => {
            r.fail(format!("listing mounted volumes: {e:#}"));
            None
        }
    };

    let mut identities: Vec<PathBuf> = Vec::new();
    for name in cfg.vaults.keys() {
        println!("Vault {name}:");
        let v = match cfg.vault(name, &VaultOverrides::default()) {
            Ok(v) => v,
            Err(e) => {
                r.fail(format!("{e:#}"));
                continue;
            }
        };
        for (p, what) in [
            (&v.volume, "volume"),
            (&v.keyfile, "encrypted keyfile"),
            (&v.identity, "identity file"),
        ] {
            match require_file(p, what) {
                Ok(()) => check_perms(&mut r, p, what),
                Err(e) => r.fail(format!("{e:#}")),
            }
        }
        if v.identity.exists() && !identities.contains(&v.identity) {
            identities.push(v.identity.clone());
        }
        match fs::metadata(&v.mountpoint) {
            Ok(m) if m.is_dir() => r.ok(format!("mountpoint {}", v.mountpoint.display())),
            Ok(_) => r.fail(format!(
                "mountpoint {} is not a directory",
                v.mountpoint.display()
            )),
            Err(_) => r.warn(format!(
                "mountpoint {} does not exist (created on mount)",
                v.mountpoint.display()
            )),
        }
        if let Some(service) = cloud_sync_service(&cfg, &v.mountpoint)? {
            r.warn(format!("mountpoint looks like it is inside {service}"));
        }
        if let Some(m) = &mounted {
            match veracrypt::find_mounted(m, &v.volume) {
                Some(_) => r.ok("currently mounted"),
                None => r.ok("not mounted"),
            }
        }
    }
    if cfg.vaults.is_empty() {
        if let Ok(rd) = fs::read_dir(&id_dir) {
            identities.extend(
                rd.flatten()
                    .map(|e| e.path())
                    .filter(|p| p.extension().is_some_and(|x| x == "txt")),
            );
        }
    }

    println!("Trezor:");
    let mut trezor_ids = Vec::new();
    for id in &identities {
        match IdentityInfo::load(id) {
            Ok(info) if info.trezor_identities > 0 => trezor_ids.push((id.clone(), info)),
            Ok(_) => r.ok(format!("{} is not a Trezor identity", id.display())),
            Err(e) => r.fail(format!("{e:#}")),
        }
    }
    let usb = trezor::detect_usb();
    if usb.is_empty() {
        r.fail("no Trezor found on USB");
    } else if usb.iter().all(|d| d.bootloader) {
        r.fail("Trezor is in bootloader mode; restart it normally");
    } else {
        r.ok("Trezor connected (USB)");
        if !use_device {
            r.warn("skipped deriving identities on the device (--no-device)");
        }
        for (id, info) in trezor_ids.iter().filter(|_| use_device) {
            r.check(check_trezor_identity(id, info));
        }
    }

    println!();
    if r.failed > 0 {
        bail!("{} check(s) failed, {} warning(s)", r.failed, r.warned);
    }
    println!("All checks passed ({} warning(s)).", r.warned);
    Ok(())
}

/// Re-derives the identity on the device and compares the recipient, which
/// proves the Trezor is reachable, unlocked and holds the right seed.
fn check_trezor_identity(path: &Path, info: &IdentityInfo) -> Result<String> {
    let want = info.recipient(path)?;
    let slip17 = info.slip17.as_deref().with_context(|| {
        format!(
            "{} has no `# SLIP-0017:` line; cannot re-derive",
            path.display()
        )
    })?;
    eprintln!("Deriving {slip17:?} on the Trezor...");
    let (_, derived) = age::trezor_identity(slip17)?;
    if derived.recipients.first().map(String::as_str) != Some(want) {
        bail!(
            "the Trezor derives a different recipient for {} (wrong seed or passphrase?)",
            path.display()
        );
    }
    Ok(format!(
        "Trezor derives the recipient of {}",
        path.display()
    ))
}

// --------------------------------------------------------------------- helpers

fn require_file(p: &Path, what: &str) -> Result<()> {
    match fs::metadata(p) {
        Ok(m) if m.is_file() => Ok(()),
        Ok(_) => bail!("{what} {} is not a regular file", p.display()),
        Err(_) => bail!("{what} {} does not exist", p.display()),
    }
}

/// Files that decide what gets decrypted must not be writable by others.
fn check_not_writable_by_others(p: &Path) -> Result<()> {
    let mode = fs::metadata(p)?.permissions().mode();
    if mode & 0o022 != 0 {
        bail!(
            "{} is writable by group or others (mode {:o}); run `chmod 600` on it",
            p.display(),
            mode & 0o777
        );
    }
    Ok(())
}

fn check_perms(r: &mut Report, p: &Path, what: &str) {
    let Ok(m) = fs::metadata(p) else { return };
    let mode = m.permissions().mode() & 0o777;
    let want = if m.is_dir() { 0o700 } else { 0o600 };
    if mode & 0o022 != 0 {
        r.fail(format!(
            "{what} {} is writable by group/others (mode {mode:o}, want {want:o})",
            p.display()
        ));
    } else if mode & 0o044 != 0 {
        r.warn(format!(
            "{what} {} is readable by group/others (mode {mode:o}, want {want:o})",
            p.display()
        ));
    } else {
        r.ok(format!("{what} {}", p.display()));
    }
}

fn cloud_sync_service(cfg: &Config, mountpoint: &Path) -> Result<Option<String>> {
    if !cfg.settings.warn_cloud_sync {
        return Ok(None);
    }
    let extra = cfg
        .settings
        .cloud_sync_dirs
        .iter()
        .map(|d| paths::expand_tilde(d))
        .collect::<Result<Vec<_>>>()?;
    Ok(cloud::detect(mountpoint, &paths::home_dir()?, &extra))
}

fn warn_cloud_sync(cfg: &Config, mountpoint: &Path) -> Result<()> {
    if let Some(service) = cloud_sync_service(cfg, mountpoint)? {
        eprintln!(
            "vcage: WARNING: mountpoint {} looks like it is inside a cloud-sync folder ({service}).\n\
             Decrypted files there may be uploaded. Set `warn_cloud_sync = false` under\n\
             [settings] in the config to silence this warning.",
            mountpoint.display()
        );
    }
    Ok(())
}

fn mkdir_private(dir: &Path) -> Result<()> {
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
        .with_context(|| format!("creating {}", dir.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sizes() {
        for ok in ["500M", "2G", "2GiB", "1048576", "10K", "1T"] {
            assert!(validate_size(ok).is_ok(), "{ok}");
        }
        for bad in [
            "", "M", "0", "00M", "1.5G", "2g", "2 G", "-1G", "2GB", "1;rm",
        ] {
            assert!(validate_size(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn recipients() {
        assert!(validate_recipient(
            "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p"
        )
        .is_ok());
        for bad in [
            "age1",
            "AGE1QL3Z7HJY54PW3",
            "ssh-ed25519 AAAA",
            "age1bad!chars",
        ] {
            assert!(validate_recipient(bad).is_err(), "{bad}");
        }
    }
}
