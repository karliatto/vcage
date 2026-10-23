//! The plaintext keyfile: a RAII guard over a file in `/dev/shm`.
//!
//! The file is created with `O_CREAT | O_EXCL | O_NOFOLLOW`, mode 0600, under
//! a unique name, and registered with [`crate::cleanup`] before anything is
//! written to it. Dropping the guard (normally or while unwinding from a
//! panic) overwrites, truncates and unlinks it; a signal does the same via
//! the cleanup thread.

use std::fs::{File, OpenOptions};
use std::io::Read;
use std::os::unix::fs::{FileExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use thiserror::Error;
use zeroize::Zeroizing;

use crate::cleanup;

/// Where plaintext keyfiles live. Must be RAM-backed (tmpfs).
pub const SHM_DIR: &str = "/dev/shm";

/// Length of a generated keyfile.
pub const KEYFILE_LEN: usize = 64;

/// Upper bound for a decrypted keyfile (VeraCrypt only uses the first 1 MiB).
pub const MAX_KEYFILE_LEN: usize = 1024 * 1024;

const TMPFS_MAGIC: i64 = 0x0102_1994;
const RAMFS_MAGIC: i64 = 0x8584_58f6;

#[derive(Debug, Error)]
pub enum KeyfileError {
    #[error("{dir} is not a RAM-backed (tmpfs) directory; refusing to write key material to it")]
    NotTmpfs { dir: String },
    #[error("{0} is missing or not a directory")]
    BadDir(String),
    #[error("could not create a keyfile in {dir}: {source}")]
    Create {
        dir: String,
        #[source]
        source: std::io::Error,
    },
    #[error("the new keyfile has unexpected ownership or permissions")]
    BadPermissions,
    #[error("I/O error on the plaintext keyfile: {0}")]
    Io(#[from] std::io::Error),
    #[error("the OS random number generator failed: {0}")]
    Random(String),
    #[error("keyfile is empty or larger than {MAX_KEYFILE_LEN} bytes")]
    BadLength,
}

/// A plaintext keyfile that is wiped and unlinked when dropped.
pub struct SecretFile {
    path: PathBuf,
    file: File,
    id: u64,
}

impl SecretFile {
    /// Creates an empty secret file in [`SHM_DIR`].
    pub fn create() -> Result<SecretFile, KeyfileError> {
        let dir = shm_dir()?;
        let ((path, file), id) = cleanup::register_file(|| {
            let (path, file) = open_unique(&dir)?;
            let reg = file.try_clone()?;
            Ok::<_, KeyfileError>(((path.clone(), file), path, reg))
        })?;
        Ok(SecretFile { path, file, id })
    }

    /// Creates a secret file holding [`KEYFILE_LEN`] fresh random bytes.
    pub fn generate() -> Result<(SecretFile, Zeroizing<[u8; KEYFILE_LEN]>), KeyfileError> {
        let mut key = Zeroizing::new([0u8; KEYFILE_LEN]);
        getrandom::fill(&mut key[..]).map_err(|e| KeyfileError::Random(e.to_string()))?;
        let f = SecretFile::create()?;
        f.write(&key[..])?;
        Ok((f, key))
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Replaces the contents with `data` and flushes it.
    pub fn write(&self, data: &[u8]) -> Result<(), KeyfileError> {
        if data.is_empty() || data.len() > MAX_KEYFILE_LEN {
            return Err(KeyfileError::BadLength);
        }
        self.file.set_len(0)?;
        self.file.write_all_at(data, 0)?;
        self.file.sync_data()?;
        Ok(())
    }

    /// Reads the contents into a zeroizing buffer.
    pub fn read(&self) -> Result<Zeroizing<Vec<u8>>, KeyfileError> {
        let len = self.file.metadata()?.len() as usize;
        if len == 0 || len > MAX_KEYFILE_LEN {
            return Err(KeyfileError::BadLength);
        }
        let mut buf = Zeroizing::new(vec![0u8; len]);
        self.file.read_exact_at(&mut buf, 0)?;
        Ok(buf)
    }
}

impl Drop for SecretFile {
    fn drop(&mut self) {
        if let Err(e) = cleanup::wipe_registered(self.id) {
            eprintln!(
                "vcage: FAILED to wipe plaintext keyfile {}: {e}; delete it manually",
                self.path.display()
            );
        }
    }
}

/// Resolves `/dev/shm` (it is a symlink on some distributions) and checks
/// that it is a RAM-backed directory.
fn shm_dir() -> Result<PathBuf, KeyfileError> {
    let dir = Path::new(SHM_DIR)
        .canonicalize()
        .map_err(|_| KeyfileError::BadDir(SHM_DIR.into()))?;
    if !dir.is_dir() {
        return Err(KeyfileError::BadDir(dir.display().to_string()));
    }
    if !is_ram_fs(&dir)? {
        return Err(KeyfileError::NotTmpfs {
            dir: dir.display().to_string(),
        });
    }
    Ok(dir)
}

pub fn is_ram_fs(dir: &Path) -> std::io::Result<bool> {
    use std::os::unix::ffi::OsStrExt;
    let c = std::ffi::CString::new(dir.as_os_str().as_bytes())?;
    // SAFETY: `c` is a valid NUL-terminated path and `st` is a plain struct
    // that statfs fills in.
    let mut st: libc::statfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statfs(c.as_ptr(), &mut st) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    #[allow(clippy::unnecessary_cast)]
    let t = st.f_type as i64;
    Ok(t == TMPFS_MAGIC || t == RAMFS_MAGIC)
}

/// The name prefix `vcage-<uid>-<pid>-`, which lets tests find the keyfiles
/// of a given process. The random suffix makes the name unpredictable.
pub fn name_prefix(pid: u32) -> String {
    // SAFETY: getuid cannot fail.
    let uid = unsafe { libc::getuid() };
    format!("vcage-{uid}-{pid}-")
}

fn open_unique(dir: &Path) -> Result<(PathBuf, File), KeyfileError> {
    let prefix = name_prefix(std::process::id());
    let mut last_err = None;
    for _ in 0..8 {
        let mut rnd = [0u8; 12];
        getrandom::fill(&mut rnd).map_err(|e| KeyfileError::Random(e.to_string()))?;
        let suffix: String = rnd.iter().map(|b| format!("{b:02x}")).collect();
        let path = dir.join(format!("{prefix}{suffix}.key"));
        // create_new = O_CREAT|O_EXCL: fails if the name exists, including as
        // a symlink, so no symlink is ever followed. O_NOFOLLOW is extra.
        match OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&path)
        {
            Ok(file) => {
                if let Err(e) = check_new_file(&file) {
                    let _ = cleanup::wipe(&file, &path);
                    return Err(e);
                }
                return Ok((path, file));
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => last_err = Some(e),
            Err(e) => {
                return Err(KeyfileError::Create {
                    dir: dir.display().to_string(),
                    source: e,
                })
            }
        }
    }
    Err(KeyfileError::Create {
        dir: dir.display().to_string(),
        source: last_err.unwrap_or_else(|| std::io::Error::other("name collision")),
    })
}

/// The umask can only remove bits, but make sure the file is exactly 0600,
/// owned by us, a regular file, and empty.
fn check_new_file(file: &File) -> Result<(), KeyfileError> {
    file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    let m = file.metadata()?;
    // SAFETY: geteuid cannot fail.
    let euid = unsafe { libc::geteuid() };
    if !m.is_file() || m.uid() != euid || m.mode() & 0o7777 != 0o600 || m.len() != 0 {
        return Err(KeyfileError::BadPermissions);
    }
    Ok(())
}

/// Reads at most [`MAX_KEYFILE_LEN`] bytes from `r` into a zeroizing buffer
/// that is allocated once (so no partial copies are left behind by growth).
pub fn read_bounded(mut r: impl Read) -> std::io::Result<Zeroizing<Vec<u8>>> {
    let mut buf = Zeroizing::new(vec![0u8; MAX_KEYFILE_LEN + 1]);
    let mut n = 0;
    loop {
        if n == buf.len() {
            return Err(std::io::Error::other(format!(
                "decrypted keyfile is larger than {MAX_KEYFILE_LEN} bytes"
            )));
        }
        match r.read(&mut buf[n..]) {
            Ok(0) => break,
            Ok(k) => n += k,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    let mut out = Zeroizing::new(vec![0u8; n]);
    out.copy_from_slice(&buf[..n]);
    Ok(out)
}

/// Constant-time comparison of two byte strings.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let diff = a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y));
    std::hint::black_box(diff) == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_keyfile_is_private_and_removed_on_drop() {
        let (f, key) = SecretFile::generate().unwrap();
        let path = f.path().to_path_buf();
        assert!(path.starts_with(Path::new(SHM_DIR).canonicalize().unwrap()));
        let name = path.file_name().unwrap().to_str().unwrap();
        assert!(name.starts_with(&name_prefix(std::process::id())));
        let m = std::fs::symlink_metadata(&path).unwrap();
        assert!(m.file_type().is_file());
        assert_eq!(m.mode() & 0o7777, 0o600);
        assert_eq!(&f.read().unwrap()[..], &key[..]);
        assert_ne!(&key[..], &[0u8; KEYFILE_LEN][..]);
        drop(f);
        assert!(!path.exists());
    }

    #[test]
    fn removed_on_error_path() {
        fn fails(p: &mut Option<PathBuf>) -> Result<(), KeyfileError> {
            let (f, _key) = SecretFile::generate()?;
            *p = Some(f.path().to_path_buf());
            Err(KeyfileError::BadLength)
        }
        let mut p = None;
        assert!(fails(&mut p).is_err());
        assert!(!p.unwrap().exists());
    }

    #[test]
    fn removed_on_panic() {
        let path = std::sync::Mutex::new(None);
        let r = std::panic::catch_unwind(|| {
            let (f, _key) = SecretFile::generate().unwrap();
            *path.lock().unwrap() = Some(f.path().to_path_buf());
            panic!("boom");
        });
        assert!(r.is_err());
        let p = path.lock().unwrap().take().unwrap();
        assert!(!p.exists());
    }

    #[test]
    fn wipe_does_not_delete_a_replaced_name() {
        let f = SecretFile::create().unwrap();
        f.write(b"secret").unwrap();
        let path = f.path().to_path_buf();
        // Simulate another process swapping the name for a different file.
        std::fs::remove_file(&path).unwrap();
        std::fs::write(&path, b"other").unwrap();
        drop(f);
        assert_eq!(std::fs::read(&path).unwrap(), b"other");
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn write_rejects_bad_lengths() {
        let f = SecretFile::create().unwrap();
        assert!(matches!(f.write(b""), Err(KeyfileError::BadLength)));
        assert!(f.write(b"x").is_ok());
        assert!(matches!(
            f.write(&vec![0u8; MAX_KEYFILE_LEN + 1]),
            Err(KeyfileError::BadLength)
        ));
    }

    #[test]
    fn read_bounded_limits_size() {
        assert_eq!(&read_bounded(&b"abc"[..]).unwrap()[..], b"abc");
        let big = vec![1u8; MAX_KEYFILE_LEN + 1];
        assert!(read_bounded(&big[..]).is_err());
        let max = vec![1u8; MAX_KEYFILE_LEN];
        assert_eq!(read_bounded(&max[..]).unwrap().len(), MAX_KEYFILE_LEN);
    }

    #[test]
    fn constant_time_eq() {
        assert!(ct_eq(b"abc", b"abc"));
        assert!(!ct_eq(b"abc", b"abd"));
        assert!(!ct_eq(b"abc", b"ab"));
        assert!(ct_eq(b"", b""));
    }

    #[test]
    fn shm_is_ram_backed() {
        assert!(is_ram_fs(&Path::new(SHM_DIR).canonicalize().unwrap()).unwrap());
    }
}
