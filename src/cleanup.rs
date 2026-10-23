//! Process-wide registry of plaintext secret files and running children, so a
//! signal can wipe every keyfile before the process exits.
//!
//! Signals are handled on a normal thread (via `signal-hook`'s iterator), not
//! inside an async signal handler, so taking the mutex and doing file I/O
//! there is safe. The thread terminates children, wipes all registered files
//! and exits while still holding the lock, so nothing new can be registered.

use std::fs::File;
use std::os::unix::fs::{FileExt, MetadataExt};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus};
use std::sync::{Mutex, MutexGuard, Once};

use anyhow::{Context, Result};
use signal_hook::consts::{SIGHUP, SIGINT, SIGQUIT, SIGTERM};
use signal_hook::iterator::Signals;

pub(crate) struct Entry {
    pub id: u64,
    pub path: PathBuf,
    pub file: File,
}

struct State {
    next_id: u64,
    files: Vec<Entry>,
    children: Vec<u32>,
}

static STATE: Mutex<State> = Mutex::new(State {
    next_id: 0,
    files: Vec::new(),
    children: Vec::new(),
});

/// Locks the registry. Poisoning is ignored: cleanup must still work after a
/// panic elsewhere.
fn state() -> MutexGuard<'static, State> {
    STATE.lock().unwrap_or_else(|e| e.into_inner())
}

/// Runs `create` with the registry locked and registers the file it returns,
/// so no signal can arrive between creating the file and registering it.
pub(crate) fn register_file<T, E>(
    create: impl FnOnce() -> Result<(T, PathBuf, File), E>,
) -> Result<(T, u64), E> {
    let mut st = state();
    let (value, path, file) = create()?;
    let id = st.next_id;
    st.next_id += 1;
    st.files.push(Entry { id, path, file });
    Ok((value, id))
}

/// Removes a file from the registry and wipes it. Returns the wipe result.
pub(crate) fn wipe_registered(id: u64) -> std::io::Result<()> {
    let mut st = state();
    match st.files.iter().position(|e| e.id == id) {
        Some(i) => {
            let e = st.files.swap_remove(i);
            wipe(&e.file, &e.path)
        }
        None => Ok(()),
    }
}

/// Number of currently registered secret files (for tests and diagnostics).
pub fn registered_files() -> usize {
    state().files.len()
}

/// Overwrites the file contents through its descriptor, truncates it, and
/// unlinks `path` only if it still names the same inode.
pub(crate) fn wipe(file: &File, path: &Path) -> std::io::Result<()> {
    let meta = file.metadata()?;
    let len = meta.len();
    let zeros = [0u8; 4096];
    let mut off = 0u64;
    while off < len {
        let n = (len - off).min(zeros.len() as u64) as usize;
        file.write_all_at(&zeros[..n], off)?;
        off += n as u64;
    }
    file.sync_data()?;
    file.set_len(0)?;
    match std::fs::symlink_metadata(path) {
        Ok(m) if m.dev() == meta.dev() && m.ino() == meta.ino() => std::fs::remove_file(path),
        Ok(_) => Ok(()), // someone replaced the name; do not delete their file
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

/// Spawns `cmd`, registering the child so a signal handler can terminate it,
/// and waits for it.
pub fn run(cmd: &mut Command) -> Result<ExitStatus> {
    let child = spawn(cmd)?;
    wait(child)
}

/// Like [`run`], with stdout piped and returned (for non-secret output only).
pub fn run_capture(cmd: &mut Command) -> Result<(ExitStatus, Vec<u8>)> {
    use std::io::Read;
    let mut child = spawn(cmd.stdout(std::process::Stdio::piped()))?;
    let mut buf = Vec::new();
    let read = child.stdout.take().map(|mut s| s.read_to_end(&mut buf));
    let status = wait(child)?;
    if let Some(r) = read {
        r.context("reading child output")?;
    }
    Ok((status, buf))
}

pub fn spawn(cmd: &mut Command) -> Result<Child> {
    let mut st = state();
    let child = cmd
        .spawn()
        .with_context(|| format!("starting {:?}", cmd.get_program()))?;
    st.children.push(child.id());
    Ok(child)
}

/// Waits for a child spawned with [`spawn`]. The child is unregistered before
/// it is reaped, so its PID can never be reused while still registered.
pub fn wait(mut child: Child) -> Result<ExitStatus> {
    let pid = child.id();
    // SAFETY: waitid with WNOWAIT only observes the child's exit, leaving it
    // waitable; `info` is a plain C struct we own.
    loop {
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        let r = unsafe {
            libc::waitid(
                libc::P_PID,
                pid as libc::id_t,
                &mut info,
                libc::WEXITED | libc::WNOWAIT,
            )
        };
        if r == 0 {
            break;
        }
        let err = std::io::Error::last_os_error();
        if err.kind() != std::io::ErrorKind::Interrupted {
            return Err(err).context("waiting for child process");
        }
    }
    state().children.retain(|&c| c != pid);
    child.wait().context("waiting for child process")
}

/// Installs handlers for SIGINT, SIGTERM, SIGHUP and SIGQUIT that wipe all
/// registered secret files and exit with status 128+signal. Idempotent.
pub fn install_signal_handlers() -> Result<()> {
    static ONCE: Once = Once::new();
    let mut result = Ok(());
    ONCE.call_once(|| {
        result = (|| {
            let mut signals = Signals::new([SIGINT, SIGTERM, SIGHUP, SIGQUIT])
                .context("installing signal handlers")?;
            std::thread::Builder::new()
                .name("vcage-signals".into())
                .spawn(move || {
                    if let Some(sig) = signals.forever().next() {
                        cleanup_and_exit(sig);
                    }
                })
                .context("starting signal thread")?;
            Ok(())
        })();
    });
    result
}

fn cleanup_and_exit(sig: i32) -> ! {
    let mut st = state();
    for &pid in &st.children {
        // SAFETY: plain syscall; the PID is still unreaped (see `wait`).
        unsafe {
            libc::kill(pid as libc::pid_t, libc::SIGTERM);
        }
    }
    let mut ok = true;
    let had_files = !st.files.is_empty();
    for e in st.files.drain(..) {
        if let Err(err) = wipe(&e.file, &e.path) {
            ok = false;
            eprintln!(
                "vcage: FAILED to wipe {}: {err}; delete it manually",
                e.path.display()
            );
        }
    }
    if ok && had_files {
        eprintln!("\nvcage: interrupted; plaintext keyfile wiped");
    }
    // Exit while holding the lock so nothing new is registered.
    std::process::exit(128 + sig);
}
