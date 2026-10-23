//! vcage must run as a normal user: only `veracrypt` is run through sudo.

use anyhow::{bail, Result};

/// Refuses to run as root or with setuid/setgid privileges.
pub fn ensure_unprivileged() -> Result<()> {
    // SAFETY: these getters cannot fail.
    let ids = unsafe {
        (
            libc::getuid(),
            libc::geteuid(),
            libc::getgid(),
            libc::getegid(),
        )
    };
    decide(ids.0, ids.1, ids.2, ids.3)
}

fn decide(uid: u32, euid: u32, gid: u32, egid: u32) -> Result<()> {
    if uid == 0 || euid == 0 {
        bail!(
            "refusing to run as root; run vcage as your normal user \
             (it uses sudo only for veracrypt)"
        );
    }
    if uid != euid || gid != egid {
        bail!(
            "refusing to run setuid/setgid; vcage must not be installed with special permissions"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decisions() {
        assert!(decide(1000, 1000, 100, 100).is_ok());
        assert!(decide(0, 0, 0, 0).is_err());
        assert!(decide(1000, 0, 100, 100).is_err()); // setuid root
        assert!(decide(0, 1000, 100, 100).is_err());
        assert!(decide(1000, 1001, 100, 100).is_err()); // setuid other user
        assert!(decide(1000, 1000, 100, 0).is_err()); // setgid
    }
}
