//! End-to-end keyfile flow with a plain age X25519 identity instead of the
//! Trezor, and fake `sudo`/`veracrypt` (see tests/common). No hardware or
//! root needed.

mod common;

use std::fs;
use std::time::{Duration, Instant};

use common::*;

const BACKUP: &str = "backup";

fn create_personal(env: &Env, extra: &[&str]) -> std::process::Output {
    let mut args = vec!["create", "personal", "--size", "10M", "--identity", "test"];
    args.extend_from_slice(extra);
    env.run(&args)
}

#[test]
fn create_mount_list_unmount() {
    let env = Env::new();
    env.keygen("test");
    let backup_pub = env.keygen(BACKUP);

    let out = create_personal(&env, &["--extra-recipient", &backup_pub]);
    assert_ok(&out);
    assert!(stderr(&out).contains("Back up NOW"));

    // Files and config.
    let vol = env.home.join("Vaults/personal.vc");
    let enc = env.home.join("Vaults/personal.key.age");
    assert!(vol.is_file());
    assert!(enc.is_file());
    assert!(env.home.join("vc/personal").is_dir());
    let cfg = fs::read_to_string(env.home.join(".config/vcage/config.toml")).unwrap();
    assert!(cfg.contains("[vaults.personal]"), "{cfg}");
    assert!(cfg.contains("volume = \"~/Vaults/personal.vc\""), "{cfg}");

    // VeraCrypt got a 64-byte, 0600 keyfile from /dev/shm with the right flags.
    let key = env.keycopy();
    assert_eq!(key.len(), 64);
    assert_eq!(env.keycopy_mode(), "600");
    let log = env.log();
    let create_line = log.lines().find(|l| l.contains("--create")).unwrap();
    for flag in [
        "--text",
        "--size=10M",
        "--volume-type=normal",
        "--encryption=AES",
        "--hash=SHA-512",
        "--filesystem=FAT",
        "--pim=0",
        "--keyfiles=/dev/shm/vcage-",
        "--random-source=/dev/urandom",
    ] {
        assert!(create_line.contains(flag), "missing {flag}: {create_line}");
    }
    assert!(!create_line.starts_with("sudo"), "create must not use sudo");

    // Both the primary and the extra recipient can decrypt it.
    let ids = env.identities();
    assert_eq!(env.age_decrypt(&ids.join("test.txt"), &enc), key);
    assert_eq!(env.age_decrypt(&ids.join("backup.txt"), &enc), key);

    // Creating it again is refused.
    assert_err(&create_personal(&env, &[]), "already exists");

    // Mount.
    fs::remove_file(env.path("keycopy")).unwrap();
    let out = env.run(&["mount", "personal"]);
    assert_ok(&out);
    assert_eq!(env.keycopy(), key);
    assert_eq!(env.keycopy_mode(), "600");
    let log = env.log();
    let sudo_line = log
        .lines()
        .find(|l| l.starts_with("sudo") && l.contains("--keyfiles="))
        .unwrap();
    assert!(sudo_line.contains("--pim=0"));
    assert!(sudo_line.contains("--protect-hidden=no"));
    assert!(sudo_line.contains(vol.to_str().unwrap()));

    // Already mounted -> refused.
    assert_err(&env.run(&["mount", "personal"]), "already mounted");

    let out = env.run(&["list"]);
    assert_ok(&out);
    assert!(stdout(&out).contains("personal"));
    assert!(stdout(&out).contains(" mounted "), "{}", stdout(&out));

    assert_ok(&env.run(&["unmount", "personal"]));
    assert!(env
        .log()
        .lines()
        .any(|l| l.starts_with("sudo") && l.contains(" -d ")));
    let out = env.run(&["list"]);
    assert!(stdout(&out).contains("unmounted"), "{}", stdout(&out));
    assert_err(&env.run(&["unmount", "personal"]), "not mounted");

    // --all with one mounted vault, then with none.
    assert_ok(&env.run(&["mount", "personal"]));
    assert_ok(&env.run(&["unmount", "--all"]));
    assert!(!env.path("state").exists());
    let out = env.run(&["unmount", "--all"]);
    assert_ok(&out);
    assert!(stderr(&out).contains("No configured vaults are mounted"));
}

#[test]
fn create_refuses_existing_files() {
    let env = Env::new();
    env.keygen("test");
    fs::create_dir_all(env.home.join("Vaults")).unwrap();
    fs::write(env.home.join("Vaults/personal.vc"), "precious").unwrap();
    assert_err(&create_personal(&env, &[]), "refusing to overwrite");
    assert_eq!(
        fs::read_to_string(env.home.join("Vaults/personal.vc")).unwrap(),
        "precious"
    );
    assert!(!env.home.join("Vaults/personal.key.age").exists());

    // Same for an existing encrypted keyfile, even as a dangling symlink.
    let env = Env::new();
    env.keygen("test");
    fs::create_dir_all(env.home.join("Vaults")).unwrap();
    std::os::unix::fs::symlink("/nonexistent", env.home.join("Vaults/personal.key.age")).unwrap();
    assert_err(&create_personal(&env, &[]), "refusing to overwrite");
    assert!(!env.home.join("Vaults/personal.vc").exists());
}

#[test]
fn create_aborts_when_verification_fails() {
    // The identity file advertises a recipient it cannot decrypt for, so the
    // decrypt-and-compare step must fail before VeraCrypt is ever run.
    let env = Env::new();
    env.keygen("test");
    let other = env.keygen("other");
    let id = env.identities().join("test.txt");
    let text = fs::read_to_string(&id).unwrap();
    let fixed: String = text
        .lines()
        .map(|l| {
            if l.starts_with("# public key:") {
                format!("# public key: {other}\n")
            } else {
                format!("{l}\n")
            }
        })
        .collect();
    fs::write(&id, fixed).unwrap();

    assert_err(&create_personal(&env, &[]), "nothing was created");
    assert!(!env.home.join("Vaults/personal.key.age").exists());
    assert!(!env.home.join("Vaults/personal.vc").exists());
    assert!(!env.log().contains("--create"));
    assert!(!env.home.join(".config/vcage/config.toml").exists());
}

#[test]
fn create_cleans_up_when_veracrypt_fails() {
    let mut env = Env::new();
    env.keygen("test");
    env.extra_env.push(("FAKE_EXIT".into(), "1".into()));
    assert_err(&create_personal(&env, &[]), "veracrypt --create failed");
    // The keyfile existed while VeraCrypt ran...
    assert_eq!(env.keycopy().len(), 64);
    // ...and the now useless encrypted keyfile and config entry are gone.
    assert!(!env.home.join("Vaults/personal.key.age").exists());
    assert!(!env.home.join(".config/vcage/config.toml").exists());
}

#[test]
fn keyfile_removed_after_mount_error() {
    let mut env = Env::new();
    env.keygen("test");
    assert_ok(&create_personal(&env, &[]));
    fs::remove_file(env.path("keycopy")).unwrap();
    env.extra_env.push(("FAKE_EXIT".into(), "1".into()));
    // `run` asserts that no keyfile is left in /dev/shm.
    assert_err(
        &env.run(&["mount", "personal"]),
        "sudo veracrypt (mount) failed",
    );
    assert_eq!(
        env.keycopy().len(),
        64,
        "keyfile should have existed during mount"
    );
}

#[test]
fn keyfile_removed_after_decrypt_error() {
    let env = Env::new();
    env.keygen("test");
    assert_ok(&create_personal(&env, &[]));
    fs::write(env.home.join("Vaults/personal.key.age"), "garbage").unwrap();
    assert_err(&env.run(&["mount", "personal"]), "age could not decrypt");
}

fn mount_and_signal(sig: i32) {
    let mut env = Env::new();
    env.keygen("test");
    assert_ok(&create_personal(&env, &[]));
    env.extra_env.push(("FAKE_BLOCK".into(), "1".into()));

    let child = env.spawn(&["mount", "personal"]);
    let pid = child.id();
    let deadline = Instant::now() + Duration::from_secs(20);
    while !env.path("ready").exists() {
        assert!(Instant::now() < deadline, "fake veracrypt never started");
        std::thread::sleep(Duration::from_millis(20));
    }
    assert_eq!(
        leftovers(pid).len(),
        1,
        "keyfile should exist while mounting"
    );

    // SAFETY: plain syscall on our own child.
    assert_eq!(unsafe { libc::kill(pid as libc::pid_t, sig) }, 0);
    let killed_at = Instant::now();
    let out = child.wait_with_output().unwrap();
    assert_eq!(out.status.code(), Some(128 + sig), "{}", stderr(&out));
    // The fake VeraCrypt sleeps 30s holding our stderr pipe; finishing fast
    // proves vcage terminated its child instead of leaving it running.
    assert!(
        killed_at.elapsed() < Duration::from_secs(10),
        "child process was not terminated"
    );
    assert!(stderr(&out).contains("plaintext keyfile wiped"));
    assert!(leftovers(pid).is_empty(), "keyfile left after signal");
    // The keyfile VeraCrypt saw was the real one (not wiped early).
    assert_eq!(env.keycopy().len(), 64);
}

#[test]
fn keyfile_removed_after_sigint() {
    mount_and_signal(libc::SIGINT);
}

#[test]
fn keyfile_removed_after_sigterm() {
    mount_and_signal(libc::SIGTERM);
}

#[test]
fn cloud_sync_warning_is_configurable() {
    let env = Env::new();
    env.keygen("test");
    let mp = env.home.join("Dropbox/vc");
    let out = create_personal(&env, &["--mountpoint", mp.to_str().unwrap()]);
    assert_ok(&out);
    assert!(stderr(&out).contains("cloud-sync folder (Dropbox)"));

    let cfg_path = env.home.join(".config/vcage/config.toml");
    let cfg = fs::read_to_string(&cfg_path).unwrap();
    fs::write(
        &cfg_path,
        cfg.replace("warn_cloud_sync = true", "warn_cloud_sync = false"),
    )
    .unwrap();
    let out = env.run(&["mount", "personal"]);
    assert_ok(&out);
    assert!(!stderr(&out).contains("cloud-sync"));
}

#[test]
fn mount_with_overrides_only() {
    let env = Env::new();
    env.keygen("test");
    assert_ok(&create_personal(&env, &[]));
    fs::remove_file(env.home.join(".config/vcage/config.toml")).unwrap();
    let h = env.home.display();
    let vol = format!("{h}/Vaults/personal.vc");
    let key = format!("{h}/Vaults/personal.key.age");
    let mp = format!("{h}/elsewhere");
    let args = [
        "mount",
        "adhoc",
        "--volume",
        &vol,
        "--keyfile",
        &key,
        "--identity",
        "test",
        "--mountpoint",
        &mp,
    ];
    assert_ok(&env.run(&args));
    assert!(fs::read_to_string(env.path("state")).unwrap().contains(&mp));
    assert_err(&env.run(&["mount", "adhoc"]), "not in the config");
}

#[test]
fn missing_veracrypt_mentions_nix() {
    let mut env = Env::new();
    fs::remove_file(env.bin.join("veracrypt")).unwrap();
    // Only our bin dir, so a real veracrypt on the caller's PATH is not found.
    env.path = env.bin.display().to_string();
    let out = env.run(&["list"]);
    assert_err(&out, "veracrypt");
    assert!(stderr(&out).contains("NIXPKGS_ALLOW_UNFREE=1"));
}

#[test]
fn list_without_vaults() {
    let env = Env::new();
    let out = env.run(&["list"]);
    assert_ok(&out);
    assert!(stderr(&out).contains("No vaults configured"));
}

#[test]
fn mount_refuses_identity_writable_by_others() {
    use std::os::unix::fs::PermissionsExt;
    let env = Env::new();
    env.keygen("test");
    assert_ok(&create_personal(&env, &[]));
    let id = env.identities().join("test.txt");
    fs::set_permissions(&id, fs::Permissions::from_mode(0o666)).unwrap();
    assert_err(
        &env.run(&["mount", "personal"]),
        "writable by group or others",
    );
}

#[test]
fn respects_xdg_config_home() {
    let mut env = Env::new();
    let xdg = env.path("xdg");
    env.extra_env
        .push(("XDG_CONFIG_HOME".into(), xdg.display().to_string()));
    // Identity lives under the XDG location.
    fs::create_dir_all(xdg.join("vcage/identities")).unwrap();
    let st = std::process::Command::new(env.bin.join("age-keygen"))
        .arg("-o")
        .arg(xdg.join("vcage/identities/test.txt"))
        .stderr(std::process::Stdio::null())
        .status()
        .unwrap();
    assert!(st.success());
    assert_ok(&create_personal(&env, &[]));
    assert!(xdg.join("vcage/config.toml").is_file());
    assert!(!env.home.join(".config/vcage/config.toml").exists());
}
