//! Tests that need real VeraCrypt + sudo, or a real Trezor. They are
//! `#[ignore]`d by default and interactive (VeraCrypt asks for a password,
//! sudo may ask for yours, the Trezor asks for confirmation). Run them in a
//! terminal from `nix develop`:
//!
//! ```sh
//! cargo test --test hardware -- --ignored --nocapture --test-threads=1
//! # Trezor tests additionally need an identity string to use:
//! VCAGE_TEST_TREZOR_IDENTITY='<vcage-test@example.com>' cargo test --test hardware -- --ignored --nocapture trezor
//! ```

mod common;

use std::process::{Command, Stdio};

use common::*;

/// Like `Env::cmd`, but uses the real tools on PATH and the terminal.
fn real(env: &Env, args: &[&str]) -> std::process::ExitStatus {
    Command::new(env!("CARGO_BIN_EXE_vcage"))
        .args(args)
        .env("HOME", &env.home)
        .env_remove("XDG_CONFIG_HOME")
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .unwrap()
}

#[test]
#[ignore = "needs veracrypt, sudo and a terminal (enter any test password)"]
fn real_veracrypt_create_mount_unmount() {
    let env = Env::new();
    env.keygen("test");
    assert!(real(&env, &["create", "t", "--size", "5M", "--identity", "test"]).success());
    assert!(env.home.join("Vaults/t.vc").is_file());

    assert!(real(&env, &["mount", "t"]).success());
    let list = Command::new(find_tool("veracrypt"))
        .args(["--text", "-l"])
        .output()
        .unwrap();
    let listed = String::from_utf8_lossy(&list.stdout);
    assert!(listed.contains("t.vc"), "{listed}");
    assert!(
        !real(&env, &["mount", "t"]).success(),
        "double mount must fail"
    );

    assert!(real(&env, &["unmount", "t"]).success());
    assert!(!real(&env, &["unmount", "t"]).success());
}

#[test]
#[ignore = "needs a Trezor and VCAGE_TEST_TREZOR_IDENTITY"]
fn trezor_init_identity_and_check() {
    let ident = std::env::var("VCAGE_TEST_TREZOR_IDENTITY")
        .expect("set VCAGE_TEST_TREZOR_IDENTITY to a throwaway identity string");
    let env = Env::new();
    assert!(real(
        &env,
        &["init-identity", "trezor", "--identity-string", &ident]
    )
    .success());
    let id = env.identities().join("trezor.txt");
    let text = std::fs::read_to_string(&id).unwrap();
    assert!(text.contains("AGE-PLUGIN-TREZOR-1"));
    assert!(text.contains("# recipient: age1"));
    // Refuses to overwrite.
    assert!(!real(
        &env,
        &["init-identity", "trezor", "--identity-string", &ident]
    )
    .success());
    // `check` re-derives the identity on the device. It may still fail on
    // other items (e.g. no vaults), so only look at its Trezor lines.
    let out = Command::new(env!("CARGO_BIN_EXE_vcage"))
        .arg("check")
        .env("HOME", &env.home)
        .env_remove("XDG_CONFIG_HOME")
        .stdin(Stdio::inherit())
        .stderr(Stdio::inherit())
        .output()
        .unwrap();
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(s.contains("Trezor derives the recipient"), "{s}");
}
