# vcage

`vcage` manages [VeraCrypt](https://veracrypt.io) volumes whose keyfile is
stored only in encrypted form, with [age](https://age-encryption.org), to an
age identity that lives on a Trezor hardware wallet (`age-plugin-trezor` from
[romanz/trezor-agent](https://github.com/romanz/trezor-agent)).

To mount a vault you need **the encrypted keyfile, the Trezor (with a physical
confirmation on the device) and the VeraCrypt password**.

vcage runs `age`, `age-plugin-trezor` and `veracrypt` as subprocesses. It
implements no cryptography of its own and never sees your VeraCrypt password:
VeraCrypt asks for it directly on your terminal.

## Installation

### Nix (recommended)

```sh
nix run github:<you>/vcage -- --help                 # try it
nix profile install github:<you>/vcage               # install it
# or, from a checkout:
nix build && ./result/bin/vcage --help
```

The package wraps `vcage` so that `age`, `age-plugin-trezor` (package
`trezor-agent`) and `veracrypt` are on its `PATH`. The flake allows only those
packages past nixpkgs' gates:

- **veracrypt is unfree.** The flake allows that one package. If you install the
  tools yourself, set `nixpkgs.config.allowUnfree = true` (or an
  `allowUnfreePredicate`), or run
  `NIXPKGS_ALLOW_UNFREE=1 nix shell --impure nixpkgs#veracrypt`.
- **trezor-agent depends on `python-ecdsa`**, which nixpkgs marks insecure
  because of CVE-2024-23342: timing leaks when *signing* with python-ecdsa's
  own keys. trezor-agent uses it only for public-key operations; the private
  keys never leave the Trezor. The flake allows that one package. Outside the
  flake you need `NIXPKGS_ALLOW_INSECURE=1` or
  `permittedInsecurePackages = [ "python3.XX-ecdsa-..." ]`.

On NixOS, add the package to `environment.systemPackages` via the flake's
`packages.<system>.default`. `sudo` is taken from the system (NixOS:
`/run/wrappers/bin/sudo`) and is deliberately not bundled.

To talk to the Trezor as a normal user you need its udev rules. On NixOS,
`services.trezord.enable = true;` installs them (package `trezor-udev-rules`).

### Cargo

```sh
cargo install --path .
```

Then install `age`, `trezor-agent` (provides `age-plugin-trezor`) and
`veracrypt` yourself. vcage looks them up on `PATH` and tells you which Nix
package to install when one is missing.

## First-time setup

1. **Create an identity on the Trezor.** Pick an identity string. It is a
   label, not a secret, but it must be reproduced *exactly*.

   ```sh
   vcage init-identity trezor --identity-string '<me@example.com>'
   ```

   This runs `age-plugin-trezor -i`, saves the result with mode 0600 to
   `~/.config/vcage/identities/trezor.txt`, and prints the `age1...`
   recipient. **Write the identity string down exactly** (case, spaces and
   punctuation all matter).

2. **(Optional, recommended) Create a paper backup key.**

   ```sh
   age-keygen -o backup-key.txt      # do this offline; print it, then delete the file
   ```

   Note its `# public key: age1...` line and keep the `AGE-SECRET-KEY-1...`
   line somewhere safe and offline.

3. **Create a vault.**

   ```sh
   vcage create personal --size 2G --identity trezor \
       --extra-recipient age1...backup...
   ```

   This:
   1. generates a 64-byte random keyfile (OS CSPRNG) in `/dev/shm`, mode 0600;
   2. encrypts it with age to the Trezor recipient (and every
      `--extra-recipient`) → `~/Vaults/personal.key.age`;
   3. **decrypts it again and compares it byte by byte** (confirm on the
      Trezor). If this fails, nothing is created;
   4. runs `veracrypt --text --create` (AES, SHA-512, FAT, PIM 0, the keyfile,
      `/dev/urandom`). VeraCrypt asks you for a password;
   5. wipes the plaintext keyfile and adds the vault to the config.

   Defaults: volume `~/Vaults/<vault>.vc`, keyfile
   `~/Vaults/<vault>.key.age`, mountpoint `~/vc/<vault>`. Override them with
   `--volume`, `--keyfile` and `--mountpoint`. `create` refuses to overwrite an
   existing file or config entry.

4. **Check everything.**

   ```sh
   vcage check
   ```

   This checks the programs, that `/dev/shm` is tmpfs, the files and their
   permissions, and the Trezor: it is on USB, and it re-derives each identity
   and compares the recipient, which proves you have the right seed and
   passphrase. Use `--no-device` to only check that the Trezor is present.

## Daily use

```sh
vcage mount personal       # confirm on the Trezor, then type the VeraCrypt password
vcage list                 # configured vaults and whether they are mounted
vcage unmount personal
vcage unmount --all        # every *configured* vault that is mounted
```

`mount` refuses a vault that is already mounted, or a mountpoint that is in
use. Only `veracrypt` runs through `sudo`. vcage itself refuses to run as
root or setuid.

### Configuration

`$XDG_CONFIG_HOME/vcage/config.toml` (default `~/.config/vcage/config.toml`):

```toml
[settings]
warn_cloud_sync = true              # warn if a mountpoint looks cloud-synced
cloud_sync_dirs = ["~/Shared"]      # extra folders to treat as synced

[vaults.personal]
volume = "~/Vaults/personal.vc"
keyfile = "~/Vaults/personal.key.age"
identity = "~/.config/vcage/identities/trezor.txt"
mountpoint = "~/vc/personal"
```

`~` is expanded. Every vault field can be overridden on the command line,
e.g. `vcage mount personal --mountpoint /mnt/tmp`. A vault that is not in
the config can be mounted if all four flags (`--volume`, `--keyfile`,
`--identity`, `--mountpoint`) are given. `--identity` takes a name (looked up
in `identities/`) or a path.

The cloud-sync check looks for Dropbox, Nextcloud, ownCloud, OneDrive,
Google Drive and Syncthing folder names (including `~/Sync`), their marker
files (`.stfolder`, `.dropbox`, `.sync_*.db`, ...), and your
`cloud_sync_dirs`. It only warns.

## Backups you MUST keep

Losing any of the first three makes the volume permanently unreadable,
unless you made an extra-recipient key.

| What | Why |
|------|-----|
| **The encrypted keyfile** (`~/Vaults/<vault>.key.age`) | It is the only copy of the keyfile. It is safe to back up anywhere, because it is useless without the Trezor (or the backup key). |
| **The Trezor recovery seed** (and passphrase, if you use one) | The identity is derived from it. A different passphrase gives a different identity. |
| **The exact identity string** | Also in the `# SLIP-0017:` line of the identity file. With the seed, `vcage init-identity` recreates the identity. |
| **The VeraCrypt password** | VeraCrypt needs both the password and the keyfile. |
| *Optional:* **the extra-recipient secret key** | Decrypts the keyfile without the Trezor, e.g. if the device is lost and you cannot restore the seed right away. Keep it offline. Anyone holding it plus the encrypted keyfile and the password can open the volume. |

Back up the volume itself as you would any other file. Its contents are
encrypted.

## Threat model and limitations

**What vcage protects:** the keyfile at rest. It exists on disk only
age-encrypted, and decrypting it requires the Trezor plus a confirmation on
the device.

- **The plaintext keyfile briefly exists in RAM-backed `/dev/shm`.** VeraCrypt
  only accepts keyfiles as file paths. vcage creates the file under a random
  name with `O_CREAT|O_EXCL|O_NOFOLLOW` and mode 0600, after checking that
  `/dev/shm` is tmpfs. It wipes the file (overwrite, truncate, unlink) as soon
  as VeraCrypt returns, and on every error, panic, SIGINT, SIGTERM, SIGHUP
  and SIGQUIT. While it exists, root and any process running as your user can
  read it. A SIGKILL or a power cut skips the cleanup; tmpfs is cleared at
  reboot.
- **The Trezor confirmation is the main protection against malware running as
  you.** Such malware can watch for the keyfile in `/dev/shm`, read your
  terminal (and so your VeraCrypt password), or replace `vcage`/`age` on your
  `PATH`. What it cannot do is decrypt the keyfile without you approving it on
  the device. **Only confirm on the Trezor when you just ran
  `vcage mount`/`create` yourself.** An unexpected prompt means something
  else is asking.
- Once a volume is mounted, its files are as exposed as any other files.
  Unmount when you are done. Mounting inside a cloud-synced folder could upload
  plaintext; vcage warns about likely cases.
- Key bytes in vcage's memory are held in zeroizing buffers and never printed
  or logged. Copies inside `age`, the plugin, the kernel's pipe buffers or
  VeraCrypt are outside its control. Swap could hold memory pages, so use
  encrypted swap or none.
- vcage passes the absolute path of `veracrypt` to `sudo` (sudo's
  `secure_path` usually lacks Nix profiles). With the Nix package that is a
  `/nix/store/...` path, which changes with every update. Keep that in mind if
  you write `sudoers` rules for it.
- `veracrypt --text -l` (used by `list`, `mount` and `unmount`) runs without
  sudo.

## Development

```sh
nix develop
cargo test                          # unit + integration tests, no hardware or root
cargo clippy --all-targets -- -D warnings
cargo fmt --check
```

The integration tests (`tests/keyfile_flow.rs`) run the real `age` with an
`age-keygen` X25519 identity instead of the Trezor, plus fake `sudo` and
`veracrypt` scripts that record their arguments. Every run asserts that no
plaintext keyfile is left in `/dev/shm`, including after errors, SIGINT and
SIGTERM.

Tests that need real VeraCrypt + sudo or a real Trezor are `#[ignore]`d and
interactive (`tests/hardware.rs`):

```sh
cargo test --test hardware -- --ignored --nocapture --test-threads=1
VCAGE_TEST_TREZOR_IDENTITY='<vcage-test@example.com>' \
    cargo test --test hardware -- --ignored --nocapture trezor
```

Decryption sits behind the `KeyfileDecryptor` trait (`src/age.rs`), so the
subprocess implementation can later be replaced by the `age` crate with its
`plugin` feature, in process.
