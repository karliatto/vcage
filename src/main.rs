use std::process::ExitCode;

use clap::{Args, Parser, Subcommand};

use vcage::commands::{self, CreateArgs};
use vcage::config::VaultOverrides;
use vcage::{cleanup, privilege};

/// VeraCrypt volumes unlocked with a Trezor-backed age keyfile.
#[derive(Parser)]
#[command(version, about)]
struct Cli {
    #[command(subcommand)]
    command: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Derive an age identity on the Trezor and save it under ~/.config/vcage/identities.
    InitIdentity {
        /// Name to save the identity as (<name>.txt).
        name: String,
        /// The SLIP-0017 identity string, e.g. "<me@example.com>". Write it down exactly.
        #[arg(long)]
        identity_string: String,
    },
    /// Create a new keyfile and VeraCrypt volume, and add the vault to the config.
    Create {
        vault: String,
        /// Volume size passed to VeraCrypt, e.g. 500M or 2G.
        #[arg(long)]
        size: String,
        /// Identity name (from init-identity) or path to an identity file.
        #[arg(long)]
        identity: String,
        /// Additional age recipient (age1...), e.g. a paper backup key. Repeatable.
        #[arg(long = "extra-recipient", value_name = "AGE1...")]
        extra_recipients: Vec<String>,
        /// Volume path [default: ~/Vaults/<vault>.vc]
        #[arg(long)]
        volume: Option<String>,
        /// Encrypted keyfile path [default: ~/Vaults/<vault>.key.age]
        #[arg(long)]
        keyfile: Option<String>,
        /// Mountpoint [default: ~/vc/<vault>]
        #[arg(long)]
        mountpoint: Option<String>,
    },
    /// Decrypt the keyfile (confirm on the Trezor) and mount the vault.
    Mount {
        vault: String,
        #[command(flatten)]
        overrides: Overrides,
    },
    /// Unmount a vault, or all mounted vaults from the config.
    Unmount {
        #[arg(required_unless_present = "all", conflicts_with = "all")]
        vault: Option<String>,
        #[arg(long)]
        all: bool,
    },
    /// Show configured vaults and whether they are mounted.
    List,
    /// Check programs, files, permissions and the Trezor.
    Check {
        /// Do not derive identities on the Trezor (only check that it is connected).
        #[arg(long)]
        no_device: bool,
    },
}

#[derive(Args)]
struct Overrides {
    /// Override the volume path.
    #[arg(long)]
    volume: Option<String>,
    /// Override the encrypted keyfile path.
    #[arg(long)]
    keyfile: Option<String>,
    /// Override the identity (name or path).
    #[arg(long)]
    identity: Option<String>,
    /// Override the mountpoint.
    #[arg(long)]
    mountpoint: Option<String>,
}

fn run(cli: Cli) -> anyhow::Result<()> {
    privilege::ensure_unprivileged()?;
    cleanup::install_signal_handlers()?;
    match cli.command {
        Cmd::InitIdentity {
            name,
            identity_string,
        } => commands::init_identity(&name, &identity_string),
        Cmd::Create {
            vault,
            size,
            identity,
            extra_recipients,
            volume,
            keyfile,
            mountpoint,
        } => commands::create(CreateArgs {
            vault,
            size,
            identity,
            extra_recipients,
            volume,
            keyfile,
            mountpoint,
        }),
        Cmd::Mount { vault, overrides } => commands::mount(
            &vault,
            &VaultOverrides {
                volume: overrides.volume,
                keyfile: overrides.keyfile,
                identity: overrides.identity,
                mountpoint: overrides.mountpoint,
            },
        ),
        Cmd::Unmount { vault, all } => commands::unmount(vault.as_deref(), all),
        Cmd::List => commands::list(),
        Cmd::Check { no_device } => commands::check(!no_device),
    }
}

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("vcage: error: {e:#}");
            ExitCode::FAILURE
        }
    }
}
