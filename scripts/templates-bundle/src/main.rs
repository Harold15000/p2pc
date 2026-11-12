// SPDX-License-Identifier: Apache-2.0

//! `templates-bundle`: checks, compiles, signs and verifies the template bundle (H2 spec §7.6).
//!
//! ```text
//! templates-bundle check   [--templates-dir templates] [--release]
//! templates-bundle compile [--templates-dir templates] --out templates.json [--release]
//! templates-bundle sign    --bundle templates.json --secret-key <file> [--password-env <VAR>] --out templates.json.minisig
//! templates-bundle verify  --bundle templates.json --signature templates.json.minisig --public-key <file>
//! ```
//!
//! `--release` is what the release pipeline passes: it refuses a placeholder image digest. `sign` reads the release
//! key from a file the release manager provides; an encrypted key's password comes from the environment variable
//! named by `--password-env`, never from the command line.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use minisign::{PublicKeyBox, SecretKeyBox};
use templates_bundle::bundle::{MAX_BUNDLE_BYTES, compile_dir};
use templates_bundle::check::Mode;
use templates_bundle::sign::{sign_bundle, verify_bundle};

#[derive(Parser)]
#[command(
    name = "templates-bundle",
    version,
    about = "Check, compile and sign the P2PC template bundle"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Check every rule over `templates/` and print nothing when they all hold.
    Check {
        /// The directory with `bundle.toml` and `<id>.toml`.
        #[arg(long, default_value = "templates")]
        templates_dir: PathBuf,
        /// Release rules: a placeholder image digest is refused.
        #[arg(long)]
        release: bool,
    },
    /// Check, then write the canonical `templates.json`.
    Compile {
        /// The directory with `bundle.toml` and `<id>.toml`.
        #[arg(long, default_value = "templates")]
        templates_dir: PathBuf,
        /// Where to write the bundle.
        #[arg(long)]
        out: PathBuf,
        /// Release rules: a placeholder image digest is refused.
        #[arg(long)]
        release: bool,
    },
    /// Sign a compiled bundle with the release key.
    Sign {
        /// The compiled `templates.json`.
        #[arg(long)]
        bundle: PathBuf,
        /// The minisign secret key file.
        #[arg(long)]
        secret_key: PathBuf,
        /// The environment variable that holds the key's password, for an encrypted key.
        #[arg(long)]
        password_env: Option<String>,
        /// Where to write the `.minisig` file.
        #[arg(long)]
        out: PathBuf,
    },
    /// Verify a bundle against its signature and a public key.
    Verify {
        /// The compiled `templates.json`.
        #[arg(long)]
        bundle: PathBuf,
        /// The `.minisig` file.
        #[arg(long)]
        signature: PathBuf,
        /// The minisign public key file.
        #[arg(long)]
        public_key: PathBuf,
    },
}

fn mode(release: bool) -> Mode {
    if release { Mode::Release } else { Mode::Dev }
}

/// Reads a file of at most `limit` bytes.
fn read_bounded(path: &Path, limit: usize) -> Result<Vec<u8>> {
    let meta = fs::metadata(path).with_context(|| format!("cannot read {}", path.display()))?;
    if meta.len() > u64::try_from(limit).unwrap_or(u64::MAX) {
        bail!("{} is over {limit} bytes", path.display());
    }
    fs::read(path).with_context(|| format!("cannot read {}", path.display()))
}

fn read_text(path: &Path) -> Result<String> {
    let bytes = read_bounded(path, 64 * 1024)?;
    String::from_utf8(bytes).with_context(|| format!("{} is not UTF-8", path.display()))
}

fn main() -> Result<()> {
    match Cli::parse().command {
        Command::Check { templates_dir, release } => {
            let (bundle, _) = compile_dir(&templates_dir, mode(release))?;
            eprintln!(
                "ok: {} template(s), bundle_version {}",
                bundle.templates.len(),
                bundle.bundle_version
            );
        }
        Command::Compile {
            templates_dir,
            out,
            release,
        } => {
            let (bundle, bytes) = compile_dir(&templates_dir, mode(release))?;
            fs::write(&out, &bytes).with_context(|| format!("cannot write {}", out.display()))?;
            eprintln!(
                "wrote {} ({} template(s), bundle_version {})",
                out.display(),
                bundle.templates.len(),
                bundle.bundle_version
            );
        }
        Command::Sign {
            bundle,
            secret_key,
            password_env,
            out,
        } => {
            let bytes = read_bounded(&bundle, MAX_BUNDLE_BYTES)?;
            let key_box =
                SecretKeyBox::from_string(&read_text(&secret_key)?).context("not a minisign secret key file")?;
            let key = match password_env {
                Some(var) => {
                    let password = std::env::var(&var).with_context(|| format!("${var} is not set"))?;
                    key_box
                        .into_secret_key(Some(password))
                        .context("cannot decrypt the secret key")?
                }
                None => key_box
                    .into_unencrypted_secret_key()
                    .context("the secret key is encrypted: pass --password-env <VAR>")?,
            };
            let signature = sign_bundle(&bytes, &key)?;
            fs::write(&out, signature).with_context(|| format!("cannot write {}", out.display()))?;
            eprintln!("wrote {}", out.display());
        }
        Command::Verify {
            bundle,
            signature,
            public_key,
        } => {
            let bytes = read_bounded(&bundle, MAX_BUNDLE_BYTES)?;
            let key = PublicKeyBox::from_string(&read_text(&public_key)?)
                .and_then(PublicKeyBox::into_public_key)
                .context("not a minisign public key file")?;
            let verified = verify_bundle(&bytes, &read_text(&signature)?, &key)?;
            eprintln!(
                "ok: bundle_version {}, {} template(s)",
                verified.bundle_version,
                verified.templates.len()
            );
        }
    }
    Ok(())
}
