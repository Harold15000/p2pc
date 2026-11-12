// SPDX-License-Identifier: AGPL-3.0-only

//! Template bundle fixtures (H2 spec §7.6, SI-H2-14): the repository's own templates compiled into a bundle of any
//! version, signed at test time with a throwaway key. No key and no signed bundle is ever committed.

// Helpers are not `#[test]` functions: a failed `expect` here is a test failure with its message.
#![allow(clippy::expect_used)]

use std::io::Cursor;
use std::path::{Path, PathBuf};

use minisign::{KeyPair, PublicKey, SignatureBox};
use p2pc_server::templates::{BUNDLE_FILE, SIGNATURE_FILE, TEMPLATES_DIR, TemplateStore, Trust};
use templates_bundle::bundle::{Bundle, compile_dir};
use templates_bundle::check::Mode;
use templates_bundle::sign::{sign_bundle, trusted_comment};

use super::TestApp;

/// The version of the hub in these tests.
pub const HUB_VERSION: &str = "0.1.0";

/// The repository's `templates/` directory.
pub fn shipped_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../templates")
}

/// The shipped templates as a bundle of `version`.
pub fn bundle(version: u64) -> Bundle {
    let (mut bundle, _) = compile_dir(&shipped_dir(), Mode::Release).expect("the shipped templates compile");
    bundle.bundle_version = version;
    bundle
}

/// The canonical bytes of `bundle`: what the release signs and the hub embeds.
pub fn bytes(bundle: &Bundle) -> Vec<u8> {
    bundle.to_canonical_json().expect("canonical JSON")
}

/// A throwaway release key.
pub struct Signer {
    keys: KeyPair,
}

impl Signer {
    pub fn new() -> Self {
        Self {
            keys: KeyPair::generate_unencrypted_keypair().expect("a key pair"),
        }
    }

    pub fn public(&self) -> PublicKey {
        self.keys.pk.clone()
    }

    /// Signs `bundle` as the release does: its canonical bytes and their `.minisig` text.
    pub fn sign(&self, bundle: &Bundle) -> (Vec<u8>, String) {
        let bytes = bytes(bundle);
        let signature = sign_bundle(&bytes, &self.keys.sk).expect("the bundle is signed");
        (bytes, signature)
    }

    /// Signs any bytes, with a trusted comment that names `comment_version`: what a release key that skipped the
    /// release checks would produce.
    pub fn sign_raw(&self, bytes: &[u8], comment_version: u64) -> String {
        minisign::sign(
            None,
            &self.keys.sk,
            Cursor::new(bytes),
            Some(&trusted_comment(comment_version)),
            Some("a test signature"),
        )
        .map(SignatureBox::into_string)
        .expect("a signature")
    }

    /// What a hub built with this key and embedding the shipped templates as `embedded_version` trusts.
    pub fn trust(&self, embedded_version: u64) -> Trust {
        Trust {
            public_key: Some(self.public()),
            embedded: bytes(&bundle(embedded_version)),
            hub_version: semver::Version::parse(HUB_VERSION).expect("a version"),
        }
    }
}

/// `<data>/templates/` of `app`, created.
pub fn templates_dir(app: &TestApp) -> PathBuf {
    let dir = app.data_dir().join(TEMPLATES_DIR);
    std::fs::create_dir_all(&dir).expect("the templates directory");
    dir
}

/// Puts a bundle file and its signature in `<data>/templates/`, as the desktop app's updater does.
pub fn put(app: &TestApp, bundle: &[u8], signature: Option<&str>) {
    let dir = templates_dir(app);
    std::fs::write(dir.join(BUNDLE_FILE), bundle).expect("the bundle file");
    match signature {
        Some(signature) => std::fs::write(dir.join(SIGNATURE_FILE), signature).expect("the signature file"),
        None => {
            let _ = std::fs::remove_file(dir.join(SIGNATURE_FILE));
        }
    }
}

/// Removes the bundle file and its signature.
pub fn remove(app: &TestApp) {
    let dir = templates_dir(app);
    let _ = std::fs::remove_file(dir.join(BUNDLE_FILE));
    let _ = std::fs::remove_file(dir.join(SIGNATURE_FILE));
}

/// A hub (re)started over `app`'s database and data dir with `trust`: its template store, loaded once.
pub async fn start(app: &TestApp, trust: Trust) -> TemplateStore {
    TemplateStore::open_with(
        app.db.clone(),
        app.clock.clone(),
        Some(app.account_id),
        &app.data_dir(),
        trust,
    )
    .await
    .expect("the template store")
}

/// Makes `app` serve `store`: its state and its router.
pub fn serve(app: &mut TestApp, store: TemplateStore) {
    app.state.set_bundle(store);
    app.router = p2pc_server::app::router(app.state.clone());
}

/// The served bundle's version, or `None` when the hub serves no template.
pub fn served_version(store: &TemplateStore) -> Option<u64> {
    store.served().ok().map(|loaded| loaded.version())
}

/// The high-water mark in `app`'s database: `(bundle_version, sha256)`.
pub async fn mark(app: &TestApp) -> Option<(i64, String)> {
    sqlx::query_as("SELECT bundle_version, sha256 FROM template_bundle_state WHERE id = 1")
        .fetch_optional(&app.db)
        .await
        .expect("the mark")
}

/// The `bundle_version`s of the `template_bundle_loaded` audit events, oldest first.
pub async fn audited_versions(app: &TestApp) -> Vec<i64> {
    let details: Vec<String> =
        sqlx::query_scalar("SELECT detail FROM audit_events WHERE kind = 'template_bundle_loaded' ORDER BY rowid")
            .fetch_all(&app.db)
            .await
            .expect("the audit events");
    details
        .iter()
        .map(|detail| {
            serde_json::from_str::<serde_json::Value>(detail).expect("a JSON detail")["bundle_version"]
                .as_i64()
                .expect("a version")
        })
        .collect()
}
