// SPDX-License-Identifier: AGPL-3.0-only

//! The template bundle the hub serves (H2 spec §7.6 "Bundle", SI-H2-14).
//!
//! - **Embedded.** The hub embeds the bundle of its own release: `build.rs` compiles the repository's `templates/`
//!   with the release compiler, and the bytes are part of the binary. It is trusted as the code is.
//! - **A newer bundle file.** The desktop app's updater may put `templates.json` and `templates.json.minisig` in
//!   `<data>/templates/` (§14.1). The hub loads that file only with **all** of: a signature that verifies against
//!   the release public key compiled into the hub; a `bundle_version` above the embedded one; a version not below
//!   the high-water mark, and at the mark's version exactly the recorded SHA-256; a `min_hub_version` at most the
//!   hub's version; and every bundle rule of SI-H2-13, checked again here ([`check_bundle`], release rules).
//!   Otherwise the hub logs why and ignores the file.
//! - **The high-water mark** (`template_bundle_state`) is the version and SHA-256 of the highest bundle the hub has
//!   ever loaded. It is raised in the transaction that makes a bundle current, together with the audit event
//!   `template_bundle_loaded`, and it never goes down.
//! - **What is served** ([`choose`]): the valid bundle file if there is one, else the embedded bundle, as long as it
//!   is not below the mark. Otherwise nothing: `GET /v1/templates` answers an empty list with `bundle_error`, a
//!   launch `503 templates_unavailable`, and an older bundle is never served.
//! - **When.** At start and every [`RELOAD_INTERVAL`] ([`TemplateStore::reload`]). Each reload decides again from
//!   what is on disk: a bundle file that was deleted or damaged stops being served at the next reload.
//!
//! **The release key.** No key lives in the repository. The public half is given to the build as
//! `P2PC_RELEASE_PUBLIC_KEY` (see `build.rs`). A hub built without it trusts no bundle file, and serves its
//! embedded bundle only.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::{Arc, PoisonError, RwLock};

use minisign::PublicKey;
use p2pc_proto::api::{AllowedRoute, AuditKind, Template};
use p2pc_proto::ids::AccountId;
use sha2::{Digest, Sha256};
use templates_bundle::bundle::{Bundle, MAX_BUNDLE_BYTES};
use templates_bundle::check::{Mode, check_bundle};
use templates_bundle::sign::verify_bundle;
use tokio::task::JoinHandle;

use crate::clock::Clock;
use crate::fsutil;
use crate::jobs_api::TemplateCatalog;
use crate::store::audit::NewEvent;
use crate::store::templates::Mark;
use crate::store::{self, Db, StoreError};

/// How often the hub reads `<data>/templates/` again (H2 §7.6).
pub const RELOAD_INTERVAL: std::time::Duration = std::time::Duration::from_secs(60);
/// The directory of bundle files, below the data dir (H2 §13).
pub const TEMPLATES_DIR: &str = "templates";
/// The bundle file (H2 §14.1).
pub const BUNDLE_FILE: &str = "templates.json";
/// Its minisign signature.
pub const SIGNATURE_FILE: &str = "templates.json.minisig";
/// Largest signature file the hub reads. A minisign signature file is under 400 bytes.
const MAX_SIGNATURE_BYTES: u64 = 4096;

/// The bundle of this release, compiled by `build.rs`.
static EMBEDDED_BUNDLE: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/templates.json"));
/// The release key's public half, as the build was given it (`build.rs` checked that it parses).
const RELEASE_PUBLIC_KEY: Option<&str> = option_env!("P2PC_RELEASE_PUBLIC_KEY");

/// What a hub trusts about bundles. [`Trust::built_in`] is the hub's own; tests give a throwaway key and fixtures.
#[derive(Debug, Clone)]
pub struct Trust {
    /// The release public key. `None`: no bundle file is ever loaded.
    pub public_key: Option<PublicKey>,
    /// The bytes of the embedded bundle.
    pub embedded: Vec<u8>,
    /// The hub's own version, which a bundle's `min_hub_version` must not exceed.
    pub hub_version: semver::Version,
}

impl Trust {
    /// What this build of the hub trusts: its embedded bundle, the key it was built with and its own version.
    #[must_use]
    pub fn built_in() -> Self {
        Self {
            public_key: RELEASE_PUBLIC_KEY
                .filter(|key| !key.is_empty())
                .and_then(|key| PublicKey::from_base64(key).ok()),
            embedded: EMBEDDED_BUNDLE.to_vec(),
            // A crate version is a semantic version; `0.0.0` would only make the hub refuse more.
            hub_version: semver::Version::parse(env!("CARGO_PKG_VERSION"))
                .unwrap_or_else(|_| semver::Version::new(0, 0, 0)),
        }
    }
}

/// Where a bundle came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    /// The hub's own binary.
    Embedded,
    /// `<data>/templates/templates.json`.
    File,
}

impl Source {
    const fn as_str(self) -> &'static str {
        match self {
            Source::Embedded => "embedded",
            Source::File => "file",
        }
    }
}

/// A bundle the hub may serve: parsed, checked, with the SHA-256 of its bytes.
#[derive(Debug, Clone, PartialEq)]
pub struct Loaded {
    /// The bundle.
    pub bundle: Bundle,
    /// SHA-256 of its bytes, 64 lowercase hex.
    pub sha256: String,
    /// Where it came from.
    pub source: Source,
}

impl Loaded {
    /// Its `bundle_version`.
    #[must_use]
    pub fn version(&self) -> u64 {
        self.bundle.bundle_version
    }

    /// The template `id`, if the bundle has it.
    #[must_use]
    pub fn template(&self, id: &str) -> Option<&Template> {
        self.bundle.templates.iter().find(|t| t.info.id == id)
    }
}

/// Why a bundle is not loaded (H2 §7.6 "Loading a bundle file"). The hub logs it and ignores the bundle.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Refused {
    /// The hub was built without the release public key.
    #[error("this hub was built without the release public key, so it loads no bundle file")]
    NoKey,
    /// `templates.json` is there, its signature is not.
    #[error("its signature file is missing")]
    NoSignature,
    /// A file could not be read, is not a regular file or is too large.
    #[error("it cannot be read: {0}")]
    Unreadable(String),
    /// The signature does not verify, or the signed bytes are not a bundle of the signed version.
    #[error("{0}")]
    NotVerified(String),
    /// The bundle breaks a rule every template must meet (SI-H2-13).
    #[error("it breaks {count} bundle rule(s), the first: {first}")]
    Rules {
        /// How many rules.
        count: usize,
        /// The first problem.
        first: String,
    },
    /// Its `min_hub_version` is above the hub's version, or is not a version.
    #[error("it needs hub version {needs}, and this hub is {hub}")]
    HubTooOld {
        /// The bundle's `min_hub_version`.
        needs: String,
        /// The hub's version.
        hub: String,
    },
    /// Its `bundle_version` is not above the embedded bundle's (the embedded floor).
    #[error("its bundle_version {version} is not above the embedded bundle's ({embedded})")]
    NotAboveEmbedded {
        /// The file's version.
        version: u64,
        /// The embedded bundle's version.
        embedded: u64,
    },
    /// Its `bundle_version` is below the high-water mark: a rollback.
    #[error("its bundle_version {version} is below the highest bundle this hub has loaded ({mark})")]
    BelowMark {
        /// The file's version.
        version: u64,
        /// The mark.
        mark: u64,
    },
    /// It has the mark's version but is not the bundle the mark recorded.
    #[error("it has the version of the highest bundle this hub has loaded ({version}) but is another bundle")]
    NotTheMarkedBundle {
        /// The version.
        version: u64,
    },
}

fn sha256_hex(bytes: &[u8]) -> String {
    data_encoding::HEXLOWER.encode(&Sha256::digest(bytes))
}

/// Admits a bundle whose bytes are already trusted to come from the release (the embedded bundle by the build, a
/// file by its signature): the bundle rules in `mode`, and `min_hub_version` against `hub`.
fn admit(bundle: Bundle, bytes: &[u8], hub: &semver::Version, mode: Mode, source: Source) -> Result<Loaded, Refused> {
    let problems = check_bundle(&bundle, mode);
    if let Some(first) = problems.first() {
        return Err(Refused::Rules {
            count: problems.len(),
            first: first.to_string(),
        });
    }
    let too_old = || Refused::HubTooOld {
        needs: bundle.min_hub_version.clone(),
        hub: hub.to_string(),
    };
    let needs = semver::Version::parse(&bundle.min_hub_version).map_err(|_| too_old())?;
    if needs > *hub {
        return Err(too_old());
    }
    // The mark is stored as a signed integer; no real bundle is near it.
    if i64::try_from(bundle.bundle_version).is_err() {
        return Err(Refused::NotVerified("its bundle_version is out of range".into()));
    }
    Ok(Loaded {
        sha256: sha256_hex(bytes),
        bundle,
        source,
    })
}

/// Reads at most `limit` bytes of the regular file `name` in `dir`, never following a link. `Ok(None)`: no such file.
fn read_bounded(dir: &std::os::fd::OwnedFd, name: &str, limit: u64) -> Result<Option<Vec<u8>>, Refused> {
    let unreadable = |e: std::io::Error| Refused::Unreadable(format!("{name}: {e}"));
    let file = match fsutil::open_read(dir, name) {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(unreadable(e)),
    };
    // One byte more than the limit, so a file that grew past it is seen without reading it whole.
    let mut bytes = Vec::new();
    file.take(limit.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(unreadable)?;
    if bytes.len() as u64 > limit {
        return Err(Refused::Unreadable(format!("{name} is over {limit} bytes")));
    }
    Ok(Some(bytes))
}

/// The bundle file and its signature, as read from `<data>/templates/`.
#[derive(Debug, Clone, PartialEq, Eq)]
struct FileBytes {
    bundle: Vec<u8>,
    /// `None`: there is no signature file.
    signature: Option<Vec<u8>>,
}

/// Reads the bundle file. `Ok(None)`: there is none (no directory, or no `templates.json` in it). Blocking.
fn read_files(data_dir: &Path) -> Result<Option<FileBytes>, Refused> {
    let dir = match fsutil::open_dir(data_dir, [TEMPLATES_DIR], false) {
        Ok(dir) => dir,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(Refused::Unreadable(format!("{TEMPLATES_DIR}/: {e}"))),
    };
    let Some(bundle) = read_bounded(&dir, BUNDLE_FILE, MAX_BUNDLE_BYTES as u64)? else {
        return Ok(None);
    };
    let signature = read_bounded(&dir, SIGNATURE_FILE, MAX_SIGNATURE_BYTES)?;
    Ok(Some(FileBytes { bundle, signature }))
}

/// Verifies the bundle file against `trust` and admits it: the signature first, then everything the bundle says
/// about itself. The version rules against the embedded bundle and the mark are [`choose`]'s.
fn verify_file(files: &FileBytes, trust: &Trust) -> Result<Loaded, Refused> {
    let key = trust.public_key.as_ref().ok_or(Refused::NoKey)?;
    let signature = files.signature.as_deref().ok_or(Refused::NoSignature)?;
    let signature = std::str::from_utf8(signature)
        .map_err(|_| Refused::NotVerified("the signature does not verify: it is not text".into()))?;
    let bundle = verify_bundle(&files.bundle, signature, key).map_err(|e| Refused::NotVerified(e.to_string()))?;
    admit(bundle, &files.bundle, &trust.hub_version, Mode::Release, Source::File)
}

/// What the hub serves, and why a bundle file was left out.
#[derive(Debug, Clone, PartialEq)]
pub struct Choice {
    /// The bundle to serve, or why there is none (`bundle_error`).
    pub serve: Result<Arc<Loaded>, String>,
    /// Why the bundle file is ignored, if there is one and it is.
    pub file_refused: Option<Refused>,
}

/// Decides what the hub serves (H2 §7.6 "Loading a bundle file", "What it serves"), from the embedded bundle, the
/// bundle file as far as it verified, and the high-water mark:
///
/// - a file is used only if its version is above the embedded one and not below the mark, and at the mark's version
///   only if it has the recorded SHA-256;
/// - the hub serves that file, else the embedded bundle, and neither if it is below the mark.
#[must_use]
pub fn choose(
    embedded: Option<&Arc<Loaded>>,
    file: Option<Result<Arc<Loaded>, Refused>>,
    mark: Option<&Mark>,
) -> Choice {
    let floor = embedded.map_or(0, |e| e.version());
    let mut file_refused = None;
    let file = match file {
        None => None,
        Some(Err(refused)) => {
            file_refused = Some(refused);
            None
        }
        Some(Ok(file)) => {
            let version = file.version();
            let refused = if version <= floor {
                Some(Refused::NotAboveEmbedded {
                    version,
                    embedded: floor,
                })
            } else {
                match mark {
                    Some(m) if version < m.bundle_version => Some(Refused::BelowMark {
                        version,
                        mark: m.bundle_version,
                    }),
                    Some(m) if version == m.bundle_version && file.sha256 != m.sha256 => {
                        Some(Refused::NotTheMarkedBundle { version })
                    }
                    _ => None,
                }
            };
            match refused {
                Some(refused) => {
                    file_refused = Some(refused);
                    None
                }
                None => Some(file),
            }
        }
    };
    // A file that passed is above the embedded bundle, so it is the highest of the two.
    let serve = match (file.or_else(|| embedded.cloned()), mark) {
        (None, _) => Err("this hub has no usable template bundle".to_string()),
        (Some(candidate), Some(m)) if candidate.version() < m.bundle_version => Err(format!(
            "this hub has loaded template bundle version {} before and now only has version {}; it serves no \
             template until the current bundle is back",
            m.bundle_version,
            candidate.version()
        )),
        (Some(candidate), _) => Ok(candidate),
    };
    Choice { serve, file_refused }
}

/// The last bundle file the hub looked at, so that an unchanged file is not verified again.
#[derive(Debug)]
struct FileSeen {
    files: FileBytes,
    result: Result<Arc<Loaded>, Refused>,
}

/// What the last reload saw.
#[derive(Debug, Default)]
struct Seen {
    file: Option<FileSeen>,
    /// The refusal of the bundle file the log already has.
    reported: Option<Refused>,
}

#[derive(Debug)]
struct Inner {
    db: Db,
    clock: Arc<dyn Clock>,
    /// The account whose audit log records `template_bundle_loaded`: the hub's owner.
    owner_account: Option<AccountId>,
    data_dir: PathBuf,
    trust: Trust,
    embedded: Option<Arc<Loaded>>,
    current: RwLock<Result<Arc<Loaded>, String>>,
    /// Serialises reloads, and remembers the file of the last one.
    seen: tokio::sync::Mutex<Seen>,
}

/// The bundle the hub serves. Cheap to clone; every clone serves the same bundle.
#[derive(Debug, Clone)]
pub struct TemplateStore {
    inner: Arc<Inner>,
}

impl TemplateStore {
    /// Opens the store of a hub with what its build trusts ([`Trust::built_in`]) and loads once.
    pub async fn open(
        db: Db,
        clock: Arc<dyn Clock>,
        owner_account: Option<AccountId>,
        data_dir: &Path,
    ) -> Result<Self, StoreError> {
        Self::open_with(db, clock, owner_account, data_dir, Trust::built_in()).await
    }

    /// [`TemplateStore::open`] with a given [`Trust`].
    pub async fn open_with(
        db: Db,
        clock: Arc<dyn Clock>,
        owner_account: Option<AccountId>,
        data_dir: &Path,
        trust: Trust,
    ) -> Result<Self, StoreError> {
        let embedded = serde_json::from_slice::<Bundle>(&trust.embedded)
            .map_err(|e| Refused::NotVerified(format!("it is not a template bundle: {e}")))
            .and_then(|bundle| admit(bundle, &trust.embedded, &trust.hub_version, Mode::Dev, Source::Embedded));
        let embedded = match embedded {
            Ok(loaded) => Some(Arc::new(loaded)),
            Err(why) => {
                // A build that embeds a bundle its own checks refuse: the hub serves none from it.
                tracing::error!(%why, "the embedded template bundle is not usable");
                None
            }
        };
        let store = Self {
            inner: Arc::new(Inner {
                db,
                clock,
                owner_account,
                data_dir: data_dir.to_path_buf(),
                trust,
                embedded,
                current: RwLock::new(Err("the template bundle is not loaded yet".to_string())),
                seen: tokio::sync::Mutex::new(Seen::default()),
            }),
        };
        store.reload().await?;
        Ok(store)
    }

    /// The bundle the hub serves now, or why it serves none.
    pub fn served(&self) -> Result<Arc<Loaded>, String> {
        self.inner
            .current
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// Why the bundle file in `<data>/templates/` was ignored at the last reload; `None` when there is no file or it
    /// is the one served.
    pub async fn file_refused(&self) -> Option<Refused> {
        self.inner.seen.lock().await.reported.clone()
    }

    /// Reads `<data>/templates/` and decides again what the hub serves. A bundle above the high-water mark raises
    /// it and is audited (`template_bundle_loaded`) in one transaction, and only then becomes current.
    pub async fn reload(&self) -> Result<(), StoreError> {
        let inner = &self.inner;
        let mut seen = inner.seen.lock().await;
        let data_dir = inner.data_dir.clone();
        let read = tokio::task::spawn_blocking(move || read_files(&data_dir))
            .await
            .unwrap_or_else(|e| Err(Refused::Unreadable(format!("the read did not finish: {e}"))));
        let file = match read {
            Ok(None) => {
                seen.file = None;
                None
            }
            Ok(Some(files)) => {
                if let Some(last) = seen.file.as_ref().filter(|last| last.files == files) {
                    Some(last.result.clone())
                } else {
                    let trust = inner.trust.clone();
                    let (files, result) = tokio::task::spawn_blocking(move || {
                        let result = verify_file(&files, &trust).map(Arc::new);
                        (files, result)
                    })
                    .await
                    .map_err(|_| StoreError::Corrupt("template bundle verification"))?;
                    seen.file = Some(FileSeen {
                        files,
                        result: result.clone(),
                    });
                    Some(result)
                }
            }
            Err(refused) => {
                seen.file = None;
                Some(Err(refused))
            }
        };
        let mark = {
            let mut conn = inner.db.acquire().await?;
            store::templates::mark(&mut conn).await?
        };
        let choice = choose(inner.embedded.as_ref(), file, mark.as_ref());
        // "The hub logs why and ignores the file": once per reason, not once a minute.
        if choice.file_refused != seen.reported {
            if let Some(why) = &choice.file_refused {
                tracing::warn!(%why, "the template bundle file is ignored");
            }
            seen.reported.clone_from(&choice.file_refused);
        }
        if let Ok(loaded) = &choice.serve
            && mark.as_ref().is_none_or(|m| loaded.version() > m.bundle_version)
        {
            self.raise_mark(loaded).await?;
        }
        let mut current = inner.current.write().unwrap_or_else(PoisonError::into_inner);
        if let Err(why) = &choice.serve
            && current.as_ref().err() != Some(why)
        {
            tracing::warn!(%why, "the hub serves no template");
        }
        *current = choice.serve;
        Ok(())
    }

    /// The step that makes a higher bundle current (H2 §7.6 "High-water mark"): the mark and the audit event, in one
    /// transaction.
    async fn raise_mark(&self, loaded: &Loaded) -> Result<(), StoreError> {
        let inner = &self.inner;
        let mut tx = store::begin_immediate(&inner.db).await?;
        let now = inner.clock.now();
        let to = Mark {
            bundle_version: loaded.version(),
            sha256: loaded.sha256.clone(),
        };
        if store::templates::raise_mark(&mut tx, &to, now).await?
            && let Some(account_id) = inner.owner_account
        {
            let mut detail = serde_json::Map::new();
            detail.insert("bundle_version".into(), loaded.version().into());
            detail.insert("source".into(), loaded.source.as_str().into());
            let event = NewEvent::new(
                AuditKind::TemplateBundleLoaded,
                None,
                Some(loaded.version().to_string()),
                detail,
            );
            store::audit::append(&mut tx, account_id, &event, now).await?;
        }
        tx.commit().await?;
        tracing::info!(
            bundle_version = loaded.version(),
            source = loaded.source.as_str(),
            "template bundle loaded"
        );
        Ok(())
    }

    /// Reloads every [`RELOAD_INTERVAL`] in a task. Abort the handle to stop it.
    #[must_use]
    pub fn spawn_reload(&self) -> JoinHandle<()> {
        let this = self.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(RELOAD_INTERVAL);
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            // The first tick completes at once, and the store loaded when it was opened.
            tick.tick().await;
            loop {
                tick.tick().await;
                if let Err(e) = this.reload().await {
                    tracing::warn!(error = %e, "cannot reload the template bundle");
                }
            }
        })
    }
}

impl TemplateCatalog for TemplateStore {
    fn singleton_ids(&self) -> Vec<String> {
        self.served().map_or_else(
            |_| Vec::new(),
            |loaded| {
                loaded
                    .bundle
                    .templates
                    .iter()
                    .filter(|t| t.info.singleton)
                    .map(|t| t.info.id.clone())
                    .collect()
            },
        )
    }

    fn allowed_routes(&self, template_id: &str) -> Vec<AllowedRoute> {
        self.served()
            .ok()
            .and_then(|loaded| loaded.template(template_id).map(|t| t.allowed_routes.clone()))
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn loaded(version: u64, sha: &str, source: Source) -> Arc<Loaded> {
        Arc::new(Loaded {
            bundle: Bundle::new(version, "0.1.0", Vec::new()),
            sha256: sha.to_string(),
            source,
        })
    }

    fn mark(version: u64, sha: &str) -> Mark {
        Mark {
            bundle_version: version,
            sha256: sha.to_string(),
        }
    }

    fn served(choice: &Choice) -> Option<(u64, Source)> {
        choice.serve.as_ref().ok().map(|l| (l.version(), l.source))
    }

    #[test]
    fn the_embedded_bundle_is_served_when_there_is_no_file() {
        let embedded = loaded(3, "e", Source::Embedded);
        for m in [None, Some(mark(2, "x")), Some(mark(3, "e"))] {
            let choice = choose(Some(&embedded), None, m.as_ref());
            assert_eq!(served(&choice), Some((3, Source::Embedded)), "{m:?}");
            assert_eq!(choice.file_refused, None);
        }
    }

    #[test]
    fn a_file_is_used_only_above_the_embedded_bundle() {
        let embedded = loaded(3, "e", Source::Embedded);
        for version in [1, 3] {
            let choice = choose(Some(&embedded), Some(Ok(loaded(version, "f", Source::File))), None);
            assert_eq!(served(&choice), Some((3, Source::Embedded)));
            assert_eq!(
                choice.file_refused,
                Some(Refused::NotAboveEmbedded { version, embedded: 3 })
            );
        }
        let choice = choose(Some(&embedded), Some(Ok(loaded(4, "f", Source::File))), None);
        assert_eq!(served(&choice), Some((4, Source::File)));
        assert_eq!(choice.file_refused, None);
    }

    #[test]
    fn a_file_below_the_mark_is_a_rollback_and_nothing_older_is_served() {
        let embedded = loaded(1, "e", Source::Embedded);
        let m = mark(5, "five");
        let choice = choose(Some(&embedded), Some(Ok(loaded(4, "four", Source::File))), Some(&m));
        assert_eq!(choice.file_refused, Some(Refused::BelowMark { version: 4, mark: 5 }));
        // Neither the older file nor the older embedded bundle.
        let why = choice.serve.unwrap_err();
        assert!(why.contains("version 5") && why.contains("version 1"), "{why}");
    }

    #[test]
    fn at_the_marks_version_only_the_recorded_bundle_loads() {
        let embedded = loaded(1, "e", Source::Embedded);
        let m = mark(5, "five");
        let same = choose(Some(&embedded), Some(Ok(loaded(5, "five", Source::File))), Some(&m));
        assert_eq!(served(&same), Some((5, Source::File)));
        let other = choose(Some(&embedded), Some(Ok(loaded(5, "evil", Source::File))), Some(&m));
        assert_eq!(other.file_refused, Some(Refused::NotTheMarkedBundle { version: 5 }));
        assert!(other.serve.is_err());
        // Above the mark, any validly signed bundle loads.
        let newer = choose(Some(&embedded), Some(Ok(loaded(6, "six", Source::File))), Some(&m));
        assert_eq!(served(&newer), Some((6, Source::File)));
    }

    #[test]
    fn with_the_file_at_the_mark_gone_or_refused_nothing_is_served() {
        let embedded = loaded(1, "e", Source::Embedded);
        let m = mark(5, "five");
        assert!(choose(Some(&embedded), None, Some(&m)).serve.is_err());
        let refused = choose(Some(&embedded), Some(Err(Refused::NoSignature)), Some(&m));
        assert!(refused.serve.is_err());
        assert_eq!(refused.file_refused, Some(Refused::NoSignature));
    }

    #[test]
    fn a_refused_file_leaves_the_embedded_bundle_served() {
        let embedded = loaded(2, "e", Source::Embedded);
        let m = mark(2, "e");
        let choice = choose(Some(&embedded), Some(Err(Refused::NoKey)), Some(&m));
        assert_eq!(served(&choice), Some((2, Source::Embedded)));
        assert_eq!(choice.file_refused, Some(Refused::NoKey));
    }

    #[test]
    fn a_hub_upgrade_serves_its_embedded_bundle_over_an_older_file() {
        // The hub was upgraded: its embedded bundle (7) is above the mark (5) and above the file (5).
        let embedded = loaded(7, "seven", Source::Embedded);
        let m = mark(5, "five");
        let choice = choose(Some(&embedded), Some(Ok(loaded(5, "five", Source::File))), Some(&m));
        assert_eq!(served(&choice), Some((7, Source::Embedded)));
        assert_eq!(
            choice.file_refused,
            Some(Refused::NotAboveEmbedded {
                version: 5,
                embedded: 7
            })
        );
    }

    #[test]
    fn without_an_embedded_bundle_only_a_valid_file_is_served() {
        assert!(choose(None, None, None).serve.is_err());
        let choice = choose(None, Some(Ok(loaded(1, "f", Source::File))), None);
        assert_eq!(served(&choice), Some((1, Source::File)));
    }

    #[test]
    fn the_embedded_bundle_of_this_build_is_a_valid_bundle_with_the_shipped_templates() {
        let trust = Trust::built_in();
        let bundle: Bundle = serde_json::from_slice(&trust.embedded).unwrap();
        let loaded = admit(bundle, &trust.embedded, &trust.hub_version, Mode::Dev, Source::Embedded).unwrap();
        assert!(loaded.version() >= 1);
        let chat = loaded.template("private-chat").unwrap();
        assert!(chat.info.singleton);
        assert_eq!(chat.allowed_routes.len(), 2);
        assert!(loaded.template("transcribe").is_some());
        assert_eq!(loaded.sha256.len(), 64);
    }

    #[test]
    fn a_bundle_for_a_newer_hub_is_refused() {
        let hub = semver::Version::new(0, 1, 0);
        let trust = Trust::built_in();
        let mut bundle: Bundle = serde_json::from_slice(&trust.embedded).unwrap();
        bundle.min_hub_version = "0.2.0".into();
        let refused = admit(bundle.clone(), b"x", &hub, Mode::Dev, Source::File).unwrap_err();
        assert_eq!(
            refused,
            Refused::HubTooOld {
                needs: "0.2.0".into(),
                hub: "0.1.0".into()
            }
        );
        bundle.min_hub_version = "0.1.0".into();
        assert!(admit(bundle, b"x", &hub, Mode::Dev, Source::File).is_ok());
    }

    #[test]
    fn the_spec_reload_interval() {
        assert_eq!(RELOAD_INTERVAL, std::time::Duration::from_secs(60));
    }
}
