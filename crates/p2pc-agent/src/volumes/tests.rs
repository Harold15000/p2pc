// SPDX-License-Identifier: Apache-2.0

//! Tests of the volume store on real directories in a temporary data dir (H2 §11.3, SI-H2-9). No container runtime:
//! "Podman confirmed the container gone" is the caller's [`VolumeStore::release`], and a restart is a second store
//! opened on the same directory. Time is a settable clock.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use p2pc_proto::protocol::LeaseRejectReason as R;
use serde_json::json;
use tempfile::TempDir;

use super::*;
use crate::sandbox::disk::DiskSpace;

// ---------------------------------------------------------------------------------------------------------------
// Fixtures

#[derive(Debug)]
struct TestClock(Mutex<OffsetDateTime>);

impl Clock for TestClock {
    fn now(&self) -> OffsetDateTime {
        *self.0.lock().unwrap()
    }
}

impl TestClock {
    fn advance(&self, by: time::Duration) {
        *self.0.lock().unwrap() += by;
    }
}

fn t0() -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(1_800_000_000).unwrap()
}

struct Fx {
    data: TempDir,
    /// A directory outside the data dir, for the targets of planted links.
    outside: TempDir,
    owner: AccountId,
    clock: Arc<TestClock>,
}

impl Fx {
    fn new() -> Self {
        Self {
            data: tempfile::tempdir().unwrap(),
            outside: tempfile::tempdir().unwrap(),
            owner: AccountId::generate(),
            clock: Arc::new(TestClock(Mutex::new(t0()))),
        }
    }

    fn config(&self, budget_mb: u64) -> StoreConfig {
        StoreConfig {
            data_dir: self.data.path().to_path_buf(),
            owner: self.owner,
            budget_mb,
            retention_days: DEFAULT_RETENTION_DAYS,
            entry_budget: 10_000,
            clock: self.clock.clone(),
        }
    }

    /// A store with room for everything the tests mount (1 TiB).
    fn store(&self) -> VolumeStore {
        VolumeStore::open(self.config(1 << 20)).unwrap()
    }

    fn account_dir(&self) -> PathBuf {
        self.data.path().join(VOLUMES_DIR).join(self.owner.to_string())
    }

    fn volume_dir(&self, name: &str) -> PathBuf {
        self.account_dir().join(dir_name(name))
    }

    fn data_of(&self, name: &str) -> PathBuf {
        self.volume_dir(name).join(DATA_DIR)
    }

    fn meta(&self, name: &str) -> serde_json::Value {
        serde_json::from_slice(&fs::read(self.volume_dir(name).join(META_FILE)).unwrap()).unwrap()
    }

    /// Mounts the volume once and lets it go, as a service that ran and ended: the volume exists, unused.
    fn used_once(&self, store: &VolumeStore, name: &str, max_mb: u64) -> PathBuf {
        let lease = LeaseId::generate();
        mount(store, lease, &self.owner, &service(&[(name, "/volumes/v", max_mb)])).unwrap();
        assert!(store.release(&lease, 1));
        self.data_of(name)
    }

    /// A file outside the volume, and what must still be true of it afterwards.
    fn outside_file(&self, name: &str) -> (PathBuf, Facts) {
        let path = self.outside.path().join(name);
        fs::write(&path, b"the owner's file").unwrap();
        let facts = Facts::of(&path);
        (path, facts)
    }

    /// Every path under the data dir.
    fn entries(&self) -> Vec<PathBuf> {
        walk(self.data.path())
    }
}

/// What a planted link's target must keep: its owner, its mode, its content's size and its place.
#[derive(Debug, PartialEq, Eq)]
struct Facts {
    uid: u32,
    gid: u32,
    mode: u32,
    len: u64,
    ino: u64,
    nlink: u64,
}

impl Facts {
    fn of(path: &Path) -> Self {
        let m = fs::symlink_metadata(path).unwrap();
        Self {
            uid: m.uid(),
            gid: m.gid(),
            mode: m.mode(),
            len: m.len(),
            ino: m.ino(),
            nlink: m.nlink(),
        }
    }
}

fn walk(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for e in fs::read_dir(dir).unwrap().flatten() {
        out.push(e.path());
        if e.file_type().unwrap().is_dir() {
            out.extend(walk(&e.path()));
        }
    }
    out
}

fn mode(path: &Path) -> u32 {
    fs::symlink_metadata(path).unwrap().mode() & 0o7777
}

fn volumes_json(volumes: &[(&str, &str, u64)]) -> serde_json::Value {
    volumes
        .iter()
        .map(|(name, mount, max_mb)| json!({"name": name, "mount": mount, "max_mb": max_mb}))
        .collect()
}

/// A service job with `volumes` as `(name, mount, max_mb)`.
fn service(volumes: &[(&str, &str, u64)]) -> JobSpec {
    serde_json::from_value(json!({
        "kind": "service",
        "image": "docker.io/library/busybox:1.36.1",
        "command": ["sleep", "3600"],
        "resources": {"cpu": 1, "memory_mb": 256, "disk_mb": 1024},
        "service": {"ports": [{"port": 8080, "name": "web"}]},
        "volumes": volumes_json(volumes),
    }))
    .unwrap()
}

/// A batch job with `volumes`; with `template`, the job of a launch of that template.
fn batch(template: Option<&str>, volumes: &[(&str, &str, u64)]) -> JobSpec {
    let mut job = json!({
        "image": "docker.io/library/busybox:1.36.1",
        "command": ["true"],
        "resources": {"cpu": 1, "memory_mb": 256, "disk_mb": 1024},
        "volumes": volumes_json(volumes),
    });
    if let Some(id) = template {
        job["template"] = json!({"id": id, "version": 1});
    }
    serde_json::from_value(job).unwrap()
}

/// Admission, then the lock and the check, as the executor and the driver do for one lease.
fn mount(store: &VolumeStore, lease: LeaseId, account: &AccountId, job: &JobSpec) -> Result<Vec<Mount>, String> {
    store
        .reserve(lease, 1, account, job)
        .map_err(|reason| format!("rejected: {reason}"))?;
    store.lock_and_check(&lease, 1).map_err(|e| e.to_string())
}

fn fifo(path: &Path) {
    rustix::fs::mknodat(
        rustix::fs::CWD,
        path,
        rustix::fs::FileType::Fifo,
        rustix::fs::Mode::from_raw_mode(0o600),
        0,
    )
    .unwrap();
}

// ---------------------------------------------------------------------------------------------------------------
// Layout: created by the agent, per account, named by a hash

#[test]
fn a_volume_directory_is_named_by_the_hash_of_its_name() {
    // The first 32 hex digits of SHA-256 (H2 §11.3 "Layout").
    assert_eq!(dir_name("models"), "8edcc26c0f6c7256a71a8ede6b954ad9");
    assert_eq!(dir_name("tpl:private-chat/models"), "5faf9d87fa1a7df25ef30f96a1d2ffba");
    for hostile in ["../../etc", "/etc/passwd", "a/b", "..", "", "x\0y"] {
        let dir = dir_name(hostile);
        assert!(is_dir_name(&dir), "{hostile:?} -> {dir}");
    }
    assert!(!is_dir_name("8EDCC26C0F6C7256A71A8EDE6B954AD9"));
    assert!(!is_dir_name(".."));
    assert!(!is_dir_name("8edcc26c0f6c7256a71a8ede6b954ad"));
}

#[test]
fn the_agent_creates_the_chain_0700_and_records_the_holder_before_the_mount() {
    let fx = Fx::new();
    let store = crate::identity::with_umask(0o022, || fx.store());
    let lease = LeaseId::generate();
    let job = service(&[("models", "/volumes/models", 2048), ("cache", "/volumes/cache/x", 64)]);
    let mounts = crate::identity::with_umask(0o022, || mount(&store, lease, &fx.owner, &job)).unwrap();

    // The host path is the agent's own directory, in the order of the job's volumes.
    assert_eq!(
        mounts,
        [
            Mount {
                name: "models".into(),
                host: fx.data_of("models"),
                mount: "/volumes/models".into(),
                max_bytes: 2048 * MIB,
            },
            Mount {
                name: "cache".into(),
                host: fx.data_of("cache"),
                mount: "/volumes/cache/x".into(),
                max_bytes: 64 * MIB,
            },
        ]
    );
    assert_eq!(
        fx.data_of("models"),
        fx.data
            .path()
            .join("volumes")
            .join(fx.owner.to_string())
            .join("8edcc26c0f6c7256a71a8ede6b954ad9")
            .join("data")
    );
    // 0700 at every level only the agent writes, whatever the umask; `data/`, which is mounted, 0755 like H1's
    // mounted job directories; `meta.json` 0600.
    for dir in [
        fx.data.path().join("volumes"),
        fx.account_dir(),
        fx.volume_dir("models"),
    ] {
        assert!(fs::symlink_metadata(&dir).unwrap().is_dir());
        assert_eq!(mode(&dir), 0o700, "{}", dir.display());
    }
    assert_eq!(mode(&fx.data_of("models")), 0o755);
    assert_eq!(mode(&fx.volume_dir("models").join(META_FILE)), 0o600);
    // `meta.json`: name, created, last used, and the holder (lease id and container name).
    let meta = fx.meta("models");
    assert_eq!(meta["name"], "models");
    assert_eq!(meta["created_at"], "2027-01-15T08:00:00Z");
    assert_eq!(meta["last_used_at"], "2027-01-15T08:00:00Z");
    assert_eq!(meta["max_mb"], 2048);
    assert_eq!(meta["holder"]["lease_id"], lease.to_string());
    assert_eq!(meta["holder"]["container"], format!("p2pc-{lease}"));
    // Nothing but the two volumes exists, and no temporary file is left.
    let names: Vec<String> = fs::read_dir(fx.volume_dir("models"))
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    assert_eq!(names.len(), 2, "{names:?}");
    assert_eq!(fs::read_dir(fx.account_dir()).unwrap().count(), 2);
}

/// SI-H2-9: names with `/`, `..` and NUL, and every other name or path from the JobSpec that could reach the host,
/// are refused as `invalid_job`, and nothing is created for them.
#[test]
fn a_name_or_a_path_from_the_jobspec_never_becomes_a_host_path() {
    let fx = Fx::new();
    let store = fx.store();
    let before = fx.entries();
    let too_long = "a".repeat(64);
    let bad_names = [
        "a/b",
        "..",
        "../../etc",
        "/etc",
        "x\0y",
        "",
        ".hidden",
        "Models",
        "a b",
        "tpl:private-chat/models",
        "tpl:../x",
        too_long.as_str(),
    ];
    for name in bad_names {
        let job = service(&[(name, "/volumes/v", 64)]);
        assert_eq!(
            store.reserve(LeaseId::generate(), 1, &fx.owner, &job),
            Err(R::InvalidJob),
            "name {name:?}"
        );
    }
    let bad_mounts = [
        "/etc",
        "/volumes",
        "/volumes/",
        "/volumes/../etc",
        "/volumes/a/../../etc",
        "volumes/a",
        "/volumesx/a",
        "/volumes/a\0b",
        // Podman's `-v` separators: these would add an option or a path to the argument.
        "/volumes/a:ro",
        "/volumes/a:/etc",
        "/volumes/a,z",
        "/volumes/a:rw,U,exec",
    ];
    for path in bad_mounts {
        let job = service(&[("models", path, 64)]);
        assert_eq!(
            store.reserve(LeaseId::generate(), 1, &fx.owner, &job),
            Err(R::InvalidJob),
            "mount {path:?}"
        );
    }
    for max_mb in [0, 63, 262_145, u64::MAX] {
        let job = service(&[("models", "/volumes/v", max_mb)]);
        assert_eq!(
            store.reserve(LeaseId::generate(), 1, &fx.owner, &job),
            Err(R::InvalidJob),
            "max_mb {max_mb}"
        );
    }
    // Five volumes, and one name twice.
    let five: Vec<(String, String)> = (0..5).map(|i| (format!("v{i}"), format!("/volumes/v{i}"))).collect();
    let five: Vec<(&str, &str, u64)> = five.iter().map(|(n, m)| (n.as_str(), m.as_str(), 64)).collect();
    assert_eq!(
        store.reserve(LeaseId::generate(), 1, &fx.owner, &service(&five)),
        Err(R::InvalidJob)
    );
    let twice = service(&[("v", "/volumes/a", 64), ("v", "/volumes/b", 64)]);
    assert_eq!(
        store.reserve(LeaseId::generate(), 1, &fx.owner, &twice),
        Err(R::InvalidJob)
    );
    assert_eq!(fx.entries(), before, "nothing was created for a refused job");
    assert!(store.report_now().volumes.is_empty());
}

// ---------------------------------------------------------------------------------------------------------------
// Who may mount

/// SI-H2-9: only a service or a template job of the enrolled account.
#[test]
fn only_a_service_or_a_template_job_of_the_account_mounts_a_volume() {
    let fx = Fx::new();
    let store = fx.store();
    let v: &[(&str, &str, u64)] = &[("data", "/volumes/data", 64)];
    // A batch job that is not a template launch.
    assert_eq!(
        store.reserve(LeaseId::generate(), 1, &fx.owner, &batch(None, v)),
        Err(R::InvalidJob)
    );
    // A lease of another account, service or not: its directory is never even derived.
    let other = AccountId::generate();
    assert_eq!(
        store.reserve(LeaseId::generate(), 1, &other, &service(v)),
        Err(R::NotOwner)
    );
    assert!(!fx.data.path().join(VOLUMES_DIR).join(other.to_string()).exists());
    assert!(!fx.account_dir().exists(), "nothing was created");

    // A service, and a batch job of a template, both of the account.
    let service_lease = LeaseId::generate();
    mount(&store, service_lease, &fx.owner, &service(v)).unwrap();
    let template_lease = LeaseId::generate();
    let tpl = batch(Some("transcribe"), &[("tpl:transcribe/models", "/volumes/models", 64)]);
    let mounts = mount(&store, template_lease, &fx.owner, &tpl).unwrap();
    assert_eq!(mounts[0].host, fx.data_of("tpl:transcribe/models"));
    assert_eq!(fx.meta("tpl:transcribe/models")["name"], "tpl:transcribe/models");

    // `tpl:` volumes only for a job of that template (H2 §11.3 "Namespace").
    let wrong = batch(
        Some("private-chat"),
        &[("tpl:transcribe/models", "/volumes/models", 64)],
    );
    assert_eq!(
        store.reserve(LeaseId::generate(), 1, &fx.owner, &wrong),
        Err(R::InvalidJob)
    );
    let plain_service = service(&[("tpl:transcribe/models", "/volumes/models", 64)]);
    assert_eq!(
        store.reserve(LeaseId::generate(), 1, &fx.owner, &plain_service),
        Err(R::InvalidJob)
    );
    // A job without volumes takes nothing and is never refused here.
    assert_eq!(store.reserve(LeaseId::generate(), 1, &other, &batch(None, &[])), Ok(()));
}

// ---------------------------------------------------------------------------------------------------------------
// One holder at a time

#[test]
fn a_volume_has_one_holder_until_its_container_is_confirmed_gone() {
    let fx = Fx::new();
    let store = fx.store();
    let job = service(&[("models", "/volumes/models", 64)]);
    let (first, second) = (LeaseId::generate(), LeaseId::generate());

    // Held from admission on, before anything is written.
    assert_eq!(store.reserve(first, 1, &fx.owner, &job), Ok(()));
    assert_eq!(store.reserve(second, 1, &fx.owner, &job), Err(R::InsufficientCapacity));
    // The same lease again changes nothing; another epoch of it is another holder.
    assert_eq!(store.reserve(first, 1, &fx.owner, &job), Ok(()));
    assert_eq!(store.reserve(first, 2, &fx.owner, &job), Err(R::InsufficientCapacity));
    // A lease that holds nothing has nothing to lock.
    assert!(matches!(
        store.lock_and_check(&second, 1),
        Err(VolumeError::NotReserved)
    ));

    store.lock_and_check(&first, 1).unwrap();
    assert_eq!(store.reserve(second, 1, &fx.owner, &job), Err(R::InsufficientCapacity));
    assert_eq!(store.report_now().volumes[0].in_use_by, Some(first));
    // Once written, giving the reservation back does nothing: only a confirmed removal frees the volume.
    store.cancel_reservation(&first, 1);
    assert_eq!(store.reserve(second, 1, &fx.owner, &job), Err(R::InsufficientCapacity));

    // The lease ended while `podman rm` failed: the lock stays, and the volume is reported in use by that lease.
    store.orphan(&first, 1);
    assert_eq!(store.orphaned(), [first]);
    assert_eq!(store.reserve(second, 1, &fx.owner, &job), Err(R::InsufficientCapacity));
    assert_eq!(store.report_now().volumes[0].in_use_by, Some(first));
    assert_eq!(fx.meta("models")["holder"]["lease_id"], first.to_string());

    // Podman confirmed the container gone.
    fx.clock.advance(time::Duration::hours(2));
    assert!(store.release_orphaned(&first));
    assert!(store.orphaned().is_empty());
    assert_eq!(fx.meta("models").get("holder"), None);
    assert_eq!(fx.meta("models")["last_used_at"], "2027-01-15T10:00:00Z");
    assert_eq!(store.report_now().volumes[0].in_use_by, None);
    assert!(!store.release_orphaned(&first), "nothing left to release");
    mount(&store, second, &fx.owner, &job).unwrap();
    assert_eq!(fx.meta("models")["holder"]["lease_id"], second.to_string());
    assert_eq!(fx.meta("models")["created_at"], "2027-01-15T08:00:00Z");
}

#[test]
fn a_reservation_that_was_never_written_is_given_back() {
    let fx = Fx::new();
    let store = fx.store();
    let job = service(&[("models", "/volumes/models", 64)]);
    let (first, second) = (LeaseId::generate(), LeaseId::generate());
    // The lease was admitted, then refused before `prepare` got anywhere.
    assert_eq!(store.reserve(first, 1, &fx.owner, &job), Ok(()));
    store.cancel_reservation(&first, 1);
    assert_eq!(store.reserve(second, 1, &fx.owner, &job), Ok(()));
    // Or its run ended before the lock: no container was created for it, so there is nothing to confirm.
    store.orphan(&second, 1);
    assert!(store.orphaned().is_empty());
    assert_eq!(store.reserve(first, 1, &fx.owner, &job), Ok(()));
    assert!(store.release(&first, 1));
    assert!(
        !fx.account_dir().exists(),
        "a volume that was never locked leaves nothing on disk"
    );
    assert!(store.report_now().volumes.is_empty());
}

/// SI-H2-9: the lock is persisted. An agent restarted while a container may still hold the volume treats it as held:
/// no lease gets it, and nothing is walked or mounted, until the container is confirmed gone.
#[test]
fn the_lock_survives_an_agent_restart() {
    let fx = Fx::new();
    let job = service(&[("models", "/volumes/models", 64)]);
    let held_by = LeaseId::generate();
    {
        let store = fx.store();
        mount(&store, held_by, &fx.owner, &job).unwrap();
        // The agent dies here: no release.
    }
    // What the old container could do meanwhile: plant a link. A walk would refuse it, so a refusal for any other
    // reason shows that nothing was walked.
    symlink("/etc", fx.data_of("models").join("planted")).unwrap();

    let restarted = fx.store();
    assert_eq!(restarted.orphaned(), [held_by]);
    let report = restarted.report_now();
    assert_eq!(report.volumes.len(), 1);
    assert_eq!(report.volumes[0].in_use_by, Some(held_by));
    let next = LeaseId::generate();
    assert_eq!(
        restarted.reserve(next, 1, &fx.owner, &job),
        Err(R::InsufficientCapacity)
    );
    assert!(matches!(
        restarted.lock_and_check(&next, 1),
        Err(VolumeError::NotReserved)
    ));
    assert!(matches!(
        restarted.delete("models"),
        Err(DeleteError::InUse(Some(lease))) if lease == held_by
    ));
    assert_eq!(restarted.collect_garbage(), 0);
    assert_eq!(fx.meta("models")["holder"]["lease_id"], held_by.to_string());

    // A second restart changes nothing: the lock is still on disk.
    let again = fx.store();
    assert_eq!(again.orphaned(), [held_by]);
    // The sweep removed the container and Podman reports it absent: only now is the volume free, and only now is
    // it walked (and refused, for the link).
    assert!(again.release_orphaned(&held_by));
    assert_eq!(fx.meta("models").get("holder"), None);
    let err = mount(&again, next, &fx.owner, &job).unwrap_err();
    assert!(err.contains("a symbolic link"), "{err}");
    assert!(fx.store().orphaned().contains(&next), "the new lock is on disk too");
}

/// Defence in depth for the one-holder lock. An orphaned hold is held against everybody, its own lease and epoch
/// included: its container may still exist, and every epoch of a lease shares the container's name. The run's own
/// `release` and `orphan` touch only that run's holds, and the sweep's release only what is orphaned.
#[test]
fn an_orphaned_hold_is_held_against_its_own_lease_and_only_the_sweep_frees_it() {
    let fx = Fx::new();
    let store = fx.store();
    let models = service(&[("models", "/volumes/models", 64)]);
    let other = service(&[("other", "/volumes/other", 64)]);
    let holder = |name: &str| {
        let report = store.report_now();
        report.volumes.iter().find(|v| v.name == name).and_then(|v| v.in_use_by)
    };
    let lease = LeaseId::generate();
    mount(&store, lease, &fx.owner, &models).unwrap();
    // Its run ended while `podman rm` failed.
    store.orphan(&lease, 1);
    // What the container can still do; a walk would find it.
    symlink("/etc", fx.data_of("models").join("planted")).unwrap();

    // The same lease and epoch offered again (the executor no longer remembers its answer): rejected, and nothing
    // of the volume is walked, measured or mounted.
    assert_eq!(
        store.reserve(lease, 1, &fx.owner, &models),
        Err(R::InsufficientCapacity)
    );
    assert!(matches!(store.lock_and_check(&lease, 1), Err(VolumeError::NotReserved)));
    assert!(store.usage(&lease, 1).is_empty());
    // Nor may the lease take another volume, under this epoch or a new one: its container would have the orphan's
    // name.
    for epoch in [1, 2] {
        assert_eq!(
            store.reserve(lease, epoch, &fx.owner, &other),
            Err(R::InsufficientCapacity),
            "epoch {epoch}"
        );
    }
    assert_eq!(holder("other"), None, "nothing was taken");
    // Nothing a run does for itself frees or changes an orphaned hold, whatever epoch it names.
    assert!(!store.release(&lease, 1));
    assert!(!store.release(&lease, 2));
    store.orphan(&lease, 2);
    store.cancel_reservation(&lease, 1);
    assert_eq!(store.orphaned(), [lease]);
    assert_eq!(holder("models"), Some(lease));
    assert_eq!(fx.meta("models")["holder"]["lease_id"], lease.to_string());

    // Another lease runs meanwhile. The sweep's release is for orphans only: it never frees a run in progress.
    let running = LeaseId::generate();
    mount(&store, running, &fx.owner, &other).unwrap();
    assert!(!store.release_orphaned(&running));
    assert_eq!(holder("other"), Some(running));
    assert_eq!(fx.meta("other")["holder"]["lease_id"], running.to_string());
    // And a run's release is for its own epoch only.
    assert!(!store.release(&running, 2));
    store.orphan(&running, 2);
    assert_eq!(store.orphaned(), [lease], "another epoch's orphan() changed nothing");
    assert_eq!(holder("other"), Some(running));

    // Podman confirmed the orphan's container gone: the sweep frees it, and only it.
    assert!(store.release_orphaned(&lease));
    assert!(store.orphaned().is_empty());
    assert_eq!(holder("models"), None);
    assert_eq!(holder("other"), Some(running));
    assert!(store.release(&running, 1));
    assert_eq!(holder("other"), None);
    // Now the lease id is free to take a volume again, and the volume is walked.
    let err = mount(&store, lease, &fx.owner, &models).unwrap_err();
    assert!(err.contains("a symbolic link"), "{err}");
}

/// While one epoch of a lease holds a volume, another epoch of it takes none, on any volume: the two would share
/// one container name, so "the container is gone" could not be told for either.
#[test]
fn a_lease_holds_volumes_under_one_epoch_at_a_time() {
    let fx = Fx::new();
    let store = fx.store();
    let lease = LeaseId::generate();
    mount(&store, lease, &fx.owner, &service(&[("a", "/volumes/a", 64)])).unwrap();
    let b = service(&[("b", "/volumes/b", 64)]);
    assert_eq!(store.reserve(lease, 2, &fx.owner, &b), Err(R::InsufficientCapacity));
    // The same epoch may: it is the same run (a job's volumes are taken together; this is the idempotent path).
    assert_eq!(
        store.reserve(lease, 1, &fx.owner, &service(&[("a", "/volumes/a", 64)])),
        Ok(())
    );
    assert!(store.release(&lease, 1));
    assert_eq!(store.reserve(lease, 2, &fx.owner, &b), Ok(()));
}

// ---------------------------------------------------------------------------------------------------------------
// The check before every mount

/// What one planted entry does to the next mount.
fn refused_for(plant: impl FnOnce(&Fx, &Path)) -> (Fx, VolumeStore, String) {
    let fx = Fx::new();
    let store = fx.store();
    let data = fx.used_once(&store, "models", 64);
    fs::create_dir(data.join("blobs")).unwrap();
    fs::write(data.join("blobs/model.gguf"), b"weights").unwrap();
    plant(&fx, &data);
    let lease = LeaseId::generate();
    let job = service(&[("models", "/volumes/models", 64)]);
    store.reserve(lease, 1, &fx.owner, &job).unwrap();
    let err = store.lock_and_check(&lease, 1).unwrap_err();
    assert!(err.is_unsafe(), "{err}");
    // The lock is the lease's: a refused volume is not handed to anybody else meanwhile.
    assert_eq!(
        store.reserve(LeaseId::generate(), 1, &fx.owner, &job),
        Err(R::InsufficientCapacity)
    );
    assert!(store.release(&lease, 1));
    (fx, store, err.to_string())
}

/// SI-H2-9: a symlink to a file and to a directory outside the volume, a FIFO and a hard-linked file, planted in a
/// volume before it is mounted again, each refuse the mount; the link's target keeps its owner; the volume is kept,
/// not repaired.
#[test]
fn a_planted_link_or_special_file_refuses_the_next_mount() {
    // A symbolic link to a file outside the volume.
    let (fx, _store, err) = refused_for(|fx, data| {
        let (target, _) = fx.outside_file("secret");
        symlink(target, data.join("link")).unwrap();
    });
    assert!(err.contains("a symbolic link at \"link\""), "{err}");
    let target = fx.outside.path().join("secret");
    assert_eq!(fs::read(&target).unwrap(), b"the owner's file");
    assert!(
        fs::symlink_metadata(fx.data_of("models").join("link"))
            .unwrap()
            .is_symlink(),
        "the volume is kept as it is, for the owner to delete"
    );

    // A symbolic link to a directory outside the volume, nested in a subdirectory.
    let (fx, _store, err) = refused_for(|fx, data| {
        let (_, _) = fx.outside_file("in-dir");
        symlink(fx.outside.path(), data.join("blobs/dir-link")).unwrap();
    });
    assert!(err.contains("a symbolic link at \"blobs/dir-link\""), "{err}");
    assert_eq!(
        fs::read_dir(fx.outside.path()).unwrap().count(),
        1,
        "nothing was created or removed in the directory the link points at"
    );

    // A dangling link, and a link to the volume's own file, are links too.
    let (_, _, err) = refused_for(|_, data| symlink("/nonexistent/x", data.join("dangling")).unwrap());
    assert!(err.contains("a symbolic link"), "{err}");
    let (_, _, err) = refused_for(|_, data| symlink("blobs/model.gguf", data.join("inner")).unwrap());
    assert!(err.contains("a symbolic link"), "{err}");

    // A FIFO, and a socket.
    let (_, _, err) = refused_for(|_, data| fifo(&data.join("blobs/pipe")));
    assert!(
        err.contains("neither a directory nor a regular file at \"blobs/pipe\""),
        "{err}"
    );
    let (_, _, err) = refused_for(|_, data| {
        rustix::fs::mknodat(
            rustix::fs::CWD,
            data.join("sock"),
            rustix::fs::FileType::Socket,
            rustix::fs::Mode::from_raw_mode(0o600),
            0,
        )
        .unwrap();
    });
    assert!(err.contains("neither a directory nor a regular file"), "{err}");

    // A regular file with a second name outside the volume: a chown through it would reach that name.
    let mut kept = None;
    let (fx, _store, err) = refused_for(|fx, data| {
        let (target, _) = fx.outside_file("hard");
        fs::hard_link(&target, data.join("blobs/hard")).unwrap();
        kept = Some(Facts::of(&target));
    });
    assert!(err.contains("more than one hard link at \"blobs/hard\""), "{err}");
    assert_eq!(
        Facts::of(&fx.outside.path().join("hard")),
        kept.unwrap(),
        "the other name keeps its owner and its mode"
    );
    // Two names inside the volume are refused as well: the rule is the link count.
    let (_, _, err) = refused_for(|_, data| {
        fs::hard_link(data.join("blobs/model.gguf"), data.join("second-name")).unwrap();
    });
    assert!(err.contains("more than one hard link"), "{err}");
}

/// The targets of the planted links are exactly as they were: owner, mode, size, link count.
#[test]
fn the_target_of_a_planted_link_keeps_its_owner() {
    let mut before = None;
    let (fx, store, _) = refused_for(|fx, data| {
        let (file, facts) = fx.outside_file("target");
        symlink(&file, data.join("to-file")).unwrap();
        symlink(fx.outside.path(), data.join("to-dir")).unwrap();
        before = Some((facts, Facts::of(fx.outside.path())));
    });
    let (file, dir) = before.unwrap();
    assert_eq!(Facts::of(&fx.outside.path().join("target")), file);
    assert_eq!(Facts::of(fx.outside.path()), dir);
    // Refused again at every mount, until the owner deletes the volume.
    let job = service(&[("models", "/volumes/models", 64)]);
    assert!(mount(&store, LeaseId::generate(), &fx.owner, &job).is_err());
}

#[test]
fn a_tree_over_the_entry_budget_or_too_deep_refuses_the_mount() {
    let fx = Fx::new();
    let mut cfg = fx.config(1024);
    cfg.entry_budget = 10;
    let store = VolumeStore::open(cfg).unwrap();
    let data = fx.used_once(&store, "models", 64);
    for i in 0..10 {
        fs::write(data.join(i.to_string()), b"").unwrap();
    }
    let job = service(&[("models", "/volumes/models", 64)]);
    let lease = LeaseId::generate();
    assert_eq!(
        mount(&store, lease, &fx.owner, &job).unwrap().len(),
        1,
        "10 entries fit"
    );
    assert!(store.release(&lease, 1));
    fs::write(data.join("one-more"), b"").unwrap();
    let err = mount(&store, LeaseId::generate(), &fx.owner, &job).unwrap_err();
    assert!(err.contains("more than 10 entries"), "{err}");

    // Deeper than the walk goes.
    let fx = Fx::new();
    let store = fx.store();
    let data = fx.used_once(&store, "models", 64);
    let mut deep = data.clone();
    for _ in 0..super::fs::MAX_DEPTH {
        deep.push("d");
    }
    std::fs::create_dir_all(&deep).unwrap();
    let err = mount(&store, LeaseId::generate(), &fx.owner, &job).unwrap_err();
    assert!(err.contains("nested deeper than 64"), "{err}");
    // One level less is fine.
    let fx = Fx::new();
    let store = fx.store();
    let data = fx.used_once(&store, "models", 64);
    let mut deep = data.clone();
    for _ in 1..super::fs::MAX_DEPTH {
        deep.push("d");
    }
    std::fs::create_dir_all(&deep).unwrap();
    mount(&store, LeaseId::generate(), &fx.owner, &job).unwrap();
}

/// SI-H2-9: a symlink replacing `data/` or `<hash>/` itself (or a level above) refuses the mount, and nothing is
/// written where it points.
#[test]
fn a_symlink_in_place_of_a_directory_of_the_chain_refuses_the_mount() {
    type Replace = fn(&Fx) -> PathBuf;
    let cases: [(&str, Replace); 4] = [
        ("data/", |fx| fx.data_of("models")),
        ("<hash>/", |fx| fx.volume_dir("models")),
        ("<account_id>/", Fx::account_dir),
        ("volumes/", |fx| fx.data.path().join(VOLUMES_DIR)),
    ];
    for (what, level) in cases {
        let fx = Fx::new();
        let store = fx.store();
        fx.used_once(&store, "models", 64);
        let path = level(&fx);
        let moved = fx.data.path().join("moved-away");
        fs::rename(&path, &moved).unwrap();
        symlink(fx.outside.path(), &path).unwrap();

        let job = service(&[("models", "/volumes/models", 64)]);
        let lease = LeaseId::generate();
        store.reserve(lease, 1, &fx.owner, &job).unwrap();
        let err = store.lock_and_check(&lease, 1).unwrap_err();
        assert!(err.is_unsafe(), "{what}: {err}");
        assert!(
            err.to_string().contains("is a symbolic link or not a directory"),
            "{what}: {err}"
        );
        assert_eq!(
            fs::read_dir(fx.outside.path()).unwrap().count(),
            0,
            "{what}: nothing was written through the link"
        );
        assert!(store.usage(&lease, 1).is_empty(), "{what}: nothing is locked");
    }
    // A regular file in the place of `data/`.
    let fx = Fx::new();
    let store = fx.store();
    let data = fx.used_once(&store, "models", 64);
    fs::remove_dir(&data).unwrap();
    fs::write(&data, b"not a directory").unwrap();
    let job = service(&[("models", "/volumes/models", 64)]);
    let err = mount(&store, LeaseId::generate(), &fx.owner, &job).unwrap_err();
    assert!(err.contains("is a symbolic link or not a directory"), "{err}");
}

#[test]
fn a_missing_chain_is_recreated_and_an_open_one_is_tightened() {
    let fx = Fx::new();
    let store = fx.store();
    let data = fx.used_once(&store, "models", 64);
    fs::write(data.join("kept"), b"x").unwrap();
    // `data/` was removed by hand: it is made again, empty.
    fs::remove_file(data.join("kept")).unwrap();
    fs::remove_dir(&data).unwrap();
    // The agent's own levels were opened up: they are 0700 again before the mount.
    fs::set_permissions(fx.volume_dir("models"), fs::Permissions::from_mode(0o755)).unwrap();
    fs::set_permissions(fx.account_dir(), fs::Permissions::from_mode(0o777)).unwrap();
    let job = service(&[("models", "/volumes/models", 64)]);
    mount(&store, LeaseId::generate(), &fx.owner, &job).unwrap();
    assert_eq!(mode(&data), 0o755, "the mounted directory, made again");
    assert_eq!(mode(&fx.volume_dir("models")), 0o700);
    assert_eq!(mode(&fx.account_dir()), 0o700);
}

/// `data/` is what is mounted, and `:U` gives it to the image's user. With rootless Podman and an image that does
/// not run as root, that user is one of the agent's subordinate UIDs, not the agent. So `data/` is 0755, as H1's
/// mounted job directories are: the agent can still open it to measure the volume and to check it before the next
/// mount. The 0700 levels above it keep every other user out.
#[test]
fn the_mounted_directory_is_0755_under_private_parents() {
    assert_eq!(super::fs::DATA_MODE, crate::sandbox::jobdir::SUBDIR_MODE);
    assert_eq!(super::fs::DIR_MODE, 0o700);
    let fx = Fx::new();
    // A tight umask must not take the bits away, as a loose one must not add any to the parents.
    let store = crate::identity::with_umask(0o077, || fx.store());
    let lease = LeaseId::generate();
    let job = service(&[("models", "/volumes/models", 64)]);
    crate::identity::with_umask(0o077, || mount(&store, lease, &fx.owner, &job)).unwrap();
    let data = fx.data_of("models");
    assert_eq!(mode(&data), 0o755);
    for private in [
        fx.volume_dir("models"),
        fx.account_dir(),
        fx.data.path().join(VOLUMES_DIR),
    ] {
        assert_eq!(mode(&private), 0o700, "{}", private.display());
    }
    // What the agent needs of a `data/` that is not its own is to read it. With no write permission at all, as on
    // a directory of another UID, the volume is still measured while it is mounted and checked before the next mount.
    fs::write(data.join("weights"), vec![1u8; 4096]).unwrap();
    fs::set_permissions(&data, fs::Permissions::from_mode(0o555)).unwrap();
    assert!(matches!(store.usage(&lease, 1)[0].used, Ok(TreeUsage::Bytes(bytes)) if bytes >= 4096));
    assert!(store.release(&lease, 1));
    let next = LeaseId::generate();
    mount(&store, next, &fx.owner, &job).unwrap();
    assert!(matches!(store.usage(&next, 1)[0].used, Ok(TreeUsage::Bytes(_))));
    // So that the temporary directory can be removed.
    fs::set_permissions(&data, fs::Permissions::from_mode(0o755)).unwrap();
}

#[test]
fn a_clean_tree_is_mounted_and_measured() {
    let fx = Fx::new();
    let store = fx.store();
    let data = fx.used_once(&store, "models", 64);
    fs::create_dir_all(data.join("blobs/sha256")).unwrap();
    fs::write(data.join("blobs/sha256/model.gguf"), vec![7u8; 300_000]).unwrap();
    fs::write(data.join("manifest.json"), b"{}").unwrap();
    let lease = LeaseId::generate();
    let job = service(&[("models", "/volumes/models", 64)]);
    mount(&store, lease, &fx.owner, &job).unwrap();
    let usage = store.usage(&lease, 1);
    assert_eq!(usage.len(), 1);
    assert_eq!(usage[0].name, "models");
    assert_eq!(usage[0].max_bytes, 64 * MIB);
    let TreeUsage::Bytes(bytes) = *usage[0].used.as_ref().unwrap() else {
        panic!("over budget")
    };
    assert!((300_000..2_000_000).contains(&bytes), "{bytes}");
    assert_eq!(store.report_now().volumes[0].size_mb, 1, "rounded up to whole MiB");
}

// ---------------------------------------------------------------------------------------------------------------
// Size

#[test]
fn the_measurement_counts_like_h1_and_fails_closed() {
    let fx = Fx::new();
    let mut cfg = fx.config(1024);
    cfg.entry_budget = 5;
    let store = VolumeStore::open(cfg).unwrap();
    let lease = LeaseId::generate();
    let job = service(&[("models", "/volumes/models", 64)]);
    mount(&store, lease, &fx.owner, &job).unwrap();
    let data = fx.data_of("models");
    let over = |store: &VolumeStore| {
        let usage = store.usage(&lease, 1).pop().unwrap();
        match usage.used {
            Ok(TreeUsage::Bytes(bytes)) => bytes > usage.max_bytes,
            Ok(TreeUsage::OverBudget) | Err(_) => true,
        }
    };
    assert!(!over(&store));
    // A sparse file counts its apparent size: 65 MiB in a 64 MiB volume.
    let sparse = fs::File::create(data.join("sparse")).unwrap();
    sparse.set_len(65 * MIB).unwrap();
    assert!(over(&store));
    sparse.set_len(1).unwrap();
    assert!(!over(&store));
    // A link planted while it runs is counted as an entry, never followed.
    symlink("/", data.join("root")).unwrap();
    assert!(!over(&store), "the link's target is not measured");
    // More entries than the budget is over the limit.
    for i in 0..5 {
        fs::write(data.join(i.to_string()), b"").unwrap();
    }
    assert!(matches!(store.usage(&lease, 1)[0].used, Ok(TreeUsage::OverBudget)));
    // A volume that cannot be read is a failed measurement, never zero bytes.
    fs::rename(fx.volume_dir("models"), fx.data.path().join("gone")).unwrap();
    assert!(store.usage(&lease, 1)[0].used.is_err());
}

// ---------------------------------------------------------------------------------------------------------------
// Budget and eviction

#[test]
fn the_budget_counts_the_volumes_other_leases_hold() {
    let fx = Fx::new();
    let store = VolumeStore::open(fx.config(1000)).unwrap();
    let a = LeaseId::generate();
    assert_eq!(
        store.reserve(a, 1, &fx.owner, &service(&[("a", "/volumes/a", 600)])),
        Ok(())
    );
    // 1000 − 600 held by another lease < 500.
    let b = LeaseId::generate();
    assert_eq!(
        store.reserve(b, 1, &fx.owner, &service(&[("b", "/volumes/b", 500)])),
        Err(R::InsufficientCapacity)
    );
    assert_eq!(
        store.reserve(b, 1, &fx.owner, &service(&[("b", "/volumes/b", 400)])),
        Ok(())
    );
    // The lease's own volumes count together.
    let c = LeaseId::generate();
    assert!(store.release(&b, 1));
    let two = service(&[("c1", "/volumes/c1", 300), ("c2", "/volumes/c2", 300)]);
    assert_eq!(store.reserve(c, 1, &fx.owner, &two), Err(R::InsufficientCapacity));
    let two = service(&[("c1", "/volumes/c1", 200), ("c2", "/volumes/c2", 200)]);
    assert_eq!(store.reserve(c, 1, &fx.owner, &two), Ok(()));
    // A volume larger than `volumes_mb` never fits.
    let d = LeaseId::generate();
    assert!(store.release(&a, 1));
    assert!(store.release(&c, 1));
    assert_eq!(
        store.reserve(d, 1, &fx.owner, &service(&[("d", "/volumes/d", 1001)])),
        Err(R::InsufficientCapacity)
    );
    assert_eq!(
        store.reserve(d, 1, &fx.owner, &service(&[("d", "/volumes/d", 1000)])),
        Ok(())
    );
    // A node that offers no volume space takes no volume.
    let none = Fx::new();
    let store = VolumeStore::open(none.config(0)).unwrap();
    assert_eq!(
        store.reserve(d, 1, &none.owner, &service(&[("d", "/volumes/d", 64)])),
        Err(R::InsufficientCapacity)
    );
    store.set_budget_mb(64);
    assert_eq!(store.budget_mb(), 64);
    assert_eq!(
        store.reserve(d, 1, &none.owner, &service(&[("d", "/volumes/d", 64)])),
        Ok(())
    );
}

/// An unused volume does not count against the budget: it is evicted, least recently used first, when a mount needs
/// the room.
#[test]
fn unused_volumes_are_evicted_least_recently_used_first_when_a_mount_needs_room() {
    let fx = Fx::new();
    let store = VolumeStore::open(fx.config(512)).unwrap();
    // Three volumes that each ended up holding 100 MiB (sparse files: the measurement counts the apparent size),
    // last used in this order: old, mid, new. Leaving them in place takes nothing from the budget.
    for name in ["old", "mid", "new"] {
        let lease = LeaseId::generate();
        mount(&store, lease, &fx.owner, &service(&[(name, "/volumes/v", 128)])).unwrap();
        fs::File::create(fx.data_of(name).join("blob"))
            .unwrap()
            .set_len(100 * MIB)
            .unwrap();
        assert!(store.release(&lease, 1));
        fx.clock.advance(time::Duration::hours(1));
    }
    assert_eq!(store.report_now().volumes.len(), 3);
    // A new 400 MiB volume: 400 in use + 300 unused does not fit in 512. `old` goes (700 → 600), then `mid`
    // (→ 500), and `new` stays.
    let lease = LeaseId::generate();
    mount(&store, lease, &fx.owner, &service(&[("fresh", "/volumes/fresh", 400)])).unwrap();
    assert!(!fx.volume_dir("old").exists());
    assert!(!fx.volume_dir("mid").exists());
    assert!(fx.data_of("new").join("blob").exists());
    let names: Vec<String> = store.report_now().volumes.into_iter().map(|v| v.name).collect();
    assert_eq!(names, ["fresh", "new"]);

    // A volume in use is never evicted, whatever room is needed: 512 in use + 100 unused, and only `new` can go.
    let other = LeaseId::generate();
    mount(&store, other, &fx.owner, &service(&[("more", "/volumes/more", 112)])).unwrap();
    assert!(!fx.volume_dir("new").exists(), "the last unused volume went");
    assert!(fx.data_of("fresh").exists());
    assert!(fx.data_of("more").exists());
    assert!(store.release(&lease, 1));
    assert!(store.release(&other, 1));
}

// ---------------------------------------------------------------------------------------------------------------
// Deletion

/// SI-H2-9: a symlink planted inside a volume before deletion is removed, never followed.
#[test]
fn deletion_never_follows_a_link() {
    let fx = Fx::new();
    let store = fx.store();
    let data = fx.used_once(&store, "models", 64);
    let (target, facts) = fx.outside_file("precious");
    let precious_dir = fx.outside.path().join("dir");
    fs::create_dir(&precious_dir).unwrap();
    fs::write(precious_dir.join("inside"), b"keep me").unwrap();
    fs::create_dir_all(data.join("a/b")).unwrap();
    fs::write(data.join("a/b/file"), b"x").unwrap();
    symlink(&target, data.join("to-file")).unwrap();
    symlink(&precious_dir, data.join("a/to-dir")).unwrap();
    symlink(fx.outside.path(), data.join("a/b/to-outside")).unwrap();
    fs::hard_link(&target, data.join("a/hard")).unwrap();
    fifo(&data.join("a/pipe"));

    store.delete("models").unwrap();
    assert!(!fx.volume_dir("models").exists());
    assert_eq!(fs::read(&target).unwrap(), b"the owner's file");
    assert_eq!(fs::read(precious_dir.join("inside")).unwrap(), b"keep me");
    let after = Facts::of(&target);
    assert_eq!(
        (after.uid, after.gid, after.mode, after.len, after.ino),
        (facts.uid, facts.gid, facts.mode, facts.len, facts.ino)
    );
    assert_eq!(after.nlink, 1, "only the name inside the volume went");
    assert!(store.report_now().volumes.is_empty());
    assert!(matches!(store.delete("models"), Err(DeleteError::NotFound)));
}

#[test]
fn deletion_handles_a_tree_deeper_than_it_holds_descriptors_and_wide_directories() {
    let fx = Fx::new();
    let store = fx.store();
    let data = fx.used_once(&store, "models", 64);
    // Far deeper than the levels a deletion keeps open; each level also holds a file.
    let mut deep = data.clone();
    for i in 0..150 {
        deep.push("d");
        fs::create_dir(&deep).unwrap();
        fs::write(deep.join(format!("f{i}")), b"x").unwrap();
    }
    // More entries than one pass handles.
    fs::create_dir(data.join("wide")).unwrap();
    for i in 0..1100 {
        fs::write(data.join("wide").join(i.to_string()), b"").unwrap();
    }
    store.delete("models").unwrap();
    assert!(!fx.volume_dir("models").exists());
    assert_eq!(fs::read_dir(fx.account_dir()).unwrap().count(), 0);
}

#[test]
fn a_link_in_place_of_the_volume_directory_is_removed_not_followed() {
    let fx = Fx::new();
    let store = fx.store();
    fx.used_once(&store, "models", 64);
    let (target, _) = fx.outside_file("precious");
    fs::rename(fx.volume_dir("models"), fx.data.path().join("moved-away")).unwrap();
    symlink(fx.outside.path(), fx.volume_dir("models")).unwrap();
    store.delete("models").unwrap();
    assert!(fs::symlink_metadata(fx.volume_dir("models")).is_err(), "the link went");
    assert_eq!(fs::read(&target).unwrap(), b"the owner's file");
    assert_eq!(fs::read_dir(fx.outside.path()).unwrap().count(), 1);
    // The same for `data/` inside a volume.
    let data = fx.used_once(&store, "cache", 64);
    fs::remove_dir(&data).unwrap();
    symlink(fx.outside.path(), &data).unwrap();
    store.delete("cache").unwrap();
    assert!(!fx.volume_dir("cache").exists());
    assert_eq!(fs::read(&target).unwrap(), b"the owner's file");
}

#[test]
fn volume_delete_refuses_bad_names_and_volumes_in_use() {
    let fx = Fx::new();
    let store = fx.store();
    for name in ["a/b", "..", "../x", "x\0y", "", "/etc", "tpl:x"] {
        assert!(matches!(store.delete(name), Err(DeleteError::InvalidName)), "{name:?}");
    }
    assert!(matches!(store.delete("unknown"), Err(DeleteError::NotFound)));
    let lease = LeaseId::generate();
    let job = batch(Some("transcribe"), &[("tpl:transcribe/models", "/volumes/models", 64)]);
    mount(&store, lease, &fx.owner, &job).unwrap();
    assert!(matches!(
        store.delete("tpl:transcribe/models"),
        Err(DeleteError::InUse(Some(l))) if l == lease
    ));
    assert!(fx.data_of("tpl:transcribe/models").exists());
    assert!(store.release(&lease, 1));
    // A `tpl:` name is a name like any other here: the hub decides who may delete.
    store.delete("tpl:transcribe/models").unwrap();
    assert!(!fx.volume_dir("tpl:transcribe/models").exists());
}

/// A deletion that was interrupted (the agent died, or a file could not be removed) is never mounted half-deleted:
/// the volume says so on disk, and the next collection finishes it.
#[test]
fn an_interrupted_deletion_is_finished_and_never_mounted() {
    let fx = Fx::new();
    let store = fx.store();
    let data = fx.used_once(&store, "models", 64);
    fs::write(data.join("half"), b"x").unwrap();
    // What `remove` writes before it deletes anything.
    let meta_path = fx.volume_dir("models").join(META_FILE);
    let mut meta = fx.meta("models");
    meta["deleting"] = json!(true);
    fs::write(&meta_path, serde_json::to_vec(&meta).unwrap()).unwrap();
    drop(store);

    let restarted = fx.store();
    let job = service(&[("models", "/volumes/models", 64)]);
    assert_eq!(
        restarted.reserve(LeaseId::generate(), 1, &fx.owner, &job),
        Err(R::InsufficientCapacity)
    );
    assert_eq!(restarted.collect_garbage(), 1);
    assert!(!fx.volume_dir("models").exists());
    assert_eq!(restarted.reserve(LeaseId::generate(), 1, &fx.owner, &job), Ok(()));
}

// ---------------------------------------------------------------------------------------------------------------
// Retention and the disk floor

#[test]
fn an_unused_volume_is_deleted_after_the_retention() {
    let fx = Fx::new();
    let store = fx.store();
    fx.used_once(&store, "stale", 64);
    fx.clock.advance(time::Duration::days(10));
    fx.used_once(&store, "recent", 64);
    let held = LeaseId::generate();
    mount(&store, held, &fx.owner, &service(&[("held", "/volumes/held", 64)])).unwrap();
    // A volume of an account this node was enrolled into before: unused, so it expires too.
    let former = AccountId::generate();
    let former_dir = fx
        .data
        .path()
        .join(VOLUMES_DIR)
        .join(former.to_string())
        .join(dir_name("old"));
    fs::create_dir_all(former_dir.join(DATA_DIR)).unwrap();
    let meta = json!({"name": "old", "created_at": "2026-01-01T00:00:00Z", "last_used_at": "2026-01-01T00:00:00Z"});
    fs::write(former_dir.join(META_FILE), serde_json::to_vec(&meta).unwrap()).unwrap();
    let store = fx.store();
    assert_eq!(store.orphaned(), [held]);
    // The account's own report never lists another account's volume.
    let names: Vec<String> = store.report_now().volumes.into_iter().map(|v| v.name).collect();
    assert_eq!(names, ["held", "recent", "stale"]);
    assert_eq!(
        store.collect_garbage(),
        1,
        "the former account's volume is long expired"
    );
    assert!(!former_dir.exists());

    // 29 days and 23 hours after `stale` was last used: nothing goes.
    fx.clock.advance(time::Duration::days(20) - time::Duration::hours(1));
    assert_eq!(store.collect_garbage(), 0);
    fx.clock.advance(time::Duration::hours(1));
    assert_eq!(store.collect_garbage(), 1);
    assert!(!fx.volume_dir("stale").exists());
    assert!(fx.volume_dir("recent").exists());
    // A volume in use never expires, however long it runs.
    fx.clock.advance(time::Duration::days(365));
    assert_eq!(store.collect_garbage(), 1, "`recent` went");
    assert!(fx.data_of("held").exists());
    assert_eq!(store.report_now().volumes.len(), 1);
}

/// The data disk as a test sees it: below the floor while any of `while_present` exists.
#[derive(Debug)]
struct FullWhile(Vec<PathBuf>);

impl FreeSpace for FullWhile {
    fn space(&self, _: &Path) -> io::Result<DiskSpace> {
        let free = if self.0.iter().any(|p| p.exists()) {
            1 << 30
        } else {
            50 << 30
        };
        Ok(DiskSpace {
            free_bytes: free,
            total_bytes: 100 << 30,
        })
    }
}

#[derive(Debug)]
struct Unreadable;

impl FreeSpace for Unreadable {
    fn space(&self, _: &Path) -> io::Result<DiskSpace> {
        Err(io::Error::other("statvfs failed"))
    }
}

/// Under the H1 disk floor, unused volumes go before any job is killed: least recently used first, only as many as
/// it takes, and never one in use.
#[test]
fn under_the_disk_floor_unused_volumes_are_evicted_first() {
    let fx = Fx::new();
    let store = fx.store();
    for name in ["oldest", "older", "newer"] {
        fx.used_once(&store, name, 64);
        fx.clock.advance(time::Duration::hours(1));
    }
    let held = LeaseId::generate();
    mount(&store, held, &fx.owner, &service(&[("held", "/volumes/held", 64)])).unwrap();

    // Above the floor: nothing is touched.
    assert!(store.evict_for_floor(&FullWhile(Vec::new())));
    assert_eq!(store.report_now().volumes.len(), 4);
    // Below it until `oldest` and `older` are gone.
    let disk = FullWhile(vec![fx.volume_dir("oldest"), fx.volume_dir("older")]);
    assert!(store.evict_for_floor(&disk));
    assert!(!fx.volume_dir("oldest").exists());
    assert!(!fx.volume_dir("older").exists());
    assert!(fx.volume_dir("newer").exists(), "no more than it takes");
    // Still below it when nothing unused is left: the caller then does what H1 does. The volume in use stays.
    let disk = FullWhile(vec![fx.volume_dir("held")]);
    assert!(!store.evict_for_floor(&disk));
    assert!(!fx.volume_dir("newer").exists());
    assert!(fx.data_of("held").exists());
    // An unreadable disk is not "above the floor", and evicts nothing.
    fx.used_once(&store, "spare", 64);
    assert!(!store.evict_for_floor(&Unreadable));
    assert!(fx.volume_dir("spare").exists());
}

/// A volume the agent cannot delete, as one written by a non-root image user is with rootless Podman: a file in a
/// `data/` the agent may read but not write. Dropping it gives the permission back (and lets the test clean up).
struct Undeletable(PathBuf);

impl Undeletable {
    /// `None` as root, who can delete anything: the tests that need it are skipped then.
    fn make(data: PathBuf) -> Option<Self> {
        if rustix::process::geteuid().is_root() {
            eprintln!("SKIPPED: root can delete anything");
            return None;
        }
        fs::write(data.join("kept-by-permissions"), b"x").unwrap();
        fs::set_permissions(&data, fs::Permissions::from_mode(0o555)).unwrap();
        Some(Self(data))
    }
}

impl Drop for Undeletable {
    fn drop(&mut self) {
        let _ = fs::set_permissions(&self.0, fs::Permissions::from_mode(0o755));
    }
}

/// One volume that cannot be deleted must not stop the eviction: it is skipped, and the next unused volume goes.
#[test]
fn a_volume_that_cannot_be_deleted_does_not_stop_the_eviction_for_room() {
    let fx = Fx::new();
    {
        let store = VolumeStore::open(fx.config(512)).unwrap();
        // Three volumes of 100 MiB each, last used in this order: stuck, mid, new.
        for name in ["stuck", "mid", "new"] {
            let lease = LeaseId::generate();
            mount(&store, lease, &fx.owner, &service(&[(name, "/volumes/v", 128)])).unwrap();
            fs::File::create(fx.data_of(name).join("blob"))
                .unwrap()
                .set_len(100 * MIB)
                .unwrap();
            assert!(store.release(&lease, 1));
            fx.clock.advance(time::Duration::hours(1));
        }
    }
    let Some(stuck) = Undeletable::make(fx.data_of("stuck")) else {
        return;
    };
    // A restart: the sizes are not known and are measured for the eviction.
    let store = VolumeStore::open(fx.config(512)).unwrap();
    // 400 in use + 300 unused do not fit in 512. `stuck` is the least recently used and cannot go: `mid` goes
    // (600), then `new` (500, with `stuck` still counted), and the mount goes ahead.
    let lease = LeaseId::generate();
    mount(&store, lease, &fx.owner, &service(&[("fresh", "/volumes/fresh", 400)])).unwrap();
    assert!(fx.data_of("stuck").join("blob").exists());
    assert!(!fx.volume_dir("mid").exists());
    assert!(!fx.volume_dir("new").exists());
    // The one that could not go says on disk that it is being deleted, is never mounted again, and goes at a later
    // collection, once it can.
    assert_eq!(fx.meta("stuck")["deleting"], true);
    let again = service(&[("stuck", "/volumes/stuck", 64)]);
    assert_eq!(
        store.reserve(LeaseId::generate(), 1, &fx.owner, &again),
        Err(R::InsufficientCapacity)
    );
    assert_eq!(store.collect_garbage(), 0, "still not deletable");
    drop(stuck);
    assert_eq!(store.collect_garbage(), 1);
    assert!(!fx.volume_dir("stuck").exists());
}

/// H2 §11.3: "Under the H1 disk floor the agent evicts unused volumes before it kills jobs". A volume that cannot be
/// deleted is skipped; the eviction gives up only when no unused volume is left to try.
#[test]
fn under_the_disk_floor_a_volume_that_cannot_be_deleted_is_skipped() {
    let fx = Fx::new();
    let store = fx.store();
    for name in ["stuck", "next", "last"] {
        fx.used_once(&store, name, 64);
        fx.clock.advance(time::Duration::hours(1));
    }
    let Some(stuck) = Undeletable::make(fx.data_of("stuck")) else {
        return;
    };
    // Below the floor until `next` is gone. The least recently used volume cannot be deleted: the next one goes,
    // and the disk is above the floor again.
    let disk = FullWhile(vec![fx.volume_dir("next")]);
    assert!(store.evict_for_floor(&disk));
    assert!(fx.volume_dir("stuck").exists());
    assert!(!fx.volume_dir("next").exists());
    assert!(fx.volume_dir("last").exists(), "no more than it takes");
    // Called again, as every 2 s while a job runs: the same volume fails again and is skipped again.
    let disk = FullWhile(vec![fx.volume_dir("last")]);
    assert!(store.evict_for_floor(&disk));
    assert!(!fx.volume_dir("last").exists());
    // Only when everything that can go is gone does it give up, and it ends: it does not try the same volume for
    // ever.
    let disk = FullWhile(vec![fx.volume_dir("stuck")]);
    assert!(!store.evict_for_floor(&disk));
    assert!(fx.volume_dir("stuck").exists());
    drop(stuck);
    assert!(store.evict_for_floor(&disk), "once it can be deleted, it goes");
    assert!(!fx.volume_dir("stuck").exists());
}

// ---------------------------------------------------------------------------------------------------------------
// A volume whose meta.json cannot be read

#[test]
fn a_volume_with_an_unreadable_meta_is_not_reused_until_the_sweep_has_finished() {
    type Damage = fn(&Fx, &Path);
    let cases: [(&str, Damage); 5] = [
        ("not JSON", |_, meta| fs::write(meta, b"{").unwrap()),
        ("missing", |_, meta| fs::remove_file(meta).unwrap()),
        ("another volume's", |_, meta| {
            let other = json!({"name": "other", "created_at": "2026-01-01T00:00:00Z",
                "last_used_at": "2026-01-01T00:00:00Z"});
            fs::write(meta, serde_json::to_vec(&other).unwrap()).unwrap();
        }),
        ("a symbolic link", |fx, meta| {
            let (target, _) = fx.outside_file("meta-target");
            fs::remove_file(meta).unwrap();
            symlink(target, meta).unwrap();
        }),
        ("a FIFO", |_, meta| {
            fs::remove_file(meta).unwrap();
            fifo(meta);
        }),
    ];
    for (what, damage) in cases {
        let fx = Fx::new();
        let data = fx.used_once(&fx.store(), "models", 64);
        fs::write(data.join("weights"), b"kept").unwrap();
        damage(&fx, &fx.volume_dir("models").join(META_FILE));

        // The restart: the agent cannot tell whether a container of the earlier process still mounts it.
        let store = fx.store();
        assert!(
            store.report_now().volumes.is_empty(),
            "{what}: it has no name to report"
        );
        let job = service(&[("models", "/volumes/models", 64)]);
        let lease = LeaseId::generate();
        assert_eq!(
            store.reserve(lease, 1, &fx.owner, &job),
            Err(R::InsufficientCapacity),
            "{what}"
        );
        assert!(
            matches!(store.delete("models"), Err(DeleteError::InUse(None))),
            "{what}"
        );
        assert_eq!(store.collect_garbage(), 0, "{what}");
        // The sweep listed the containers and none of an earlier process is left: it is a volume again, checked
        // like any other before it is mounted.
        store.sweep_finished();
        mount(&store, lease, &fx.owner, &job).unwrap_or_else(|e| panic!("{what}: {e}"));
        assert_eq!(fx.meta("models")["name"], "models", "{what}");
        assert_eq!(fs::read(data.join("weights")).unwrap(), b"kept", "{what}");
        if what == "a symbolic link" {
            assert_eq!(
                fs::read(fx.outside.path().join("meta-target")).unwrap(),
                b"the owner's file",
                "the link was replaced, its target not written"
            );
        }
    }
}

#[test]
fn entries_the_agent_did_not_make_are_left_alone() {
    let fx = Fx::new();
    fx.used_once(&fx.store(), "models", 64);
    let volumes = fx.data.path().join(VOLUMES_DIR);
    fs::create_dir(volumes.join("not-an-account")).unwrap();
    fs::write(volumes.join("stray-file"), b"x").unwrap();
    fs::create_dir(fx.account_dir().join("not-a-hash")).unwrap();
    symlink(fx.outside.path(), fx.account_dir().join("link")).unwrap();
    let store = fx.store();
    store.sweep_finished();
    fx.clock.advance(time::Duration::days(400));
    assert_eq!(store.collect_garbage(), 1, "only the volume");
    assert!(volumes.join("not-an-account").exists());
    assert!(volumes.join("stray-file").exists());
    assert!(fx.account_dir().join("not-a-hash").exists());
    assert!(fs::symlink_metadata(fx.account_dir().join("link")).is_ok());
}

#[test]
fn volumes_must_be_the_agents_own_directory() {
    let fx = Fx::new();
    symlink(fx.outside.path(), fx.data.path().join(VOLUMES_DIR)).unwrap();
    let err = VolumeStore::open(fx.config(1024)).unwrap_err();
    assert!(err.is_unsafe(), "{err}");
    assert_eq!(fs::read_dir(fx.outside.path()).unwrap().count(), 0);
}

// ---------------------------------------------------------------------------------------------------------------
// Reports

#[test]
fn the_report_lists_the_accounts_volumes() {
    let fx = Fx::new();
    let store = fx.store();
    let data = fx.used_once(&store, "cache", 64);
    fs::File::create(data.join("blob"))
        .unwrap()
        .set_len(3 * MIB + 1)
        .unwrap();
    fx.clock.advance(time::Duration::minutes(30));
    let lease = LeaseId::generate();
    let tpl = batch(
        Some("transcribe"),
        &[("tpl:transcribe/models", "/volumes/models", 5120)],
    );
    mount(&store, lease, &fx.owner, &tpl).unwrap();
    // A restart forgets the sizes: they are measured for the report.
    let report = fx.store().report_now();
    assert_eq!(report.validate(), Ok(()));
    assert_eq!(report.volumes.len(), 2);
    let cache = &report.volumes[0];
    assert_eq!(cache.name, "cache");
    assert_eq!(cache.size_mb, 4, "3 MiB and a bit, rounded up");
    assert_eq!(cache.last_used_at, t0());
    assert_eq!(cache.in_use_by, None);
    let models = &report.volumes[1];
    assert_eq!(models.name, "tpl:transcribe/models");
    assert_eq!(models.last_used_at, t0() + time::Duration::minutes(30));
    assert_eq!(models.in_use_by, Some(lease));
    let wire = serde_json::to_value(&report).unwrap();
    assert_eq!(wire["volumes"][1]["last_used_at"], "2027-01-15T08:30:00Z");
    assert_eq!(wire["volumes"][1]["in_use_by"], lease.to_string());
    assert_eq!(wire["volumes"][0].get("in_use_by"), None);
}

/// H2 §6.1: a `VolumeReport` once the session is welcomed, every 10 minutes, when a lease that held a volume ends,
/// and in answer to `VolumeDelete`.
#[tokio::test(start_paused = true)]
async fn a_session_reports_at_once_every_interval_on_changes_and_after_a_delete() {
    use p2pc_proto::protocol::VOLUME_REPORT_INTERVAL;

    let fx = Fx::new();
    let store = fx.store();
    fx.used_once(&store, "cache", 64);
    let (outbox, mut sent) = mpsc::channel(8);
    let (deletes, deletes_rx) = mpsc::channel(MAX_PENDING_DELETES);
    let session = tokio::spawn(serve_session(store.clone(), outbox, deletes_rx, VOLUME_REPORT_INTERVAL));
    let names = |msg: Option<AgentMsg>| match msg {
        Some(AgentMsg::VolumeReport(report)) => report
            .volumes
            .into_iter()
            .map(|v| (v.name, v.in_use_by))
            .collect::<Vec<_>>(),
        other => panic!("expected a VolumeReport, got {other:?}"),
    };
    // At once.
    let started = tokio::time::Instant::now();
    assert_eq!(names(sent.recv().await), [("cache".to_string(), None)]);
    assert_eq!(started.elapsed(), Duration::ZERO);
    // Every 10 minutes.
    assert_eq!(names(sent.recv().await), [("cache".to_string(), None)]);
    assert_eq!(started.elapsed(), VOLUME_REPORT_INTERVAL);
    // When a lease takes a volume, and when it ends.
    let lease = LeaseId::generate();
    let job = service(&[("models", "/volumes/models", 64)]);
    mount(&store, lease, &fx.owner, &job).unwrap();
    assert_eq!(
        names(sent.recv().await),
        [("cache".to_string(), None), ("models".to_string(), Some(lease))]
    );
    assert!(store.release(&lease, 1));
    assert_eq!(
        names(sent.recv().await),
        [("cache".to_string(), None), ("models".to_string(), None)]
    );
    // `VolumeDelete`: the volume goes, and a fresh report answers. A refused one is answered too.
    deletes.send("cache".to_string()).await.unwrap();
    assert_eq!(names(sent.recv().await), [("models".to_string(), None)]);
    assert!(!fx.volume_dir("cache").exists());
    deletes.send("../etc".to_string()).await.unwrap();
    assert_eq!(names(sent.recv().await), [("models".to_string(), None)]);
    assert_eq!(
        started.elapsed(),
        VOLUME_REPORT_INTERVAL,
        "none of them waited for the interval"
    );
    // It ends with the session.
    drop(sent);
    deletes.send("models".to_string()).await.unwrap();
    session.await.unwrap();
}

// ---------------------------------------------------------------------------------------------------------------
// Property: whatever the JobSpec says, the only thing that appears on disk is a hash-named directory

proptest::proptest! {
    #![proptest_config(proptest::prelude::ProptestConfig::with_cases(48))]

    #[test]
    fn whatever_the_jobspec_says_only_hash_named_directories_appear(
        name in proptest::string::string_regex("([a-z0-9._/:-]|\\.\\.|\\x00){0,24}").unwrap(),
        tail in proptest::string::string_regex("([a-z0-9._/:,-]|\\.\\.){0,24}").unwrap(),
        template in proptest::option::of("[a-z]{1,8}"),
    ) {
        let fx = Fx::new();
        let store = fx.store();
        let mount_path = format!("/volumes/{tail}");
        let job = batch(template.as_deref(), &[(name.as_str(), mount_path.as_str(), 64)]);
        let lease = LeaseId::generate();
        match store.reserve(lease, 1, &fx.owner, &job) {
            Err(reason) => {
                proptest::prop_assert_eq!(reason, R::InvalidJob);
                proptest::prop_assert_eq!(fx.entries(), [fx.data.path().join(VOLUMES_DIR)]);
            }
            Ok(()) => {
                let mounts = store.lock_and_check(&lease, 1).unwrap();
                proptest::prop_assert!(template.is_some(), "a batch job without a template never mounts");
                proptest::prop_assert!(!mounts[0].mount.contains([':', ',', '\0']));
                proptest::prop_assert!(mounts[0].mount.split('/').all(|segment| segment != ".."));
                let account = fx.account_dir();
                let volume = account.join(dir_name(&name));
                let expected = [
                    fx.data.path().join(VOLUMES_DIR),
                    account,
                    volume.clone(),
                    volume.join(DATA_DIR),
                    volume.join(META_FILE),
                ];
                let mut entries = fx.entries();
                entries.sort();
                let mut expected = expected.to_vec();
                expected.sort();
                proptest::prop_assert_eq!(entries, expected);
                proptest::prop_assert_eq!(&mounts[0].host, &volume.join(DATA_DIR));
            }
        }
    }
}
