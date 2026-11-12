// SPDX-License-Identifier: Apache-2.0

//! The app's device key, stored with DPAPI for the current user in `%LOCALAPPDATA%\P2PC\device.key` (H2 §8.9).
//!
//! The device key is the app's iroh identity towards the hub (§5.1): 32 secret bytes (an Ed25519 secret key). It is
//! never written in the clear: [`FileKeyStore`] hands it to a [`Protector`] and stores only the protected blob, after
//! a fixed header. On Windows the protector is [`Dpapi`] (`CryptProtectData` without `CRYPTPROTECT_LOCAL_MACHINE`, so
//! only the same Windows user can unprotect it); the tests use a fake one, so the file logic runs on any OS.
//!
//! **A key that cannot be read is an error, never a reason to make a new one.** A new key is a new device: the hub
//! would no longer know this PC's app. [`load_or_create`] creates a key only when there is no file at all.
//!
//! No API key is ever stored by the app (§8.9); this module stores the device key only.

use std::fmt;
use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use zeroize::Zeroizing;

/// The length of a device key (an Ed25519 secret key).
pub const DEVICE_KEY_LEN: usize = 32;

/// The file name under `%LOCALAPPDATA%\P2PC` (§8.7 step 5 deletes it on uninstall).
pub const DEVICE_KEY_FILE: &str = "device.key";

/// The first bytes of `device.key`: the format and its version. The protected blob follows.
pub const HEADER: &[u8; 16] = b"P2PC-DEVKEY-v1\0\n";

/// The largest `device.key` the app reads. A DPAPI blob of 32 bytes is a few hundred bytes.
pub const MAX_FILE_LEN: u64 = 4096;

/// `%LOCALAPPDATA%\P2PC\device.key` under a given `%LOCALAPPDATA%` (the same `P2PC` folder as `p2pc-wsl`'s layout).
pub fn device_key_path(local_app_data: &Path) -> PathBuf {
    local_app_data.join("P2PC").join(DEVICE_KEY_FILE)
}

/// The secret bytes of the device key. Wiped from memory when dropped; its `Debug` never shows them.
/// No `PartialEq`: secret bytes are not compared with a short-circuiting `==`.
#[derive(Clone)]
pub struct DeviceKey(Zeroizing<[u8; DEVICE_KEY_LEN]>);

impl DeviceKey {
    /// A key from its 32 bytes.
    pub fn from_bytes(bytes: [u8; DEVICE_KEY_LEN]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    /// A new key from the operating system's random generator.
    pub fn generate() -> Result<Self, KeyError> {
        let mut bytes = Zeroizing::new([0u8; DEVICE_KEY_LEN]);
        getrandom::fill(bytes.as_mut()).map_err(|_| KeyError::Random)?;
        Ok(Self(bytes))
    }

    /// The secret bytes.
    pub fn as_bytes(&self) -> &[u8; DEVICE_KEY_LEN] {
        &self.0
    }
}

impl fmt::Debug for DeviceKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DeviceKey(<redacted>)")
    }
}

/// Why the protector failed. Carries no data, only the OS error code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ProtectError {
    /// The OS refused (DPAPI's `HRESULT`): for example the blob belongs to another Windows user.
    #[error("the operating system refused (code {0:#010x})")]
    Os(i32),
    /// The data is larger than the OS call accepts.
    #[error("the data is too large")]
    TooLarge,
}

/// Encrypts the key for this user only, and decrypts it back. DPAPI on Windows, a fake in the tests.
pub trait Protector {
    /// Protects `plain`.
    fn protect(&self, plain: &[u8]) -> Result<Vec<u8>, ProtectError>;
    /// Unprotects a blob from [`Protector::protect`]. The result is wiped when dropped.
    fn unprotect(&self, blob: &[u8]) -> Result<Zeroizing<Vec<u8>>, ProtectError>;
}

/// Why the device key could not be read or stored. Never contains key material.
#[derive(Debug, thiserror::Error)]
pub enum KeyError {
    /// Reading or writing the file failed.
    #[error("device key file: {0}")]
    Io(#[from] io::Error),
    /// The file is not a device key of this format (wrong header, wrong length, too large).
    #[error("device key file is not in the expected format")]
    Corrupt,
    /// The protector refused the blob: another Windows user's file, or a damaged one.
    #[error("device key could not be unprotected: {0}")]
    Unprotect(ProtectError),
    /// The protector could not protect the key.
    #[error("device key could not be protected: {0}")]
    Protect(ProtectError),
    /// A key file already exists; the app never replaces one.
    #[error("a device key already exists")]
    AlreadyExists,
    /// The OS random generator failed.
    #[error("the system random generator failed")]
    Random,
}

/// Where the device key lives.
pub trait DeviceKeyStore {
    /// The stored key, or `None` when there is none yet.
    fn load(&self) -> Result<Option<DeviceKey>, KeyError>;
    /// Stores a key where there is none. Refuses ([`KeyError::AlreadyExists`]) to replace one.
    fn store_new(&self, key: &DeviceKey) -> Result<(), KeyError>;
}

/// The stored key, or a new one from `generate` stored first when there is none. Any error reading an existing key
/// is returned as is: the key is never replaced.
pub fn load_or_create(
    store: &dyn DeviceKeyStore,
    generate: impl FnOnce() -> Result<DeviceKey, KeyError>,
) -> Result<DeviceKey, KeyError> {
    if let Some(key) = store.load()? {
        return Ok(key);
    }
    let key = generate()?;
    store.store_new(&key)?;
    Ok(key)
}

/// `device.key` on disk: [`HEADER`] then the protected blob.
#[derive(Debug)]
pub struct FileKeyStore<P> {
    path: PathBuf,
    protector: P,
}

impl<P: Protector> FileKeyStore<P> {
    /// A store at `path` (normally [`device_key_path`]) using `protector`.
    pub fn new(path: impl Into<PathBuf>, protector: P) -> Self {
        Self {
            path: path.into(),
            protector,
        }
    }

    /// The file's path.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// A temporary name next to the key, unique to this process and call (`device.key.<pid>-<n>.tmp`), so that two
    /// writers never share one.
    fn new_temp_path(&self) -> PathBuf {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let n = NEXT.fetch_add(1, Ordering::Relaxed);
        let mut name = self.path.file_name().map(|n| n.to_os_string()).unwrap_or_default();
        name.push(format!(".{}-{n}.tmp", std::process::id()));
        self.path.with_file_name(name)
    }
}

/// Gives the finished temporary file its final name only if that name is free, then removes the temporary name.
///
/// `rename` would replace an existing file (on Windows and on Unix); a hard link fails with `AlreadyExists` instead,
/// atomically, so a key that another writer stored in the meantime is never replaced. `%LOCALAPPDATA%` is on NTFS,
/// which has hard links.
fn publish_new(temp: &Path, path: &Path) -> io::Result<()> {
    fs::hard_link(temp, path)?;
    // The key is in place; a temporary name left behind is only clutter.
    let _ = fs::remove_file(temp);
    Ok(())
}

impl<P: Protector> DeviceKeyStore for FileKeyStore<P> {
    fn load(&self) -> Result<Option<DeviceKey>, KeyError> {
        let file = match fs::File::open(&self.path) {
            Ok(file) => file,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        let mut data = Vec::new();
        file.take(MAX_FILE_LEN + 1).read_to_end(&mut data)?;
        if data.len() as u64 > MAX_FILE_LEN {
            return Err(KeyError::Corrupt);
        }
        let Some(blob) = data.strip_prefix(HEADER.as_slice()) else {
            return Err(KeyError::Corrupt);
        };
        let plain = self.protector.unprotect(blob).map_err(KeyError::Unprotect)?;
        let bytes: [u8; DEVICE_KEY_LEN] = plain.as_slice().try_into().map_err(|_| KeyError::Corrupt)?;
        Ok(Some(DeviceKey::from_bytes(bytes)))
    }

    fn store_new(&self, key: &DeviceKey) -> Result<(), KeyError> {
        if fs::symlink_metadata(&self.path).is_ok() {
            return Err(KeyError::AlreadyExists);
        }
        let blob = self.protector.protect(key.as_bytes()).map_err(KeyError::Protect)?;
        if let Some(dir) = self.path.parent() {
            fs::create_dir_all(dir)?;
        }
        // Write a temporary file of our own, flush it to disk, then give it the final name without ever replacing an
        // existing key (see `publish_new`): a crash leaves either no key or a whole one.
        let temp = self.new_temp_path();
        let written = (|| -> io::Result<()> {
            let mut file = fs::OpenOptions::new().write(true).create_new(true).open(&temp)?;
            file.write_all(HEADER)?;
            file.write_all(&blob)?;
            file.sync_all()
        })();
        match written.and_then(|()| publish_new(&temp, &self.path)) {
            Ok(()) => Ok(()),
            Err(e) => {
                let _ = fs::remove_file(&temp);
                if e.kind() == io::ErrorKind::AlreadyExists {
                    Err(KeyError::AlreadyExists)
                } else {
                    Err(e.into())
                }
            }
        }
    }
}

/// DPAPI for the current Windows user (H2 §8.9).
#[cfg(windows)]
pub use dpapi::Dpapi;

#[cfg(windows)]
#[allow(unsafe_code)]
mod dpapi {
    //! `CryptProtectData` / `CryptUnprotectData` (Win32 DPAPI), current-user scope, no UI.
    //!
    //! The `windows` crate exposes these only as `unsafe` FFI: this module is the one place in the crate that uses
    //! `unsafe` (the crate denies it everywhere else).

    use windows::Win32::Foundation::{HLOCAL, LocalFree};
    use windows::Win32::Security::Cryptography::{
        CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN, CryptProtectData, CryptUnprotectData,
    };
    use windows::core::w;
    use zeroize::Zeroizing;

    use super::{ProtectError, Protector};

    /// Extra entropy mixed into the protection, so that a blob from another program protected for the same user does
    /// not unprotect as a P2PC key by accident. It is not a secret (it is in this public source).
    const ENTROPY: &[u8] = b"p2pc-desktop/device.key/v1";

    /// DPAPI, current-user scope (never `CRYPTPROTECT_LOCAL_MACHINE`), with `CRYPTPROTECT_UI_FORBIDDEN`.
    #[derive(Debug, Clone, Copy, Default)]
    pub struct Dpapi;

    fn input_blob(data: &[u8]) -> Result<CRYPT_INTEGER_BLOB, ProtectError> {
        Ok(CRYPT_INTEGER_BLOB {
            cbData: u32::try_from(data.len()).map_err(|_| ProtectError::TooLarge)?,
            // DPAPI only reads input blobs; the field is `*mut` in the Win32 signature.
            pbData: data.as_ptr().cast_mut(),
        })
    }

    /// Copies DPAPI's output out, wipes DPAPI's buffer and frees it with `LocalFree`.
    ///
    /// # Safety
    ///
    /// `out` must be an output blob that a successful `CryptProtectData` or `CryptUnprotectData` call filled in: its
    /// `pbData` is either null or a `LocalAlloc` buffer of `cbData` bytes that nothing else owns.
    unsafe fn take_output(out: CRYPT_INTEGER_BLOB) -> Zeroizing<Vec<u8>> {
        if out.pbData.is_null() {
            return Zeroizing::new(Vec::new());
        }
        let len = out.cbData as usize;
        // SAFETY: per this function's contract, `pbData` points to `len` initialized bytes that we own.
        let copy = Zeroizing::new(unsafe { std::slice::from_raw_parts(out.pbData, len) }.to_vec());
        // SAFETY: same buffer, still owned and `len` bytes long; wiping it before freeing keeps the plaintext key out
        // of freed heap memory.
        unsafe { std::ptr::write_bytes(out.pbData, 0, len) };
        // SAFETY: the buffer was allocated by DPAPI with `LocalAlloc` and is freed exactly once, here.
        unsafe { LocalFree(Some(HLOCAL(out.pbData.cast()))) };
        copy
    }

    impl Protector for Dpapi {
        fn protect(&self, plain: &[u8]) -> Result<Vec<u8>, ProtectError> {
            let input = input_blob(plain)?;
            let entropy = input_blob(ENTROPY)?;
            let mut out = CRYPT_INTEGER_BLOB::default();
            // SAFETY: `input` and `entropy` point into slices that outlive the call and are only read; `out` is a
            // valid, writable blob; the description is a static NUL-terminated wide string; no prompt struct.
            unsafe {
                CryptProtectData(
                    &input,
                    w!("P2PC device key"),
                    Some(&raw const entropy),
                    None,
                    None,
                    CRYPTPROTECT_UI_FORBIDDEN,
                    &mut out,
                )
            }
            .map_err(|e| ProtectError::Os(e.code().0))?;
            // SAFETY: `out` was filled in by the successful call above.
            let blob = unsafe { take_output(out) };
            Ok(blob.to_vec())
        }

        fn unprotect(&self, blob: &[u8]) -> Result<Zeroizing<Vec<u8>>, ProtectError> {
            let input = input_blob(blob)?;
            let entropy = input_blob(ENTROPY)?;
            let mut out = CRYPT_INTEGER_BLOB::default();
            // SAFETY: as in `protect`; the description output pointer is not requested (`None`).
            unsafe {
                CryptUnprotectData(
                    &input,
                    None,
                    Some(&raw const entropy),
                    None,
                    None,
                    CRYPTPROTECT_UI_FORBIDDEN,
                    &mut out,
                )
            }
            .map_err(|e| ProtectError::Os(e.code().0))?;
            // SAFETY: `out` was filled in by the successful call above.
            Ok(unsafe { take_output(out) })
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        // Runs on Windows only (the Windows build machine): the real DPAPI round trip.
        #[test]
        fn dpapi_round_trips_and_does_not_store_the_key_in_the_clear() {
            let key = [7u8; 32];
            let blob = Dpapi.protect(&key).expect("protect");
            assert!(
                !blob.windows(key.len()).any(|w| w == key),
                "plaintext key inside the blob"
            );
            assert_eq!(Dpapi.unprotect(&blob).expect("unprotect").as_slice(), key.as_slice());
            let mut damaged = blob.clone();
            let last = damaged.len() - 1;
            damaged[last] ^= 0xff;
            assert!(Dpapi.unprotect(&damaged).is_err());
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::AtomicU32;
    use std::sync::{Arc, Barrier};

    use super::*;

    /// A reversible stand-in for DPAPI: a marker, then the bytes XORed with 0x5a. Refuses blobs without the marker
    /// (as DPAPI refuses another user's blob).
    #[derive(Debug, Default)]
    struct FakeProtector {
        protects: AtomicU32,
    }

    const MARK: &[u8] = b"FAKE";

    impl Protector for FakeProtector {
        fn protect(&self, plain: &[u8]) -> Result<Vec<u8>, ProtectError> {
            self.protects.fetch_add(1, Ordering::Relaxed);
            let mut out = MARK.to_vec();
            out.extend(plain.iter().map(|b| b ^ 0x5a));
            Ok(out)
        }

        fn unprotect(&self, blob: &[u8]) -> Result<Zeroizing<Vec<u8>>, ProtectError> {
            let body = blob
                .strip_prefix(MARK)
                .ok_or(ProtectError::Os(0x8009_0005_u32 as i32))?;
            Ok(Zeroizing::new(body.iter().map(|b| b ^ 0x5a).collect()))
        }
    }

    /// A protector that cannot protect (to check that nothing is written).
    #[derive(Debug)]
    struct BrokenProtector;

    impl Protector for BrokenProtector {
        fn protect(&self, _: &[u8]) -> Result<Vec<u8>, ProtectError> {
            Err(ProtectError::Os(-1))
        }
        fn unprotect(&self, _: &[u8]) -> Result<Zeroizing<Vec<u8>>, ProtectError> {
            Err(ProtectError::Os(-1))
        }
    }

    fn key(byte: u8) -> DeviceKey {
        DeviceKey::from_bytes([byte; DEVICE_KEY_LEN])
    }

    fn bytes(key: Option<DeviceKey>) -> Option<[u8; DEVICE_KEY_LEN]> {
        key.map(|k| *k.as_bytes())
    }

    fn store(dir: &tempfile::TempDir) -> FileKeyStore<FakeProtector> {
        FileKeyStore::new(device_key_path(dir.path()), FakeProtector::default())
    }

    #[test]
    fn the_path_is_under_the_p2pc_folder() {
        let path = device_key_path(Path::new("base"));
        assert_eq!(path, Path::new("base").join("P2PC").join("device.key"));
    }

    #[test]
    fn no_file_means_no_key() {
        let dir = tempfile::tempdir().expect("tempdir");
        assert!(store(&dir).load().expect("load").is_none());
    }

    #[test]
    fn a_stored_key_loads_back() {
        let dir = tempfile::tempdir().expect("tempdir");
        let s = store(&dir);
        s.store_new(&key(9)).expect("store");
        assert_eq!(bytes(s.load().expect("load")), Some([9; DEVICE_KEY_LEN]));
        assert_only_the_key_is_left(&s);
    }

    #[test]
    fn the_file_holds_the_header_and_the_protected_blob_never_the_key() {
        let dir = tempfile::tempdir().expect("tempdir");
        let s = store(&dir);
        let k = key(0x11);
        s.store_new(&k).expect("store");
        let data = fs::read(s.path()).expect("read");
        assert!(data.starts_with(HEADER));
        assert_eq!(&data[HEADER.len()..HEADER.len() + MARK.len()], MARK);
        assert!(
            !data.windows(DEVICE_KEY_LEN).any(|w| w == k.as_bytes()),
            "key in the clear"
        );
    }

    #[test]
    fn an_existing_key_is_never_replaced() {
        let dir = tempfile::tempdir().expect("tempdir");
        let s = store(&dir);
        s.store_new(&key(1)).expect("store");
        assert!(matches!(s.store_new(&key(2)), Err(KeyError::AlreadyExists)));
        assert_eq!(bytes(s.load().expect("load")), Some([1; DEVICE_KEY_LEN]));
    }

    #[test]
    fn load_or_create_creates_once_then_loads() {
        let dir = tempfile::tempdir().expect("tempdir");
        let s = store(&dir);
        let first = load_or_create(&s, || Ok(key(3))).expect("create");
        assert_eq!(first.as_bytes(), &[3; DEVICE_KEY_LEN]);
        let again = load_or_create(&s, || panic!("must not generate a second key")).expect("load");
        assert_eq!(again.as_bytes(), &[3; DEVICE_KEY_LEN]);
        assert_eq!(s.protector.protects.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn publishing_never_replaces_an_existing_file() {
        // The window between "no key yet" and the final rename: another writer got there first.
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join(DEVICE_KEY_FILE);
        let temp = dir.path().join("device.key.1-0.tmp");
        fs::write(&path, b"the existing key").expect("write");
        fs::write(&temp, b"a new key").expect("write");
        let err = publish_new(&temp, &path).expect_err("must not replace");
        assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(fs::read(&path).expect("read"), b"the existing key");
    }

    #[test]
    fn concurrent_creations_store_exactly_one_key() {
        let dir = tempfile::tempdir().expect("tempdir");
        let s = Arc::new(store(&dir));
        let start = Arc::new(Barrier::new(8));
        let handles: Vec<_> = (0..8u8)
            .map(|i| {
                let (s, start) = (Arc::clone(&s), Arc::clone(&start));
                std::thread::spawn(move || {
                    start.wait();
                    s.store_new(&key(i)).map(|()| i)
                })
            })
            .collect();
        let results: Vec<_> = handles.into_iter().map(|h| h.join().expect("thread")).collect();
        let winners: Vec<u8> = results.iter().filter_map(|r| r.as_ref().ok().copied()).collect();
        assert_eq!(winners.len(), 1, "{results:?}");
        assert!(
            results
                .iter()
                .all(|r| matches!(r, Ok(_) | Err(KeyError::AlreadyExists))),
            "{results:?}"
        );
        assert_eq!(bytes(s.load().expect("load")), Some([winners[0]; DEVICE_KEY_LEN]));
        assert_only_the_key_is_left(&s);
    }

    #[test]
    fn temporary_names_are_unique() {
        let dir = tempfile::tempdir().expect("tempdir");
        let s = store(&dir);
        assert_ne!(s.new_temp_path(), s.new_temp_path());
    }

    fn assert_only_the_key_is_left(s: &FileKeyStore<FakeProtector>) {
        let dir = s.path().parent().expect("parent");
        let names: Vec<_> = fs::read_dir(dir)
            .expect("read dir")
            .map(|e| e.expect("entry").file_name())
            .collect();
        assert_eq!(
            names,
            vec![std::ffi::OsString::from(DEVICE_KEY_FILE)],
            "temporary file left behind"
        );
    }

    #[test]
    fn an_unreadable_key_is_an_error_and_is_never_replaced() {
        let dir = tempfile::tempdir().expect("tempdir");
        let s = store(&dir);
        fs::create_dir_all(s.path().parent().expect("parent")).expect("mkdir");
        // Right header, but a blob the protector refuses (another Windows user's file).
        let mut foreign = HEADER.to_vec();
        foreign.extend_from_slice(b"NOT-OURS");
        fs::write(s.path(), &foreign).expect("write");
        let err = load_or_create(&s, || panic!("must not generate")).expect_err("must fail");
        assert!(matches!(err, KeyError::Unprotect(_)), "{err:?}");
        assert_eq!(fs::read(s.path()).expect("read"), foreign, "file changed");
    }

    #[test]
    fn a_wrong_header_or_length_is_corrupt() {
        let dir = tempfile::tempdir().expect("tempdir");
        let s = store(&dir);
        fs::create_dir_all(s.path().parent().expect("parent")).expect("mkdir");
        let fake = FakeProtector::default();
        let short = fake.protect(&[1u8; 31]).expect("protect");
        let cases: Vec<Vec<u8>> = vec![
            Vec::new(),
            b"P2PC-DEVKEY-v2\0\n".to_vec(),
            [b"P2PC-DEVKEY-v2\0\n".as_slice(), &fake.protect(&[1u8; 32]).expect("p")].concat(),
            [HEADER.as_slice(), &short].concat(),
        ];
        for data in cases {
            fs::write(s.path(), &data).expect("write");
            assert!(matches!(s.load(), Err(KeyError::Corrupt)), "{data:?}");
        }
    }

    #[test]
    fn an_oversized_file_is_refused_without_reading_it_all() {
        let dir = tempfile::tempdir().expect("tempdir");
        let s = store(&dir);
        fs::create_dir_all(s.path().parent().expect("parent")).expect("mkdir");
        let mut data = HEADER.to_vec();
        data.resize(MAX_FILE_LEN as usize + 1, b'x');
        fs::write(s.path(), &data).expect("write");
        assert!(matches!(s.load(), Err(KeyError::Corrupt)));
    }

    #[test]
    fn a_failed_protection_writes_nothing() {
        let dir = tempfile::tempdir().expect("tempdir");
        let s = FileKeyStore::new(device_key_path(dir.path()), BrokenProtector);
        assert!(matches!(s.store_new(&key(4)), Err(KeyError::Protect(_))));
        assert!(!s.path().exists());
        // Protection fails before anything is written: no temporary file, not even the folder.
        assert!(!dir.path().join("P2PC").exists());
    }

    #[test]
    fn debug_never_shows_the_key() {
        let k = key(0xab);
        let shown = format!("{k:?}");
        assert_eq!(shown, "DeviceKey(<redacted>)");
        assert!(!shown.contains("171") && !shown.to_lowercase().contains("ab, "));
    }

    #[test]
    fn generated_keys_differ() {
        let a = DeviceKey::generate().expect("random");
        let b = DeviceKey::generate().expect("random");
        assert_ne!(a.as_bytes(), b.as_bytes());
    }
}
