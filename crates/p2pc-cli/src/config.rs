// SPDX-License-Identifier: Apache-2.0

//! Profiles, credentials and how they are resolved (spec §7 "CLI conventions").
//!
//! # Files
//!
//! `config.toml` and `credentials.toml` live in one directory:
//! - `$P2PC_CONFIG_DIR`, if it is set;
//! - otherwise `$XDG_CONFIG_HOME/p2pc` (default `~/.config/p2pc`) on Linux and macOS, and `%APPDATA%\p2pc` on Windows.
//!
//! ```toml
//! # config.toml                         # credentials.toml
//! default_profile = "home"              [profiles.home]
//! [profiles.home]                       api_key = "p2pc_sk_…"
//! server = "https://p2pc.example.invalid"
//! ```
//!
//! A profile's `server` is an `https://` or `http://` URL, or a server address `p2pc_srv_…` (spec §10), which is
//! reached through the `p2pc/http/1` tunnel.
//!
//! # Precedence
//!
//! For the profile: `--profile`, then `P2PC_PROFILE`, then `default_profile` of `config.toml`, then `default`.
//! For the server: `--server`, then `P2PC_SERVER`, then the profile's `server`. For the key: `P2PC_API_KEY`, then the
//! profile's `api_key` in `credentials.toml`. **There is no flag for the key**: it would end up in the shell history
//! and in `ps` (spec §7).
//!
//! # Permissions
//!
//! `credentials.toml` is written through a temporary file in the same directory that is created with mode 0600
//! **before** the key is written to it, then renamed over the old file. On Unix the CLI refuses to read a
//! `credentials.toml` that the group or others can read, as `ssh` does, and says how to fix it.
//!
//! On Windows there is no mode to check. The file lives under `%APPDATA%`, which is per user and whose ACL denies other
//! users by default, and the CLI relies on that. Do not point `P2PC_CONFIG_DIR` at a shared folder.
//!
//! # Secrets (SI-6)
//!
//! Keys are [`ApiKey`] values, whose `Debug` and `Display` redact them. Errors about a file never quote its content.

use std::collections::BTreeMap;
use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use p2pc_proto::auth::{ApiKey, ServerAddress};
use serde::{Deserialize, Serialize};
use url::Url;

/// The profile used when nothing selects another.
pub const DEFAULT_PROFILE: &str = "default";
/// The file with the profiles' servers.
pub const CONFIG_FILE: &str = "config.toml";
/// The file with the profiles' keys.
pub const CREDENTIALS_FILE: &str = "credentials.toml";
/// What a server address starts with (spec §10).
pub const SERVER_ADDRESS_PREFIX: &str = p2pc_proto::auth::SERVER_ADDRESS_PREFIX;

/// An environment lookup. The real one is `std::env::var`; tests pass a map.
pub type Env<'a> = &'a dyn Fn(&str) -> Option<String>;

/// The operating system family, for the location of the files.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Os {
    /// Linux and macOS: XDG.
    Unix,
    /// Windows: `%APPDATA%`.
    Windows,
}

impl Os {
    /// The system this binary runs on.
    #[must_use]
    pub const fn current() -> Self {
        if cfg!(windows) { Os::Windows } else { Os::Unix }
    }
}

/// Why a configuration or credentials operation failed. No message holds a key.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// A file could not be read or written.
    #[error("{path}: {source}")]
    Io {
        /// The file.
        path: String,
        /// The cause.
        source: io::Error,
    },
    /// `credentials.toml` can be read by other users.
    #[error("{path} is readable by other users (mode {mode:04o}); refusing to use it. Fix it with: chmod 600 {path}")]
    InsecurePermissions {
        /// The file.
        path: String,
        /// Its mode.
        mode: u32,
    },
    /// A file is not valid TOML of the expected shape.
    #[error("{path}: {message}")]
    Parse {
        /// The file.
        path: String,
        /// What is wrong, without quoting the file.
        message: String,
    },
    /// The server starts with `p2pc_srv_` but is not a valid server address.
    #[error("that is not a valid server address (p2pc_srv_…); copy it again from `p2pc-server init` or GET /v1/server")]
    InvalidServerAddress,
    /// The server value is not an `http://` or `https://` URL.
    #[error("the server {0:?} is not a valid http:// or https:// URL")]
    InvalidServer(String),
    /// No place for the files could be determined.
    #[error("cannot find a configuration directory: set P2PC_CONFIG_DIR")]
    NoConfigDir,
    /// `P2PC_API_KEY` or a stored key is not a well-formed key.
    #[error("{origin} does not hold a valid API key (expected p2pc_sk_<id>_<secret>)")]
    InvalidKey {
        /// Where the key came from.
        origin: String,
    },
    /// No key for the profile.
    #[error("not logged in (profile {profile:?}): run `p2pc login`, or set P2PC_API_KEY")]
    NotLoggedIn {
        /// The profile.
        profile: String,
    },
    /// No server for the profile.
    #[error("no server for profile {profile:?}: run `p2pc login --server URL`, or set P2PC_SERVER")]
    NoServer {
        /// The profile.
        profile: String,
    },
}

/// `config.toml`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfigFile {
    /// The profile used when nothing else selects one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_profile: Option<String>,
    /// Profiles by name.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub profiles: BTreeMap<String, ProfileConfig>,
}

/// One profile of `config.toml`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProfileConfig {
    /// The server: an `https://` or `http://` URL, or a server address `p2pc_srv_…`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server: Option<String>,
}

/// `credentials.toml`. `Debug` redacts the keys.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Credentials {
    /// Keys by profile name.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub profiles: BTreeMap<String, ProfileCredentials>,
}

/// One profile of `credentials.toml`. `Debug` redacts the key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProfileCredentials {
    /// The API key.
    pub api_key: ApiKey,
}

/// The directory of `config.toml` and `credentials.toml`.
pub fn config_dir(os: Os, env: Env) -> Result<PathBuf, ConfigError> {
    let get = |name: &str| env(name).filter(|v| !v.is_empty());
    if let Some(dir) = get("P2PC_CONFIG_DIR") {
        return Ok(PathBuf::from(dir));
    }
    match os {
        Os::Windows => get("APPDATA")
            .map(|dir| PathBuf::from(dir).join("p2pc"))
            .ok_or(ConfigError::NoConfigDir),
        Os::Unix => {
            // XDG: a relative `XDG_CONFIG_HOME` is invalid and ignored.
            if let Some(base) = get("XDG_CONFIG_HOME").map(PathBuf::from).filter(|p| p.is_absolute()) {
                return Ok(base.join("p2pc"));
            }
            get("HOME")
                .map(|home| PathBuf::from(home).join(".config").join("p2pc"))
                .ok_or(ConfigError::NoConfigDir)
        }
    }
}

/// Reads and writes the two files of a configuration directory.
#[derive(Debug, Clone)]
pub struct Store {
    dir: PathBuf,
}

impl Store {
    /// The store in `dir`. Nothing is created until something is saved.
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    /// The directory.
    #[must_use]
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// `config.toml`, or an empty configuration when the file does not exist.
    pub fn load_config(&self) -> Result<ConfigFile, ConfigError> {
        let path = self.dir.join(CONFIG_FILE);
        match read_file(&path)? {
            None => Ok(ConfigFile::default()),
            Some(text) => parse_toml(&path, &text),
        }
    }

    /// Writes `config.toml`.
    pub fn save_config(&self, config: &ConfigFile) -> Result<(), ConfigError> {
        let text = toml::to_string(config).map_err(|e| ConfigError::Parse {
            path: self.dir.join(CONFIG_FILE).display().to_string(),
            message: e.to_string(),
        })?;
        self.write_atomic(CONFIG_FILE, text.as_bytes())
    }

    /// `credentials.toml`, or no credentials when the file does not exist. On Unix, a file that the group or others
    /// can read is refused (the check is made on the open file, so it cannot be swapped between check and read).
    pub fn load_credentials(&self) -> Result<Credentials, ConfigError> {
        let path = self.dir.join(CREDENTIALS_FILE);
        let io_err = |source| ConfigError::Io {
            path: path.display().to_string(),
            source,
        };
        let mut file = match fs::File::open(&path) {
            Ok(f) => f,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Credentials::default()),
            Err(e) => return Err(io_err(e)),
        };
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = file.metadata().map_err(io_err)?.permissions().mode() & 0o777;
            if mode & 0o077 != 0 {
                return Err(ConfigError::InsecurePermissions {
                    path: path.display().to_string(),
                    mode,
                });
            }
        }
        let mut text = String::new();
        file.read_to_string(&mut text).map_err(io_err)?;
        parse_toml(&path, &text)
    }

    /// Writes `credentials.toml` with mode 0600 on Unix: through a temporary file in the same directory, created
    /// private **before** the keys are written to it, and renamed over the old file.
    pub fn save_credentials(&self, credentials: &Credentials) -> Result<(), ConfigError> {
        let text = toml::to_string(credentials).map_err(|_| ConfigError::Parse {
            path: self.dir.join(CREDENTIALS_FILE).display().to_string(),
            // Never `e.to_string()`: serializer errors may quote values.
            message: "could not serialize the credentials".into(),
        })?;
        self.write_atomic(CREDENTIALS_FILE, text.as_bytes())
    }

    fn write_atomic(&self, name: &str, contents: &[u8]) -> Result<(), ConfigError> {
        let path = self.dir.join(name);
        let io_err = |source| ConfigError::Io {
            path: path.display().to_string(),
            source,
        };
        create_private_dir(&self.dir).map_err(io_err)?;
        // `tempfile` creates the file with mode 0600 on Unix; the explicit call below makes the promise visible and
        // survives a change of default. The key is only written after it.
        let mut tmp = tempfile::Builder::new()
            .prefix(&format!(".{name}."))
            .suffix(".tmp")
            .tempfile_in(&self.dir)
            .map_err(io_err)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            tmp.as_file()
                .set_permissions(fs::Permissions::from_mode(0o600))
                .map_err(io_err)?;
        }
        tmp.write_all(contents).map_err(io_err)?;
        tmp.as_file().sync_all().map_err(io_err)?;
        // On error `tempfile` removes the temporary file when it is dropped.
        tmp.persist(&path).map_err(|e| io_err(e.error))?;
        Ok(())
    }
}

fn create_private_dir(dir: &Path) -> io::Result<()> {
    if dir.is_dir() {
        return Ok(());
    }
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(dir)
}

fn read_file(path: &Path) -> Result<Option<String>, ConfigError> {
    match fs::read_to_string(path) {
        Ok(text) => Ok(Some(text)),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(source) => Err(ConfigError::Io {
            path: path.display().to_string(),
            source,
        }),
    }
}

/// Parses a TOML file. The error carries the message and the position, never the offending text: `toml`'s own
/// `Display` quotes the line, which for `credentials.toml` would be a key.
fn parse_toml<T: serde::de::DeserializeOwned>(path: &Path, text: &str) -> Result<T, ConfigError> {
    toml::from_str(text).map_err(|e| {
        let position = e.span().map_or(String::new(), |span| {
            let line = text[..span.start.min(text.len())].matches('\n').count() + 1;
            format!(" (line {line})")
        });
        ConfigError::Parse {
            path: path.display().to_string(),
            message: format!("{}{position}", e.message()),
        }
    })
}

/// Checks a server value: an `http://` or `https://` URL, or a server address `p2pc_srv_…`.
pub fn validate_server(text: &str) -> Result<String, ConfigError> {
    Server::parse(text)?;
    Ok(text.trim().to_string())
}

/// A server, as a profile names it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Server {
    /// An `http://` or `https://` base URL.
    Url(String),
    /// A server address, reached through the `p2pc/http/1` tunnel (spec §10).
    Address(ServerAddress),
}

impl Server {
    /// Parses a server value (surrounding whitespace is ignored).
    pub fn parse(text: &str) -> Result<Self, ConfigError> {
        let text = text.trim();
        if text.starts_with(SERVER_ADDRESS_PREFIX) {
            return ServerAddress::parse(text)
                .map(Server::Address)
                .map_err(|_| ConfigError::InvalidServerAddress);
        }
        match Url::parse(text) {
            Ok(url) if matches!(url.scheme(), "http" | "https") && url.host_str().is_some() => {
                Ok(Server::Url(text.to_string()))
            }
            _ => Err(ConfigError::InvalidServer(text.to_string())),
        }
    }
}

/// What the command line says about the profile and the server.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Flags {
    /// `--profile`.
    pub profile: Option<String>,
    /// `--server`.
    pub server: Option<String>,
}

/// Everything a command needs to reach the server.
#[derive(Debug, Clone)]
pub struct Target {
    /// The profile that was selected.
    pub profile: String,
    /// The server: a URL or a server address `p2pc_srv_…`.
    pub server: String,
    /// The key (`Debug` redacts it).
    pub api_key: ApiKey,
}

/// The profile: `--profile`, then `P2PC_PROFILE`, then `default_profile` of `config.toml`, then `default`.
#[must_use]
pub fn resolve_profile(flags: &Flags, env: Env, config: &ConfigFile) -> String {
    let non_empty = |v: Option<String>| v.filter(|s| !s.is_empty());
    non_empty(flags.profile.clone())
        .or_else(|| non_empty(env("P2PC_PROFILE")))
        .or_else(|| non_empty(config.default_profile.clone()))
        .unwrap_or_else(|| DEFAULT_PROFILE.to_string())
}

/// The server: `--server`, then `P2PC_SERVER`, then the profile's `server`. `None` when none is set.
pub fn resolve_server(
    flags: &Flags,
    env: Env,
    config: &ConfigFile,
    profile: &str,
) -> Result<Option<String>, ConfigError> {
    let non_empty = |v: Option<String>| v.filter(|s| !s.is_empty());
    let found = non_empty(flags.server.clone())
        .or_else(|| non_empty(env("P2PC_SERVER")))
        .or_else(|| config.profiles.get(profile).and_then(|p| non_empty(p.server.clone())));
    found.map(|s| validate_server(&s)).transpose()
}

/// The key: `P2PC_API_KEY`, then the profile's key in `credentials.toml`. The file is only read (and its permissions
/// only checked) when the variable is not set. `None` when there is no key.
pub fn resolve_api_key(env: Env, store: &Store, profile: &str) -> Result<Option<ApiKey>, ConfigError> {
    if let Some(text) = env("P2PC_API_KEY").filter(|v| !v.is_empty()) {
        return ApiKey::parse(text.trim())
            .map(Some)
            .map_err(|_| ConfigError::InvalidKey {
                origin: "P2PC_API_KEY".into(),
            });
    }
    Ok(store
        .load_credentials()?
        .profiles
        .get(profile)
        .map(|p| p.api_key.clone()))
}

/// The profile, server and key, or the error that says what is missing.
pub fn resolve_target(flags: &Flags, env: Env, store: &Store) -> Result<Target, ConfigError> {
    let config = store.load_config()?;
    let profile = resolve_profile(flags, env, &config);
    let server = resolve_server(flags, env, &config, &profile)?.ok_or_else(|| ConfigError::NoServer {
        profile: profile.clone(),
    })?;
    let api_key = resolve_api_key(env, store, &profile)?.ok_or_else(|| ConfigError::NotLoggedIn {
        profile: profile.clone(),
    })?;
    Ok(Target {
        profile,
        server,
        api_key,
    })
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    fn env_of<'a>(pairs: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<String> + 'a {
        let map: HashMap<&str, &str> = pairs.iter().copied().collect();
        move |name| map.get(name).map(|v| (*v).to_string())
    }

    fn creds_with(profile: &str, key: &ApiKey) -> Credentials {
        Credentials {
            profiles: BTreeMap::from([(profile.to_string(), ProfileCredentials { api_key: key.clone() })]),
        }
    }

    #[test]
    fn config_dir_prefers_p2pc_config_dir_then_xdg_then_home() {
        let env = env_of(&[
            ("P2PC_CONFIG_DIR", "/x/p2pc"),
            ("XDG_CONFIG_HOME", "/xdg"),
            ("HOME", "/home/u"),
        ]);
        assert_eq!(config_dir(Os::Unix, &env).unwrap(), PathBuf::from("/x/p2pc"));
        let env = env_of(&[("XDG_CONFIG_HOME", "/xdg"), ("HOME", "/home/u")]);
        assert_eq!(config_dir(Os::Unix, &env).unwrap(), PathBuf::from("/xdg/p2pc"));
        let env = env_of(&[("HOME", "/home/u")]);
        assert_eq!(
            config_dir(Os::Unix, &env).unwrap(),
            PathBuf::from("/home/u/.config/p2pc")
        );
        // A relative XDG_CONFIG_HOME is ignored, as the XDG specification says.
        let env = env_of(&[("XDG_CONFIG_HOME", "relative"), ("HOME", "/home/u")]);
        assert_eq!(
            config_dir(Os::Unix, &env).unwrap(),
            PathBuf::from("/home/u/.config/p2pc")
        );
        assert!(config_dir(Os::Unix, &env_of(&[])).is_err());
    }

    #[test]
    fn config_dir_on_windows_uses_appdata() {
        let env = env_of(&[("APPDATA", "C:/Users/u/AppData/Roaming"), ("HOME", "/ignored")]);
        assert_eq!(
            config_dir(Os::Windows, &env).unwrap(),
            PathBuf::from("C:/Users/u/AppData/Roaming").join("p2pc")
        );
        let env = env_of(&[("P2PC_CONFIG_DIR", "D:/cfg"), ("APPDATA", "C:/a")]);
        assert_eq!(config_dir(Os::Windows, &env).unwrap(), PathBuf::from("D:/cfg"));
        assert!(config_dir(Os::Windows, &env_of(&[])).is_err());
    }

    #[test]
    fn profile_precedence_is_flag_env_file_default() {
        let config = ConfigFile {
            default_profile: Some("from-file".into()),
            ..Default::default()
        };
        let flags = Flags {
            profile: Some("from-flag".into()),
            ..Default::default()
        };
        let env = env_of(&[("P2PC_PROFILE", "from-env")]);
        assert_eq!(resolve_profile(&flags, &env, &config), "from-flag");
        assert_eq!(resolve_profile(&Flags::default(), &env, &config), "from-env");
        assert_eq!(resolve_profile(&Flags::default(), &env_of(&[]), &config), "from-file");
        assert_eq!(
            resolve_profile(&Flags::default(), &env_of(&[]), &ConfigFile::default()),
            "default"
        );
    }

    #[test]
    fn server_precedence_is_flag_env_file() {
        let config = ConfigFile {
            profiles: BTreeMap::from([(
                "p".into(),
                ProfileConfig {
                    server: Some("https://file.example.invalid".into()),
                },
            )]),
            ..Default::default()
        };
        let flags = Flags {
            server: Some("https://flag.example.invalid".into()),
            ..Default::default()
        };
        let env = env_of(&[("P2PC_SERVER", "https://env.example.invalid")]);
        let got = |f: &Flags, e: Env| resolve_server(f, e, &config, "p").unwrap();
        assert_eq!(got(&flags, &env).as_deref(), Some("https://flag.example.invalid"));
        assert_eq!(
            got(&Flags::default(), &env).as_deref(),
            Some("https://env.example.invalid")
        );
        assert_eq!(
            got(&Flags::default(), &env_of(&[])).as_deref(),
            Some("https://file.example.invalid")
        );
        assert_eq!(
            resolve_server(&Flags::default(), &env_of(&[]), &config, "other").unwrap(),
            None
        );
    }

    fn address() -> String {
        p2pc_proto::auth::ServerAddress::new(
            "a".repeat(64),
            vec![Url::parse("https://relay.example.invalid/").unwrap()],
        )
        .encode()
        .unwrap()
    }

    #[test]
    fn a_server_address_is_accepted_from_every_source() {
        let addr = address();
        for source in ["flag", "env", "file"] {
            let mut flags = Flags::default();
            let mut config = ConfigFile::default();
            let env_pairs = [("P2PC_SERVER", addr.as_str())];
            let env = if source == "env" {
                env_of(&env_pairs)
            } else {
                env_of(&[])
            };
            match source {
                "flag" => flags.server = Some(addr.clone()),
                "file" => {
                    config.profiles.insert(
                        "p".into(),
                        ProfileConfig {
                            server: Some(addr.clone()),
                        },
                    );
                }
                _ => {}
            }
            let got = resolve_server(&flags, &env, &config, "p").unwrap();
            assert_eq!(got.as_deref(), Some(addr.as_str()), "{source}");
            assert!(matches!(Server::parse(&addr).unwrap(), Server::Address(_)));
        }
    }

    #[test]
    fn a_malformed_server_address_is_refused_with_a_clear_message() {
        for bad in ["p2pc_srv_MFRGGZDFMZTWQ2LK", "p2pc_srv_", "p2pc_srv_!!!"] {
            let err = validate_server(bad).unwrap_err();
            assert!(matches!(err, ConfigError::InvalidServerAddress), "{bad}: {err}");
            assert!(err.to_string().contains("p2pc_srv_"), "{err}");
        }
    }

    #[test]
    fn servers_that_are_not_urls_are_refused() {
        for bad in ["ftp://example.invalid", "example.invalid", "https://", "not a url"] {
            assert!(validate_server(bad).is_err(), "{bad}");
        }
        assert!(validate_server("http://127.0.0.1:7477").is_ok());
        assert!(validate_server("https://p2pc.example.invalid/api").is_ok());
    }

    #[test]
    fn the_key_comes_from_the_environment_before_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::new(dir.path());
        let file_key = ApiKey::generate();
        store.save_credentials(&creds_with("p", &file_key)).unwrap();
        let env_key = ApiKey::generate();
        let text = env_key.expose();
        let pairs = [("P2PC_API_KEY", text.as_str())];
        let env = env_of(&pairs);
        assert_eq!(resolve_api_key(&env, &store, "p").unwrap(), Some(env_key));
        assert_eq!(resolve_api_key(&env_of(&[]), &store, "p").unwrap(), Some(file_key));
        assert_eq!(resolve_api_key(&env_of(&[]), &store, "other").unwrap(), None);
    }

    #[test]
    fn the_environment_key_does_not_need_a_readable_credentials_file() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join(CREDENTIALS_FILE), "this is not toml").unwrap();
        let key = ApiKey::generate();
        let text = key.expose();
        let pairs = [("P2PC_API_KEY", text.as_str())];
        let env = env_of(&pairs);
        assert!(resolve_api_key(&env, &Store::new(dir.path()), "p").is_ok());
    }

    #[test]
    fn a_malformed_environment_key_is_refused_without_echoing_it() {
        let dir = tempfile::tempdir().unwrap();
        let env = env_of(&[("P2PC_API_KEY", "p2pc_sk_not-a-real-key-SECRETVALUE")]);
        let err = resolve_api_key(&env, &Store::new(dir.path()), "p").unwrap_err();
        assert!(!err.to_string().contains("SECRETVALUE"), "{err}");
        assert!(err.to_string().contains("P2PC_API_KEY"));
    }

    #[cfg(unix)]
    fn mode_of(path: &Path) -> u32 {
        use std::os::unix::fs::PermissionsExt;
        fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    #[cfg(unix)]
    fn set_mode(path: &Path, mode: u32) {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn credentials_readable_by_group_or_others_are_refused() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::new(dir.path());
        let key = ApiKey::generate();
        store.save_credentials(&creds_with("p", &key)).unwrap();
        let path = dir.path().join(CREDENTIALS_FILE);
        for mode in [0o644, 0o640, 0o604, 0o660, 0o666] {
            set_mode(&path, mode);
            let err = store.load_credentials().unwrap_err();
            assert!(
                matches!(err, ConfigError::InsecurePermissions { .. }),
                "{mode:o}: {err}"
            );
            let text = err.to_string();
            assert!(text.contains("chmod 600"), "{text}");
            assert!(text.contains(&path.display().to_string()), "{text}");
            assert!(!text.contains(&key.expose()), "{text}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn credentials_with_mode_0600_or_stricter_are_read() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::new(dir.path());
        let key = ApiKey::generate();
        store.save_credentials(&creds_with("p", &key)).unwrap();
        let path = dir.path().join(CREDENTIALS_FILE);
        for mode in [0o600, 0o400] {
            set_mode(&path, mode);
            assert_eq!(store.load_credentials().unwrap().profiles["p"].api_key, key, "{mode:o}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn the_atomic_write_leaves_mode_0600_and_no_temporary_files() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::new(dir.path().join("nested").join("p2pc"));
        let first = ApiKey::generate();
        store.save_credentials(&creds_with("p", &first)).unwrap();
        let path = store.dir().join(CREDENTIALS_FILE);
        assert_eq!(mode_of(&path), 0o600);
        assert_eq!(mode_of(store.dir()), 0o700, "the directory is private too");
        // Overwrite: still 0600, the new key wins, and nothing is left behind.
        let second = ApiKey::generate();
        store.save_credentials(&creds_with("p", &second)).unwrap();
        assert_eq!(mode_of(&path), 0o600);
        assert_eq!(store.load_credentials().unwrap().profiles["p"].api_key, second);
        let names: Vec<_> = fs::read_dir(store.dir())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, vec![CREDENTIALS_FILE.to_string()]);
    }

    #[cfg(unix)]
    #[test]
    fn a_widely_readable_file_is_replaced_by_a_private_one() {
        // `p2pc login` fixes a bad file by writing a new one: the mode of the old file does not carry over.
        let dir = tempfile::tempdir().unwrap();
        let store = Store::new(dir.path());
        let path = dir.path().join(CREDENTIALS_FILE);
        fs::write(&path, "").unwrap();
        set_mode(&path, 0o644);
        store.save_credentials(&creds_with("p", &ApiKey::generate())).unwrap();
        assert_eq!(mode_of(&path), 0o600);
        assert!(store.load_credentials().is_ok());
    }

    #[test]
    fn config_round_trips_and_a_missing_file_is_empty() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::new(dir.path());
        assert_eq!(store.load_config().unwrap(), ConfigFile::default());
        assert_eq!(store.load_credentials().unwrap(), Credentials::default());
        let config = ConfigFile {
            default_profile: Some("home".into()),
            profiles: BTreeMap::from([(
                "home".into(),
                ProfileConfig {
                    server: Some("https://p2pc.example.invalid".into()),
                },
            )]),
        };
        store.save_config(&config).unwrap();
        assert_eq!(store.load_config().unwrap(), config);
    }

    #[test]
    fn a_broken_credentials_file_is_reported_without_quoting_it() {
        let dir = tempfile::tempdir().unwrap();
        let key = ApiKey::generate().expose();
        // A key that is almost right, so a naive error would quote it.
        let almost = format!("{}X", &key[..key.len() - 1]);
        let path = dir.path().join(CREDENTIALS_FILE);
        fs::write(&path, format!("[profiles.p]\napi_key = \"{almost}\"\n")).unwrap();
        #[cfg(unix)]
        set_mode(&path, 0o600);
        let err = Store::new(dir.path()).load_credentials().unwrap_err();
        let text = format!("{err} {err:?}");
        assert!(matches!(err, ConfigError::Parse { .. }), "{text}");
        assert!(!text.contains(&almost[12..]), "{text}");

        fs::write(&path, format!("api_key = \"{key}\"\n= broken\n")).unwrap();
        let err = Store::new(dir.path()).load_credentials().unwrap_err();
        assert!(!format!("{err} {err:?}").contains(&key[12..]));
    }

    #[test]
    fn debug_output_of_credentials_and_targets_never_contains_the_key() {
        let key = ApiKey::generate();
        let secret = key.expose();
        let secret_part = secret.rsplit('_').next().unwrap().to_string();
        let creds = creds_with("p", &key);
        let target = Target {
            profile: "p".into(),
            server: "https://example.invalid".into(),
            api_key: key.clone(),
        };
        for text in [
            format!("{creds:?}"),
            format!("{creds:#?}"),
            format!("{:?}", creds.profiles["p"]),
            format!("{target:?}"),
            format!("{target:#?}"),
        ] {
            assert!(!text.contains(&secret_part), "{text}");
        }
    }

    #[test]
    fn resolve_target_reports_what_is_missing() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::new(dir.path());
        let env = env_of(&[]);
        let err = resolve_target(&Flags::default(), &env, &store).unwrap_err();
        assert!(matches!(err, ConfigError::NoServer { .. }), "{err}");
        let flags = Flags {
            server: Some("https://example.invalid".into()),
            ..Default::default()
        };
        let err = resolve_target(&flags, &env, &store).unwrap_err();
        assert!(matches!(err, ConfigError::NotLoggedIn { .. }), "{err}");
        assert!(err.to_string().contains("p2pc login"));
        let key = ApiKey::generate();
        store.save_credentials(&creds_with("default", &key)).unwrap();
        let target = resolve_target(&flags, &env, &store).unwrap();
        assert_eq!((target.profile.as_str(), target.api_key), ("default", key));
    }
}
