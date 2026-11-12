// SPDX-License-Identifier: Apache-2.0

//! The app's security configuration, checked as data (H2 §8.9).
//!
//! The Tauri files are the source of truth (`tauri.conf.json` for the CSP and the window, `capabilities/main.json` for
//! what the window may call, `Cargo.toml` for the plugins). The tests below pin them, so that a wider grant, a weaker
//! CSP or a new plugin fails `cargo test` here, on any machine, without building the Tauri glue:
//!
//! - the main window may call exactly the app's own commands ([`crate::commands::COMMANDS`]); no core, shell,
//!   filesystem, HTTP or opener permission, and no remote origin;
//! - the webview loads only bundled assets, under a strict CSP with no `eval` and no inline script;
//! - the only Tauri plugins are single instance and opener, both used from Rust only.

use crate::commands::COMMANDS;

/// The capability identifier of the main window.
pub const MAIN_CAPABILITY: &str = "main";

/// The main window's label.
pub const MAIN_WINDOW: &str = "main";

/// Tauri's permission name for an app command: `allow-` and the name with dashes.
pub fn permission(command: &str) -> String {
    format!("allow-{}", command.replace('_', "-"))
}

/// The permissions the main window gets: one per app command.
pub fn main_window_permissions() -> Vec<String> {
    COMMANDS.iter().map(|c| permission(c)).collect()
}

/// The Tauri plugins the app may depend on. Neither adds a permission to the webview: the app grants none of theirs.
pub const ALLOWED_PLUGINS: [&str; 2] = ["tauri-plugin-opener", "tauri-plugin-single-instance"];

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use serde_json::Value;

    use super::*;

    const CAPABILITY: &str = include_str!("../capabilities/main.json");
    const CONFIG: &str = include_str!("../tauri.conf.json");
    const MANIFEST: &str = include_str!("../Cargo.toml");

    fn json(text: &str) -> Value {
        serde_json::from_str(text).expect("valid JSON")
    }

    fn keys(value: &Value) -> BTreeSet<String> {
        value.as_object().expect("object").keys().cloned().collect()
    }

    #[test]
    fn permission_names_follow_tauri_s_rule() {
        assert_eq!(permission("status"), "allow-status");
        assert_eq!(permission("set_autostart"), "allow-set-autostart");
    }

    #[test]
    fn commands_are_unique_snake_case_names() {
        let unique: BTreeSet<_> = COMMANDS.iter().collect();
        assert_eq!(unique.len(), COMMANDS.len());
        for c in COMMANDS {
            assert!(
                !c.is_empty() && c.chars().all(|ch| ch.is_ascii_lowercase() || ch == '_'),
                "{c}"
            );
        }
    }

    #[test]
    fn the_main_window_gets_exactly_the_app_s_commands() {
        let cap = json(CAPABILITY);
        assert_eq!(
            keys(&cap),
            ["description", "identifier", "local", "permissions", "windows"]
                .map(String::from)
                .into()
        );
        assert_eq!(cap["identifier"], MAIN_CAPABILITY);
        assert_eq!(cap["local"], true);
        assert_eq!(cap["windows"], serde_json::json!([MAIN_WINDOW]));
        let granted: Vec<String> = cap["permissions"]
            .as_array()
            .expect("permissions")
            .iter()
            .map(|p| p.as_str().expect("a plain permission name, no scope").to_owned())
            .collect();
        assert_eq!(granted, main_window_permissions());
    }

    #[test]
    fn no_plugin_or_core_permission_is_granted() {
        let cap = json(CAPABILITY);
        for p in cap["permissions"].as_array().expect("permissions") {
            let p = p.as_str().expect("string");
            assert!(!p.contains(':'), "plugin or core permission granted: {p}");
        }
        assert!(cap.get("remote").is_none(), "remote origins must not get capabilities");
        assert!(cap.get("webviews").is_none());
        assert!(cap.get("platforms").is_none());
    }

    #[test]
    fn only_the_main_capability_is_enabled() {
        let config = json(CONFIG);
        assert_eq!(
            config["app"]["security"]["capabilities"],
            serde_json::json!([MAIN_CAPABILITY])
        );
    }

    #[test]
    fn the_csp_is_strict() {
        let config = json(CONFIG);
        let csp: BTreeMap<String, String> =
            serde_json::from_value(config["app"]["security"]["csp"].clone()).expect("CSP as a directive map");
        let expected: BTreeMap<String, String> = [
            ("default-src", "'self'"),
            ("script-src", "'self'"),
            ("style-src", "'self'"),
            ("img-src", "'self' data:"),
            ("font-src", "'self'"),
            ("connect-src", "ipc: http://ipc.localhost"),
            ("object-src", "'none'"),
            ("base-uri", "'none'"),
            ("form-action", "'none'"),
            ("frame-src", "'none'"),
            ("frame-ancestors", "'none'"),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_owned(), v.to_owned()))
        .collect();
        assert_eq!(csp, expected);
        for (directive, sources) in &csp {
            for source in sources.split_whitespace() {
                assert!(
                    !matches!(
                        source,
                        "*" | "'unsafe-eval'" | "'unsafe-inline'" | "'wasm-unsafe-eval'" | "http:" | "https:"
                    ),
                    "{directive}: {source}"
                );
            }
        }
    }

    #[test]
    fn tauri_keeps_its_csp_protections() {
        let security = &json(CONFIG)["app"]["security"];
        assert_eq!(security["freezePrototype"], true);
        for weakening in [
            "dangerousDisableAssetCspModification",
            "devCsp",
            "assetProtocol",
            "pattern",
            "headers",
            "dangerousRemoteDomainIpcAccess",
        ] {
            assert!(security.get(weakening).is_none(), "{weakening} must not be set");
        }
    }

    #[test]
    fn the_webview_loads_only_bundled_assets() {
        let config = json(CONFIG);
        assert!(config["build"].get("devUrl").is_none(), "no dev server URL");
        assert_eq!(config["build"]["frontendDist"], "../ui");
        let windows = config["app"]["windows"].as_array().expect("windows");
        assert_eq!(windows.len(), 1);
        let main = &windows[0];
        assert_eq!(main["label"], MAIN_WINDOW);
        assert!(main.get("url").is_none(), "the window loads the bundled index");
        // Created in Rust, so that its navigation guard is installed before it loads anything.
        assert_eq!(main["create"], false);
        assert_eq!(main["visible"], false);
        assert!(config["app"].get("trayIcon").is_none(), "the tray is built in Rust");
        assert!(config.get("plugins").is_none(), "no plugin configuration");
    }

    #[test]
    fn the_installer_is_per_user_with_the_webview2_bootstrapper() {
        let windows = &json(CONFIG)["bundle"]["windows"];
        assert_eq!(windows["nsis"]["installMode"], "currentUser");
        assert_eq!(windows["webviewInstallMode"]["type"], "downloadBootstrapper");
        assert_eq!(json(CONFIG)["bundle"]["targets"], serde_json::json!(["nsis"]));
    }

    #[test]
    fn the_only_plugins_are_single_instance_and_opener() {
        let mut found = BTreeSet::new();
        for line in MANIFEST.lines().map(str::trim).filter(|l| !l.starts_with('#')) {
            let mut rest = line;
            while let Some(at) = rest.find("tauri-plugin-") {
                let name: String = rest[at..]
                    .chars()
                    .take_while(|c| c.is_ascii_alphanumeric() || *c == '-')
                    .collect();
                found.insert(name);
                rest = &rest[at + "tauri-plugin-".len()..];
            }
        }
        let allowed: BTreeSet<String> = ALLOWED_PLUGINS.iter().map(|s| s.to_string()).collect();
        assert_eq!(found, allowed);
        for forbidden in ["tauri-plugin-shell", "tauri-plugin-fs", "tauri-plugin-http"] {
            assert!(!MANIFEST.contains(forbidden), "{forbidden}");
        }
    }
}
