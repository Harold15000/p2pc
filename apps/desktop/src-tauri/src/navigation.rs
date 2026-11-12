// SPDX-License-Identifier: Apache-2.0

//! Where the webview may go (H2 §8.9: "The webview loads only bundled assets. No remote page […] Links open in the
//! system browser").
//!
//! [`decide`] is asked for every navigation and every `window.open`: the app's own bundled origin stays in the
//! webview; an `http`/`https` link opens in the system browser and the webview stays where it is; everything else
//! (`file:`, `data:`, `javascript:`, custom schemes, URLs with credentials) is refused.

use url::Url;

/// The origins Tauri serves the bundled assets from: `tauri://localhost` (Linux, macOS) and `http(s)://tauri.localhost`
/// (Windows, WebView2).
const APP_ORIGINS: [(&str, &str); 3] = [
    ("tauri", "localhost"),
    ("http", "tauri.localhost"),
    ("https", "tauri.localhost"),
];

/// What to do with a URL the webview asks for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Navigation {
    /// The app's own bundled page: load it.
    Allow,
    /// A web link: open it in the system browser, never in the app's webview.
    OpenInBrowser,
    /// Anything else: refuse.
    Deny,
}

/// Decides what to do with `url`.
pub fn decide(url: &Url) -> Navigation {
    if !url.username().is_empty() || url.password().is_some() {
        return Navigation::Deny;
    }
    let scheme = url.scheme();
    let host = url.host_str().unwrap_or_default();
    if url.port().is_none() && APP_ORIGINS.iter().any(|(s, h)| *s == scheme && *h == host) {
        return Navigation::Allow;
    }
    if matches!(scheme, "http" | "https") && !host.is_empty() {
        return Navigation::OpenInBrowser;
    }
    Navigation::Deny
}

#[cfg(test)]
mod tests {
    use super::*;

    fn check(url: &str) -> Navigation {
        decide(&Url::parse(url).expect("valid URL"))
    }

    #[test]
    fn the_bundled_app_stays_in_the_webview() {
        for url in [
            "tauri://localhost",
            "tauri://localhost/index.html",
            "http://tauri.localhost/",
            "https://tauri.localhost/settings?tab=1#x",
        ] {
            assert_eq!(check(url), Navigation::Allow, "{url}");
        }
    }

    #[test]
    fn web_links_open_in_the_system_browser() {
        for url in [
            "https://example.com/help",
            "http://example.com/",
            "https://tauri.localhost.example.com/",
            "https://localhost/",
            "http://tauri.localhost:8080/",
            "http://192.0.2.10/",
        ] {
            assert_eq!(check(url), Navigation::OpenInBrowser, "{url}");
        }
    }

    #[test]
    fn everything_else_is_refused() {
        for url in [
            "file:///C:/Windows/System32/drivers/etc/hosts",
            "data:text/html,<script>alert(1)</script>",
            "javascript:alert(1)",
            "about:blank",
            "ms-settings:privacy",
            "tauri://example.com/",
            "ftp://example.com/",
            "https://user:pass@example.com/", // gitleaks:allow
            "http://user@tauri.localhost/",
        ] {
            assert_eq!(check(url), Navigation::Deny, "{url}");
        }
    }
}
