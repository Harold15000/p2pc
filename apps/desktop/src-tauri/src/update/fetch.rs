// SPDX-License-Identifier: Apache-2.0

//! Bounded HTTPS GETs for the update checks (§9.6, §14.1), behind [`Fetch`] so that every check is tested with a fake.
//!
//! The real one, [`HttpsGet`], is `p2pc-wsl`'s fetcher: HTTPS only, rustls with the OS certificate store, a 30 s
//! connect and a 60 s read timeout, and no identifier beyond the app's user agent (§14.1: "carrying no identifier").
//! Every body is capped: a hostile host cannot make the app read without end.

use std::io::Read;

use p2pc_wsl::image::{HttpFetcher, RangeFetch};

/// Why a GET gave no body.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FetchError {
    /// The server answered 404 or 410: there is no such file.
    #[error("not found")]
    NotFound,
    /// Any other status than 200.
    #[error("HTTP status {0}")]
    Status(u16),
    /// The body is larger than the cap.
    #[error("larger than {0} bytes")]
    TooLarge(u64),
    /// The request did not complete (DNS, TLS, timeout, a broken connection).
    #[error("network error: {0}")]
    Network(String),
}

/// A bounded GET.
pub trait Fetch: Send + Sync {
    /// The body of `url`, at most `max_bytes` long.
    fn get(&self, url: &str, max_bytes: u64) -> Result<Vec<u8>, FetchError>;
}

/// The real [`Fetch`]. Blocking: call it from a blocking thread.
#[derive(Debug, Clone)]
pub struct HttpsGet(HttpFetcher);

impl HttpsGet {
    /// An HTTPS-only client.
    pub fn new() -> Result<Self, FetchError> {
        HttpFetcher::new()
            .map(Self)
            .map_err(|e| FetchError::Network(e.to_string()))
    }
}

/// Reads at most `max_bytes` of a body; one byte more is [`FetchError::TooLarge`].
pub fn read_capped(body: &mut dyn Read, max_bytes: u64) -> Result<Vec<u8>, FetchError> {
    let mut out = Vec::new();
    body.take(max_bytes.saturating_add(1))
        .read_to_end(&mut out)
        .map_err(|e| FetchError::Network(e.to_string()))?;
    if out.len() as u64 > max_bytes {
        return Err(FetchError::TooLarge(max_bytes));
    }
    Ok(out)
}

impl Fetch for HttpsGet {
    fn get(&self, url: &str, max_bytes: u64) -> Result<Vec<u8>, FetchError> {
        let mut resp = self.0.fetch(url, 0).map_err(FetchError::Network)?;
        match resp.status {
            200 => {}
            404 | 410 => return Err(FetchError::NotFound),
            s => return Err(FetchError::Status(s)),
        }
        if resp.content_length.is_some_and(|n| n > max_bytes) {
            return Err(FetchError::TooLarge(max_bytes));
        }
        read_capped(&mut resp.body, max_bytes)
    }
}

#[cfg(test)]
pub(crate) mod fake {
    //! A fake [`Fetch`]: canned bodies by URL, every request recorded.

    use std::collections::HashMap;
    use std::sync::Mutex;

    use super::*;

    #[derive(Default)]
    pub(crate) struct FakeFetch {
        bodies: Mutex<HashMap<String, Result<Vec<u8>, FetchError>>>,
        requests: Mutex<Vec<String>>,
    }

    impl FakeFetch {
        pub(crate) fn serve(&self, url: &str, body: impl Into<Vec<u8>>) -> &Self {
            self.bodies.lock().unwrap().insert(url.to_owned(), Ok(body.into()));
            self
        }

        pub(crate) fn fail(&self, url: &str, err: FetchError) -> &Self {
            self.bodies.lock().unwrap().insert(url.to_owned(), Err(err));
            self
        }

        pub(crate) fn requests(&self) -> Vec<String> {
            self.requests.lock().unwrap().clone()
        }
    }

    impl Fetch for FakeFetch {
        fn get(&self, url: &str, max_bytes: u64) -> Result<Vec<u8>, FetchError> {
            self.requests.lock().unwrap().push(url.to_owned());
            let body = self
                .bodies
                .lock()
                .unwrap()
                .get(url)
                .cloned()
                .unwrap_or(Err(FetchError::NotFound))?;
            read_capped(&mut body.as_slice(), max_bytes)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_body_over_the_cap_is_refused_without_reading_further() {
        let mut endless = std::io::repeat(b'x');
        assert_eq!(read_capped(&mut endless, 10), Err(FetchError::TooLarge(10)));
        assert_eq!(read_capped(&mut &b"0123456789"[..], 10).unwrap().len(), 10);
    }
}
