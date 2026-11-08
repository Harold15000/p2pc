// SPDX-License-Identifier: Apache-2.0

//! Reading the join token (§7 "Credentials", decided while reviewing T15a; SI-6).
//!
//! `p2pc-agent join <token>` accepts the token as an argument for a person typing it, but argv is visible to every
//! user through `ps` (and on Windows it shows up on the command line). So with `-` or no argument the token comes
//! from **stdin** instead: read to the end when stdin is a pipe or a file (our installers and the acceptance harness
//! do this), or from a hidden prompt when it is a terminal.
//!
//! The text lives in a [`Zeroizing`] buffer, and [`TokenText`]'s `Debug` never shows it. Errors never quote it.

use std::fmt;
use std::io::{IsTerminal as _, Read};

use p2pc_proto::auth::JoinToken;
use zeroize::Zeroizing;

/// The warning `join` prints on stderr when the token came as an argument (T14b2 review). It never quotes the token.
pub const ARGV_WARNING: &str = "the token was visible to other users in the process list; next time, paste it when \
                                asked or pipe it on stdin";

/// Whether `arg` puts the token on the command line (anything but `-` or nothing).
#[must_use]
pub fn in_argv(arg: Option<&str>) -> bool {
    arg.is_some_and(|a| a != "-")
}

/// Most bytes read from stdin. A token is well under 1 KiB.
pub const MAX_TOKEN_INPUT: u64 = 8 * 1024;

/// The token's text, as typed or piped. `Debug` shows only its length.
pub struct TokenText(Zeroizing<String>);

impl fmt::Debug for TokenText {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TokenText").field("len", &self.0.len()).finish()
    }
}

/// Why the token could not be read or decoded. Never contains the token.
#[derive(Debug, thiserror::Error)]
pub enum TokenError {
    /// Reading stdin failed.
    #[error("cannot read the join token from stdin: {0}")]
    Read(std::io::Error),
    /// Nothing was given.
    #[error("no join token: pass it as an argument, or pipe it on stdin")]
    Empty,
    /// More than [`MAX_TOKEN_INPUT`] bytes, or more than one word.
    #[error("the input is not a single join token")]
    NotOneToken,
    /// Not a `p2pc_join_…` token this agent can decode.
    #[error("this is not a valid join token (p2pc_join_…); copy it again from `p2pc join-token create`")]
    Malformed,
}

impl TokenText {
    /// Wraps text read from somewhere (argv, stdin, a prompt): trims it and checks that it is one word.
    pub fn new(text: String) -> Result<Self, TokenError> {
        let text = Zeroizing::new(text);
        let trimmed = text.trim();
        if trimmed.is_empty() {
            return Err(TokenError::Empty);
        }
        if trimmed.split_whitespace().nth(1).is_some() || trimmed.len() as u64 > MAX_TOKEN_INPUT {
            return Err(TokenError::NotOneToken);
        }
        Ok(Self(Zeroizing::new(trimmed.to_string())))
    }

    /// The token from `arg`, or from stdin when `arg` is `-` or missing.
    pub fn from_arg_or_stdin(arg: Option<&str>) -> Result<Self, TokenError> {
        match arg {
            Some(a) if a != "-" => Self::new(a.to_string()),
            _ => {
                let stdin = std::io::stdin();
                if stdin.is_terminal() {
                    let typed = rpassword::prompt_password("Join token (input hidden): ").map_err(TokenError::Read)?;
                    Self::new(typed)
                } else {
                    Self::read_from(stdin.lock())
                }
            }
        }
    }

    /// Reads the token from `reader`, to its end (at most [`MAX_TOKEN_INPUT`] bytes).
    pub fn read_from(reader: impl Read) -> Result<Self, TokenError> {
        let mut buf = Zeroizing::new(Vec::new());
        reader
            .take(MAX_TOKEN_INPUT + 1)
            .read_to_end(&mut buf)
            .map_err(TokenError::Read)?;
        if buf.len() as u64 > MAX_TOKEN_INPUT {
            return Err(TokenError::NotOneToken);
        }
        let text = String::from_utf8(buf.to_vec()).map_err(|_| TokenError::Malformed)?;
        Self::new(text)
    }

    /// Decodes it. The result's `Debug` hides the code too.
    pub fn decode(&self) -> Result<JoinToken, TokenError> {
        JoinToken::decode(&self.0).map_err(|_| TokenError::Malformed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET_LOOKING: &str = "p2pc_join_thisisnotarealtokenexampleinvalid"; // gitleaks:allow

    #[test]
    fn stdin_is_read_to_the_end_and_trimmed() {
        let t = TokenText::read_from(format!("  {SECRET_LOOKING}\n").as_bytes()).unwrap();
        assert_eq!(&*t.0, SECRET_LOOKING);
        assert!(matches!(TokenText::read_from(&b"\n\n"[..]), Err(TokenError::Empty)));
        assert!(matches!(
            TokenText::read_from(&b"one two\n"[..]),
            Err(TokenError::NotOneToken)
        ));
        let huge = vec![b'a'; usize::try_from(MAX_TOKEN_INPUT).unwrap() + 10];
        assert!(matches!(TokenText::read_from(&huge[..]), Err(TokenError::NotOneToken)));
    }

    #[test]
    fn only_a_token_in_argv_gets_the_warning() {
        assert!(in_argv(Some(SECRET_LOOKING)));
        assert!(!in_argv(Some("-")));
        assert!(!in_argv(None));
        assert!(!ARGV_WARNING.contains("p2pc_join_"));
    }

    #[test]
    fn the_text_never_shows_in_debug_or_errors() {
        let t = TokenText::new(SECRET_LOOKING.into()).unwrap();
        let shown = format!("{t:?} {t:#?}");
        assert!(!shown.contains("thisisnotareal"), "{shown}");
        let err = t.decode().unwrap_err();
        let shown = format!("{err} {err:?}");
        assert!(!shown.contains("thisisnotareal"), "{shown}");
    }
}
