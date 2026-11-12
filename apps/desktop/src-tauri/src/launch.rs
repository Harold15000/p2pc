// SPDX-License-Identifier: Apache-2.0

//! How the app was started, and what a second start does (H2 §8.1: "One app process per signed-in user, single
//! instance, started at sign-in from `HKCU\…\Run` […], living in the tray").
//!
//! - Started by the user: the main window opens.
//! - Started at sign-in (`--autostart`, the `Run` entry of [`crate::autostart`]): the app stays in the tray.
//! - Started again while it runs: the running instance shows its window (the second process exits; the
//!   single-instance plugin forwards its arguments). A second `--autostart` start changes nothing.
//!
//! - Started by the uninstaller (`--uninstall-cleanup`, §8.7): the cleanup window only, outside the single-instance
//!   rule (the uninstaller closes a running instance first), and the process's exit code tells the uninstaller whether
//!   to go on ([`crate::uninstall::exit`]).
//!
//! Any other argument is refused: the app exits without starting, rather than guess.

use crate::autostart::AUTOSTART_FLAG;
use crate::uninstall::CLEANUP_FLAG;

/// How this process should start.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Launch {
    /// Open the main window.
    Window,
    /// Stay in the tray (start at sign-in).
    Tray,
    /// Run the uninstall cleanup and exit (§8.7).
    UninstallCleanup,
}

/// The arguments are not ones the app knows. The argument itself is not kept.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("unknown command-line arguments")]
pub struct UnknownArguments;

/// Parses the arguments after the program name.
pub fn parse<I, S>(args: I) -> Result<Launch, UnknownArguments>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut args = args.into_iter();
    let launch = match args.next() {
        None => Launch::Window,
        Some(arg) if arg.as_ref() == AUTOSTART_FLAG => Launch::Tray,
        Some(arg) if arg.as_ref() == CLEANUP_FLAG => Launch::UninstallCleanup,
        Some(_) => return Err(UnknownArguments),
    };
    match args.next() {
        None => Ok(launch),
        Some(_) => Err(UnknownArguments),
    }
}

/// What the running instance does when the app is started again.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecondInstance {
    /// Show and focus the main window.
    ShowWindow,
    /// Nothing.
    Ignore,
}

/// Decides what a second start does, from its full `argv` (program name first, as the single-instance plugin hands
/// it over).
pub fn second_instance<S: AsRef<str>>(argv: &[S]) -> SecondInstance {
    match parse(argv.iter().skip(1).map(AsRef::as_ref)) {
        Ok(Launch::Window) => SecondInstance::ShowWindow,
        Ok(Launch::Tray | Launch::UninstallCleanup) | Err(UnknownArguments) => SecondInstance::Ignore,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_plain_start_opens_the_window() {
        assert_eq!(parse(Vec::<String>::new()), Ok(Launch::Window));
    }

    #[test]
    fn a_start_at_sign_in_stays_in_the_tray() {
        assert_eq!(parse(["--autostart"]), Ok(Launch::Tray));
    }

    #[test]
    fn unknown_or_extra_arguments_are_refused() {
        for args in [
            vec!["--uninstall-cleanup", "x"],
            vec!["--UNINSTALL-CLEANUP"],
            vec!["--AUTOSTART"],
            vec!["--autostart", "--autostart"],
            vec!["--autostart", "x"],
            vec![""],
        ] {
            assert_eq!(parse(&args), Err(UnknownArguments), "{args:?}");
        }
    }

    #[test]
    fn the_uninstaller_s_start_runs_the_cleanup() {
        assert_eq!(parse(["--uninstall-cleanup"]), Ok(Launch::UninstallCleanup));
        assert_eq!(
            second_instance(&["P2PC.exe", "--uninstall-cleanup"]),
            SecondInstance::Ignore
        );
    }

    #[test]
    fn a_second_plain_start_shows_the_window() {
        assert_eq!(second_instance(&["P2PC.exe"]), SecondInstance::ShowWindow);
    }

    #[test]
    fn a_second_start_at_sign_in_or_with_unknown_arguments_changes_nothing() {
        assert_eq!(second_instance(&["P2PC.exe", "--autostart"]), SecondInstance::Ignore);
        assert_eq!(second_instance(&["P2PC.exe", "--something"]), SecondInstance::Ignore);
    }

    #[test]
    fn a_second_start_without_even_a_program_name_shows_the_window() {
        assert_eq!(second_instance::<&str>(&[]), SecondInstance::ShowWindow);
    }
}
