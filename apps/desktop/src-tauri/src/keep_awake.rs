// SPDX-License-Identifier: Apache-2.0

//! "Keep this PC awake while sharing" (H2 spec §8.6).
//!
//! > "Keep this PC awake while sharing" (off by default; suggested on the hub PC) holds
//! > `SetThreadExecutionState(ES_CONTINUOUS | ES_SYSTEM_REQUIRED)` while the app runs, the state is `sharing` or
//! > `paused`, and, on a laptop, only on AC power. It never changes the Windows power plan.
//!
//! The rule is [`should_hold`], a pure function of the user's setting, the app's state and the power supply. Windows
//! sits behind two traits, so the tests use fakes: [`ExecutionState`] (`SetThreadExecutionState`) and [`PowerSource`]
//! (`GetSystemPowerStatus`).
//!
//! `SetThreadExecutionState` with `ES_CONTINUOUS` is a property of the *calling thread*: it lasts until that thread
//! clears it or ends. So one dedicated thread owns the hold ([`KeepAwake`]): it applies the latest [`Wish`], looks at
//! the power supply again every [`POLL_INTERVAL`] (a laptop unplugged while sharing must stop holding), and releases the
//! hold when it stops. A hold that Windows refused is tried again at the next poll; nothing else is ever left held.
//!
//! The hold is not tied to the node running a job: §8.6 holds it for as long as the state is `sharing` or `paused`,
//! because on the hub PC the phone reaches the cloud only while the PC is awake (§8.5 "Sleep").

use std::sync::mpsc::{self, RecvTimeoutError, Sender};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use crate::state::State;

/// How often the power supply is looked at again, so that unplugging a laptop releases the hold.
pub const POLL_INTERVAL: Duration = Duration::from_secs(30);

/// What the PC reports about its power supply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PowerStatus {
    /// The PC has a battery (a laptop, or a desktop on a UPS that reports as one).
    pub has_battery: bool,
    /// The PC is on AC power.
    pub on_ac: bool,
}

/// The PC's power supply.
pub trait PowerSource: Send + 'static {
    /// The current supply, or `None` when it cannot be read.
    fn status(&mut self) -> Option<PowerStatus>;
}

/// `SetThreadExecutionState`, for the thread that calls it.
pub trait ExecutionState: Send + 'static {
    /// Holds the system awake (`true`: `ES_CONTINUOUS | ES_SYSTEM_REQUIRED`) or releases it (`false`: `ES_CONTINUOUS`
    /// alone). Returns whether the call took effect.
    fn set(&mut self, awake: bool) -> bool;
}

/// What the app wants right now: the user's setting and the app's state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Wish {
    /// "Keep this PC awake while sharing" (settings; off by default).
    pub enabled: bool,
    /// The app's state (§8.4).
    pub state: State,
}

impl Wish {
    /// A wish that holds nothing (the app's start, before it knows anything).
    pub const NONE: Wish = Wish {
        enabled: false,
        state: State::Setup,
    };

    /// The user asked for it and the state is one in which the PC is sharing: `sharing` or `paused` (§8.6). Not while
    /// `setup`, `stopped` (nothing runs), `updating` or in `attention`.
    pub fn wants_awake(self) -> bool {
        self.enabled && matches!(self.state, State::Sharing | State::Paused)
    }
}

/// Whether the power supply allows a hold: a PC with no battery always does, a laptop only on AC power. An unreadable
/// supply does not: the one thing this setting must not do is drain a battery the user did not agree to drain.
pub fn power_allows(power: Option<PowerStatus>) -> bool {
    power.is_some_and(|p| !p.has_battery || p.on_ac)
}

/// The rule of §8.6.
pub fn should_hold(wish: Wish, power: Option<PowerStatus>) -> bool {
    wish.wants_awake() && power_allows(power)
}

/// The supply from Windows' `SYSTEM_POWER_STATUS` fields. `ACLineStatus`: 0 offline, 1 online, 255 unknown.
/// `BatteryFlag`: bit 128 set means "no system battery", 255 unknown. Unknown means a battery on battery power, which
/// holds nothing.
pub fn power_status_from_windows(ac_line_status: u8, battery_flag: u8) -> PowerStatus {
    PowerStatus {
        has_battery: battery_flag == 255 || battery_flag & 128 == 0,
        on_ac: ac_line_status == 1,
    }
}

/// The dedicated thread that owns the hold, and the way to tell it what is wanted. Dropping it releases the hold and
/// ends the thread.
#[derive(Debug)]
pub struct KeepAwake {
    wishes: Option<Sender<Wish>>,
    thread: Option<JoinHandle<()>>,
}

impl KeepAwake {
    /// Starts the thread, holding nothing. `poll` is how often the power supply is read again (use
    /// [`POLL_INTERVAL`]).
    pub fn start(backend: impl ExecutionState, power: impl PowerSource, poll: Duration) -> Self {
        let (wishes, inbox) = mpsc::channel();
        let thread = thread::Builder::new()
            .name("p2pc-keep-awake".into())
            .spawn(move || run(&inbox, backend, power, poll))
            .ok();
        Self {
            // Without a thread there is nobody to tell: the PC simply is not kept awake.
            wishes: thread.as_ref().map(|_| wishes),
            thread,
        }
    }

    /// Starts with this build's Windows calls, or, off Windows, with calls that hold nothing.
    pub fn start_for_this_os() -> Self {
        Self::start(os::Execution, os::Power, POLL_INTERVAL)
    }

    /// Tells the thread what is wanted now. Cheap and idempotent: call it after anything that may change the answer
    /// (a state change, the setting).
    pub fn update(&self, wish: Wish) {
        if let Some(wishes) = &self.wishes {
            // The thread ends only when the channel closes (in `drop`) or if it panicked: nothing to do then.
            let _ = wishes.send(wish);
        }
    }
}

impl Drop for KeepAwake {
    fn drop(&mut self) {
        // Closing the channel ends the thread, which releases a hold before it goes.
        self.wishes = None;
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn run(inbox: &mpsc::Receiver<Wish>, mut backend: impl ExecutionState, mut power: impl PowerSource, poll: Duration) {
    let mut wish = Wish::NONE;
    let mut held = false;
    loop {
        match inbox.recv_timeout(poll) {
            Ok(latest) => wish = latest,
            // Time to look at the power supply again.
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => break,
        }
        // The supply is read only when it matters.
        let want = wish.wants_awake() && power_allows(power.status());
        // A refused call leaves `held` as it was, so the next message or poll tries again.
        if want != held && backend.set(want) {
            held = want;
        }
    }
    if held {
        backend.set(false);
    }
}

#[cfg(not(windows))]
use unsupported as os;
/// Windows' calls, or, elsewhere, calls that hold nothing (the app only ships for Windows, §8.1).
#[cfg(windows)]
use windows_impl as os;

#[cfg(not(windows))]
mod unsupported {
    use super::{ExecutionState, PowerSource, PowerStatus};

    /// Holds nothing: reports every call as refused.
    #[derive(Debug, Clone, Copy)]
    pub struct Execution;

    impl ExecutionState for Execution {
        fn set(&mut self, _: bool) -> bool {
            false
        }
    }

    /// Reads nothing.
    #[derive(Debug, Clone, Copy)]
    pub struct Power;

    impl PowerSource for Power {
        fn status(&mut self) -> Option<PowerStatus> {
            None
        }
    }
}

#[cfg(windows)]
mod windows_impl {
    use windows::Win32::System::Power::{
        ES_CONTINUOUS, ES_SYSTEM_REQUIRED, GetSystemPowerStatus, SYSTEM_POWER_STATUS, SetThreadExecutionState,
    };

    use super::{ExecutionState, PowerSource, PowerStatus, power_status_from_windows};

    /// `SetThreadExecutionState` for the thread that calls it ([`super::KeepAwake`]'s own).
    #[derive(Debug, Clone, Copy)]
    pub struct Execution;

    impl ExecutionState for Execution {
        #[allow(unsafe_code)]
        fn set(&mut self, awake: bool) -> bool {
            let flags = if awake {
                ES_CONTINUOUS | ES_SYSTEM_REQUIRED
            } else {
                ES_CONTINUOUS
            };
            // SAFETY: `SetThreadExecutionState` takes only flags, no pointer, and has no preconditions. It returns the
            // previous state, or 0 when it fails. It touches the calling thread's own state only, and never the power
            // plan.
            unsafe { SetThreadExecutionState(flags).0 != 0 }
        }
    }

    /// `GetSystemPowerStatus`.
    #[derive(Debug, Clone, Copy)]
    pub struct Power;

    impl PowerSource for Power {
        #[allow(unsafe_code)]
        fn status(&mut self) -> Option<PowerStatus> {
            let mut raw = SYSTEM_POWER_STATUS::default();
            // SAFETY: `raw` is a valid, writable `SYSTEM_POWER_STATUS` that lives for the whole call; the function
            // only writes into it.
            unsafe { GetSystemPowerStatus(&mut raw) }.ok()?;
            Some(power_status_from_windows(raw.ACLineStatus, raw.BatteryFlag))
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::mpsc::{Receiver, channel};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use super::*;

    const DESKTOP_ON_AC: PowerStatus = PowerStatus {
        has_battery: false,
        on_ac: true,
    };
    const LAPTOP_ON_AC: PowerStatus = PowerStatus {
        has_battery: true,
        on_ac: true,
    };
    const LAPTOP_ON_BATTERY: PowerStatus = PowerStatus {
        has_battery: true,
        on_ac: false,
    };

    /// A generous bound for waiting on the thread; reached only when a test is about to fail.
    const PATIENCE: Duration = Duration::from_secs(30);

    fn wish(enabled: bool, state: State) -> Wish {
        Wish { enabled, state }
    }

    #[test]
    fn it_holds_only_when_enabled_and_sharing_or_paused() {
        for state in State::ALL {
            let sharing = matches!(state, State::Sharing | State::Paused);
            assert_eq!(
                should_hold(wish(true, state), Some(DESKTOP_ON_AC)),
                sharing,
                "enabled, {state:?}"
            );
            // Off by default and off when the user turned it off: never held, whatever the state.
            assert!(
                !should_hold(wish(false, state), Some(DESKTOP_ON_AC)),
                "disabled, {state:?}"
            );
        }
    }

    #[test]
    fn a_laptop_holds_only_on_ac_power() {
        let on = wish(true, State::Sharing);
        assert!(should_hold(on, Some(LAPTOP_ON_AC)));
        assert!(!should_hold(on, Some(LAPTOP_ON_BATTERY)));
        // A PC without a battery has no battery to drain.
        assert!(should_hold(on, Some(DESKTOP_ON_AC)));
    }

    #[test]
    fn an_unreadable_power_supply_holds_nothing() {
        assert!(!should_hold(wish(true, State::Sharing), None));
    }

    #[test]
    fn windows_power_flags_are_read_conservatively() {
        // (ACLineStatus, BatteryFlag) -> (has_battery, on_ac)
        let cases = [
            ((1, 128), (false, true)),   // desktop on AC: "no system battery"
            ((1, 1), (true, true)),      // laptop on AC, battery high
            ((1, 8), (true, true)),      // laptop on AC, charging
            ((0, 1), (true, false)),     // laptop on battery
            ((255, 255), (true, false)), // unknown: a battery on battery power
            ((255, 128), (false, false)),
        ];
        for ((ac, flag), (has_battery, on_ac)) in cases {
            assert_eq!(
                power_status_from_windows(ac, flag),
                PowerStatus { has_battery, on_ac },
                "ACLineStatus {ac}, BatteryFlag {flag}"
            );
        }
    }

    /// Every call the thread makes, in order, to the fake `SetThreadExecutionState`.
    #[derive(Debug, Clone)]
    struct FakeExecution {
        calls: Arc<Mutex<Vec<bool>>>,
        /// Answers for the next calls (`true` = took effect); `true` once it runs out.
        answers: Arc<Mutex<Vec<bool>>>,
        /// Tells the test that a call happened, so that it waits on this channel and never on a sleep.
        seen: mpsc::Sender<bool>,
    }

    impl ExecutionState for FakeExecution {
        fn set(&mut self, awake: bool) -> bool {
            self.calls.lock().expect("lock").push(awake);
            let answer = {
                let mut answers = self.answers.lock().expect("lock");
                if answers.is_empty() { true } else { answers.remove(0) }
            };
            let _ = self.seen.send(awake);
            answer
        }
    }

    /// A power supply the test changes between polls.
    #[derive(Debug, Clone)]
    struct FakePower(Arc<Mutex<Option<PowerStatus>>>);

    impl PowerSource for FakePower {
        fn status(&mut self) -> Option<PowerStatus> {
            *self.0.lock().expect("lock")
        }
    }

    struct Rig {
        calls: Arc<Mutex<Vec<bool>>>,
        answers: Arc<Mutex<Vec<bool>>>,
        seen: Receiver<bool>,
        power: Arc<Mutex<Option<PowerStatus>>>,
        awake: KeepAwake,
    }

    /// A `KeepAwake` over fakes. `poll` is long unless a test is about the poll.
    fn rig(power: Option<PowerStatus>, poll: Duration) -> Rig {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let answers = Arc::new(Mutex::new(Vec::new()));
        let (seen_tx, seen) = channel();
        let power = Arc::new(Mutex::new(power));
        let awake = KeepAwake::start(
            FakeExecution {
                calls: Arc::clone(&calls),
                answers: Arc::clone(&answers),
                seen: seen_tx,
            },
            FakePower(Arc::clone(&power)),
            poll,
        );
        Rig {
            calls,
            answers,
            seen,
            power,
            awake,
        }
    }

    impl Rig {
        fn next_call(&self) -> bool {
            self.seen.recv_timeout(PATIENCE).expect("the thread made a call")
        }

        /// Stops the thread (releasing any hold) and returns every call it made.
        fn finish(self) -> Vec<bool> {
            let Rig { calls, awake, .. } = self;
            drop(awake);
            let mut made = calls.lock().expect("lock");
            std::mem::take(&mut *made)
        }
    }

    const LONG: Duration = Duration::from_secs(3600);

    #[test]
    fn it_holds_when_sharing_starts_and_releases_when_it_stops() {
        let rig = rig(Some(DESKTOP_ON_AC), LONG);
        rig.awake.update(wish(true, State::Sharing));
        assert!(rig.next_call(), "held");
        rig.awake.update(wish(true, State::Stopped));
        assert!(!rig.next_call(), "released");
        assert_eq!(rig.finish(), vec![true, false]);
    }

    #[test]
    fn repeating_the_same_wish_calls_windows_once() {
        let rig = rig(Some(DESKTOP_ON_AC), LONG);
        for state in [State::Sharing, State::Paused, State::Sharing, State::Paused] {
            rig.awake.update(wish(true, state));
        }
        assert!(rig.next_call());
        // Sharing and paused hold alike: the four wishes made one call. `finish` releases once.
        assert_eq!(rig.finish(), vec![true, false]);
    }

    #[test]
    fn a_hold_is_released_when_the_app_drops_it() {
        let rig = rig(Some(DESKTOP_ON_AC), LONG);
        rig.awake.update(wish(true, State::Paused));
        assert!(rig.next_call());
        assert_eq!(rig.finish(), vec![true, false], "the hold does not outlive its owner");
    }

    #[test]
    fn nothing_is_ever_held_or_released_when_it_is_off() {
        let rig = rig(Some(DESKTOP_ON_AC), LONG);
        for state in State::ALL {
            rig.awake.update(wish(false, state));
        }
        assert_eq!(rig.finish(), Vec::<bool>::new());
    }

    #[test]
    fn turning_the_setting_off_releases_the_hold() {
        let rig = rig(Some(DESKTOP_ON_AC), LONG);
        rig.awake.update(wish(true, State::Sharing));
        assert!(rig.next_call());
        rig.awake.update(wish(false, State::Sharing));
        assert!(!rig.next_call());
        assert_eq!(rig.finish(), vec![true, false]);
    }

    #[test]
    fn a_laptop_on_battery_is_not_held_awake() {
        let rig = rig(Some(LAPTOP_ON_BATTERY), LONG);
        rig.awake.update(wish(true, State::Sharing));
        assert_eq!(rig.finish(), Vec::<bool>::new());
    }

    #[test]
    fn unplugging_a_laptop_releases_the_hold_at_the_next_poll_and_plugging_it_in_holds_again() {
        // A short poll; the test waits on the fake's calls, never on a sleep.
        let rig = rig(Some(LAPTOP_ON_AC), Duration::from_millis(5));
        rig.awake.update(wish(true, State::Sharing));
        assert!(rig.next_call(), "held on AC");
        *rig.power.lock().expect("lock") = Some(LAPTOP_ON_BATTERY);
        assert!(!rig.next_call(), "released on battery, by the poll alone");
        *rig.power.lock().expect("lock") = Some(LAPTOP_ON_AC);
        assert!(rig.next_call(), "held again on AC");
        assert_eq!(rig.finish(), vec![true, false, true, false]);
    }

    #[test]
    fn a_refused_hold_is_tried_again_at_the_next_poll() {
        let rig = rig(Some(DESKTOP_ON_AC), Duration::from_millis(5));
        // Windows refuses the first attempt.
        rig.answers.lock().expect("lock").push(false);
        rig.awake.update(wish(true, State::Sharing));
        assert!(rig.next_call(), "first attempt, refused");
        assert!(rig.next_call(), "second attempt, by the poll");
        // It is held now, so no further attempt; the drop releases once.
        assert_eq!(rig.finish().first(), Some(&true));
    }

    #[test]
    fn a_refused_release_is_tried_again_and_nothing_is_left_held_on_exit() {
        let rig = rig(Some(DESKTOP_ON_AC), Duration::from_millis(5));
        rig.awake.update(wish(true, State::Sharing));
        assert!(rig.next_call());
        // Windows refuses the release once.
        rig.answers.lock().expect("lock").push(false);
        rig.awake.update(wish(true, State::Stopped));
        assert!(!rig.next_call(), "release, refused");
        assert!(!rig.next_call(), "release again, by the poll");
        let calls = rig.finish();
        assert_eq!(calls[..3], [true, false, false]);
    }
}
