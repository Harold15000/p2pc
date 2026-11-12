// SPDX-License-Identifier: Apache-2.0

//! The app's states and controls (H2 spec §8.4).
//!
//! | State | Meaning | Tray icon | Entered by |
//! |---|---|---|---|
//! | `setup` | First run not finished | grey | install |
//! | `sharing` | Node online, taking work | green | resume, setup done |
//! | `paused` | Node online, takes no new work | yellow | "Pause"; on the hub PC also its own node being removed (§8.5) |
//! | `stopped` | Distro terminated, task disabled | grey | "Stop sharing" / "Turn off my cloud" |
//! | `updating` | §14 | blue | update |
//! | `attention` | An error needs the user (§8.8) | red | any error |
//!
//! [`Machine`] is the only way to change state: every transition goes through [`Machine::apply`], which refuses an
//! event the current state does not accept. The user's controls ([`Control`]) are a subset of the events, and
//! [`Machine::controls`] lists exactly the ones [`Machine::apply`] accepts, so the tray and the window never offer a
//! control that would be refused.

use serde::{Deserialize, Serialize};

/// The six states of §8.4.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum State {
    /// First run not finished.
    Setup,
    /// Node online, taking work.
    Sharing,
    /// Node online, takes no new work; running jobs and services continue.
    Paused,
    /// Distro terminated, task disabled; nothing runs. On the hub PC the whole cloud is offline.
    Stopped,
    /// An update is running (§14).
    Updating,
    /// An error needs the user (§8.8).
    Attention,
}

impl State {
    /// Every state, for exhaustive tests and menus.
    pub const ALL: [State; 6] = [
        State::Setup,
        State::Sharing,
        State::Paused,
        State::Stopped,
        State::Updating,
        State::Attention,
    ];

    /// The stable name used by the UI (the spec's own word).
    pub fn as_str(self) -> &'static str {
        match self {
            State::Setup => "setup",
            State::Sharing => "sharing",
            State::Paused => "paused",
            State::Stopped => "stopped",
            State::Updating => "updating",
            State::Attention => "attention",
        }
    }

    /// The tray icon's colour for this state (§8.4 "Tray icon").
    pub fn tray_color(self) -> TrayColor {
        match self {
            State::Setup | State::Stopped => TrayColor::Grey,
            State::Sharing => TrayColor::Green,
            State::Paused => TrayColor::Yellow,
            State::Updating => TrayColor::Blue,
            State::Attention => TrayColor::Red,
        }
    }

    /// A state the app returns to after an update or an error is over. `updating` and `attention` are temporary and
    /// `setup` is left only by finishing it.
    fn is_settled(self) -> bool {
        matches!(self, State::Sharing | State::Paused | State::Stopped)
    }
}

/// The tray icon colours of §8.4.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TrayColor {
    Grey,
    Green,
    Yellow,
    Blue,
    Red,
}

impl TrayColor {
    /// Every colour.
    pub const ALL: [TrayColor; 5] = [
        TrayColor::Grey,
        TrayColor::Green,
        TrayColor::Yellow,
        TrayColor::Blue,
        TrayColor::Red,
    ];

    /// The colour as 8-bit RGB.
    pub fn rgb(self) -> [u8; 3] {
        match self {
            TrayColor::Grey => [0x8a, 0x8f, 0x98],
            TrayColor::Green => [0x2e, 0xa0, 0x43],
            TrayColor::Yellow => [0xe3, 0xb3, 0x41],
            TrayColor::Blue => [0x2f, 0x81, 0xf7],
            TrayColor::Red => [0xd1, 0x24, 0x2f],
        }
    }
}

/// Whether this PC hosts the cloud's hub (§8.4 "On the hub PC", §8.6) or joined another PC's cloud. Known once first
/// run has finished (§8.2 step 4: "Create my cloud" or "Join my cloud").
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    /// This PC hosts the hub.
    Hub,
    /// This PC joined another PC's cloud.
    Joined,
}

/// The §8.8 errors whose "Then" column puts the app in `attention`. The errors of the first-run steps stay at their
/// step (they never leave `setup`), `agent_too_old` runs the updater (`updating`), `join_pending` waits and
/// `gpu_unavailable` is a warning only, so none of those is here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttentionCode {
    /// Boot status or isolation checks fail.
    DistroUnhealthy,
    /// A joined PC cannot reach the hub.
    HubUnreachable,
    /// `hub_unreachable` without a break for 14 days.
    HubGone,
    /// Agent exit 7: this PC was removed from the cloud.
    NodeRemoved,
}

impl AttentionCode {
    /// Whether the error is final: the node does not come back by itself, so clearing the error, or an update, must
    /// not return to a state where it runs. On the hub PC `NodeRemoved` is the exception to what final means for the
    /// app: the hub keeps running (§8.5), so [`Machine::apply`] settles in `paused` (or leaves a stopped cloud
    /// stopped) instead of entering `attention`.
    pub fn is_terminal(self) -> bool {
        // `hub_gone`: the app runs H1 `-Stop` and never retries on its own (§8.8). `node_removed`: agent exit 7.
        matches!(self, AttentionCode::HubGone | AttentionCode::NodeRemoved)
    }
}

/// The controls of §8.4 that the user can pick in the tray or the window.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Control {
    /// "Pause": `owner_paused = true`; running jobs and services continue.
    Pause,
    /// "Resume": `owner_paused = false`.
    Resume,
    /// "Stop sharing" on a joined PC: H1 `-Stop` (task disabled, distro terminated).
    StopSharing,
    /// "Stop sharing this PC" on the hub PC: pause, then cancel this node's running jobs; the hub stays up.
    StopSharingThisPc,
    /// "Turn off my cloud" on the hub PC: H1 `-Stop`; the phone and the other PCs lose the cloud.
    TurnOffCloud,
    /// From `stopped`: "Start sharing" (joined PC) or "Turn on my cloud" (hub PC).
    Start,
}

impl Control {
    /// Every control, for exhaustive tests.
    pub const ALL: [Control; 6] = [
        Control::Pause,
        Control::Resume,
        Control::StopSharing,
        Control::StopSharingThisPc,
        Control::TurnOffCloud,
        Control::Start,
    ];

    /// The stable identifier used by the window's `control` command and the tray menu.
    pub fn as_str(self) -> &'static str {
        match self {
            Control::Pause => "pause",
            Control::Resume => "resume",
            Control::StopSharing => "stop_sharing",
            Control::StopSharingThisPc => "stop_sharing_this_pc",
            Control::TurnOffCloud => "turn_off_cloud",
            Control::Start => "start",
        }
    }

    /// The control named `name`, or `None` for anything else. Input from the webview goes through here.
    pub fn parse(name: &str) -> Option<Control> {
        Control::ALL.into_iter().find(|c| c.as_str() == name)
    }

    /// The words of the spec for this control on a PC with `role`.
    pub fn label(self, role: Role) -> &'static str {
        match (self, role) {
            (Control::Pause, _) => "Pause",
            (Control::Resume, _) => "Resume",
            (Control::StopSharing, _) => "Stop sharing",
            (Control::StopSharingThisPc, _) => "Stop sharing this PC",
            (Control::TurnOffCloud, _) => "Turn off my cloud",
            (Control::Start, Role::Joined) => "Start sharing",
            (Control::Start, Role::Hub) => "Turn on my cloud",
        }
    }

    /// The state this control leads to once its action has succeeded.
    fn target(self) -> State {
        match self {
            Control::Pause | Control::StopSharingThisPc => State::Paused,
            Control::Resume | Control::Start => State::Sharing,
            Control::StopSharing | Control::TurnOffCloud => State::Stopped,
        }
    }
}

/// Everything that can change the state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event {
    /// First run finished (§8.2 "Ready"), with the role step 4 chose.
    SetupDone(Role),
    /// The user's control succeeded.
    Control(Control),
    /// An update started (§14).
    UpdateStarted,
    /// The update finished; the app goes back to where it was.
    UpdateFinished,
    /// An error that needs the user (§8.8).
    Fault(AttentionCode),
    /// The error is gone; the app goes back to where it was.
    FaultCleared,
    /// On the hub PC, its own node enrolled again after `node_removed` ("Join again", §8.8).
    NodeRejoined,
}

/// An event the current state does not accept. Nothing changed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("{event:?} is not allowed in state `{}`", state.as_str())]
pub struct IllegalTransition {
    /// The state the machine was (and still is) in.
    pub state: State,
    /// The refused event.
    pub event: Event,
}

/// The app's state machine (§8.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Machine {
    state: State,
    role: Option<Role>,
    /// The settled state to return to after `updating` or `attention`.
    resume_to: State,
    attention: Option<AttentionCode>,
    /// Hub PC only: this PC's own node was removed from the cloud (agent exit 7) and has not joined again. The hub keeps
    /// running (§8.5), so this is a fact about the node, not a state: it survives `FaultCleared` and "Turn off my cloud".
    node_removed: bool,
}

impl Machine {
    /// A freshly installed app: `setup` ("Entered by: install").
    pub fn new() -> Self {
        Self {
            state: State::Setup,
            role: None,
            resume_to: State::Setup,
            attention: None,
            node_removed: false,
        }
    }

    /// An app whose first run has finished, starting in `state` (`sharing`, `paused` or `stopped`, as the node
    /// reports it). Any other state is refused: the temporary states are only entered through [`Machine::apply`].
    pub fn settled(role: Role, state: State) -> Option<Self> {
        state.is_settled().then_some(Self {
            state,
            role: Some(role),
            resume_to: state,
            attention: None,
            node_removed: false,
        })
    }

    /// The current state.
    pub fn state(&self) -> State {
        self.state
    }

    /// The PC's role, once first run has finished.
    pub fn role(&self) -> Option<Role> {
        self.role
    }

    /// The error that put the app in `attention`, while it is there.
    pub fn attention(&self) -> Option<AttentionCode> {
        self.attention
    }

    /// Hub PC only: this PC's own node was removed from the cloud while the hub kept running (§8.5, §8.8
    /// `node_removed`). Always `false` on a joined PC, where the same error is final and stops the node.
    pub fn node_removed(&self) -> bool {
        self.node_removed
    }

    /// The controls the user may pick now, in menu order. Exactly the controls [`Machine::apply`] accepts.
    pub fn controls(&self) -> Vec<Control> {
        let Some(role) = self.role else {
            return Vec::new();
        };
        match (self.state, role) {
            // The hub's own node is gone: there is nothing to pause, resume or stop on this PC, only the cloud itself.
            (State::Sharing | State::Paused, Role::Hub) if self.node_removed => vec![Control::TurnOffCloud],
            (State::Sharing, Role::Joined) => vec![Control::Pause, Control::StopSharing],
            (State::Paused, Role::Joined) => vec![Control::Resume, Control::StopSharing],
            (State::Sharing, Role::Hub) => vec![Control::Pause, Control::StopSharingThisPc, Control::TurnOffCloud],
            (State::Paused, Role::Hub) => vec![Control::Resume, Control::StopSharingThisPc, Control::TurnOffCloud],
            (State::Stopped, _) => vec![Control::Start],
            // "You can stop […] at any time" (§8.2 step 1), errors included: the role's H1 `-Stop`.
            (State::Attention, Role::Joined) => vec![Control::StopSharing],
            (State::Attention, Role::Hub) => vec![Control::TurnOffCloud],
            (State::Setup | State::Updating, _) => Vec::new(),
        }
    }

    /// Whether `control` may be picked now.
    pub fn allows(&self, control: Control) -> bool {
        self.controls().contains(&control)
    }

    /// Applies `event`, or refuses it and leaves the machine unchanged.
    pub fn apply(&mut self, event: Event) -> Result<State, IllegalTransition> {
        let illegal = IllegalTransition {
            state: self.state,
            event,
        };
        match (self.state, event) {
            (State::Setup, Event::SetupDone(role)) => {
                self.role = Some(role);
                self.enter_settled(State::Sharing);
            }
            (_, Event::Control(control)) => {
                if !self.allows(control) {
                    return Err(illegal);
                }
                // Turning the cloud back on starts the hub; a node that was removed does not start taking work.
                let target = match control {
                    Control::Start if self.node_removed => State::Paused,
                    other => other.target(),
                };
                self.enter_settled(target);
            }
            (State::Sharing | State::Paused | State::Stopped | State::Attention, Event::UpdateStarted) => {
                // From `attention`, `resume_to` already holds the settled state under the error.
                self.attention = None;
                self.state = State::Updating;
            }
            (State::Updating, Event::UpdateFinished) => self.state = self.resume_to,
            (
                State::Sharing | State::Paused | State::Stopped | State::Updating | State::Attention,
                Event::Fault(code),
            ) => {
                if code == AttentionCode::NodeRemoved && self.role == Some(Role::Hub) {
                    // §8.5: the hub keeps running after its own node is removed. The agent stays removed until the PC
                    // joins again, so nothing would ever clear this error: it is recorded as a fact about the node
                    // (`node_removed`), not parked in `attention`. The PC settles in `paused` (hub up, no work taken),
                    // never `sharing`; a cloud that was off stays off. An update or another error already in progress
                    // is left to finish, and it too returns to that settled state.
                    self.node_removed = true;
                    self.resume_to = match self.resume_to {
                        State::Stopped => State::Stopped,
                        _ => State::Paused,
                    };
                    if !matches!(self.state, State::Updating | State::Attention) {
                        self.enter_settled(self.resume_to);
                    }
                    return Ok(self.state);
                } else if code.is_terminal() {
                    // A final error never leads back to a running state, whether it is cleared or an update follows.
                    self.resume_to = State::Stopped;
                }
                self.attention = Some(code);
                self.state = State::Attention;
            }
            (State::Attention, Event::FaultCleared) => {
                self.attention = None;
                self.state = self.resume_to;
            }
            (_, Event::NodeRejoined) if self.role == Some(Role::Hub) && self.node_removed => {
                self.node_removed = false;
            }
            _ => return Err(illegal),
        }
        Ok(self.state)
    }

    fn enter_settled(&mut self, state: State) {
        debug_assert!(state.is_settled());
        self.state = state;
        self.resume_to = state;
        self.attention = None;
    }
}

impl Default for Machine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ROLES: [Role; 2] = [Role::Hub, Role::Joined];
    const CODES: [AttentionCode; 4] = [
        AttentionCode::DistroUnhealthy,
        AttentionCode::HubUnreachable,
        AttentionCode::HubGone,
        AttentionCode::NodeRemoved,
    ];

    fn at(role: Role, state: State) -> Machine {
        let mut m = Machine::settled(role, State::Sharing).expect("sharing is settled");
        match state {
            State::Setup => Machine::new(),
            State::Sharing | State::Paused | State::Stopped => Machine::settled(role, state).expect("settled"),
            State::Updating => {
                m.apply(Event::UpdateStarted).expect("update from sharing");
                m
            }
            State::Attention => {
                m.apply(Event::Fault(AttentionCode::DistroUnhealthy))
                    .expect("fault from sharing");
                m
            }
        }
    }

    fn all_events() -> Vec<Event> {
        let mut events = vec![Event::UpdateStarted, Event::UpdateFinished, Event::FaultCleared];
        events.push(Event::NodeRejoined);
        events.extend(ROLES.map(Event::SetupDone));
        events.extend(Control::ALL.map(Event::Control));
        events.extend(CODES.map(Event::Fault));
        events
    }

    #[test]
    fn a_new_app_starts_in_setup_with_a_grey_icon_and_no_controls() {
        let m = Machine::new();
        assert_eq!(m.state(), State::Setup);
        assert_eq!(m.state().tray_color(), TrayColor::Grey);
        assert_eq!(m.role(), None);
        assert!(m.controls().is_empty());
    }

    #[test]
    fn tray_colours_follow_the_table() {
        let expected = [
            (State::Setup, TrayColor::Grey),
            (State::Sharing, TrayColor::Green),
            (State::Paused, TrayColor::Yellow),
            (State::Stopped, TrayColor::Grey),
            (State::Updating, TrayColor::Blue),
            (State::Attention, TrayColor::Red),
        ];
        for (state, colour) in expected {
            assert_eq!(state.tray_color(), colour, "{state:?}");
        }
    }

    #[test]
    fn setup_done_enters_sharing_and_records_the_role() {
        for role in ROLES {
            let mut m = Machine::new();
            assert_eq!(m.apply(Event::SetupDone(role)), Ok(State::Sharing));
            assert_eq!(m.role(), Some(role));
        }
    }

    #[test]
    fn setup_accepts_nothing_but_setup_done() {
        for event in all_events() {
            if matches!(event, Event::SetupDone(_)) {
                continue;
            }
            let mut m = Machine::new();
            let before = m.clone();
            assert!(m.apply(event).is_err(), "{event:?} accepted in setup");
            assert_eq!(m, before, "{event:?} changed the machine");
        }
    }

    #[test]
    fn setup_done_is_refused_once_setup_is_over() {
        for role in ROLES {
            for state in State::ALL.into_iter().filter(|s| *s != State::Setup) {
                let mut m = at(role, state);
                assert!(m.apply(Event::SetupDone(role)).is_err(), "{state:?}");
            }
        }
    }

    #[test]
    fn pause_and_resume_on_every_pc() {
        for role in ROLES {
            let mut m = at(role, State::Sharing);
            assert_eq!(m.apply(Event::Control(Control::Pause)), Ok(State::Paused));
            assert_eq!(m.apply(Event::Control(Control::Resume)), Ok(State::Sharing));
        }
    }

    #[test]
    fn a_joined_pc_offers_stop_sharing_and_no_hub_control() {
        let m = at(Role::Joined, State::Sharing);
        assert_eq!(m.controls(), vec![Control::Pause, Control::StopSharing]);
        let mut m = at(Role::Joined, State::Paused);
        assert_eq!(m.controls(), vec![Control::Resume, Control::StopSharing]);
        assert_eq!(m.apply(Event::Control(Control::StopSharing)), Ok(State::Stopped));
        for hub_only in [Control::StopSharingThisPc, Control::TurnOffCloud] {
            let mut m = at(Role::Joined, State::Sharing);
            assert!(m.apply(Event::Control(hub_only)).is_err(), "{hub_only:?}");
        }
    }

    #[test]
    fn the_hub_pc_offers_its_three_choices() {
        let m = at(Role::Hub, State::Sharing);
        assert_eq!(
            m.controls(),
            vec![Control::Pause, Control::StopSharingThisPc, Control::TurnOffCloud]
        );
        // "Stop sharing this PC" pauses and keeps the hub up: the distro still runs, so the state is `paused`.
        let mut m = at(Role::Hub, State::Sharing);
        assert_eq!(m.apply(Event::Control(Control::StopSharingThisPc)), Ok(State::Paused));
        // "Turn off my cloud" is H1 `-Stop`.
        let mut m = at(Role::Hub, State::Paused);
        assert_eq!(m.apply(Event::Control(Control::TurnOffCloud)), Ok(State::Stopped));
        // The joined PC's "Stop sharing" (H1 `-Stop` without the explanation) is not offered on the hub PC.
        let mut m = at(Role::Hub, State::Sharing);
        assert!(m.apply(Event::Control(Control::StopSharing)).is_err());
    }

    #[test]
    fn stopped_offers_only_start_with_the_role_s_words() {
        for role in ROLES {
            let mut m = at(role, State::Stopped);
            assert_eq!(m.controls(), vec![Control::Start]);
            assert_eq!(m.apply(Event::Control(Control::Start)), Ok(State::Sharing));
        }
        assert_eq!(Control::Start.label(Role::Joined), "Start sharing");
        assert_eq!(Control::Start.label(Role::Hub), "Turn on my cloud");
    }

    #[test]
    fn controls_lists_exactly_what_apply_accepts() {
        for role in ROLES {
            for state in State::ALL {
                for control in Control::ALL {
                    let mut m = at(role, state);
                    let offered = m.controls().contains(&control);
                    let accepted = m.apply(Event::Control(control)).is_ok();
                    assert_eq!(offered, accepted, "{role:?} {state:?} {control:?}");
                }
            }
        }
    }

    #[test]
    fn updating_offers_no_control() {
        for role in ROLES {
            assert!(at(role, State::Updating).controls().is_empty(), "{role:?}");
        }
    }

    #[test]
    fn attention_offers_only_the_role_s_stop_control() {
        // §8.2 step 1: "you can stop or uninstall at any time", errors included.
        let expected = [(Role::Joined, Control::StopSharing), (Role::Hub, Control::TurnOffCloud)];
        for (role, stop) in expected {
            for code in CODES {
                // The hub PC's removed node does not enter `attention` (tested on its own).
                if role == Role::Hub && code == AttentionCode::NodeRemoved {
                    continue;
                }
                for state in [State::Sharing, State::Paused, State::Stopped] {
                    let mut m = at(role, state);
                    m.apply(Event::Fault(code)).expect("fault");
                    assert_eq!(m.controls(), vec![stop], "{role:?} {code:?} {state:?}");
                }
            }
        }
    }

    #[test]
    fn stopping_from_attention_enters_stopped_and_clears_the_error() {
        for (role, stop) in [(Role::Joined, Control::StopSharing), (Role::Hub, Control::TurnOffCloud)] {
            let mut m = at(role, State::Sharing);
            m.apply(Event::Fault(AttentionCode::DistroUnhealthy)).expect("fault");
            assert_eq!(m.apply(Event::Control(stop)), Ok(State::Stopped));
            assert_eq!(m.attention(), None);
            // Where to return is now `stopped`: an update comes back there, not to `sharing`.
            m.apply(Event::UpdateStarted).expect("update");
            assert_eq!(m.apply(Event::UpdateFinished), Ok(State::Stopped));
        }
    }

    #[test]
    fn terminal_errors_return_to_stopped_by_clearing_or_by_an_update() {
        // §8.8: `hub_gone` stops the watchdog and never retries; `node_removed` is agent exit 7.
        for code in [AttentionCode::HubGone, AttentionCode::NodeRemoved] {
            assert!(code.is_terminal(), "{code:?}");
            for role in ROLES {
                // The hub PC's own node being removed does not stop the cloud (§8.5): tested on its own below.
                if role == Role::Hub && code == AttentionCode::NodeRemoved {
                    continue;
                }
                for state in [State::Sharing, State::Paused, State::Stopped, State::Updating] {
                    let mut m = at(role, state);
                    m.apply(Event::Fault(code)).expect("fault");
                    assert_eq!(
                        m.apply(Event::FaultCleared),
                        Ok(State::Stopped),
                        "clear {code:?} {state:?}"
                    );

                    let mut m = at(role, state);
                    m.apply(Event::Fault(code)).expect("fault");
                    m.apply(Event::UpdateStarted).expect("update");
                    assert_eq!(
                        m.apply(Event::UpdateFinished),
                        Ok(State::Stopped),
                        "update {code:?} {state:?}"
                    );
                }
            }
        }
    }

    #[test]
    fn on_the_hub_pc_a_removed_node_settles_in_paused_with_no_error_to_clear() {
        // §8.5: "On the hub PC, the hub keeps running after its own node is removed." The hub PC's state is therefore
        // not `stopped` (that means "the whole cloud is offline"), and its node, which takes no work, is not `sharing`
        // either. Nothing will ever clear this error (the agent stays removed), so the PC does not wait in `attention`
        // for a `FaultCleared`: it settles at once.
        for state in [State::Sharing, State::Paused] {
            let mut m = at(Role::Hub, state);
            assert!(!m.node_removed());
            assert_eq!(
                m.apply(Event::Fault(AttentionCode::NodeRemoved)),
                Ok(State::Paused),
                "{state:?}"
            );
            assert!(m.node_removed());
            assert_eq!(m.attention(), None, "no red icon, no `Problem` line");
            assert_eq!(m.state().tray_color(), TrayColor::Yellow);
            // Nothing that acts on the removed node is offered; the hub itself can still be turned off.
            assert_eq!(m.controls(), vec![Control::TurnOffCloud]);
            for refused in [Control::Pause, Control::Resume, Control::StopSharingThisPc] {
                assert!(m.apply(Event::Control(refused)).is_err(), "{refused:?}");
            }
            // And a second report of the same exit changes nothing.
            let before = m.clone();
            assert_eq!(m.apply(Event::Fault(AttentionCode::NodeRemoved)), Ok(State::Paused));
            assert_eq!(m, before);
        }
    }

    #[test]
    fn on_the_hub_pc_node_removed_during_an_update_settles_in_paused_when_it_ends() {
        let mut m = at(Role::Hub, State::Sharing);
        m.apply(Event::UpdateStarted).expect("update");
        assert_eq!(m.apply(Event::Fault(AttentionCode::NodeRemoved)), Ok(State::Updating));
        assert!(m.node_removed());
        assert_eq!(m.apply(Event::UpdateFinished), Ok(State::Paused));
        assert_eq!(m.attention(), None);
    }

    #[test]
    fn on_the_hub_pc_node_removed_does_not_hide_another_error_in_attention() {
        let mut m = at(Role::Hub, State::Sharing);
        m.apply(Event::Fault(AttentionCode::DistroUnhealthy)).expect("fault");
        assert_eq!(m.apply(Event::Fault(AttentionCode::NodeRemoved)), Ok(State::Attention));
        assert_eq!(m.attention(), Some(AttentionCode::DistroUnhealthy));
        assert!(m.node_removed());
        assert_eq!(
            m.apply(Event::FaultCleared),
            Ok(State::Paused),
            "never back to `sharing`"
        );
    }

    #[test]
    fn on_the_hub_pc_node_removed_while_the_cloud_is_off_leaves_it_off() {
        let mut m = at(Role::Hub, State::Stopped);
        assert_eq!(m.apply(Event::Fault(AttentionCode::NodeRemoved)), Ok(State::Stopped));
        assert!(m.node_removed());
        assert_eq!(m.attention(), None);
        // Turning the cloud on starts the hub, not the removed node.
        assert_eq!(m.controls(), vec![Control::Start]);
        assert_eq!(m.apply(Event::Control(Control::Start)), Ok(State::Paused));
    }

    #[test]
    fn on_the_hub_pc_turning_the_cloud_off_and_on_keeps_the_node_removed() {
        let mut m = at(Role::Hub, State::Sharing);
        m.apply(Event::Fault(AttentionCode::NodeRemoved)).expect("fault");
        assert_eq!(m.apply(Event::Control(Control::TurnOffCloud)), Ok(State::Stopped));
        assert!(m.node_removed());
        assert_eq!(m.apply(Event::Control(Control::Start)), Ok(State::Paused));
        assert!(m.node_removed());
    }

    #[test]
    fn a_node_that_joined_again_clears_the_hub_pc_s_removed_mark() {
        let mut m = at(Role::Hub, State::Sharing);
        m.apply(Event::Fault(AttentionCode::NodeRemoved)).expect("fault");
        assert_eq!(m.apply(Event::NodeRejoined), Ok(State::Paused));
        assert!(!m.node_removed());
        assert_eq!(
            m.controls(),
            vec![Control::Resume, Control::StopSharingThisPc, Control::TurnOffCloud]
        );
    }

    #[test]
    fn node_rejoined_is_refused_unless_the_hub_pc_s_node_was_removed() {
        for role in ROLES {
            for state in State::ALL {
                let mut m = at(role, state);
                let before = m.clone();
                assert!(m.apply(Event::NodeRejoined).is_err(), "{role:?} {state:?}");
                assert_eq!(m, before);
            }
        }
        // And a joined PC never has the mark: its node_removed is final and stops it (§8.8).
        let mut m = at(Role::Joined, State::Sharing);
        m.apply(Event::Fault(AttentionCode::NodeRemoved)).expect("fault");
        assert!(!m.node_removed());
        assert!(m.apply(Event::NodeRejoined).is_err());
    }

    #[test]
    fn a_later_fault_does_not_undo_a_terminal_one() {
        let mut m = at(Role::Joined, State::Sharing);
        m.apply(Event::Fault(AttentionCode::NodeRemoved)).expect("terminal");
        m.apply(Event::Fault(AttentionCode::HubUnreachable))
            .expect("later fault");
        assert_eq!(m.apply(Event::FaultCleared), Ok(State::Stopped));
    }

    #[test]
    fn an_update_returns_to_the_settled_state_it_left() {
        for role in ROLES {
            for state in [State::Sharing, State::Paused, State::Stopped] {
                let mut m = at(role, state);
                assert_eq!(m.apply(Event::UpdateStarted), Ok(State::Updating));
                assert_eq!(m.state().tray_color(), TrayColor::Blue);
                assert!(m.apply(Event::UpdateStarted).is_err(), "nested update");
                assert_eq!(m.apply(Event::UpdateFinished), Ok(state));
            }
        }
    }

    #[test]
    fn a_temporary_fault_enters_attention_and_clearing_it_returns() {
        for role in ROLES {
            for state in [State::Sharing, State::Paused, State::Stopped] {
                for code in [AttentionCode::DistroUnhealthy, AttentionCode::HubUnreachable] {
                    assert!(!code.is_terminal(), "{code:?}");
                    let mut m = at(role, state);
                    assert_eq!(m.apply(Event::Fault(code)), Ok(State::Attention));
                    assert_eq!(m.attention(), Some(code));
                    assert_eq!(m.state().tray_color(), TrayColor::Red);
                    assert_eq!(m.apply(Event::FaultCleared), Ok(state));
                    assert_eq!(m.attention(), None);
                }
            }
        }
    }

    #[test]
    fn a_second_fault_replaces_the_first_and_keeps_where_to_return() {
        let mut m = at(Role::Joined, State::Paused);
        m.apply(Event::Fault(AttentionCode::HubUnreachable)).expect("fault");
        m.apply(Event::Fault(AttentionCode::DistroUnhealthy))
            .expect("second fault");
        assert_eq!(m.attention(), Some(AttentionCode::DistroUnhealthy));
        assert_eq!(m.apply(Event::FaultCleared), Ok(State::Paused));
    }

    #[test]
    fn an_update_from_attention_clears_it_and_returns_to_the_settled_state() {
        let mut m = at(Role::Hub, State::Stopped);
        m.apply(Event::Fault(AttentionCode::DistroUnhealthy)).expect("fault");
        assert_eq!(m.apply(Event::UpdateStarted), Ok(State::Updating));
        assert_eq!(m.attention(), None);
        assert_eq!(m.apply(Event::UpdateFinished), Ok(State::Stopped));
    }

    #[test]
    fn a_fault_during_an_update_returns_to_the_state_before_the_update() {
        let mut m = at(Role::Joined, State::Sharing);
        m.apply(Event::UpdateStarted).expect("update");
        assert_eq!(
            m.apply(Event::Fault(AttentionCode::DistroUnhealthy)),
            Ok(State::Attention)
        );
        assert_eq!(m.apply(Event::FaultCleared), Ok(State::Sharing));
    }

    #[test]
    fn finish_and_clear_are_refused_outside_their_state() {
        for role in ROLES {
            for state in State::ALL {
                let mut m = at(role, state);
                assert_eq!(
                    m.apply(Event::UpdateFinished).is_ok(),
                    state == State::Updating,
                    "{state:?}"
                );
                let mut m = at(role, state);
                assert_eq!(
                    m.apply(Event::FaultCleared).is_ok(),
                    state == State::Attention,
                    "{state:?}"
                );
            }
        }
    }

    #[test]
    fn a_refused_event_changes_nothing() {
        for role in ROLES {
            for state in State::ALL {
                for event in all_events() {
                    let mut m = at(role, state);
                    let before = m.clone();
                    if m.apply(event).is_err() {
                        assert_eq!(m, before, "{role:?} {state:?} {event:?}");
                    }
                }
            }
        }
    }

    #[test]
    fn settled_refuses_the_temporary_states() {
        for role in ROLES {
            for state in State::ALL {
                let ok = matches!(state, State::Sharing | State::Paused | State::Stopped);
                assert_eq!(Machine::settled(role, state).is_some(), ok, "{state:?}");
            }
        }
    }

    #[test]
    fn control_names_round_trip_and_unknown_names_are_refused() {
        for control in Control::ALL {
            assert_eq!(Control::parse(control.as_str()), Some(control));
        }
        for bad in ["", "Pause", "pause ", "stop", "../pause", "turn_on_cloud"] {
            assert_eq!(Control::parse(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn serialized_names_match_as_str() {
        for state in State::ALL {
            assert_eq!(
                serde_json::to_value(state).expect("serialize"),
                serde_json::Value::from(state.as_str())
            );
        }
        for control in Control::ALL {
            assert_eq!(
                serde_json::to_value(control).expect("serialize"),
                serde_json::Value::from(control.as_str())
            );
        }
    }
}
