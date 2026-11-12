// SPDX-License-Identifier: Apache-2.0

//! The app core behind the window's commands and the tray: the state machine, the one control in flight, and what the
//! window is shown (H2 §8.4, §8.9).
//!
//! A control runs in three steps, so that the slow part (driving `wsl.exe`) never holds the lock:
//! 1. [`Core::begin`] validates the name the webview sent, checks that the current state offers it and that no other
//!    control is running, and returns a [`Ticket`];
//! 2. the caller runs [`NodeControl::run`] without the lock (on a blocking thread);
//! 3. [`Core::finish`] applies the transition only if the action succeeded, and frees the slot.
//!
//! The node actions themselves (`p2pc-agent share set --paused …` and H1 `-Stop` through `p2pc-wsl`) sit behind
//! [`NodeControl`]. This task ships no real implementation of it: [`Unwired`] refuses every action with
//! [`CommandError::NotAvailable`], so the app never shows a state the node is not in. First run (T2-43) wires it.

use serde::Serialize;

use crate::state::{AttentionCode, Control, Event, Machine, Role, State, TrayColor};
use crate::tray::{HUB_NOTICE, NODE_REMOVED_HUB_NOTICE, needs_confirmation, state_label};

/// The node actions behind the controls.
pub trait NodeControl: Send + Sync {
    /// Carries out `control` on this PC (`role` decides what "stop" means, §8.4). Blocking.
    fn run(&self, control: Control, role: Role) -> Result<(), ControlError>;
}

/// Why a node action failed. Fixed codes only: never raw command output (§8.2 "Errors").
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ControlError {
    /// This build cannot carry out the action yet.
    #[error("not available in this build")]
    NotAvailable,
    /// The action ran and failed.
    #[error("the action failed")]
    Failed,
}

/// The node actions of a build that has none yet: every action is refused.
#[derive(Debug, Clone, Copy, Default)]
pub struct Unwired;

impl NodeControl for Unwired {
    fn run(&self, _: Control, _: Role) -> Result<(), ControlError> {
        Err(ControlError::NotAvailable)
    }
}

/// The error a window command returns: a fixed code, serialized as its snake-case name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, thiserror::Error)]
#[serde(rename_all = "snake_case")]
pub enum CommandError {
    /// An argument is not one the command accepts.
    #[error("invalid argument")]
    InvalidArgument,
    /// The current state does not offer this control.
    #[error("not allowed now")]
    NotAllowed,
    /// Another control is still running.
    #[error("another action is running")]
    Busy,
    /// This build cannot do it yet.
    #[error("not available in this build")]
    NotAvailable,
    /// The action failed.
    #[error("the action failed")]
    Failed,
    /// The app's own state is broken (a poisoned lock); restarting the app clears it.
    #[error("internal error")]
    Internal,
}

impl From<ControlError> for CommandError {
    fn from(e: ControlError) -> Self {
        match e {
            ControlError::NotAvailable => CommandError::NotAvailable,
            ControlError::Failed => CommandError::Failed,
        }
    }
}

/// A control offered to the window.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ControlView {
    /// The name to send back to the `control` command.
    pub id: Control,
    /// The spec's words for it on this PC.
    pub label: &'static str,
    /// Whether the window must confirm it first (§8.4).
    pub confirm: bool,
}

/// What the `status` command returns.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct StatusView {
    /// The state of §8.4.
    pub state: State,
    /// Its words.
    pub label: &'static str,
    /// The tray icon's colour.
    pub tray: TrayColor,
    /// Hub PC or joined PC, once first run has finished.
    pub role: Option<Role>,
    /// The §8.8 error, in `attention`.
    pub attention: Option<AttentionCode>,
    /// The controls offered now.
    pub controls: Vec<ControlView>,
    /// The §8.6 sentence, on the hub PC.
    pub hub_notice: Option<&'static str>,
    /// Hub PC only: this PC's own node was removed from the cloud while the hub keeps running (§8.5, §8.8).
    pub node_removed: bool,
    /// The words for `node_removed`.
    pub node_notice: Option<&'static str>,
    /// Whether a control is running.
    pub busy: bool,
    /// A control the user picked in the tray that the window must now ask to confirm (§8.4).
    pub ask_confirm: Option<Control>,
}

/// A control that [`Core::begin`] accepted and that must be handed back to [`Core::finish`].
#[derive(Debug, PartialEq, Eq)]
#[must_use = "a ticket must be handed back to Core::finish, or no other control can run"]
pub struct Ticket {
    control: Control,
    role: Role,
}

impl Ticket {
    /// The control to run.
    pub fn control(&self) -> Control {
        self.control
    }

    /// The PC's role.
    pub fn role(&self) -> Role {
        self.role
    }
}

/// The state machine plus the one control in flight.
#[derive(Debug, Clone, Default)]
pub struct Core {
    machine: Machine,
    busy: bool,
    /// Set by the tray for a control that needs confirmation; shown once by the window ([`Core::take_status`]).
    pending_confirm: Option<Control>,
}

impl Core {
    /// A core starting from `machine`.
    pub fn new(machine: Machine) -> Self {
        Self {
            machine,
            busy: false,
            pending_confirm: None,
        }
    }

    /// Records that the user picked `control` in the tray and the window must ask to confirm it. Refused (`false`)
    /// for a control that needs no confirmation or that the state does not offer.
    pub fn ask_confirmation(&mut self, control: Control) -> bool {
        let ok = needs_confirmation(control) && self.machine.allows(control);
        if ok {
            self.pending_confirm = Some(control);
        }
        ok
    }

    /// What the window shows, handing over a pending confirmation once: the window's `status` command.
    pub fn take_status(&mut self) -> StatusView {
        let view = self.status();
        self.pending_confirm = None;
        view
    }

    /// The state machine.
    pub fn machine(&self) -> &Machine {
        &self.machine
    }

    /// What the window shows.
    pub fn status(&self) -> StatusView {
        let m = &self.machine;
        let controls = match m.role() {
            Some(role) if !self.busy => m
                .controls()
                .into_iter()
                .map(|c| ControlView {
                    id: c,
                    label: c.label(role),
                    confirm: needs_confirmation(c),
                })
                .collect(),
            _ => Vec::new(),
        };
        StatusView {
            state: m.state(),
            label: state_label(m.state()),
            tray: m.state().tray_color(),
            role: m.role(),
            attention: m.attention(),
            controls,
            hub_notice: (m.role() == Some(Role::Hub)).then_some(HUB_NOTICE),
            node_removed: m.node_removed(),
            node_notice: m.node_removed().then_some(NODE_REMOVED_HUB_NOTICE),
            busy: self.busy,
            // Only while the state still offers it (a stale request is dropped).
            ask_confirm: self.pending_confirm.filter(|c| !self.busy && m.allows(*c)),
        }
    }

    /// Step 1: accepts the control named `name` if the current state offers it and nothing else runs.
    pub fn begin(&mut self, name: &str) -> Result<Ticket, CommandError> {
        let control = Control::parse(name).ok_or(CommandError::InvalidArgument)?;
        if self.busy {
            return Err(CommandError::Busy);
        }
        let role = self.machine.role().ok_or(CommandError::NotAllowed)?;
        if !self.machine.allows(control) {
            return Err(CommandError::NotAllowed);
        }
        self.busy = true;
        // The user acted: a confirmation asked from the tray is no longer pending.
        self.pending_confirm = None;
        Ok(Ticket { control, role })
    }

    /// Step 3: frees the slot and, if the action succeeded, applies its transition.
    pub fn finish(&mut self, ticket: Ticket, outcome: Result<(), ControlError>) -> Result<StatusView, CommandError> {
        self.busy = false;
        outcome?;
        self.machine
            .apply(Event::Control(ticket.control))
            .map_err(|_| CommandError::NotAllowed)?;
        Ok(self.status())
    }

    /// Applies an event that does not come from the user (setup done, update, fault).
    pub fn apply(&mut self, event: Event) -> Result<State, crate::state::IllegalTransition> {
        self.machine.apply(event)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;

    /// Records the actions and answers with a canned outcome.
    #[derive(Debug)]
    struct FakeNode {
        outcome: Result<(), ControlError>,
        ran: Mutex<Vec<(Control, Role)>>,
    }

    impl FakeNode {
        fn answering(outcome: Result<(), ControlError>) -> Self {
            Self {
                outcome,
                ran: Mutex::new(Vec::new()),
            }
        }
    }

    impl NodeControl for FakeNode {
        fn run(&self, control: Control, role: Role) -> Result<(), ControlError> {
            self.ran.lock().expect("lock").push((control, role));
            self.outcome
        }
    }

    fn sharing(role: Role) -> Core {
        Core::new(Machine::settled(role, State::Sharing).expect("settled"))
    }

    fn run(core: &mut Core, node: &dyn NodeControl, name: &str) -> Result<StatusView, CommandError> {
        let ticket = core.begin(name)?;
        let outcome = node.run(ticket.control(), ticket.role());
        core.finish(ticket, outcome)
    }

    #[test]
    fn a_successful_control_changes_the_state() {
        let node = FakeNode::answering(Ok(()));
        let mut core = sharing(Role::Joined);
        let view = run(&mut core, &node, "pause").expect("pause");
        assert_eq!(view.state, State::Paused);
        assert_eq!(view.tray, TrayColor::Yellow);
        assert_eq!(*node.ran.lock().expect("lock"), vec![(Control::Pause, Role::Joined)]);
    }

    #[test]
    fn a_failed_control_changes_nothing_and_frees_the_slot() {
        for (outcome, error) in [
            (ControlError::Failed, CommandError::Failed),
            (ControlError::NotAvailable, CommandError::NotAvailable),
        ] {
            let node = FakeNode::answering(Err(outcome));
            let mut core = sharing(Role::Hub);
            assert_eq!(run(&mut core, &node, "pause"), Err(error));
            assert_eq!(core.machine().state(), State::Sharing);
            assert!(!core.status().busy);
        }
    }

    #[test]
    fn the_unwired_build_refuses_every_control_and_keeps_its_state() {
        for role in [Role::Hub, Role::Joined] {
            let mut core = sharing(role);
            for control in core.machine().controls() {
                assert_eq!(
                    run(&mut core, &Unwired, control.as_str()),
                    Err(CommandError::NotAvailable)
                );
                assert_eq!(core.machine().state(), State::Sharing);
            }
        }
    }

    #[test]
    fn unknown_names_are_invalid_and_run_nothing() {
        let node = FakeNode::answering(Ok(()));
        let mut core = sharing(Role::Joined);
        for name in ["", "PAUSE", "rm -rf /", "pause;resume", "control:pause"] {
            assert_eq!(
                run(&mut core, &node, name),
                Err(CommandError::InvalidArgument),
                "{name:?}"
            );
        }
        assert!(node.ran.lock().expect("lock").is_empty());
    }

    #[test]
    fn controls_the_state_does_not_offer_are_refused_and_run_nothing() {
        let node = FakeNode::answering(Ok(()));
        let mut core = sharing(Role::Joined);
        for name in ["resume", "start", "turn_off_cloud", "stop_sharing_this_pc"] {
            assert_eq!(run(&mut core, &node, name), Err(CommandError::NotAllowed), "{name:?}");
        }
        let mut setup = Core::default();
        assert_eq!(run(&mut setup, &node, "pause"), Err(CommandError::NotAllowed));
        assert!(node.ran.lock().expect("lock").is_empty());
    }

    #[test]
    fn only_one_control_runs_at_a_time() {
        let mut core = sharing(Role::Hub);
        let first = core.begin("pause").expect("first");
        assert_eq!(core.begin("turn_off_cloud"), Err(CommandError::Busy));
        assert!(core.status().busy);
        assert!(core.status().controls.is_empty(), "no control offered while one runs");
        core.finish(first, Ok(())).expect("finish");
        assert!(core.begin("resume").is_ok());
    }

    #[test]
    fn a_state_change_while_running_refuses_the_late_transition() {
        let mut core = sharing(Role::Joined);
        let ticket = core.begin("pause").expect("begin");
        core.apply(Event::Fault(AttentionCode::DistroUnhealthy)).expect("fault");
        assert_eq!(core.finish(ticket, Ok(())), Err(CommandError::NotAllowed));
        assert_eq!(core.machine().state(), State::Attention);
        assert!(!core.status().busy);
    }

    #[test]
    fn the_status_shows_controls_with_their_words_and_confirmations() {
        let view = sharing(Role::Hub).status();
        assert_eq!(view.hub_notice, Some(HUB_NOTICE));
        let shown: Vec<_> = view.controls.iter().map(|c| (c.id, c.label, c.confirm)).collect();
        assert_eq!(
            shown,
            vec![
                (Control::Pause, "Pause", false),
                (Control::StopSharingThisPc, "Stop sharing this PC", true),
                (Control::TurnOffCloud, "Turn off my cloud", true),
            ]
        );
        assert_eq!(sharing(Role::Joined).status().hub_notice, None);
    }

    #[test]
    fn the_status_of_a_new_app_is_setup() {
        let view = Core::default().status();
        let json = serde_json::to_value(&view).expect("serialize");
        assert_eq!(
            json,
            serde_json::json!({
                "state": "setup",
                "label": "Setting up",
                "tray": "grey",
                "role": null,
                "attention": null,
                "controls": [],
                "hub_notice": null,
                "node_removed": false,
                "node_notice": null,
                "busy": false,
                "ask_confirm": null,
            })
        );
    }

    #[test]
    fn the_hub_pc_shows_its_node_as_removed_and_says_the_cloud_keeps_running() {
        // §8.8 `node_removed` ("This PC was removed from your cloud") on the hub PC, where §8.5 keeps the hub running.
        let mut core = sharing(Role::Hub);
        assert!(!core.status().node_removed);
        assert_eq!(core.status().node_notice, None);
        // No `FaultCleared` is needed or sent: nothing would ever clear this error.
        assert_eq!(core.apply(Event::Fault(AttentionCode::NodeRemoved)), Ok(State::Paused));
        let view = core.status();
        // The hub keeps running: `paused`, not `stopped` (the whole cloud offline), and no error is shown.
        assert_eq!(view.state, State::Paused);
        assert_eq!(view.attention, None);
        assert!(view.node_removed);
        assert_eq!(view.node_notice, Some(NODE_REMOVED_HUB_NOTICE));
        // The hub PC keeps its §8.6 sentence, and its only control is the cloud's own.
        assert_eq!(view.hub_notice, Some(HUB_NOTICE));
        let ids: Vec<_> = view.controls.iter().map(|c| c.id).collect();
        assert_eq!(ids, vec![Control::TurnOffCloud]);
        assert!(NODE_REMOVED_HUB_NOTICE.contains("removed from your cloud"));
        assert!(NODE_REMOVED_HUB_NOTICE.contains("keeps running"));
    }

    #[test]
    fn a_joined_pc_has_no_removed_node_mark_its_node_removed_error_is_final() {
        let mut core = sharing(Role::Joined);
        core.apply(Event::Fault(AttentionCode::NodeRemoved)).expect("fault");
        let view = core.status();
        assert_eq!(view.attention, Some(AttentionCode::NodeRemoved));
        assert!(!view.node_removed);
        assert_eq!(view.node_notice, None);
        core.apply(Event::FaultCleared).expect("cleared");
        assert_eq!(core.status().state, State::Stopped);
    }

    #[test]
    fn a_tray_confirmation_is_handed_to_the_window_once() {
        let mut core = sharing(Role::Joined);
        assert!(core.ask_confirmation(Control::StopSharing));
        // A plain read (the tray) does not consume it; the window's `status` does, once.
        assert_eq!(core.status().ask_confirm, Some(Control::StopSharing));
        assert_eq!(core.take_status().ask_confirm, Some(Control::StopSharing));
        assert_eq!(core.take_status().ask_confirm, None);
    }

    #[test]
    fn only_offered_controls_that_need_confirmation_are_asked() {
        let mut core = sharing(Role::Joined);
        assert!(!core.ask_confirmation(Control::Pause), "no confirmation needed");
        assert!(!core.ask_confirmation(Control::TurnOffCloud), "hub-only control");
        assert_eq!(core.take_status().ask_confirm, None);
    }

    #[test]
    fn a_stale_confirmation_is_dropped() {
        // Asked while sharing; the state moved on before the window looked.
        let mut core = Core::new(Machine::settled(Role::Hub, State::Sharing).expect("settled"));
        assert!(core.ask_confirmation(Control::StopSharingThisPc));
        core.apply(Event::Fault(AttentionCode::HubUnreachable)).expect("fault");
        assert_eq!(core.take_status().ask_confirm, None);
        // And a control that starts clears it.
        let mut core = sharing(Role::Joined);
        assert!(core.ask_confirmation(Control::StopSharing));
        let ticket = core.begin("pause").expect("begin");
        core.finish(ticket, Ok(())).expect("finish");
        assert_eq!(core.take_status().ask_confirm, None);
    }

    #[test]
    fn command_errors_serialize_as_fixed_codes() {
        assert_eq!(
            serde_json::to_value(CommandError::InvalidArgument).expect("serialize"),
            serde_json::json!("invalid_argument")
        );
        assert_eq!(
            serde_json::to_value(CommandError::NotAvailable).expect("serialize"),
            serde_json::json!("not_available")
        );
    }
}
