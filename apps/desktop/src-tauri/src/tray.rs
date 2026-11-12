// SPDX-License-Identifier: Apache-2.0

//! The tray: its menu, its tooltip and its icon, as plain data built from the state machine (H2 §8.1, §8.4, §8.6).
//! The Tauri glue only draws what [`menu`] and [`icon_rgba`] return and sends menu clicks to [`on_menu`].
//!
//! Controls that lose running work or take the cloud offline ("Stop sharing", "Stop sharing this PC", "Turn off my
//! cloud") are never run straight from the tray: they open the window, which asks for confirmation and explains the
//! consequence (§8.4). "Pause", "Resume" and "Start" run at once.

use crate::state::{Control, Machine, Role, State, TrayColor};

/// The sentence of §8.6 that the tray menu (and the Ready screen) shows on the hub PC.
pub const HUB_NOTICE: &str =
    "This PC is your cloud's hub. Your phone can reach your cloud only while this PC is on, awake and signed in.";

/// What the hub PC says when its own node was removed from the cloud (§8.8 `node_removed`). The hub keeps running
/// (§8.5), so the sentence says so: the phone and the other PCs are not affected.
pub const NODE_REMOVED_HUB_NOTICE: &str =
    "This PC was removed from your cloud. Your cloud keeps running; this PC no longer takes work.";

/// The side of the square tray icon, in pixels.
pub const ICON_SIZE: u32 = 32;

/// A clickable menu entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MenuAction {
    /// Show the main window.
    Open,
    /// One of the controls of §8.4.
    Control(Control),
    /// Quit the app. The node keeps running: the scheduled task keeps it, not the app (§8.1).
    Quit,
}

impl MenuAction {
    /// The menu item's id.
    pub fn id(self) -> String {
        match self {
            MenuAction::Open => "open".to_owned(),
            MenuAction::Quit => "quit".to_owned(),
            MenuAction::Control(c) => format!("control:{}", c.as_str()),
        }
    }

    /// The action of a menu item id, or `None` for an id the app did not make.
    pub fn parse(id: &str) -> Option<MenuAction> {
        match id {
            "open" => Some(MenuAction::Open),
            "quit" => Some(MenuAction::Quit),
            _ => id
                .strip_prefix("control:")
                .and_then(Control::parse)
                .map(MenuAction::Control),
        }
    }
}

/// One line of the tray menu.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MenuEntry {
    /// Text that cannot be clicked (status, hub notice).
    Text(String),
    /// A separator.
    Separator,
    /// A clickable item.
    Item {
        /// What it does.
        action: MenuAction,
        /// What it says.
        label: String,
    },
}

/// What a click on a menu item does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Effect {
    /// Show and focus the main window.
    ShowWindow,
    /// Run this control now.
    RunControl(Control),
    /// Show the window with this control's confirmation already open (see [`crate::core::Core::ask_confirmation`]).
    Confirm(Control),
    /// Quit the app.
    Quit,
    /// Nothing (unknown item, or a control the state no longer offers).
    Nothing,
}

/// Whether a control needs the window's confirmation before it runs (§8.4: running work is lost, or the cloud goes
/// offline for the phone and the other PCs).
pub fn needs_confirmation(control: Control) -> bool {
    matches!(
        control,
        Control::StopSharing | Control::StopSharingThisPc | Control::TurnOffCloud
    )
}

/// The words for a state.
pub fn state_label(state: State) -> &'static str {
    match state {
        State::Setup => "Setting up",
        State::Sharing => "Sharing",
        State::Paused => "Paused",
        State::Stopped => "Stopped",
        State::Updating => "Updating",
        State::Attention => "Needs your attention",
    }
}

/// The tray icon's tooltip.
pub fn tooltip(machine: &Machine) -> String {
    format!("P2PC: {}", state_label(machine.state()))
}

/// The tray menu for the current state.
pub fn menu(machine: &Machine) -> Vec<MenuEntry> {
    let mut entries = vec![MenuEntry::Text(tooltip(machine))];
    if machine.role() == Some(Role::Hub) {
        entries.push(MenuEntry::Text(HUB_NOTICE.to_owned()));
        if machine.node_removed() {
            entries.push(MenuEntry::Text(NODE_REMOVED_HUB_NOTICE.to_owned()));
        }
    }
    entries.push(MenuEntry::Separator);
    let controls = machine.controls();
    if let Some(role) = machine.role() {
        for control in &controls {
            let mut label = control.label(role).to_owned();
            if needs_confirmation(*control) {
                label.push('…');
            }
            entries.push(MenuEntry::Item {
                action: MenuAction::Control(*control),
                label,
            });
        }
    }
    if !controls.is_empty() {
        entries.push(MenuEntry::Separator);
    }
    entries.push(MenuEntry::Item {
        action: MenuAction::Open,
        label: "Open P2PC".to_owned(),
    });
    entries.push(MenuEntry::Item {
        action: MenuAction::Quit,
        label: "Quit".to_owned(),
    });
    entries
}

/// What a click on the menu item `id` does in the current state.
pub fn on_menu(machine: &Machine, id: &str) -> Effect {
    match MenuAction::parse(id) {
        Some(MenuAction::Open) => Effect::ShowWindow,
        Some(MenuAction::Quit) => Effect::Quit,
        Some(MenuAction::Control(c)) if !machine.allows(c) => Effect::Nothing,
        Some(MenuAction::Control(c)) if needs_confirmation(c) => Effect::Confirm(c),
        Some(MenuAction::Control(c)) => Effect::RunControl(c),
        None => Effect::Nothing,
    }
}

/// The tray icon for `color`: a filled, anti-aliased disc on a transparent square of [`ICON_SIZE`] pixels, as RGBA
/// rows from top to bottom. Drawn in code, so the six states need no image files.
pub fn icon_rgba(color: TrayColor) -> Vec<u8> {
    let [r, g, b] = color.rgb();
    let size = ICON_SIZE as f32;
    let centre = size / 2.0;
    let radius = size / 2.0 - 2.0;
    let mut rgba = Vec::with_capacity((ICON_SIZE * ICON_SIZE * 4) as usize);
    for y in 0..ICON_SIZE {
        for x in 0..ICON_SIZE {
            let dx = x as f32 + 0.5 - centre;
            let dy = y as f32 + 0.5 - centre;
            let distance = (dx * dx + dy * dy).sqrt();
            // Full inside the disc, a one-pixel ramp on its edge, transparent outside.
            let coverage = (radius + 0.5 - distance).clamp(0.0, 1.0);
            rgba.extend_from_slice(&[r, g, b, (coverage * 255.0).round() as u8]);
        }
    }
    rgba
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::{AttentionCode, Event};

    fn sharing(role: Role) -> Machine {
        Machine::settled(role, State::Sharing).expect("settled")
    }

    fn items(entries: &[MenuEntry]) -> Vec<(MenuAction, String)> {
        entries
            .iter()
            .filter_map(|e| match e {
                MenuEntry::Item { action, label } => Some((*action, label.clone())),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn menu_ids_round_trip_and_foreign_ids_are_ignored() {
        let mut actions = vec![MenuAction::Open, MenuAction::Quit];
        actions.extend(Control::ALL.map(MenuAction::Control));
        for action in actions {
            assert_eq!(MenuAction::parse(&action.id()), Some(action));
        }
        for bad in ["", "control:", "control:explode", "Open", "control:pause:x"] {
            assert_eq!(MenuAction::parse(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn during_setup_the_menu_offers_only_open_and_quit() {
        let entries = menu(&Machine::new());
        assert_eq!(entries[0], MenuEntry::Text("P2PC: Setting up".into()));
        let actions: Vec<_> = items(&entries).into_iter().map(|(a, _)| a).collect();
        assert_eq!(actions, vec![MenuAction::Open, MenuAction::Quit]);
    }

    #[test]
    fn a_joined_pc_menu_lists_its_controls_without_the_hub_notice() {
        let entries = menu(&sharing(Role::Joined));
        assert!(!entries.contains(&MenuEntry::Text(HUB_NOTICE.into())));
        assert_eq!(
            items(&entries),
            vec![
                (MenuAction::Control(Control::Pause), "Pause".into()),
                (MenuAction::Control(Control::StopSharing), "Stop sharing…".into()),
                (MenuAction::Open, "Open P2PC".into()),
                (MenuAction::Quit, "Quit".into()),
            ]
        );
    }

    #[test]
    fn the_hub_pc_menu_shows_the_hub_notice_and_its_three_choices() {
        let entries = menu(&sharing(Role::Hub));
        assert_eq!(entries[1], MenuEntry::Text(HUB_NOTICE.into()));
        let labels: Vec<_> = items(&entries).into_iter().map(|(_, l)| l).collect();
        assert_eq!(
            labels,
            vec![
                "Pause",
                "Stop sharing this PC…",
                "Turn off my cloud…",
                "Open P2PC",
                "Quit"
            ]
        );
        let stopped = Machine::settled(Role::Hub, State::Stopped).expect("settled");
        assert!(items(&menu(&stopped)).contains(&(MenuAction::Control(Control::Start), "Turn on my cloud".into())));
    }

    #[test]
    fn the_hub_pc_menu_shows_a_removed_node_and_offers_only_the_cloud_s_own_control() {
        let mut m = sharing(Role::Hub);
        // No `FaultCleared`: the removed node settles the hub PC in `paused` by itself.
        m.apply(Event::Fault(AttentionCode::NodeRemoved)).expect("fault");
        let entries = menu(&m);
        assert_eq!(entries[0], MenuEntry::Text("P2PC: Paused".into()));
        assert_eq!(entries[1], MenuEntry::Text(HUB_NOTICE.into()));
        assert_eq!(entries[2], MenuEntry::Text(NODE_REMOVED_HUB_NOTICE.into()));
        let labels: Vec<_> = items(&entries).into_iter().map(|(_, l)| l).collect();
        assert_eq!(labels, vec!["Turn off my cloud…", "Open P2PC", "Quit"]);
        // A joined PC never shows it.
        let mut joined = sharing(Role::Joined);
        joined.apply(Event::Fault(AttentionCode::NodeRemoved)).expect("fault");
        assert!(!menu(&joined).contains(&MenuEntry::Text(NODE_REMOVED_HUB_NOTICE.into())));
    }

    #[test]
    fn the_menu_offers_exactly_the_machine_s_controls() {
        for role in [Role::Hub, Role::Joined] {
            for state in [State::Sharing, State::Paused, State::Stopped] {
                let m = Machine::settled(role, state).expect("settled");
                let offered: Vec<_> = items(&menu(&m))
                    .into_iter()
                    .filter_map(|(a, _)| match a {
                        MenuAction::Control(c) => Some(c),
                        _ => None,
                    })
                    .collect();
                assert_eq!(offered, m.controls(), "{role:?} {state:?}");
            }
        }
    }

    #[test]
    fn clicks_run_safe_controls_and_ask_the_window_to_confirm_the_others() {
        let hub = sharing(Role::Hub);
        assert_eq!(on_menu(&hub, "control:pause"), Effect::RunControl(Control::Pause));
        assert_eq!(
            on_menu(&hub, "control:stop_sharing_this_pc"),
            Effect::Confirm(Control::StopSharingThisPc)
        );
        assert_eq!(
            on_menu(&hub, "control:turn_off_cloud"),
            Effect::Confirm(Control::TurnOffCloud)
        );
        let joined = sharing(Role::Joined);
        assert_eq!(
            on_menu(&joined, "control:stop_sharing"),
            Effect::Confirm(Control::StopSharing)
        );
        assert_eq!(on_menu(&joined, "open"), Effect::ShowWindow);
        assert_eq!(on_menu(&joined, "quit"), Effect::Quit);
    }

    #[test]
    fn in_attention_the_menu_still_offers_the_stop_control() {
        for (role, stop, label) in [
            (Role::Joined, Control::StopSharing, "Stop sharing…"),
            (Role::Hub, Control::TurnOffCloud, "Turn off my cloud…"),
        ] {
            let mut m = sharing(role);
            m.apply(Event::Fault(AttentionCode::DistroUnhealthy)).expect("fault");
            assert!(
                items(&menu(&m)).contains(&(MenuAction::Control(stop), label.into())),
                "{role:?}"
            );
            assert_eq!(on_menu(&m, &MenuAction::Control(stop).id()), Effect::Confirm(stop));
        }
    }

    #[test]
    fn a_stale_or_foreign_click_does_nothing() {
        // The menu was built while sharing; the click arrives after the state moved on.
        let mut m = sharing(Role::Joined);
        m.apply(Event::Fault(AttentionCode::HubUnreachable)).expect("fault");
        assert_eq!(on_menu(&m, "control:pause"), Effect::Nothing);
        assert_eq!(on_menu(&m, "control:turn_off_cloud"), Effect::Nothing);
        assert_eq!(on_menu(&m, "something-else"), Effect::Nothing);
    }

    #[test]
    fn the_icon_is_a_disc_of_the_state_colour() {
        for color in TrayColor::ALL {
            let rgba = icon_rgba(color);
            assert_eq!(rgba.len(), (ICON_SIZE * ICON_SIZE * 4) as usize);
            let pixel = |x: u32, y: u32| {
                let i = ((y * ICON_SIZE + x) * 4) as usize;
                [rgba[i], rgba[i + 1], rgba[i + 2], rgba[i + 3]]
            };
            let [r, g, b] = color.rgb();
            assert_eq!(pixel(ICON_SIZE / 2, ICON_SIZE / 2), [r, g, b, 255], "{color:?} centre");
            assert_eq!(pixel(0, 0)[3], 0, "{color:?} corner");
            assert_eq!(pixel(ICON_SIZE - 1, ICON_SIZE - 1)[3], 0, "{color:?} corner");
        }
    }

    #[test]
    fn the_colours_are_distinct() {
        let mut seen = std::collections::HashSet::new();
        for color in TrayColor::ALL {
            assert!(seen.insert(color.rgb()), "{color:?}");
        }
    }
}
