// SPDX-License-Identifier: Apache-2.0
//
// Placeholder UI of the desktop app (H2 T2-42, T2-43) until the web app build (T2-31) replaces it. It calls only the
// app's own commands (H2 §8.9) and writes text with `textContent` only, never HTML. While the app is in the state
// `setup` it shows first run (setup.js); afterwards, the status and the controls of §8.4.

import { $, invoke, commandMessage } from "./common.js";
import { refreshSetup, setupView } from "./setup.js";

// What the window says before a control that loses work or takes the cloud offline (H2 §8.4).
const CONFIRMATIONS = {
  stop_sharing: "Stop sharing this PC? Work running here stops and is retried on another PC.",
  stop_sharing_this_pc: "Stop sharing this PC? Its running jobs are cancelled. Your cloud stays on.",
  turn_off_cloud:
    "Turn off your cloud? Your phone and your other PCs lose your cloud until you turn it on again.",
};

function showError(code) {
  $("error").textContent = commandMessage(code);
  $("error").hidden = false;
}

function clearError() {
  $("error").hidden = true;
  $("error").textContent = "";
}

function render(status) {
  const inSetup = status.state === "setup";
  $("setup").hidden = !inSetup;
  $("status-section").hidden = inSetup;
  if (inSetup) {
    refreshSetup();
    return;
  }
  // First run has just finished in this window: say so once (§8.2 "Ready").
  $("ready").hidden = setupView()?.step !== "ready";

  $("dot").className = `dot ${status.tray}`;
  $("state").textContent = status.label;

  $("hub-notice").hidden = !status.hub_notice;
  $("hub-notice").textContent = status.hub_notice ?? "";

  // Hub PC: its own node was removed from the cloud while the hub keeps running (H2 §8.5, §8.8).
  $("node-notice").hidden = !status.node_notice;
  $("node-notice").textContent = status.node_notice ?? "";

  $("attention").hidden = !status.attention;
  $("attention").textContent = status.attention ? `Problem: ${status.attention}` : "";

  const controls = $("controls");
  controls.replaceChildren();
  for (const c of status.controls) {
    const button = document.createElement("button");
    button.type = "button";
    button.textContent = c.confirm ? `${c.label}…` : c.label;
    button.addEventListener("click", () => (c.confirm ? askConfirmation(c) : runControl(c.id)));
    controls.append(button);
  }

  // A control picked in the tray that needs confirmation: open its confirmation straight away.
  const asked = status.controls.find((c) => c.id === status.ask_confirm);
  if (asked) {
    askConfirmation(asked);
  }
}

function askConfirmation(c) {
  $("confirm-text").textContent = CONFIRMATIONS[c.id] ?? `${c.label}?`;
  $("confirm-yes").textContent = c.label;
  $("confirm-yes").onclick = () => {
    $("confirm").hidden = true;
    runControl(c.id);
  };
  $("confirm").hidden = false;
}

async function refresh() {
  try {
    render(await invoke("status"));
  } catch (code) {
    showError(code);
  }
}

async function runControl(name) {
  clearError();
  try {
    render(await invoke("control", { name }));
  } catch (code) {
    showError(code);
    await refresh();
  }
}

async function loadSettings() {
  try {
    const settings = await invoke("settings");
    $("autostart").checked = settings.autostart;
  } catch (code) {
    showError(code);
  }
}

$("confirm-no").addEventListener("click", () => {
  $("confirm").hidden = true;
});

$("autostart").addEventListener("change", async (event) => {
  const enabled = event.target.checked;
  clearError();
  try {
    const settings = await invoke("set_autostart", { enabled });
    $("autostart").checked = settings.autostart;
  } catch (code) {
    $("autostart").checked = !enabled;
    showError(code);
  }
});

window.addEventListener("focus", refresh);
setInterval(refresh, 5000);
refresh();
loadSettings();
