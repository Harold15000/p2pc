// SPDX-License-Identifier: Apache-2.0
//
// The Updates section of the placeholder window (H2 §14, §9.6; T2-45). It calls only the app's own update commands and
// writes text with `textContent` only, never HTML. Nothing here contacts the network by itself: "Check for updates"
// and "Verify web app" ask the app, which does it in Rust.

import { $, invoke, commandMessage, el, button } from "./common.js";

const DISTRO_TEXT = {
  wait_for_hub: "Waiting for your hub PC to update",
  update_app_first: "The P2PC distro is newer than this app: update the app first.",
  upgrade_now: "The P2PC distro is being updated.",
  ask: "The P2PC distro needs an update. It stops what runs on this PC for about a minute.",
};

function showError(code) {
  $("error").textContent = commandMessage(code);
  $("error").hidden = false;
}

function render(view) {
  $("update-checks").checked = view.update_checks === true;
  $("update-last").textContent = view.last_check
    ? `Last check: ${view.last_check}`
    : "No check for updates yet.";
  $("update-notice").hidden = !view.notice;
  $("update-notice").textContent = view.notice ?? "";
  $("update-check").disabled = !view.configured;
  $("update-install").hidden = !view.ready_to_install;
  $("update-install").textContent = view.ready_to_install ? `Install P2PC ${view.ready_to_install}` : "";
  const web = view.web;
  $("web-messages").replaceChildren(...(web ? web.messages.map((m) => el("li", m, web.warning ? "warning" : "")) : []));
  const plan = view.distro?.plan;
  const text = view.distro_error ?? DISTRO_TEXT[plan];
  $("distro").hidden = !text;
  $("distro-text").textContent = text ?? "";
  const buttons = $("distro-buttons");
  buttons.replaceChildren();
  if (plan === "ask" && !view.distro_deferred) {
    for (const [choice, label] of [
      ["now", "Update now"],
      ["tonight", "Tonight at 03:00"],
      ["later", "Later"],
    ]) {
      buttons.append(button(label, () => run("distro_upgrade", { choice })));
    }
  }
}

async function run(command, args) {
  try {
    const out = await invoke(command, args);
    if (out && typeof out === "object" && "configured" in out) {
      render(out);
    } else {
      render(await invoke("update_status"));
    }
  } catch (code) {
    showError(code);
  }
}

$("update-check").addEventListener("click", () => run("update_check"));
$("update-install").addEventListener("click", () => run("update_install"));
$("web-verify").addEventListener("click", () => run("web_verify"));
$("update-checks").addEventListener("change", (event) =>
  run("set_update_checks", { enabled: event.target.checked }),
);

run("update_status");
