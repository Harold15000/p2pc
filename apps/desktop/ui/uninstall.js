// SPDX-License-Identifier: Apache-2.0
//
// The uninstaller's cleanup page (H2 §8.7, T2-45). It calls only `uninstall_view`, `uninstall_run` and
// `uninstall_finish`, and writes text with `textContent` only, never HTML. Closing the window before "Uninstall" is a
// cancel: the uninstaller then stops and changes nothing.

import { $, invoke, commandMessage, el } from "./common.js";

function showError(code) {
  $("error").textContent = commandMessage(code);
  $("error").hidden = false;
}

function finish() {
  invoke("uninstall_finish").catch(showError);
}

async function load() {
  try {
    const view = await invoke("uninstall_view");
    if (view.hub_consequence) {
      $("hub-text").textContent = view.hub_consequence;
      $("hub").hidden = false;
    }
    if (view.kept_backups.length > 0) {
      $("backups-reason").textContent = view.kept_backup_reason;
      $("delete-backups-label").textContent = view.delete_backups_label;
      $("backups-list").replaceChildren(...view.kept_backups.map((p) => el("li", p)));
      $("backups").hidden = false;
    }
    const sync = () => {
      $("go").disabled = Boolean(view.hub_consequence) && !$("hub-ok").checked;
    };
    $("hub-ok").addEventListener("change", sync);
    sync();
    $("confirm").hidden = false;
  } catch (code) {
    showError(code);
  }
}

$("cancel").addEventListener("click", finish);
$("finish").addEventListener("click", finish);

$("go").addEventListener("click", async () => {
  $("confirm").hidden = true;
  $("working").hidden = false;
  try {
    const out = await invoke("uninstall_run", {
      confirm: {
        hub_confirmed: $("hub-ok").checked,
        delete_failed_backups: $("delete-backups").checked,
      },
    });
    $("working").hidden = true;
    if (out.outcome === "cancelled") {
      $("confirm").hidden = false;
      return;
    }
    const lines = out.outcome === "done" ? out.lines : [`P2PC was not removed: ${out.message}`];
    $("done-lines").replaceChildren(...lines.map((l) => el("li", l)));
    $("done-log").textContent = `What was done is logged in ${out.log}.`;
    $("done").hidden = false;
  } catch (code) {
    $("working").hidden = true;
    showError(code);
  }
});

load();
