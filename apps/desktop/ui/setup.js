// SPDX-License-Identifier: Apache-2.0
//
// First run (H2 §8.2, T2-43) in the desktop app's placeholder window. The web app's `apps/web/src/desktop/` pages
// replace this file later: they call the same `setup_*` commands and read the same JSON (`SetupView`,
// src/setup/flow.rs), so nothing in Rust changes. Every decision is made in Rust; this page only shows the view and
// sends the user's choices. Text is written with `textContent` only.

import { $, invoke, commandMessage, el, button } from "./common.js";

// §8.2 step 1: what P2PC does and does not do, in five lines.
const WELCOME_LINES = [
  "P2PC runs only what you start.",
  "Nothing of it is visible on your network.",
  "You can stop sharing or uninstall P2PC at any time.",
  "There is no account.",
  "There is no telemetry.",
];

const STEP_TITLES = {
  welcome: "Welcome",
  checks: "Checking this PC",
  share: "What this PC shares",
  create_or_join: "Create or join",
  add_phone: "Add my phone",
  ready: "Your cloud is ready",
};

const GIB = 1024;

let view = null;
// The action running from this page, with its words ("Checking…"), or null.
let action = null;
// A command error (busy, not allowed…), shown once.
let commandError = null;
let downloadAsked = false;
let phoneTimer = null;
// Step 1's radio choice, before "Start".
let welcomeChoice = null;

export function setupView() {
  return view;
}

// Asks for the view again; draws only when it changed, so that a periodic refresh never resets a form being filled.
export async function refreshSetup() {
  try {
    const next = await invoke("setup_status");
    if (JSON.stringify(next) === JSON.stringify(view)) {
      autoActions();
      return;
    }
    view = next;
  } catch (code) {
    commandError = commandMessage(code);
  }
  render();
  autoActions();
}

async function act(command, args, words) {
  action = words;
  commandError = null;
  render();
  try {
    view = await invoke(command, args);
  } catch (code) {
    commandError = commandMessage(code);
    try {
      view = await invoke("setup_status");
    } catch {
      // The status itself failed: the error above is shown.
    }
  }
  action = null;
  render();
  autoActions();
}

// What runs without a click: the checks when step 2 opens, the background download (steps 2-3), and the import when
// step 3 opens. After a failure, nothing runs again until the user asks ("Try again").
function autoActions() {
  if (!view || action || view.busy || view.error) {
    return;
  }
  if ((view.step === "checks" || (view.step === "share" && !view.share)) && !downloadAsked) {
    downloadAsked = true;
    invoke("setup_download")
      .then((v) => {
        view = v;
        render();
      })
      .catch(() => {});
  }
  if (view.step === "checks" && !view.checks && !view.reboot_pending) {
    act("setup_checks", {}, "Checking this PC…");
  } else if (view.step === "share" && (!view.share || view.share.disk_max_gib === null)) {
    act("setup_prepare_node", {}, "Preparing P2PC on this PC. This takes about a minute…");
  }
  if (view.step === "add_phone" && view.phone?.qr && !view.phone.paired) {
    if (!phoneTimer) {
      phoneTimer = setInterval(async () => {
        try {
          view = await invoke("setup_phone_status");
          render();
        } catch {
          // Busy: the next tick asks again.
        }
      }, 3000);
    }
  } else if (phoneTimer) {
    clearInterval(phoneTimer);
    phoneTimer = null;
  }
}

function render() {
  const root = $("setup");
  root.replaceChildren();
  if (!view) {
    return;
  }
  root.append(el("h2", STEP_TITLES[view.step] ?? "Setting up"));
  const body = {
    welcome: renderWelcome,
    checks: renderChecks,
    share: renderShare,
    create_or_join: renderCreate,
    add_phone: renderPhone,
    ready: renderReady,
  }[view.step];
  if (body) {
    body(root);
  }
  if (view.warnings?.length) {
    for (const w of view.warnings) {
      root.append(el("p", w, "warning"));
    }
  }
  if (action) {
    root.append(el("p", action, "progress"));
  }
  if (view.error) {
    root.append(renderError(view.error));
  }
  if (commandError) {
    root.append(el("p", commandError, "error"));
  }
}

function renderError(error) {
  const box = el("div", null, "error-box");
  box.setAttribute("role", "alert");
  box.append(el("p", error.message, "error"));
  if (error.detail) {
    box.append(el("p", error.detail, "detail"));
  }
  if (error.guide_url) {
    // Opened in the system browser by the app's navigation guard (src/navigation.rs).
    const link = el("a", "How to turn on virtualization");
    link.href = error.guide_url;
    link.target = "_blank";
    link.rel = "noopener noreferrer";
    box.append(el("p", "Restart your PC, open its firmware settings (often with F2 or Del at start-up) and turn on Intel VT-x or AMD-V (SVM). Then open P2PC again."));
    box.append(link);
  }
  if (error.try_again) {
    box.append(button("Try again", retry, Boolean(action)));
  }
  return box;
}

function retry() {
  switch (view.step) {
    case "checks":
      act("setup_checks", {}, "Checking this PC…");
      break;
    case "share":
      if (!view.share || view.share.disk_max_gib === null) {
        act("setup_prepare_node", {}, "Preparing P2PC on this PC…");
      } else {
        commandError = null;
        view.error = null;
        render();
      }
      break;
    case "create_or_join":
      act("setup_create_cloud", {}, "Creating your cloud…");
      break;
    case "add_phone":
      act("setup_pair_phone", {}, "Making a pairing code…");
      break;
    default:
      refreshSetup();
  }
}

// --- Step 1 ---

function renderWelcome(root) {
  const list = el("ul");
  for (const line of WELCOME_LINES) {
    list.append(el("li", line));
  }
  root.append(list);
  const set = el("fieldset");
  set.append(el("legend", "Check for updates and verify the web app automatically:"));
  const start = button("Start", () => act("setup_welcome", { update_checks: welcomeChoice }, "Saving…"), true);
  for (const [value, label] of [
    [true, "Yes"],
    [false, "No"],
  ]) {
    const id = `updates-${label.toLowerCase()}`;
    const input = el("input");
    input.type = "radio";
    input.name = "updates";
    input.id = id;
    // Nothing is preselected (§8.2 step 1): "Start" stays disabled until one is picked.
    input.checked = welcomeChoice === value;
    input.addEventListener("change", () => {
      welcomeChoice = value;
      start.disabled = false;
    });
    const labelEl = el("label", ` ${label}`);
    labelEl.prepend(input);
    set.append(labelEl);
  }
  start.disabled = welcomeChoice === null || Boolean(action);
  root.append(set);
  root.append(el("p", "You can change this later in Settings.", "note"));
  root.append(start);
}

// --- Step 2 and 2a ---

function renderDownload(root) {
  const d = view.download;
  if (d.state === "running") {
    const total = d.total ? ` of ${Math.round(d.total / 1048576)} MB` : "";
    root.append(el("p", `Downloading P2PC: ${Math.round(d.done / 1048576)} MB${total}`, "note"));
  } else if (d.state === "done") {
    root.append(el("p", "P2PC is downloaded and verified.", "note"));
  } else if (d.state === "failed" && d.error) {
    root.append(el("p", `Download: ${d.error.message}`, "note"));
  }
}

function renderChecks(root) {
  if (view.reboot_pending && !view.checks) {
    root.append(el("p", "Restart your PC to finish installing WSL. P2PC opens again after the restart."));
    root.append(button("I restarted: check again", () => act("setup_checks", {}, "Checking this PC…"), Boolean(action)));
  }
  const c = view.checks;
  if (c) {
    if (c.passed) {
      root.append(el("p", "This PC is ready for P2PC."));
    }
    for (const f of c.failures) {
      root.append(el("p", f.message, "check-failed"));
    }
    for (const w of c.warnings) {
      root.append(el("p", w, "warning"));
    }
    if (c.install_wsl && !view.reboot_pending) {
      root.append(
        el(
          "p",
          "P2PC runs its work inside WSL, Windows' own Linux environment, which this PC does not have yet (or has in a version that is too old). Windows asks once for administrator permission to install it; it may then ask you to restart.",
        ),
      );
      root.append(button("Install WSL", () => act("setup_install_wsl", {}, "Installing WSL…"), Boolean(action)));
    }
    if (view.reboot_pending && view.checks) {
      root.append(el("p", "Restart your PC to finish installing WSL. P2PC opens again after the restart."));
    }
    if (!c.passed && !view.error && !c.install_wsl) {
      root.append(button("Check again", () => act("setup_checks", {}, "Checking this PC…"), Boolean(action)));
    }
  }
  renderDownload(root);
}

// --- Step 3 ---

function numberField(label, min, max, value, step = 1) {
  const wrap = el("label", `${label} `);
  const input = el("input");
  input.type = "number";
  input.min = String(min);
  input.max = String(max);
  input.step = String(step);
  input.value = String(value);
  wrap.append(input);
  return { wrap, input };
}

function renderShare(root) {
  renderDownload(root);
  const s = view.share;
  if (!s || s.disk_max_gib === null) {
    return;
  }
  const form = el("div", null, "share");
  const cpu = numberField("CPU cores", 1, s.cpu_max, s.chosen?.cpu ?? s.cpu_default);
  const memMax = Math.floor(s.memory_mb_max / GIB);
  const memory = numberField(
    "RAM (GiB)",
    1,
    memMax,
    Math.min(memMax, Math.floor((s.chosen?.memory_mb ?? s.memory_mb_default) / GIB)),
  );
  form.append(cpu.wrap, el("br"), memory.wrap, el("br"));
  let gpu = null;
  if (s.gpu_offerable) {
    gpu = el("input");
    gpu.type = "checkbox";
    gpu.checked = s.chosen?.gpu ?? s.gpu_default;
    const label = el("label", " Share the GPU");
    label.prepend(gpu);
    form.append(label, el("br"));
  }
  const disk = el("input");
  disk.type = "range";
  disk.min = String(s.disk_min_gib);
  disk.max = String(s.disk_max_gib);
  disk.step = "1";
  disk.value = String(s.chosen?.share_gib ?? s.disk_default_gib);
  const diskLabel = el("label", "Disk space for P2PC: ");
  const diskValue = el("strong");
  const templatesNote = el("p", "", "warning");
  const showDisk = () => {
    const d = Number(disk.value);
    diskValue.textContent = `${d} GiB`;
    templatesNote.textContent =
      d < s.templates_gib ? "The AI chat and transcription may not run on this PC (they need 50 GiB)." : "";
    templatesNote.hidden = d >= s.templates_gib;
  };
  disk.addEventListener("input", showDisk);
  diskLabel.append(diskValue);
  form.append(diskLabel, el("br"), disk, el("p", `Marked: ${s.templates_gib} GiB for the AI chat and transcription.`, "note"), templatesNote);
  showDisk();
  const awake = el("input");
  awake.type = "checkbox";
  const awakeLabel = el("label", " Keep this PC awake while sharing");
  awakeLabel.prepend(awake);
  form.append(awakeLabel, el("br"));
  form.append(
    button(
      "Continue",
      () =>
        act(
          "setup_share",
          {
            request: {
              cpu: Number(cpu.input.value),
              memory_mb: Number(memory.input.value) * GIB,
              gpu: gpu ? gpu.checked : false,
              share_gib: Number(disk.value),
            },
            keep_awake: awake.checked,
          },
          "Applying the share…",
        ),
      Boolean(action),
    ),
  );
  root.append(form);
}

// --- Step 4 ---

function renderCreate(root) {
  root.append(el("p", "Create your cloud on the PC that is on most often."));
  root.append(button("Create my cloud", () => act("setup_create_cloud", {}, "Creating your cloud…"), Boolean(action)));
  const join = button("Join my cloud", () => {
    commandError = "Joining a cloud from another PC comes in a later version of the app.";
    render();
  });
  root.append(join);
}

// --- Step 5 ---

function drawQr(qr) {
  const quiet = 4;
  const scale = 6;
  const canvas = el("canvas");
  const size = (qr.size + 2 * quiet) * scale;
  canvas.width = size;
  canvas.height = size;
  canvas.setAttribute("role", "img");
  canvas.setAttribute("aria-label", "QR code to pair your phone");
  const g = canvas.getContext("2d");
  g.fillStyle = "#ffffff";
  g.fillRect(0, 0, size, size);
  g.fillStyle = "#000000";
  qr.rows.forEach((row, y) => {
    for (let x = 0; x < row.length; x += 1) {
      if (row[x] === "1") {
        g.fillRect((x + quiet) * scale, (y + quiet) * scale, scale, scale);
      }
    }
  });
  return canvas;
}

function renderPhone(root) {
  const p = view.phone ?? {};
  if (p.qr) {
    root.append(el("p", "Scan this code with your phone's camera."));
    root.append(drawQr(p.qr));
    if (p.web_app_url) {
      root.append(el("p", `Or open ${p.web_app_url} on your phone.`, "note"));
    }
    if (p.paired) {
      root.append(el("p", `Paired: ${p.paired}`, "paired"));
      root.append(button("Continue", () => act("setup_finish_phone", {}, "Finishing…"), Boolean(action)));
    } else {
      root.append(el("p", "Waiting for your phone… The code is valid for 10 minutes.", "note"));
      root.append(button("New code", () => act("setup_pair_phone", {}, "Making a pairing code…"), Boolean(action)));
    }
  } else {
    root.append(el("p", "Use your cloud from your phone: pair it with this PC."));
    root.append(button("Show the pairing code", () => act("setup_pair_phone", {}, "Making a pairing code…"), Boolean(action)));
  }
  if (!p.paired) {
    root.append(button("Skip for now", () => act("setup_finish_phone", {}, "Finishing…"), Boolean(action)));
  }
}

// --- Ready ---

function renderReady(root) {
  if (view.hub_notice) {
    root.append(el("p", view.hub_notice));
  }
  root.append(el("p", "Your PCs and your phones show in this window."));
}
