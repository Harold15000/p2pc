// SPDX-License-Identifier: Apache-2.0
//
// Shared by the placeholder pages of the desktop app (H2 T2-42, T2-43). Text is written with `textContent` only,
// never as HTML.

export const { invoke } = window.__TAURI__.core;

export const $ = (id) => document.getElementById(id);

// The fixed codes of `CommandError` (src/core.rs).
export const MESSAGES = {
  invalid_argument: "That is not a valid choice.",
  not_allowed: "That is not possible right now.",
  busy: "Another action is still running.",
  not_available: "This is not available in this version of the app yet.",
  failed: "That did not work. Try again.",
  internal: "Something went wrong. Restart P2PC.",
};

export function commandMessage(code) {
  return MESSAGES[code] ?? MESSAGES.failed;
}

// A new element with text (never HTML).
export function el(tag, text, className) {
  const node = document.createElement(tag);
  if (text !== undefined && text !== null) {
    node.textContent = String(text);
  }
  if (className) {
    node.className = className;
  }
  return node;
}

export function button(label, onClick, disabled = false) {
  const b = el("button", label);
  b.type = "button";
  b.disabled = disabled;
  b.addEventListener("click", onClick);
  return b;
}
