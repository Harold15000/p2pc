# apps/web

The P2PC web app (H2 spec §9): a static TypeScript app for the phone and any browser (pairing, device key storage, home,
jobs, chat, transcribe, uploads, invites). It talks to the hub through `crates/p2pc-device` compiled to WebAssembly.
The desktop app (`apps/desktop`) embeds the same UI build; its own pages go under `src/desktop/`.

**Empty for now: no code and no JavaScript toolchain.** The workspace scaffold (T2-00) only reserves the directory.

Filled by:

- T2-31: the shell, `/pair`, `/settings`, key storage, lint config and headers (§9.1-§9.3, §9.5).
- T2-32: home, jobs and chat (§9.4).
- T2-33: transcribe, uploads and invites.
- T2-43 and T2-44: the desktop pages under `src/desktop/` (setup, join).
