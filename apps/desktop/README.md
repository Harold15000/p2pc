# apps/desktop

The P2PC desktop app (H2 spec §8): a per-user Tauri 2 app for Windows 11 with the tray, first run, the states and
controls, the install of the `p2pc-node` WSL2 distro (through `crates/p2pc-wsl`), the join flow, updates and uninstall.
The Tauri core will live in `src-tauri` (crate `p2pc-desktop`) and embed the UI build of `apps/web`.

**Empty for now: no code and no toolchain.** The workspace scaffold (T2-00) only reserves the directory.

Filled by:

- T2-42: the Tauri app shell (§8.1, §8.4, §8.9).
- T2-43: first run (`setup/`, §8.2).
- T2-44: the join flow (`invite/`, §5.4).
- T2-45: updates and uninstall (`update/`, `uninstall/`, §8.7, §14.1).
