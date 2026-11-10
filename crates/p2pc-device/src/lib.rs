// SPDX-License-Identifier: Apache-2.0

//! The client side of P2PC pairing and of the device protocol (H2 spec §4.1, §5 and §6.3).
//!
//! One code base, compiled natively (desktop app) and to WebAssembly (web app): pairing and invite clients
//! (`p2pc/pair/1`, `p2pc/invite/1`), the device connection (`p2pc/device/1`), HTTP/1.1 over its streams and
//! `open_port` (§7.4). No tokio networking and no filesystem.
//!
//! This crate is an empty scaffold (T2-00). T2-30 fills it.

#[cfg(test)]
mod tests {
    #[test]
    fn scaffold_builds() {
        assert_eq!(env!("CARGO_PKG_NAME"), "p2pc-device");
    }
}
