// SPDX-License-Identifier: Apache-2.0

//! What first run asks of the hub over the app's own device connection (H2 §5.2, §5.4, §8.2 steps 4 and 5).
//!
//! The hub PC's app is the owner device (`init --owner-device`, §5.3): an `admin` principal on `p2pc/device/1`. First
//! run needs five of its REST calls, behind [`HubApi`]:
//!
//! - `PATCH /v1/server {hub_name}`: the hub's name, "My cloud" (§8.2 step 4);
//! - `POST /v1/nodes/join-tokens {ttl_s: 300, pre_approved: true}`: the token of the hub PC's own node (§5.4 "The hub
//!   PC's own node": minted without asking, 300 s, `pre_approved`, so the node is `approved` at once);
//! - `POST /v1/devices/pairing-tickets {expires_in_s: 600}` with the default scopes, the phone profile (§5.2, step 5);
//! - `DELETE /v1/devices/pairing-tickets/{id}` when the QR screen closes (§5.2);
//! - `GET /v1/devices`, polled to show "Paired: <platform>" (§5.3 step 5).
//!
//! The device connection itself is `p2pc-device` (T2-30), which is not merged yet: this build has no real
//! [`HubApi`], only [`UnwiredHub`], which answers [`HubError::NotAvailable`]. T2-30 (or the task that wires it) adds
//! the implementation; the flow and its tests do not change.
//!
//! [`OwnerDevice`] gives the app's device NodeId, the public half of the DPAPI-protected device key (§8.9).

use std::fmt;

use serde::Serialize;
use zeroize::Zeroizing;

use crate::keystore::{DeviceKey, DeviceKeyStore, KeyError, load_or_create};

use super::host::JoinToken;

/// The hub's name at "Create my cloud" (§8.2 step 4).
pub const HUB_NAME: &str = "My cloud";

/// The label of the owner device (`init --owner-device … --label`).
pub const OWNER_DEVICE_LABEL: &str = "P2PC app on the hub PC";

/// The life of the hub PC's own join token (§5.4: `expires_in_s` 300).
pub const OWN_NODE_TOKEN_TTL_S: u32 = 300;

/// The life of the pairing ticket of step 5 (§8.2: "phone profile, 10 min"; §5.2's default).
pub const PAIRING_TICKET_TTL_S: u32 = 600;

/// `POST /v1/nodes/join-tokens` (H1, plus `pre_approved`, §7.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct JoinTokenRequest {
    /// Validity in seconds (`ttl_s` in `p2pc-proto`; the spec's `expires_in_s`).
    pub ttl_s: u32,
    /// The node it enrolls starts `approved` (`admin` only).
    pub pre_approved: bool,
}

impl JoinTokenRequest {
    /// The token of the hub PC's own node: 300 s, pre-approved (§5.4).
    pub const OWN_NODE: JoinTokenRequest = JoinTokenRequest {
        ttl_s: OWN_NODE_TOKEN_TTL_S,
        pre_approved: true,
    };
}

/// `POST /v1/devices/pairing-tickets`. No `scopes`: the hub's default, the phone profile (§5.2, §5.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct PairingTicketRequest {
    pub expires_in_s: u32,
}

impl PairingTicketRequest {
    /// Step 5's ticket: phone profile, 10 minutes.
    pub const PHONE: PairingTicketRequest = PairingTicketRequest {
        expires_in_s: PAIRING_TICKET_TTL_S,
    };
}

/// A pairing ticket the hub created. Its `url` carries the ticket in its fragment: secret, never logged, never shown
/// as text, wiped when dropped (§5.2, SI-H2-1).
pub struct PairingTicket {
    /// The ticket's row id, for `DELETE /v1/devices/pairing-tickets/{id}`.
    pub id: String,
    /// `https://<web app origin>/pair#p2pc_pair_…`.
    pub url: Zeroizing<String>,
    /// When it expires (RFC 3339, from the hub).
    pub expires_at: String,
}

impl fmt::Debug for PairingTicket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PairingTicket")
            .field("id", &self.id)
            .field("url", &"<redacted>")
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

/// A device as `GET /v1/devices` lists it (the fields step 5 needs).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairedDevice {
    pub id: String,
    /// The platform hint the device sent at pairing (untrusted text, at most 64 bytes).
    pub platform: String,
}

/// Why a hub call failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum HubError {
    /// This build has no device connection yet (T2-30).
    #[error("the device connection is not available in this build")]
    NotAvailable,
    /// The hub did not answer.
    #[error("the hub did not answer")]
    Unreachable,
    /// The hub answered with an error status.
    #[error("the hub refused (HTTP {0})")]
    Refused(u16),
}

/// The hub's REST API over the app's device connection.
pub trait HubApi: Send + Sync {
    /// `PATCH /v1/server {hub_name}`. Waits a bounded time for a hub that is still starting.
    fn set_hub_name(&self, name: &str) -> Result<(), HubError>;
    /// `POST /v1/nodes/join-tokens`; the token is returned once.
    fn mint_join_token(&self, request: &JoinTokenRequest) -> Result<JoinToken, HubError>;
    /// `POST /v1/devices/pairing-tickets`.
    fn create_pairing_ticket(&self, request: &PairingTicketRequest) -> Result<PairingTicket, HubError>;
    /// `DELETE /v1/devices/pairing-tickets/{id}`.
    fn revoke_pairing_ticket(&self, id: &str) -> Result<(), HubError>;
    /// `GET /v1/devices`.
    fn devices(&self) -> Result<Vec<PairedDevice>, HubError>;
}

/// The hub API of a build without the device connection: every call is [`HubError::NotAvailable`].
#[derive(Debug, Clone, Copy, Default)]
pub struct UnwiredHub;

impl HubApi for UnwiredHub {
    fn set_hub_name(&self, _: &str) -> Result<(), HubError> {
        Err(HubError::NotAvailable)
    }
    fn mint_join_token(&self, _: &JoinTokenRequest) -> Result<JoinToken, HubError> {
        Err(HubError::NotAvailable)
    }
    fn create_pairing_ticket(&self, _: &PairingTicketRequest) -> Result<PairingTicket, HubError> {
        Err(HubError::NotAvailable)
    }
    fn revoke_pairing_ticket(&self, _: &str) -> Result<(), HubError> {
        Err(HubError::NotAvailable)
    }
    fn devices(&self) -> Result<Vec<PairedDevice>, HubError> {
        Err(HubError::NotAvailable)
    }
}

/// The app's device identity.
pub trait OwnerDevice: Send + Sync {
    /// The device NodeId: 64 lowercase hex characters of the device key's Ed25519 public key.
    fn node_id(&self) -> Result<String, KeyError>;
}

/// The NodeId of a device key.
pub fn node_id_of(key: &DeviceKey) -> String {
    iroh_base::SecretKey::from_bytes(key.as_bytes()).public().to_string()
}

/// The device key in a [`DeviceKeyStore`] (on Windows, `device.key` under DPAPI), created on first use. A key that
/// cannot be read is an error, never a reason to make a new one (`keystore`).
#[derive(Debug)]
pub struct StoredDevice<S> {
    store: S,
}

impl<S> StoredDevice<S> {
    pub fn new(store: S) -> Self {
        Self { store }
    }
}

impl<S: DeviceKeyStore + Send + Sync> OwnerDevice for StoredDevice<S> {
    fn node_id(&self) -> Result<String, KeyError> {
        let key = load_or_create(&self.store, DeviceKey::generate)?;
        Ok(node_id_of(&key))
    }
}

/// The device of a build with no key store (not Windows: no DPAPI): it has no NodeId.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoDevice;

impl OwnerDevice for NoDevice {
    fn node_id(&self) -> Result<String, KeyError> {
        Err(KeyError::Io(std::io::Error::from(std::io::ErrorKind::Unsupported)))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;

    #[test]
    fn the_hub_pc_s_own_token_is_pre_approved_for_300_s() {
        let own = JoinTokenRequest::OWN_NODE;
        assert_eq!(
            own,
            JoinTokenRequest {
                ttl_s: 300,
                pre_approved: true
            }
        );
        assert_eq!(
            serde_json::to_value(own).expect("json"),
            serde_json::json!({"ttl_s": 300, "pre_approved": true})
        );
        assert_eq!(PairingTicketRequest::PHONE.expires_in_s, 600);
    }

    #[test]
    fn a_node_id_is_64_lowercase_hex_and_stable() {
        let key = DeviceKey::from_bytes([7; 32]);
        let id = node_id_of(&key);
        assert_eq!(id.len(), 64);
        assert!(
            id.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
            "{id}"
        );
        assert_eq!(id, node_id_of(&DeviceKey::from_bytes([7; 32])));
        assert_ne!(id, node_id_of(&DeviceKey::from_bytes([8; 32])));
        assert!(!id.contains(&"07".repeat(32)), "the public key, not the secret");
    }

    #[test]
    fn a_pairing_ticket_never_shows_its_url() {
        let t = PairingTicket {
            id: "pt_1".into(),
            url: Zeroizing::new("https://app.example.invalid/pair#p2pc_pair_EXAMPLEONLY".into()), // gitleaks:allow
            expires_at: "2026-11-12T10:10:00Z".into(),
        };
        let shown = format!("{t:?}");
        assert!(!shown.contains("p2pc_pair_"), "{shown}");
        assert!(shown.contains("pt_1"));
    }

    #[test]
    fn the_unwired_hub_refuses_everything() {
        let h = UnwiredHub;
        assert_eq!(h.set_hub_name(HUB_NAME), Err(HubError::NotAvailable));
        assert!(matches!(
            h.mint_join_token(&JoinTokenRequest::OWN_NODE),
            Err(HubError::NotAvailable)
        ));
        assert!(matches!(
            h.create_pairing_ticket(&PairingTicketRequest::PHONE),
            Err(HubError::NotAvailable)
        ));
        assert_eq!(h.devices(), Err(HubError::NotAvailable));
    }

    /// A store in memory.
    #[derive(Debug, Default)]
    struct MemStore(Mutex<Option<[u8; 32]>>);

    impl DeviceKeyStore for MemStore {
        fn load(&self) -> Result<Option<DeviceKey>, KeyError> {
            Ok(self.0.lock().expect("lock").map(DeviceKey::from_bytes))
        }
        fn store_new(&self, key: &DeviceKey) -> Result<(), KeyError> {
            let mut slot = self.0.lock().expect("lock");
            if slot.is_some() {
                return Err(KeyError::AlreadyExists);
            }
            *slot = Some(*key.as_bytes());
            Ok(())
        }
    }

    #[test]
    fn the_stored_device_creates_its_key_once_and_keeps_its_node_id() {
        let device = StoredDevice::new(MemStore::default());
        let first = device.node_id().expect("node id");
        assert_eq!(device.node_id().expect("node id"), first);
    }
}
