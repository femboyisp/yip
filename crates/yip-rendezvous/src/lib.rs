//! Rendezvous + relay control protocol shared by `yipd` (client) and the
//! `yip-rendezvous` server: node-id derivation, the wire `Message` codec, and
//! the pure server state machine.
#![forbid(unsafe_code)]

pub mod proto;
pub mod server;

pub use proto::{
    compute_register_auth_mac, compute_register_mac, decode, derive_node_id, derive_reg_auth_key,
    encode, node_id, register_auth_payload, verify_register_auth_mac, verify_register_mac, Message,
    NodeId, RENDEZVOUS_NODE_ID_CONTEXT_V2, RENDEZVOUS_REG_AUTH_KEY_CONTEXT_V2,
};
pub use server::RendezvousServer;
