//! Rendezvous + relay control protocol shared by `yipd` (client) and the
//! `yip-rendezvous` server: node-id derivation, the wire `Message` codec, and
//! the pure server state machine.
#![forbid(unsafe_code)]

pub mod proto;

pub use proto::{decode, encode, node_id, Message, NodeId};
