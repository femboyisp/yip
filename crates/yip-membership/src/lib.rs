//! yip mesh membership: CA-signed certificates, member-signed directory
//! records, the signed root set, and the gossip wire codec. Pure (no I/O);
//! shared by `yipd`, its membership module, and the `yip-ca` tool.
#![forbid(unsafe_code)]

pub mod cert;
pub mod gossip;
pub mod ids;
pub mod record;

pub use cert::{verify_cert, Cert, CertError, RootSet};
pub use gossip::GossipMsg;
pub use ids::{node_addr, node_id, NodeId};
pub use record::Record;
