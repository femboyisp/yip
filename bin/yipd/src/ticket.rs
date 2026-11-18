#![forbid(unsafe_code)]

//! Invitation ticket encoding, decoding, and terminal QR code rendering.
//!
//! Re-exports cross-platform invitation ticket primitives from `yip-proto`.

pub use yip_proto::ticket::*;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ticket_round_trip_json() {
        let ticket = NetworkTicket::new("Office Mesh", "aabbccddeeff0011", "MeshOnly")
            .with_endpoint("198.51.100.10:51820")
            .with_seeds(vec!["198.51.100.1:51820".into()]);

        let json = ticket.to_json().expect("to_json");
        let parsed = NetworkTicket::parse(&json).expect("parse json");
        assert_eq!(ticket.name, parsed.name);
        assert_eq!(ticket.network_id, parsed.network_id);
        assert_eq!(ticket.endpoint, parsed.endpoint);
        assert_eq!(ticket.seeds, parsed.seeds);
        assert_eq!(parsed.route_mode, "MeshOnly");
    }

    #[test]
    fn test_ticket_round_trip_uri() {
        let ticket = NetworkTicket::new("Homelab", "1234567890abcdef", "ExitNode")
            .with_endpoint("203.0.113.5:51820");

        let uri = ticket.to_uri().expect("to_uri");
        assert!(uri.starts_with("yip://join?ticket="));

        let parsed = NetworkTicket::parse(&uri).expect("parse URI");
        assert_eq!(ticket.name, parsed.name);
        assert_eq!(ticket.network_id, parsed.network_id);
        assert_eq!(ticket.endpoint, parsed.endpoint);
        assert_eq!(parsed.route_mode, "ExitNode");
    }

    #[test]
    fn test_ticket_direct_base64() {
        let ticket = NetworkTicket::new("Field Mesh", "deadbeefcafe0001", "SplitTunnel");
        let b64 = ticket.to_base64().expect("to_base64");
        let parsed = NetworkTicket::parse(&b64).expect("parse base64");
        assert_eq!(parsed.name, "Field Mesh");
        assert_eq!(parsed.network_id, "deadbeefcafe0001");
        assert_eq!(parsed.route_mode, "SplitTunnel");
    }

    #[test]
    fn test_ticket_validation_failures() {
        assert!(NetworkTicket::parse("").is_err());
        assert!(NetworkTicket::parse("   ").is_err());
        assert!(NetworkTicket::parse("not-base64-or-json@@@").is_err());
        assert!(NetworkTicket::parse("yip://join").is_err());
        assert!(NetworkTicket::parse(r#"{"name":"","network_id":"123"}"#).is_err());
        assert!(NetworkTicket::parse(r#"{"name":"test","network_id":""}"#).is_err());
    }

    #[test]
    fn test_ticket_terminal_qr_rendering() {
        let ticket = NetworkTicket::new("Test Mesh", "0102030405060708", "MeshOnly");
        let qr = ticket.render_qr_terminal().expect("render_qr_terminal");
        assert!(!qr.is_empty());
        assert!(qr.contains('█') || qr.contains('▀') || qr.contains('▄') || qr.contains(' '));
    }
}
