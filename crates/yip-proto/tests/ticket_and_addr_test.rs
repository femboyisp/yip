use std::net::Ipv6Addr;
use yip_proto::addr::{
    derive_overlay_ipv6, node_addr, verify_addr, MESH_PREFIX_LEN, OVERLAY_ADDR_CONTEXT_V2,
};
use yip_proto::ticket::{render_qr_terminal, NetworkTicket, TICKET_VERSION};

#[test]
fn test_overlay_address_derivation_and_verification() {
    assert_eq!(MESH_PREFIX_LEN, 8);
    assert_eq!(OVERLAY_ADDR_CONTEXT_V2, "yip-v2-overlay-ipv6-addr");

    let pubkey1 = [0x42u8; 32];
    let pubkey2 = [0x43u8; 32];

    let addr1: Ipv6Addr = derive_overlay_ipv6(&pubkey1);
    let addr1_alias = node_addr(&pubkey1);
    assert_eq!(addr1, addr1_alias);

    // Verify IPv6 ULA prefix: starts with 0xfd
    assert_eq!(addr1.octets()[0], 0xfd);

    // Blake3 derivation matches
    let digest = blake3::derive_key(OVERLAY_ADDR_CONTEXT_V2, &pubkey1);
    assert_eq!(&addr1.octets()[1..16], &digest[0..15]);

    // Verify self-certification
    assert!(verify_addr(addr1, &pubkey1));
    assert!(!verify_addr(addr1, &pubkey2));

    let addr2 = derive_overlay_ipv6(&pubkey2);
    assert_ne!(addr1, addr2);
    assert!(verify_addr(addr2, &pubkey2));
    assert!(!verify_addr(addr2, &pubkey1));
}

#[test]
fn test_ticket_round_trips_and_qr() {
    assert_eq!(TICKET_VERSION, 1);

    let ticket = NetworkTicket::new("Alpha Mesh", "net-12345", "ExitNode")
        .with_endpoint("192.0.2.1:51820")
        .with_seeds(vec!["192.0.2.2:51820".to_string()]);

    assert_eq!(ticket.v, 1);
    assert_eq!(ticket.name, "Alpha Mesh");
    assert_eq!(ticket.network_id, "net-12345");
    assert_eq!(ticket.route_mode, "ExitNode");
    assert_eq!(ticket.endpoint.as_deref(), Some("192.0.2.1:51820"));
    assert_eq!(
        ticket.seeds.as_deref(),
        Some(&["192.0.2.2:51820".to_string()][..])
    );

    // JSON round-trip
    let json = ticket.to_json().expect("to_json succeeds");
    let parsed_from_json = NetworkTicket::parse(&json).expect("parse json succeeds");
    assert_eq!(ticket, parsed_from_json);

    // Base64 round-trip
    let b64 = ticket.to_base64().expect("to_base64 succeeds");
    let parsed_from_b64 = NetworkTicket::parse(&b64).expect("parse b64 succeeds");
    assert_eq!(ticket, parsed_from_b64);

    // URI round-trip
    let uri = ticket.to_uri().expect("to_uri succeeds");
    assert!(uri.starts_with("yip://join?ticket="));
    let parsed_from_uri = NetworkTicket::parse(&uri).expect("parse uri succeeds");
    assert_eq!(ticket, parsed_from_uri);

    // Terminal QR code rendering
    let qr = ticket
        .render_qr_terminal()
        .expect("render_qr_terminal succeeds");
    assert!(!qr.is_empty());
    assert!(qr.contains('\n'));

    let direct_qr = render_qr_terminal("hello yip").expect("render string directly");
    assert!(!direct_qr.is_empty());
}

#[test]
fn test_ticket_fallback_uri_and_validation() {
    let uri =
        "yip://join?name=FallbackNet&net=net-67890&mode=SplitTunnel&endpoint=198.51.100.1:51820";
    let ticket = NetworkTicket::parse(uri).expect("parse query params succeeds");
    assert_eq!(ticket.name, "FallbackNet");
    assert_eq!(ticket.network_id, "net-67890");
    assert_eq!(ticket.route_mode, "SplitTunnel");
    assert_eq!(ticket.endpoint.as_deref(), Some("198.51.100.1:51820"));

    // Validation failures
    assert!(NetworkTicket::parse("").is_err());
    assert!(NetworkTicket::parse("   ").is_err());
    assert!(NetworkTicket::parse("yip://join").is_err());
    assert!(NetworkTicket::parse("invalid-base64-payload!!!").is_err());
    assert!(NetworkTicket::parse(r#"{"name":"","network_id":"abc"}"#).is_err());
    assert!(NetworkTicket::parse(r#"{"name":"abc","network_id":""}"#).is_err());
}
