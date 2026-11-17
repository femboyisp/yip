#![forbid(unsafe_code)]

//! Invitation ticket encoding, decoding, and terminal QR code rendering.
//!
//! Compatible with the cross-platform `yip-client` (desktop and mobile) ticket format.

use base64::engine::general_purpose::{STANDARD, URL_SAFE, URL_SAFE_NO_PAD};
use base64::Engine;
use qrcode::render::unicode;
use qrcode::QrCode;
use serde::{Deserialize, Serialize};

/// Version identifier for network tickets.
pub const TICKET_VERSION: u32 = 1;

/// Network invitation ticket for onboarding mesh clients.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkTicket {
    #[serde(default = "default_ticket_version")]
    pub v: u32,
    pub name: String,
    pub network_id: String,
    #[serde(default = "default_ticket_route_mode")]
    pub route_mode: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seeds: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
}

fn default_ticket_version() -> u32 {
    TICKET_VERSION
}

fn default_ticket_route_mode() -> String {
    "MeshOnly".to_string()
}

impl NetworkTicket {
    /// Create a new ticket with required parameters and current UTC timestamp.
    pub fn new(
        name: impl Into<String>,
        network_id: impl Into<String>,
        route_mode: impl Into<String>,
    ) -> Self {
        let mode = route_mode.into();
        let normalized_mode = match mode.as_str() {
            "ExitNode" | "FullExitNode" => "ExitNode".to_string(),
            "SplitTunnel" => "SplitTunnel".to_string(),
            _ => "MeshOnly".to_string(),
        };

        Self {
            v: TICKET_VERSION,
            name: name.into().trim().to_string(),
            network_id: network_id.into().trim().to_string(),
            route_mode: normalized_mode,
            endpoint: None,
            seeds: None,
            created_at: None,
        }
    }

    /// Set an optional public endpoint (e.g. `203.0.113.1:51820`).
    pub fn with_endpoint(mut self, endpoint: impl Into<String>) -> Self {
        let ep = endpoint.into().trim().to_string();
        if !ep.is_empty() {
            self.endpoint = Some(ep);
        }
        self
    }

    /// Set optional seed node addresses.
    pub fn with_seeds(mut self, seeds: Vec<String>) -> Self {
        let filtered: Vec<String> = seeds
            .into_iter()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        if !filtered.is_empty() {
            self.seeds = Some(filtered);
        }
        self
    }

    /// Serialize ticket to compact JSON string.
    pub fn to_json(&self) -> Result<String, String> {
        serde_json::to_string(self).map_err(|e| format!("Failed to serialize ticket to JSON: {e}"))
    }

    /// Serialize ticket to URL-safe base64 string.
    pub fn to_base64(&self) -> Result<String, String> {
        let json = self.to_json()?;
        Ok(URL_SAFE_NO_PAD.encode(json.as_bytes()))
    }

    /// Format ticket as a `yip://join?ticket={b64}` invitation URI.
    pub fn to_uri(&self) -> Result<String, String> {
        let b64 = self.to_base64()?;
        Ok(format!("yip://join?ticket={b64}"))
    }

    /// Parse a ticket from a `yip://` URI, base64 payload, or raw JSON.
    pub fn parse(raw: &str) -> Result<Self, String> {
        let cleaned = raw.trim();
        if cleaned.is_empty() {
            return Err("Invitation ticket is empty".to_string());
        }

        let decode_b64 = |b64: &str| -> Result<String, String> {
            let b64_clean = b64.trim();
            let bytes = URL_SAFE_NO_PAD
                .decode(b64_clean)
                .or_else(|_| URL_SAFE.decode(b64_clean))
                .or_else(|_| STANDARD.decode(b64_clean))
                .map_err(|e| format!("Invalid Base64 ticket payload: {e}"))?;
            String::from_utf8(bytes).map_err(|e| format!("Invalid UTF-8 in decoded ticket: {e}"))
        };

        let json_str = if cleaned.starts_with("yip://") {
            // Parse query string manually or via URL parser
            let query = cleaned.split_once('?').map(|(_, q)| q).unwrap_or("");
            let mut ticket_param = None;
            let mut name_param = None;
            let mut net_param = None;
            let mut mode_param = None;
            let mut endpoint_param = None;

            for pair in query.split('&') {
                if pair.is_empty() {
                    continue;
                }
                let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
                match k {
                    "ticket" => ticket_param = Some(v.to_string()),
                    "name" => name_param = Some(v.to_string()),
                    "net" | "network_id" => net_param = Some(v.to_string()),
                    "mode" | "route_mode" => mode_param = Some(v.to_string()),
                    "endpoint" => endpoint_param = Some(v.to_string()),
                    _ => {}
                }
            }

            if let Some(t) = ticket_param {
                decode_b64(&t)?
            } else if let (Some(name), Some(net)) = (name_param, net_param) {
                let mode = mode_param.unwrap_or_else(|| "MeshOnly".to_string());
                let ticket = NetworkTicket {
                    v: TICKET_VERSION,
                    name,
                    network_id: net,
                    route_mode: mode,
                    endpoint: endpoint_param,
                    seeds: None,
                    created_at: None,
                };
                return Ok(ticket);
            } else {
                return Err(
                    "Missing ticket payload or network parameters in yip:// URI".to_string()
                );
            }
        } else if cleaned.starts_with('{') {
            cleaned.to_string()
        } else {
            decode_b64(cleaned)?
        };

        let ticket: NetworkTicket = serde_json::from_str(&json_str)
            .map_err(|e| format!("Failed to parse ticket JSON payload: {e}"))?;

        if ticket.name.trim().is_empty() {
            return Err("Ticket is missing valid network name".to_string());
        }
        if ticket.network_id.trim().is_empty() {
            return Err("Ticket is missing valid network ID".to_string());
        }

        Ok(ticket)
    }

    /// Render a compact terminal Unicode QR code representing this ticket's URI.
    pub fn render_qr_terminal(&self) -> Result<String, String> {
        let uri = self.to_uri()?;
        render_qr_terminal(&uri)
    }
}

impl std::str::FromStr for NetworkTicket {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

/// Render a string into a compact Unicode terminal QR code.
pub fn render_qr_terminal(content: &str) -> Result<String, String> {
    let code =
        QrCode::new(content.as_bytes()).map_err(|e| format!("Failed to generate QR code: {e}"))?;
    let rendered = code.render::<unicode::Dense1x2>().build();
    Ok(rendered)
}

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

    #[test]
    fn test_ticket_methods_and_fallbacks() {
        // with_endpoint with empty vs valid
        let t = NetworkTicket::new("Net", "1234", "FullExitNode").with_endpoint("   ");
        assert_eq!(t.endpoint, None);
        assert_eq!(t.route_mode, "ExitNode");

        let t2 = NetworkTicket::new("Net", "1234", "other")
            .with_endpoint("10.0.0.1:443")
            .with_seeds(vec!["  ".into(), "10.0.0.2:443".into()]);
        assert_eq!(t2.route_mode, "MeshOnly");
        assert_eq!(t2.endpoint.as_deref(), Some("10.0.0.1:443"));
        assert_eq!(t2.seeds, Some(vec!["10.0.0.2:443".into()]));

        let t3 = NetworkTicket::new("Net", "1234", "SplitTunnel").with_seeds(vec![]);
        assert_eq!(t3.seeds, None);
        assert_eq!(t3.route_mode, "SplitTunnel");

        // Parse via FromStr
        let b64 = t2.to_base64().unwrap();
        let parsed: NetworkTicket = b64.parse().expect("FromStr parse");
        assert_eq!(parsed.name, "Net");

        // Fallback URI query parameters
        let uri = "yip://join?name=QueryNet&net=55667788&mode=ExitNode&endpoint=1.2.3.4:443";
        let parsed_uri = NetworkTicket::parse(uri).expect("parse query uri");
        assert_eq!(parsed_uri.name, "QueryNet");
        assert_eq!(parsed_uri.network_id, "55667788");
        assert_eq!(parsed_uri.route_mode, "ExitNode");
        assert_eq!(parsed_uri.endpoint.as_deref(), Some("1.2.3.4:443"));

        // Standalone render_qr_terminal
        let rendered = render_qr_terminal("test").expect("render_qr_terminal");
        assert!(!rendered.is_empty());

        // Standard Base64 with padding
        let json_payload = t2.to_json().unwrap();
        let standard_b64 = STANDARD.encode(json_payload.as_bytes());
        let from_standard = NetworkTicket::parse(&standard_b64).expect("parse standard base64");
        assert_eq!(from_standard.name, "Net");

        // Query URI with network_id and route_mode and without mode (defaults to MeshOnly)
        let uri2 = "yip://join?name=DefaultNet&network_id=99887766&route_mode=SplitTunnel";
        let parsed_uri2 = NetworkTicket::parse(uri2).expect("parse query uri2");
        assert_eq!(parsed_uri2.name, "DefaultNet");
        assert_eq!(parsed_uri2.network_id, "99887766");
        assert_eq!(parsed_uri2.route_mode, "SplitTunnel");

        let uri3 = "yip://join?name=DefaultNet&net=11223344";
        let parsed_uri3 = NetworkTicket::parse(uri3).expect("parse query uri3");
        assert_eq!(parsed_uri3.route_mode, "MeshOnly");

        // Invalid UTF-8 in base64 payload
        let invalid_utf8_b64 = STANDARD.encode([0xFF, 0xFE, 0xFD]);
        assert!(NetworkTicket::parse(&invalid_utf8_b64).is_err());
    }
}
