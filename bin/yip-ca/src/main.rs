//! `yip-ca` — the offline mesh CA. Generates an Ed25519 CA keypair, issues
//! member certs, and signs bootstrap root sets. Never runs as a service and
//! is never linked into `yipd`; it is a one-shot operator tool whose output
//! (certs, signed root sets) is loaded by mesh nodes via config.
#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::io::Read as _;
use std::net::SocketAddr;
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_dalek::{Signer, SigningKey};
use rand_core::OsRng;
use yip_membership::cert::{cert_signing_body, rootset_signing_body, Cert, RootSet};

const SECS_PER_DAY: u64 = 86_400;

fn main() -> ExitCode {
    let mut args = std::env::args();
    let _prog = args.next();
    let cmd = args.next();
    let rest: Vec<String> = args.collect();

    let result = match cmd.as_deref() {
        Some("genkey") => cmd_genkey(),
        Some("sign-cert") => cmd_sign_cert(&rest),
        Some("sign-roots") => cmd_sign_roots(&rest),
        _ => Err(usage()),
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(msg) => {
            eprintln!("{msg}");
            ExitCode::from(2)
        }
    }
}

fn usage() -> String {
    "usage: yip-ca <genkey|sign-cert|sign-roots> [args]\n\
     \n\
     yip-ca genkey\n\
     yip-ca sign-cert --member <hex32> --member-sign <hex32> --network <hex16> --days <N> [--ca-private <hex>]\n\
     yip-ca sign-roots --roots <file> --version <N> [--ca-private <hex>]\n\
     \n\
     If --ca-private is omitted, the CA private key hex is read from stdin."
        .to_string()
}

// --- genkey -----------------------------------------------------------

fn cmd_genkey() -> Result<(), String> {
    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();
    println!("ca_private={}", hex_encode(&signing_key.to_bytes()));
    println!("ca_public={}", hex_encode(verifying_key.as_bytes()));
    Ok(())
}

// --- sign-cert ----------------------------------------------------------

fn cmd_sign_cert(args: &[String]) -> Result<(), String> {
    let flags = parse_flags(args)?;
    let member_pubkey = fixed32(&hex_decode(require(&flags, "member")?)?, "member")?;
    let member_sign_pubkey = fixed32(&hex_decode(require(&flags, "member-sign")?)?, "member-sign")?;
    let network_id = fixed16(&hex_decode(require(&flags, "network")?)?, "network")?;
    let days_str = require(&flags, "days")?;
    let days: u64 = days_str
        .parse()
        .map_err(|e| format!("bad --days {days_str:?}: {e}"))?;
    let ca_key = load_ca_private(flags.get("ca-private").map(String::as_str))?;

    let not_before = now_secs()?;
    let validity = days
        .checked_mul(SECS_PER_DAY)
        .ok_or_else(|| "--days too large: overflow computing validity window".to_string())?;
    let not_after = not_before
        .checked_add(validity)
        .ok_or_else(|| "--days too large: overflow computing not_after".to_string())?;

    let mut cert = Cert {
        version: 1,
        member_pubkey,
        member_sign_pubkey,
        network_id,
        not_before,
        not_after,
        tags: vec![],
        ca_sig: [0u8; 64],
    };
    let sig = ca_key.sign(&cert_signing_body(&cert));
    cert.ca_sig = sig.to_bytes();

    let mut buf = Vec::new();
    cert.encode(&mut buf);
    println!("{}", hex_encode(&buf));
    Ok(())
}

// --- sign-roots ---------------------------------------------------------

fn cmd_sign_roots(args: &[String]) -> Result<(), String> {
    let flags = parse_flags(args)?;
    let roots_path = require(&flags, "roots")?;
    let version_str = require(&flags, "version")?;
    let version: u64 = version_str
        .parse()
        .map_err(|e| format!("bad --version {version_str:?}: {e}"))?;
    let ca_key = load_ca_private(flags.get("ca-private").map(String::as_str))?;

    let contents = std::fs::read_to_string(roots_path)
        .map_err(|e| format!("failed to read roots file {roots_path:?}: {e}"))?;
    let roots = parse_roots_file(&contents)?;

    let mut rootset = RootSet {
        roots,
        version,
        ca_sig: [0u8; 64],
    };
    let sig = ca_key.sign(&rootset_signing_body(&rootset));
    rootset.ca_sig = sig.to_bytes();

    let mut buf = Vec::new();
    rootset.encode(&mut buf);
    println!("{}", hex_encode(&buf));
    Ok(())
}

fn parse_roots_file(contents: &str) -> Result<Vec<([u8; 32], SocketAddr)>, String> {
    let mut roots = Vec::new();
    for (idx, raw_line) in contents.lines().enumerate() {
        let line_no = idx + 1;
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut fields = line.split_whitespace();
        let pk_hex = fields
            .next()
            .ok_or_else(|| format!("roots file line {line_no}: missing pubkey field"))?;
        let addr_str = fields
            .next()
            .ok_or_else(|| format!("roots file line {line_no}: missing address field"))?;
        if fields.next().is_some() {
            return Err(format!("roots file line {line_no}: too many fields"));
        }
        let pk = fixed32(&hex_decode(pk_hex)?, "root pubkey")?;
        let addr: SocketAddr = addr_str
            .parse()
            .map_err(|e| format!("roots file line {line_no}: bad address {addr_str:?}: {e}"))?;
        roots.push((pk, addr));
    }
    Ok(roots)
}

// --- shared helpers -------------------------------------------------------

fn load_ca_private(arg: Option<&str>) -> Result<SigningKey, String> {
    let raw = match arg {
        Some(s) => s.to_string(),
        None => {
            let mut buf = String::new();
            std::io::stdin()
                .read_to_string(&mut buf)
                .map_err(|e| format!("failed to read CA private key from stdin: {e}"))?;
            buf.trim().to_string()
        }
    };
    let raw = raw.strip_prefix("ca_private=").unwrap_or(&raw);
    let bytes = fixed32(&hex_decode(raw)?, "ca-private")?;
    Ok(SigningKey::from_bytes(&bytes))
}

fn now_secs() -> Result<u64, String> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| format!("system clock is before the Unix epoch: {e}"))
        .map(|d| d.as_secs())
}

fn parse_flags(args: &[String]) -> Result<BTreeMap<String, String>, String> {
    let mut map = BTreeMap::new();
    let mut i = 0;
    while i < args.len() {
        let key = &args[i];
        let Some(name) = key.strip_prefix("--") else {
            return Err(format!(
                "unexpected argument {key:?} (flags must start with --)"
            ));
        };
        let value = args
            .get(i + 1)
            .ok_or_else(|| format!("missing value for --{name}"))?;
        map.insert(name.to_string(), value.clone());
        i += 2;
    }
    Ok(map)
}

fn require<'a>(flags: &'a BTreeMap<String, String>, key: &str) -> Result<&'a str, String> {
    flags
        .get(key)
        .map(String::as_str)
        .ok_or_else(|| format!("missing required --{key}"))
}

fn fixed32(bytes: &[u8], what: &str) -> Result<[u8; 32], String> {
    <[u8; 32]>::try_from(bytes).map_err(|_| {
        format!(
            "--{what} must be 32 bytes (64 hex chars), got {}",
            bytes.len()
        )
    })
}

fn fixed16(bytes: &[u8], what: &str) -> Result<[u8; 16], String> {
    <[u8; 16]>::try_from(bytes).map_err(|_| {
        format!(
            "--{what} must be 16 bytes (32 hex chars), got {}",
            bytes.len()
        )
    })
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

fn hex_decode(s: &str) -> Result<Vec<u8>, String> {
    let s = s.trim();
    if !s.len().is_multiple_of(2) {
        return Err(format!("odd-length hex string: {s:?}"));
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let mut chars = s.chars();
    while let (Some(a), Some(b)) = (chars.next(), chars.next()) {
        let mut byte_str = String::with_capacity(2);
        byte_str.push(a);
        byte_str.push(b);
        let byte = u8::from_str_radix(&byte_str, 16)
            .map_err(|e| format!("bad hex byte {byte_str:?} in {s:?}: {e}"))?;
        out.push(byte);
    }
    Ok(out)
}
