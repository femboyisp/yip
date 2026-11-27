//! `yip-exit`: L3 IPv4/IPv6 exit NAT gateway for yip mobile Full Tunnel clients.
#![forbid(unsafe_code)]

mod nat;
mod wire;

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::process::Command;
use std::time::{Duration, Instant};

use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use yip_device::{DeviceKind, TunTap};

use nat::{rewrite_inbound_dst, rewrite_outbound_src, ClientOrigAddr};
use wire::{
    derive_mesh_secret, encode_control_packet, encode_data_packet, verify_auth_tag, xor_keystream,
    PacketHeader, ReplayWindow, AUTH_TAG_LEN, CONTROL_FLAG_ACK, CONTROL_FLAG_REGISTER, HEADER_LEN,
    MIN_PACKET_LEN, PACKET_TYPE_CONTROL, PACKET_TYPE_DATA, PACKET_TYPE_DECOY,
};

const SESSION_TTL: Duration = Duration::from_secs(300);
const SWEEP_INTERVAL: Duration = Duration::from_secs(30);

struct ClientSession {
    sender_id: [u8; 8],
    src_addr: SocketAddr,
    traffic_secret: [u8; 32],
    assigned_v4: Ipv4Addr,
    assigned_v6: Ipv6Addr,
    orig_v4: Ipv4Addr,
    orig_v6: Ipv6Addr,
    replay: ReplayWindow,
    send_counter: u64,
    last_seen: Instant,
}

struct ExitState {
    sessions: HashMap<[u8; 8], ClientSession>,
    v4_to_sender: HashMap<Ipv4Addr, [u8; 8]>,
    v6_to_sender: HashMap<Ipv6Addr, [u8; 8]>,
    next_host_idx: u16,
}

impl ExitState {
    fn new() -> Self {
        Self {
            sessions: HashMap::new(),
            v4_to_sender: HashMap::new(),
            v6_to_sender: HashMap::new(),
            next_host_idx: 2,
        }
    }

    fn allocate_addrs(&mut self) -> (Ipv4Addr, Ipv6Addr) {
        for _ in 0..65000 {
            let idx = self.next_host_idx;
            self.next_host_idx = if idx >= 65530 { 2 } else { idx + 1 };
            let hi = u8::try_from(idx >> 8).unwrap_or(0);
            let lo = u8::try_from(idx & 0xFF).unwrap_or(2);
            if lo == 0 || lo == 255 {
                continue;
            }
            let v4 = Ipv4Addr::new(10, 77, hi, lo);
            let v6 = Ipv6Addr::new(0xfd77, 0, 0, 0, 0, 0, 0, idx);
            if !self.v4_to_sender.contains_key(&v4) && !self.v6_to_sender.contains_key(&v6) {
                return (v4, v6);
            }
        }
        (
            Ipv4Addr::new(10, 77, 0, 2),
            Ipv6Addr::new(0xfd77, 0, 0, 0, 0, 0, 0, 2),
        )
    }

    fn upsert_session(
        &mut self,
        sender_id: [u8; 8],
        src_addr: SocketAddr,
        traffic_secret: [u8; 32],
    ) {
        let now = Instant::now();
        if let Some(sess) = self.sessions.get_mut(&sender_id) {
            sess.src_addr = src_addr;
            sess.traffic_secret = traffic_secret;
            sess.last_seen = now;
            return;
        }
        let (assigned_v4, assigned_v6) = self.allocate_addrs();
        let sess = ClientSession {
            sender_id,
            src_addr,
            traffic_secret,
            assigned_v4,
            assigned_v6,
            orig_v4: Ipv4Addr::new(192, 0, 2, 1),
            orig_v6: Ipv6Addr::new(0xfd00, 0x7969, 0x70, 0, 0, 0, 0, 1),
            replay: ReplayWindow::default(),
            send_counter: 0,
            last_seen: now,
        };
        self.v4_to_sender.insert(assigned_v4, sender_id);
        self.v6_to_sender.insert(assigned_v6, sender_id);
        self.sessions.insert(sender_id, sess);
    }

    fn sweep_expired(&mut self) {
        let now = Instant::now();
        let expired: Vec<[u8; 8]> = self
            .sessions
            .iter()
            .filter_map(|(&id, s)| {
                if now.duration_since(s.last_seen) > SESSION_TTL {
                    Some(id)
                } else {
                    None
                }
            })
            .collect();
        for id in expired {
            if let Some(s) = self.sessions.remove(&id) {
                self.v4_to_sender.remove(&s.assigned_v4);
                self.v6_to_sender.remove(&s.assigned_v6);
            }
        }
    }
}

fn run_cmd(prog: &str, args: &[&str]) {
    let status = Command::new(prog).args(args).status();
    if let Err(e) = status {
        eprintln!("yip-exit: command `{prog} {}` failed: {e}", args.join(" "));
    }
}

fn configure_tun_and_nat(tun_name: &str, mtu: u16, wan_iface: &str) {
    let mtu_str = mtu.to_string();
    run_cmd("ip", &["addr", "replace", "10.77.0.1/16", "dev", tun_name]);
    run_cmd(
        "ip",
        &["-6", "addr", "replace", "fd77::1/64", "dev", tun_name],
    );
    run_cmd(
        "ip",
        &["link", "set", "dev", tun_name, "mtu", &mtu_str, "up"],
    );
    run_cmd("sysctl", &["-w", "net.ipv4.ip_forward=1"]);
    run_cmd("sysctl", &["-w", "net.ipv6.conf.all.forwarding=1"]);

    // Idempotently ensure MASQUERADE rules exist on the WAN interface.
    let v4_exists = Command::new("iptables")
        .args([
            "-t",
            "nat",
            "-C",
            "POSTROUTING",
            "-s",
            "10.77.0.0/16",
            "-o",
            wan_iface,
            "-j",
            "MASQUERADE",
        ])
        .status()
        .is_ok_and(|s| s.success());
    if !v4_exists {
        run_cmd(
            "iptables",
            &[
                "-t",
                "nat",
                "-A",
                "POSTROUTING",
                "-s",
                "10.77.0.0/16",
                "-o",
                wan_iface,
                "-j",
                "MASQUERADE",
            ],
        );
    }

    let v6_exists = Command::new("ip6tables")
        .args([
            "-t",
            "nat",
            "-C",
            "POSTROUTING",
            "-s",
            "fd77::/64",
            "-o",
            wan_iface,
            "-j",
            "MASQUERADE",
        ])
        .status()
        .is_ok_and(|s| s.success());
    if !v6_exists {
        run_cmd(
            "ip6tables",
            &[
                "-t",
                "nat",
                "-A",
                "POSTROUTING",
                "-s",
                "fd77::/64",
                "-o",
                wan_iface,
                "-j",
                "MASQUERADE",
            ],
        );
    }
}

fn extract_dst_ip(pkt: &[u8]) -> Option<IpAddr> {
    let version = pkt.first().map(|b| b >> 4)?;
    if version == 4 && pkt.len() >= 20 {
        Some(IpAddr::V4(Ipv4Addr::new(
            pkt[16], pkt[17], pkt[18], pkt[19],
        )))
    } else if version == 6 && pkt.len() >= 40 {
        let bytes: [u8; 16] = pkt[24..40].try_into().ok()?;
        Some(IpAddr::V6(Ipv6Addr::from(bytes)))
    } else {
        None
    }
}

struct CliArgs {
    listen_udp: String,
    tun_name: String,
    mtu: u16,
    wan_iface: String,
}

fn parse_args() -> CliArgs {
    let mut args = CliArgs {
        listen_udp: "0.0.0.0:4445".to_string(),
        tun_name: "yip-exit0".to_string(),
        mtu: 1380,
        wan_iface: "eth1".to_string(),
    };
    let mut it = std::env::args().skip(1);
    while let Some(flag) = it.next() {
        match flag.as_str() {
            "--listen-udp" => {
                if let Some(v) = it.next() {
                    args.listen_udp = v;
                }
            }
            "--tun" => {
                if let Some(v) = it.next() {
                    args.tun_name = v;
                }
            }
            "--mtu" => {
                if let Some(v) = it.next() {
                    if let Ok(m) = v.parse::<u16>() {
                        args.mtu = m;
                    }
                }
            }
            "--wan-iface" => {
                if let Some(v) = it.next() {
                    args.wan_iface = v;
                }
            }
            _ => {}
        }
    }
    args
}

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() {
    let cli = parse_args();
    let tun = TunTap::create(&cli.tun_name, DeviceKind::Tun, false).unwrap_or_else(|e| {
        eprintln!("fatal: failed to create TUN {}: {e}", cli.tun_name);
        std::process::exit(1);
    });

    configure_tun_and_nat(&cli.tun_name, cli.mtu, &cli.wan_iface);

    let (mut tun_reader, mut tun_writer) = tun.split().unwrap_or_else(|e| {
        eprintln!("fatal: failed to split TUN {}: {e}", cli.tun_name);
        std::process::exit(1);
    });

    let udp = UdpSocket::bind(&cli.listen_udp).await.unwrap_or_else(|e| {
        eprintln!("fatal: failed to bind UDP {}: {e}", cli.listen_udp);
        std::process::exit(1);
    });
    eprintln!(
        "yip-exit listening on {} (tun={}, wan={})",
        cli.listen_udp, cli.tun_name, cli.wan_iface
    );

    let (tun_rx_tx, mut tun_rx_rx) = mpsc::channel::<Vec<u8>>(1024);
    std::thread::spawn(move || {
        let mut buf = vec![0u8; 65536];
        loop {
            match tun_reader.read_frame(&mut buf) {
                Ok(0) => continue,
                Ok(n) => {
                    if tun_rx_tx.blocking_send(buf[..n].to_vec()).is_err() {
                        break;
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(_) => break,
            }
        }
    });

    let mut state = ExitState::new();
    let mut udp_buf = vec![0u8; 65536];
    let mut sweep_tick = tokio::time::interval(SWEEP_INTERVAL);

    loop {
        tokio::select! {
            _ = sweep_tick.tick() => {
                state.sweep_expired();
            }
            recv_res = udp.recv_from(&mut udp_buf) => {
                let Ok((len, src_addr)) = recv_res else {
                    continue;
                };
                if len < MIN_PACKET_LEN {
                    continue;
                }
                let Ok(header_bytes): Result<[u8; HEADER_LEN], _> = udp_buf[..HEADER_LEN].try_into() else {
                    continue;
                };
                let hdr = PacketHeader::from_bytes(&header_bytes);
                let payload_end = HEADER_LEN + usize::from(hdr.payload_len);
                if payload_end + AUTH_TAG_LEN != len {
                    continue;
                }
                let body = &udp_buf[HEADER_LEN..payload_end];
                let Ok(tag): Result<[u8; AUTH_TAG_LEN], _> = udp_buf[payload_end..len].try_into() else {
                    continue;
                };

                if hdr.packet_type == PACKET_TYPE_CONTROL && hdr.flags == CONTROL_FLAG_REGISTER {
                    let Ok(network_id) = std::str::from_utf8(body) else {
                        continue;
                    };
                    if network_id.is_empty() || network_id.len() > 64 {
                        continue;
                    }
                    let secret = derive_mesh_secret(network_id);
                    if !verify_auth_tag(&secret, &header_bytes, body, &tag) {
                        continue;
                    }
                    state.upsert_session(hdr.sender_id, src_addr, secret);
                    let ack = encode_control_packet(
                        &secret,
                        CONTROL_FLAG_ACK,
                        hdr.epoch,
                        hdr.nonce,
                        hdr.sender_id,
                        b"ok",
                    );
                    let _ = udp.send_to(&ack, src_addr).await;
                    continue;
                }

                let Some(sess) = state.sessions.get_mut(&hdr.sender_id) else {
                    continue;
                };
                if !sess.replay.check(hdr.nonce) {
                    continue;
                }
                if !verify_auth_tag(&sess.traffic_secret, &header_bytes, body, &tag) {
                    continue;
                }
                sess.replay.commit(hdr.nonce);
                sess.src_addr = src_addr;
                sess.last_seen = Instant::now();

                if hdr.packet_type == PACKET_TYPE_DECOY {
                    continue;
                }
                if hdr.packet_type == PACKET_TYPE_DATA {
                    let mut plaintext = xor_keystream(
                        &sess.traffic_secret,
                        hdr.epoch,
                        hdr.nonce,
                        &hdr.sender_id,
                        body,
                    );
                    let Some(orig_addr) =
                        rewrite_outbound_src(&mut plaintext, sess.assigned_v4, sess.assigned_v6)
                    else {
                        continue;
                    };
                    match orig_addr {
                        ClientOrigAddr::V4(v4) => sess.orig_v4 = v4,
                        ClientOrigAddr::V6(v6) => sess.orig_v6 = v6,
                    }
                    let _ = tun_writer.write_frame(&plaintext);
                }
            }
            Some(mut pkt) = tun_rx_rx.recv() => {
                let Some(dst_ip) = extract_dst_ip(&pkt) else {
                    continue;
                };
                let sender_opt = match dst_ip {
                    IpAddr::V4(v4) => state.v4_to_sender.get(&v4).copied(),
                    IpAddr::V6(v6) => state.v6_to_sender.get(&v6).copied(),
                };
                let Some(sender_id) = sender_opt else {
                    continue;
                };
                let Some(sess) = state.sessions.get_mut(&sender_id) else {
                    continue;
                };
                if !rewrite_inbound_dst(&mut pkt, sess.orig_v4, sess.orig_v6) {
                    continue;
                }
                sess.send_counter = sess.send_counter.wrapping_add(1);
                let frame = encode_data_packet(
                    &sess.traffic_secret,
                    1,
                    sess.send_counter,
                    sess.sender_id,
                    &pkt,
                );
                let _ = udp.send_to(&frame, sess.src_addr).await;
            }
        }
    }
}
