#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio as _;
use turmoil::Builder;
use yip_crypto as _;
use yip_membership::cert::Cert;
use yip_membership::ids::{node_id, NodeId};
use yip_membership::record::Record;
use yip_membership::GossipMsg;
use yip_transport as _;
use yip_wire as _;

fn mock_record(node_index: u8, seq: u64) -> Record {
    let mut member_pubkey = [0u8; 32];
    member_pubkey[0] = node_index.saturating_add(1);
    let mut member_sign_pubkey = [0u8; 32];
    member_sign_pubkey[0] = node_index.saturating_add(1);
    let mut network_id = [0u8; 16];
    network_id[0] = 0x42;

    let cert = Cert {
        version: 1,
        member_pubkey,
        member_sign_pubkey,
        network_id,
        not_before: 0,
        not_after: u64::MAX,
        tags: Vec::new(),
        ca_sig: [0u8; 64],
    };

    let node_id = node_id(&member_pubkey);
    let endpoints = vec![SocketAddr::from((
        [10, 0, 0, node_index.saturating_add(1)],
        9000,
    ))];
    Record {
        node_id,
        cert,
        endpoints,
        seq,
        sig: [0u8; 64],
    }
}

fn run_gossip_convergence_sim(
    node_count: usize,
    fail_rate: f64,
    rng_seed: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut sim = Builder::new()
        .min_message_latency(Duration::from_millis(5))
        .max_message_latency(Duration::from_millis(25))
        .fail_rate(fail_rate)
        .rng_seed(rng_seed)
        .simulation_duration(Duration::from_secs(30))
        .build();

    let expected_records: Vec<Record> = (0..node_count)
        .map(|i| mock_record(u8::try_from(i).expect("node index fits in u8"), 1))
        .collect();

    let final_directories: Arc<Mutex<HashMap<usize, HashMap<NodeId, Record>>>> =
        Arc::new(Mutex::new(HashMap::new()));
    let converged_count = Arc::new(AtomicUsize::new(0));
    let all_done = Arc::new(AtomicBool::new(false));

    for (i, my_record) in expected_records.iter().cloned().enumerate() {
        let hostname = format!("node_{i}");
        let peers: Vec<String> = (0..node_count)
            .filter(|&j| j != i)
            .map(|j| format!("node_{j}:9000"))
            .collect();
        let final_directories = Arc::clone(&final_directories);
        let converged_count = Arc::clone(&converged_count);
        let all_done = Arc::clone(&all_done);

        sim.client(hostname, async move {
            let socket = turmoil::net::UdpSocket::bind("0.0.0.0:9000").await?;
            let mut directory: HashMap<NodeId, Record> = HashMap::new();
            directory.insert(my_record.node_id, my_record);

            let mut marked_converged = false;
            let mut interval = tokio::time::interval(Duration::from_millis(50));
            let mut recv_buf = [0u8; 4096];

            loop {
                if all_done.load(Ordering::SeqCst) {
                    break;
                }

                tokio::select! {
                    _ = interval.tick() => {
                        if all_done.load(Ordering::SeqCst) {
                            break;
                        }

                        let digest_entries: Vec<(NodeId, u64)> = directory
                            .values()
                            .map(|r| (r.node_id, r.seq))
                            .collect();
                        let msg = GossipMsg::Digest(digest_entries);
                        let mut buf = Vec::new();
                        msg.encode(&mut buf);

                        for peer in &peers {
                            let _ = socket.send_to(&buf, peer).await;
                        }
                    }
                    recv_res = socket.recv_from(&mut recv_buf) => {
                        let (len, peer_addr) = match recv_res {
                            Ok(res) => res,
                            Err(_) => continue,
                        };
                        if let Some(msg) = GossipMsg::decode(&recv_buf[..len]) {
                            match msg {
                                GossipMsg::Digest(peer_digest) => {
                                    let mut needed = Vec::new();
                                    for (id, seq) in peer_digest {
                                        match directory.get(&id) {
                                            None => needed.push(id),
                                            Some(r) if r.seq < seq => needed.push(id),
                                            _ => {}
                                        }
                                    }
                                    if !needed.is_empty() {
                                        let pull_req = GossipMsg::PullRequest(needed);
                                        let mut buf = Vec::new();
                                        pull_req.encode(&mut buf);
                                        let _ = socket.send_to(&buf, peer_addr).await;
                                    }
                                }
                                GossipMsg::PullRequest(requested_ids) => {
                                    let mut to_send = Vec::new();
                                    for id in requested_ids {
                                        if let Some(r) = directory.get(&id) {
                                            to_send.push(r.clone());
                                        }
                                    }
                                    if !to_send.is_empty() {
                                        let records_msg = GossipMsg::Records(to_send);
                                        let mut buf = Vec::new();
                                        records_msg.encode(&mut buf);
                                        let _ = socket.send_to(&buf, peer_addr).await;
                                    }
                                }
                                GossipMsg::Records(records) => {
                                    for r in records {
                                        let replace = match directory.get(&r.node_id) {
                                            None => true,
                                            Some(existing) => r.seq > existing.seq,
                                        };
                                        if replace {
                                            directory.insert(r.node_id, r);
                                        }
                                    }

                                    if directory.len() == node_count && !marked_converged {
                                        marked_converged = true;
                                        let prev = converged_count.fetch_add(1, Ordering::SeqCst);
                                        if prev + 1 == node_count {
                                            all_done.store(true, Ordering::SeqCst);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            {
                let mut lock = final_directories.lock().expect("lock final directories");
                lock.insert(i, directory);
            }
            Ok(())
        });
    }

    sim.run()?;

    let dirs = final_directories.lock().expect("lock final directories");
    assert_eq!(dirs.len(), node_count, "all nodes completed simulation");
    for i in 0..node_count {
        let node_dir = &dirs[&i];
        assert_eq!(
            node_dir.len(),
            node_count,
            "node {i} must hold all {node_count} records"
        );
        for (j, expected_record) in expected_records.iter().enumerate() {
            assert_eq!(
                node_dir.get(&expected_record.node_id),
                Some(expected_record),
                "node {i} must contain expected record of node {j}"
            );
        }
    }

    Ok(())
}

#[test]
fn test_turmoil_virtual_udp_ping_pong() -> Result<(), Box<dyn std::error::Error>> {
    let mut sim = Builder::new().build();

    sim.host("server", || async {
        let socket = turmoil::net::UdpSocket::bind("0.0.0.0:9000").await?;
        let mut buf = [0u8; 64];
        let (len, peer) = socket.recv_from(&mut buf).await?;
        assert_eq!(&buf[..len], b"ping");
        socket.send_to(b"pong", peer).await?;
        Ok(())
    });

    sim.client("client", async {
        let socket = turmoil::net::UdpSocket::bind("0.0.0.0:9001").await?;
        socket.send_to(b"ping", "server:9000").await?;
        let mut buf = [0u8; 64];
        let (len, _) = socket.recv_from(&mut buf).await?;
        assert_eq!(&buf[..len], b"pong");
        Ok(())
    });

    sim.run()
}

#[test]
fn test_turmoil_multi_node_gossip_convergence() -> Result<(), Box<dyn std::error::Error>> {
    // 3-node gossip mesh under simulated latency jitter and 5% packet loss
    run_gossip_convergence_sim(3, 0.05, 42)?;
    // 5-node gossip mesh under simulated latency jitter and 5% packet loss
    run_gossip_convergence_sim(5, 0.05, 1337)?;
    Ok(())
}
