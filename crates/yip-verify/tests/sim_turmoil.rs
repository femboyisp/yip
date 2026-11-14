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
use yip_transport::{FecEncoder, FecReassembler, FlowParams, Symbol};
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

fn serialize_symbol(sym: &Symbol) -> Vec<u8> {
    let mut buf = Vec::with_capacity(10 + sym.data.len());
    buf.extend_from_slice(&sym.object_id.to_be_bytes());
    buf.extend_from_slice(&sym.object_size.to_be_bytes());
    buf.extend_from_slice(&sym.payload_id);
    buf.extend_from_slice(&sym.data);
    buf
}

fn deserialize_symbol(bytes: &[u8]) -> Option<Symbol> {
    if bytes.len() < 10 {
        return None;
    }
    let object_id = u16::from_be_bytes([bytes[0], bytes[1]]);
    let object_size = u32::from_be_bytes([bytes[2], bytes[3], bytes[4], bytes[5]]);
    let mut payload_id = [0u8; 4];
    payload_id.copy_from_slice(&bytes[6..10]);
    let data = bytes[10..].to_vec();
    Some(Symbol {
        object_id,
        object_size,
        payload_id,
        data,
    })
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

#[test]
fn test_turmoil_byzantine_partition_healing() -> Result<(), Box<dyn std::error::Error>> {
    let mut sim = Builder::new()
        .min_message_latency(Duration::from_millis(5))
        .max_message_latency(Duration::from_millis(25))
        .fail_rate(0.0)
        .rng_seed(42)
        .simulation_duration(Duration::from_secs(30))
        .build();

    let node_count = 4;
    let expected_records: Vec<Record> = (0..node_count)
        .map(|i| mock_record(u8::try_from(i).expect("node index fits in u8"), 1))
        .collect();

    let current_directories: Arc<Mutex<HashMap<usize, HashMap<NodeId, Record>>>> =
        Arc::new(Mutex::new(HashMap::new()));
    let all_done = Arc::new(AtomicBool::new(false));

    for (i, my_record) in expected_records.iter().cloned().enumerate() {
        let hostname = format!("node_{i}");
        let peers: Vec<String> = (0..node_count)
            .filter(|&j| j != i)
            .map(|j| format!("node_{j}:9000"))
            .collect();
        let current_directories = Arc::clone(&current_directories);
        let all_done = Arc::clone(&all_done);

        sim.client(hostname, async move {
            let socket = turmoil::net::UdpSocket::bind("0.0.0.0:9000").await?;
            let mut directory: HashMap<NodeId, Record> = HashMap::new();
            directory.insert(my_record.node_id, my_record);

            {
                let mut lock = current_directories
                    .lock()
                    .expect("lock current directories");
                lock.insert(i, directory.clone());
            }

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
                                    let mut updated = false;
                                    for r in records {
                                        let replace = match directory.get(&r.node_id) {
                                            None => true,
                                            Some(existing) => r.seq > existing.seq,
                                        };
                                        if replace {
                                            directory.insert(r.node_id, r);
                                            updated = true;
                                        }
                                    }

                                    if updated {
                                        let mut lock = current_directories
                                            .lock()
                                            .expect("lock current directories");
                                        lock.insert(i, directory.clone());
                                    }
                                }
                            }
                        }
                    }
                }
            }

            {
                let mut lock = current_directories
                    .lock()
                    .expect("lock current directories");
                lock.insert(i, directory);
            }
            Ok(())
        });
    }

    // Initial partitioned state across partition boundary:
    // sub_a = ["node_0", "node_1"], sub_b = ["node_2", "node_3"]
    sim.partition("node_0", "node_2");
    sim.partition("node_0", "node_3");
    sim.partition("node_1", "node_2");
    sim.partition("node_1", "node_3");

    // Run simulation until each sub-cluster reaches 2 records
    loop {
        {
            let dirs = current_directories
                .lock()
                .expect("lock current directories");
            let sub_a_ready = dirs.get(&0).map_or(0, |d| d.len()) >= 2
                && dirs.get(&1).map_or(0, |d| d.len()) >= 2;
            let sub_b_ready = dirs.get(&2).map_or(0, |d| d.len()) >= 2
                && dirs.get(&3).map_or(0, |d| d.len()) >= 2;
            if sub_a_ready && sub_b_ready {
                break;
            }
        }
        let finished = sim.step()?;
        if finished {
            break;
        }
    }

    // Assert neither sub-cluster knows about the other
    {
        let dirs = current_directories
            .lock()
            .expect("lock current directories");
        for i in 0..node_count {
            assert_eq!(
                dirs[&i].len(),
                2,
                "node {i} must hold exactly 2 records before repair"
            );
        }
        for i in 0..2 {
            let dir = &dirs[&i];
            assert!(dir.contains_key(&expected_records[0].node_id));
            assert!(dir.contains_key(&expected_records[1].node_id));
            assert!(!dir.contains_key(&expected_records[2].node_id));
            assert!(!dir.contains_key(&expected_records[3].node_id));
        }
        for i in 2..4 {
            let dir = &dirs[&i];
            assert!(!dir.contains_key(&expected_records[0].node_id));
            assert!(!dir.contains_key(&expected_records[1].node_id));
            assert!(dir.contains_key(&expected_records[2].node_id));
            assert!(dir.contains_key(&expected_records[3].node_id));
        }
    }

    // Call sim.repair between all nodes across the partition boundary
    sim.repair("node_0", "node_2");
    sim.repair("node_0", "node_3");
    sim.repair("node_1", "node_2");
    sim.repair("node_1", "node_3");

    // Run simulation until all 4 nodes reach 4 records (100% full directory reconciliation)
    loop {
        {
            let dirs = current_directories
                .lock()
                .expect("lock current directories");
            let all_converged = (0..node_count).all(|i| dirs.get(&i).map_or(0, |d| d.len()) == 4);
            if all_converged {
                all_done.store(true, Ordering::SeqCst);
                break;
            }
        }
        let finished = sim.step()?;
        if finished {
            break;
        }
    }

    // Step until all clients complete
    while !sim.step()? {}

    // Assert that partition healing achieves 100% convergence across all 4 nodes deterministically
    let dirs = current_directories
        .lock()
        .expect("lock current directories");
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

fn run_fec_burst_loss_sim(
    k: usize,
    r: usize,
    symbol_size: u16,
    rng_seed: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut sim = Builder::new()
        .min_message_latency(Duration::from_millis(5))
        .max_message_latency(Duration::from_millis(20))
        .fail_rate(0.20)
        .rng_seed(rng_seed)
        .simulation_duration(Duration::from_secs(30))
        .build();

    let payload_len = k * usize::from(symbol_size);
    let original_payload: Vec<u8> = (0..payload_len)
        .map(|idx| ((idx * 37 + 11) % 256) as u8)
        .collect();

    let mut encoder = FecEncoder::new();
    let params = FlowParams {
        symbol_size,
        initial_repair_ratio: 0.1,
        deadline: Duration::from_secs(10),
        arq: false,
    };
    let shards = encoder.encode(
        &original_payload,
        params,
        u32::try_from(r).expect("r fits u32"),
    );
    assert_eq!(shards.len(), k + r);

    let done = Arc::new(AtomicBool::new(false));
    let packets_sent = Arc::new(AtomicUsize::new(0));
    let packets_received = Arc::new(AtomicUsize::new(0));
    let recovered_payload: Arc<Mutex<Option<Vec<u8>>>> = Arc::new(Mutex::new(None));
    let recovered_with_fec = Arc::new(AtomicBool::new(false));

    let sender_shards = shards;
    let sender_done = Arc::clone(&done);
    let sender_packets_sent = Arc::clone(&packets_sent);

    sim.client("sender", async move {
        let socket = turmoil::net::UdpSocket::bind("0.0.0.0:9001").await?;
        let mut ack_buf = [0u8; 16];
        let mut interval = tokio::time::interval(Duration::from_millis(40));

        loop {
            if sender_done.load(Ordering::SeqCst) {
                break;
            }

            tokio::select! {
                _ = interval.tick() => {
                    if sender_done.load(Ordering::SeqCst) {
                        break;
                    }
                    for sym in &sender_shards {
                        let wire_bytes = serialize_symbol(sym);
                        sender_packets_sent.fetch_add(1, Ordering::SeqCst);
                        let _ = socket.send_to(&wire_bytes, "receiver:9000").await;
                    }
                }
                ack_res = socket.recv_from(&mut ack_buf) => {
                    if let Ok((len, _)) = ack_res {
                        if &ack_buf[..len] == b"ACK" {
                            break;
                        }
                    }
                }
            }
        }
        Ok(())
    });

    let receiver_done = Arc::clone(&done);
    let receiver_packets_received = Arc::clone(&packets_received);
    let receiver_recovered = Arc::clone(&recovered_payload);
    let receiver_with_fec = Arc::clone(&recovered_with_fec);

    sim.client("receiver", async move {
        let socket = turmoil::net::UdpSocket::bind("0.0.0.0:9000").await?;
        let mut reassembler = FecReassembler::new(symbol_size, 64);
        let mut recv_buf = [0u8; 2048];

        loop {
            let (len, peer) = socket.recv_from(&mut recv_buf).await?;
            receiver_packets_received.fetch_add(1, Ordering::SeqCst);

            if let Some(sym) = deserialize_symbol(&recv_buf[..len]) {
                let key = u64::from(sym.object_id);
                if let Some(recovered) = reassembler.push(key, &sym, 0, 10_000) {
                    if reassembler.recovered_count() > 0 {
                        receiver_with_fec.store(true, Ordering::SeqCst);
                    }
                    {
                        let mut lock = receiver_recovered.lock().expect("lock recovered payload");
                        *lock = Some(recovered);
                    }
                    let _ = socket.send_to(b"ACK", peer).await;
                    receiver_done.store(true, Ordering::SeqCst);
                    break;
                }
            }
        }
        Ok(())
    });

    sim.run()?;

    let lock = recovered_payload.lock().expect("lock recovered payload");
    let recovered = lock
        .as_ref()
        .expect("receiver must successfully reconstruct payload under packet loss");
    assert_eq!(
        recovered, &original_payload,
        "recovered payload must match original byte-for-byte"
    );

    // Verify packet loss was actively encountered on the simulated link
    let sent = packets_sent.load(Ordering::SeqCst);
    let received = packets_received.load(Ordering::SeqCst);
    assert!(
        sent > received,
        "simulated turmoil link must drop packets (sent: {sent}, received: {received})"
    );
    assert!(
        recovered_with_fec.load(Ordering::SeqCst),
        "reconstruction must exercise RS FEC repair under packet loss"
    );

    Ok(())
}

#[test]
fn test_turmoil_adaptive_fec_burst_loss() -> Result<(), Box<dyn std::error::Error>> {
    // 4096-byte payload encoded with (k=4, r=2, symbol_size=1024) under 20% loss
    run_fec_burst_loss_sim(4, 2, 1024, 42)?;
    // 4096-byte payload encoded with (k=8, r=4, symbol_size=512) under 20% loss
    run_fec_burst_loss_sim(8, 4, 512, 1337)?;
    Ok(())
}
