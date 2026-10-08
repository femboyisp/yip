use yip_transport::rlnc::{scale_row, RlncDecoder, RlncEncoder};

#[test]
fn test_rlnc_rateless_encode_decode_round_trip() {
    let window_size = 8;
    let symbol_len = 1400;
    let mut encoder = RlncEncoder::new(window_size);

    let original: Vec<Vec<u8>> = (0..window_size)
        .map(|i| vec![(i * 31 + 7) as u8; symbol_len])
        .collect();

    for sym in &original {
        encoder.push_source(sym);
    }

    let mut decoder = RlncDecoder::new(window_size, symbol_len);

    let mut seed = 12345u32;
    while !decoder.is_complete() {
        let (coeffs, coded) = encoder.produce_coded_symbol(seed);
        decoder.consume_coded_symbol(&coeffs, &coded);
        seed += 1;
    }

    let decoded = decoder.extract_source_symbols().unwrap();
    assert_eq!(decoded, original);
}

#[test]
fn test_rlnc_varying_window_sizes_and_symbol_lengths() {
    for window_size in [4, 8, 16] {
        for symbol_len in [64, 512, 1400, 1500] {
            let mut encoder = RlncEncoder::new(window_size);

            let original: Vec<Vec<u8>> = (0..window_size)
                .map(|i| {
                    (0..symbol_len)
                        .map(|j| ((i * 37 + j * 13 + 3) % 256) as u8)
                        .collect()
                })
                .collect();

            for sym in &original {
                encoder.push_source(sym);
            }

            let mut decoder = RlncDecoder::new(window_size, symbol_len);
            let mut seed = 9999u32;
            let mut packets_sent = 0;

            while !decoder.is_complete() {
                let (coeffs, coded) = encoder.produce_coded_symbol(seed);
                decoder.consume_coded_symbol(&coeffs, &coded);
                seed = seed.wrapping_add(1);
                packets_sent += 1;
                assert!(packets_sent < 1000, "Too many packets without decoding");
            }

            assert_eq!(decoder.rank(), window_size);
            let decoded = decoder.extract_source_symbols().unwrap();
            assert_eq!(
                decoded, original,
                "Decoded symbols mismatch for W={window_size}, len={symbol_len}"
            );
        }
    }
}

#[test]
fn test_rlnc_linear_dependence_and_duplicate_rejection() {
    let window_size = 4;
    let symbol_len = 100;
    let mut encoder = RlncEncoder::new(window_size);

    let original: Vec<Vec<u8>> = (0..window_size)
        .map(|i| vec![(i * 17 + 5) as u8; symbol_len])
        .collect();

    for sym in &original {
        encoder.push_source(sym);
    }

    let mut decoder = RlncDecoder::new(window_size, symbol_len);

    // Generate first coded symbol
    let (c1, p1) = encoder.produce_coded_symbol(1001);
    assert!(
        decoder.consume_coded_symbol(&c1, &p1),
        "First packet must increase rank"
    );
    assert_eq!(decoder.rank(), 1);

    // Duplicate submission of first packet must return false and not increase rank
    assert!(
        !decoder.consume_coded_symbol(&c1, &p1),
        "Duplicate packet must be rejected"
    );
    assert_eq!(decoder.rank(), 1);

    // Second independent packet
    let (c2, p2) = encoder.produce_coded_symbol(1002);
    assert!(
        decoder.consume_coded_symbol(&c2, &p2),
        "Second packet must increase rank"
    );
    assert_eq!(decoder.rank(), 2);

    // Duplicate of second packet must be rejected
    assert!(
        !decoder.consume_coded_symbol(&c2, &p2),
        "Duplicate packet must be rejected"
    );
    assert_eq!(decoder.rank(), 2);

    // Construct an explicitly linearly dependent packet: c3 = c1 ^ c2, p3 = p1 ^ p2
    let mut c_dep = vec![0u8; window_size];
    for (i, cd) in c_dep.iter_mut().enumerate() {
        *cd = c1[i] ^ c2[i];
    }
    let mut p_dep = vec![0u8; symbol_len];
    for (j, pd) in p_dep.iter_mut().enumerate() {
        *pd = p1[j] ^ p2[j];
    }

    assert!(
        !decoder.consume_coded_symbol(&c_dep, &p_dep),
        "Linearly dependent packet must be rejected"
    );
    assert_eq!(decoder.rank(), 2);

    // Supply more packets until full rank
    let mut seed = 2000u32;
    while !decoder.is_complete() {
        let (coeffs, coded) = encoder.produce_coded_symbol(seed);
        decoder.consume_coded_symbol(&coeffs, &coded);
        seed += 1;
    }

    assert_eq!(decoder.rank(), window_size);
    assert!(decoder.is_complete());

    // Once complete, further packets must return false
    let (extra_c, extra_p) = encoder.produce_coded_symbol(seed);
    assert!(
        !decoder.consume_coded_symbol(&extra_c, &extra_p),
        "Packet delivered after completion must return false"
    );

    let decoded = decoder.extract_source_symbols().unwrap();
    assert_eq!(decoded, original);
}

#[test]
fn test_rlnc_incomplete_decoder_returns_none() {
    let window_size = 4;
    let symbol_len = 64;
    let mut encoder = RlncEncoder::new(window_size);

    for i in 0..window_size {
        encoder.push_source(&vec![i as u8; symbol_len]);
    }

    let mut decoder = RlncDecoder::new(window_size, symbol_len);
    assert_eq!(decoder.extract_source_symbols(), None);

    let (c1, p1) = encoder.produce_coded_symbol(42);
    decoder.consume_coded_symbol(&c1, &p1);
    assert_eq!(decoder.rank(), 1);
    assert!(!decoder.is_complete());
    assert_eq!(decoder.extract_source_symbols(), None);
}

#[test]
fn test_rlnc_malformed_packet_rejection() {
    let window_size = 4;
    let symbol_len = 64;
    let mut decoder = RlncDecoder::new(window_size, symbol_len);

    // Wrong coeffs length
    let bad_coeffs = vec![1u8; window_size - 1];
    let good_payload = vec![0xaa; symbol_len];
    assert!(!decoder.consume_coded_symbol(&bad_coeffs, &good_payload));

    // Wrong payload length
    let good_coeffs = vec![1u8; window_size];
    let bad_payload = vec![0xaa; symbol_len + 1];
    assert!(!decoder.consume_coded_symbol(&good_coeffs, &bad_payload));

    assert_eq!(decoder.rank(), 0);
}

#[test]
fn test_scale_row() {
    let mut row = vec![1, 2, 3, 4, 5, 255];
    let copy = row.clone();

    // Scale by 1 is no-op
    scale_row(1, &mut row);
    assert_eq!(row, copy);

    // Scale by 0 zeroes row
    scale_row(0, &mut row);
    assert_eq!(row, vec![0; copy.len()]);

    // Scale by scalar c matches scalar gf256::mul
    let mut test_row = vec![10, 20, 30, 40, 50];
    let c = 0x57;
    scale_row(c, &mut test_row);
    let expected: Vec<u8> = vec![10, 20, 30, 40, 50]
        .into_iter()
        .map(|b| yip_transport::gf256::mul(c, b))
        .collect();
    assert_eq!(test_row, expected);
}
