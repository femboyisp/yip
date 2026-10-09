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
    let mut packets_sent = 0;
    while !decoder.is_complete() {
        let (coeffs, coded) = encoder.produce_coded_symbol(seed);
        decoder.consume_coded_symbol(&coeffs, &coded);
        seed += 1;
        packets_sent += 1;
        assert!(packets_sent < 100, "Too many packets without decoding");
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
    let mut packets_sent = 0;
    while !decoder.is_complete() {
        let (coeffs, coded) = encoder.produce_coded_symbol(seed);
        decoder.consume_coded_symbol(&coeffs, &coded);
        seed += 1;
        packets_sent += 1;
        assert!(packets_sent < 100, "Too many packets without decoding");
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

#[test]
fn test_rlnc_accessors_and_edge_cases() {
    let mut encoder = RlncEncoder::new(5);
    assert_eq!(encoder.window_size(), 5);
    assert_eq!(encoder.len(), 0);
    assert!(encoder.is_empty());

    // Empty encoder produce_coded_symbol
    let (c, p) = encoder.produce_coded_symbol(123);
    assert_eq!(c.len(), 5);
    assert_eq!(p.len(), 0);

    encoder.push_source(&[1, 2, 3]);
    assert_eq!(encoder.len(), 1);
    assert!(!encoder.is_empty());

    let mut decoder = RlncDecoder::new(5, 3);
    assert_eq!(decoder.window_size(), 5);
    assert_ne!(decoder.window_size(), 1);
    assert_eq!(decoder.symbol_len(), 3);
    assert_eq!(decoder.rank(), 0);

    // Test produce_coded_symbol with seed=33 where first byte is 0 and second byte is 59
    let mut enc2 = RlncEncoder::new(2);
    enc2.push_source(&[10, 20]);
    enc2.push_source(&[30, 40]);
    let (c_seed, p_seed) = enc2.produce_coded_symbol(33);
    assert_eq!(c_seed[0], 0);
    assert_eq!(c_seed[1], 59);
    assert_eq!(p_seed.len(), 2);

    // Test produce_coded_symbol with seed=1640531527 where first 4-byte draw is ALL zero.
    // Must loop to draw second round where bytes are non-zero:
    let mut enc4 = RlncEncoder::new(4);
    for i in 0..4 {
        enc4.push_source(&[i as u8, (i * 2) as u8]);
    }
    let (c_zero_draw, _) = enc4.produce_coded_symbol(1640531527);
    // In first iteration, rand_val is 0. If loop doesn't re-draw (or doesn't detect all-zero),
    // c_zero_draw would be all 0 (or fallback coeffs[0]=1 with others 0).
    // In second iteration, rand_val = 2462723854 = 0x92c90f0e.
    assert_eq!(c_zero_draw[0], 14);
    assert_eq!(c_zero_draw[1], 47);
    assert_eq!(c_zero_draw[2], 202);
    assert_eq!(c_zero_draw[3], 146);

    let (c1, p1) = encoder.produce_coded_symbol(999);
    assert!(decoder.consume_coded_symbol(&c1[..5], &p1));
    assert_eq!(decoder.rank(), 1);
    assert!(!decoder.is_complete());

    // Test pivot normalization: row with non-zero trailing coefficient scaled by inv
    // col = 0, cur_coeffs = [2, 3], inv = inv(2) = 142.
    // cur_coeffs[1] = mul(3, 142) = 217.
    let mut dec2 = RlncDecoder::new(2, 2);
    let coeffs = vec![2u8, 3u8];
    let payload = vec![4u8, 5u8];
    assert!(dec2.consume_coded_symbol(&coeffs, &payload));
    assert_eq!(dec2.rank(), 1);

    // Test pivot normalization when col = 2 (col > 0 so (col + 1) != (col * 1)):
    // window_size = 4. Pivot at col = 2 with coeffs = [0, 0, 5, 7].
    // If (col + 1) is mutated to (col * 1), slice starts at col = 2 instead of col + 1 = 3.
    // Submitting a second packet that cancels col = 2 and checks col = 3 tests normalized value!
    let mut dec3 = RlncDecoder::new(4, 2);
    let coeffs_pivot = vec![0u8, 0u8, 5u8, 7u8];
    assert!(dec3.consume_coded_symbol(&coeffs_pivot, &[10, 20]));
    // Pivot normalized cur_coeffs[2] to 1, cur_coeffs[3] = mul(7, inv(5)) = mul(7, 167) = 82.
    // Normalized payload: scale_row(inv(5), &[10, 20]) = [2, 4].
    // Now submit packet with [0, 0, 1, 82] and payload [2, 4].
    // It must be rejected as linearly dependent!
    // Under mutant `*`, cur_coeffs[2] gets overwritten or cur_coeffs[3] is wrong!
    assert!(
        !dec3.consume_coded_symbol(&[0u8, 0u8, 1u8, 82u8], &[2, 4]),
        "normalized row must detect exact linearly dependent row"
    );

    // Consume when already complete returns false
    let mut dec_comp = RlncDecoder::new(1, 3);
    assert!(dec_comp.consume_coded_symbol(&c1[..1], &p1));
    assert!(dec_comp.is_complete());
    assert!(!dec_comp.consume_coded_symbol(&c1[..1], &p1));
}

#[test]
#[should_panic(expected = "cannot push more than window_size symbols")]
fn test_rlnc_push_exceeds_window() {
    let mut encoder = RlncEncoder::new(1);
    encoder.push_source(&[1, 2, 3]);
    encoder.push_source(&[4, 5, 6]);
}

#[test]
#[should_panic(expected = "all source symbols must have identical length")]
fn test_rlnc_push_mismatched_length() {
    let mut encoder = RlncEncoder::new(2);
    encoder.push_source(&[1, 2, 3]);
    encoder.push_source(&[1, 2]);
}

#[test]
fn test_splitmix32_exact_vectors() {
    use yip_transport::rlnc::splitmix32;
    let mut s = 1u32;
    assert_eq!(splitmix32(&mut s), 0x96a0f96b);
    assert_eq!(s, 0x9e3779ba);
    assert_eq!(splitmix32(&mut s), 0x12bc8390);
    assert_eq!(s, 0x3c6ef373);
    assert_eq!(splitmix32(&mut s), 0x971e9964);
    assert_eq!(s, 0xdaa66d2c);
    assert_eq!(splitmix32(&mut s), 0x79adc7e7);
    assert_eq!(s, 0x78dde6e5);
    assert_eq!(splitmix32(&mut s), 0x591c8dd8);
    assert_eq!(s, 0x1715609e);
}
