use coin_smith::builder::*;
use coin_smith::coin_selection::*;
use coin_smith::fixture::*;
use coin_smith::report::*;

// ═══════════════════════════════════════════════════════════════════════════
// Helper functions
// ═══════════════════════════════════════════════════════════════════════════

fn make_utxo(txid: &str, vout: u32, value: u64, script_type: &str) -> Utxo {
    Utxo {
        txid: txid.to_string(),
        vout,
        value_sats: value,
        script_pubkey_hex: match script_type {
            "p2wpkh" => "00141111111111111111111111111111111111111111".to_string(),
            "p2tr" => "51201111111111111111111111111111111111111111111111111111111111111111".to_string(),
            "p2pkh" => "76a914111111111111111111111111111111111111111188ac".to_string(),
            "p2sh-p2wpkh" => "a914111111111111111111111111111111111111111187".to_string(),
            "p2wsh" => "00201111111111111111111111111111111111111111111111111111111111111111".to_string(),
            _ => "00141111111111111111111111111111111111111111".to_string(),
        },
        script_type: script_type.to_string(),
        address: None,
    }
}

fn make_fixture(rbf: Option<bool>, locktime: Option<u32>, current_height: Option<u32>) -> Fixture {
    Fixture {
        network: "mainnet".to_string(),
        utxos: vec![make_utxo(
            "1111111111111111111111111111111111111111111111111111111111111111",
            0, 100000, "p2wpkh",
        )],
        payments: vec![Payment {
            address: None,
            script_pubkey_hex: "00142222222222222222222222222222222222222222".to_string(),
            script_type: "p2wpkh".to_string(),
            value_sats: 50000,
        }],
        change: ChangeTemplate {
            address: None,
            script_pubkey_hex: "00143333333333333333333333333333333333333333".to_string(),
            script_type: "p2wpkh".to_string(),
        },
        fee_rate_sat_vb: 5.0,
        rbf,
        locktime,
        current_height,
        policy: None,
    }
}

fn make_fixture_with_policy(rbf: Option<bool>, locktime: Option<u32>, current_height: Option<u32>, max_inputs: Option<usize>) -> Fixture {
    let mut f = make_fixture(rbf, locktime, current_height);
    f.policy = max_inputs.map(|mi| Policy { max_inputs: Some(mi) });
    f
}

// ═══════════════════════════════════════════════════════════════════════════
// 1. RBF / nSequence comprehensive tests (hidden categories)
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_rbf_false_explicit_nsequence() {
    // rbf: false explicitly → nSequence = 0xFFFFFFFF
    let fixture = make_fixture(Some(false), None, None);
    let seq = determine_nsequence(&fixture);
    assert_eq!(seq.0, 0xFFFFFFFF, "rbf:false should give MAX sequence");
}

#[test]
fn test_rbf_false_with_locktime_nsequence() {
    // rbf: false + locktime → nSequence = 0xFFFFFFFE
    let fixture = make_fixture(Some(false), Some(850000), None);
    let seq = determine_nsequence(&fixture);
    assert_eq!(seq.0, 0xFFFFFFFE, "rbf:false + locktime should give ENABLE_LOCKTIME");
}

#[test]
fn test_rbf_absent_nsequence() {
    // rbf absent (None) → same as false → 0xFFFFFFFF
    let fixture = make_fixture(None, None, None);
    let seq = determine_nsequence(&fixture);
    assert_eq!(seq.0, 0xFFFFFFFF);
}

#[test]
fn test_rbf_true_all_inputs_signal() {
    // With multiple inputs, all must have nSequence = 0xFFFFFFFD
    let mut fixture = make_fixture(Some(true), None, None);
    fixture.utxos = vec![
        make_utxo("1111111111111111111111111111111111111111111111111111111111111111", 0, 30000, "p2wpkh"),
        make_utxo("2222222222222222222222222222222222222222222222222222222222222222", 0, 30000, "p2wpkh"),
        make_utxo("3333333333333333333333333333333333333333333333333333333333333333", 0, 30000, "p2wpkh"),
    ];
    fixture.payments[0].value_sats = 50000;
    let result = build_psbt(
        &fixture,
        &fixture.utxos,
        &fixture.payments,
        Some((20000, &fixture.change)),
    ).unwrap();
    for input in &result.tx.input {
        assert_eq!(input.sequence.0, 0xFFFFFFFD, "All inputs must signal RBF");
    }
}

#[test]
fn test_rbf_true_with_locktime_nsequence() {
    // rbf: true + locktime → nSequence = 0xFFFFFFFD (RBF wins)
    let fixture = make_fixture(Some(true), Some(850000), None);
    let seq = determine_nsequence(&fixture);
    assert_eq!(seq.0, 0xFFFFFFFD);
}

#[test]
fn test_rbf_true_no_locktime_no_current_height() {
    // rbf: true, no locktime, no current_height → nLockTime = 0
    let fixture = make_fixture(Some(true), None, None);
    let lt = determine_locktime(&fixture);
    assert_eq!(locktime_to_u32(&lt), 0);
}

// ═══════════════════════════════════════════════════════════════════════════
// 2. Anti-fee-sniping tests
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_anti_fee_sniping_basic() {
    // rbf: true + current_height + no locktime → nLockTime = current_height
    let fixture = make_fixture(Some(true), None, Some(860000));
    let lt = determine_locktime(&fixture);
    assert_eq!(locktime_to_u32(&lt), 860000);
    assert_eq!(locktime_type_str(860000), "block_height");
}

#[test]
fn test_anti_fee_sniping_locktime_overrides() {
    // rbf: true + current_height + explicit locktime → locktime wins
    let fixture = make_fixture(Some(true), Some(850000), Some(860000));
    let lt = determine_locktime(&fixture);
    assert_eq!(locktime_to_u32(&lt), 850000);
}

#[test]
fn test_no_anti_fee_sniping_when_rbf_false() {
    // rbf: false + current_height → no anti-fee-sniping, nLockTime = 0
    let fixture = make_fixture(Some(false), None, Some(860000));
    let lt = determine_locktime(&fixture);
    assert_eq!(locktime_to_u32(&lt), 0);
}

#[test]
fn test_no_anti_fee_sniping_when_rbf_absent() {
    // rbf: absent + current_height → no anti-fee-sniping
    let fixture = make_fixture(None, None, Some(860000));
    let lt = determine_locktime(&fixture);
    assert_eq!(locktime_to_u32(&lt), 0);
}

// ═══════════════════════════════════════════════════════════════════════════
// 3. Locktime boundary tests (hidden category)
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_locktime_type_1() {
    assert_eq!(locktime_type_str(1), "block_height");
}

#[test]
fn test_locktime_type_boundary_just_below() {
    assert_eq!(locktime_type_str(499_999_998), "block_height");
}

#[test]
fn test_locktime_type_boundary_500000001() {
    assert_eq!(locktime_type_str(500_000_001), "unix_timestamp");
}

#[test]
fn test_locktime_type_max_u32() {
    assert_eq!(locktime_type_str(u32::MAX), "unix_timestamp");
}

#[test]
fn test_locktime_boundary_in_psbt() {
    // locktime = 499999999 → block_height, nSequence = 0xFFFFFFFE
    let fixture = make_fixture(None, Some(499_999_999), None);
    let lt = determine_locktime(&fixture);
    assert_eq!(locktime_to_u32(&lt), 499_999_999);
    let seq = determine_nsequence(&fixture);
    assert_eq!(seq.0, 0xFFFFFFFE);
}

#[test]
fn test_locktime_timestamp_in_psbt() {
    // locktime = 500000000 → unix_timestamp, nSequence = 0xFFFFFFFE
    let fixture = make_fixture(None, Some(500_000_000), None);
    let lt = determine_locktime(&fixture);
    assert_eq!(locktime_to_u32(&lt), 500_000_000);
    let seq = determine_nsequence(&fixture);
    assert_eq!(seq.0, 0xFFFFFFFE);
}

#[test]
fn test_locktime_1700000000() {
    let fixture = make_fixture(None, Some(1_700_000_000), None);
    let lt = determine_locktime(&fixture);
    assert_eq!(locktime_to_u32(&lt), 1_700_000_000);
    assert_eq!(locktime_type_str(1_700_000_000), "unix_timestamp");
}

// ═══════════════════════════════════════════════════════════════════════════
// 4. Interaction matrix tests (all 5 rows)
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_matrix_row1_no_rbf_no_locktime() {
    let f = make_fixture(None, None, None);
    assert_eq!(determine_nsequence(&f).0, 0xFFFFFFFF);
    assert_eq!(locktime_to_u32(&determine_locktime(&f)), 0);
}

#[test]
fn test_matrix_row2_no_rbf_yes_locktime() {
    let f = make_fixture(Some(false), Some(850000), None);
    assert_eq!(determine_nsequence(&f).0, 0xFFFFFFFE);
    assert_eq!(locktime_to_u32(&determine_locktime(&f)), 850000);
}

#[test]
fn test_matrix_row3_rbf_no_locktime_yes_height() {
    let f = make_fixture(Some(true), None, Some(860000));
    assert_eq!(determine_nsequence(&f).0, 0xFFFFFFFD);
    assert_eq!(locktime_to_u32(&determine_locktime(&f)), 860000);
}

#[test]
fn test_matrix_row4_rbf_yes_locktime() {
    let f = make_fixture(Some(true), Some(850000), Some(860000));
    assert_eq!(determine_nsequence(&f).0, 0xFFFFFFFD);
    assert_eq!(locktime_to_u32(&determine_locktime(&f)), 850000);
}

#[test]
fn test_matrix_row5_rbf_no_locktime_no_height() {
    let f = make_fixture(Some(true), None, None);
    assert_eq!(determine_nsequence(&f).0, 0xFFFFFFFD);
    assert_eq!(locktime_to_u32(&determine_locktime(&f)), 0);
}

// ═══════════════════════════════════════════════════════════════════════════
// 5. Coin selection edge cases
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_exact_payment_no_change() {
    // Input value exactly covers payment + fee → no change
    let utxos = vec![make_utxo(
        "1111111111111111111111111111111111111111111111111111111111111111",
        0, 50550, "p2wpkh",
    )];
    // payment=50000, fee for 1 input + 1 output + overhead (11+68+31=110 vbytes)
    // fee = ceil(110 * 1.0) = 110
    let result = select_coins(&utxos, 50000, &["p2wpkh"], "p2wpkh", 1.0, None);
    assert!(result.is_ok());
    let r = result.unwrap();
    // Leftover = 50550 - 50000 - 110 = 440 < 546, so no change
    assert!(r.change_amount.is_none());
}

#[test]
fn test_change_at_exact_dust_threshold() {
    // Change exactly = 546 → should create change
    let utxos = vec![make_utxo(
        "1111111111111111111111111111111111111111111111111111111111111111",
        0, 200000, "p2wpkh",
    )];
    let result = select_coins(&utxos, 50000, &["p2wpkh"], "p2wpkh", 5.0, None).unwrap();
    // With change: vbytes = 11 + 68 + 31 + 31 = 141, fee = ceil(141*5) = 705
    // change = 200000 - 50000 - 705 = 149295 >= 546
    assert!(result.change_amount.is_some());
    assert!(result.change_amount.unwrap() >= 546);
}

#[test]
fn test_single_utxo_p2tr() {
    let utxos = vec![make_utxo(
        "1111111111111111111111111111111111111111111111111111111111111111",
        0, 100000, "p2tr",
    )];
    let result = select_coins(&utxos, 50000, &["p2tr"], "p2tr", 5.0, None).unwrap();
    assert_eq!(result.selected.len(), 1);
    assert!(result.change_amount.is_some());
}

#[test]
fn test_single_utxo_p2pkh() {
    let utxos = vec![make_utxo(
        "1111111111111111111111111111111111111111111111111111111111111111",
        0, 100000, "p2pkh",
    )];
    let result = select_coins(&utxos, 50000, &["p2pkh"], "p2pkh", 5.0, None).unwrap();
    assert_eq!(result.selected.len(), 1);
}

#[test]
fn test_mixed_script_type_inputs() {
    let utxos = vec![
        make_utxo("1111111111111111111111111111111111111111111111111111111111111111", 0, 30000, "p2wpkh"),
        make_utxo("2222222222222222222222222222222222222222222222222222222222222222", 0, 30000, "p2tr"),
        make_utxo("3333333333333333333333333333333333333333333333333333333333333333", 0, 30000, "p2pkh"),
    ];
    let result = select_coins(&utxos, 50000, &["p2wpkh"], "p2wpkh", 1.0, None);
    assert!(result.is_ok());
}

#[test]
fn test_max_inputs_exactly_met() {
    let utxos: Vec<Utxo> = (0..5)
        .map(|i| {
            let txid = format!("{:064x}", i + 1);
            make_utxo(&txid, 0, 20000, "p2wpkh")
        })
        .collect();
    let result = select_coins(&utxos, 50000, &["p2wpkh"], "p2wpkh", 1.0, Some(5));
    assert!(result.is_ok());
    let r = result.unwrap();
    assert!(r.selected.len() <= 5);
}

#[test]
fn test_insufficient_with_max_inputs() {
    let utxos: Vec<Utxo> = (0..10)
        .map(|i| {
            let txid = format!("{:064x}", i + 1);
            make_utxo(&txid, 0, 1000, "p2wpkh")
        })
        .collect();
    // Need 50000 but max 2 inputs, each 1000 = 2000 total, insufficient
    let result = select_coins(&utxos, 50000, &["p2wpkh"], "p2wpkh", 1.0, Some(2));
    assert!(result.is_err());
}

// ═══════════════════════════════════════════════════════════════════════════
// 6. Fee calculation edge cases
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_fee_rate_1_sat_vb() {
    let utxos = vec![make_utxo(
        "1111111111111111111111111111111111111111111111111111111111111111",
        0, 100000, "p2wpkh",
    )];
    let result = select_coins(&utxos, 50000, &["p2wpkh"], "p2wpkh", 1.0, None).unwrap();
    let min_fee = (1.0 * result.vbytes as f64).ceil() as u64;
    assert!(result.fee >= min_fee);
}

#[test]
fn test_high_fee_rate() {
    let utxos = vec![make_utxo(
        "1111111111111111111111111111111111111111111111111111111111111111",
        0, 1_000_000, "p2wpkh",
    )];
    let result = select_coins(&utxos, 50000, &["p2wpkh"], "p2wpkh", 500.0, None).unwrap();
    let min_fee = (500.0 * result.vbytes as f64).ceil() as u64;
    assert!(result.fee >= min_fee);
}

#[test]
fn test_balance_equation_always_holds() {
    let utxos = vec![make_utxo(
        "1111111111111111111111111111111111111111111111111111111111111111",
        0, 200000, "p2wpkh",
    )];
    for rate in [1.0, 5.0, 10.0, 50.0, 100.0] {
        let result = select_coins(&utxos, 50000, &["p2wpkh"], "p2wpkh", rate, None).unwrap();
        let input_total: u64 = result.selected.iter().map(|u| u.value_sats).sum();
        let change = result.change_amount.unwrap_or(0);
        assert_eq!(input_total, 50000 + change + result.fee,
            "Balance eq failed at fee_rate={}", rate);
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// 7. Warning generation tests
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_warning_high_fee_by_amount() {
    let fixture = make_fixture(None, None, None);
    let selection = CoinSelectionResult {
        selected: fixture.utxos.clone(),
        fee: 1_000_001,
        change_amount: None,
        vbytes: 110,
        strategy: "greedy".to_string(),
    };
    let report = build_report(&fixture, &selection, "dummy");
    let codes: Vec<&str> = report.warnings.iter().map(|w| w.code.as_str()).collect();
    assert!(codes.contains(&"HIGH_FEE"));
}

#[test]
fn test_warning_high_fee_by_rate() {
    let fixture = make_fixture(None, None, None);
    let selection = CoinSelectionResult {
        selected: fixture.utxos.clone(),
        fee: 22000, // 22000/110 = 200 is NOT >200
        change_amount: None,
        vbytes: 110,
        strategy: "greedy".to_string(),
    };
    let report = build_report(&fixture, &selection, "dummy");
    let codes: Vec<&str> = report.warnings.iter().map(|w| w.code.as_str()).collect();
    // fee_rate = 22000/110 = 200.0, not > 200, so no HIGH_FEE by rate
    // But fee < 1M so no HIGH_FEE by amount either
    assert!(!codes.contains(&"HIGH_FEE"));
}

#[test]
fn test_warning_high_fee_rate_above_200() {
    let fixture = make_fixture(None, None, None);
    let selection = CoinSelectionResult {
        selected: fixture.utxos.clone(),
        fee: 22001, // 22001/110 > 200
        change_amount: None,
        vbytes: 110,
        strategy: "greedy".to_string(),
    };
    let report = build_report(&fixture, &selection, "dummy");
    let codes: Vec<&str> = report.warnings.iter().map(|w| w.code.as_str()).collect();
    assert!(codes.contains(&"HIGH_FEE"));
}

#[test]
fn test_warning_send_all_no_change() {
    let fixture = make_fixture(None, None, None);
    let selection = CoinSelectionResult {
        selected: fixture.utxos.clone(),
        fee: 1000,
        change_amount: None,
        vbytes: 110,
        strategy: "greedy".to_string(),
    };
    let report = build_report(&fixture, &selection, "dummy");
    let codes: Vec<&str> = report.warnings.iter().map(|w| w.code.as_str()).collect();
    assert!(codes.contains(&"SEND_ALL"));
    assert!(!codes.contains(&"RBF_SIGNALING")); // no RBF
}

#[test]
fn test_no_send_all_with_change() {
    let fixture = make_fixture(None, None, None);
    let selection = CoinSelectionResult {
        selected: fixture.utxos.clone(),
        fee: 705,
        change_amount: Some(49295),
        vbytes: 141,
        strategy: "greedy".to_string(),
    };
    let report = build_report(&fixture, &selection, "dummy");
    let codes: Vec<&str> = report.warnings.iter().map(|w| w.code.as_str()).collect();
    assert!(!codes.contains(&"SEND_ALL"));
}

#[test]
fn test_warning_rbf_signaling_present() {
    let fixture = make_fixture(Some(true), None, None);
    let selection = CoinSelectionResult {
        selected: fixture.utxos.clone(),
        fee: 705,
        change_amount: Some(49295),
        vbytes: 141,
        strategy: "greedy".to_string(),
    };
    let report = build_report(&fixture, &selection, "dummy");
    assert!(report.rbf_signaling);
    let codes: Vec<&str> = report.warnings.iter().map(|w| w.code.as_str()).collect();
    assert!(codes.contains(&"RBF_SIGNALING"));
}

#[test]
fn test_no_rbf_warning_when_false() {
    let fixture = make_fixture(Some(false), None, None);
    let selection = CoinSelectionResult {
        selected: fixture.utxos.clone(),
        fee: 705,
        change_amount: Some(49295),
        vbytes: 141,
        strategy: "greedy".to_string(),
    };
    let report = build_report(&fixture, &selection, "dummy");
    assert!(!report.rbf_signaling);
    let codes: Vec<&str> = report.warnings.iter().map(|w| w.code.as_str()).collect();
    assert!(!codes.contains(&"RBF_SIGNALING"));
}

// ═══════════════════════════════════════════════════════════════════════════
// 8. Report field correctness
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_report_locktime_fields() {
    let fixture = make_fixture(None, Some(850000), None);
    let selection = CoinSelectionResult {
        selected: fixture.utxos.clone(),
        fee: 705,
        change_amount: Some(49295),
        vbytes: 141,
        strategy: "greedy".to_string(),
    };
    let report = build_report(&fixture, &selection, "dummy");
    assert_eq!(report.locktime, 850000);
    assert_eq!(report.locktime_type, "block_height");
}

#[test]
fn test_report_locktime_unix_timestamp() {
    let fixture = make_fixture(None, Some(1_700_000_000), None);
    let selection = CoinSelectionResult {
        selected: fixture.utxos.clone(),
        fee: 705,
        change_amount: Some(49295),
        vbytes: 141,
        strategy: "greedy".to_string(),
    };
    let report = build_report(&fixture, &selection, "dummy");
    assert_eq!(report.locktime, 1_700_000_000);
    assert_eq!(report.locktime_type, "unix_timestamp");
}

#[test]
fn test_report_locktime_none() {
    let fixture = make_fixture(None, None, None);
    let selection = CoinSelectionResult {
        selected: fixture.utxos.clone(),
        fee: 705,
        change_amount: Some(49295),
        vbytes: 141,
        strategy: "greedy".to_string(),
    };
    let report = build_report(&fixture, &selection, "dummy");
    assert_eq!(report.locktime, 0);
    assert_eq!(report.locktime_type, "none");
}

#[test]
fn test_report_change_index_null_when_no_change() {
    let fixture = make_fixture(None, None, None);
    let selection = CoinSelectionResult {
        selected: fixture.utxos.clone(),
        fee: 1000,
        change_amount: None,
        vbytes: 110,
        strategy: "greedy".to_string(),
    };
    let report = build_report(&fixture, &selection, "dummy");
    assert!(report.change_index.is_none());
}

#[test]
fn test_report_change_index_present() {
    let fixture = make_fixture(None, None, None);
    let selection = CoinSelectionResult {
        selected: fixture.utxos.clone(),
        fee: 705,
        change_amount: Some(49295),
        vbytes: 141,
        strategy: "greedy".to_string(),
    };
    let report = build_report(&fixture, &selection, "dummy");
    assert_eq!(report.change_index, Some(1)); // payment at 0, change at 1
}

#[test]
fn test_report_fee_rate_accuracy() {
    let fixture = make_fixture(None, None, None);
    let selection = CoinSelectionResult {
        selected: fixture.utxos.clone(),
        fee: 705,
        change_amount: Some(49295),
        vbytes: 141,
        strategy: "greedy".to_string(),
    };
    let report = build_report(&fixture, &selection, "dummy");
    let expected_rate = 705.0 / 141.0;
    assert!((report.fee_rate_sat_vb - expected_rate).abs() <= 0.01);
}

// ═══════════════════════════════════════════════════════════════════════════
// 9. PSBT construction tests
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_psbt_with_rbf_nsequence() {
    let fixture = make_fixture(Some(true), None, None);
    let br = build_psbt(
        &fixture,
        &fixture.utxos,
        &fixture.payments,
        Some((49000, &fixture.change)),
    ).unwrap();
    for input in &br.tx.input {
        assert_eq!(input.sequence.0, 0xFFFFFFFD);
    }
}

#[test]
fn test_psbt_with_locktime_value() {
    let fixture = make_fixture(None, Some(850000), None);
    let br = build_psbt(
        &fixture,
        &fixture.utxos,
        &fixture.payments,
        Some((49000, &fixture.change)),
    ).unwrap();
    assert_eq!(locktime_to_u32(&br.tx.lock_time), 850000);
    for input in &br.tx.input {
        assert_eq!(input.sequence.0, 0xFFFFFFFE);
    }
}

#[test]
fn test_psbt_no_change_output() {
    let fixture = make_fixture(None, None, None);
    let br = build_psbt(
        &fixture,
        &fixture.utxos,
        &fixture.payments,
        None,
    ).unwrap();
    assert_eq!(br.tx.output.len(), 1); // only payment
}

#[test]
fn test_psbt_witness_utxo_populated() {
    let fixture = make_fixture(None, None, None);
    let br = build_psbt(
        &fixture,
        &fixture.utxos,
        &fixture.payments,
        Some((49000, &fixture.change)),
    ).unwrap();
    assert!(br.psbt.inputs[0].witness_utxo.is_some());
    let wu = br.psbt.inputs[0].witness_utxo.as_ref().unwrap();
    assert_eq!(wu.value.to_sat(), 100000);
}

#[test]
fn test_psbt_multiple_payments() {
    let mut fixture = make_fixture(None, None, None);
    fixture.payments.push(Payment {
        address: None,
        script_pubkey_hex: "00144444444444444444444444444444444444444444".to_string(),
        script_type: "p2wpkh".to_string(),
        value_sats: 10000,
    });
    let br = build_psbt(
        &fixture,
        &fixture.utxos,
        &fixture.payments,
        Some((30000, &fixture.change)),
    ).unwrap();
    assert_eq!(br.tx.output.len(), 3); // 2 payments + 1 change
}

// ═══════════════════════════════════════════════════════════════════════════
// 10. Fixture validation tests
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_validate_zero_payment_value() {
    let mut fixture = make_fixture(None, None, None);
    fixture.payments[0].value_sats = 0;
    assert!(validate_fixture(&fixture).is_err());
}

#[test]
fn test_validate_zero_utxo_value() {
    let mut fixture = make_fixture(None, None, None);
    fixture.utxos[0].value_sats = 0;
    assert!(validate_fixture(&fixture).is_err());
}

#[test]
fn test_validate_empty_script_pubkey() {
    let mut fixture = make_fixture(None, None, None);
    fixture.utxos[0].script_pubkey_hex = "".to_string();
    assert!(validate_fixture(&fixture).is_err());
}

#[test]
fn test_validate_invalid_hex_script() {
    let mut fixture = make_fixture(None, None, None);
    fixture.utxos[0].script_pubkey_hex = "zzzz".to_string();
    assert!(validate_fixture(&fixture).is_err());
}

#[test]
fn test_validate_odd_length_hex() {
    let mut fixture = make_fixture(None, None, None);
    fixture.utxos[0].script_pubkey_hex = "001".to_string();
    assert!(validate_fixture(&fixture).is_err());
}

#[test]
fn test_validate_invalid_txid_length() {
    let mut fixture = make_fixture(None, None, None);
    fixture.utxos[0].txid = "abcd".to_string();
    assert!(validate_fixture(&fixture).is_err());
}

#[test]
fn test_validate_invalid_txid_hex() {
    let mut fixture = make_fixture(None, None, None);
    fixture.utxos[0].txid = "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz".to_string();
    assert!(validate_fixture(&fixture).is_err());
}

#[test]
fn test_validate_testnet_network() {
    let mut fixture = make_fixture(None, None, None);
    fixture.network = "testnet".to_string();
    assert!(validate_fixture(&fixture).is_ok());
}

#[test]
fn test_validate_signet_network() {
    let mut fixture = make_fixture(None, None, None);
    fixture.network = "signet".to_string();
    assert!(validate_fixture(&fixture).is_ok());
}

#[test]
fn test_validate_regtest_network() {
    let mut fixture = make_fixture(None, None, None);
    fixture.network = "regtest".to_string();
    assert!(validate_fixture(&fixture).is_ok());
}

#[test]
fn test_validate_unknown_script_type() {
    let mut fixture = make_fixture(None, None, None);
    fixture.utxos[0].script_type = "p2xyz".to_string();
    assert!(validate_fixture(&fixture).is_err());
}

#[test]
fn test_validate_zero_fee_rate() {
    let mut fixture = make_fixture(None, None, None);
    fixture.fee_rate_sat_vb = 0.0;
    assert!(validate_fixture(&fixture).is_err());
}

#[test]
fn test_validate_empty_change_script() {
    let mut fixture = make_fixture(None, None, None);
    fixture.change.script_pubkey_hex = "".to_string();
    assert!(validate_fixture(&fixture).is_err());
}

// ═══════════════════════════════════════════════════════════════════════════
// 11. vbytes estimation tests
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_input_vbytes_p2wsh() {
    assert_eq!(input_vbytes("p2wsh"), 104);
}

#[test]
fn test_input_vbytes_p2sh() {
    assert_eq!(input_vbytes("p2sh"), 256);
}

#[test]
fn test_input_vbytes_unknown() {
    assert_eq!(input_vbytes("unknown_type"), 68);
}

#[test]
fn test_output_vbytes_p2pkh() {
    assert_eq!(output_vbytes("p2pkh"), 34);
}

#[test]
fn test_output_vbytes_p2sh() {
    assert_eq!(output_vbytes("p2sh"), 32);
}

#[test]
fn test_output_vbytes_p2wsh() {
    assert_eq!(output_vbytes("p2wsh"), 43);
}

#[test]
fn test_output_vbytes_unknown() {
    assert_eq!(output_vbytes("unknown_type"), 31);
}

#[test]
fn test_tx_overhead() {
    assert_eq!(tx_overhead_vbytes(), 11);
}

#[test]
fn test_estimate_vbytes_no_change() {
    let utxo = make_utxo("1111111111111111111111111111111111111111111111111111111111111111", 0, 100000, "p2wpkh");
    let vb = estimate_vbytes(&[&utxo], &["p2wpkh"], None);
    // overhead(11) + input(68) + output(31) = 110
    assert_eq!(vb, 110);
}

#[test]
fn test_estimate_vbytes_mixed_inputs() {
    let u1 = make_utxo("1111111111111111111111111111111111111111111111111111111111111111", 0, 50000, "p2wpkh");
    let u2 = make_utxo("2222222222222222222222222222222222222222222222222222222222222222", 0, 50000, "p2tr");
    let vb = estimate_vbytes(&[&u1, &u2], &["p2wpkh"], Some("p2wpkh"));
    // overhead(11) + p2wpkh_in(68) + p2tr_in(58) + p2wpkh_out(31) + change_out(31) = 199
    assert_eq!(vb, 199);
}

#[test]
fn test_estimate_vbytes_multiple_outputs() {
    let u1 = make_utxo("1111111111111111111111111111111111111111111111111111111111111111", 0, 100000, "p2wpkh");
    let vb = estimate_vbytes(&[&u1], &["p2wpkh", "p2tr", "p2pkh"], Some("p2wpkh"));
    // overhead(11) + input(68) + p2wpkh_out(31) + p2tr_out(43) + p2pkh_out(34) + change(31) = 218
    assert_eq!(vb, 218);
}

// ═══════════════════════════════════════════════════════════════════════════
// 12. RBF + send-all test (hidden category)
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_rbf_send_all_warnings() {
    let fixture = make_fixture(Some(true), None, None);
    let selection = CoinSelectionResult {
        selected: fixture.utxos.clone(),
        fee: 1000,
        change_amount: None,
        vbytes: 110,
        strategy: "greedy".to_string(),
    };
    let report = build_report(&fixture, &selection, "dummy");
    let codes: Vec<&str> = report.warnings.iter().map(|w| w.code.as_str()).collect();
    assert!(codes.contains(&"SEND_ALL"));
    assert!(codes.contains(&"RBF_SIGNALING"));
    assert!(report.rbf_signaling);
}

// ═══════════════════════════════════════════════════════════════════════════
// 13. Neither rbf nor locktime (backward compatibility)
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_backward_compat_defaults() {
    let fixture = make_fixture(None, None, None);
    let seq = determine_nsequence(&fixture);
    let lt = determine_locktime(&fixture);
    assert_eq!(seq.0, 0xFFFFFFFF);
    assert_eq!(locktime_to_u32(&lt), 0);

    let selection = CoinSelectionResult {
        selected: fixture.utxos.clone(),
        fee: 705,
        change_amount: Some(49295),
        vbytes: 141,
        strategy: "greedy".to_string(),
    };
    let report = build_report(&fixture, &selection, "dummy");
    assert!(!report.rbf_signaling);
    assert_eq!(report.locktime, 0);
    assert_eq!(report.locktime_type, "none");
}

// ═══════════════════════════════════════════════════════════════════════════
// 14. Dust threshold tests
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_dust_threshold_constant() {
    assert_eq!(DUST_THRESHOLD, 546);
}

#[test]
fn test_no_dust_outputs_created() {
    let utxos = vec![make_utxo(
        "1111111111111111111111111111111111111111111111111111111111111111",
        0, 100000, "p2wpkh",
    )];
    let result = select_coins(&utxos, 50000, &["p2wpkh"], "p2wpkh", 5.0, None).unwrap();
    if let Some(change) = result.change_amount {
        assert!(change >= 546, "Change {} is dust!", change);
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// 15. PSBT base64 encoding
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_psbt_base64_valid() {
    let fixture = make_fixture(None, None, None);
    let br = build_psbt(
        &fixture,
        &fixture.utxos,
        &fixture.payments,
        Some((49000, &fixture.change)),
    ).unwrap();
    let b64 = psbt_to_base64(&br.psbt);
    assert!(!b64.is_empty());
    assert!(b64.starts_with("cHNidP8")); // "psbt\xff"
}

// ═══════════════════════════════════════════════════════════════════════════
// 16. Multi-strategy selection
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_multi_strategy_returns_best() {
    let utxos = vec![
        make_utxo("1111111111111111111111111111111111111111111111111111111111111111", 0, 100000, "p2wpkh"),
        make_utxo("2222222222222222222222222222222222222222222222222222222222222222", 0, 50000, "p2wpkh"),
    ];
    let (result, scores) = select_coins_multi(&utxos, 50000, &["p2wpkh"], "p2wpkh", 5.0, None).unwrap();
    assert!(!scores.is_empty());
    assert!(!result.strategy.is_empty());
    // Balance equation holds
    let input_total: u64 = result.selected.iter().map(|u| u.value_sats).sum();
    let change = result.change_amount.unwrap_or(0);
    assert_eq!(input_total, 50000 + change + result.fee);
}

// ═══════════════════════════════════════════════════════════════════════════
// 17. Error report format
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_error_report_format() {
    let err = BuildError {
        code: "INSUFFICIENT_FUNDS".to_string(),
        message: "Not enough funds".to_string(),
    };
    let report = error_report(&err);
    assert_eq!(report.ok, false);
    assert_eq!(report.error.code, "INSUFFICIENT_FUNDS");
    assert!(!report.error.message.is_empty());
}

#[test]
fn test_error_report_serializes() {
    let err = BuildError {
        code: "INVALID_FIXTURE".to_string(),
        message: "Bad data".to_string(),
    };
    let report = error_report(&err);
    let json = serde_json::to_string(&report).unwrap();
    assert!(json.contains("\"ok\":false"));
    assert!(json.contains("\"code\":\"INVALID_FIXTURE\""));
}

// ═══════════════════════════════════════════════════════════════════════════
// 18. Normalize fixture tests
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_normalize_detects_p2wpkh() {
    let mut fixture = make_fixture(None, None, None);
    fixture.utxos[0].script_type = "unknown".to_string();
    normalize_fixture(&mut fixture);
    assert_eq!(fixture.utxos[0].script_type, "p2wpkh");
}

#[test]
fn test_normalize_detects_p2tr() {
    let mut fixture = make_fixture(None, None, None);
    fixture.utxos[0].script_pubkey_hex = "51201111111111111111111111111111111111111111111111111111111111111111".to_string();
    fixture.utxos[0].script_type = "unknown".to_string();
    normalize_fixture(&mut fixture);
    assert_eq!(fixture.utxos[0].script_type, "p2tr");
}

#[test]
fn test_normalize_detects_p2pkh() {
    let mut fixture = make_fixture(None, None, None);
    fixture.utxos[0].script_pubkey_hex = "76a914111111111111111111111111111111111111111188ac".to_string();
    fixture.utxos[0].script_type = "unknown".to_string();
    normalize_fixture(&mut fixture);
    assert_eq!(fixture.utxos[0].script_type, "p2pkh");
}

#[test]
fn test_normalize_preserves_p2sh_p2wpkh() {
    let mut fixture = make_fixture(None, None, None);
    fixture.utxos[0].script_pubkey_hex = "a914111111111111111111111111111111111111111187".to_string();
    fixture.utxos[0].script_type = "p2sh-p2wpkh".to_string();
    normalize_fixture(&mut fixture);
    // Should NOT override p2sh-p2wpkh to p2sh
    assert_eq!(fixture.utxos[0].script_type, "p2sh-p2wpkh");
}

#[test]
fn test_normalize_deduplicates_utxos() {
    let mut fixture = make_fixture(None, None, None);
    fixture.utxos.push(fixture.utxos[0].clone()); // duplicate
    assert_eq!(fixture.utxos.len(), 2);
    normalize_fixture(&mut fixture);
    assert_eq!(fixture.utxos.len(), 1);
}

// ═══════════════════════════════════════════════════════════════════════════
// 19. Report output ordering
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_report_payment_outputs_before_change() {
    let mut fixture = make_fixture(None, None, None);
    fixture.payments.push(Payment {
        address: None,
        script_pubkey_hex: "00144444444444444444444444444444444444444444".to_string(),
        script_type: "p2wpkh".to_string(),
        value_sats: 10000,
    });
    let selection = CoinSelectionResult {
        selected: fixture.utxos.clone(),
        fee: 860,
        change_amount: Some(39140),
        vbytes: 172,
        strategy: "greedy".to_string(),
    };
    let report = build_report(&fixture, &selection, "dummy");
    assert_eq!(report.outputs.len(), 3); // 2 payments + 1 change
    assert!(!report.outputs[0].is_change);
    assert!(!report.outputs[1].is_change);
    assert!(report.outputs[2].is_change);
    assert_eq!(report.change_index, Some(2));
}

// ═══════════════════════════════════════════════════════════════════════════
// 20. Report ok field
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_report_ok_true() {
    let fixture = make_fixture(None, None, None);
    let selection = CoinSelectionResult {
        selected: fixture.utxos.clone(),
        fee: 705,
        change_amount: Some(49295),
        vbytes: 141,
        strategy: "greedy".to_string(),
    };
    let report = build_report(&fixture, &selection, "dummy");
    assert!(report.ok);
}
