use coin_smith::builder::*;
use coin_smith::coin_selection::*;
use coin_smith::fixture::*;
use coin_smith::report::*;

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

// ── Input vbytes estimation ─────────────────────────────────────────────

#[test]
fn test_input_vbytes_p2wpkh() {
    assert_eq!(input_vbytes("p2wpkh"), 68);
}

#[test]
fn test_input_vbytes_p2tr() {
    assert_eq!(input_vbytes("p2tr"), 58);
}

#[test]
fn test_input_vbytes_p2pkh() {
    assert_eq!(input_vbytes("p2pkh"), 148);
}

#[test]
fn test_input_vbytes_p2sh_p2wpkh() {
    assert_eq!(input_vbytes("p2sh-p2wpkh"), 91);
}

#[test]
fn test_output_vbytes_p2wpkh() {
    assert_eq!(output_vbytes("p2wpkh"), 31);
}

#[test]
fn test_output_vbytes_p2tr() {
    assert_eq!(output_vbytes("p2tr"), 43);
}

// ── Coin selection ──────────────────────────────────────────────────────

#[test]
fn test_select_single_utxo_with_change() {
    let utxos = vec![make_utxo(
        "1111111111111111111111111111111111111111111111111111111111111111",
        0, 100000, "p2wpkh",
    )];
    let result = select_coins(&utxos, 50000, &["p2wpkh"], "p2wpkh", 5.0, None).unwrap();
    assert_eq!(result.selected.len(), 1);
    assert!(result.change_amount.is_some());
    let change = result.change_amount.unwrap();
    assert!(change >= 546); // not dust
    assert_eq!(result.selected[0].value_sats, result.fee + 50000 + change);
}

#[test]
fn test_select_send_all_dust_change() {
    // 10000 sats input, 9500 sats payment => leftover ~500 < 546 dust
    let utxos = vec![make_utxo(
        "1111111111111111111111111111111111111111111111111111111111111111",
        0, 10000, "p2wpkh",
    )];
    let result = select_coins(&utxos, 9500, &["p2wpkh"], "p2wpkh", 1.0, None).unwrap();
    assert!(result.change_amount.is_none()); // send-all
    assert_eq!(result.fee, 500);
}

#[test]
fn test_select_insufficient_funds() {
    let utxos = vec![make_utxo(
        "1111111111111111111111111111111111111111111111111111111111111111",
        0, 1000, "p2wpkh",
    )];
    let result = select_coins(&utxos, 50000, &["p2wpkh"], "p2wpkh", 5.0, None);
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().code, "INSUFFICIENT_FUNDS");
}

#[test]
fn test_select_respects_max_inputs() {
    let utxos: Vec<Utxo> = (0..10)
        .map(|i| {
            let txid = format!("{:064x}", i + 1);
            make_utxo(&txid, 0, 5000, "p2wpkh")
        })
        .collect();
    // Need ~30000, with max 3 inputs, each 5000 = 15000 total, insufficient
    let result = select_coins(&utxos, 30000, &["p2wpkh"], "p2wpkh", 1.0, Some(3));
    assert!(result.is_err());
}

#[test]
fn test_select_multiple_inputs() {
    let utxos = vec![
        make_utxo("1111111111111111111111111111111111111111111111111111111111111111", 0, 30000, "p2wpkh"),
        make_utxo("2222222222222222222222222222222222222222222222222222222222222222", 0, 30000, "p2wpkh"),
    ];
    let result = select_coins(&utxos, 50000, &["p2wpkh"], "p2wpkh", 1.0, None).unwrap();
    assert_eq!(result.selected.len(), 2);
}

// ── Fee calculation ─────────────────────────────────────────────────────

#[test]
fn test_fee_meets_target() {
    let utxos = vec![make_utxo(
        "1111111111111111111111111111111111111111111111111111111111111111",
        0, 100000, "p2wpkh",
    )];
    let result = select_coins(&utxos, 50000, &["p2wpkh"], "p2wpkh", 10.0, None).unwrap();
    let min_fee = (10.0 * result.vbytes as f64).ceil() as u64;
    assert!(result.fee >= min_fee);
}

#[test]
fn test_estimate_vbytes_single_p2wpkh() {
    let utxo = make_utxo("1111111111111111111111111111111111111111111111111111111111111111", 0, 100000, "p2wpkh");
    let vb = estimate_vbytes(&[&utxo], &["p2wpkh"], Some("p2wpkh"));
    // overhead(11) + input(68) + output(31) + change(31) = 141
    assert_eq!(vb, 141);
}

// ── RBF/Locktime ────────────────────────────────────────────────────────

#[test]
fn test_nsequence_no_rbf_no_locktime() {
    let fixture = make_fixture(None, None, None);
    let seq = determine_nsequence(&fixture);
    assert_eq!(seq.0, 0xFFFFFFFF);
}

#[test]
fn test_nsequence_rbf_true() {
    let fixture = make_fixture(Some(true), None, None);
    let seq = determine_nsequence(&fixture);
    assert_eq!(seq.0, 0xFFFFFFFD);
}

#[test]
fn test_nsequence_locktime_no_rbf() {
    let fixture = make_fixture(None, Some(850000), None);
    let seq = determine_nsequence(&fixture);
    assert_eq!(seq.0, 0xFFFFFFFE);
}

#[test]
fn test_nsequence_rbf_with_locktime() {
    let fixture = make_fixture(Some(true), Some(850000), None);
    let seq = determine_nsequence(&fixture);
    assert_eq!(seq.0, 0xFFFFFFFD);
}

#[test]
fn test_locktime_explicit() {
    let fixture = make_fixture(None, Some(850000), None);
    let lt = determine_locktime(&fixture);
    assert_eq!(locktime_to_u32(&lt), 850000);
}

#[test]
fn test_locktime_anti_fee_sniping() {
    let fixture = make_fixture(Some(true), None, Some(860000));
    let lt = determine_locktime(&fixture);
    assert_eq!(locktime_to_u32(&lt), 860000);
}

#[test]
fn test_locktime_none() {
    let fixture = make_fixture(None, None, None);
    let lt = determine_locktime(&fixture);
    assert_eq!(locktime_to_u32(&lt), 0);
}

#[test]
fn test_locktime_type_none() {
    assert_eq!(locktime_type_str(0), "none");
}

#[test]
fn test_locktime_type_block_height() {
    assert_eq!(locktime_type_str(850000), "block_height");
}

#[test]
fn test_locktime_type_unix_timestamp() {
    assert_eq!(locktime_type_str(1700000000), "unix_timestamp");
}

#[test]
fn test_locktime_boundary_499999999() {
    assert_eq!(locktime_type_str(499999999), "block_height");
}

#[test]
fn test_locktime_boundary_500000000() {
    assert_eq!(locktime_type_str(500000000), "unix_timestamp");
}

// ── PSBT construction ───────────────────────────────────────────────────

#[test]
fn test_build_psbt_basic() {
    let fixture = make_fixture(None, None, None);
    let result = build_psbt(
        &fixture,
        &fixture.utxos,
        &fixture.payments,
        Some((49000, &fixture.change)),
    );
    assert!(result.is_ok());
    let br = result.unwrap();
    assert_eq!(br.tx.input.len(), 1);
    assert_eq!(br.tx.output.len(), 2);
    assert!(br.psbt.inputs[0].witness_utxo.is_some());
}

#[test]
fn test_psbt_base64_starts_with_magic() {
    let fixture = make_fixture(None, None, None);
    let br = build_psbt(
        &fixture,
        &fixture.utxos,
        &fixture.payments,
        Some((49000, &fixture.change)),
    ).unwrap();
    let b64 = psbt_to_base64(&br.psbt);
    assert!(b64.starts_with("cHNidP8")); // "psbt\xff" in base64
}

// ── Fixture validation ──────────────────────────────────────────────────

#[test]
fn test_validate_empty_utxos() {
    let mut fixture = make_fixture(None, None, None);
    fixture.utxos.clear();
    let result = validate_fixture(&fixture);
    assert!(result.is_err());
}

#[test]
fn test_validate_empty_payments() {
    let mut fixture = make_fixture(None, None, None);
    fixture.payments.clear();
    let result = validate_fixture(&fixture);
    assert!(result.is_err());
}

#[test]
fn test_validate_bad_fee_rate() {
    let mut fixture = make_fixture(None, None, None);
    fixture.fee_rate_sat_vb = -1.0;
    let result = validate_fixture(&fixture);
    assert!(result.is_err());
}

#[test]
fn test_validate_invalid_network() {
    let mut fixture = make_fixture(None, None, None);
    fixture.network = "foonet".to_string();
    let result = validate_fixture(&fixture);
    assert!(result.is_err());
}

// ── Report generation ───────────────────────────────────────────────────

#[test]
fn test_report_warnings_send_all() {
    let fixture = make_fixture(None, None, None);
    let selection = CoinSelectionResult {
        selected: fixture.utxos.clone(),
        fee: 1000,
        change_amount: None,
        vbytes: 110,
        strategy: "greedy".to_string(),
    };
    let report = build_report(&fixture, &selection, "dummybase64");
    let codes: Vec<&str> = report.warnings.iter().map(|w| w.code.as_str()).collect();
    assert!(codes.contains(&"SEND_ALL"));
}

#[test]
fn test_report_warnings_rbf() {
    let fixture = make_fixture(Some(true), None, None);
    let selection = CoinSelectionResult {
        selected: fixture.utxos.clone(),
        fee: 705,
        change_amount: Some(49295),
        vbytes: 141,
        strategy: "greedy".to_string(),
    };
    let report = build_report(&fixture, &selection, "dummybase64");
    let codes: Vec<&str> = report.warnings.iter().map(|w| w.code.as_str()).collect();
    assert!(codes.contains(&"RBF_SIGNALING"));
    assert!(report.rbf_signaling);
}

#[test]
fn test_report_warnings_high_fee() {
    let fixture = make_fixture(None, None, None);
    let selection = CoinSelectionResult {
        selected: fixture.utxos.clone(),
        fee: 2_000_000,
        change_amount: None,
        vbytes: 110,
        strategy: "greedy".to_string(),
    };
    let report = build_report(&fixture, &selection, "dummybase64");
    let codes: Vec<&str> = report.warnings.iter().map(|w| w.code.as_str()).collect();
    assert!(codes.contains(&"HIGH_FEE"));
}

#[test]
fn test_report_balance_equation() {
    let _fixture = make_fixture(None, None, None);
    let utxos = vec![make_utxo(
        "1111111111111111111111111111111111111111111111111111111111111111",
        0, 100000, "p2wpkh",
    )];
    let selection = select_coins(&utxos, 50000, &["p2wpkh"], "p2wpkh", 5.0, None).unwrap();
    let input_total: u64 = selection.selected.iter().map(|u| u.value_sats).sum();
    let change = selection.change_amount.unwrap_or(0);
    assert_eq!(input_total, 50000 + change + selection.fee);
}
