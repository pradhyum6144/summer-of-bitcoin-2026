use std::fs;
use std::path::PathBuf;
use std::process;

use coin_smith::builder::{build_psbt, psbt_to_base64};
use coin_smith::coin_selection::select_coins_multi;
use coin_smith::fixture::{normalize_fixture, validate_fixture, BuildError, Fixture};
use coin_smith::report::{build_report_full, error_report};
use coin_smith::signer::sign_psbt_with_test_keys;

fn run(fixture_path: &str, output_path: &str) -> Result<(), BuildError> {
    let content = fs::read_to_string(fixture_path).map_err(|e| BuildError {
        code: "FILE_ERROR".to_string(),
        message: format!("Cannot read fixture file: {}", e),
    })?;

    let mut fixture: Fixture = serde_json::from_str(&content).map_err(|e| BuildError {
        code: "INVALID_FIXTURE".to_string(),
        message: format!("Cannot parse fixture JSON: {}", e),
    })?;

    validate_fixture(&fixture)?;
    normalize_fixture(&mut fixture);

    let payment_total: u64 = fixture.payments.iter().map(|p| p.value_sats).sum();
    let payment_script_types: Vec<&str> =
        fixture.payments.iter().map(|p| p.script_type.as_str()).collect();
    let max_inputs = fixture.policy.as_ref().and_then(|p| p.max_inputs);

    let (selection, scores) = select_coins_multi(
        &fixture.utxos,
        payment_total,
        &payment_script_types,
        &fixture.change.script_type,
        fixture.fee_rate_sat_vb,
        max_inputs,
    )?;

    let change_param = selection.change_amount.map(|amt| (amt, &fixture.change));
    let build_result = build_psbt(&fixture, &selection.selected, &fixture.payments, change_param)?;
    let psbt_b64 = psbt_to_base64(&build_result.psbt);

    // Sign PSBT with test keys
    let input_script_types: Vec<String> = selection.selected.iter().map(|u| u.script_type.clone()).collect();
    let mut psbt_for_signing = build_result.psbt.clone();
    let signing_result = sign_psbt_with_test_keys(&mut psbt_for_signing, &input_script_types).ok();

    let report = build_report_full(&fixture, &selection, &psbt_b64, Some(scores), signing_result);

    let json = serde_json::to_string_pretty(&report).map_err(|e| BuildError {
        code: "SERIALIZATION_ERROR".to_string(),
        message: format!("Cannot serialize report: {}", e),
    })?;

    fs::write(output_path, &json).map_err(|e| BuildError {
        code: "FILE_ERROR".to_string(),
        message: format!("Cannot write output file: {}", e),
    })?;

    Ok(())
}

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 3 {
        eprintln!("Usage: coin-smith <fixture.json> <output.json>");
        process::exit(1);
    }

    let fixture_path = &args[1];
    let output_path = &args[2];

    if let Some(parent) = PathBuf::from(output_path).parent() {
        let _ = fs::create_dir_all(parent);
    }

    match run(fixture_path, output_path) {
        Ok(()) => process::exit(0),
        Err(err) => {
            eprintln!("Error: {}", err);
            let error_json = serde_json::to_string_pretty(&error_report(&err)).unwrap_or_else(
                |_| {
                    r#"{"ok":false,"error":{"code":"UNKNOWN","message":"Serialization failed"}}"#
                        .to_string()
                },
            );
            let _ = fs::write(output_path, &error_json);
            process::exit(1);
        }
    }
}
