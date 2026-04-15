use crate::parser::{compute_txid, compute_wtxid, parse_transaction, Transaction};
use crate::script::{
    classify_input, classify_script, disassemble_script, encode_address, extract_op_return_data,
    input_script_type_to_string, script_type_to_string, InputScriptType, ScriptType,
};
use crate::types::*;
use anyhow::Result;
use std::collections::HashMap;

pub fn analyze_transaction(
    raw_tx_hex: &str,
    prevouts: &[Prevout],
    network: &str,
) -> Result<TransactionOutput> {
    let tx = match parse_transaction(raw_tx_hex) {
        Ok(tx) => tx,
        Err(e) => {
            return Ok(TransactionOutput {
                ok: false,
                error: Some(ErrorInfo {
                    code: "INVALID_TX".to_string(),
                    message: format!("Failed to parse transaction: {}", e),
                }),
                network: None,
                segwit: None,
                txid: None,
                wtxid: None,
                version: None,
                locktime: None,
                size_bytes: None,
                weight: None,
                vbytes: None,
                total_input_sats: None,
                total_output_sats: None,
                fee_sats: None,
                fee_rate_sat_vb: None,
                rbf_signaling: None,
                locktime_type: None,
                locktime_value: None,
                segwit_savings: None,
                vin: None,
                vout: None,
                warnings: None,
            });
        }
    };

    // Check for duplicate prevouts (normalize txid to lowercase for case-insensitive matching)
    let mut seen_prevout_keys = std::collections::HashSet::new();
    for p in prevouts {
        if !seen_prevout_keys.insert((p.txid.to_lowercase(), p.vout)) {
            return Ok(TransactionOutput {
                ok: false,
                error: Some(ErrorInfo {
                    code: "DUPLICATE_PREVOUT".to_string(),
                    message: format!("Duplicate prevout for {}:{}", p.txid, p.vout),
                }),
                network: None, segwit: None, txid: None, wtxid: None,
                version: None, locktime: None, size_bytes: None, weight: None,
                vbytes: None, total_input_sats: None, total_output_sats: None,
                fee_sats: None, fee_rate_sat_vb: None, rbf_signaling: None,
                locktime_type: None, locktime_value: None, segwit_savings: None,
                vin: None, vout: None, warnings: None,
            });
        }
    }

    // Build prevout lookup map (lowercase txid for case-insensitive matching)
    let mut prevout_map: HashMap<(String, u32), &Prevout> = HashMap::new();
    for prevout in prevouts {
        prevout_map.insert((prevout.txid.to_lowercase(), prevout.vout), prevout);
    }

    // Check for prevouts that don't correspond to any input outpoint
    // hex::encode always produces lowercase, so normalize fixture txids too
    let input_outpoints: std::collections::HashSet<(String, u32)> = tx
        .inputs
        .iter()
        .map(|i| (hex::encode(&i.prev_txid), i.prev_vout))
        .collect();
    for p in prevouts {
        if !input_outpoints.contains(&(p.txid.to_lowercase(), p.vout)) {
            return Ok(TransactionOutput {
                ok: false,
                error: Some(ErrorInfo {
                    code: "INVALID_PREVOUT".to_string(),
                    message: format!(
                        "Prevout {}:{} does not correspond to any input",
                        p.txid, p.vout
                    ),
                }),
                network: None, segwit: None, txid: None, wtxid: None,
                version: None, locktime: None, size_bytes: None, weight: None,
                vbytes: None, total_input_sats: None, total_output_sats: None,
                fee_sats: None, fee_rate_sat_vb: None, rbf_signaling: None,
                locktime_type: None, locktime_value: None, segwit_savings: None,
                vin: None, vout: None, warnings: None,
            });
        }
    }

    // Verify all inputs have prevouts
    for input in &tx.inputs {
        let txid = hex::encode(&input.prev_txid);
        if !prevout_map.contains_key(&(txid.clone(), input.prev_vout)) {
            return Ok(TransactionOutput {
                ok: false,
                error: Some(ErrorInfo {
                    code: "MISSING_PREVOUT".to_string(),
                    message: format!("Missing prevout for input {}:{}", txid, input.prev_vout),
                }),
                network: None, segwit: None, txid: None, wtxid: None,
                version: None, locktime: None, size_bytes: None, weight: None,
                vbytes: None, total_input_sats: None, total_output_sats: None,
                fee_sats: None, fee_rate_sat_vb: None, rbf_signaling: None,
                locktime_type: None, locktime_value: None, segwit_savings: None,
                vin: None, vout: None, warnings: None,
            });
        }
    }

    let txid = compute_txid(&tx);
    let wtxid = compute_wtxid(&tx);

    // Analyze inputs
    let mut vin = Vec::new();
    let mut total_input_sats = 0u64;

    for input in &tx.inputs {
        let txid_hex = hex::encode(&input.prev_txid);
        let prevout = prevout_map.get(&(txid_hex.clone(), input.prev_vout)).unwrap();

        let prevout_script = hex::decode(&prevout.script_pubkey_hex)?;

        let script_type = classify_input(&input.script_sig, &input.witness, &prevout_script);
        let address = encode_address(&prevout_script, network);

        let script_asm = disassemble_script(&input.script_sig).unwrap_or_default();
        let witness: Vec<String> = input.witness.iter().map(|w| hex::encode(w)).collect();

        // Relative timelock analysis (BIP68)
        let relative_timelock = analyze_relative_timelock(input.sequence);

        // Check if this is P2WSH or P2SH-P2WSH for witness script
        let witness_script_asm = if matches!(script_type, InputScriptType::P2WSH | InputScriptType::P2SHP2WSH) {
            if let Some(last_witness) = input.witness.last() {
                disassemble_script(last_witness).ok()
            } else {
                None
            }
        } else {
            None
        };

        vin.push(TxInput {
            txid: txid_hex,
            vout: input.prev_vout,
            sequence: input.sequence,
            script_sig_hex: hex::encode(&input.script_sig),
            script_asm,
            witness,
            script_type: input_script_type_to_string(&script_type).to_string(),
            address,
            prevout: PrevoutInfo {
                value_sats: prevout.value_sats,
                script_pubkey_hex: prevout.script_pubkey_hex.clone(),
            },
            relative_timelock,
            witness_script_asm,
        });

        total_input_sats += prevout.value_sats;
    }

    // Analyze outputs
    let mut vout = Vec::new();
    let mut total_output_sats = 0u64;

    for (n, output) in tx.outputs.iter().enumerate() {
        let script_type = classify_script(&output.script_pubkey);
        let address = encode_address(&output.script_pubkey, network);
        let script_asm = disassemble_script(&output.script_pubkey).unwrap_or_default();

        let (op_return_data_hex, op_return_data_utf8, op_return_protocol) =
            if script_type == ScriptType::OpReturn {
                extract_op_return_data(&output.script_pubkey)
                    // utf8 is Option<String>; wrap in Some(...) so None → JSON null (not absent)
                    .map(|(_, hex, utf8, protocol)| (Some(hex), Some(utf8), Some(protocol)))
                    .unwrap_or((None, None, None))
            } else {
                (None, None, None)
            };

        vout.push(TxOutput {
            n: n as u32,
            value_sats: output.value,
            script_pubkey_hex: hex::encode(&output.script_pubkey),
            script_asm,
            script_type: script_type_to_string(&script_type).to_string(),
            address,
            op_return_data_hex,
            op_return_data_utf8,
            op_return_protocol,
        });

        total_output_sats += output.value;
    }

    // Calculate fees
    let fee_sats = total_input_sats.saturating_sub(total_output_sats);

    // Calculate size and weight
    let (size_bytes, weight, vbytes) = calculate_size_and_weight(&tx);
    let fee_rate_sat_vb = if vbytes > 0 {
        fee_sats as f64 / vbytes as f64
    } else {
        0.0
    };

    // RBF signaling (BIP125)
    let rbf_signaling = tx.inputs.iter().any(|i| i.sequence < 0xfffffffe);

    // Locktime analysis
    // Per Bitcoin consensus: locktime is only enforced when at least one input has sequence < 0xFFFFFFFF.
    // If ALL inputs have sequence == 0xFFFFFFFF, locktime is disabled ("hidden").
    let locktime_disabled = tx.inputs.iter().all(|i| i.sequence == 0xffffffff);
    let (locktime_type, locktime_value) = analyze_locktime(tx.locktime, locktime_disabled);

    // SegWit savings
    let segwit_savings = if tx.has_witness {
        Some(calculate_segwit_savings(&tx))
    } else {
        None
    };

    // Generate warnings
    let warnings = generate_warnings(fee_sats, fee_rate_sat_vb, &vout, rbf_signaling);

    Ok(TransactionOutput {
        ok: true,
        network: Some(network.to_string()),
        segwit: Some(tx.has_witness),
        txid: Some(txid),
        wtxid,
        version: Some(tx.version),
        locktime: Some(tx.locktime),
        size_bytes: Some(size_bytes),
        weight: Some(weight),
        vbytes: Some(vbytes),
        total_input_sats: Some(total_input_sats),
        total_output_sats: Some(total_output_sats),
        fee_sats: Some(fee_sats),
        fee_rate_sat_vb: Some(fee_rate_sat_vb),
        rbf_signaling: Some(rbf_signaling),
        locktime_type: Some(locktime_type),
        locktime_value: Some(locktime_value),
        segwit_savings,
        vin: Some(vin),
        vout: Some(vout),
        warnings: Some(warnings),
        error: None,
    })
}

fn analyze_relative_timelock(sequence: u32) -> RelativeTimelock {
    // BIP68: If bit 31 is set, disable flag is active
    if sequence & (1 << 31) != 0 {
        return RelativeTimelock::Disabled { enabled: false };
    }

    // BIP68: bit 22 determines type (0 = blocks, 1 = time)
    let is_time_based = sequence & (1 << 22) != 0;
    // Lower 16 bits contain the value
    let value = (sequence & 0xffff) as u32;

    if is_time_based {
        // Time-based: value * 512 seconds
        RelativeTimelock::Enabled {
            enabled: true,
            lock_type: "time".to_string(),
            value: value * 512,
        }
    } else {
        // Block-based
        RelativeTimelock::Enabled {
            enabled: true,
            lock_type: "blocks".to_string(),
            value,
        }
    }
}

fn analyze_locktime(locktime: u32, disabled: bool) -> (String, u32) {
    if locktime == 0 || disabled {
        ("none".to_string(), locktime)
    } else if locktime < 500_000_000 {
        ("block_height".to_string(), locktime)
    } else {
        ("unix_timestamp".to_string(), locktime)
    }
}

fn calculate_size_and_weight(tx: &Transaction) -> (usize, usize, usize) {
    let total_bytes = tx.raw_bytes.len();

    if !tx.has_witness {
        // Legacy transaction
        let weight = total_bytes * 4;
        let vbytes = total_bytes;
        return (total_bytes, weight, vbytes);
    }

    // Calculate non-witness size (base transaction without marker, flag, and witness data)
    let mut non_witness_size = 0;

    // Version (4 bytes)
    non_witness_size += 4;

    // Input count varint
    non_witness_size += varint_size(tx.inputs.len() as u64);

    // Inputs (without witness)
    for input in &tx.inputs {
        non_witness_size += 32; // prev txid
        non_witness_size += 4; // prev vout
        non_witness_size += varint_size(input.script_sig.len() as u64);
        non_witness_size += input.script_sig.len();
        non_witness_size += 4; // sequence
    }

    // Output count varint
    non_witness_size += varint_size(tx.outputs.len() as u64);

    // Outputs
    for output in &tx.outputs {
        non_witness_size += 8; // value
        non_witness_size += varint_size(output.script_pubkey.len() as u64);
        non_witness_size += output.script_pubkey.len();
    }

    // Locktime (4 bytes)
    non_witness_size += 4;

    // Calculate witness size (includes marker + flag bytes, counted at 1× per BIP141)
    let witness_size = total_bytes - non_witness_size;

    // Weight = base_size * 4 + witness_size (marker+flag counted at 1× discount rate)
    let weight = non_witness_size * 4 + witness_size;
    let vbytes = (weight + 3) / 4; // Round up

    (total_bytes, weight, vbytes)
}

fn calculate_segwit_savings(tx: &Transaction) -> SegwitSavings {
    let (total_bytes, weight_actual, _) = calculate_size_and_weight(tx);

    // Calculate witness bytes
    let mut witness_bytes = 2; // marker + flag
    for input in &tx.inputs {
        witness_bytes += varint_size(input.witness.len() as u64);
        for item in &input.witness {
            witness_bytes += varint_size(item.len() as u64);
            witness_bytes += item.len();
        }
    }

    let non_witness_bytes = total_bytes - witness_bytes;

    // Weight if this were a legacy transaction (all bytes * 4)
    let weight_if_legacy = total_bytes * 4;

    let savings_pct = if weight_if_legacy > 0 {
        ((weight_if_legacy - weight_actual) as f64 / weight_if_legacy as f64) * 100.0
    } else {
        0.0
    };

    SegwitSavings {
        witness_bytes,
        non_witness_bytes,
        total_bytes,
        weight_actual,
        weight_if_legacy,
        savings_pct: (savings_pct * 100.0).round() / 100.0, // Round to 2 decimals
    }
}

fn varint_size(n: u64) -> usize {
    if n < 0xfd {
        1
    } else if n <= 0xffff {
        3
    } else if n <= 0xffffffff {
        5
    } else {
        9
    }
}

fn generate_warnings(fee_sats: u64, fee_rate_sat_vb: f64, vout: &[TxOutput], rbf_signaling: bool) -> Vec<Warning> {
    let mut warnings = Vec::new();

    // HIGH_FEE
    if fee_sats > 1_000_000 || fee_rate_sat_vb > 200.0 {
        warnings.push(Warning {
            code: "HIGH_FEE".to_string(),
        });
    }

    // DUST_OUTPUT
    for output in vout {
        if output.script_type != "op_return" && output.value_sats < 546 {
            warnings.push(Warning {
                code: "DUST_OUTPUT".to_string(),
            });
            break;
        }
    }

    // UNKNOWN_OUTPUT_SCRIPT
    for output in vout {
        if output.script_type == "unknown" {
            warnings.push(Warning {
                code: "UNKNOWN_OUTPUT_SCRIPT".to_string(),
            });
            break;
        }
    }

    // RBF_SIGNALING
    if rbf_signaling {
        warnings.push(Warning {
            code: "RBF_SIGNALING".to_string(),
        });
    }

    warnings
}
