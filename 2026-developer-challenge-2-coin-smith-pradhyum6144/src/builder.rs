use bitcoin::absolute::LockTime;
use bitcoin::blockdata::script::ScriptBuf;
use bitcoin::blockdata::transaction::{OutPoint, TxIn, TxOut, Version};
use bitcoin::psbt::Psbt;
use bitcoin::transaction::Transaction;
use bitcoin::Sequence;
use bitcoin::Txid;

use crate::fixture::{BuildError, ChangeTemplate, Fixture, Payment, Utxo};

/// Determine nSequence value based on RBF and locktime settings
pub fn determine_nsequence(fixture: &Fixture) -> Sequence {
    let rbf = fixture.rbf.unwrap_or(false);
    let has_locktime = fixture.locktime.is_some() && fixture.locktime.unwrap() > 0;

    if rbf {
        // RBF signaling: 0xFFFFFFFD
        Sequence::ENABLE_RBF_NO_LOCKTIME
    } else if has_locktime {
        // Non-RBF with locktime: 0xFFFFFFFE
        Sequence::ENABLE_LOCKTIME_NO_RBF
    } else {
        // Final: 0xFFFFFFFF
        Sequence::MAX
    }
}

/// Determine nLockTime based on fixture fields
pub fn determine_locktime(fixture: &Fixture) -> LockTime {
    let rbf = fixture.rbf.unwrap_or(false);

    if let Some(lt) = fixture.locktime {
        if lt >= 500_000_000 {
            LockTime::from_time(lt).unwrap_or(LockTime::ZERO)
        } else if lt > 0 {
            LockTime::from_height(lt).unwrap_or(LockTime::ZERO)
        } else {
            LockTime::ZERO
        }
    } else if rbf {
        if let Some(ch) = fixture.current_height {
            // Anti-fee-sniping
            LockTime::from_height(ch).unwrap_or(LockTime::ZERO)
        } else {
            LockTime::ZERO
        }
    } else {
        LockTime::ZERO
    }
}

pub fn locktime_to_u32(lt: &LockTime) -> u32 {
    match lt {
        LockTime::Blocks(h) => h.to_consensus_u32(),
        LockTime::Seconds(s) => s.to_consensus_u32(),
    }
}

pub fn locktime_type_str(lt_val: u32) -> &'static str {
    if lt_val == 0 {
        "none"
    } else if lt_val < 500_000_000 {
        "block_height"
    } else {
        "unix_timestamp"
    }
}

fn parse_txid(txid_hex: &str) -> Result<Txid, BuildError> {
    txid_hex.parse::<Txid>().map_err(|e| BuildError {
        code: "INVALID_TXID".to_string(),
        message: format!("Invalid txid {}: {}", txid_hex, e),
    })
}

fn parse_script(hex_str: &str) -> Result<ScriptBuf, BuildError> {
    let bytes = hex_to_bytes(hex_str).map_err(|e| BuildError {
        code: "INVALID_SCRIPT".to_string(),
        message: format!("Invalid script hex {}: {}", hex_str, e),
    })?;
    Ok(ScriptBuf::from_bytes(bytes))
}

fn hex_to_bytes(s: &str) -> Result<Vec<u8>, String> {
    if s.len() % 2 != 0 {
        return Err("odd length".to_string());
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| e.to_string()))
        .collect()
}

pub struct BuildResult {
    pub psbt: Psbt,
    pub tx: Transaction,
}

pub fn build_psbt(
    fixture: &Fixture,
    selected_inputs: &[Utxo],
    payments: &[Payment],
    change: Option<(u64, &ChangeTemplate)>,
) -> Result<BuildResult, BuildError> {
    let sequence = determine_nsequence(fixture);
    let locktime = determine_locktime(fixture);

    // Build inputs
    let mut tx_inputs = Vec::new();
    for utxo in selected_inputs {
        let txid = parse_txid(&utxo.txid)?;
        let outpoint = OutPoint {
            txid,
            vout: utxo.vout,
        };
        tx_inputs.push(TxIn {
            previous_output: outpoint,
            script_sig: ScriptBuf::new(),
            sequence,
            witness: bitcoin::Witness::default(),
        });
    }

    // Build outputs
    let mut tx_outputs = Vec::new();

    // Payment outputs
    for payment in payments {
        let script = parse_script(&payment.script_pubkey_hex)?;
        tx_outputs.push(TxOut {
            value: bitcoin::Amount::from_sat(payment.value_sats),
            script_pubkey: script,
        });
    }

    // Change output
    if let Some((change_amount, change_template)) = change {
        let script = parse_script(&change_template.script_pubkey_hex)?;
        tx_outputs.push(TxOut {
            value: bitcoin::Amount::from_sat(change_amount),
            script_pubkey: script,
        });
    }

    let unsigned_tx = Transaction {
        version: Version::TWO,
        lock_time: locktime,
        input: tx_inputs,
        output: tx_outputs,
    };

    // Build PSBT
    let mut psbt = Psbt::from_unsigned_tx(unsigned_tx.clone()).map_err(|e| BuildError {
        code: "PSBT_ERROR".to_string(),
        message: format!("Failed to create PSBT: {}", e),
    })?;

    // Add witness_utxo for each input
    for (i, utxo) in selected_inputs.iter().enumerate() {
        let script = parse_script(&utxo.script_pubkey_hex)?;
        let witness_utxo = TxOut {
            value: bitcoin::Amount::from_sat(utxo.value_sats),
            script_pubkey: script.clone(),
        };

        if i < psbt.inputs.len() {
            psbt.inputs[i].witness_utxo = Some(witness_utxo);

            // For p2sh-p2wpkh, add redeem script
            if utxo.script_type == "p2sh-p2wpkh" {
                // The redeem script for p2sh-p2wpkh is: OP_0 <20-byte-pubkey-hash>
                // We extract the pubkey hash from the p2sh script
                // p2sh script_pubkey is: OP_HASH160 <20-byte-hash> OP_EQUAL
                // The actual witness program is embedded inside
                // We can't reconstruct it without extra info, but we provide witness_utxo
            }
        }
    }

    Ok(BuildResult {
        psbt,
        tx: unsigned_tx,
    })
}

pub fn psbt_to_base64(psbt: &Psbt) -> String {
    let serialized = psbt.serialize();
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(&serialized)
}
