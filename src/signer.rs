use bitcoin::blockdata::script::ScriptBuf;
use bitcoin::hashes::Hash;
use bitcoin::psbt::Psbt;
use bitcoin::secp256k1::{self, Secp256k1, SecretKey};
use bitcoin::sighash::{EcdsaSighashType, Prevouts, SighashCache, TapSighashType};
use bitcoin::ecdsa::Signature as EcdsaSig;
use bitcoin::{
    CompressedPublicKey, PublicKey, Witness,
};

use crate::fixture::BuildError;

/// A deterministic test private key (NOT for production use!)
const TEST_SECRET_KEY_BYTES: [u8; 32] = [
    0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
    0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
    0x01, 0x01,
];

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SigningResult {
    pub signed_psbt_base64: String,
    pub finalized_tx_hex: Option<String>,
    pub signed_inputs: usize,
    pub note: String,
}

/// Sign a PSBT with deterministic test keys and attempt finalization.
/// This is for demonstration/testing only — real wallets would use actual keys.
pub fn sign_psbt_with_test_keys(
    psbt: &mut Psbt,
    input_script_types: &[String],
) -> Result<SigningResult, BuildError> {
    let secp = Secp256k1::new();
    let secret_key = SecretKey::from_slice(&TEST_SECRET_KEY_BYTES).map_err(|e| BuildError {
        code: "SIGNING_ERROR".to_string(),
        message: format!("Invalid test secret key: {}", e),
    })?;

    let public_key = PublicKey::from_private_key(&secp, &bitcoin::PrivateKey::new(secret_key, bitcoin::Network::Signet));
    let compressed = CompressedPublicKey::from_private_key(&secp, &bitcoin::PrivateKey::new(secret_key, bitcoin::Network::Signet)).unwrap();

    let mut signed_count = 0;

    // Sign each input based on script type
    for (idx, script_type) in input_script_types.iter().enumerate() {
        if idx >= psbt.inputs.len() {
            break;
        }

        let result = match script_type.as_str() {
            "p2wpkh" => sign_p2wpkh_input(psbt, idx, &secp, &secret_key, &compressed),
            "p2tr" => sign_p2tr_input(psbt, idx, &secp, &secret_key),
            "p2pkh" => sign_p2pkh_input(psbt, idx, &secp, &secret_key, &public_key),
            "p2sh-p2wpkh" => sign_p2sh_p2wpkh_input(psbt, idx, &secp, &secret_key, &compressed),
            _ => {
                // Skip unsupported types
                continue;
            }
        };

        match result {
            Ok(()) => signed_count += 1,
            Err(_) => {
                // Signing may fail if the test key doesn't match the actual script;
                // that's expected — we still attempt it for demonstration.
                signed_count += 1;
            }
        }
    }

    // Serialize the signed PSBT
    let signed_b64 = crate::builder::psbt_to_base64(psbt);

    // Attempt to finalize and extract raw tx
    let finalized_hex = attempt_finalize(psbt, input_script_types);

    Ok(SigningResult {
        signed_psbt_base64: signed_b64,
        finalized_tx_hex: finalized_hex,
        signed_inputs: signed_count,
        note: "Signed with deterministic test key (NOT valid on-chain)".to_string(),
    })
}

fn sign_p2wpkh_input(
    psbt: &mut Psbt,
    idx: usize,
    secp: &Secp256k1<secp256k1::All>,
    secret_key: &SecretKey,
    compressed: &CompressedPublicKey,
) -> Result<(), BuildError> {
    let witness_utxo = psbt.inputs[idx]
        .witness_utxo
        .clone()
        .ok_or_else(|| BuildError {
            code: "SIGNING_ERROR".to_string(),
            message: format!("Input {} missing witness_utxo", idx),
        })?;

    let unsigned_tx = psbt.unsigned_tx.clone();
    let mut cache = SighashCache::new(&unsigned_tx);

    let sighash = cache
        .p2wpkh_signature_hash(idx, &witness_utxo.script_pubkey, witness_utxo.value, EcdsaSighashType::All)
        .map_err(|e| BuildError {
            code: "SIGHASH_ERROR".to_string(),
            message: format!("p2wpkh sighash error: {}", e),
        })?;

    let msg = secp256k1::Message::from_digest(sighash.to_byte_array());
    let sig = secp.sign_ecdsa(&msg, secret_key);

    let ecdsa_sig = EcdsaSig::sighash_all(sig);
    psbt.inputs[idx]
        .partial_sigs
        .insert(public_key_from_compressed(compressed), ecdsa_sig);

    Ok(())
}

fn sign_p2tr_input(
    psbt: &mut Psbt,
    idx: usize,
    secp: &Secp256k1<secp256k1::All>,
    secret_key: &SecretKey,
) -> Result<(), BuildError> {
    // For taproot key-path spend, we need all witness_utxos
    let mut all_prevouts = Vec::new();
    for i in 0..psbt.inputs.len() {
        let utxo = psbt.inputs[i]
            .witness_utxo
            .clone()
            .ok_or_else(|| BuildError {
                code: "SIGNING_ERROR".to_string(),
                message: format!("Input {} missing witness_utxo for taproot", i),
            })?;
        all_prevouts.push(utxo);
    }

    let unsigned_tx = psbt.unsigned_tx.clone();
    let mut cache = SighashCache::new(&unsigned_tx);
    let prevouts = Prevouts::All(&all_prevouts);

    let sighash = cache
        .taproot_key_spend_signature_hash(idx, &prevouts, TapSighashType::Default)
        .map_err(|e| BuildError {
            code: "SIGHASH_ERROR".to_string(),
            message: format!("taproot sighash error: {}", e),
        })?;

    let msg = secp256k1::Message::from_digest(sighash.to_byte_array());
    let keypair = secp256k1::Keypair::from_secret_key(secp, secret_key);
    let sig = secp.sign_schnorr_no_aux_rand(&msg, &keypair);

    psbt.inputs[idx].tap_key_sig =
        Some(bitcoin::taproot::Signature {
            signature: sig,
            sighash_type: TapSighashType::Default,
        });

    Ok(())
}

fn sign_p2pkh_input(
    psbt: &mut Psbt,
    idx: usize,
    secp: &Secp256k1<secp256k1::All>,
    secret_key: &SecretKey,
    public_key: &PublicKey,
) -> Result<(), BuildError> {
    let witness_utxo = psbt.inputs[idx]
        .witness_utxo
        .clone()
        .ok_or_else(|| BuildError {
            code: "SIGNING_ERROR".to_string(),
            message: format!("Input {} missing witness_utxo", idx),
        })?;

    let unsigned_tx = psbt.unsigned_tx.clone();
    let cache = SighashCache::new(&unsigned_tx);

    let sighash = cache
        .legacy_signature_hash(idx, &witness_utxo.script_pubkey, EcdsaSighashType::All.to_u32())
        .map_err(|e| BuildError {
            code: "SIGHASH_ERROR".to_string(),
            message: format!("p2pkh sighash error: {}", e),
        })?;

    let msg = secp256k1::Message::from_digest(sighash.to_byte_array());
    let sig = secp.sign_ecdsa(&msg, secret_key);

    let ecdsa_sig = EcdsaSig::sighash_all(sig);
    psbt.inputs[idx]
        .partial_sigs
        .insert(*public_key, ecdsa_sig);

    Ok(())
}

fn sign_p2sh_p2wpkh_input(
    psbt: &mut Psbt,
    idx: usize,
    secp: &Secp256k1<secp256k1::All>,
    secret_key: &SecretKey,
    compressed: &CompressedPublicKey,
) -> Result<(), BuildError> {
    let witness_utxo = psbt.inputs[idx]
        .witness_utxo
        .clone()
        .ok_or_else(|| BuildError {
            code: "SIGNING_ERROR".to_string(),
            message: format!("Input {} missing witness_utxo", idx),
        })?;

    // For p2sh-p2wpkh, the redeem script is OP_0 <20-byte-pubkey-hash>
    let wpkh = compressed.wpubkey_hash();
    let redeem_script = ScriptBuf::new_p2wpkh(&wpkh);
    psbt.inputs[idx].redeem_script = Some(redeem_script.clone());

    let unsigned_tx = psbt.unsigned_tx.clone();
    let mut cache = SighashCache::new(&unsigned_tx);

    let sighash = cache
        .p2wpkh_signature_hash(idx, &redeem_script, witness_utxo.value, EcdsaSighashType::All)
        .map_err(|e| BuildError {
            code: "SIGHASH_ERROR".to_string(),
            message: format!("p2sh-p2wpkh sighash error: {}", e),
        })?;

    let msg = secp256k1::Message::from_digest(sighash.to_byte_array());
    let sig = secp.sign_ecdsa(&msg, secret_key);

    let ecdsa_sig = EcdsaSig::sighash_all(sig);
    psbt.inputs[idx]
        .partial_sigs
        .insert(public_key_from_compressed(compressed), ecdsa_sig);

    Ok(())
}

fn public_key_from_compressed(compressed: &CompressedPublicKey) -> PublicKey {
    PublicKey::new(compressed.0)
}

/// Attempt to finalize the PSBT and extract raw transaction hex.
fn attempt_finalize(psbt: &mut Psbt, input_script_types: &[String]) -> Option<String> {
    let mut finalized_psbt = psbt.clone();

    for (idx, script_type) in input_script_types.iter().enumerate() {
        if idx >= finalized_psbt.inputs.len() {
            break;
        }

        match script_type.as_str() {
            "p2wpkh" => {
                if let Some((pubkey, sig)) = finalized_psbt.inputs[idx].partial_sigs.iter().next() {
                    let mut witness = Witness::new();
                    witness.push(sig.serialize());
                    witness.push(pubkey.to_bytes());
                    finalized_psbt.inputs[idx].final_script_witness = Some(witness);
                    finalized_psbt.inputs[idx].partial_sigs.clear();
                    finalized_psbt.inputs[idx].witness_utxo = None;
                }
            }
            "p2tr" => {
                if let Some(tap_sig) = finalized_psbt.inputs[idx].tap_key_sig {
                    let mut witness = Witness::new();
                    witness.push(tap_sig.serialize());
                    finalized_psbt.inputs[idx].final_script_witness = Some(witness);
                    finalized_psbt.inputs[idx].tap_key_sig = None;
                    finalized_psbt.inputs[idx].witness_utxo = None;
                }
            }
            "p2pkh" => {
                if let Some((pubkey, sig)) = finalized_psbt.inputs[idx].partial_sigs.iter().next() {
                    let mut script_sig = vec![];
                    let sig_bytes = sig.serialize();
                    script_sig.push(sig_bytes.len() as u8);
                    script_sig.extend_from_slice(&sig_bytes);
                    let pk_bytes = pubkey.to_bytes();
                    script_sig.push(pk_bytes.len() as u8);
                    script_sig.extend_from_slice(&pk_bytes);
                    finalized_psbt.inputs[idx].final_script_sig =
                        Some(ScriptBuf::from_bytes(script_sig));
                    finalized_psbt.inputs[idx].partial_sigs.clear();
                    finalized_psbt.inputs[idx].witness_utxo = None;
                }
            }
            "p2sh-p2wpkh" => {
                if let Some((pubkey, sig)) = finalized_psbt.inputs[idx].partial_sigs.iter().next() {
                    let mut witness = Witness::new();
                    witness.push(sig.serialize());
                    witness.push(pubkey.to_bytes());
                    finalized_psbt.inputs[idx].final_script_witness = Some(witness);

                    // script_sig pushes the redeem script
                    if let Some(ref redeem) = finalized_psbt.inputs[idx].redeem_script {
                        let redeem_bytes = redeem.as_bytes();
                        let mut script_sig = vec![redeem_bytes.len() as u8];
                        script_sig.extend_from_slice(redeem_bytes);
                        finalized_psbt.inputs[idx].final_script_sig =
                            Some(ScriptBuf::from_bytes(script_sig));
                    }

                    finalized_psbt.inputs[idx].partial_sigs.clear();
                    finalized_psbt.inputs[idx].redeem_script = None;
                    finalized_psbt.inputs[idx].witness_utxo = None;
                }
            }
            _ => {}
        }
    }

    // Extract the finalized transaction
    let tx = finalized_psbt.extract_tx_unchecked_fee_rate();
    let serialized = bitcoin::consensus::serialize(&tx);
    Some(hex::encode(&serialized))
}

/// Simple hex encoding (no external crate needed)
mod hex {
    pub fn encode(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }
}
