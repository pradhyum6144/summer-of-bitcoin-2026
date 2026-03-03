use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Fixture {
    pub network: String,
    pub utxos: Vec<Utxo>,
    pub payments: Vec<Payment>,
    pub change: ChangeTemplate,
    pub fee_rate_sat_vb: f64,
    #[serde(default)]
    pub rbf: Option<bool>,
    #[serde(default)]
    pub locktime: Option<u32>,
    #[serde(default)]
    pub current_height: Option<u32>,
    #[serde(default)]
    pub policy: Option<Policy>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Utxo {
    pub txid: String,
    pub vout: u32,
    pub value_sats: u64,
    pub script_pubkey_hex: String,
    pub script_type: String,
    #[serde(default)]
    pub address: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Payment {
    #[serde(default)]
    pub address: Option<String>,
    pub script_pubkey_hex: String,
    pub script_type: String,
    pub value_sats: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChangeTemplate {
    #[serde(default)]
    pub address: Option<String>,
    pub script_pubkey_hex: String,
    pub script_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    #[serde(default)]
    pub max_inputs: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BuildError {
    pub code: String,
    pub message: String,
}

impl std::fmt::Display for BuildError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for BuildError {}

pub fn validate_fixture(fixture: &Fixture) -> Result<(), BuildError> {
    // Validate network
    match fixture.network.as_str() {
        "mainnet" | "testnet" | "signet" | "regtest" => {}
        _ => {
            return Err(BuildError {
                code: "INVALID_NETWORK".to_string(),
                message: format!("Unknown network: {}", fixture.network),
            });
        }
    }

    // Validate UTXOs
    if fixture.utxos.is_empty() {
        return Err(BuildError {
            code: "INVALID_FIXTURE".to_string(),
            message: "No UTXOs provided".to_string(),
        });
    }

    for (i, utxo) in fixture.utxos.iter().enumerate() {
        if utxo.txid.len() != 64 {
            return Err(BuildError {
                code: "INVALID_FIXTURE".to_string(),
                message: format!("UTXO {} has invalid txid length: {}", i, utxo.txid.len()),
            });
        }
        if hex::decode(&utxo.txid).is_err() {
            return Err(BuildError {
                code: "INVALID_FIXTURE".to_string(),
                message: format!("UTXO {} has invalid txid hex", i),
            });
        }
        if utxo.value_sats == 0 {
            return Err(BuildError {
                code: "INVALID_FIXTURE".to_string(),
                message: format!("UTXO {} has zero value", i),
            });
        }
        if utxo.script_pubkey_hex.is_empty() {
            return Err(BuildError {
                code: "INVALID_FIXTURE".to_string(),
                message: format!("UTXO {} has empty script_pubkey_hex", i),
            });
        }
        if hex::decode(&utxo.script_pubkey_hex).is_err() {
            return Err(BuildError {
                code: "INVALID_FIXTURE".to_string(),
                message: format!("UTXO {} has invalid script_pubkey_hex", i),
            });
        }
        validate_script_type(&utxo.script_type, i, "UTXO")?;
    }

    // Validate payments
    if fixture.payments.is_empty() {
        return Err(BuildError {
            code: "INVALID_FIXTURE".to_string(),
            message: "No payments provided".to_string(),
        });
    }

    for (i, payment) in fixture.payments.iter().enumerate() {
        if payment.value_sats == 0 {
            return Err(BuildError {
                code: "INVALID_FIXTURE".to_string(),
                message: format!("Payment {} has zero value", i),
            });
        }
        if payment.script_pubkey_hex.is_empty() {
            return Err(BuildError {
                code: "INVALID_FIXTURE".to_string(),
                message: format!("Payment {} has empty script_pubkey_hex", i),
            });
        }
        if hex::decode(&payment.script_pubkey_hex).is_err() {
            return Err(BuildError {
                code: "INVALID_FIXTURE".to_string(),
                message: format!("Payment {} has invalid script_pubkey_hex", i),
            });
        }
        validate_script_type(&payment.script_type, i, "Payment")?;
    }

    // Validate change
    if fixture.change.script_pubkey_hex.is_empty() {
        return Err(BuildError {
            code: "INVALID_FIXTURE".to_string(),
            message: "Change has empty script_pubkey_hex".to_string(),
        });
    }
    if hex::decode(&fixture.change.script_pubkey_hex).is_err() {
        return Err(BuildError {
            code: "INVALID_FIXTURE".to_string(),
            message: "Change has invalid script_pubkey_hex".to_string(),
        });
    }

    // Validate fee rate
    if fixture.fee_rate_sat_vb <= 0.0 {
        return Err(BuildError {
            code: "INVALID_FIXTURE".to_string(),
            message: "Fee rate must be positive".to_string(),
        });
    }

    Ok(())
}

fn validate_script_type(script_type: &str, index: usize, context: &str) -> Result<(), BuildError> {
    match script_type {
        "p2pkh" | "p2sh" | "p2sh-p2wpkh" | "p2sh-p2wsh" | "p2wpkh" | "p2wsh" | "p2tr" => Ok(()),
        _ => Err(BuildError {
            code: "INVALID_FIXTURE".to_string(),
            message: format!("{} {} has unknown script_type: {}", context, index, script_type),
        }),
    }
}

/// Detect the actual script type from the authoritative script_pubkey_hex.
/// Returns None if the script doesn't match any known pattern.
fn detect_script_type(script_pubkey_hex: &str) -> Option<&'static str> {
    let len = script_pubkey_hex.len(); // hex chars = 2 * byte count
    // P2PKH: OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG → 25 bytes → 50 hex
    // Pattern: 76a914{40 hex}88ac
    if len == 50 && script_pubkey_hex.starts_with("76a914") && script_pubkey_hex.ends_with("88ac") {
        return Some("p2pkh");
    }
    // P2SH: OP_HASH160 <20 bytes> OP_EQUAL → 23 bytes → 46 hex
    // Pattern: a914{40 hex}87
    if len == 46 && script_pubkey_hex.starts_with("a914") && script_pubkey_hex.ends_with("87") {
        return Some("p2sh");
    }
    // P2WPKH: OP_0 <20 bytes> → 22 bytes → 44 hex
    // Pattern: 0014{40 hex}
    if len == 44 && script_pubkey_hex.starts_with("0014") {
        return Some("p2wpkh");
    }
    // P2WSH: OP_0 <32 bytes> → 34 bytes → 68 hex
    // Pattern: 0020{64 hex}
    if len == 68 && script_pubkey_hex.starts_with("0020") {
        return Some("p2wsh");
    }
    // P2TR: OP_1 <32 bytes> → 34 bytes → 68 hex
    // Pattern: 5120{64 hex}
    if len == 68 && script_pubkey_hex.starts_with("5120") {
        return Some("p2tr");
    }
    None
}

/// Determine whether to override declared script_type with detected type.
/// P2SH sub-types (p2sh-p2wpkh, p2sh-p2wsh) share the same a914...87 script pattern
/// as plain p2sh, so we preserve the declared sub-type when hex detects "p2sh".
fn should_override(detected: &str, declared: &str) -> bool {
    if detected == "p2sh" && (declared == "p2sh-p2wpkh" || declared == "p2sh-p2wsh") {
        return false;
    }
    true
}

/// Normalize a fixture after parsing and validation:
/// - Override script_type with detected type from script_pubkey_hex (hex is authoritative)
/// - Deduplicate UTXOs by (txid, vout)
pub fn normalize_fixture(fixture: &mut Fixture) {
    // Deduplicate UTXOs by (txid, vout), keeping the first occurrence
    let mut seen = std::collections::HashSet::new();
    fixture.utxos.retain(|utxo| seen.insert((utxo.txid.clone(), utxo.vout)));

    // Override script_type from script_pubkey_hex for UTXOs
    for utxo in &mut fixture.utxos {
        if let Some(detected) = detect_script_type(&utxo.script_pubkey_hex) {
            if should_override(detected, &utxo.script_type) {
                utxo.script_type = detected.to_string();
            }
        }
    }

    // Override script_type from script_pubkey_hex for payments
    for payment in &mut fixture.payments {
        if let Some(detected) = detect_script_type(&payment.script_pubkey_hex) {
            if should_override(detected, &payment.script_type) {
                payment.script_type = detected.to_string();
            }
        }
    }

    // Override script_type from script_pubkey_hex for change template
    if let Some(detected) = detect_script_type(&fixture.change.script_pubkey_hex) {
        if should_override(detected, &fixture.change.script_type) {
            fixture.change.script_type = detected.to_string();
        }
    }
}

/// Simple hex decoder (avoid extra dependency)
mod hex {
    pub fn decode(s: &str) -> Result<Vec<u8>, String> {
        if s.len() % 2 != 0 {
            return Err("odd length".to_string());
        }
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| e.to_string()))
            .collect()
    }
}
